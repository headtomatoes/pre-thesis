// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_prog.c — XDP/eBPF program for real-time L3/L4 DDoS feature extraction
 *
 * This program is attached to the NIC driver's earliest receive path.
 * For every incoming packet it:
 *   1. Checks a blacklist map — if the source IP is blocked → XDP_DROP.
 *   2. Parses Ethernet → IP → TCP/UDP/ICMP headers.
 *   3. Updates per-source-IP flow counters in a per-CPU hash map.
 *   4. Updates global aggregate counters.
 *   5. Returns XDP_PASS to let the packet proceed to the kernel stack.
 *
 * The Go userspace controller polls the maps every ~500ms to build
 * feature vectors and run ONNX inference.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_prog.h"

/* ────────────────────────────────────────────
 * MAP DEFINITIONS
 * ──────────────────────────────────────────── */

/* Per-source-IP flow counters (per-CPU to avoid locking) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_FLOW_ENTRIES);
    __type(key, struct flow_key);
    __type(value, struct flow_counters);
} flow_stats SEC(".maps");

/* Global aggregate counters (per-CPU for lock-free updates) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_counters);
} global_stats SEC(".maps");

/* Blacklist map — populated by Go controller, checked by XDP */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLACKLIST);
    __type(key, struct flow_key);
    __type(value, struct blacklist_entry);
} blacklist SEC(".maps");

/* ────────────────────────────────────────────
 * HELPER: bounds-checked pointer advance
 * ──────────────────────────────────────────── */
static __always_inline int parse_ethhdr(void *data, void *data_end,
                                        struct ethhdr **eth)
{
    *eth = data;
    if ((void *)(*eth + 1) > data_end)
        return -1;
    return bpf_ntohs((*eth)->h_proto);
}

/* ────────────────────────────────────────────
 * MAIN XDP PROGRAM
 * ──────────────────────────────────────────── */
SEC("xdp")
int xdp_ddos_detector(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* ── Step 0: Parse Ethernet header ── */
    struct ethhdr *eth;
    int proto = parse_ethhdr(data, data_end, &eth);
    if (proto < 0)
        return XDP_PASS;   /* malformed — let kernel handle */

    /* We only care about IPv4 */
    if (proto != ETH_P_IP)
        return XDP_PASS;

    /* ── Step 1: Parse IP header ── */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 pkt_len = data_end - data;
    __u64 now     = bpf_ktime_get_ns();

    struct flow_key key = {
        .src_ip = iph->saddr,
    };

    /* ── Step 2: Blacklist check ── */
    struct blacklist_entry *blocked = bpf_map_lookup_elem(&blacklist, &key);
    if (blocked) {
        /* Check TTL expiry */
        if (blocked->ttl_ns == 0 || (now - blocked->blocked_at_ns) < blocked->ttl_ns) {
            /* Update drop counter */
            __u32 gk = 0;
            struct global_counters *gc = bpf_map_lookup_elem(&global_stats, &gk);
            if (gc)
                gc->total_dropped++;
            return XDP_DROP;
        }
        /* TTL expired — remove from blacklist */
        bpf_map_delete_elem(&blacklist, &key);
    }

    /* ── Step 3: Determine L4 protocol and extract flags ── */
    __u8  is_syn  = 0;
    __u8  is_ack  = 0;
    __u8  is_udp  = 0;
    __u8  is_icmp = 0;
    __u8  is_tcp  = 0;

    switch (iph->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end)
            return XDP_PASS;
        is_tcp = 1;
        if (tcph->syn)
            is_syn = 1;
        if (tcph->ack)
            is_ack = 1;
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *udph = (void *)iph + (iph->ihl * 4);
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;
        is_udp = 1;
        break;
    }
    case IPPROTO_ICMP: {
        struct icmphdr *icmph = (void *)iph + (iph->ihl * 4);
        if ((void *)(icmph + 1) > data_end)
            return XDP_PASS;
        is_icmp = 1;
        break;
    }
    default:
        break;
    }

    /* ── Step 4: Update per-source-IP flow counters ── */
    struct flow_counters *counters = bpf_map_lookup_elem(&flow_stats, &key);
    if (counters) {
        /* Existing flow — update in place */
        __u64 iat = now - counters->last_seen_ns;

        counters->pkt_count++;
        counters->byte_count    += pkt_len;
        counters->syn_count     += is_syn;
        counters->ack_count     += is_ack;
        counters->tcp_count     += is_tcp;
        counters->udp_count     += is_udp;
        counters->icmp_count    += is_icmp;
        counters->other_proto   += (!is_tcp && !is_udp && !is_icmp) ? 1 : 0;
        counters->pkt_size_sum_sq += (__u64)pkt_len * (__u64)pkt_len;
        counters->last_seen_ns   = now;
        counters->iat_sum_ns    += iat;
        counters->iat_sum_sq_ns += iat * iat;
    } else {
        /* New flow — initialize */
        struct flow_counters new_counters = {
            .pkt_count      = 1,
            .byte_count     = pkt_len,
            .syn_count      = is_syn,
            .ack_count      = is_ack,
            .tcp_count      = is_tcp,
            .udp_count      = is_udp,
            .icmp_count     = is_icmp,
            .other_proto    = (!is_tcp && !is_udp && !is_icmp) ? 1 : 0,
            .pkt_size_sum_sq = (__u64)pkt_len * (__u64)pkt_len,
            .first_seen_ns  = now,
            .last_seen_ns   = now,
            .iat_sum_ns     = 0,
            .iat_sum_sq_ns  = 0,
        };
        bpf_map_update_elem(&flow_stats, &key, &new_counters, BPF_ANY);
    }

    /* ── Step 5: Update global aggregate counters ── */
    __u32 gk = 0;
    struct global_counters *gc = bpf_map_lookup_elem(&global_stats, &gk);
    if (gc) {
        gc->total_pkts++;
        gc->total_bytes += pkt_len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
