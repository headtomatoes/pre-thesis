/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __XDP_PROG_H__
#define __XDP_PROG_H__

/*
 * Shared header between BPF kernel program and Go userspace controller.
 * All structs that appear in eBPF maps must be defined here so both sides
 * agree on layout.
 */

#include <linux/types.h>

/* ────────────────────────────────────────────
 * Flow Key — identifies a source IP
 * For L3/L4 DDoS the primary aggregation is per-source-IP.
 * ──────────────────────────────────────────── */
struct flow_key {
    __u32 src_ip;           /* Source IPv4 address (network byte order) */
};

/* ────────────────────────────────────────────
 * Flow Counters — accumulated in XDP per-CPU maps
 * These are the "stateless / semi-stateful" features
 * described in the thesis feature table.
 * ──────────────────────────────────────────── */
struct flow_counters {
    __u64 pkt_count;        /* Feature 1: Total packets from this source       */
    __u64 byte_count;       /* Feature 2: Total bytes from this source         */
    __u64 syn_count;        /* Feature 3: TCP SYN flag count                   */
    __u64 ack_count;        /* Feature 4: TCP ACK flag count                   */
    __u64 udp_count;        /* Protocol counter: UDP packets                   */
    __u64 icmp_count;       /* Protocol counter: ICMP packets                  */
    __u64 tcp_count;        /* Protocol counter: TCP packets                   */
    __u64 other_proto;      /* Protocol counter: everything else               */
    __u64 pkt_size_sum_sq;  /* Σ(pkt_len²) — for variance calc in userspace    */
    __u64 first_seen_ns;    /* Timestamp of first packet (ktime, nanoseconds)  */
    __u64 last_seen_ns;     /* Timestamp of most recent packet                 */
    __u64 iat_sum_ns;       /* Sum of inter-arrival times (nanoseconds)        */
    __u64 iat_sum_sq_ns;    /* Σ(IAT²) for IAT variance in userspace          */
};

/* ────────────────────────────────────────────
 * Global (aggregate) counters — single-entry map
 * Used for overall throughput monitoring.
 * ──────────────────────────────────────────── */
struct global_counters {
    __u64 total_pkts;
    __u64 total_bytes;
    __u64 total_dropped;
};

/* ────────────────────────────────────────────
 * Blacklist entry — written by Go controller
 * when ML inference determines a source is malicious.
 * XDP checks this map and issues XDP_DROP.
 * ──────────────────────────────────────────── */
struct blacklist_entry {
    __u64 blocked_at_ns;    /* When the IP was blocked (ktime)                 */
    __u64 ttl_ns;           /* How long to keep the block (0 = permanent)      */
};

/* ────────────────────────────────────────────
 * Map sizing constants
 * ──────────────────────────────────────────── */
#define MAX_FLOW_ENTRIES    65536   /* Max unique source IPs tracked            */
#define MAX_BLACKLIST       16384   /* Max blacklisted IPs                      */

#endif /* __XDP_PROG_H__ */
