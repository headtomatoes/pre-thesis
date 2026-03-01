# Comprehensive Guide: Understanding the DDoS Early Warning System

> A complete educational reference covering every concept needed to understand,
> build, and defend this thesis. Start from Chapter 1 and work forward — each
> chapter builds on the previous one.

---

# Table of Contents

1. [Networking Foundations](#chapter-1-networking-foundations)
2. [DDoS Attacks: Mechanics and Taxonomy](#chapter-2-ddos-attacks-mechanics-and-taxonomy)
3. [The Linux Kernel Networking Stack](#chapter-3-the-linux-kernel-networking-stack)
4. [eBPF and XDP: Programmable Data Planes](#chapter-4-ebpf-and-xdp-programmable-data-planes)
5. [Machine Learning Foundations](#chapter-5-machine-learning-foundations)
6. [Ensemble Methods and Gradient Boosting](#chapter-6-ensemble-methods-and-gradient-boosting)
7. [Feature Engineering for Network Traffic](#chapter-7-feature-engineering-for-network-traffic)
8. [Data Structures for High-Speed Networking](#chapter-8-data-structures-for-high-speed-networking)
9. [ONNX and Cross-Language Model Deployment](#chapter-9-onnx-and-cross-language-model-deployment)
10. [System Integration: Putting It All Together](#chapter-10-system-integration-putting-it-all-together)

---

# Chapter 1: Networking Foundations

## 1.1 The OSI Model and Where DDoS Attacks Live

The OSI (Open Systems Interconnection) model divides network communication into 7 layers. For this thesis, only Layers 3 and 4 matter:

```
┌───────────────────────────────────────────────┐
│  Layer 7: Application    (HTTP, DNS, SMTP)    │  ← "App-layer DDoS" (not our scope)
│  Layer 6: Presentation   (SSL/TLS, encoding)  │
│  Layer 5: Session        (sockets, sessions)  │
├───────────────────────────────────────────────┤
│  Layer 4: Transport      (TCP, UDP)           │  ← OUR SCOPE: SYN floods, UDP floods
│  Layer 3: Network        (IP, ICMP)           │  ← OUR SCOPE: IP spoofing, amplification
├───────────────────────────────────────────────┤
│  Layer 2: Data Link      (Ethernet, ARP)      │
│  Layer 1: Physical       (cables, signals)    │
└───────────────────────────────────────────────┘
```

**Why L3/L4?** These layers handle *how packets move* across the network. Attacks at these layers don't need to understand the application — they simply overwhelm the network pipe or exhaust connection-tracking resources.

## 1.2 IPv4 Packet Structure

Every packet on the internet starts with an IP header. Here's what matters for detection:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |    DSCP/ECN   |         Total Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|    Fragment Offset      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |   Protocol    |       Header Checksum         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source IP Address                       |  ← Can be SPOOFED
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination IP Address                     |  ← The victim
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Fields our XDP program reads:**
- `Protocol` (8 bits): Tells us if the next header is TCP (6), UDP (17), or ICMP (1).
- `Source IP Address` (32 bits): This is the key we use to track flows. Attackers often *spoof* this field.
- `Total Length` (16 bits): Total packet size — used for byte counting and size variance features.
- `IHL` (4 bits): Internet Header Length — tells us where the L4 header starts (important for parsing TCP flags).

**What is IP Spoofing?**

The source IP field is *self-reported* by the sender. There is no built-in authentication. An attacker can set it to any value:

```
Attacker (real IP: 1.2.3.4)
    │
    │  Sends packet with Source IP = 100.200.50.25 (FAKE)
    ▼
Victim sees traffic "from" 100.200.50.25
    │
    │  Tries to respond to 100.200.50.25
    ▼
100.200.50.25 receives unwanted response (BACKSCATTER)
```

This is why we cannot simply "block the source IP" as a complete defence — the real attacker's IP is hidden.

## 1.3 TCP: The Connection-Oriented Protocol

TCP (Transmission Control Protocol) provides reliable, ordered delivery. Every TCP connection begins with a **3-way handshake**:

```
   Client                          Server
     │                               │
     │──── SYN (seq=100) ──────────▶│  Step 1: "I want to connect"
     │                               │
     │◀─── SYN-ACK (seq=300,        │  Step 2: "OK, I'm ready"
     │      ack=101) ────────────────│
     │                               │          Server allocates a
     │                               │          Transmission Control
     │                               │          Block (TCB) in memory
     │──── ACK (ack=301) ──────────▶│  Step 3: "Let's go"
     │                               │
     │◀──── Data transfer ─────────▶│  Connection established
```

### TCP Header and Flags

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Offset|  Res  |C|E|U|A|P|R|S|F|           Window             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                         ▲ ▲   ▲ ▲
                         │ │   │ └─ FIN (connection close)
                         │ │   └─── SYN (connection start)
                         │ └─────── RST (connection reset)
                         └───────── ACK (acknowledgement)
```

**The flags our system counts:**
- **SYN** (Synchronize): Initiates a connection. High SYN count = potential SYN flood.
- **ACK** (Acknowledge): Confirms received data. In normal traffic, SYN and ACK are roughly balanced.

### Why the SYN/ACK Ratio Matters

In a legitimate TCP session:
```
1 SYN → 1 SYN-ACK → 1 ACK → many ACKs (during data transfer)
Ratio: SYN/ACK ≈ very small (1 SYN per many ACKs)
```

In a SYN flood attack:
```
10,000 SYNs → 0 ACKs (attacker never completes handshake)
Ratio: SYN/ACK = ∞ (or very large)
```

This is why Feature #5 (SYN/ACK Ratio) is such a powerful indicator.

## 1.4 UDP: The Connectionless Protocol

UDP (User Datagram Protocol) has no handshake, no connection state, and no reliability guarantees:

```
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|     Source       |   Destination   |
|      Port        |      Port       |
+--------+--------+--------+--------+
|     Length        |    Checksum     |
+--------+--------+--------+--------+
|          Data (payload)            |
+------------------------------------+
```

**Why UDP is abused for DDoS:**
1. **No handshake**: The sender doesn't need to wait for permission. It just floods.
2. **No authentication**: The source IP can be freely spoofed.
3. **Amplification**: Many UDP-based services (DNS, NTP, LDAP) return responses much larger than the request.

## 1.5 ICMP: The Control Protocol

ICMP (Internet Control Message Protocol) is used for network diagnostics (ping, traceroute). While not a transport protocol per se, ICMP packets can be used in **Ping Floods** (Smurf attacks). Our XDP program counts ICMP packets for the Protocol Entropy feature.

## 1.6 Understanding Bandwidth and Packet Rates

Two metrics define network capacity:

| Metric | Unit | Meaning |
|--------|------|---------|
| **Bandwidth** | bits per second (bps) | Total data throughput |
| **Packet Rate** | packets per second (pps) | Number of individual packets |

A 10 Gbps link can carry:
- **Best case** (large 1500-byte packets): ~833,000 pps
- **Worst case** (small 64-byte packets): ~14,880,000 pps (14.88 Mpps)

DDoS attacks exploit both dimensions:
- **Volumetric**: Saturate bandwidth (e.g., DNS amplification sending huge responses)
- **Packet-rate**: Overwhelm CPU with millions of tiny packets (e.g., SYN flood with 40-byte packets)

Our system must handle both — which is why XDP's ability to process **10–24 Mpps** is critical.

---

# Chapter 2: DDoS Attacks — Mechanics and Taxonomy

## 2.1 What is a DDoS Attack?

A **Distributed Denial of Service** attack uses many sources (a botnet) to flood a target, making it unavailable to legitimate users. The key word is "distributed" — the attack comes from thousands or millions of IPs simultaneously.

```
    ┌───────┐
    │ Bot 1 │──┐
    └───────┘  │
    ┌───────┐  │     ┌──────────┐
    │ Bot 2 │──┼────▶│  VICTIM  │ ← Overwhelmed
    └───────┘  │     │  Server  │
    ┌───────┐  │     └──────────┘
    │ Bot N │──┘
    └───────┘
    
    Controlled by an Attacker via C&C (Command & Control)
```

## 2.2 Attack Taxonomy

### 2.2.1 Volumetric Attacks (L3)

**Goal:** Saturate the victim's bandwidth.

**UDP Flood:**
```
Attacker → Sends millions of UDP packets → Victim's pipe is full
```
- Easiest to execute — just blast random UDP packets.
- Easy to detect (huge packet and byte counts), but hard to mitigate at scale.

**ICMP Flood (Ping Flood):**
```
Attacker → Sends millions of ICMP Echo Requests → Victim must process each
```

### 2.2.2 Amplification/Reflection Attacks (L3/L4)

**Goal:** Use third-party servers to multiply attack traffic.

**How it works:**

```
Step 1: Attacker sends small request to Reflector
        Source IP is SPOOFED to be the Victim's IP

Step 2: Reflector sends large response to Victim
        (because it thinks Victim sent the request)

┌──────────┐    Small query     ┌───────────┐
│ Attacker │ ──────────────────▶│ Reflector │
│          │  src_ip = VICTIM   │ (DNS/NTP) │
└──────────┘                    └─────┬─────┘
                                      │
                    Large response     │
                    (amplified)        │
                                      ▼
                                ┌──────────┐
                                │  VICTIM  │ ← Gets huge response it never asked for
                                └──────────┘
```

**Amplification Factors:**

| Protocol | Request Size | Response Size | Amplification Factor |
|----------|-------------|---------------|---------------------|
| DNS      | 60 bytes    | 4,000 bytes   | ~67x |
| NTP      | 234 bytes   | 482,000 bytes | ~2,060x |
| LDAP     | 52 bytes    | 28,000 bytes  | ~538x |
| SSDP     | 29 bytes    | 30,000 bytes  | ~1,034x |
| SNMP     | 60 bytes    | 6,000 bytes   | ~100x |

**Example:** An attacker with 1 Mbps upload can generate a **2 Gbps** flood using NTP amplification. This is why amplification attacks are the most dangerous volumetric threat.

### 2.2.3 Protocol Attacks (L4)

**Goal:** Exhaust server resources (memory, connection tables) rather than bandwidth.

**SYN Flood:**

```
Normal:
  Client → SYN → Server (allocates TCB: ~280 bytes)
  Client ← SYN-ACK ← Server
  Client → ACK → Server (connection complete, TCB stays)

Attack:
  Bot 1 → SYN (spoofed) → Server (allocates TCB)
  Bot 2 → SYN (spoofed) → Server (allocates TCB)
  Bot 3 → SYN (spoofed) → Server (allocates TCB)
  ...
  Bot N → SYN (spoofed) → Server (OUT OF MEMORY — no more TCBs)
  
  Legitimate user → SYN → Server: "Sorry, connection refused"
```

**Why SYN floods work:**
- The server must allocate memory (TCB) for every SYN received.
- The server waits for the ACK that never comes (half-open connection).
- Default timeout is 60–120 seconds — thousands of half-open connections accumulate.
- With spoofed IPs, the SYN-ACK goes to the wrong address, so no ACK ever returns.

**Our detection approach:**
- Feature #3 (SYN Count): Extremely high → suspicious.
- Feature #5 (SYN/ACK Ratio): Very high ratio → attack pattern (many SYNs, few ACKs).

### 2.2.4 Why Traditional Defences Fail

| Defence | Mechanism | Why It Fails |
|---------|-----------|--------------|
| Rate limiting | Drop if > N pps | Flash crowds trigger false positives |
| IP blacklisting | Block known-bad IPs | Spoofed IPs are random; botnets rotate |
| Signature matching | Pattern match packets | Zero-day attacks have no signature |
| Scrubbing centres | Route traffic through CDN | High latency (seconds to reroute) |
| Firewalls (iptables) | Kernel-space filtering | Too slow at 10+ Mpps |

**Our advantage:** ML-based classification at XDP speed adapts to unknown attack patterns and processes packets before the kernel bottleneck.

---

# Chapter 3: The Linux Kernel Networking Stack

## 3.1 How a Packet Travels Through the Kernel

Understanding *why* the standard stack is slow requires tracing a single packet's journey:

```
                    HARDWARE
                    ────────
  ① NIC receives electrical signals → frames
  ② DMA (Direct Memory Access) copies frame to ring buffer in RAM
  ③ NIC raises a hardware interrupt (IRQ)

                    KERNEL
                    ──────
  ④ Interrupt handler runs (top half) — very fast
  ⑤ NAPI: schedule softirq for deferred processing (bottom half)
  ⑥ Allocate sk_buff structure (~256 bytes of metadata per packet)
  ⑦ Parse Ethernet header → IP header → TCP/UDP header
  ⑧ Netfilter hooks execute (iptables rules, conntrack)
  ⑨ Route decision (forward? deliver locally?)
  ⑩ Copy packet data to socket buffer

                    USERSPACE
                    ─────────
  ⑪ Application calls recv() / read()
  ⑫ Kernel copies socket buffer → application memory (ANOTHER copy)
  ⑬ Application processes the packet
```

### Cost Analysis

| Step | Operation | Cost |
|------|-----------|------|
| ② | DMA transfer | ~0 CPU (hardware does it) |
| ③ | Hardware interrupt | ~1 µs (context switch) |
| ⑥ | sk_buff allocation | ~0.3 µs (slab allocator) |
| ⑧ | Netfilter/iptables | ~2-10 µs per rule chain |
| ⑩⑫ | Memory copies (×2) | ~1-3 µs per copy |
| | **Total per packet** | **~5-15 µs** |

At 14.88 Mpps (10GbE worst case), the CPU has only **67 nanoseconds** per packet. The standard stack's 5-15 µs per packet means it can handle only **1-2 Mpps** — an order of magnitude too slow.

## 3.2 The sk_buff Problem

`sk_buff` is the kernel's universal packet representation. It's incredibly flexible but also expensive:

```c
struct sk_buff {
    /* Linked list pointers */
    struct sk_buff *next, *prev;
    
    /* Timestamps, device info */
    ktime_t tstamp;
    struct net_device *dev;
    
    /* Header pointers */
    unsigned char *head, *data, *tail, *end;
    
    /* Protocol info */
    __be16 protocol;
    __u16 transport_header;
    __u16 network_header;
    
    /* Reference counting, cloning support */
    refcount_t users;
    
    /* ... many more fields ... */
    /* Total: ~256 bytes of metadata PER PACKET */
};
```

**The problem:** Allocating and initialising 256 bytes of metadata for a 64-byte packet is disproportionately expensive. For DDoS detection, we don't need most of this metadata — we just need to read a few header fields and update counters.

## 3.3 Where XDP Fits

XDP intercepts packets at step ② — *before* `sk_buff` allocation:

```
  ① NIC receives frame
  ② DMA copies to ring buffer
  ──────────────────────────────
  ★ XDP PROGRAM RUNS HERE ★     ← Before sk_buff, before Netfilter
  ──────────────────────────────
  ③ Only if XDP_PASS: allocate sk_buff and continue
```

By running at the driver level, XDP avoids:
- `sk_buff` allocation (saves ~0.3 µs)
- Netfilter processing (saves ~2-10 µs)  
- One memory copy (saves ~1-3 µs)

Result: **~0.1-1 µs per packet** → handles **10-24 Mpps** on a single core.

---

# Chapter 4: eBPF and XDP — Programmable Data Planes

## 4.1 What is eBPF?

eBPF (extended Berkeley Packet Filter) is a **virtual machine inside the Linux kernel** that lets you run custom programs safely, without modifying the kernel or loading kernel modules.

Think of it as JavaScript for the kernel:
- JavaScript lets you run custom code in a web browser safely (sandbox).
- eBPF lets you run custom code in the Linux kernel safely (verifier).

```
┌─────────────────────────────────────────────────────────────┐
│                        LINUX KERNEL                         │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────┐  │
│  │  Networking   │   │  Tracing     │   │  Security      │  │
│  │  (XDP, TC)    │   │  (kprobes)   │   │  (LSM)         │  │
│  └──────┬───────┘   └──────┬───────┘   └───────┬────────┘  │
│         │                  │                    │           │
│         └──────────────────┼────────────────────┘           │
│                            │                                │
│                    ┌───────▼───────┐                        │
│                    │   eBPF VM     │   ← Runs your program  │
│                    │   (Verifier   │                        │
│                    │    + JIT)     │                        │
│                    └───────┬───────┘                        │
│                            │                                │
│                    ┌───────▼───────┐                        │
│                    │   eBPF Maps   │   ← Shared data store  │
│                    └───────────────┘                        │
│                            ▲                                │
├────────────────────────────┼────────────────────────────────┤
│                    USERSPACE                                │
│                    ┌───────┴───────┐                        │
│                    │  Go Controller │  ← Reads maps         │
│                    └───────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

## 4.2 The eBPF Lifecycle

```
Step 1: Write                Step 2: Compile              Step 3: Verify
┌──────────────┐            ┌──────────────┐            ┌──────────────┐
│  xdp_prog.c  │  ─clang─▶ │  xdp_prog.o  │  ─load──▶ │   Verifier   │
│  (C source)  │            │  (BPF ELF)   │            │  (safety     │
│              │            │              │            │   check)     │
└──────────────┘            └──────────────┘            └──────┬───────┘
                                                               │
                                                        ┌──────▼───────┐
Step 5: Execute             Step 4: JIT Compile          │   PASS?      │─ NO ─▶ Rejected
┌──────────────┐            ┌──────────────┐            └──────┬───────┘
│  Run at wire │  ◀─────── │  Native x86  │  ◀── YES ──────┘
│  speed!      │            │  machine code│
└──────────────┘            └──────────────┘
```

## 4.3 The Verifier: Why eBPF is Safe

The verifier is the most critical component. It statically analyses every possible execution path of your BPF program and rejects it if any path could:

| Rule | Why |
|------|-----|
| No infinite loops | Kernel code must complete in bounded time |
| No out-of-bounds memory access | Prevents kernel memory corruption |
| No uninitialized reads | Prevents information leaks |
| No unreachable code | Ensures program is well-formed |
| Max 1M instructions (Linux 5.2+) | Prevents overly complex programs |
| No floating-point operations | FPU state is not saved in kernel context |
| All memory accesses must be bounds-checked | Verifier tracks pointer ranges |

**Practical impact on our code:** Every pointer dereference must be preceded by a bounds check:

```c
// WRONG — verifier will reject this:
struct iphdr *iph = data + sizeof(struct ethhdr);
__u32 src = iph->saddr;  // ← Might read past packet end!

// CORRECT — explicit bounds check:
struct iphdr *iph = data + sizeof(struct ethhdr);
if ((void *)(iph + 1) > data_end)  // ← "Is there room for an IP header?"
    return XDP_PASS;               // ← If not, bail out safely
__u32 src = iph->saddr;            // ← Now the verifier knows this is safe
```

## 4.4 eBPF Maps: Kernel↔Userspace Communication

Maps are the shared data structures between the kernel-space BPF program and the userspace controller. Think of them as a database that both sides can read and write.

### Map Types We Use

**1. `BPF_MAP_TYPE_PERCPU_HASH` — Flow Statistics**

```
Purpose: Track per-source-IP counters without locking.

"Per-CPU" means each CPU core has its own copy of the value.
When userspace reads it, it gets an array of values (one per CPU)
and must sum them.

Why per-CPU? On a multi-core machine, if two CPUs process packets
from the same IP simultaneously, they'd need a lock to safely
update shared counters. Locks are extremely expensive in the
kernel's fast path. Per-CPU maps eliminate this entirely.

  CPU 0: flow_stats[10.0.0.1] = {pkts: 50, bytes: 3000, ...}
  CPU 1: flow_stats[10.0.0.1] = {pkts: 30, bytes: 1800, ...}
  CPU 2: flow_stats[10.0.0.1] = {pkts: 20, bytes: 1200, ...}
  
  Go controller reads → aggregates → {pkts: 100, bytes: 6000, ...}
```

**2. `BPF_MAP_TYPE_PERCPU_ARRAY` — Global Counters**

```
Purpose: Overall throughput statistics (total pkts, bytes, drops).

An array with a single key (0) — simpler than a hash map.
Also per-CPU for the same locking reason.
```

**3. `BPF_MAP_TYPE_HASH` — Blacklist**

```
Purpose: Source IPs that should be dropped by XDP.

NOT per-CPU because:
  - Written by userspace (Go controller), read by kernel (XDP)
  - Updates are infrequent (only when ML detects an attack)
  - A regular hash with atomic operations is sufficient
```

### How Map Operations Work in C (Kernel Side)

```c
// LOOKUP: Get the value for a key
struct flow_counters *counters = bpf_map_lookup_elem(&flow_stats, &key);
if (counters) {
    // Key exists — update in place
    counters->pkt_count++;
} else {
    // Key doesn't exist — create new entry
    struct flow_counters new = { .pkt_count = 1 };
    bpf_map_update_elem(&flow_stats, &key, &new, BPF_ANY);
}
```

### How Map Operations Work in Go (Userspace)

```go
// ITERATE: Walk through all entries
var key FlowKey
var values []FlowCounters   // one per CPU

iter := flowStatsMap.Iterate()
for iter.Next(&key, &values) {
    // Aggregate across CPUs
    total := aggregate(values)
    fmt.Printf("IP %s: %d packets\n", Uint32ToIP(key.SrcIP), total.PktCount)
}
```

## 4.5 XDP Action Codes

When the XDP program finishes processing a packet, it returns one of:

```
┌─────────────────────────────────────────────────────────────┐
│                        XDP ACTIONS                          │
├─────────────┬───────────────────────────────────────────────┤
│  XDP_DROP   │ Discard the packet immediately.               │
│             │ Zero overhead — packet never enters the stack. │
│             │ WE USE THIS for blacklisted IPs.               │
├─────────────┼───────────────────────────────────────────────┤
│  XDP_PASS   │ Hand packet to the normal kernel stack.        │
│             │ This is the "do nothing" default.               │
│             │ WE USE THIS for normal/unclassified traffic.   │
├─────────────┼───────────────────────────────────────────────┤
│  XDP_TX     │ Bounce the packet back out the same NIC.       │
│             │ Useful for sending ICMP unreachable replies.    │
│             │ We don't use this.                              │
├─────────────┼───────────────────────────────────────────────┤
│  XDP_REDIRECT│ Send packet to a different NIC or CPU.        │
│             │ Used with AF_XDP for zero-copy to userspace.   │
│             │ Advanced — not needed for this thesis.          │
└─────────────┴───────────────────────────────────────────────┘
```

## 4.6 XDP Attachment Modes

```
┌─────────────────────────────────────────────────────────────┐
│                    XDP MODES                                │
├───────────────┬─────────────────────────────────────────────┤
│  Native       │ Best performance. BPF runs inside the NIC   │
│  (Driver)     │ driver. Requires driver support.             │
│               │ Supported: Intel (ixgbe, i40e, ice),        │
│               │            Mellanox (mlx4, mlx5)             │
├───────────────┼─────────────────────────────────────────────┤
│  Generic      │ Works on ANY NIC. BPF runs in the kernel's  │
│  (SKB)        │ networking stack (after sk_buff allocation). │
│               │ Slower but universally compatible.            │
│               │ Good for testing in VMs.                      │
├───────────────┼─────────────────────────────────────────────┤
│  Offloaded    │ BPF runs on the NIC hardware itself.         │
│  (HW)         │ Fastest possible but requires SmartNICs      │
│               │ (Netronome). Rare and expensive.              │
└───────────────┴─────────────────────────────────────────────┘
```

For this thesis, **Generic mode** is sufficient for testing. In production, Native mode on an Intel NIC would be used.

---

# Chapter 5: Machine Learning Foundations

## 5.1 What is Classification?

Classification is the task of assigning a **label** to an input based on learned patterns.

```
Input (Feature Vector):                Output (Label):
[pkt_count=5000, syn_count=4990, ...]  →  "Attack" (1)
[pkt_count=10, syn_count=2, ...]       →  "Benign" (0)
```

Our system performs **binary classification**: every source IP in a time window is classified as either Benign (0) or Attack (1).

## 5.2 Features, Labels, and Training

**Feature** = A measurable property of the input. Our 10 features are numerical measurements of network traffic.

**Label** = The correct answer (ground truth). In the CIC-DDoS2019 dataset, each flow is labelled as "BENIGN" or a specific attack type.

**Training** = The process of showing the model millions of (features, label) pairs so it learns the patterns:

```
TRAINING DATA
─────────────────────────────────────────────────────────────
| pkt_count | byte_count | syn_count | ... | label    |
|-----------|------------|-----------|-----|----------|
|     5     |    2000    |     1     | ... | Benign   |
|  50000    |  3000000   |  49900    | ... | SYN Flood|
|    20     |    8000    |     5     | ... | Benign   |
|  80000    |  5000000   |     0     | ... | UDP Flood|
─────────────────────────────────────────────────────────────
                      │
                      ▼
               ┌─────────────┐
               │  ML Algorithm│
               │  (XGBoost)   │
               └──────┬──────┘
                      │
                      ▼
               ┌─────────────┐
               │ Trained Model│ ← This is what we export to ONNX
               └─────────────┘
```

## 5.3 Decision Trees: The Building Block

A Decision Tree is a series of **if-else** questions that split data:

```
                    ┌─────────────────────────┐
                    │  SYN/ACK Ratio > 10?    │
                    └───────────┬─────────────┘
                       YES /         \ NO
                      /               \
           ┌──────────────┐    ┌──────────────┐
           │ Pkt Count    │    │ Flow Duration │
           │  > 1000?     │    │  > 60s?       │
           └──────┬───────┘    └──────┬────────┘
            YES /    \ NO       YES /    \ NO
               /      \           /       \
         ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
         │ ATTACK │ │ ATTACK │ │BENIGN  │ │BENIGN  │
         │ (0.95) │ │ (0.60) │ │ (0.85) │ │ (0.99) │
         └────────┘ └────────┘ └────────┘ └────────┘
```

**Why trees are "lightweight":**
- Inference is just a series of comparisons: `if x > threshold then go left else go right`.
- No matrix multiplication (unlike neural networks).
- Inference time is proportional to tree depth, not data size.
- A tree of depth 10 requires at most 10 comparisons — nanoseconds on modern CPUs.

### How Trees Split: Gini Impurity

The tree decides *where* to split by minimising **Gini Impurity**:

$$\text{Gini}(S) = 1 - \sum_{i=1}^{C} p_i^2$$

Where $p_i$ is the proportion of class $i$ in set $S$.

**Example:**

```
Before split: 100 samples (50 Benign, 50 Attack)
  Gini = 1 - (0.5² + 0.5²) = 1 - 0.5 = 0.5 (maximum impurity)

After splitting on "SYN Count > 100":
  Left child:  60 samples (5 Benign, 55 Attack)
    Gini = 1 - (0.083² + 0.917²) = 1 - 0.847 = 0.153
  Right child: 40 samples (45 Benign, 5 Attack)  [wait, doesn't add up]
  
  Actually:
  Left:  55 Attack + 5 Benign = 60 samples
    Gini = 1 - ((55/60)² + (5/60)²) = 0.153
  Right: 45 Benign + 0 Attack = 45 samples (net from 50-5=45)
    Gini = 1 - ((45/45)²) = 0.0 (pure!)
  
  This split is excellent because the right child is perfectly pure.
```

The algorithm tries every feature and every threshold, selecting the split that reduces impurity the most.

## 5.4 Overfitting vs. Underfitting

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  Accuracy                                                    │
│     ▲                                                        │
│     │         ╱─────────── Training accuracy                 │
│     │        ╱    ╲                                          │
│     │       ╱      ╲──────────── Test accuracy               │
│     │      ╱        ╲                                        │
│     │     ╱          ╲                                       │
│     │    ╱            ╲                                      │
│     │   ╱              ╲                                     │
│     │──┼────────────────┼──▶ Model Complexity                │
│     │  │   SWEET SPOT   │                                    │
│     │  │                │                                    │
│     │  Underfitting     Overfitting                           │
│     │  (too simple)     (memorises noise)                     │
└──────────────────────────────────────────────────────────────┘
```

- **Underfitting:** Model is too simple. A single decision stump can't capture the complexity of DDoS patterns.
- **Overfitting:** Model is too complex. It memorises the training data (including noise) and fails on new data. A tree of depth 100 on a dataset of 1000 samples will overfit.
- **Sweet spot:** The model captures real patterns but ignores noise. Achieved through regularisation (limiting tree depth, minimum samples per leaf).

## 5.5 Evaluation Metrics

### Why Accuracy Alone is Misleading

Imagine a network where 99.9% of traffic is benign and 0.1% is attack:

```
Stupid Model: "Everything is BENIGN"
  Accuracy = 99.9%  ← Looks great!
  But it NEVER detects a single attack. Useless.
```

This is the **class imbalance problem**, and it's why we need better metrics.

### The Confusion Matrix

```
                        PREDICTED
                    Benign    Attack
                  ┌──────────┬──────────┐
    ACTUAL Benign │    TN     │    FP    │
                  │ (correct) │ (false   │
                  │           │  alarm)  │
                  ├──────────┼──────────┤
    ACTUAL Attack │    FN     │    TP    │
                  │ (missed   │(correct  │
                  │  attack!) │detection)│
                  └──────────┴──────────┘
```

| Cell | Meaning | Impact |
|------|---------|--------|
| **TN** (True Negative) | Correctly identified benign | Good — no disruption |
| **TP** (True Positive) | Correctly identified attack | Good — attack stopped |
| **FP** (False Positive) | Benign flagged as attack | Bad — legitimate user blocked |
| **FN** (False Negative) | Attack flagged as benign | Very Bad — attack gets through |

### Key Metrics

**Precision** — "Of all the alerts I raised, how many were real attacks?"

$$\text{Precision} = \frac{TP}{TP + FP}$$

High precision = few false alarms. Important for operator trust.

**Recall (Sensitivity)** — "Of all real attacks, how many did I catch?"

$$\text{Recall} = \frac{TP}{TP + FN}$$

High recall = few missed attacks. Important for security.

**F1-Score** — Harmonic mean of Precision and Recall:

$$F_1 = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

F1 is our primary metric because it balances both concerns.

**False Positive Rate (FPR)** — "Of all benign traffic, how much did I wrongly block?"

$$FPR = \frac{FP}{FP + TN}$$

Target: < 0.1%. Blocking legitimate users is unacceptable.

### ROC and Precision-Recall Curves

```
ROC Curve                          Precision-Recall Curve
(Receiver Operating Characteristic)

  TPR (Recall)                      Precision
    ▲                                  ▲
  1 │    ╱────── Perfect              1 │──────╲
    │   ╱                              │       ╲
    │  ╱  ← Our model                 │        ╲ ← Our model
    │ ╱                                │         ╲
    │╱                                 │          ╲
  0 └──────────▶ FPR                 0 └──────────▶ Recall
    0           1                      0           1

  AUC (Area Under Curve):             AP (Average Precision):
    1.0 = Perfect                       1.0 = Perfect
    0.5 = Random guessing               Baseline = positive class ratio
```

## 5.6 Class Imbalance and SMOTE

### The Problem

In real network traffic, attacks might be 1% of all flows. In attack-specific datasets, benign traffic might be underrepresented. Either way, the model becomes biased toward the majority class.

### SMOTE (Synthetic Minority Over-sampling Technique)

SMOTE creates **synthetic** examples of the minority class by interpolating between existing examples:

```
Original minority class:        After SMOTE:
    •                               •   ◦
      •                           ◦   •   ◦
        •                       ◦       •
                                  ◦   ◦
                                
Legend: • = original samples, ◦ = synthetic samples
```

**Algorithm:**
1. For each minority sample, find its $k$ nearest neighbours (default $k=5$).
2. Randomly select one neighbour.
3. Create a new sample at a random point on the line between the original and the neighbour.

```python
# Pseudo-code
new_sample = original + random(0,1) × (neighbour - original)
```

**Why not just duplicate?** Simple duplication (oversampling) causes the model to memorise specific examples. SMOTE creates *new* examples in the feature space, improving generalisation.

---

# Chapter 6: Ensemble Methods and Gradient Boosting

## 6.1 Why Single Trees Aren't Enough

A single decision tree is fast but has high variance — small changes in training data can produce very different trees. **Ensemble methods** combine multiple trees to reduce this variance.

## 6.2 Random Forest: Bagging

Random Forest builds $N$ independent trees and averages their predictions:

```
Training Data
      │
      ├──── Bootstrap Sample 1 ──▶ Tree 1 ──▶ "Attack"
      │     (random subset)
      ├──── Bootstrap Sample 2 ──▶ Tree 2 ──▶ "Benign"
      │     (random subset)
      ├──── Bootstrap Sample 3 ──▶ Tree 3 ──▶ "Attack"
      │     (random subset)
      └──── Bootstrap Sample N ──▶ Tree N ──▶ "Attack"
                                                  │
                                      MAJORITY VOTE
                                                  │
                                          Final: "Attack"
```

**Key innovations:**
- **Bootstrap sampling:** Each tree trains on a random subset (with replacement) of the data.
- **Feature randomness:** At each split, only a random subset of features is considered.
- **Parallel:** Trees are independent → can train and predict simultaneously.

**Strengths:**
- Very resistant to overfitting.
- Implicit feature importance (how often each feature is used for splits).
- No need for feature scaling.

**Weaknesses:**
- All trees have the same weight — a bad tree has equal influence as a good one.
- Trees don't learn from each other's mistakes.

## 6.3 Gradient Boosting: Learning from Mistakes

Instead of building trees independently, Gradient Boosting builds them **sequentially**, where each new tree corrects the errors of the previous ones:

```
Step 1: Train Tree 1 on original data
        Prediction: ŷ₁
        Error: e₁ = y - ŷ₁   (residuals)

Step 2: Train Tree 2 on the ERRORS (e₁)
        Prediction: ŷ₂
        Combined: ŷ₁ + η·ŷ₂  (η = learning rate)
        Error: e₂ = y - (ŷ₁ + η·ŷ₂)

Step 3: Train Tree 3 on the new errors (e₂)
        ...

Final: ŷ = ŷ₁ + η·ŷ₂ + η·ŷ₃ + ... + η·ŷₙ
```

**The learning rate ($\eta$)** controls how much each tree contributes:
- Small $\eta$ (0.01–0.1): Slow learning, needs more trees, but generalises better.
- Large $\eta$ (0.3–1.0): Fast learning, fewer trees needed, but risks overfitting.

## 6.4 XGBoost: Extreme Gradient Boosting

XGBoost (Chen & Guestrin, 2016) is an optimised implementation of gradient boosting with several key innovations:

### Regularised Objective Function

$$\mathcal{L} = \sum_{i=1}^{n} l(y_i, \hat{y}_i) + \sum_{k=1}^{K} \Omega(f_k)$$

Where:
- $l$ = loss function (how wrong the prediction is)
- $\Omega(f_k) = \gamma T + \frac{1}{2}\lambda \|w\|^2$ = regularisation term
- $T$ = number of leaves in tree $k$
- $w$ = leaf weights
- $\gamma$ = penalty for each additional leaf (encourages simpler trees)
- $\lambda$ = L2 regularisation on leaf weights

This prevents overfitting by penalising complex trees.

### System-Level Optimisations

```
┌──────────────────────────────────────────────────────────────┐
│  Why XGBoost is fast:                                        │
│                                                              │
│  1. Cache-aware access patterns                              │
│     → Data sorted for sequential memory access               │
│     → Exploits CPU cache lines (avoid random memory jumps)   │
│                                                              │
│  2. Histogram-based splitting                                │
│     → Instead of trying every possible threshold,            │
│       bin continuous features into ~256 buckets              │
│     → Reduces split candidates from millions to 256          │
│                                                              │
│  3. Parallel tree construction                               │
│     → Feature-level parallelism: different threads           │
│       evaluate different features simultaneously             │
│                                                              │
│  4. Out-of-core computing                                    │
│     → Can train on datasets larger than RAM                  │
│     → Streams data from disk in compressed blocks            │
└──────────────────────────────────────────────────────────────┘
```

### Key Hyperparameters

| Parameter | Meaning | Our Range |
|-----------|---------|-----------|
| `n_estimators` | Number of boosting rounds (trees) | 100–300 |
| `max_depth` | Maximum depth per tree | 4–8 |
| `learning_rate` | Step size shrinkage ($\eta$) | 0.05–0.2 |
| `subsample` | Fraction of training data per tree | 0.8–1.0 |
| `colsample_bytree` | Fraction of features per tree | 0.8–1.0 |
| `gamma` | Min loss reduction for a split | 0–5 |
| `reg_lambda` | L2 regularisation | 1.0 |

## 6.5 LightGBM: Leaf-Wise Growth

LightGBM (Ke et al., 2017) is an alternative gradient boosting implementation with a different tree growth strategy:

```
XGBoost: Level-wise growth          LightGBM: Leaf-wise growth
(balanced, slower)                  (deeper on important splits, faster)

        ┌───┐                              ┌───┐
      ┌─┤   ├─┐                          ┌─┤   ├─┐
      │ └───┘ │                          │ └───┘ │
    ┌─┴─┐ ┌─┴─┐                       ┌─┴─┐   ┌┴─┐
    │   │ │   │  ← Grows ALL           │   │   │  │
    └─┬─┘ └─┬─┘    leaves at           └─┬─┘   └──┘
   ┌──┴┐ ┌─┴─┐    each level         ┌──┴──┐
   │   │ │   │                        │     │  ← Grows the LEAF
   └───┘ └───┘                        └──┬──┘    with highest
                                      ┌──┴──┐    loss reduction
                                      │     │
                                      └─────┘
```

**Leaf-wise** often converges faster (needs fewer iterations) but risks overfitting on small datasets because it creates deeper, more asymmetric trees.

## 6.6 Comparison for This Thesis

| Aspect | Random Forest | XGBoost | LightGBM |
|--------|--------------|---------|----------|
| Tree building | Independent (parallel) | Sequential (boosted) | Sequential (boosted) |
| Growth strategy | Level-wise | Level-wise | Leaf-wise |
| Speed (training) | Fast (embarrassingly parallel) | Medium | Fastest |
| Speed (inference) | Medium (query all trees) | Fast (early stopping) | Fast |
| Overfitting risk | Low | Medium (regularised) | Higher (needs tuning) |
| Interpretability | Good (feature importance) | Good (SHAP values) | Good |
| **Recommended for thesis** | Baseline | **Primary choice** | Alternative |

---

# Chapter 7: Feature Engineering for Network Traffic

## 7.1 What is Feature Engineering?

Feature engineering transforms raw data (packets) into meaningful numerical inputs for the ML model. Good features make even simple models powerful; bad features make even complex models fail.

## 7.2 The "Lightweight 10" — Detailed Walkthrough

### Feature 1: Packet Count

```
What:  Number of packets from a source IP in one polling interval.
Where: Counted in eBPF via atomic increment.
Why:   Volumetric attacks send orders of magnitude more packets than
       normal connections.

Normal web browsing: ~5-50 packets per 500ms
SYN flood:           ~5,000-50,000 packets per 500ms
```

### Feature 2: Byte Count

```
What:  Total bytes from a source IP in one polling interval.
Where: Accumulated in eBPF: counters->byte_count += pkt_len
Why:   Amplification attacks generate massive byte volumes.
       A DNS amplification source sends ~67× more bytes than it receives.
```

### Feature 3: SYN Flag Count

```
What:  Number of TCP packets with the SYN flag set.
Where: In eBPF: if (tcph->syn) counters->syn_count++
Why:   SYN floods are the most common L4 attack. Normal traffic
       has 1 SYN per connection. An attack has thousands of SYNs
       with no corresponding ACKs.
```

### Feature 4: ACK Flag Count

```
What:  Number of TCP packets with the ACK flag set.
Where: In eBPF: if (tcph->ack) counters->ack_count++
Why:   Used in combination with SYN Count to compute the ratio.
       Also detects ACK floods (less common but still relevant).
```

### Feature 5: SYN/ACK Ratio

```
What:  syn_count / max(ack_count, 1)
Where: Computed in Go userspace (division is expensive in kernel).
Why:   The most powerful single indicator for SYN floods.

       Normal TCP session:
         1 SYN + many ACKs → ratio ≈ 0.01-0.1
       
       SYN flood:
         10000 SYNs + 0 ACKs → ratio = 10000
         (We cap at syn_count when ack_count = 0)
```

### Feature 6: Packet Size Mean

```
What:  byte_count / pkt_count
Where: Computed in Go.
Why:   Attack tools send uniform packet sizes. Botnet SYN packets
       are always 40-60 bytes. Normal traffic has varied sizes
       (small ACKs, medium requests, large downloads).

       SYN flood:     mean ≈ 40-60 bytes (just headers)
       DNS amplification: mean ≈ 400-4000 bytes (large responses)
       Normal browsing:   mean ≈ 200-800 bytes (mixed)
```

### Feature 7: Packet Size Variance

```
What:  Var(packet_sizes) = E[X²] - (E[X])²
Where: Kernel stores Σ(size²) as pkt_size_sum_sq.
       Go computes: (pkt_size_sum_sq / pkt_count) - (byte_count / pkt_count)²

Why:   Low variance = automated tool (identical packets).
       High variance = human behaviour (mixed content types).

The "Welford trick" for computing variance without storing
all individual values:

  In kernel (integer only):
    sum_x  += pkt_len          // running sum
    sum_x2 += pkt_len * pkt_len // running sum of squares

  In userspace (floating point):
    mean = sum_x / n
    variance = (sum_x2 / n) - mean²
```

### Feature 8: Flow Duration

```
What:  (last_seen_ns - first_seen_ns) / 1,000,000,000  (seconds)
Where: Kernel stores timestamps via bpf_ktime_get_ns().
       Go converts to seconds.

Why:   Attack flows are either very short (one burst) or
       indefinitely long (connection exhaustion).
       Normal flows have natural durations based on web page loads,
       file downloads, etc.
```

### Feature 9: Protocol Entropy (Shannon Entropy)

```
What:  How "random" is the protocol distribution from this source?
Where: Kernel counts: tcp_count, udp_count, icmp_count, other_count
       Go computes Shannon Entropy.

Formula:
  H = -Σ p_i × log₂(p_i)
  
  where p_i = count_i / total_count for each protocol

Examples:
  Source sends ONLY TCP packets:
    p_TCP=1.0, p_UDP=0, p_ICMP=0, p_Other=0
    H = -(1.0 × log₂(1.0)) = 0 bits  ← SUSPICIOUS (single protocol)
  
  Source sends 50% TCP, 50% UDP:
    H = -(0.5 × log₂(0.5) + 0.5 × log₂(0.5))
    H = -(0.5 × (-1) + 0.5 × (-1))
    H = 1.0 bit  ← Normal (mixed protocols)
  
  Source sends 25% each:
    H = -(4 × 0.25 × log₂(0.25))
    H = -(4 × 0.25 × (-2))
    H = 2.0 bits  ← Maximum diversity

Maximum entropy = log₂(number of categories) = log₂(4) = 2 bits

A botnet node running a SYN flood sends ONLY TCP → entropy = 0.
A normal user browses (TCP), does DNS lookups (UDP), and sometimes
pings (ICMP) → entropy > 0.
```

### Feature 10: Inter-Arrival Time (IAT) Mean

```
What:  Average time between consecutive packets from the same source.
Where: Kernel accumulates: iat_sum_ns += (now - last_seen_ns)
       Go computes: iat_sum_ns / (pkt_count - 1), converted to µs.

Why:   Machine-generated traffic has extremely regular,
       microsecond-scale IAT. Human traffic has irregular,
       millisecond-to-second-scale IAT.

       Bot (SYN flood at 10kpps): IAT ≈ 100 µs (very consistent)
       Human (web browsing):      IAT ≈ 50,000-500,000 µs (variable)
```

## 7.3 Feature Normalisation: Min-Max Scaling

ML models work best when all features are on the same scale. Without normalisation, a feature like `byte_count` (range: 0–10,000,000) would dominate `syn_ack_ratio` (range: 0–100).

**Min-Max Scaling** transforms each feature to [0, 1]:

$$x_{scaled} = \frac{x - x_{min}}{x_{max} - x_{min}}$$

**Critical rule:** Fit the scaler on training data only. Apply the same parameters to test data and production inference. Our system saves scaler parameters to `scaler_params.json`.

---

# Chapter 8: Data Structures for High-Speed Networking

## 8.1 Hash Maps: O(1) Lookup

Our primary data structure in eBPF is a hash map keyed by source IP.

```
Key:   Source IP (32 bits = 4 bytes)
Value: FlowCounters struct (104 bytes)

Operation:
  hash(src_ip) → bucket_index → linked list → find entry

Time complexity:
  Lookup:  O(1) average, O(n) worst case (all keys collide)
  Insert:  O(1) average
  Delete:  O(1) average
```

**Hash collision:** When two different keys map to the same bucket. The eBPF hash map handles this internally with linked lists. With a good hash function and sufficient map size (65,536 entries), collisions are rare.

**Memory usage:**
```
Per entry: 4 bytes (key) + 104 bytes (value) + ~16 bytes (overhead) ≈ 124 bytes
Max entries: 65,536
Total: 65,536 × 124 ≈ 7.9 MB

With per-CPU maps on 8 cores: 7.9 MB × 8 = ~63 MB
This is fine for modern servers.
```

## 8.2 The Spoofed IP Problem

When an attacker spoofs random source IPs, our hash map may overflow:

```
Attacker sends packets with source IPs:
  1.1.1.1, 2.2.2.2, 3.3.3.3, ..., N.N.N.N

If N > 65,536 (our map size), new entries fail to insert.
We lose visibility into some attackers.
```

**Solutions:**
1. **Increase map size** — but more memory = higher cost.
2. **LRU eviction** — remove the least recently seen IP to make room (risks losing important entries).
3. **Probabilistic data structures** — Count-Min Sketch (see below).

## 8.3 Count-Min Sketch: Bounded Memory for Unbounded Flows

A Count-Min Sketch (CMS) is a probabilistic data structure that estimates flow frequency using fixed memory, regardless of how many unique flows exist.

```
Structure: d hash functions × w counters (2D array)

    hash₁  hash₂  hash₃  ... hashd
     │       │       │          │
     ▼       ▼       ▼          ▼
  ┌──┬──┬──┬──┬──┬──┬──┬──┬──┬──┐  ← Row 1 (w counters)
  │ 0│ 5│ 0│ 0│ 3│ 0│ 2│ 0│ 0│ 1│
  ├──┼──┼──┼──┼──┼──┼──┼──┼──┼──┤  ← Row 2
  │ 0│ 0│ 3│ 0│ 0│ 5│ 0│ 0│ 2│ 0│
  ├──┼──┼──┼──┼──┼──┼──┼──┼──┼──┤  ← Row 3
  │ 2│ 0│ 0│ 5│ 0│ 0│ 0│ 3│ 0│ 0│
  └──┴──┴──┴──┴──┴──┴──┴──┴──┴──┘

INSERT(IP):
  For each row i: increment counter at position hash_i(IP) % w

QUERY(IP):
  For each row i: read counter at position hash_i(IP) % w
  Return MINIMUM across all rows
  (minimum reduces overcount from collisions)
```

**Properties:**
- Memory: $O(d \times w)$ — fixed regardless of unique IPs.
- Never underestimates: always returns count ≥ true count.
- May overestimate: probability of error decreases with more rows ($d$).

**Example sizing for our system:**
```
d = 4 hash functions
w = 16,384 counters per row
Counter size = 8 bytes (uint64)

Memory = 4 × 16,384 × 8 = 512 KB

This can track millions of unique IPs in only 512 KB,
vs. 63 MB for the hash map approach.
```

## 8.4 Bloom Filters: Set Membership Testing

A Bloom Filter answers the question: "Have I seen this IP before?" with guaranteed no false negatives but possible false positives.

```
Structure: bit array of m bits + k hash functions

INSERT(IP):  Set bits at hash₁(IP), hash₂(IP), ..., hashₖ(IP)

QUERY(IP):   Check bits at hash₁(IP), hash₂(IP), ..., hashₖ(IP)
             If ALL are 1 → "Probably yes" (might be false positive)
             If ANY is 0  → "Definitely no"
```

**Use case in our system:** The blacklist could use a Bloom filter for an even faster check than a hash map lookup. However, since we need to store TTL information per entry, the hash map is more practical.

---

# Chapter 9: ONNX and Cross-Language Model Deployment

## 9.1 The Problem: Train in Python, Infer in Go

```
TRAINING (Python)                        INFERENCE (Go)
┌────────────────────┐                  ┌────────────────────┐
│ - Rich ecosystem   │                  │ - Fast, compiled   │
│ - scikit-learn     │                  │ - Low-level eBPF   │
│ - XGBoost          │     HOW?         │   integration      │
│ - pandas, numpy    │ ──────────────▶  │ - Goroutines       │
│ - Easy prototyping │                  │ - No Python GIL    │
│ - Slow inference   │                  │ - Production-ready │
└────────────────────┘                  └────────────────────┘
```

**Answer:** ONNX (Open Neural Network Exchange).

## 9.2 What is ONNX?

ONNX is an **open standard format** for ML models. It defines a common set of operators (add, multiply, comparison, tree traversal, etc.) that any runtime can execute.

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│   Python     │   │     ONNX     │   │ ONNX Runtime │
│              │   │              │   │              │
│  XGBoost     │──▶│  model.onnx  │──▶│  C++ Engine  │──▶ Prediction
│  .fit(X, y)  │   │  (portable)  │   │  (any lang)  │
│              │   │              │   │              │
└──────────────┘   └──────────────┘   └──────────────┘
   Training         Serialisation       Inference
   (one-time)       (file format)       (real-time)
```

## 9.3 The ONNX Graph

Inside `model.onnx`, the model is stored as a **computation graph**:

```
For a Decision Tree:

  Input: features [1, 10]
     │
     ▼
  ┌─────────────────────┐
  │  TreeEnsembleClassifier  │
  │  - node thresholds  │
  │  - node feature IDs │
  │  - leaf weights     │
  │  - tree structure   │
  └──────────┬──────────┘
             │
     ┌───────┴────────┐
     ▼                ▼
  labels [1]     probabilities [1, 2]
  (0 or 1)      ([P(benign), P(attack)])
```

For XGBoost, the graph contains the entire ensemble (all boosted trees) serialised as a single `TreeEnsembleClassifier` operator.

## 9.4 ONNX Runtime: The Inference Engine

ONNX Runtime (by Microsoft) is a high-performance inference engine:

```
Optimisations:
  1. Graph optimisation: fuse operations, eliminate redundant nodes
  2. Kernel selection: choose the fastest implementation for the hardware
  3. Memory planning: pre-allocate I/O tensors to avoid runtime allocation
  4. Thread pooling: parallelise independent operations
```

In our Go controller:
```
Load model once at startup → session = NewSession("model.onnx")
                                │
For each polling cycle:         │
  Build feature vector          │
  session.Run(features) ──────▶ │ ← ~5-50 µs per sample
  Read output probability       │
  Make decision                 │
```

## 9.5 Export Pipeline

```
Python training:
  model = XGBClassifier()
  model.fit(X_train, y_train)
       │
       ▼
  from skl2onnx import convert_sklearn
  onnx_model = convert_sklearn(
      model,
      initial_types=[("features", FloatTensorType([None, 10]))]
  )
       │
       ▼
  onnx.save(onnx_model, "model.onnx")
       │
       ▼
  Verify: compare Python and ONNX predictions
  assert (python_pred == onnx_pred).all()
```

---

# Chapter 10: System Integration — Putting It All Together

## 10.1 The Complete Data Flow

```
TIME ─────────────────────────────────────────────────────────────▶

t=0ms        t=0.001ms     t=250ms       t=500ms      t=500.05ms
  │             │              │             │              │
  │  Packet     │  XDP         │  More       │  Go polls    │  ONNX
  │  arrives    │  updates     │  packets    │  eBPF maps   │  inference
  │  at NIC     │  flow_stats  │  arrive     │              │
  ▼             ▼              ▼             ▼              ▼

  ┌──────┐   ┌──────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
  │ Wire │──▶│ XDP  │──▶│ eBPF Map │──▶│ Go reads │──▶│ ONNX     │
  │      │   │ prog │   │ accumul. │   │ + compute│   │ predict  │
  └──────┘   └──────┘   └──────────┘   │ features │   └────┬─────┘
                                        └──────────┘        │
                                                            ▼
  t=500.1ms       t=500.2ms                          ┌──────────┐
       │               │                             │ Score >  │
       │  Alert        │  Blacklist                  │ 0.85?    │
       │  logged       │  updated                    └────┬─────┘
       ▼               ▼                                  │
  ┌──────────┐   ┌──────────┐                     YES ─┘  └── NO
  │ Log/     │   │ XDP now  │                     │          │
  │ Webhook  │   │ drops    │                     ▼          ▼
  │ InfluxDB │   │ this IP  │                  (action)   (ignore)
  └──────────┘   └──────────┘
```

## 10.2 Latency Budget

```
┌──────────────────────────────────────────────────────────────┐
│                    2-SECOND BUDGET                            │
│                                                              │
│  ┌─────────────────────────────────────┐                     │
│  │ Polling interval: 500ms             │ ← Dominant factor   │
│  │ (configurable: 200ms-1000ms)        │                     │
│  └─────────────────────────────────────┘                     │
│  ┌───────┐                                                   │
│  │ ~50µs │ Feature computation                               │
│  └───────┘                                                   │
│  ┌───────┐                                                   │
│  │ ~50µs │ ONNX inference (per source IP)                    │
│  └───────┘                                                   │
│  ┌───────┐                                                   │
│  │ ~5µs  │ Blacklist map write                               │
│  └───────┘                                                   │
│                                                              │
│  WORST CASE: Attack starts immediately after a poll          │
│    → Detected at next poll: 500ms + ~0.1ms = ~500ms          │
│                                                              │
│  ABSOLUTE WORST CASE: Poll + inference on 65536 IPs          │
│    → 500ms + (65536 × 50µs) = 500ms + 3.3s = 3.8s           │
│    → Mitigated by: batch inference, early termination,       │
│      processing only top-N suspicious IPs                    │
│                                                              │
│  TYPICAL CASE: ~100 unique source IPs                        │
│    → 500ms + (100 × 50µs) = 500ms + 5ms = ~505ms ✓          │
└──────────────────────────────────────────────────────────────┘
```

## 10.3 The Feedback Loop: Detection → Mitigation → Verification

```
                    ┌──────────────────────────┐
                    │      DETECTION CYCLE     │
                    │                          │
                    │  1. Poll maps            │
                    │  2. Compute features     │
                    │  3. Run inference        │
                    │  4. Score > threshold?   │
                    └────────────┬─────────────┘
                                 │
                          YES    │    NO
                          ┌──────┘──────┐
                          ▼             ▼
                    ┌───────────┐  (continue monitoring)
                    │ MITIGATION│
                    │           │
                    │ 1. Log alert
                    │ 2. Add to │
                    │    blacklist
                    │ 3. XDP now│
                    │    DROPs  │
                    └─────┬─────┘
                          │
                          ▼
                    ┌───────────┐
                    │ TTL Timer │
                    │ (60s)     │
                    └─────┬─────┘
                          │
                          ▼
                    ┌───────────┐
                    │ RE-EVALUATE│  ← Is the attack still ongoing?
                    │           │     If yes, re-block.
                    │ Remove    │     If no, the IP is unblocked.
                    │ from      │
                    │ blacklist │
                    └───────────┘
```

## 10.4 Key Design Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Packet processing | XDP (not DPDK) | Kernel-integrated, easier to manage, sufficient performance |
| Map type | Per-CPU Hash | Lock-free, high throughput, bounded memory |
| ML algorithm | XGBoost (not DL) | Fastest inference on tabular data, no GPU needed |
| Model format | ONNX (not pickle) | Cross-language, optimised runtime, portable |
| Controller language | Go (not C/Python) | eBPF library support, goroutines, safe memory |
| Poll interval | 500ms | Balances latency (~500ms worst case) vs CPU usage |
| Feature count | 10 (not 80+) | All extractable in-kernel, proven sufficient accuracy |
| Threshold | 0.85 | Balances FPR (<0.1%) vs detection rate (>99%) |
| Blacklist TTL | 60 seconds | Prevents permanent lockout from false positives |

## 10.5 What to Study Next

Follow this learning path to build the system:

```
Week 1-2: Learn C for BPF
  → Focus: pointers, structs, bitwise operations, header parsing
  → Resource: "Linux Observability with BPF" (O'Reilly)

Week 2-3: Learn Go
  → Focus: goroutines, channels, binary encoding, cilium/ebpf library
  → Resource: "The Go Programming Language" (Donovan & Kernighan)

Week 3-4: Learn Python ML
  → Focus: pandas, scikit-learn, XGBoost, train/test/eval pipeline
  → Resource: "Hands-On Machine Learning" (Géron)

Week 4-5: Learn eBPF/XDP
  → Focus: verifier rules, map types, XDP actions, bpftool
  → Resource: "Learning eBPF" (O'Reilly, Liz Rice)
  → Labs: https://github.com/xdp-project/xdp-tutorial

Week 6+: Build the system
  → Follow the roadmap in docs/roadmap.md
```

---

# Glossary

| Term | Definition |
|------|------------|
| **AUC** | Area Under the ROC Curve — overall classifier quality (1.0 = perfect) |
| **BPF** | Berkeley Packet Filter — VM for running programs in the Linux kernel |
| **Botnet** | Network of compromised machines controlled by an attacker |
| **BTF** | BPF Type Format — metadata that describes kernel data structures |
| **CMS** | Count-Min Sketch — probabilistic frequency estimation structure |
| **DDoS** | Distributed Denial of Service — attack from many sources |
| **DMA** | Direct Memory Access — hardware copies data to RAM without CPU |
| **eBPF** | Extended BPF — modern, programmable kernel VM |
| **F1** | Harmonic mean of Precision and Recall |
| **FPR** | False Positive Rate — fraction of benign traffic incorrectly blocked |
| **Gini** | Gini Impurity — measure of class mixing used for tree splits |
| **IAT** | Inter-Arrival Time — time gap between consecutive packets |
| **IRQ** | Interrupt Request — hardware signal to CPU |
| **JIT** | Just-In-Time compilation — BPF bytecode → native machine code |
| **LRU** | Least Recently Used — eviction policy for bounded caches |
| **MPPS** | Million Packets Per Second — throughput metric |
| **NIC** | Network Interface Card — hardware that sends/receives packets |
| **ONNX** | Open Neural Network Exchange — portable model format |
| **SHAP** | SHapley Additive exPlanations — feature importance method |
| **sk_buff** | Socket buffer — kernel's internal packet representation |
| **SMOTE** | Synthetic Minority Over-sampling Technique |
| **TCB** | Transmission Control Block — kernel memory for a TCP connection |
| **TSDB** | Time-Series Database — optimised for timestamped data |
| **XDP** | eXpress Data Path — BPF hook at the NIC driver level |
