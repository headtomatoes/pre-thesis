# Architecture Overview

## System Architecture

The DDoS Early Warning System follows a **Split-Plane Architecture** with two distinct execution domains:

### Fast Data Plane (Kernel Space — eBPF/XDP)

The data plane runs inside the Linux kernel at the earliest possible point in the network stack — the NIC driver's receive path. This is achieved through **XDP (eXpress Data Path)**.

```
Packet arrives at NIC
        │
        ▼
┌───────────────────┐
│   XDP Program     │──── XDP_DROP (if blacklisted)
│   (xdp_prog.c)    │
│                   │
│   1. Parse headers│
│   2. Check blacklist
│   3. Update flow  │
│      counters     │
│   4. Update global│
│      counters     │
└───────┬───────────┘
        │ XDP_PASS
        ▼
   Kernel Stack (normal processing)
```

**Key design decisions:**

- **Per-CPU Maps** (`BPF_MAP_TYPE_PERCPU_HASH`): Each CPU core maintains its own copy of the flow counters, eliminating lock contention. The userspace agent aggregates per-CPU values during polling.

- **Integer-only arithmetic**: The eBPF verifier prohibits floating-point operations. All calculations in the kernel (sum of squares for variance, timestamps for IAT) use 64-bit integers. The Go controller performs final floating-point computations.

- **Blacklist with TTL**: Blocked IPs have a Time-To-Live (TTL) after which the XDP program stops dropping their packets. This prevents permanent lockout from false positives.

### Smart Control Plane (User Space — Go)

The control plane runs as a standard userspace process with elevated privileges (CAP_NET_ADMIN, CAP_BPF).

```
┌─────────────────────────────────────────────┐
│              Go Controller                   │
│                                              │
│  ┌────────────┐    Every 500ms               │
│  │ time.Ticker │──────────────┐              │
│  └────────────┘               │              │
│                               ▼              │
│  ┌────────────────────────────────────┐      │
│  │ 1. Poll eBPF Maps                  │      │
│  │    - Iterate flow_stats (per-CPU)  │      │
│  │    - Read global_stats             │      │
│  ├────────────────────────────────────┤      │
│  │ 2. Compute Feature Vectors         │      │
│  │    - Per source IP: 10 features    │      │
│  │    - Variance, entropy in float64  │      │
│  ├────────────────────────────────────┤      │
│  │ 3. ONNX Inference                  │      │
│  │    - Batch predict all source IPs  │      │
│  │    - Score ∈ [0, 1]                │      │
│  ├────────────────────────────────────┤      │
│  │ 4. Decision Logic                  │      │
│  │    - Score > threshold → ALERT     │      │
│  │    - Optionally: write to blacklist│      │
│  ├────────────────────────────────────┤      │
│  │ 5. Telemetry                       │      │
│  │    - Write to InfluxDB             │      │
│  │    - Log to file (JSON-lines)      │      │
│  ├────────────────────────────────────┤      │
│  │ 6. Reset flow counters             │      │
│  └────────────────────────────────────┘      │
│                                              │
└─────────────────────────────────────────────┘
```

## Data Flow

```
  Packet (wire)
      │
      ▼
  XDP Program ──────────────────────────► XDP_DROP (blocked IP)
      │
      │ Updates eBPF Maps:
      │   flow_stats[src_ip] += counters
      │   global_stats[0]    += totals
      │
      ▼
  XDP_PASS → Kernel Stack
      
  ─── meanwhile (every 500ms) ───

  Go Controller
      │
      │ Reads eBPF Maps
      ▼
  Feature Extraction
      │ [pkt_count, byte_count, syn_count, ack_count,
      │  syn_ack_ratio, pkt_size_mean, pkt_size_var,
      │  flow_duration, proto_entropy, iat_mean]
      ▼
  ONNX Runtime (XGBoost model)
      │ score = P(attack)
      ▼
  Decision
      │
      ├── score < threshold → (no action)
      │
      └── score ≥ threshold → Alert + Blacklist
              │
              ├── Write alert to log/webhook
              ├── Write to InfluxDB
              └── Insert src_ip into blacklist map
                      │
                      └── XDP program now drops this IP
```

## Latency Analysis

The end-to-end detection latency is bounded by:

| Component | Latency |
|-----------|---------|
| XDP packet processing | ~1-5 µs |
| Map accumulation | Continuous (no added latency) |
| Polling interval | 500 ms (configurable) |
| Feature computation | ~10-50 µs |
| ONNX inference | ~5-50 µs per sample |
| Blacklist write | ~1-5 µs |
| **Total worst-case** | **~500 ms + inference time** |

The dominant factor is the **polling interval**. With a 500ms poll, the worst-case detection time is ~500ms (if the attack starts just after a poll) to ~1000ms (if the attack starts just before the next poll). This is well within the 2-second target.

## Technology Choices

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Packet processing | XDP/eBPF | Line-rate, kernel-bypass, safe (verified) |
| Language (kernel) | C | Required by BPF compiler |
| Language (userspace) | Go | cilium/ebpf library, goroutines, GC |
| ML framework (train) | Python + XGBoost | Ecosystem, ease of use |
| ML framework (infer) | ONNX Runtime | Cross-language, optimised CPU inference |
| Time-series DB | InfluxDB | Purpose-built TSDB, Grafana integration |
| Dashboard | Grafana | Industry standard, Flux query support |
| BPF library | cilium/ebpf | Production-grade, well-maintained |
