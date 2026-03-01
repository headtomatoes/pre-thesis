# Feature Engineering: The "Lightweight 10"

## Design Principles

The feature set is designed under three constraints:

1. **Extractable in-kernel**: Features must be computable from packet headers using only integer arithmetic (eBPF verifier restriction).
2. **Low memory footprint**: Per-flow state must fit in a bounded eBPF map entry (~104 bytes per source IP).
3. **High discriminative power**: Features must separate benign from malicious traffic with high accuracy.

## Feature Table

| # | Feature | eBPF Kernel | Go Userspace | Formula |
|---|---------|-------------|--------------|---------|
| 1 | **Packet Count** | `atomic_inc(pkt_count)` | Direct read | `pkt_count` |
| 2 | **Byte Count** | `atomic_add(byte_count, pkt_len)` | Direct read | `byte_count` |
| 3 | **SYN Flag Count** | `if (tcp->syn) syn_count++` | Direct read | `syn_count` |
| 4 | **ACK Flag Count** | `if (tcp->ack) ack_count++` | Direct read | `ack_count` |
| 5 | **SYN/ACK Ratio** | — | Computed | `syn_count / max(ack_count, 1)` |
| 6 | **Packet Size Mean** | — | Computed | `byte_count / pkt_count` |
| 7 | **Packet Size Variance** | `pkt_size_sum_sq += len²` | Computed | `E[X²] - (E[X])²` |
| 8 | **Flow Duration** | `first_seen_ns`, `last_seen_ns` | Computed | `(last - first) / 1e9` seconds |
| 9 | **Protocol Entropy** | `tcp_count`, `udp_count`, `icmp_count`, `other` | Computed | `-Σ p_i log₂(p_i)` |
| 10 | **IAT Mean** | `iat_sum_ns += (now - last_seen)` | Computed | `iat_sum / (pkt_count - 1)` µs |

## Feature Descriptions

### 1. Packet Count
**Why it detects DDoS:** Volumetric attacks (UDP flood, ICMP flood) rely on overwhelming the target with a high volume of packets per second. A source IP sending thousands of packets in a 500ms window is anomalous.

**Normal range:** 1–50 packets per 500ms interval  
**Attack range:** 100–10,000+ packets per 500ms interval

### 2. Byte Count
**Why it detects DDoS:** Amplification attacks (DNS, NTP, LDAP) generate large response packets. A single DNS query (~60 bytes) can produce a response of ~4000 bytes, amplifying bandwidth consumption.

**Normal range:** 100–50,000 bytes per interval  
**Attack range:** 100,000–10,000,000+ bytes per interval

### 3. SYN Flag Count
**Why it detects DDoS:** TCP SYN floods exhaust the victim's TCB (Transmission Control Block) memory by initiating thousands of half-open connections. Normal traffic has a balanced SYN/ACK pattern.

### 4. ACK Flag Count
**Why it detects DDoS:** ACK floods and reflective attacks generate high ACK counts. Combined with SYN count, the ratio reveals protocol-level anomalies.

### 5. SYN/ACK Ratio
**Why it detects DDoS:** Normal TCP traffic maintains a roughly 1:1 SYN-to-ACK ratio due to the 3-way handshake. A SYN flood produces a very high ratio (many SYNs, few ACKs) because connections are never completed.

**Normal:** ≈ 1.0  
**SYN Flood:** >> 10.0

### 6. Packet Size Mean
**Why it detects DDoS:** Automated attack tools send packets of uniform size (e.g., minimum 40-byte SYN packets). Legitimate traffic exhibits greater size diversity due to varied application data.

### 7. Packet Size Variance
**Why it detects DDoS:** Low variance indicates machine-generated traffic (bots sending identical packets). High variance indicates human-driven browsing behaviour.

**Implementation note:** Calculated using Welford's decomposition:
- Kernel stores: `Σx` (byte_count) and `Σx²` (pkt_size_sum_sq)
- Userspace computes: `Var = E[X²] - (E[X])² = (Σx²/n) - (Σx/n)²`

### 8. Flow Duration
**Why it detects DDoS:** Attack flows tend to be either very short (single-packet probes) or indefinitely long (connection exhaustion). Normal flows have distinct durations based on application behaviour.

### 9. Protocol Entropy (Shannon)
**Why it detects DDoS:** A legitimate user's traffic spans multiple protocols (TCP for HTTP, UDP for DNS, etc.). A botnet node typically sends only one protocol type, resulting in zero entropy.

**Formula:** `H = -Σ p_i × log₂(p_i)` over {TCP, UDP, ICMP, Other}

| Scenario | Entropy |
|----------|---------|
| Only TCP (SYN flood) | 0.00 bits |
| 50% TCP, 50% UDP | 1.00 bits |
| 25% each (diverse) | 2.00 bits |

### 10. Inter-Arrival Time (IAT) Mean
**Why it detects DDoS:** Machine-generated traffic has extremely low and consistent IAT (microsecond-scale). Human-generated traffic has variable IAT (millisecond to second scale) due to think time, page loading, etc.

**Normal:** 1,000–100,000 µs  
**Attack:** 1–100 µs

## Mapping to CIC-DDoS2019 Columns

For training, these features are mapped from the CIC-DDoS2019 CSV columns:

| Our Feature | CIC-DDoS2019 Column |
|-------------|---------------------|
| Packet Count | `Total Fwd Packets` |
| Byte Count | `Total Length of Fwd Packets` |
| SYN Count | `SYN Flag Count` |
| ACK Count | `ACK Flag Count` |
| SYN/ACK Ratio | Computed: `SYN Flag Count / ACK Flag Count` |
| Pkt Size Mean | `Packet Length Mean` |
| Pkt Size Variance | `Packet Length Variance` |
| Flow Duration | `Flow Duration` |
| Proto Entropy | Approximated from bidirectional ratio |
| IAT Mean | `Flow IAT Mean` |
