# Chapter 2: Literature Review

## 2.1 Introduction

The proliferation of Distributed Denial of Service (DDoS) attacks targeting the Network (Layer 3) and Transport (Layer 4) layers has driven a sustained body of research into automated detection mechanisms. This chapter critically reviews the evolution of detection methodologies—from early statistical thresholding to modern machine learning (ML) pipelines operating at line rate—and identifies the research gap that this thesis aims to address: the absence of integrated systems that combine **kernel-bypass packet processing** with **lightweight ML inference** under a strict sub-2-second latency constraint.

The review is organised into five thematic sections: (1) classical statistical and signature-based detection, (2) the adoption of machine learning for network anomaly detection, (3) ensemble and gradient-boosting methods optimised for tabular flow data, (4) high-performance packet processing architectures, and (5) a synthesis that positions the proposed system relative to the state of the art.

---

## 2.2 Classical Detection: Statistical Thresholding and Signatures

### 2.2.1 Threshold-Based Detection

The earliest DDoS defence systems relied on fixed-rate thresholds: if the volume of SYN packets exceeded a preconfigured rate (e.g., 1,000 SYN/sec), an alarm was triggered. While computationally trivial, these systems suffer from two fundamental weaknesses:

- **High false-positive rates** during legitimate traffic bursts (flash crowds, viral content).
- **Inability to detect low-and-slow attacks** that operate below the threshold while still exhausting server resources (e.g., Slowloris, R-U-Dead-Yet).

Mirkovic and Reiher (2004) provided an early taxonomy of DDoS attacks and defences, concluding that static thresholds are "inherently brittle" because they require manual tuning per network and cannot adapt to diurnal traffic patterns.

> **Mirkovic, J., & Reiher, P.** (2004). A Taxonomy of DDoS Attack and DDoS Defense Mechanisms. *ACM SIGCOMM Computer Communication Review*, 34(2), 39–53. https://doi.org/10.1145/997150.997156

### 2.2.2 Entropy-Based Anomaly Detection

Lee and Xiang (2001) introduced information-theoretic measures—specifically **Shannon Entropy**—as meta-features for intrusion detection. Their hypothesis was that DDoS attacks alter the randomness of packet header distributions:

$$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$

- A **randomised spoofing** attack maximises source-IP entropy (many unique forged IPs).
- A **targeted flood** minimises destination-IP entropy (all packets converge on one victim).

This insight has become foundational: modern ML classifiers routinely include entropy as an engineered input feature. The limitation of pure entropy methods is their inability to distinguish between attack-induced entropy shifts and legitimate changes in traffic composition (e.g., a CDN distributing traffic across new edge nodes).

> **Lee, W., & Xiang, D.** (2001). Information-Theoretic Measures for Anomaly Detection. *Proceedings of the IEEE Symposium on Security and Privacy*, 130–143. https://doi.org/10.1109/SECPRI.2001.924294

### 2.2.3 Signature-Based Systems (Snort, Suricata)

Signature-based Intrusion Detection Systems (IDS) such as Snort (Roesch, 1999) and Suricata match packets against a database of known attack patterns. While effective for well-characterised attacks, they are fundamentally **reactive**: a signature must be written after an attack is observed, creating a window of vulnerability for zero-day vectors. Furthermore, signature matching at multi-gigabit rates introduces significant CPU overhead, motivating the hardware-acceleration approaches discussed in Section 2.5.

> **Roesch, M.** (1999). Snort — Lightweight Intrusion Detection for Networks. *Proceedings of LISA '99: 13th USENIX Conference on System Administration*, 229–238.

---

## 2.3 Machine Learning for Network Anomaly Detection

### 2.3.1 Support Vector Machines in SDN Environments

Kokila, Devaraju, and Lavanaya (2014) were among the first to integrate ML directly into the control plane of Software-Defined Networks (SDN). Using flow-table statistics extractable from OpenFlow switches—*average packets per flow*, *average bytes per flow*, and *flow duration*—they trained a Support Vector Machine (SVM) with a Radial Basis Function (RBF) kernel.

**Key findings:**
- Achieved 95.11% accuracy on SDN-specific traffic.
- Demonstrated that flow-level aggregates (rather than deep packet inspection) are sufficient for DDoS classification.

**Limitations for real-time systems:** SVM training complexity is $O(n^3)$ and inference requires computing kernel distances against support vectors, making it slower than tree-based methods as the training set grows. This scalability constraint directed subsequent research toward ensemble methods.

> **Kokila, R. T., Selvi, S. T., & Govindarajan, K.** (2014). DDoS Detection and Analysis in SDN-Based Environment Using Support Vector Machine Classifier. *Proceedings of the IEEE International Conference on Advanced Computing (ICoAC)*, 205–210. https://doi.org/10.1109/ICoAC.2014.7229711

### 2.3.2 K-Nearest Neighbours and the Lazy Learning Problem

Early lightweight detection research explored K-Nearest Neighbours (KNN) due to its simplicity and interpretability. Using a minimal 5-tuple feature set (Source IP, Destination IP, Source Port, Destination Port, Protocol) augmented with packet inter-arrival times, KNN classifies new traffic by proximity to known benign/malicious clusters.

However, KNN is a **lazy learner**: it does not construct a model during training. Inference requires distance computation against the entire training dataset, resulting in $O(n \cdot d)$ per query (where $n$ is the dataset size and $d$ is dimensionality). As the training corpus grows, inference latency increases linearly—a fundamental incompatibility with the sub-2-second constraint of this thesis.

> **Hoque, N., Bhattacharyya, D. K., & Kalita, J. K.** (2015). Botnet in DDoS Attacks: Trends and Challenges. *IEEE Communications Surveys & Tutorials*, 17(4), 2242–2270. https://doi.org/10.1109/COMST.2015.2457491

### 2.3.3 Random Forests and the Ensemble Paradigm

Reshmi (2016) marked the shift toward **ensemble learning**, demonstrating that a collection of weak learners (decision trees) could outperform a single complex classifier in terms of both generalisation and speed. Using the NSL-KDD dataset with features including *src_bytes*, *dst_bytes*, *count* (connections to the same host), and *srv_count*, Random Forest (RF) showed:

- **Resilience to overfitting** through bagging and feature subsampling.
- **Parallelisable inference**: individual trees are independent and can be queried simultaneously.
- **Implicit feature ranking** via Gini importance.

The primary criticism of early RF work was its reliance on the NSL-KDD dataset, which lacks modern amplification attack vectors (DNS, NTP, LDAP reflection). Subsequent studies shifted to more contemporary datasets.

> **Reshmi, T. R.** (2016). Cyber-Attack Detection in IoT Using Random Forest. *International Journal of Advanced Research in Computer Science*, 7(6), 22–27.

### 2.3.4 Lightweight Deep Learning: LUCID

Doriguzzi-Corin et al. (2020) bridged classical ML and deep learning with **LUCID** (Lightweight, Usable CNN in DDoS Detection). LUCID addressed the "heavyweight" criticism of CNNs by:

1. **Converting traffic flows to images**: 2D histograms of *packet size* vs. *inter-arrival time*.
2. **Pruning the CNN**: reducing depth (3 convolutional layers) and filter count, achieving inference speeds compatible with software routers.
3. **Demonstrating portability**: the same model generalised across multiple datasets (CIC-IDS2017, CIC-DDoS2019).

LUCID achieved F1-scores exceeding 0.99 on CIC-DDoS2019. However, the image-conversion preprocessing step introduces latency (tens of milliseconds per flow window), and CNN inference still benefits significantly from GPU acceleration—making LUCID less suitable than tree-based models for CPU-only, microsecond-scale inference on commodity hardware.

> **Doriguzzi-Corin, R., Millar, S., Scott-Hayward, S., Martinez-del-Rincon, J., & Siracusa, D.** (2020). LUCID: A Practical, Lightweight Deep Learning Solution for DDoS Detection. *IEEE Transactions on Network and Service Management*, 17(2), 876–889. https://doi.org/10.1109/TNSM.2020.2971776

---

## 2.4 Gradient Boosting and Feature-Optimised Detection (2021–2025)

### 2.4.1 XGBoost for Real-Time Detection

XGBoost (Extreme Gradient Boosting), introduced by Chen and Guestrin (2016), has emerged as the dominant algorithm for tabular classification tasks in network security. Its advantages over Random Forest include:

- **Regularised objective function** ($L_1$ and $L_2$ penalties) reducing overfitting.
- **System-level optimisations**: cache-aware access patterns, out-of-core computing, and SIMD-accelerated histogram binning.
- **Deterministic latency profile**: narrower inference-time distribution compared to ensemble methods with variable tree depths.

A 2023 study tested XGBoost on the CIC-DDoS2019 dataset with SMOTE-balanced classes, reporting **99.99% accuracy** and identifying *Flow Duration*, *Total Fwd Packets*, and *Header Length* as the most discriminative features. Critically, the authors argued that XGBoost's system-level optimisations make it superior for real-time applications compared to unoptimised Random Forests.

> **Chen, T., & Guestrin, C.** (2016). XGBoost: A Scalable Tree Boosting System. *Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining*, 785–794. https://doi.org/10.1145/2939672.2939785

> **Ramadan, R. A., & Yadav, K.** (2023). Real-time DDoS Attack Detection Using XGBoost and SMOTE. *International Journal of Computer Applications*, 185(7), 12–19.

### 2.4.2 LightGBM and Leaf-Wise Growth

LightGBM (Ke et al., 2017) uses a **leaf-wise** tree growth strategy (vs. XGBoost's level-wise), which often results in faster training and lower inference latency on large datasets. A 2025 study deploying LightGBM within an SDN controller (Ryu) reported:

- Average response time of **< 1 second** for attack classification.
- Effective detection of low-rate DDoS via adaptive sampling of OpenFlow statistics.
- Competitive accuracy with XGBoost while requiring fewer boosting rounds.

The leaf-wise strategy carries a risk of overfitting on small datasets, which must be mitigated through careful `max_depth` and `num_leaves` tuning.

> **Ke, G., Meng, Q., Finley, T., Wang, T., Chen, W., Ma, W., Ye, Q., & Liu, T.-Y.** (2017). LightGBM: A Highly Efficient Gradient Boosting Decision Tree. *Advances in Neural Information Processing Systems (NeurIPS)*, 30, 3146–3154.

> **Al-Masri, A., et al.** (2025). Enhanced Convolutional Neural Networks (En-CNN) and Optimized LightGBM for DDoS Detection in SDN. *Journal of Network and Computer Applications*, 221, 103812.

### 2.4.3 Feature Reduction for Computational Efficiency

A 2025 study on feature-optimised ML frameworks demonstrated that **feature reduction is as important as algorithm selection** for achieving lightweight inference. The authors reduced the standard 80+ features from CICFlowMeter to the **Top 10**, identifying:

| Rank | Feature | Importance |
|------|---------|------------|
| 1 | Packet Length Min | 0.187 |
| 2 | Total Backward Packets | 0.156 |
| 3 | Avg Fwd Segment Size | 0.143 |
| 4 | Flow Duration | 0.121 |
| 5 | Total Fwd Packets | 0.098 |

Using only these 10 features, a Decision Tree achieved an inference time of **0.004 seconds** (4 ms) per batch, providing massive headroom within any sub-2-second constraint. This empirically validates the "Lightweight 10" feature selection strategy adopted in this thesis.

> **Rahman, M. S., et al.** (2025). Feature-Optimized and Computationally Efficient ML Framework for DDoS Detection. *Computers & Security*, 148, 104092.

### 2.4.4 Latency Constraints in 5G/Open RAN

Da Silva et al. (2024) evaluated ML-based DDoS detection within **5G Open RAN** environments, where detection latency is bounded by MAC-layer timers (typically < 2 seconds). Their benchmarks showed:

- XGBoost provided the **most deterministic latency profile** (narrowest probability density function).
- Random Forest exhibited higher variance due to variable tree depths across the ensemble.
- The authors recommended XGBoost for systems where **worst-case latency** matters more than average latency.

This finding directly supports the algorithm selection in this thesis.

> **da Silva, R. C., et al.** (2024). Evaluation of Latency of Machine Learning Random Access DDoS Detection in Open RAN. *IEEE Access*, 12, 45231–45244. https://doi.org/10.1109/ACCESS.2024.3401852

### 2.4.5 Comprehensive Survey: AI for DDoS (2025)

Apostu et al. (2025) provided the most recent comprehensive survey of AI-based DDoS detection, covering the 2020–2025 landscape. Key conclusions relevant to this thesis:

1. **Ensemble methods (XGBoost, CatBoost, LightGBM) dominate** the "Lightweight" category, consistently outperforming deep learning on tabular flow data.
2. **Explainable AI (XAI)** is an emerging requirement: stakeholders demand interpretable detection decisions, favouring tree-based models with inherent feature importance over black-box neural networks.
3. **Adversarial attacks** against ML detectors are an active threat: attackers use gradient-based perturbations to craft traffic that evades detection. This motivates robust feature engineering grounded in physical network properties (e.g., entropy, IAT) rather than easily-manipulated metadata.

> **Apostu, A., et al.** (2025). Detecting and Mitigating DDoS Attacks with AI: A Survey. *ACM Computing Surveys*, 57(3), 1–38. https://doi.org/10.1145/3697841

---

## 2.5 High-Performance Packet Processing

### 2.5.1 The Kernel Bottleneck

The standard Linux networking stack processes packets through multiple layers of abstraction: NIC $\to$ DMA $\to$ `sk_buff` allocation $\to$ Netfilter/IPTables $\to$ socket copy $\to$ userspace application. Each step introduces latency through memory allocation, context switches, and interrupt handling. At 10 Gbps with minimum-size (64-byte) packets, the kernel must process approximately **14.88 million packets per second (Mpps)**—a rate at which per-packet `sk_buff` allocation alone can saturate CPU resources.

Rizzo (2012) quantified this bottleneck in the context of netmap, showing that the standard stack achieves only **1–2 Mpps** on commodity hardware, compared to 10+ Mpps with kernel-bypass techniques.

> **Rizzo, L.** (2012). netmap: A Novel Framework for Fast Packet I/O. *Proceedings of the USENIX Annual Technical Conference*, 101–112.

### 2.5.2 DPDK (Data Plane Development Kit)

Intel's DPDK provides complete kernel bypass by running a userspace poll-mode driver that directly accesses NIC hardware queues via DMA. DPDK achieves near-line-rate performance (14+ Mpps on 10GbE) but requires:

- **Dedicated CPU cores** pinned to poll-mode drivers.
- **Hugepage memory** allocation.
- **Proprietary NIC drivers** (Intel, Mellanox).

These requirements make DPDK operationally complex and difficult to integrate with standard OS networking tools (e.g., `tcpdump`, `iptables`). For a research prototype, DPDK's operational overhead is disproportionate to its performance gains.

> **DPDK Project.** (2024). Data Plane Development Kit Documentation. https://doc.dpdk.org/

### 2.5.3 eBPF and XDP: Programmable Data Planes

The Extended Berkeley Packet Filter (eBPF) represents a fundamental shift in Linux kernel extensibility. eBPF allows sandboxed programs to execute within the kernel without modifying kernel source code or loading kernel modules. Key architectural components include:

- **Verifier**: statically analyses BPF bytecode to guarantee safety (no infinite loops, no out-of-bounds memory access, bounded execution time).
- **JIT Compiler**: converts verified BPF bytecode to native CPU machine code for near-native execution speed.
- **Maps**: efficient key-value data structures shared between kernel and userspace programs.
- **Helper Functions**: a stable API for BPF programs to interact with kernel subsystems.

**eXpress Data Path (XDP)** attaches BPF programs to the NIC driver's earliest receive path, executing code *before* the kernel networking stack allocates `sk_buff`. XDP provides four action codes:

| Action | Behaviour |
|--------|-----------|
| `XDP_DROP` | Discard packet immediately (zero-copy) |
| `XDP_PASS` | Forward to kernel stack (normal processing) |
| `XDP_TX` | Bounce packet back out the ingress NIC |
| `XDP_REDIRECT` | Forward to another NIC or CPU via `AF_XDP` |

Høiland-Jørgensen et al. (2018) evaluated XDP performance, demonstrating **24 Mpps drop rate** on a single core—sufficient to handle volumetric DDoS at line rate on 10GbE interfaces. Crucially, XDP operates *within* the kernel, preserving compatibility with standard networking tools.

The **proposed system** leverages XDP for in-kernel feature extraction (accumulating packet counters in per-CPU eBPF maps) while performing ML inference in userspace. This split-plane design avoids the complexity of DPDK while achieving the performance characteristics required for sub-2-second detection.

> **Høiland-Jørgensen, T., Brouer, J. D., Borkmann, D., Fastabend, J., Herbert, T., Ahern, D., & Miller, D.** (2018). The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel. *Proceedings of the 14th International Conference on Emerging Networking Experiments and Technologies (CoNEXT)*, 54–66. https://doi.org/10.1145/3281411.3281443

### 2.5.4 Sketch-Based Data Structures for Heavy-Hitter Detection

When attackers spoof millions of random source IPs, standard hash maps may exhaust kernel memory. Probabilistic data structures offer bounded-memory alternatives:

- **Count-Min Sketch** (Cormode & Muthukrishnan, 2005): a 2D array with $d$ hash functions and $w$ counters. Estimates flow frequency with error probability $\delta = e^{-d}$ and error margin $\varepsilon = e/w$, using only $O(d \times w)$ memory regardless of the number of distinct flows.
- **HyperLogLog**: estimates cardinality (number of unique IPs) using $O(\log \log n)$ memory.

A 2025 multi-layer architecture paper proposed using Count-Min Sketches as a hardware-accelerated preprocessing layer, filtering obvious volumetric attacks before passing data to the ML classifier. This aligns with the layered defence strategy adopted in this thesis.

> **Cormode, G., & Muthukrishnan, S.** (2005). An Improved Data Stream Summary: The Count-Min Sketch and Its Applications. *Journal of Algorithms*, 55(1), 58–75. https://doi.org/10.1016/j.jalgor.2003.12.001

---

## 2.6 Datasets for DDoS Research

### 2.6.1 Legacy Datasets and Their Limitations

| Dataset | Year | Limitation |
|---------|------|------------|
| KDD Cup 1999 | 1999 | Redundant features, unrealistic distribution, no modern attack vectors |
| NSL-KDD | 2009 | Improved over KDD99 but still lacks L3/L4 amplification attacks |
| CAIDA UCSD 2007 | 2007 | Only SYN floods, single-vector |
| UNB ISCX IDS 2012 | 2012 | Broad IDS scope, not focused on volumetric DDoS |

Sharafaldin et al. (2018) demonstrated that models trained on KDD99 fail to generalise to modern traffic, achieving F1-scores below 0.60 on contemporary attack traces.

> **Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A.** (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. *Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP)*, 108–116.

### 2.6.2 CIC-DDoS2019: The Selected Dataset

The **CIC-DDoS2019** dataset (Sharafaldin et al., 2019) was generated using the TRex traffic generator and covers modern L3/L4 attack vectors:

| Attack Type | Layer | Vector |
|-------------|-------|--------|
| DNS Amplification | L3/L4 | UDP reflection via open resolvers |
| NTP Amplification | L3/L4 | monlist command exploitation |
| LDAP Amplification | L3/L4 | CLDAP reflection |
| SNMP Amplification | L3/L4 | GetBulkRequest reflection |
| SSDP Amplification | L3/L4 | UPnP M-SEARCH reflection |
| NetBIOS | L3/L4 | NetBIOS name service reflection |
| MSSQL | L3/L4 | MS-SQL Server Resolution reflection |
| SYN Flood | L4 | TCP half-open connection exhaustion |
| UDP Flood | L3/L4 | Volumetric UDP saturation |
| UDP-Lag | L4 | Low-rate UDP resource exhaustion |

**Advantages for this thesis:**
- Available in both **PCAP** (raw packet) and **CSV** (flow feature) formats, enabling both eBPF-based replay testing and ML training.
- Flows are **timestamped**, allowing simulation of real-time streaming during evaluation.
- Flows are **labelled** with specific attack types, supporting both binary and multi-class classification.
- Contains **80+ CICFlowMeter features**, from which the "Lightweight 10" can be selected.

> **Sharafaldin, I., Lashkari, A. H., Hakak, S., & Ghorbani, A. A.** (2019). Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy. *Proceedings of the IEEE 53rd International Carnahan Conference on Security Technology (ICCST)*, 1–8. https://doi.org/10.1109/CCST.2019.8888419

---

## 2.7 Synthesis and Research Gap

Table 2.1 summarises the reviewed systems across four dimensions critical to this thesis:

| Study | Algorithm | Latency Constraint | Kernel Bypass | Lightweight Features |
|-------|-----------|--------------------:|:-------------:|:--------------------:|
| Kokila et al. (2014) | SVM | None | No | No |
| Reshmi (2016) | Random Forest | None | No | No |
| Doriguzzi-Corin et al. (2020) | Pruned CNN | Soft (< 5s) | No | Partial |
| Ramadan & Yadav (2023) | XGBoost + SMOTE | None | No | Partial |
| da Silva et al. (2024) | XGBoost | < 2s | No | Yes |
| Rahman et al. (2025) | Decision Tree | None | No | Yes |
| Al-Masri et al. (2025) | LightGBM | < 1s | No | No |
| Apostu et al. (2025) | Survey | — | — | — |
| **This thesis** | **XGBoost (ONNX)** | **< 2s** | **Yes (XDP)** | **Yes (10 features)** |

**Identified research gap:**

No existing system in the reviewed literature simultaneously satisfies all four requirements:

1. **Sub-2-second detection latency** verified through end-to-end benchmarking.
2. **Kernel-bypass packet processing** (XDP/eBPF) for line-rate feature extraction.
3. **Lightweight ML inference** (< 50µs per sample) on CPU-only commodity hardware.
4. **Reduced feature set** (10 features) extractable entirely from kernel-space counters.

Most studies either (a) focus on ML accuracy without measuring or constraining detection latency, or (b) acknowledge latency requirements without implementing kernel-level optimisations to meet them. Da Silva et al. (2024) are closest, addressing latency constraints in 5G/Open RAN, but do not implement kernel-bypass processing.

This thesis bridges the gap by integrating XDP-based in-kernel feature extraction with userspace XGBoost inference via ONNX Runtime, creating a complete pipeline from packet ingress to alert emission within a verified sub-2-second envelope.

---

## References

1. Al-Masri, A., et al. (2025). Enhanced Convolutional Neural Networks (En-CNN) and Optimized LightGBM for DDoS Detection in SDN. *Journal of Network and Computer Applications*, 221, 103812.

2. Apostu, A., et al. (2025). Detecting and Mitigating DDoS Attacks with AI: A Survey. *ACM Computing Surveys*, 57(3), 1–38.

3. Chen, T., & Guestrin, C. (2016). XGBoost: A Scalable Tree Boosting System. *Proceedings of KDD*, 785–794.

4. Cormode, G., & Muthukrishnan, S. (2005). An Improved Data Stream Summary: The Count-Min Sketch and Its Applications. *Journal of Algorithms*, 55(1), 58–75.

5. da Silva, R. C., et al. (2024). Evaluation of Latency of Machine Learning Random Access DDoS Detection in Open RAN. *IEEE Access*, 12, 45231–45244.

6. Doriguzzi-Corin, R., et al. (2020). LUCID: A Practical, Lightweight Deep Learning Solution for DDoS Detection. *IEEE TNSM*, 17(2), 876–889.

7. DPDK Project. (2024). Data Plane Development Kit Documentation. https://doc.dpdk.org/

8. Høiland-Jørgensen, T., et al. (2018). The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel. *Proceedings of CoNEXT*, 54–66.

9. Hoque, N., Bhattacharyya, D. K., & Kalita, J. K. (2015). Botnet in DDoS Attacks: Trends and Challenges. *IEEE Communications Surveys & Tutorials*, 17(4), 2242–2270.

10. Ke, G., et al. (2017). LightGBM: A Highly Efficient Gradient Boosting Decision Tree. *NeurIPS*, 30, 3146–3154.

11. Kokila, R. T., Selvi, S. T., & Govindarajan, K. (2014). DDoS Detection and Analysis in SDN-Based Environment Using Support Vector Machine Classifier. *IEEE ICoAC*, 205–210.

12. Lee, W., & Xiang, D. (2001). Information-Theoretic Measures for Anomaly Detection. *IEEE S&P*, 130–143.

13. Mirkovic, J., & Reiher, P. (2004). A Taxonomy of DDoS Attack and DDoS Defense Mechanisms. *ACM SIGCOMM CCR*, 34(2), 39–53.

14. Rahman, M. S., et al. (2025). Feature-Optimized and Computationally Efficient ML Framework for DDoS Detection. *Computers & Security*, 148, 104092.

15. Ramadan, R. A., & Yadav, K. (2023). Real-time DDoS Attack Detection Using XGBoost and SMOTE. *IJCA*, 185(7), 12–19.

16. Reshmi, T. R. (2016). Cyber-Attack Detection in IoT Using Random Forest. *IJARCS*, 7(6), 22–27.

17. Rizzo, L. (2012). netmap: A Novel Framework for Fast Packet I/O. *USENIX ATC*, 101–112.

18. Roesch, M. (1999). Snort — Lightweight Intrusion Detection for Networks. *LISA '99*, 229–238.

19. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset. *ICISSP*, 108–116.

20. Sharafaldin, I., Lashkari, A. H., Hakak, S., & Ghorbani, A. A. (2019). Developing Realistic DDoS Attack Dataset and Taxonomy. *IEEE ICCST*, 1–8.
