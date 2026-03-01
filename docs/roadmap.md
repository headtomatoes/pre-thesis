# 12-Week Implementation Roadmap

## Phase 1: Research & Data Preparation (Weeks 1–3)

### Week 1: Environment Setup
- [ ] Install Ubuntu 22.04/24.04 (Kernel 6.x+)
- [ ] Run `scripts/setup_testbed.sh` to install toolchain
- [ ] Verify: `clang`, `llvm`, `libbpf-dev`, `bpftool`, `go 1.21+`
- [ ] Set up 2 VMs: Attacker (with tcpreplay) + Victim (with XDP)
- [ ] Clone this repository and verify `make build-bpf` works

### Week 2: Data Analysis (EDA)
- [ ] Run `python scripts/download_dataset.py` (or download CIC-DDoS2019 manually)
- [ ] Run `python scripts/eda.py` to generate visualisations
- [ ] Verify feature separability between Benign vs Attack classes
- [ ] Document findings in thesis

### Week 3: Preprocessing & Feature Selection
- [ ] Run `python scripts/preprocess.py`
- [ ] Verify SMOTE balancing in `data/train.csv`
- [ ] Review `data/scaler_params.json` for normalisation ranges
- [ ] Generate `train.csv` and `test.csv`

## Phase 2: Baseline Model Training (Weeks 4–6)

### Week 4: Model Prototyping
- [ ] Run `python scripts/train.py --quick` for fast iteration
- [ ] Compare: Decision Tree, Random Forest, XGBoost, LightGBM
- [ ] Review `models/comparison_report.csv`

### Week 5: Optimisation & Pruning
- [ ] Run full training: `python scripts/train.py`
- [ ] Run evaluation: `python scripts/evaluate.py`
- [ ] Verify inference time < 50µs per sample
- [ ] Prune tree depth if model size > 10MB
- [ ] Review SHAP feature importance plots

### Week 6: Model Export
- [ ] Run `python scripts/export_onnx.py`
- [ ] Verify `models/model.onnx` exists and passes verification
- [ ] Document model selection rationale

## Phase 3: Real-time Pipeline Development (Weeks 7–10)

### Week 7: XDP "Hello World"
- [ ] Build BPF: `cd bpf && make`
- [ ] Load with: `sudo ip link set dev eth0 xdp obj xdp_prog.o sec xdp`
- [ ] Verify counters: `sudo bpftool map dump name flow_stats`
- [ ] Test XDP_PASS (traffic flows normally)

### Week 8: Advanced Feature Extraction
- [ ] Verify all 13 counters in `flow_counters` struct populate correctly
- [ ] Test with tcpdump alongside XDP to verify no packet loss
- [ ] Test per-CPU map aggregation with multi-core traffic

### Week 9: Go Controller
- [ ] Build: `go build -o bin/controller ./cmd/controller`
- [ ] Run: `sudo ./bin/controller --config configs/config.yaml`
- [ ] Verify map polling works (check stdout logs)
- [ ] Verify feature vectors are computed correctly (compare with manual calculation)

### Week 10: Full Integration
- [ ] Copy `models/model.onnx` to expected path
- [ ] Test end-to-end: traffic → XDP → maps → Go → ONNX → alert
- [ ] Test blacklisting: verify XDP_DROP for blocked IPs
- [ ] Test blacklist TTL expiry

## Phase 4: Testing & Optimisation (Weeks 11–12)

### Week 11: Latency Benchmarking
- [ ] Run `sudo ./scripts/benchmark_latency.sh`
- [ ] Verify detection latency < 2 seconds
- [ ] Measure PPS throughput with and without XDP
- [ ] Stress test with `tcpreplay --mbps=1000`
- [ ] Document: CPU usage, memory usage, PPS graphs

### Week 12: Reporting & Thesis Finalisation
- [ ] Generate confusion matrix visualisation
- [ ] Generate ROC/PR curves
- [ ] Compare XDP throughput vs standard libpcap
- [ ] Write thesis conclusions
- [ ] Prepare presentation slides

## Challenge Mode (Optional)

### Count-Min Sketch in eBPF
- [ ] Implement CMS data structure in `bpf/xdp_prog.c`
- [ ] Replace hash map for heavy-hitter detection
- [ ] Benchmark: memory usage with 1M spoofed IPs
- [ ] Compare accuracy vs exact hash map counting
