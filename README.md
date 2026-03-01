# Real-Time L3/L4 DDoS Early Warning System

> Utilizing Lightweight Machine Learning and Kernel-Bypass Networking

A high-performance DDoS detection system that combines **eBPF/XDP** kernel-bypass packet processing with **lightweight ML (XGBoost)** inference to achieve sub-2-second detection latency on commodity hardware.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     FAST DATA PLANE (Kernel)                │
│  ┌─────────┐    ┌──────────────┐    ┌───────────────────┐  │
│  │   NIC   │───▶│  XDP Program │───▶│  eBPF Maps        │  │
│  │ (Driver)│    │  (xdp_prog.c)│    │  (Per-CPU Hash)   │  │
│  └─────────┘    └──────┬───────┘    └────────┬──────────┘  │
│                        │ XDP_DROP (if blacklisted)         │
├────────────────────────┼─────────────────────┼──────────────┤
│                SMART CONTROL PLANE (User Space)            │
│                        │                     │              │
│  ┌─────────────────────▼─────────────────────▼──────────┐  │
│  │              Go Controller (cmd/controller)           │  │
│  │  ┌──────────┐  ┌──────────────┐  ┌────────────────┐  │  │
│  │  │ Map Poll │  │ Feature Calc │  │ ONNX Inference │  │  │
│  │  │ (500ms)  │──▶ (extractor)  │──▶ (model.onnx)   │  │  │
│  │  └──────────┘  └──────────────┘  └───────┬────────┘  │  │
│  └──────────────────────────────────────────┼───────────┘  │
│                                              │              │
│  ┌──────────────┐  ┌─────────────┐  ┌───────▼────────┐    │
│  │   InfluxDB   │◀─│   Alerter   │◀─│  Scorer/Logic  │    │
│  │  (Telemetry) │  │  (Webhook)  │  │  (Threshold)   │    │
│  └──────┬───────┘  └─────────────┘  └────────────────┘    │
│         │                                                   │
│  ┌──────▼───────┐                                          │
│  │   Grafana    │                                          │
│  │ (Dashboard)  │                                          │
│  └──────────────┘                                          │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
ddos-early-warning/
├── bpf/                    # XDP/eBPF kernel programs (C)
│   ├── headers/            # BPF helper headers
│   ├── xdp_prog.c          # Main XDP program
│   ├── xdp_prog.h          # Shared structs (kernel ↔ userspace)
│   └── Makefile
├── cmd/
│   └── controller/         # Go controller entry point
│       └── main.go
├── internal/               # Go internal packages
│   ├── ebpfloader/         # eBPF program loader & map access
│   ├── features/           # Feature vector computation
│   ├── inference/          # ONNX Runtime wrapper
│   ├── alerting/           # Alert dispatch (log, webhook, InfluxDB)
│   └── config/             # Configuration management
├── ml/                     # Python ML pipeline
│   ├── data/               # Raw & processed datasets
│   ├── models/             # Trained model artifacts (.onnx)
│   ├── notebooks/          # Jupyter EDA notebooks
│   └── scripts/            # Training, evaluation, export scripts
├── deployments/            # Docker, Grafana, InfluxDB configs
├── scripts/                # Testbed setup & traffic replay
├── tests/                  # Integration tests
├── configs/                # Runtime YAML configuration
└── docs/                   # Architecture & feature docs
```

## Quick Start

### Prerequisites

- **OS:** Ubuntu 22.04/24.04 (Kernel 6.1+)
- **Toolchain:** `clang-15+`, `llvm-15+`, `libbpf-dev`, `bpftool`
- **Go:** 1.21+
- **Python:** 3.10+ (with pip/venv)
- **Optional:** Docker, Docker Compose, InfluxDB, Grafana

### 1. Build the BPF program

```bash
cd bpf && make
```

### 2. Train the ML model

```bash
cd ml
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python scripts/download_dataset.py
python scripts/preprocess.py
python scripts/train.py
python scripts/export_onnx.py
```

### 3. Build and run the Go controller

```bash
go build -o bin/controller ./cmd/controller
sudo ./bin/controller --config configs/config.yaml
```

### 4. (Optional) Launch monitoring stack

```bash
cd deployments && docker-compose up -d
```

## Key Features

| Feature | Description |
|---------|-------------|
| **XDP-native ingestion** | Process packets at driver level (~10-20 Mpps) |
| **In-kernel feature extraction** | eBPF maps accumulate counters without userspace copies |
| **Lightweight ML** | XGBoost/RF exported to ONNX for fast CPU inference |
| **Sub-2s detection** | 500ms polling interval + microsecond inference |
| **Automatic mitigation** | Blacklist IPs via XDP_DROP without firewall rules |
| **Real-time dashboard** | Grafana + InfluxDB telemetry pipeline |

## Evaluation Metrics

| Metric | Target |
|--------|--------|
| Detection Latency | < 2 seconds |
| False Positive Rate | < 0.1% |
| F1-Score | > 0.95 |
| Throughput Overhead | < 5% PPS drop |

## Dataset

**CIC-DDoS2019** — Contains benign and modern DDoS flows (NTP, DNS, LDAP, MSSQL, NetBIOS, SNMP, SSDP, UDP amplification, SYN flood).

## License

This project is developed as part of a university pre-thesis research project.
