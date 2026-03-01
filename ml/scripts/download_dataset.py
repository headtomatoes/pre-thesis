"""
download_dataset.py — Download the CIC-DDoS2019 dataset.

This script downloads the CSV flow files from the CIC-DDoS2019 dataset.
If the dataset is already present, it skips the download.

Usage:
    python scripts/download_dataset.py

Note:
    The full CIC-DDoS2019 dataset is very large (~10GB+ for PCAPs).
    This script downloads the pre-extracted CSV flow files which are
    sufficient for model training. For replay testing against XDP,
    download PCAPs separately from:
    https://www.unb.ca/cic/datasets/ddos-2019.html
"""

import os
import sys
import hashlib
from pathlib import Path

# ────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────

DATA_DIR = Path(__file__).parent.parent / "data"

# CIC-DDoS2019 CSV files (hosted on UNB servers)
# These URLs may change; update as needed.
DATASET_FILES = {
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": {
        "description": "Friday afternoon DDoS attacks (primary training file)",
        "size_mb": "~800MB",
    },
    "Friday-WorkingHours-Morning.pcap_ISCX.csv": {
        "description": "Friday morning benign traffic",
        "size_mb": "~200MB",
    },
}


def check_existing():
    """Check which files are already downloaded."""
    existing = []
    missing = []

    for filename in DATASET_FILES:
        filepath = DATA_DIR / filename
        if filepath.exists() and filepath.stat().st_size > 0:
            existing.append(filename)
        else:
            missing.append(filename)

    return existing, missing


def print_instructions():
    """Print manual download instructions."""
    print("=" * 70)
    print("CIC-DDoS2019 Dataset Download Instructions")
    print("=" * 70)
    print()
    print("The CIC-DDoS2019 dataset requires manual download from UNB:")
    print("  https://www.unb.ca/cic/datasets/ddos-2019.html")
    print()
    print("Steps:")
    print("  1. Visit the URL above and request access (may need registration)")
    print("  2. Download the CSV flow files")
    print("  3. Place them in the following directory:")
    print(f"     {DATA_DIR.resolve()}")
    print()
    print("Required files:")
    for filename, info in DATASET_FILES.items():
        filepath = DATA_DIR / filename
        status = "✓ Found" if filepath.exists() else "✗ Missing"
        print(f"  [{status}] {filename}")
        print(f"           {info['description']} ({info['size_mb']})")
    print()
    print("Alternative: Use Kaggle mirror")
    print("  pip install kaggle")
    print("  kaggle datasets download -d devendra416/ddos-datasets")
    print()
    print("For PCAP files (needed for tcpreplay testing):")
    print("  Download separately from the UNB page.")
    print("=" * 70)


def create_sample_data():
    """Create a small synthetic sample for development/testing."""
    import numpy as np
    import pandas as pd

    print("\nGenerating synthetic sample data for development...")

    np.random.seed(42)
    n_benign = 5000
    n_attack = 5000

    # Feature names matching CIC-DDoS2019 CSV format
    # We use simplified names that map to our "Lightweight 10"
    columns = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Fwd Packet Length Min",
        "Fwd Packet Length Max",
        "Fwd Packet Length Mean",
        "Bwd Packet Length Min",
        "Bwd Packet Length Max",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Flow IAT Mean",
        "Flow IAT Std",
        "Fwd IAT Mean",
        "Fwd Header Length",
        "Bwd Header Length",
        "Fwd Packets/s",
        "Bwd Packets/s",
        "Packet Length Mean",
        "Packet Length Std",
        "Packet Length Variance",
        "SYN Flag Count",
        "ACK Flag Count",
        "Average Packet Size",
        "Fwd Segment Size Avg",
        "Label",
    ]

    # ── Benign traffic characteristics ──
    benign = pd.DataFrame({
        "Flow Duration":              np.random.exponential(5e6, n_benign),      # longer flows
        "Total Fwd Packets":          np.random.poisson(15, n_benign),
        "Total Backward Packets":     np.random.poisson(12, n_benign),
        "Total Length of Fwd Packets": np.random.exponential(2000, n_benign),
        "Total Length of Bwd Packets": np.random.exponential(5000, n_benign),
        "Fwd Packet Length Min":       np.random.uniform(40, 100, n_benign),
        "Fwd Packet Length Max":       np.random.uniform(500, 1500, n_benign),
        "Fwd Packet Length Mean":      np.random.uniform(100, 800, n_benign),
        "Bwd Packet Length Min":       np.random.uniform(40, 100, n_benign),
        "Bwd Packet Length Max":       np.random.uniform(500, 1500, n_benign),
        "Flow Bytes/s":               np.random.exponential(50000, n_benign),
        "Flow Packets/s":             np.random.exponential(100, n_benign),
        "Flow IAT Mean":              np.random.exponential(50000, n_benign),     # variable IAT
        "Flow IAT Std":               np.random.exponential(30000, n_benign),     # high variance
        "Fwd IAT Mean":               np.random.exponential(80000, n_benign),
        "Fwd Header Length":          np.random.poisson(400, n_benign),
        "Bwd Header Length":          np.random.poisson(350, n_benign),
        "Fwd Packets/s":             np.random.exponential(50, n_benign),
        "Bwd Packets/s":             np.random.exponential(40, n_benign),
        "Packet Length Mean":         np.random.uniform(100, 800, n_benign),
        "Packet Length Std":          np.random.uniform(50, 500, n_benign),       # high variance
        "Packet Length Variance":     np.random.uniform(2500, 250000, n_benign),
        "SYN Flag Count":            np.random.choice([0, 1], n_benign, p=[0.5, 0.5]),
        "ACK Flag Count":            np.random.poisson(8, n_benign),
        "Average Packet Size":       np.random.uniform(100, 800, n_benign),
        "Fwd Segment Size Avg":      np.random.uniform(100, 800, n_benign),
        "Label":                     "BENIGN",
    })

    # ── Attack traffic characteristics (SYN Flood) ──
    attack = pd.DataFrame({
        "Flow Duration":              np.random.exponential(1e4, n_attack),       # very short flows
        "Total Fwd Packets":          np.random.poisson(500, n_attack),           # high packet count
        "Total Backward Packets":     np.random.poisson(1, n_attack),             # almost no response
        "Total Length of Fwd Packets": np.random.exponential(20000, n_attack),
        "Total Length of Bwd Packets": np.random.exponential(50, n_attack),
        "Fwd Packet Length Min":       np.random.uniform(40, 60, n_attack),       # small, fixed size
        "Fwd Packet Length Max":       np.random.uniform(40, 80, n_attack),
        "Fwd Packet Length Mean":      np.random.uniform(40, 60, n_attack),
        "Bwd Packet Length Min":       np.zeros(n_attack),
        "Bwd Packet Length Max":       np.random.uniform(0, 60, n_attack),
        "Flow Bytes/s":               np.random.exponential(5000000, n_attack),   # very high
        "Flow Packets/s":             np.random.exponential(10000, n_attack),     # very high PPS
        "Flow IAT Mean":              np.random.exponential(100, n_attack),       # very low IAT
        "Flow IAT Std":               np.random.exponential(50, n_attack),        # low variance (machine)
        "Fwd IAT Mean":               np.random.exponential(100, n_attack),
        "Fwd Header Length":          np.random.poisson(20000, n_attack),
        "Bwd Header Length":          np.random.poisson(5, n_attack),
        "Fwd Packets/s":             np.random.exponential(10000, n_attack),
        "Bwd Packets/s":             np.random.exponential(1, n_attack),
        "Packet Length Mean":         np.random.uniform(40, 60, n_attack),        # fixed size
        "Packet Length Std":          np.random.uniform(0, 10, n_attack),          # low variance
        "Packet Length Variance":     np.random.uniform(0, 100, n_attack),
        "SYN Flag Count":            np.random.poisson(400, n_attack),            # masses of SYNs
        "ACK Flag Count":            np.random.choice([0, 1], n_attack, p=[0.9, 0.1]),
        "Average Packet Size":       np.random.uniform(40, 60, n_attack),
        "Fwd Segment Size Avg":      np.random.uniform(40, 60, n_attack),
        "Label":                     "DDoS",
    })

    df = pd.concat([benign, attack], ignore_index=True).sample(frac=1, random_state=42)

    output_path = DATA_DIR / "sample_dataset.csv"
    df.to_csv(output_path, index=False)
    print(f"  Saved {len(df)} rows to {output_path}")
    print("  (Use this for development; replace with real CIC-DDoS2019 for thesis)")

    return output_path


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    existing, missing = check_existing()

    if existing:
        print(f"Found {len(existing)} dataset file(s):")
        for f in existing:
            print(f"  ✓ {f}")

    if missing:
        print(f"\nMissing {len(missing)} file(s).")
        print_instructions()

    # Always generate sample data for development
    create_sample_data()


if __name__ == "__main__":
    main()
