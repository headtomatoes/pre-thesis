"""
preprocess.py — Data preprocessing & feature engineering pipeline.

Loads raw CIC-DDoS2019 CSV data (or synthetic sample), performs:
  1. Cleaning (NaN, Inf, duplicates)
  2. Feature selection (the "Lightweight 10")
  3. Class imbalance handling (SMOTE)
  4. Train/test split
  5. Min-Max normalisation

Outputs:
  - data/train.csv
  - data/test.csv
  - data/scaler_params.json  (for inference-time normalisation)

Usage:
    python scripts/preprocess.py [--input data/sample_dataset.csv]
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from imblearn.over_sampling import SMOTE

# ────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────

DATA_DIR = Path(__file__).parent.parent / "data"

# The "Lightweight 10" features mapped to CIC-DDoS2019 column names.
# These correspond to the features extractable from eBPF maps.
FEATURE_COLUMNS = [
    "Total Fwd Packets",        # → Packet Count
    "Total Length of Fwd Packets",  # → Byte Count
    "SYN Flag Count",           # → SYN Count
    "ACK Flag Count",           # → ACK Count
    # SYN/ACK Ratio is computed below
    "Packet Length Mean",       # → Packet Size Mean
    "Packet Length Variance",   # → Packet Size Variance
    "Flow Duration",            # → Flow Duration
    # Protocol Entropy is computed below
    "Flow IAT Mean",            # → Inter-Arrival Time Mean
]

LABEL_COL = "Label"
BENIGN_LABEL = "BENIGN"


def load_data(input_path: Path) -> pd.DataFrame:
    """Load CSV and perform basic cleaning."""
    print(f"Loading data from {input_path}...")
    df = pd.read_csv(input_path, low_memory=False)

    # Strip whitespace from column names (CIC-DDoS2019 quirk)
    df.columns = df.columns.str.strip()

    print(f"  Loaded {len(df)} rows, {len(df.columns)} columns")
    print(f"  Label distribution:\n{df[LABEL_COL].value_counts()}\n")

    return df


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """Remove NaN, Inf, and duplicate rows."""
    initial = len(df)

    # Replace Inf with NaN, then drop
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()

    # Remove duplicates
    df = df.drop_duplicates()

    removed = initial - len(df)
    print(f"Cleaning: removed {removed} rows ({removed/initial*100:.1f}%)")
    print(f"  Remaining: {len(df)} rows")

    return df


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Compute derived features that match the eBPF extraction pipeline."""

    # Feature 5: SYN/ACK Ratio
    df["SYN_ACK_Ratio"] = df["SYN Flag Count"] / df["ACK Flag Count"].replace(0, 1)

    # Feature 9: Protocol Entropy (approximated from available columns)
    # In the real system this is computed from per-IP protocol distribution.
    # For training, we approximate using packet direction asymmetry.
    total_pkts = df["Total Fwd Packets"] + df["Total Backward Packets"]
    fwd_ratio = df["Total Fwd Packets"] / total_pkts.replace(0, 1)
    bwd_ratio = 1 - fwd_ratio
    # Shannon entropy of bidirectional distribution
    df["Proto_Entropy"] = -(
        fwd_ratio * np.log2(fwd_ratio.replace(0, 1)) +
        bwd_ratio * np.log2(bwd_ratio.replace(0, 1))
    )
    df["Proto_Entropy"] = df["Proto_Entropy"].fillna(0)

    return df


def select_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Select the final 10 features and binary label."""

    final_features = [
        "Total Fwd Packets",              # 1. Packet Count
        "Total Length of Fwd Packets",     # 2. Byte Count
        "SYN Flag Count",                  # 3. SYN Count
        "ACK Flag Count",                  # 4. ACK Count
        "SYN_ACK_Ratio",                   # 5. SYN/ACK Ratio
        "Packet Length Mean",              # 6. Packet Size Mean
        "Packet Length Variance",          # 7. Packet Size Variance
        "Flow Duration",                   # 8. Flow Duration
        "Proto_Entropy",                   # 9. Protocol Entropy
        "Flow IAT Mean",                   # 10. IAT Mean
    ]

    X = df[final_features].copy()

    # Binary label: 0 = Benign, 1 = Attack
    y = (df[LABEL_COL] != BENIGN_LABEL).astype(int)

    print(f"\nSelected {len(final_features)} features:")
    for i, f in enumerate(final_features, 1):
        print(f"  {i:2d}. {f}")

    print(f"\nLabel distribution: Benign={sum(y==0)}, Attack={sum(y==1)}")

    return X, y


def apply_smote(X: pd.DataFrame, y: pd.Series) -> tuple[pd.DataFrame, pd.Series]:
    """Balance classes using SMOTE (Synthetic Minority Over-sampling)."""
    print(f"\nApplying SMOTE...")
    print(f"  Before: {dict(zip(*np.unique(y, return_counts=True)))}")

    smote = SMOTE(random_state=42, k_neighbors=5)
    X_resampled, y_resampled = smote.fit_resample(X, y)

    print(f"  After:  {dict(zip(*np.unique(y_resampled, return_counts=True)))}")

    return pd.DataFrame(X_resampled, columns=X.columns), pd.Series(y_resampled)


def normalize_and_split(
    X: pd.DataFrame, y: pd.Series
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, dict]:
    """Split into train/test and apply Min-Max scaling."""

    # Split BEFORE scaling to prevent data leakage
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\nTrain/Test split:")
    print(f"  Train: {len(X_train)} samples")
    print(f"  Test:  {len(X_test)} samples")

    # Fit scaler on training data only
    scaler = MinMaxScaler()
    X_train_scaled = pd.DataFrame(
        scaler.fit_transform(X_train),
        columns=X_train.columns,
        index=X_train.index,
    )
    X_test_scaled = pd.DataFrame(
        scaler.transform(X_test),
        columns=X_test.columns,
        index=X_test.index,
    )

    # Save scaler parameters for inference-time use
    scaler_params = {
        "feature_names": list(X_train.columns),
        "min": scaler.data_min_.tolist(),
        "max": scaler.data_max_.tolist(),
        "scale": scaler.scale_.tolist(),
        "data_range": scaler.data_range_.tolist(),
    }

    return X_train_scaled, X_test_scaled, y_train, y_test, scaler_params


def main():
    parser = argparse.ArgumentParser(description="Preprocess CIC-DDoS2019 data")
    parser.add_argument(
        "--input",
        type=str,
        default=str(DATA_DIR / "sample_dataset.csv"),
        help="Path to input CSV file",
    )
    parser.add_argument(
        "--no-smote",
        action="store_true",
        help="Skip SMOTE oversampling",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} not found.")
        print("Run `python scripts/download_dataset.py` first.")
        sys.exit(1)

    # ── Pipeline ──
    df = load_data(input_path)
    df = clean_data(df)
    df = engineer_features(df)
    X, y = select_features(df)

    if not args.no_smote:
        X, y = apply_smote(X, y)

    X_train, X_test, y_train, y_test, scaler_params = normalize_and_split(X, y)

    # ── Save outputs ──
    train_df = X_train.copy()
    train_df["label"] = y_train.values
    train_df.to_csv(DATA_DIR / "train.csv", index=False)

    test_df = X_test.copy()
    test_df["label"] = y_test.values
    test_df.to_csv(DATA_DIR / "test.csv", index=False)

    with open(DATA_DIR / "scaler_params.json", "w") as f:
        json.dump(scaler_params, f, indent=2)

    print(f"\n✓ Saved:")
    print(f"  {DATA_DIR / 'train.csv'} ({len(train_df)} rows)")
    print(f"  {DATA_DIR / 'test.csv'} ({len(test_df)} rows)")
    print(f"  {DATA_DIR / 'scaler_params.json'}")


if __name__ == "__main__":
    main()
