"""
eda.py — Exploratory Data Analysis for CIC-DDoS2019 dataset.

Generates visualisations to confirm feature separability between
benign and attack traffic. Run this as a script or convert to Jupyter.

Outputs (in ml/models/):
  - eda_feature_distributions.png
  - eda_correlation_matrix.png
  - eda_pairplot.png

Usage:
    python scripts/eda.py [--input data/sample_dataset.csv]
"""

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

DATA_DIR  = Path(__file__).parent.parent / "data"
MODEL_DIR = Path(__file__).parent.parent / "models"

# Features to analyse (matching the "Lightweight 10")
FEATURES = [
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "SYN Flag Count",
    "ACK Flag Count",
    "Packet Length Mean",
    "Packet Length Variance",
    "Flow Duration",
    "Flow IAT Mean",
]

LABEL_COL = "Label"
BENIGN    = "BENIGN"


def load_data(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    return df


def plot_feature_distributions(df: pd.DataFrame):
    """Box plots showing feature distributions per class."""
    available = [f for f in FEATURES if f in df.columns]
    n = len(available)
    fig, axes = plt.subplots(2, (n + 1) // 2, figsize=(5 * ((n + 1) // 2), 10))
    axes = axes.flatten()

    label_binary = df[LABEL_COL].apply(lambda x: "Benign" if x == BENIGN else "Attack")

    for i, feat in enumerate(available):
        sns.boxplot(x=label_binary, y=df[feat], ax=axes[i], palette="Set2")
        axes[i].set_title(feat, fontsize=10)
        axes[i].set_xlabel("")

    # Hide unused axes
    for j in range(i + 1, len(axes)):
        axes[j].set_visible(False)

    plt.suptitle("Feature Distributions: Benign vs Attack", fontsize=14, y=1.02)
    plt.tight_layout()
    plt.savefig(MODEL_DIR / "eda_feature_distributions.png", dpi=150, bbox_inches="tight")
    print(f"✓ Feature distributions saved")


def plot_correlation_matrix(df: pd.DataFrame):
    """Correlation heatmap of selected features."""
    available = [f for f in FEATURES if f in df.columns]
    corr = df[available].corr()

    fig, ax = plt.subplots(figsize=(10, 8))
    sns.heatmap(
        corr, annot=True, fmt=".2f", cmap="coolwarm",
        center=0, square=True, ax=ax,
    )
    ax.set_title("Feature Correlation Matrix")
    plt.tight_layout()
    plt.savefig(MODEL_DIR / "eda_correlation_matrix.png", dpi=150)
    print(f"✓ Correlation matrix saved")


def plot_class_distribution(df: pd.DataFrame):
    """Bar chart of class distribution."""
    fig, ax = plt.subplots(figsize=(8, 5))
    counts = df[LABEL_COL].value_counts()
    counts.plot(kind="bar", ax=ax, color=["steelblue", "coral"])
    ax.set_title("Class Distribution")
    ax.set_xlabel("Label")
    ax.set_ylabel("Count")
    for i, v in enumerate(counts.values):
        ax.text(i, v + v * 0.01, f"{v:,}", ha="center", fontsize=10)
    plt.tight_layout()
    plt.savefig(MODEL_DIR / "eda_class_distribution.png", dpi=150)
    print(f"✓ Class distribution saved")


def print_summary_stats(df: pd.DataFrame):
    """Print summary statistics."""
    print("\n── Dataset Summary ──")
    print(f"Total samples: {len(df):,}")
    print(f"Features:      {len(df.columns)}")
    print(f"\nLabel distribution:")
    print(df[LABEL_COL].value_counts().to_string())

    available = [f for f in FEATURES if f in df.columns]
    print(f"\nFeature statistics (selected {len(available)} features):")
    print(df[available].describe().round(2).to_string())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str, default=str(DATA_DIR / "sample_dataset.csv"))
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} not found. Run download_dataset.py first.")
        return

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    df = load_data(input_path)

    print_summary_stats(df)
    plot_class_distribution(df)
    plot_feature_distributions(df)
    plot_correlation_matrix(df)

    print("\n✓ EDA complete. Check ml/models/ for visualisations.")


if __name__ == "__main__":
    main()
