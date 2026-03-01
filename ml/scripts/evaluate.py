"""
evaluate.py — Detailed evaluation of the best trained model.

Generates:
  - Detailed classification report
  - Feature importance ranking (with SHAP values)
  - ROC and Precision-Recall curves
  - Latency distribution histogram

Usage:
    python scripts/evaluate.py
"""

import json
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    classification_report,
    roc_curve,
    auc,
    precision_recall_curve,
    average_precision_score,
)

warnings.filterwarnings("ignore")

DATA_DIR  = Path(__file__).parent.parent / "data"
MODEL_DIR = Path(__file__).parent.parent / "models"


def load_model_and_data():
    """Load the best model and test data."""
    model = joblib.load(MODEL_DIR / "best_model.pkl")
    test_df = pd.read_csv(DATA_DIR / "test.csv")

    X_test = test_df.drop(columns=["label"])
    y_test = test_df["label"]

    model_name = "Unknown"
    name_file = MODEL_DIR / "best_model_name.txt"
    if name_file.exists():
        model_name = name_file.read_text().strip()

    print(f"Model: {model_name}")
    print(f"Test samples: {len(X_test)}")

    return model, X_test, y_test, model_name


def detailed_classification_report(model, X_test, y_test):
    """Print detailed classification metrics."""
    y_pred = model.predict(X_test)
    report = classification_report(
        y_test, y_pred,
        target_names=["Benign", "Attack"],
        digits=4,
    )
    print("\n── Classification Report ──")
    print(report)

    # Save to file
    with open(MODEL_DIR / "classification_report.txt", "w") as f:
        f.write(report)


def plot_roc_pr_curves(model, X_test, y_test, model_name):
    """Plot ROC and Precision-Recall curves."""
    # Get probability scores
    if hasattr(model, "predict_proba"):
        y_scores = model.predict_proba(X_test)[:, 1]
    elif hasattr(model, "decision_function"):
        y_scores = model.decision_function(X_test)
    else:
        print("Model does not support probability scores, skipping curves.")
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # ROC Curve
    fpr, tpr, thresholds = roc_curve(y_test, y_scores)
    roc_auc = auc(fpr, tpr)

    ax1.plot(fpr, tpr, "b-", linewidth=2, label=f"{model_name} (AUC = {roc_auc:.4f})")
    ax1.plot([0, 1], [0, 1], "k--", alpha=0.3)
    ax1.set_xlabel("False Positive Rate")
    ax1.set_ylabel("True Positive Rate")
    ax1.set_title("ROC Curve")
    ax1.legend(loc="lower right")
    ax1.grid(True, alpha=0.3)

    # Precision-Recall Curve
    precision, recall, _ = precision_recall_curve(y_test, y_scores)
    ap = average_precision_score(y_test, y_scores)

    ax2.plot(recall, precision, "r-", linewidth=2, label=f"{model_name} (AP = {ap:.4f})")
    ax2.set_xlabel("Recall")
    ax2.set_ylabel("Precision")
    ax2.set_title("Precision-Recall Curve")
    ax2.legend(loc="lower left")
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(MODEL_DIR / "roc_pr_curves.png", dpi=150)
    print(f"✓ ROC/PR curves saved to {MODEL_DIR / 'roc_pr_curves.png'}")


def plot_feature_importance(model, X_test, model_name):
    """Plot feature importance using built-in importance and optionally SHAP."""
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))

    # ── Built-in feature importance ──
    if hasattr(model, "feature_importances_"):
        importance = model.feature_importances_
        feature_names = X_test.columns

        sorted_idx = np.argsort(importance)
        axes[0].barh(
            range(len(sorted_idx)),
            importance[sorted_idx],
            color="steelblue",
        )
        axes[0].set_yticks(range(len(sorted_idx)))
        axes[0].set_yticklabels(feature_names[sorted_idx])
        axes[0].set_xlabel("Importance")
        axes[0].set_title(f"{model_name} — Built-in Feature Importance")

    # ── SHAP values (if available) ──
    try:
        import shap

        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X_test.iloc[:500])

        # For binary classification, shap_values may be a list
        if isinstance(shap_values, list):
            shap_values = shap_values[1]  # attack class

        mean_abs_shap = np.abs(shap_values).mean(axis=0)
        sorted_idx = np.argsort(mean_abs_shap)
        axes[1].barh(
            range(len(sorted_idx)),
            mean_abs_shap[sorted_idx],
            color="coral",
        )
        axes[1].set_yticks(range(len(sorted_idx)))
        axes[1].set_yticklabels(X_test.columns[sorted_idx])
        axes[1].set_xlabel("Mean |SHAP value|")
        axes[1].set_title(f"{model_name} — SHAP Feature Importance")
    except ImportError:
        axes[1].text(0.5, 0.5, "Install 'shap' for\nSHAP analysis",
                     ha="center", va="center", fontsize=14)
        axes[1].set_title("SHAP (not available)")
    except Exception as e:
        axes[1].text(0.5, 0.5, f"SHAP error:\n{e}",
                     ha="center", va="center", fontsize=10)

    plt.tight_layout()
    plt.savefig(MODEL_DIR / "feature_importance.png", dpi=150)
    print(f"✓ Feature importance saved to {MODEL_DIR / 'feature_importance.png'}")


def benchmark_inference_latency(model, X_test):
    """Measure per-sample inference latency distribution."""
    single_sample = X_test.iloc[:1]
    latencies_us = []

    # Warm up
    for _ in range(50):
        model.predict(single_sample)

    # Measure 1000 inferences
    for _ in range(1000):
        start = time.perf_counter_ns()
        model.predict(single_sample)
        elapsed_us = (time.perf_counter_ns() - start) / 1000
        latencies_us.append(elapsed_us)

    latencies = np.array(latencies_us)

    print(f"\n── Inference Latency (µs) ──")
    print(f"  Mean:   {latencies.mean():.1f}")
    print(f"  Median: {np.median(latencies):.1f}")
    print(f"  P95:    {np.percentile(latencies, 95):.1f}")
    print(f"  P99:    {np.percentile(latencies, 99):.1f}")
    print(f"  Max:    {latencies.max():.1f}")

    # Check against 50µs target
    pct_under_50 = (latencies < 50).sum() / len(latencies) * 100
    print(f"  Under 50µs target: {pct_under_50:.1f}%")

    # Plot
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.hist(latencies, bins=50, color="steelblue", edgecolor="white", alpha=0.8)
    ax.axvline(50, color="red", linestyle="--", label="50µs target")
    ax.axvline(latencies.mean(), color="green", linestyle="--", label=f"Mean ({latencies.mean():.1f}µs)")
    ax.set_xlabel("Inference Latency (µs)")
    ax.set_ylabel("Count")
    ax.set_title("Single-Sample Inference Latency Distribution")
    ax.legend()
    plt.tight_layout()
    plt.savefig(MODEL_DIR / "inference_latency.png", dpi=150)
    print(f"✓ Latency histogram saved to {MODEL_DIR / 'inference_latency.png'}")


def main():
    model, X_test, y_test, model_name = load_model_and_data()

    detailed_classification_report(model, X_test, y_test)
    plot_roc_pr_curves(model, X_test, y_test, model_name)
    plot_feature_importance(model, X_test, model_name)
    benchmark_inference_latency(model, X_test)

    print("\n✓ Evaluation complete.")


if __name__ == "__main__":
    main()
