"""
train.py — Train and compare lightweight ML models for DDoS detection.

Models trained:
  1. Decision Tree (baseline)
  2. Random Forest
  3. XGBoost (primary candidate)
  4. LightGBM

For each model, we measure:
  - Accuracy, Precision, Recall, F1-Score
  - Per-sample inference time (must be < 50µs)
  - Model size on disk

Outputs:
  - models/best_model.pkl        (best scikit-compatible model)
  - models/comparison_report.csv (metric comparison table)
  - models/confusion_matrix.png  (visualisation)

Usage:
    python scripts/train.py [--input data/train.csv]
"""

import argparse
import json
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")  # non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.model_selection import GridSearchCV

import xgboost as xgb
import lightgbm as lgb

warnings.filterwarnings("ignore")

# ────────────────────────────────────────────
# Paths
# ────────────────────────────────────────────

DATA_DIR   = Path(__file__).parent.parent / "data"
MODEL_DIR  = Path(__file__).parent.parent / "models"


def load_splits():
    """Load preprocessed train/test CSV files."""
    train_df = pd.read_csv(DATA_DIR / "train.csv")
    test_df  = pd.read_csv(DATA_DIR / "test.csv")

    X_train = train_df.drop(columns=["label"])
    y_train = train_df["label"]
    X_test  = test_df.drop(columns=["label"])
    y_test  = test_df["label"]

    print(f"Train: {X_train.shape}, Test: {X_test.shape}")
    return X_train, X_test, y_train, y_test


def define_models():
    """Define the model zoo with hyperparameter grids."""
    return {
        "DecisionTree": {
            "model": DecisionTreeClassifier(random_state=42),
            "params": {
                "max_depth": [5, 10, 15, None],
                "min_samples_split": [2, 5, 10],
                "min_samples_leaf": [1, 2, 4],
            },
        },
        "RandomForest": {
            "model": RandomForestClassifier(random_state=42, n_jobs=-1),
            "params": {
                "n_estimators": [50, 100, 200],
                "max_depth": [10, 15, 20],
                "min_samples_split": [2, 5],
            },
        },
        "XGBoost": {
            "model": xgb.XGBClassifier(
                objective="binary:logistic",
                eval_metric="logloss",
                use_label_encoder=False,
                random_state=42,
                n_jobs=-1,
            ),
            "params": {
                "n_estimators": [100, 200, 300],
                "max_depth": [4, 6, 8],
                "learning_rate": [0.05, 0.1, 0.2],
                "subsample": [0.8, 1.0],
            },
        },
        "LightGBM": {
            "model": lgb.LGBMClassifier(
                objective="binary",
                random_state=42,
                n_jobs=-1,
                verbose=-1,
            ),
            "params": {
                "n_estimators": [100, 200, 300],
                "max_depth": [4, 6, 8],
                "learning_rate": [0.05, 0.1, 0.2],
                "num_leaves": [31, 50, 80],
            },
        },
    }


def measure_inference_time(model, X_sample, n_runs=100):
    """Measure average per-sample inference time in microseconds."""
    single = X_sample.iloc[:1]

    # Warm up
    for _ in range(10):
        model.predict(single)

    # Benchmark
    times = []
    for _ in range(n_runs):
        start = time.perf_counter_ns()
        model.predict(single)
        elapsed_ns = time.perf_counter_ns() - start
        times.append(elapsed_ns / 1000)  # → µs

    return np.mean(times), np.std(times)


def train_and_evaluate(models_dict, X_train, X_test, y_train, y_test):
    """Train all models with grid search and collect metrics."""
    results = []

    for name, spec in models_dict.items():
        print(f"\n{'='*60}")
        print(f"Training: {name}")
        print(f"{'='*60}")

        # Grid search with 3-fold CV
        grid = GridSearchCV(
            spec["model"],
            spec["params"],
            cv=3,
            scoring="f1",
            n_jobs=-1,
            verbose=0,
        )

        t_start = time.time()
        grid.fit(X_train, y_train)
        train_time = time.time() - t_start

        best = grid.best_estimator_
        y_pred = best.predict(X_test)

        # Metrics
        acc  = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec  = recall_score(y_test, y_pred, zero_division=0)
        f1   = f1_score(y_test, y_pred, zero_division=0)

        # False Positive Rate = FP / (FP + TN)
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

        # Inference latency
        mean_us, std_us = measure_inference_time(best, X_test)

        # Model size
        model_path = MODEL_DIR / f"{name}.pkl"
        joblib.dump(best, model_path)
        size_kb = model_path.stat().st_size / 1024

        print(f"  Best params: {grid.best_params_}")
        print(f"  Accuracy:    {acc:.4f}")
        print(f"  Precision:   {prec:.4f}")
        print(f"  Recall:      {rec:.4f}")
        print(f"  F1-Score:    {f1:.4f}")
        print(f"  FPR:         {fpr:.4f}")
        print(f"  Inference:   {mean_us:.1f} ± {std_us:.1f} µs/sample")
        print(f"  Train time:  {train_time:.1f}s")
        print(f"  Model size:  {size_kb:.1f} KB")

        results.append({
            "Model": name,
            "Accuracy": round(acc, 4),
            "Precision": round(prec, 4),
            "Recall": round(rec, 4),
            "F1-Score": round(f1, 4),
            "FPR": round(fpr, 6),
            "Inference_µs": round(mean_us, 2),
            "Train_Time_s": round(train_time, 2),
            "Size_KB": round(size_kb, 1),
            "Best_Params": json.dumps(grid.best_params_),
        })

    return pd.DataFrame(results)


def plot_confusion_matrices(models_dict, X_test, y_test):
    """Plot confusion matrices for all models side by side."""
    fig, axes = plt.subplots(1, len(models_dict), figsize=(5 * len(models_dict), 4))
    if len(models_dict) == 1:
        axes = [axes]

    for ax, name in zip(axes, models_dict):
        model_path = MODEL_DIR / f"{name}.pkl"
        if not model_path.exists():
            continue

        model = joblib.load(model_path)
        y_pred = model.predict(X_test)
        cm = confusion_matrix(y_test, y_pred)

        sns.heatmap(
            cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["Benign", "Attack"],
            yticklabels=["Benign", "Attack"],
            ax=ax,
        )
        ax.set_title(name)
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")

    plt.tight_layout()
    plt.savefig(MODEL_DIR / "confusion_matrices.png", dpi=150)
    print(f"\n✓ Saved confusion matrices to {MODEL_DIR / 'confusion_matrices.png'}")


def select_best_model(report_df):
    """Select the best model based on F1-Score, breaking ties with inference speed."""
    # Primary: highest F1-Score
    # Secondary: lowest inference latency
    report_df = report_df.sort_values(
        by=["F1-Score", "Inference_µs"],
        ascending=[False, True],
    )

    best_name = report_df.iloc[0]["Model"]
    print(f"\n{'='*60}")
    print(f"BEST MODEL: {best_name}")
    print(f"  F1-Score:    {report_df.iloc[0]['F1-Score']}")
    print(f"  FPR:         {report_df.iloc[0]['FPR']}")
    print(f"  Inference:   {report_df.iloc[0]['Inference_µs']} µs/sample")
    print(f"{'='*60}")

    # Copy best model to the canonical name
    src = MODEL_DIR / f"{best_name}.pkl"
    dst = MODEL_DIR / "best_model.pkl"
    joblib.dump(joblib.load(src), dst)
    print(f"✓ Best model saved to {dst}")

    # Save best model name for export script
    with open(MODEL_DIR / "best_model_name.txt", "w") as f:
        f.write(best_name)

    return best_name


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true",
                        help="Use reduced hyperparameter grid for faster iteration")
    args = parser.parse_args()

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    X_train, X_test, y_train, y_test = load_splits()

    models_dict = define_models()

    # In quick mode, reduce grid sizes
    if args.quick:
        print("Quick mode: using reduced hyperparameter grids")
        for spec in models_dict.values():
            for param_name in spec["params"]:
                vals = spec["params"][param_name]
                if len(vals) > 2:
                    spec["params"][param_name] = [vals[0], vals[-1]]

    report = train_and_evaluate(models_dict, X_train, X_test, y_train, y_test)

    # Save comparison report
    report.to_csv(MODEL_DIR / "comparison_report.csv", index=False)
    print(f"\n✓ Comparison report saved to {MODEL_DIR / 'comparison_report.csv'}")
    print("\n" + report.to_string(index=False))

    # Plot confusion matrices
    plot_confusion_matrices(models_dict, X_test, y_test)

    # Select and save best model
    select_best_model(report)


if __name__ == "__main__":
    main()
