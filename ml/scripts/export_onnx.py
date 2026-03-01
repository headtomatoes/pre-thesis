"""
export_onnx.py — Export the best trained model to ONNX format.

Converts the scikit-learn/XGBoost/LightGBM model to ONNX so it can
be loaded by the Go controller via ONNX Runtime for real-time inference.

Outputs:
  - models/model.onnx
  - Verification: compares Python vs ONNX predictions

Usage:
    python scripts/export_onnx.py
"""

import sys
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
import onnx
from skl2onnx import convert_sklearn, update_registered_converter
from skl2onnx.common.shape_calculator import calculate_linear_classifier_output_shapes
from skl2onnx.common.data_types import FloatTensorType

warnings.filterwarnings("ignore")

DATA_DIR  = Path(__file__).parent.parent / "data"
MODEL_DIR = Path(__file__).parent.parent / "models"

N_FEATURES = 10  # The "Lightweight 10"


def register_converters():
    """Register custom ONNX converters for XGBoost and LightGBM."""
    try:
        from onnxmltools.convert.xgboost.operator_converters.XGBoost import convert_xgboost
        from xgboost import XGBClassifier
        update_registered_converter(
            XGBClassifier,
            "XGBoostXGBClassifier",
            calculate_linear_classifier_output_shapes,
            convert_xgboost,
            options={"nocl": [True, False], "zipmap": [True, False, "columns"]},
        )
        print("  ✓ XGBoost converter registered")
    except ImportError:
        print("  ⚠ XGBoost ONNX converter not available")

    try:
        from onnxmltools.convert.lightgbm.operator_converters.LightGbm import convert_lightgbm_classifier
        from lightgbm import LGBMClassifier
        update_registered_converter(
            LGBMClassifier,
            "LightGbmLGBMClassifier",
            calculate_linear_classifier_output_shapes,
            convert_lightgbm_classifier,
            options={"nocl": [True, False], "zipmap": [True, False, "columns"]},
        )
        print("  ✓ LightGBM converter registered")
    except ImportError:
        print("  ⚠ LightGBM ONNX converter not available")


def export_to_onnx(model, output_path: Path):
    """Convert a scikit-learn compatible model to ONNX format."""
    print(f"\nConverting {type(model).__name__} to ONNX...")

    # Define input type: batch of N_FEATURES float32 values
    initial_type = [("features", FloatTensorType([None, N_FEATURES]))]

    onnx_model = convert_sklearn(
        model,
        initial_types=initial_type,
        target_opset=13,
        options={id(model): {"zipmap": False}},  # Return array instead of dict
    )

    # Rename outputs for clarity
    for output in onnx_model.graph.output:
        if "label" in output.name:
            output.name = "predicted_label"
        elif "probabilities" in output.name:
            output.name = "probabilities"

    # Validate
    onnx.checker.check_model(onnx_model)

    # Save
    onnx.save_model(onnx_model, str(output_path))
    size_kb = output_path.stat().st_size / 1024
    print(f"  ✓ ONNX model saved to {output_path} ({size_kb:.1f} KB)")

    return onnx_model


def verify_onnx(model, onnx_path: Path, X_test: pd.DataFrame):
    """Verify ONNX model produces matching predictions."""
    import onnxruntime as ort

    print("\nVerifying ONNX model outputs...")

    session = ort.InferenceSession(str(onnx_path))

    # Get input/output names
    input_name = session.get_inputs()[0].name
    output_names = [o.name for o in session.get_outputs()]
    print(f"  Input:  {input_name} {session.get_inputs()[0].shape}")
    print(f"  Output: {output_names}")

    # Compare predictions on test subset
    X_sample = X_test.iloc[:100].values.astype(np.float32)

    # Python predictions
    py_pred = model.predict(X_sample)
    py_proba = model.predict_proba(X_sample) if hasattr(model, "predict_proba") else None

    # ONNX predictions
    onnx_out = session.run(None, {input_name: X_sample})
    onnx_pred = onnx_out[0]  # labels
    onnx_proba = onnx_out[1] if len(onnx_out) > 1 else None

    # Compare labels
    match_rate = (py_pred == onnx_pred.flatten()).mean()
    print(f"  Label match rate: {match_rate:.4f}")

    # Compare probabilities
    if py_proba is not None and onnx_proba is not None:
        max_diff = np.abs(py_proba - onnx_proba).max()
        print(f"  Max probability difference: {max_diff:.6f}")

    if match_rate < 0.99:
        print("  ⚠ WARNING: Predictions diverge significantly!")
    else:
        print("  ✓ Verification passed!")


def main():
    # Load best model
    model_path = MODEL_DIR / "best_model.pkl"
    if not model_path.exists():
        print("Error: No trained model found. Run `python scripts/train.py` first.")
        sys.exit(1)

    model = joblib.load(model_path)
    model_name = "Unknown"
    name_file = MODEL_DIR / "best_model_name.txt"
    if name_file.exists():
        model_name = name_file.read_text().strip()

    print(f"Model: {model_name} ({type(model).__name__})")

    # Register custom converters
    register_converters()

    # Export
    onnx_path = MODEL_DIR / "model.onnx"
    export_to_onnx(model, onnx_path)

    # Load test data for verification
    test_df = pd.read_csv(DATA_DIR / "test.csv")
    X_test = test_df.drop(columns=["label"])

    # Verify
    try:
        verify_onnx(model, onnx_path, X_test)
    except ImportError:
        print("\n⚠ Install 'onnxruntime' to verify: pip install onnxruntime")
    except Exception as e:
        print(f"\n⚠ Verification failed: {e}")

    print(f"\n✓ Export complete. ONNX model ready at: {onnx_path}")
    print("  Copy this file to the Go controller's model directory.")


if __name__ == "__main__":
    main()
