"""Evaluation script for ScamShield-AI baseline model.
Evaluates the saved pipeline on the strictly held-out test set (ml/data/processed/test.csv)
and exports comprehensive performance metrics to ml/reports/baseline_metrics.json.
Enforces test-set isolation: this script only measures final performance.
"""

from __future__ import annotations

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def compute_split_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray) -> dict:
    """Compute detailed classification metrics including rates and confusion matrix."""
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision_macro": round(float(precision_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "recall_macro": round(float(recall_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "f1_macro": round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "f1_weighted": round(float(f1_score(y_true, y_pred, average="weighted", zero_division=0)), 4),
        "scam_precision": round(float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)), 4),
        "scam_recall": round(float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)), 4),
        "scam_f1": round(float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 4),
        "confusion_matrix": {
            "true_negatives_legit": int(tn),
            "false_positives_false_alarm": int(fp),
            "false_negatives_missed_scam": int(fn),
            "true_positives_detected_scam": int(tp),
        },
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0, 4),
        "false_negative_rate": round(float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0, 4),
    }


def evaluate_model(
    model_path: Path,
    val_csv: Path,
    test_csv: Path,
    report_output_path: Path,
) -> dict:
    """Evaluate pipeline on validation and held-out test splits."""
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found at {model_path}")

    print(f"Loading model from {model_path}...")
    pipeline = joblib.load(model_path)

    val_df = pd.read_csv(val_csv).fillna("")
    test_df = pd.read_csv(test_csv).fillna("")

    # Validation evaluation
    val_X = val_df["text"].tolist()
    val_y = val_df["label"].to_numpy(dtype=int)
    val_pred = pipeline.predict(val_X)
    val_prob = pipeline.predict_proba(val_X)[:, 1]
    val_metrics = compute_split_metrics(val_y, val_pred, val_prob)

    # Held-out Test evaluation
    test_X = test_df["text"].tolist()
    test_y = test_df["label"].to_numpy(dtype=int)
    test_pred = pipeline.predict(test_X)
    test_prob = pipeline.predict_proba(test_X)[:, 1]
    test_metrics = compute_split_metrics(test_y, test_pred, test_prob)

    report = {
        "model_architecture": "TF-IDF (1-2 ngrams, max_features=10000) + LogisticRegression(class_weight='balanced')",
        "model_file": str(model_path.name),
        "model_version": "v1.0.0-baseline-tfidf-lr",
        "dataset": "SMS Spam Collection (UCI)",
        "sample_counts": {
            "validation_samples": len(val_df),
            "test_samples": len(test_df),
        },
        "probability_calibration": {
            "is_calibrated": False,
            "method": "raw_logistic_sigmoid",
            "notes": "Probabilities represent uncalibrated logistic sigmoid outputs. Platt scaling or Isotonic Regression planned for Day 2 calibration.",
        },
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
    }

    report_output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"Metrics saved to {report_output_path}")
    print("\n=== HELD-OUT TEST EVALUATION SUMMARY ===")
    print(f"Accuracy:         {test_metrics['accuracy']:.4f}")
    print(f"Scam Precision:   {test_metrics['scam_precision']:.4f}")
    print(f"Scam Recall:      {test_metrics['scam_recall']:.4f}")
    print(f"Scam F1-Score:    {test_metrics['scam_f1']:.4f}")
    print(f"ROC-AUC:          {test_metrics['roc_auc']:.4f}")
    print(f"Confusion Matrix: TN={test_metrics['confusion_matrix']['true_negatives_legit']}, "
          f"FP={test_metrics['confusion_matrix']['false_positives_false_alarm']}, "
          f"FN={test_metrics['confusion_matrix']['false_negatives_missed_scam']}, "
          f"TP={test_metrics['confusion_matrix']['true_positives_detected_scam']}")
    print("=========================================\n")

    return report


def main():
    base_dir = Path(__file__).resolve().parent.parent
    model_path = base_dir / "models" / "model.joblib"
    val_csv = base_dir / "data" / "processed" / "val.csv"
    test_csv = base_dir / "data" / "processed" / "test.csv"
    report_output_path = base_dir / "reports" / "baseline_metrics.json"

    evaluate_model(model_path, val_csv, test_csv, report_output_path)


if __name__ == "__main__":
    main()
