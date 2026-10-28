"""Training script for ScamShield-AI baseline model.
Trains a TF-IDF + Logistic Regression pipeline on the training split,
evaluates validation performance, and serializes the model artifact to ml/models/model.joblib.
Prevents data leakage: fit() is called strictly on X_train.
"""

from __future__ import annotations

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline


def build_pipeline() -> Pipeline:
    """Build the baseline TF-IDF + Logistic Regression pipeline."""
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    max_features=10000,
                    sublinear_tf=True,
                    stop_words="english",
                    strip_accents="unicode",
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=1000,
                    C=1.0,
                    solver="lbfgs",
                    random_state=42,
                ),
            ),
        ]
    )


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray) -> dict:
    """Compute standard classification evaluation metrics."""
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


def train_baseline(
    train_csv: Path,
    val_csv: Path,
    model_output_path: Path,
) -> tuple[Pipeline, dict]:
    """Train pipeline on train_csv, validate on val_csv, and save artifact."""
    print(f"Loading training data from {train_csv}...")
    train_df = pd.read_csv(train_csv)
    val_df = pd.read_csv(val_csv)

    # Fill NaN texts defensively
    train_df["text"] = train_df["text"].fillna("")
    val_df["text"] = val_df["text"].fillna("")

    X_train = train_df["text"].tolist()
    y_train = train_df["label"].to_numpy(dtype=int)

    X_val = val_df["text"].tolist()
    y_val = val_df["label"].to_numpy(dtype=int)

    print(f"Fitting pipeline on {len(X_train)} training samples...")
    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    print(f"Evaluating on {len(X_val)} validation samples...")
    val_pred = pipeline.predict(X_val)
    val_prob = pipeline.predict_proba(X_val)[:, 1]

    val_metrics = compute_metrics(y_val, val_pred, val_prob)
    print("Validation Metrics:")
    for metric_name, val in val_metrics.items():
        if metric_name != "confusion_matrix":
            print(f"  {metric_name}: {val}")
        else:
            print(f"  {metric_name}: {json.dumps(val)}")

    print(f"Saving trained pipeline to {model_output_path}...")
    model_output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_output_path)
    print(f"Model saved successfully (size: {model_output_path.stat().st_size / 1024:.2f} KB).")

    return pipeline, val_metrics


def main():
    base_dir = Path(__file__).resolve().parent.parent
    train_csv = base_dir / "data" / "processed" / "train.csv"
    val_csv = base_dir / "data" / "processed" / "val.csv"
    model_output_path = base_dir / "models" / "model.joblib"

    if not train_csv.exists() or not val_csv.exists():
        raise FileNotFoundError(
            "Processed train or val CSV not found. Please run ml/src/preprocess.py first."
        )

    train_baseline(train_csv, val_csv, model_output_path)


if __name__ == "__main__":
    main()
