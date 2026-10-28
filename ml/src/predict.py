"""Inference interface for ScamShield-AI.
Exposes predict(text: str) -> dict for FastAPI backend integration.
Provides model caching to ensure fast, low-latency prediction.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

# Mitigate Windows OpenBLAS memory pool allocation limits in Python 3.12
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")

import joblib

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "model.joblib"
MODEL_VERSION = "v1.0.0-baseline-tfidf-lr"

# In-memory singleton cache
_MODEL = None
_LOADED_PATH = None


def load_model(model_path: Optional[str | Path] = None):
    """Load and cache the trained scikit-learn pipeline."""
    global _MODEL, _LOADED_PATH

    path = Path(model_path) if model_path else DEFAULT_MODEL_PATH

    if _MODEL is None or _LOADED_PATH != str(path):
        if not path.exists():
            raise FileNotFoundError(
                f"Trained model not found at {path}. Run ml/src/train.py first."
            )
        _MODEL = joblib.load(path)
        _LOADED_PATH = str(path)

    return _MODEL


def predict(text: str, model_path: Optional[str | Path] = None) -> dict:
    """Predict whether a given message text is a scam or legitimate.

    Args:
        text: Input string to scan.
        model_path: Optional path to custom model artifact.

    Returns:
        dict: Structured prediction dictionary containing:
            - text: input text (truncated if very long)
            - label: 'scam' or 'legitimate'
            - is_scam: boolean flag
            - scam_probability: float between 0.0 and 1.0
            - probabilities: dict with 'legitimate' and 'scam' probabilities
            - confidence: float highest class probability
            - model_version: model identifier string
            - calibrated: False (uncalibrated logistic sigmoid output)
    """
    model = load_model(model_path)

    sanitized_text = "" if text is None else str(text).strip()

    # Empty string handling
    if not sanitized_text:
        return {
            "text": "",
            "label": "legitimate",
            "is_scam": False,
            "scam_probability": 0.0,
            "probabilities": {
                "legitimate": 1.0,
                "scam": 0.0,
            },
            "confidence": 1.0,
            "model_version": MODEL_VERSION,
            "calibrated": False,
        }

    # Model inference: classes_ are [0, 1] mapped to [legitimate, scam]
    probs = model.predict_proba([sanitized_text])[0]
    legit_prob = round(float(probs[0]), 4)
    scam_prob = round(float(probs[1]), 4)

    is_scam = bool(scam_prob >= 0.50)
    label = "scam" if is_scam else "legitimate"
    confidence = round(float(max(legit_prob, scam_prob)), 4)

    return {
        "text": sanitized_text if len(sanitized_text) <= 500 else sanitized_text[:497] + "...",
        "label": label,
        "is_scam": is_scam,
        "scam_probability": scam_prob,
        "probabilities": {
            "legitimate": legit_prob,
            "scam": scam_prob,
        },
        "confidence": confidence,
        "model_version": MODEL_VERSION,
        "calibrated": False,
    }


if __name__ == "__main__":
    # Quick CLI test
    import sys

    sample_texts = [
        "URGENT: Your bank account has been locked. Verify immediately at http://scam-bank.com to avoid charges.",
        "Hey Mom, I will be home around 6 for dinner. Love you!",
        "WINNER!! You have won a guaranteed cash prize of 5000 pounds. Claim now by calling 09050000332.",
        "Can you send me the lecture notes for CS101 when you get a chance?",
    ]

    print("Running sample predictions:")
    for sample in sample_texts:
        res = predict(sample)
        print(f"\nText: {res['text']}")
        print(f"  Verdict: {res['label']} (Scam Prob: {res['scam_probability']:.4f}, Confidence: {res['confidence']:.4f})")
