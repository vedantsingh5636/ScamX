"""ML prediction service wrapper for ScamShield-AI backend.
Directly interfaces with ml/src/predict.py and extracts model evidence.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import MODEL_PATH
from backend.app.schemas import EvidenceItem, TextScanResponse

logger = logging.getLogger("scamshield.services")


class MLServiceException(Exception):
    """Custom exception for ML service errors."""
    pass


class ModelUnavailableException(MLServiceException):
    """Raised when the model artifact cannot be found or loaded."""
    pass


def get_model_status() -> Tuple[bool, Optional[str], Optional[str]]:
    """Check whether the model file exists and can be loaded.
    Returns: (is_loaded, model_version, error_message)
    """
    try:
        from ml.src.predict import load_model, MODEL_VERSION
        model = load_model(MODEL_PATH)
        if model is None:
            return False, None, "Model loaded object is None"
        return True, MODEL_VERSION, None
    except FileNotFoundError:
        logger.warning(f"Model file not found at {MODEL_PATH}")
        return False, None, "Model file not found"
    except Exception as exc:
        logger.error(f"Error loading model: {exc}")
        return False, None, "Failed to load model artifact"


def extract_evidence(
    text: str,
    model: Any,
    top_k: int = 5,
    is_scam: Optional[bool] = None,
) -> Tuple[List[EvidenceItem], Optional[str]]:
    """Extract keyword evidence and rationale from the fitted pipeline weights."""
    evidence_items: List[EvidenceItem] = []
    explanation: Optional[str] = None

    try:
        tfidf = getattr(model, "named_steps", {}).get("tfidf")
        clf = getattr(model, "named_steps", {}).get("clf")

        if tfidf is None or clf is None:
            return evidence_items, explanation

        # Analyze tokens in the input text using the pipeline's vectorizer
        analyzer = tfidf.build_analyzer()
        text_tokens = analyzer(text)

        vocab = tfidf.vocabulary_
        coefs = clf.coef_[0]

        matched_tokens: Dict[str, float] = {}
        for token in set(text_tokens):
            if token in vocab:
                idx = vocab[token]
                matched_tokens[token] = float(coefs[idx])

        # Sort tokens by absolute weight or positive weight.
        # Exclude pure numeric tokens (e.g., '00', '28', '24') from being labeled as scam keyword evidence.
        # Genuine scam signals are semantic words or brand tokens, not arbitrary digits or slide/page numbers.
        scam_tokens = [
            (t, w) for t, w in matched_tokens.items()
            if w > 0.3 and any(c.isalpha() for c in t)
        ]
        scam_tokens.sort(key=lambda x: x[1], reverse=True)

        legit_tokens = [
            (t, w) for t, w in matched_tokens.items()
            if w < -0.3 and any(c.isalpha() for c in t)
        ]
        legit_tokens.sort(key=lambda x: x[1])

        # Top scam signals
        for token, weight in scam_tokens[:top_k]:
            evidence_items.append(
                EvidenceItem(
                    token=token,
                    weight=round(weight, 4),
                    signal="scam_indicator",
                )
            )

        # Top legitimate signals
        for token, weight in legit_tokens[:2]:
            evidence_items.append(
                EvidenceItem(
                    token=token,
                    weight=round(weight, 4),
                    signal="legitimate_indicator",
                )
            )

        if is_scam is False:
            if scam_tokens:
                top_names = [f"'{t}'" for t, _ in scam_tokens[:3]]
                explanation = f"Text evaluated as legitimate. Minor keyword flags ({', '.join(top_names)}) did not exceed the scam threshold."
            else:
                explanation = "No recognized scam keywords identified in text. Text is consistent with legitimate content."
        elif scam_tokens:
            top_names = [f"'{t}'" for t, _ in scam_tokens[:3]]
            explanation = f"Detected high-risk scam indicators: {', '.join(top_names)}."
        else:
            explanation = "No strong scam keywords identified in text."

    except Exception as exc:
        logger.debug(f"Evidence extraction skipped: {exc}")

    return evidence_items, explanation


def scan_text(text: str) -> TextScanResponse:
    """Scan input text using the existing ml/src/predict.py pipeline."""
    try:
        from ml.src.predict import predict, load_model
        # Ensure model is loadable
        model = load_model(MODEL_PATH)
    except FileNotFoundError:
        raise ModelUnavailableException("ML model artifact is not available on the server.")
    except Exception as exc:
        logger.error(f"Failed to access model: {exc}")
        raise ModelUnavailableException("ML model is temporarily unavailable.")

    try:
        # Call existing ML predict interface directly
        raw_pred = predict(text, model_path=MODEL_PATH)
    except Exception as exc:
        logger.error(f"Prediction failed: {exc}")
        raise MLServiceException("An error occurred while evaluating the message text.")

    # Extract explanation and evidence tokens from fitted weights
    evidence, explanation = extract_evidence(text, model, is_scam=raw_pred.get("is_scam"))

    return TextScanResponse(
        text=raw_pred["text"],
        label=raw_pred["label"],
        is_scam=raw_pred["is_scam"],
        scam_probability=raw_pred["scam_probability"],
        probabilities=raw_pred["probabilities"],
        confidence=raw_pred["confidence"],
        model_version=raw_pred["model_version"],
        calibrated=raw_pred["calibrated"],
        evidence=evidence,
        explanation=explanation,
    )
