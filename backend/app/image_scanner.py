"""Image screenshot scanning, validation, local OCR, and combined risk analysis.

Provides secure screenshot processing:
1. Validates true image format (JPEG, PNG, WebP) and dimensions purely in memory.
2. Rejects spoofed MIME types, oversized uploads (>5MB), and malformed files.
3. Performs local OCR using Tesseract (or injected/mock provider).
4. Feeds extracted text to existing ML scam classifier.
5. Extracts HTTP/HTTPS URLs and evaluates with URL analyzer and threat reputation.
6. Computes unified combined verdict without claiming visual identity verification.
"""

from __future__ import annotations

import io
import logging
import os
import re
import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from PIL import Image, ImageFile

from backend.app.config import (
    ALLOWED_IMAGE_FORMATS,
    MAX_EXTRACTED_URLS,
    MAX_IMAGE_HEIGHT,
    MAX_IMAGE_PIXELS,
    MAX_IMAGE_SIZE_BYTES,
    MAX_IMAGE_WIDTH,
    OCR_ENGINE,
    TESSERACT_CMD,
)
from backend.app.schemas import (
    CombinedEvidenceItem,
    ImageScanResponse,
    OCRResultInfo,
    TextScanResponse,
    URLScanResponse,
)
from backend.app.services import scan_text
from backend.app.url_analyzer import scan_url

logger = logging.getLogger("scamshield.image_scanner")

# Strict handling for corrupted or truncated images
ImageFile.LOAD_TRUNCATED_IMAGES = False
# Pillow decompression bomb protection
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS


class ImageValidationError(Exception):
    """Raised when an uploaded image fails format, size, or integrity checks."""
    pass


# ---------------------------------------------------------------------------
# Image Validation & In-Memory Loading
# ---------------------------------------------------------------------------

def validate_and_open_image(file_bytes: bytes) -> Tuple[Image.Image, str, Tuple[int, int]]:
    """Validate raw uploaded bytes as a real, supported, safely-dimensioned image.
    
    Returns:
        (PIL.Image in memory, format_string, (width, height))
    
    Raises:
        ImageValidationError on any violation.
    """
    if not file_bytes or len(file_bytes) == 0:
        raise ImageValidationError("Uploaded image is empty (0 bytes).")

    if len(file_bytes) > MAX_IMAGE_SIZE_BYTES:
        raise ImageValidationError(
            f"Image file size ({len(file_bytes)} bytes) exceeds maximum allowed limit of {MAX_IMAGE_SIZE_BYTES} bytes (5 MB)."
        )

    # 1. Attempt initial header parsing
    try:
        raw_stream = io.BytesIO(file_bytes)
        img = Image.open(raw_stream)
    except Exception as exc:
        raise ImageValidationError(
            f"Invalid or corrupted image content. The uploaded file cannot be parsed as an image: {exc}"
        ) from exc

    # 2. Check detected format (must match magic bytes, not file extension)
    detected_format = (img.format or "").upper()
    if detected_format not in ALLOWED_IMAGE_FORMATS:
        raise ImageValidationError(
            f"Unsupported image format: '{detected_format or 'unknown'}'. Allowed formats are JPEG, PNG, and WebP."
        )

    # 3. Check image dimensions and pixel count
    width, height = img.size
    if width <= 0 or height <= 0:
        raise ImageValidationError(f"Invalid image dimensions: {width}x{height}.")

    if width > MAX_IMAGE_WIDTH or height > MAX_IMAGE_HEIGHT:
        raise ImageValidationError(
            f"Image dimensions ({width}x{height}) exceed maximum allowed limit of {MAX_IMAGE_WIDTH}x{MAX_IMAGE_HEIGHT} pixels."
        )

    if width * height > MAX_IMAGE_PIXELS:
        raise ImageValidationError(
            f"Image total pixel count ({width * height}) exceeds safety limit of {MAX_IMAGE_PIXELS} pixels."
        )

    # 4. Verify integrity
    try:
        img.verify()
    except Exception as exc:
        raise ImageValidationError(f"Image integrity verification failed: corrupted data ({exc}).") from exc

    # Re-open stream because img.verify() closes or exhausts the PIL reader
    try:
        img_reopened = Image.open(io.BytesIO(file_bytes))
        # Ensure image data can be fully decoded without error
        img_reopened.load()
    except Exception as exc:
        raise ImageValidationError(f"Malformed image data could not be decoded: {exc}") from exc

    return img_reopened, detected_format, (width, height)


# ---------------------------------------------------------------------------
# OCR Provider Interface and Implementations
# ---------------------------------------------------------------------------

class BaseOCRProvider(ABC):
    """Abstract base class for OCR extraction providers."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the OCR engine is configured and ready."""
        pass

    @abstractmethod
    def extract_text(self, image: Image.Image) -> Tuple[str, OCRResultInfo]:
        """Extract text from a PIL Image. Returns (text, OCRResultInfo)."""
        pass


def find_tesseract_binary() -> Optional[str]:
    """Search for Tesseract executable in environment, PATH, and standard Windows paths."""
    if TESSERACT_CMD and os.path.isfile(TESSERACT_CMD):
        return TESSERACT_CMD

    which_path = shutil.which("tesseract")
    if which_path:
        return which_path

    # Common Windows installation directories
    candidate_paths = [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
    ]
    for candidate in candidate_paths:
        if os.path.isfile(candidate):
            return candidate

    return None


class TesseractOCRProvider(BaseOCRProvider):
    """Local Tesseract OCR provider using pytesseract.
    
    Does NOT upload screenshots to any external service.
    Gracefully detects availability on host machine.
    """

    def __init__(self, tesseract_cmd: Optional[str] = None):
        self._cmd = tesseract_cmd or find_tesseract_binary()

    def is_available(self) -> bool:
        return self._cmd is not None and os.path.isfile(self._cmd)

    def extract_text(self, image: Image.Image) -> Tuple[str, OCRResultInfo]:
        if not self.is_available():
            return "", OCRResultInfo(
                status="ocr_unavailable",
                engine="tesseract",
                characters_extracted=0,
                confidence=None,
                notes=(
                    "Local OCR engine (Tesseract) is not installed or not in system PATH. "
                    "Install Tesseract-OCR locally and configure PATH to enable optical text extraction."
                ),
            )

        try:
            import pytesseract
            if self._cmd:
                pytesseract.pytesseract.tesseract_cmd = self._cmd

            # Convert image to RGB mode if necessary for pytesseract
            ocr_img = image
            if ocr_img.mode not in ("RGB", "L"):
                ocr_img = ocr_img.convert("RGB")

            raw_text = pytesseract.image_to_string(ocr_img)
            cleaned_text = (raw_text or "").strip()

            if not cleaned_text:
                return "", OCRResultInfo(
                    status="no_text_detected",
                    engine="tesseract",
                    characters_extracted=0,
                    confidence=None,
                    notes="OCR engine processed the image successfully but detected no readable text.",
                )

            return cleaned_text, OCRResultInfo(
                status="success",
                engine="tesseract",
                characters_extracted=len(cleaned_text),
                confidence=None,
                notes=None,
            )

        except Exception as exc:
            logger.error(f"Tesseract OCR extraction error: {exc}", exc_info=True)
            return "", OCRResultInfo(
                status="ocr_error",
                engine="tesseract",
                characters_extracted=0,
                confidence=None,
                notes=f"OCR execution failed: {type(exc).__name__}: {exc}",
            )


class MockOCRProvider(BaseOCRProvider):
    """Mock OCR provider for deterministic unit testing without external binary dependencies."""

    def __init__(
        self,
        text: Optional[str] = None,
        status: str = "success",
        confidence: Optional[float] = 0.95,
        raise_exception: Optional[Exception] = None,
        is_available_override: Optional[bool] = None,
    ):
        self._text = text or ""
        self._status = status
        self._confidence = confidence
        self._raise_exception = raise_exception
        self._is_available_override = is_available_override

    def is_available(self) -> bool:
        if self._is_available_override is not None:
            return self._is_available_override
        return self._raise_exception is None

    def extract_text(self, image: Image.Image) -> Tuple[str, OCRResultInfo]:
        if self._raise_exception:
            return "", OCRResultInfo(
                status="ocr_error",
                engine="mock",
                characters_extracted=0,
                confidence=None,
                notes=f"Mock OCR failure: {self._raise_exception}",
            )

        if not self._text.strip():
            status = "no_text_detected" if self._status == "success" else self._status
            return "", OCRResultInfo(
                status=status,
                engine="mock",
                characters_extracted=0,
                confidence=self._confidence,
                notes="No text detected in mock image.",
            )

        return self._text, OCRResultInfo(
            status=self._status,
            engine="mock",
            characters_extracted=len(self._text),
            confidence=self._confidence,
            notes=None,
        )


class RapidOCRProvider(BaseOCRProvider):
    """Local ONNX-based OCR provider using RapidOCR.
    
    Runs 100% locally on CPU without external binaries or network downloads.
    Pretrained ONNX models are bundled directly within the installed wheel.
    """

    def __init__(self):
        self._engine = None
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        if self._available is None:
            try:
                import rapidocr_onnxruntime
                self._available = True
            except ImportError:
                self._available = False
        return self._available

    def _get_engine(self):
        if self._engine is None and self.is_available():
            from rapidocr_onnxruntime import RapidOCR
            self._engine = RapidOCR()
        return self._engine

    def extract_text(self, image: Image.Image) -> Tuple[str, OCRResultInfo]:
        if not self.is_available():
            return "", OCRResultInfo(
                status="ocr_unavailable",
                engine="rapidocr",
                characters_extracted=0,
                confidence=None,
                notes=(
                    "RapidOCR engine is not installed or available. "
                    "Install rapidocr-onnxruntime to enable local ONNX OCR."
                ),
            )

        try:
            engine = self._get_engine()
            # Convert image to RGB mode if necessary
            ocr_img = image
            if ocr_img.mode not in ("RGB", "L"):
                ocr_img = ocr_img.convert("RGB")

            result, _ = engine(ocr_img)

            if not result:
                return "", OCRResultInfo(
                    status="no_text_detected",
                    engine="rapidocr",
                    characters_extracted=0,
                    confidence=None,
                    notes="RapidOCR processed the image successfully but detected no readable text.",
                )

            # Extract recognized text lines and confidences
            lines = [item[1] for item in result if len(item) > 1 and item[1]]
            confs = [float(item[2]) for item in result if len(item) > 2 and item[2] is not None]

            cleaned_text = " ".join(lines).strip()
            avg_conf = round(sum(confs) / len(confs), 4) if confs else None

            if not cleaned_text:
                return "", OCRResultInfo(
                    status="no_text_detected",
                    engine="rapidocr",
                    characters_extracted=0,
                    confidence=None,
                    notes="RapidOCR processed the image successfully but detected no readable text.",
                )

            return cleaned_text, OCRResultInfo(
                status="success",
                engine="rapidocr",
                characters_extracted=len(cleaned_text),
                confidence=avg_conf,
                notes=None,
            )

        except Exception as exc:
            logger.error(f"RapidOCR extraction error: {exc}", exc_info=True)
            return "", OCRResultInfo(
                status="ocr_error",
                engine="rapidocr",
                characters_extracted=0,
                confidence=None,
                notes=f"RapidOCR execution failed: {type(exc).__name__}: {exc}",
            )


# Global default provider
_DEFAULT_OCR_PROVIDER: Optional[BaseOCRProvider] = None


def get_ocr_provider() -> BaseOCRProvider:
    """Return the configured OCR provider instance.
    
    Priority resolution:
    1. Explicit manual override (set_ocr_provider).
    2. OCR_ENGINE='tesseract': Tesseract provider.
    3. OCR_ENGINE='rapidocr': RapidOCR provider.
    4. OCR_ENGINE='auto' (default):
       - RapidOCR if installed and available (local ONNX, no external binary needed).
       - Tesseract if binary is installed and accessible.
       - Otherwise falls back to Tesseract (reporting safe ocr_unavailable status).
    """
    global _DEFAULT_OCR_PROVIDER
    if _DEFAULT_OCR_PROVIDER is not None:
        return _DEFAULT_OCR_PROVIDER

    engine_pref = (OCR_ENGINE or "auto").lower()

    if engine_pref == "tesseract":
        return TesseractOCRProvider()
    elif engine_pref == "rapidocr":
        return RapidOCRProvider()
    else:  # "auto"
        rapid = RapidOCRProvider()
        if rapid.is_available():
            return rapid

        tess = TesseractOCRProvider()
        if tess.is_available():
            return tess

        return tess


def set_ocr_provider(provider: Optional[BaseOCRProvider]) -> None:
    """Override the active OCR provider (useful for testing)."""
    global _DEFAULT_OCR_PROVIDER
    _DEFAULT_OCR_PROVIDER = provider


# ---------------------------------------------------------------------------
# URL Extraction from OCR Text
# ---------------------------------------------------------------------------

# Regular expression matching HTTP/HTTPS URLs
URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+",
    re.IGNORECASE,
)

# Trailing punctuation characters commonly captured from sentence endings
TRAILING_PUNCTUATION = ".,;:!?)>\"']}"


def extract_urls_from_text(text: str) -> List[str]:
    """Extract, clean, and deduplicate HTTP/HTTPS URLs found within extracted OCR text."""
    if not text:
        return []

    found = URL_PATTERN.findall(text)
    clean_urls: List[str] = []
    seen: Set[str] = set()

    for raw in found:
        # Strip trailing punctuation marks attached by OCR or sentence structure
        cleaned = raw.rstrip(TRAILING_PUNCTUATION)
        # Basic sanity check: must parse with scheme and netloc
        try:
            parsed = urlparse(cleaned)
            if parsed.scheme.lower() in ("http", "https") and parsed.netloc:
                norm = cleaned.strip()
                if norm not in seen:
                    seen.add(norm)
                    clean_urls.append(norm)
        except Exception:
            continue

        if len(clean_urls) >= MAX_EXTRACTED_URLS:
            break

    return clean_urls


# ---------------------------------------------------------------------------
# Combined Verdict and Evidence Aggregation
# ---------------------------------------------------------------------------

def aggregate_scan_results(
    extracted_text: str,
    ocr_info: OCRResultInfo,
    text_analysis: Optional[TextScanResponse],
    url_analyses: List[URLScanResponse],
) -> Tuple[str, float, str, List[CombinedEvidenceItem], List[str], List[str]]:
    """Determine combined verdict, risk score, evidence signals, and limitations.
    
    Verdict Rules:
    1. 'malicious' if any extracted URL matched a verified malicious threat feed.
    2. 'suspicious' if ML text classification is scam OR any URL heuristic is suspicious.
    3. 'inconclusive' if OCR returned no usable text, OCR was unavailable, or OCR errored.
    4. 'benign' if usable text was analyzed, ML classified it legitimate, and all URLs are benign.
       (Safety flag is always False: image visual identity / logos are unverified).
    """
    evidence: List[CombinedEvidenceItem] = []
    warnings: List[str] = []
    limitations: List[str] = [
        "Visual elements, logos, watermarks, seals, and visual identity were NOT verified.",
        "Screenshot authenticity was not verified; visual images can be forged, cropped, or simulated.",
        "Analysis is limited strictly to optical character recognition (OCR) of visible text and extracted URLs.",
        "Absence of detected threat does NOT guarantee the image or sender is safe or legitimate.",
    ]

    # Check for confirmed malicious URLs
    has_malicious_url = any(u.verdict == "malicious" for u in url_analyses)
    # Check for suspicious URLs
    has_suspicious_url = any(u.verdict == "suspicious" for u in url_analyses)
    # Check for scam text
    is_scam_text = text_analysis.is_scam if text_analysis else False

    # Aggregate Evidence from Text
    if text_analysis and text_analysis.evidence:
        for ev in text_analysis.evidence:
            severity = "high" if ev.signal == "scam_indicator" and ev.weight > 1.0 else (
                "medium" if ev.signal == "scam_indicator" else "low"
            )
            evidence.append(
                CombinedEvidenceItem(
                    source="text",
                    signal=f"text_{ev.signal}",
                    token=ev.token,
                    description=f"Model keyword indicator '{ev.token}' (weight: {ev.weight})",
                    severity=severity,
                    weight=ev.weight,
                )
            )

    # Aggregate Evidence from URLs
    for url_res in url_analyses:
        for u_ev in url_res.evidence:
            evidence.append(
                CombinedEvidenceItem(
                    source="url",
                    signal=f"url_{u_ev.signal}",
                    token=u_ev.signal,
                    description=f"[{url_res.url}] {u_ev.description}",
                    severity=u_ev.severity,
                    weight=u_ev.weight,
                )
            )
        for rep_ev in url_res.reputation_evidence:
            evidence.append(
                CombinedEvidenceItem(
                    source="url",
                    signal="url_threat_feed_match",
                    token=rep_ev.get("threat_type", "threat_match"),
                    description=f"[{url_res.url}] Verified threat match: {rep_ev.get('threat_type', 'threat')} ({rep_ev.get('feed_source', 'feed')})",
                    severity="critical",
                    weight=1.0,
                )
            )

    # Combined Verdict Logic
    if has_malicious_url:
        combined_verdict = "malicious"
        risk_score = 1.0
        risk_level = "critical"
        warnings.append("Critical threat detected: An extracted URL matches known malicious threat intelligence.")
    elif is_scam_text or has_suspicious_url:
        combined_verdict = "suspicious"
        text_prob = text_analysis.scam_probability if text_analysis else 0.0
        url_max_score = max((u.risk_score for u in url_analyses), default=0.0)
        risk_score = round(max(text_prob, url_max_score), 4)
        risk_level = "high" if risk_score >= 0.60 else "medium"
        if is_scam_text and has_suspicious_url:
            warnings.append("High risk: Both image text and extracted URLs exhibit suspicious fraud patterns.")
        elif is_scam_text:
            warnings.append("Suspicious: Visible text in the image exhibits recognized scam characteristics.")
        else:
            warnings.append("Suspicious: URLs extracted from the image exhibit deceptive or risky structural patterns.")
    elif ocr_info.status in ("no_text_detected", "ocr_unavailable", "ocr_error"):
        combined_verdict = "inconclusive"
        risk_score = 0.0
        risk_level = "inconclusive"
        if ocr_info.status == "no_text_detected":
            warnings.append("No readable text detected in image. The image cannot be confirmed safe or fraudulent.")
        elif ocr_info.status == "ocr_unavailable":
            warnings.append(
                "Local OCR engine is unavailable on the server. Image text could not be analyzed; result is inconclusive."
            )
        else:
            warnings.append(f"OCR processing encountered an error: {ocr_info.notes}")
    else:
        # OCR succeeded and text was found, text is legitimate, and all URLs (if any) are benign
        combined_verdict = "benign"
        text_prob = text_analysis.scam_probability if text_analysis else 0.0
        url_max_score = max((u.risk_score for u in url_analyses), default=0.0)
        risk_score = round(max(text_prob, url_max_score), 4)
        risk_level = "low"
        warnings.append(
            "No recognized scam text patterns or malicious URLs detected. Visual authenticity was NOT checked."
        )

    # Note on unconfirmed safe URLs
    if url_analyses:
        for u in url_analyses:
            if not u.reputation_check.matched:
                limitations.append(
                    f"URL '{u.url}' has unknown threat reputation; absence of a known record does NOT confirm safety."
                )

    return combined_verdict, risk_score, risk_level, evidence, warnings, limitations


# ---------------------------------------------------------------------------
# Main Image Scan Pipeline
# ---------------------------------------------------------------------------

def scan_image(
    file_bytes: bytes,
    filename: Optional[str] = None,
    ocr_provider: Optional[BaseOCRProvider] = None,
    reputation_provider: Optional[Any] = None,
) -> ImageScanResponse:
    """Process, validate, OCR-extract, and analyze an uploaded image screenshot.
    
    Images and extracted data are processed strictly in-memory and are NOT persisted to disk.
    """
    # 1. Validate image format, size, and dimensions in memory
    img, detected_format, (width, height) = validate_and_open_image(file_bytes)

    try:
        # 2. Extract visible text via local OCR
        provider = ocr_provider or get_ocr_provider()
        extracted_text, ocr_info = provider.extract_text(img)

        # 3. Analyze extracted text with ML pipeline (if text exists)
        text_analysis: Optional[TextScanResponse] = None
        if extracted_text.strip():
            try:
                text_analysis = scan_text(extracted_text)
            except Exception as exc:
                logger.warning(f"Text analysis of OCR text failed: {exc}")
                # Fallback: proceed without ML text analysis

        # 4. Extract and analyze any HTTP/HTTPS URLs
        extracted_urls = extract_urls_from_text(extracted_text)
        url_analyses: List[URLScanResponse] = []
        for raw_url in extracted_urls:
            try:
                res_dict = scan_url(raw_url, reputation_provider=reputation_provider)
                url_analyses.append(URLScanResponse(**res_dict))
            except Exception as exc:
                logger.warning(f"Failed to analyze extracted URL '{raw_url}': {exc}")

        # 5. Determine combined verdict and aggregate evidence
        (
            combined_verdict,
            risk_score,
            risk_level,
            evidence,
            warnings,
            limitations,
        ) = aggregate_scan_results(
            extracted_text=extracted_text,
            ocr_info=ocr_info,
            text_analysis=text_analysis,
            url_analyses=url_analyses,
        )

        return ImageScanResponse(
            filename=filename,
            image_format=detected_format,
            dimensions={"width": width, "height": height},
            file_size_bytes=len(file_bytes),
            ocr_status=ocr_info.status,
            ocr_info=ocr_info,
            extracted_text=extracted_text,
            text_analysis=text_analysis,
            extracted_urls=extracted_urls,
            url_analyses=url_analyses,
            combined_verdict=combined_verdict,
            verdict=combined_verdict,
            risk_score=risk_score,
            risk_level=risk_level,
            is_confirmed_safe=False,
            evidence=evidence,
            warnings=warnings,
            limitations=limitations,
        )

    finally:
        # Explicit cleanup of in-memory resources
        try:
            img.close()
        except Exception:
            pass
