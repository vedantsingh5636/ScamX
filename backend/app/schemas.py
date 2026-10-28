"""Pydantic schemas for request and response validation."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
from backend.app.config import MAX_TEXT_LENGTH, MIN_TEXT_LENGTH


class HealthResponse(BaseModel):
    """Health check response schema."""
    status: str = Field(..., description="Overall service status ('ok' or 'degraded')")
    model_loaded: bool = Field(..., description="Whether the ML model is successfully loaded in memory")
    model_version: Optional[str] = Field(None, description="ML model version identifier")
    api_version: str = Field("1.0.0", description="API version")


class TextScanRequest(BaseModel):
    """Request schema for text scan."""
    text: str = Field(
        ...,
        description="The text content or message to analyze for scams",
        min_length=MIN_TEXT_LENGTH,
        max_length=MAX_TEXT_LENGTH,
    )

    @field_validator("text")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("Input text cannot be empty or contain only whitespace.")
        return trimmed


class EvidenceItem(BaseModel):
    """Explanation/evidence token extracted from model weights."""
    token: str = Field(..., description="N-gram or word token identified in message")
    weight: float = Field(..., description="Model coefficient weight associated with this token")
    signal: str = Field(..., description="'scam_indicator' or 'legitimate_indicator'")


class TextScanResponse(BaseModel):
    """Structured response schema matching ScamShield-AI specifications."""
    text: str = Field(..., description="Input message text analyzed")
    label: str = Field(..., description="Classification verdict: 'scam' or 'legitimate'")
    is_scam: bool = Field(..., description="Boolean flag: True if scam, False if legitimate")
    scam_probability: float = Field(..., ge=0.0, le=1.0, description="Model scam probability score")
    probabilities: Dict[str, float] = Field(
        ...,
        description="Probability distribution across classes ('legitimate', 'scam')",
    )
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence of the predicted class")
    model_version: str = Field(..., description="ML model version string")
    calibrated: bool = Field(False, description="Flag indicating if probabilities are calibrated")
    evidence: List[EvidenceItem] = Field(
        default_factory=list,
        description="Identified keyword signals based on learned model weights",
    )
    explanation: Optional[str] = Field(
        None,
        description="Human-readable explanation of the prediction outcome",
    )


class ErrorResponse(BaseModel):
    """Safe standard error envelope without leaking stack traces or internal secrets."""
    error: str = Field(..., description="High-level error classification")
    detail: str = Field(..., description="Safe user-facing explanation of the error")


class URLEvidenceItem(BaseModel):
    """Evidence item for a detected URL heuristic risk signal."""
    signal: str = Field(..., description="Identifier name of the detected signal")
    description: str = Field(..., description="Explanation of why this signal is considered risky")
    severity: str = Field(..., description="Severity level: 'low', 'medium', or 'high'")
    weight: float = Field(..., description="Risk score contribution")


class ReputationCheckInfo(BaseModel):
    """Status and match details from verified threat intelligence feeds."""
    feed_available: bool = Field(False, description="Whether a verified local feed snapshot is active")
    matched: bool = Field(False, description="Whether the URL matched a verified reputation list")
    status: str = Field("unavailable", description="Lookup status: 'matched', 'unknown', 'unavailable', 'stale_match', 'stale_unknown'")
    match_type: Optional[str] = Field(None, description="Type of pattern matched: 'exact_url', 'host', 'apex_domain'")
    threat_type: Optional[str] = Field(None, description="Identified threat category: 'malware_distribution', 'phishing', 'credential_theft'")
    feed_source: Optional[str] = Field(None, description="Threat intelligence feed name/provider")
    reference_id: Optional[str] = Field(None, description="External intelligence reference ID")
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Feed provider confidence score")
    feed_retrieved_at: Optional[str] = Field(None, description="ISO timestamp when feed snapshot was created")
    feed_age_days: Optional[float] = Field(None, description="Age of the local feed snapshot in days")
    is_stale: bool = Field(False, description="Whether the feed snapshot exceeds freshness threshold")
    notes: str = Field(..., description="Clarification of reputation check status and limitations")
    is_confirmed_safe: bool = Field(False, description="Explicit flag: missing feed match is UNKNOWN, never confirmed safe")


class URLScanRequest(BaseModel):
    """Request schema for URL scan."""
    url: str = Field(
        ...,
        description="The web URL to scan for phishing and scam indicators",
        min_length=1,
        max_length=2048,
    )

    @field_validator("url")
    @classmethod
    def validate_url_syntax(cls, value: str) -> str:
        from backend.app.url_analyzer import normalize_and_validate_url
        normalize_and_validate_url(value)
        return value.strip()


class URLScanResponse(BaseModel):
    """Structured response schema for URL scan results."""
    url: str = Field(..., description="Original submitted URL")
    normalized_url: str = Field(..., description="Canonical normalized URL")
    verdict: str = Field(..., description="Overall verdict: 'malicious', 'suspicious', 'benign', or 'inconclusive'")
    label: str = Field(..., description="Compatibility alias for verdict ('malicious', 'suspicious', 'benign', 'inconclusive')")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Risk score from 0.0 to 1.0 (heuristic-derived or 1.0 on confirmed match)")
    risk_level: str = Field(..., description="Categorical risk level: 'low', 'medium', 'high', or 'critical'")
    heuristic_verdict: str = Field(..., description="Heuristic-only verdict before threat intelligence comparison")
    evidence: List[URLEvidenceItem] = Field(
        default_factory=list,
        description="List of detected heuristic risk signals",
    )
    reputation_evidence: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of verified threat intelligence reputation matches",
    )
    analysis_method: str = Field(..., description="Analysis methodology used")
    limitations: List[str] = Field(..., description="Explicit limitations of this offline static analysis")
    reputation_check: ReputationCheckInfo = Field(..., description="Reputation feed check status and metadata")


class OCRResultInfo(BaseModel):
    """OCR processing details and operational status."""
    status: str = Field(..., description="Status: 'success', 'no_text_detected', 'ocr_unavailable', or 'ocr_error'")
    engine: str = Field("tesseract", description="OCR engine utilized (e.g. 'tesseract', 'mock', 'none')")
    characters_extracted: int = Field(0, description="Total number of characters extracted by OCR")
    confidence: Optional[float] = Field(None, description="Average OCR confidence score if reported by engine")
    notes: Optional[str] = Field(None, description="Operational notes, troubleshooting or failure details")


class CombinedEvidenceItem(BaseModel):
    """Unified risk evidence signal aggregated from text or URL analysis."""
    source: str = Field(..., description="Source of evidence: 'text' or 'url'")
    signal: str = Field(..., description="Identifier name of the detected risk signal")
    token: Optional[str] = Field(None, description="Keyword token or indicator identifier")
    description: str = Field(..., description="Explanation of why this signal is considered risky")
    severity: str = Field(..., description="Severity level: 'low', 'medium', 'high', or 'critical'")
    weight: Optional[float] = Field(None, description="Risk score or coefficient contribution")


class ImageScanResponse(BaseModel):
    """Structured response schema for image screenshot scam scan."""
    filename: Optional[str] = Field(None, description="Original filename of the submitted image")
    image_format: str = Field(..., description="Validated image format: 'JPEG', 'PNG', or 'WEBP'")
    dimensions: Dict[str, int] = Field(..., description="Image width and height in pixels")
    file_size_bytes: int = Field(..., description="Validated file size in bytes")
    ocr_status: str = Field(..., description="OCR status: 'success', 'no_text_detected', 'ocr_unavailable', or 'ocr_error'")
    ocr_info: OCRResultInfo = Field(..., description="Detailed OCR processing status and metadata")
    extracted_text: str = Field(..., description="Visible text extracted from image via OCR")
    text_analysis: Optional[TextScanResponse] = Field(None, description="ML text scan analysis if text was usable")
    extracted_urls: List[str] = Field(default_factory=list, description="Unique HTTP/HTTPS URLs extracted from text")
    url_analyses: List[URLScanResponse] = Field(default_factory=list, description="Analyses for each extracted URL")
    combined_verdict: str = Field(..., description="Overall verdict: 'malicious', 'suspicious', 'benign', or 'inconclusive'")
    verdict: str = Field(..., description="Compatibility alias for combined_verdict")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Overall risk score from 0.0 to 1.0")
    risk_level: str = Field(..., description="Categorical risk level: 'low', 'medium', 'high', 'critical', or 'inconclusive'")
    is_confirmed_safe: bool = Field(False, description="Safety flag: False even for benign verdicts as visual identity is unverified")
    evidence: List[CombinedEvidenceItem] = Field(default_factory=list, description="Aggregated evidence signals from text and URLs")
    warnings: List[str] = Field(default_factory=list, description="Operational warnings and security caveats")
    limitations: List[str] = Field(default_factory=list, description="Explicit limitations of screenshot/image scanning")


