"""FastAPI Application entrypoint for ScamShield-AI.
Exposes GET /health and POST /api/v1/scans/text endpoints.
"""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Ensure project root is on sys.path for direct uvicorn launches
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import (
    API_HOST,
    API_PORT,
    API_PREFIX,
    API_TITLE,
    API_VERSION,
    CORS_ORIGINS,
    MAX_IMAGE_SIZE_BYTES,
)
from backend.app.image_scanner import ImageValidationError, scan_image
from backend.app.schemas import (
    ErrorResponse,
    HealthResponse,
    ImageScanResponse,
    TextScanRequest,
    TextScanResponse,
    URLScanRequest,
    URLScanResponse,
)
from backend.app.services import (
    MLServiceException,
    ModelUnavailableException,
    get_model_status,
    scan_text,
)
from backend.app.url_analyzer import scan_url

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("scamshield.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events."""
    logger.info("Initializing ScamShield-AI Backend...")
    is_loaded, version, err = get_model_status()
    if is_loaded:
        logger.info(f"ML Model successfully verified and loaded: {version}")
    else:
        logger.warning(f"ML Model could not be pre-loaded at startup: {err}")
    yield
    logger.info("ScamShield-AI Backend shutting down.")


app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description="Backend detection and scanning API for ScamShield-AI",
    lifespan=lifespan,
)

# CORS Middleware (explicit development origins, no wildcard with credentials)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Exception Handlers ensuring no stack trace or secrets are exposed
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle input validation failures with safe, clean JSON error envelopes."""
    errors = []
    for err in exc.errors():
        loc = " -> ".join(str(item) for item in err.get("loc", []))
        msg = err.get("msg", "Validation error")
        errors.append(f"{loc}: {msg}")
    return JSONResponse(
        status_code=getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422),
        content={
            "error": "Validation Error",
            "detail": "; ".join(errors),
        },
    )


@app.exception_handler(ImageValidationError)
async def image_validation_exception_handler(request: Request, exc: ImageValidationError):
    """Handle image validation failures with standard safe 422 error envelope."""
    return JSONResponse(
        status_code=getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422),
        content={
            "error": "Validation Error",
            "detail": str(exc),
        },
    )


@app.exception_handler(ModelUnavailableException)
async def model_unavailable_handler(request: Request, exc: ModelUnavailableException):
    """Handle model unavailable errors safely (HTTP 503)."""
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "error": "Service Unavailable",
            "detail": str(exc),
        },
    )


@app.exception_handler(MLServiceException)
async def ml_service_handler(request: Request, exc: MLServiceException):
    """Handle general ML service errors safely (HTTP 500)."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Prediction Error",
            "detail": str(exc),
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Global catch-all preventing stack traces and internal secrets from leaking."""
    logger.error(f"Unhandled server error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "detail": "An unexpected server error occurred while processing the request.",
        },
    )


# Endpoints
@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Application and ML model health check",
    tags=["System"],
)
async def health_check() -> HealthResponse:
    """Check system health and verify whether the ML model is currently loaded."""
    is_loaded, model_version, error_msg = get_model_status()
    overall_status = "ok" if is_loaded else "degraded"

    return HealthResponse(
        status=overall_status,
        model_loaded=is_loaded,
        model_version=model_version,
        api_version=API_VERSION,
    )


@app.post(
    f"{API_PREFIX}/scans/text",
    response_model=TextScanResponse,
    status_code=status.HTTP_200_OK,
    responses={
        422: {"model": ErrorResponse, "description": "Invalid input text"},
        503: {"model": ErrorResponse, "description": "Model unavailable"},
        500: {"model": ErrorResponse, "description": "Prediction error"},
    },
    summary="Scan message text for scam and fraud indicators",
    tags=["Scans"],
)
async def scan_text_endpoint(payload: TextScanRequest) -> TextScanResponse:
    """Analyze a single message text string using the trained ScamShield-AI classifier.

    - **text**: Raw text to analyze (1 to 5000 characters).
    - Returns verdict ('scam' or 'legitimate'), scam probability, confidence, and keyword evidence.
    """
    result = scan_text(payload.text)
    return result


@app.post(
    f"{API_PREFIX}/scans/url",
    response_model=URLScanResponse,
    status_code=status.HTTP_200_OK,
    responses={
        422: {"model": ErrorResponse, "description": "Invalid or unsupported URL syntax"},
        500: {"model": ErrorResponse, "description": "Server error during URL analysis"},
    },
    summary="Scan URL for phishing and fraudulent indicators (offline heuristic analysis)",
    tags=["Scans"],
)
async def scan_url_endpoint(payload: URLScanRequest) -> URLScanResponse:
    """Analyze a single URL using transparent, offline structural heuristics.

    - **url**: URL string to evaluate (http/https, up to 2048 chars).
    - Evaluates IP hostnames, excessive subdomains, brand spoofing, punycode, etc.
    - Strictly offline: never visits, crawls, or sends the URL over the network.
    """
    result = scan_url(payload.url)
    return result


@app.post(
    f"{API_PREFIX}/scans/image",
    response_model=ImageScanResponse,
    status_code=status.HTTP_200_OK,
    responses={
        422: {"model": ErrorResponse, "description": "Invalid, unsupported, or oversized image"},
        500: {"model": ErrorResponse, "description": "Server error during image processing"},
    },
    summary="Scan screenshot or image for scam text and embedded URLs",
    tags=["Scans"],
)
async def scan_image_endpoint(file: UploadFile = File(...)) -> ImageScanResponse:
    """Scan an uploaded screenshot or image (JPEG, PNG, WebP) for fraud indicators.

    - **file**: Multipart image upload (max 5 MB; JPEG, PNG, or WebP).
    - Validates actual image binary content and dimensions in memory.
    - Extracts visible text using local OCR (never uploaded to external third-party services).
    - Analyzes extracted text with ML scam model and scans extracted URLs for threats.
    - Inconclusive verdict if OCR detects no readable text.
    - Does NOT verify logos or visual authenticity; never persists images to disk.
    """
    # Read up to MAX_IMAGE_SIZE_BYTES + 1 to detect oversized files early
    file_bytes = await file.read(MAX_IMAGE_SIZE_BYTES + 1)
    if len(file_bytes) > MAX_IMAGE_SIZE_BYTES:
        raise ImageValidationError(
            f"Image file size ({len(file_bytes)} bytes) exceeds maximum allowed limit of {MAX_IMAGE_SIZE_BYTES} bytes (5 MB)."
        )

    try:
        result = scan_image(
            file_bytes=file_bytes,
            filename=file.filename,
        )
        return result
    finally:
        await file.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host=API_HOST, port=API_PORT, reload=True)

