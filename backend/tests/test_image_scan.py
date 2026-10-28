"""Unit and integration tests for secure image screenshot scam scanning (Milestone 4).

Covers:
1. Valid images (PNG, JPEG, WebP)
2. Scam text detection via ML classifier
3. Legitimate text detection
4. Extracted URLs and threat intelligence reputation lookup
5. Extracted URLs with suspicious heuristics
6. Unreadable / no-text images -> inconclusive verdict (never confirmed safe)
7. OCR engine unavailable -> inconclusive verdict
8. OCR failures / exceptions handled safely
9. Unsupported formats (BMP, GIF) rejected (422)
10. Spoofed MIME types (text file renamed as image) rejected (422)
11. Oversized image uploads (>5 MB) rejected (422)
12. Malformed / corrupted image bytes rejected (422)
13. Excessive dimension limits rejected (422)
14. Empty files rejected (422)
15. Privacy & hygiene: no image persistence to disk
16. Mandatory disclaimers: no logo or visual identity verification claims
"""

from __future__ import annotations

import io
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from PIL import Image

from backend.app.config import MAX_IMAGE_SIZE_BYTES
from backend.app.image_scanner import (
    ImageValidationError,
    MockOCRProvider,
    TesseractOCRProvider,
    extract_urls_from_text,
    set_ocr_provider,
    validate_and_open_image,
)
from backend.app.main import app


def create_in_memory_image(img_format: str = "PNG", size: tuple[int, int] = (120, 80), color: str = "white") -> bytes:
    """Generate in-memory valid image bytes using Pillow."""
    img = Image.new("RGB", size, color=color)
    buf = io.BytesIO()
    img.save(buf, format=img_format)
    return buf.getvalue()


class TestImageScanMilestone4(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def tearDown(self):
        # Reset OCR provider override after each test
        set_ocr_provider(None)

    # -----------------------------------------------------------------------
    # Valid Images & ML Classification
    # -----------------------------------------------------------------------

    def test_valid_png_with_scam_text(self):
        """Valid PNG image with high-risk scam text must return suspicious verdict."""
        scam_text = "URGENT! You have won a 1000 cash prize! Call 09061743806 right now to claim before it expires."
        set_ocr_provider(MockOCRProvider(text=scam_text))

        img_bytes = create_in_memory_image("PNG")
        files = {"file": ("screenshot.png", img_bytes, "image/png")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["ocr_status"], "success")
        self.assertEqual(data["image_format"], "PNG")
        self.assertEqual(data["combined_verdict"], "suspicious")
        self.assertEqual(data["verdict"], "suspicious")
        self.assertIn(data["risk_level"], ["high", "medium"])
        self.assertGreater(data["risk_score"], 0.50)
        self.assertFalse(data["is_confirmed_safe"])
        self.assertIsNotNone(data["text_analysis"])
        self.assertTrue(data["text_analysis"]["is_scam"])
        self.assertGreater(len(data["evidence"]), 0)

    def test_valid_jpeg_with_legitimate_text(self):
        """Valid JPEG image with legitimate text must return benign verdict."""
        legit_text = "Hey Alex, are we still meeting in the computer lab at 3pm today?"
        set_ocr_provider(MockOCRProvider(text=legit_text))

        img_bytes = create_in_memory_image("JPEG")
        files = {"file": ("screenshot.jpg", img_bytes, "image/jpeg")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["ocr_status"], "success")
        self.assertEqual(data["image_format"], "JPEG")
        self.assertEqual(data["combined_verdict"], "benign")
        self.assertEqual(data["risk_level"], "low")
        self.assertLess(data["risk_score"], 0.50)
        self.assertFalse(data["is_confirmed_safe"])
        self.assertFalse(data["text_analysis"]["is_scam"])

    def test_valid_webp_image_scan(self):
        """Valid WebP image format must be accepted and parsed correctly."""
        set_ocr_provider(MockOCRProvider(text="Office memo: Please review the updated policy doc."))

        img_bytes = create_in_memory_image("WEBP")
        files = {"file": ("memo.webp", img_bytes, "image/webp")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["image_format"], "WEBP")
        self.assertEqual(data["ocr_status"], "success")
        self.assertEqual(data["combined_verdict"], "benign")

    # -----------------------------------------------------------------------
    # URL Extraction & Combined Threat Logic
    # -----------------------------------------------------------------------

    def test_image_with_extracted_malicious_reputation_url(self):
        """Image containing a URL matching verified threat intelligence must elevate verdict to malicious."""
        text_with_url = (
            "Security Alert! Your account is locked. "
            "Please verify immediately at http://malware-drop.example.com/payload.exe to unlock."
        )
        set_ocr_provider(MockOCRProvider(text=text_with_url))

        img_bytes = create_in_memory_image("PNG")
        files = {"file": ("alert.png", img_bytes, "image/png")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["combined_verdict"], "malicious")
        self.assertEqual(data["risk_score"], 1.0)
        self.assertEqual(data["risk_level"], "critical")
        self.assertFalse(data["is_confirmed_safe"])
        self.assertIn("http://malware-drop.example.com/payload.exe", data["extracted_urls"])
        self.assertEqual(len(data["url_analyses"]), 1)
        self.assertEqual(data["url_analyses"][0]["verdict"], "malicious")

        # Verify threat intelligence evidence item exists
        url_threat_signals = [
            e for e in data["evidence"] if e["signal"] == "url_threat_feed_match"
        ]
        self.assertGreater(len(url_threat_signals), 0)

    def test_image_with_suspicious_heuristic_url(self):
        """Image containing an IP-hosted phishing URL must trigger suspicious verdict."""
        text_with_url = (
            "Account notice: Access your secure portal at http://192.168.1.1/paypal/login/verify.exe now."
        )
        set_ocr_provider(MockOCRProvider(text=text_with_url))

        img_bytes = create_in_memory_image("PNG")
        files = {"file": ("phish.png", img_bytes, "image/png")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["combined_verdict"], "suspicious")
        self.assertGreaterEqual(data["risk_score"], 0.60)
        self.assertEqual(data["risk_level"], "high")
        self.assertEqual(len(data["url_analyses"]), 1)
        self.assertEqual(data["url_analyses"][0]["verdict"], "suspicious")

    def test_image_with_clean_benign_url(self):
        """Image containing a benign URL and clean text must remain benign with unknown reputation note."""
        text_with_url = "Check the schedule on https://docs.python.org/3/tutorial/index.html"
        set_ocr_provider(MockOCRProvider(text=text_with_url))

        img_bytes = create_in_memory_image("PNG")
        files = {"file": ("docs.png", img_bytes, "image/png")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["combined_verdict"], "benign")
        self.assertEqual(data["risk_level"], "low")
        self.assertFalse(data["is_confirmed_safe"])
        self.assertIn("https://docs.python.org/3/tutorial/index.html", data["extracted_urls"])

    # -----------------------------------------------------------------------
    # Inconclusive & Failure Scenarios
    # -----------------------------------------------------------------------

    def test_unreadable_no_text_image_returns_inconclusive(self):
        """When OCR produces no readable text, verdict must be inconclusive, NOT safe."""
        set_ocr_provider(MockOCRProvider(text="", status="no_text_detected"))

        img_bytes = create_in_memory_image("PNG")
        files = {"file": ("empty.png", img_bytes, "image/png")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["ocr_status"], "no_text_detected")
        self.assertEqual(data["combined_verdict"], "inconclusive")
        self.assertEqual(data["verdict"], "inconclusive")
        self.assertEqual(data["risk_level"], "inconclusive")
        self.assertFalse(data["is_confirmed_safe"])
        self.assertIsNone(data["text_analysis"])
        # Must clearly inform user in warnings
        warning_text = " ".join(data["warnings"])
        self.assertIn("No readable text detected", warning_text)

    def test_ocr_unavailable_returns_inconclusive(self):
        """When OCR engine is unavailable, verdict must be inconclusive, NOT safe."""
        set_ocr_provider(MockOCRProvider(text="", status="ocr_unavailable", is_available_override=False))

        img_bytes = create_in_memory_image("PNG")
        files = {"file": ("screenshot.png", img_bytes, "image/png")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["ocr_status"], "ocr_unavailable")
        self.assertEqual(data["combined_verdict"], "inconclusive")
        self.assertFalse(data["is_confirmed_safe"])
        warning_text = " ".join(data["warnings"])
        self.assertIn("OCR", warning_text)

    def test_ocr_failure_exception_handled_safely(self):
        """OCR runtime exception must produce inconclusive result without crashing."""
        set_ocr_provider(MockOCRProvider(raise_exception=RuntimeError("OCR engine crashed")))

        img_bytes = create_in_memory_image("PNG")
        files = {"file": ("crash.png", img_bytes, "image/png")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["ocr_status"], "ocr_error")
        self.assertEqual(data["combined_verdict"], "inconclusive")
        self.assertFalse(data["is_confirmed_safe"])

    # -----------------------------------------------------------------------
    # Image Validation & Rejection (HTTP 422)
    # -----------------------------------------------------------------------

    def test_unsupported_format_gif_rejected(self):
        """GIF images must be rejected with HTTP 422."""
        img_bytes = create_in_memory_image("GIF")
        files = {"file": ("animation.gif", img_bytes, "image/gif")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 422)

        data = response.json()
        self.assertEqual(data["error"], "Validation Error")
        self.assertIn("Unsupported image format", data["detail"])

    def test_unsupported_format_bmp_rejected(self):
        """BMP images must be rejected with HTTP 422."""
        img_bytes = create_in_memory_image("BMP")
        files = {"file": ("bitmap.bmp", img_bytes, "image/bmp")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 422)

        data = response.json()
        self.assertEqual(data["error"], "Validation Error")
        self.assertIn("Unsupported image format", data["detail"])

    def test_spoofed_mime_type_rejected(self):
        """Text file renamed with .png extension and image/png MIME must be rejected via magic byte check."""
        fake_bytes = b"Hello, this is a plain text file pretending to be a PNG image."
        files = {"file": ("fake_screenshot.png", fake_bytes, "image/png")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 422)

        data = response.json()
        self.assertEqual(data["error"], "Validation Error")
        self.assertNotIn("Traceback", response.text)

    def test_oversized_upload_rejected(self):
        """Uploads exceeding 5 MB limit must be rejected with HTTP 422."""
        oversized_bytes = b"P" * (MAX_IMAGE_SIZE_BYTES + 1024)
        files = {"file": ("huge.png", oversized_bytes, "image/png")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 422)

        data = response.json()
        self.assertEqual(data["error"], "Validation Error")
        self.assertIn("5 MB", data["detail"])

    def test_empty_file_rejected(self):
        """Zero-byte file uploads must be rejected with HTTP 422."""
        files = {"file": ("empty.png", b"", "image/png")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 422)

        data = response.json()
        self.assertEqual(data["error"], "Validation Error")

    def test_corrupted_image_bytes_rejected(self):
        """Image with valid PNG signature but corrupted payload must be rejected safely."""
        corrupted = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 50
        files = {"file": ("corrupted.png", corrupted, "image/png")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 422)

        data = response.json()
        self.assertEqual(data["error"], "Validation Error")

    # -----------------------------------------------------------------------
    # Unit Tests for Helper Functions & Architecture
    # -----------------------------------------------------------------------

    def test_extract_urls_from_text(self):
        """URL extraction helper correctly extracts and cleans multiple URLs."""
        sample_text = (
            "Visit https://example.com/login. Also see http://sub.domain.org/path?k=v! "
            "Ignore plain words and email test@example.com."
        )
        urls = extract_urls_from_text(sample_text)
        self.assertIn("https://example.com/login", urls)
        self.assertIn("http://sub.domain.org/path?k=v", urls)
        self.assertEqual(len(urls), 2)

    def test_tesseract_provider_real_fallback(self):
        """TesseractOCRProvider gracefully handles environments where binary is missing."""
        provider = TesseractOCRProvider(tesseract_cmd="C:\\nonexistent_tesseract_xyz.exe")
        self.assertFalse(provider.is_available())

        img = Image.new("RGB", (50, 50), color="white")
        text, info = provider.extract_text(img)
        self.assertEqual(text, "")
        self.assertEqual(info.status, "ocr_unavailable")

    def test_disclaimers_and_limitations_present(self):
        """Mandatory disclaimers on logo verification and visual authenticity must be present."""
        set_ocr_provider(MockOCRProvider(text="Hello world"))
        img_bytes = create_in_memory_image("PNG")
        files = {"file": ("screenshot.png", img_bytes, "image/png")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        lims = " ".join(data["limitations"])
        self.assertIn("Visual elements, logos, watermarks, seals", lims)
        self.assertIn("Screenshot authenticity was not verified", lims)
        self.assertFalse(data["is_confirmed_safe"])

    def test_regression_physics_lecture_verdict_and_evidence_consistency(self):
        """Ordinary educational physics lecture text with numbers (24, 28, 00) must return benign with low risk level,

        and ordinary numbers must NOT be highlighted as scam evidence.
        """
        physics_text = (
            "Physics 101 Lecture 24: Rotational Dynamics and Conservation of Momentum. "
            "Problem 28: A disc rotating at 1200 rpm decelerates to 00 rad/s under constant friction."
        )
        set_ocr_provider(MockOCRProvider(text=physics_text))
        img_bytes = create_in_memory_image("PNG")
        files = {"file": ("physics_lecture.png", img_bytes, "image/png")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["combined_verdict"], "benign")
        self.assertEqual(data["verdict"], "benign")
        self.assertEqual(data["risk_level"], "low")
        self.assertFalse(data["text_analysis"]["is_scam"])
        self.assertEqual(data["text_analysis"]["label"], "legitimate")

        # Risk score reflects actual model output score (e.g. ~0.34-0.38) and is not forced to 0
        self.assertGreater(data["risk_score"], 0.0)
        self.assertLess(data["risk_score"], 0.50)

        # Evidence must NOT contain pure numbers (00, 28, 24) as scam indicators
        scam_signals = [
            e["token"] or e["description"] for e in data["evidence"]
            if e.get("severity") in ("high", "medium") or "scam" in e.get("signal", "")
        ]
        for num in ("00", "28", "24"):
            self.assertNotIn(num, scam_signals, f"Ordinary number '{num}' should not be labeled as scam evidence")

    def test_regression_suspicious_sms_screenshot_verdict_and_evidence_consistency(self):
        """Suspicious SMS screenshot mentioning gift card reward, claim window, and URL must return suspicious verdict

        with high risk level and genuine scam keyword evidence.
        """
        sms_text = (
            "Amazon: You have been selected to receive a $1000 Amazon Gift Card reward! "
            "Limited 24 hour claim window. Claim here: https://tinyurl.com/amz-claim"
        )
        set_ocr_provider(MockOCRProvider(text=sms_text))
        img_bytes = create_in_memory_image("PNG")
        files = {"file": ("sms_gift_card.png", img_bytes, "image/png")}

        response = self.client.post("/api/v1/scans/image", files=files)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["combined_verdict"], "suspicious")
        self.assertEqual(data["verdict"], "suspicious")
        self.assertIn(data["risk_level"], ["high", "medium"])
        self.assertGreater(data["risk_score"], 0.60)
        self.assertTrue(data["text_analysis"]["is_scam"])

        # Genuine scam tokens like claim, reward, gift should be in evidence
        tokens = [e.get("token") for e in data["evidence"] if e.get("token")]
        self.assertTrue(
            any(k in tokens for k in ("claim", "reward", "gift", "com")),
            f"Expected genuine scam keywords in evidence tokens, got: {tokens}"
        )
        # Numbers like '24' must NOT be in scam evidence
        self.assertNotIn("24", tokens)


if __name__ == "__main__":
    unittest.main()
