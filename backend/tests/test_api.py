"""Automated API integration tests for ScamShield-AI backend."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services import ModelUnavailableException


class TestBackendAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health_endpoint_model_loaded(self):
        """GET /health should report 'ok' and model_loaded: True."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertTrue(data["model_loaded"])
        self.assertEqual(data["model_version"], "v1.0.0-baseline-tfidf-lr")
        self.assertEqual(data["api_version"], "1.0.0")

    def test_scan_legitimate_message(self):
        """POST /api/v1/scans/text with normal text should return legitimate."""
        payload = {"text": "Hey Alex, are we still meeting in the computer lab at 3pm?"}
        response = self.client.post("/api/v1/scans/text", json=payload)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertFalse(data["is_scam"])
        self.assertEqual(data["label"], "legitimate")
        self.assertLess(data["scam_probability"], 0.50)
        self.assertGreater(data["probabilities"]["legitimate"], 0.50)
        self.assertEqual(data["model_version"], "v1.0.0-baseline-tfidf-lr")
        self.assertFalse(data["calibrated"])
        self.assertIn("evidence", data)
        self.assertIn("explanation", data)

    def test_scan_scam_message(self):
        """POST /api/v1/scans/text with phishing/scam text should return scam."""
        payload = {
            "text": "URGENT! You have won a 1000 cash prize! Call 09061743806 right now to claim before it expires."
        }
        response = self.client.post("/api/v1/scans/text", json=payload)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["is_scam"])
        self.assertEqual(data["label"], "scam")
        self.assertGreater(data["scam_probability"], 0.50)
        self.assertGreater(data["probabilities"]["scam"], 0.50)
        self.assertEqual(data["model_version"], "v1.0.0-baseline-tfidf-lr")
        self.assertFalse(data["calibrated"])
        self.assertIsInstance(data["evidence"], list)
        self.assertGreater(len(data["evidence"]), 0)

    def test_scan_empty_text_rejected(self):
        """POST /api/v1/scans/text with empty string should be rejected (422)."""
        payload = {"text": ""}
        response = self.client.post("/api/v1/scans/text", json=payload)
        self.assertEqual(response.status_code, 422)

        data = response.json()
        self.assertEqual(data["error"], "Validation Error")
        self.assertNotIn("Traceback", response.text)

    def test_scan_whitespace_text_rejected(self):
        """POST /api/v1/scans/text with only whitespace should be rejected (422)."""
        payload = {"text": "   \n\t   "}
        response = self.client.post("/api/v1/scans/text", json=payload)
        self.assertEqual(response.status_code, 422)

        data = response.json()
        self.assertEqual(data["error"], "Validation Error")
        self.assertNotIn("Traceback", response.text)

    def test_scan_missing_field_rejected(self):
        """POST /api/v1/scans/text without 'text' key should be rejected (422)."""
        payload = {}
        response = self.client.post("/api/v1/scans/text", json=payload)
        self.assertEqual(response.status_code, 422)

        data = response.json()
        self.assertEqual(data["error"], "Validation Error")

    def test_scan_exceeds_max_length_rejected(self):
        """POST /api/v1/scans/text exceeding 5000 characters should be rejected (422)."""
        payload = {"text": "A" * 5001}
        response = self.client.post("/api/v1/scans/text", json=payload)
        self.assertEqual(response.status_code, 422)

        data = response.json()
        self.assertEqual(data["error"], "Validation Error")

    def test_model_unavailable_safety(self):
        """If model cannot be loaded, API must return safe 503 without stack traces."""
        with patch(
            "backend.app.main.scan_text",
            side_effect=ModelUnavailableException("ML model artifact is not available on the server."),
        ):
            response = self.client.post(
                "/api/v1/scans/text",
                json={"text": "Test message while model down."},
            )
            self.assertEqual(response.status_code, 503)

            data = response.json()
            self.assertEqual(data["error"], "Service Unavailable")
            self.assertIn("ML model artifact is not available", data["detail"])
            # Ensure no python traceback is returned
            self.assertNotIn("Traceback", response.text)
            self.assertNotIn("File \"", response.text)

    # ==========================================
    # Milestone 2: URL Scanning Tests
    # ==========================================

    def test_scan_normal_https_url(self):
        """Normal legitimate HTTPS URL should return benign with low risk score."""
        payload = {"url": "https://example.com/about"}
        response = self.client.post("/api/v1/scans/url", json=payload)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["url"], "https://example.com/about")
        self.assertEqual(data["normalized_url"], "https://example.com/about")
        self.assertEqual(data["verdict"], "benign")
        self.assertEqual(data["label"], "benign")
        self.assertEqual(data["risk_level"], "low")
        self.assertLess(data["risk_score"], 0.30)
        self.assertEqual(data["evidence"], [])
        self.assertIn("analysis_method", data)
        self.assertIsInstance(data["limitations"], list)
        self.assertGreater(len(data["limitations"]), 0)
        self.assertTrue(data["reputation_check"]["feed_available"])
        self.assertFalse(data["reputation_check"]["matched"])
        self.assertFalse(data["reputation_check"]["is_confirmed_safe"])
        self.assertEqual(data["reputation_check"]["status"], "unknown")

    def test_scan_ip_hosted_url(self):
        """URL hosted on raw IP address should trigger ip_address_host signal and suspicious verdict."""
        payload = {"url": "http://192.168.1.100/admin/login"}
        response = self.client.post("/api/v1/scans/url", json=payload)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["verdict"], "suspicious")
        self.assertIn(data["risk_level"], ["medium", "high"])
        self.assertGreaterEqual(data["risk_score"], 0.45)

        # Check evidence contains ip_address_host
        signals = [item["signal"] for item in data["evidence"]]
        self.assertIn("ip_address_host", signals)
        self.assertIn("unencrypted_http", signals)

    def test_scan_https_example_com(self):
        """Root https://example.com should return benign with low risk."""
        payload = {"url": "https://example.com"}
        response = self.client.post("/api/v1/scans/url", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["verdict"], "benign")
        self.assertEqual(data["risk_level"], "low")

    def test_scan_http_ip_verify_account(self):
        """URL http://192.0.2.1/login/verify-account should be flagged suspicious with ip_address_host signal."""
        payload = {"url": "http://192.0.2.1/login/verify-account"}
        response = self.client.post("/api/v1/scans/url", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["verdict"], "suspicious")
        signals = [item["signal"] for item in data["evidence"]]
        self.assertIn("ip_address_host", signals)

    def test_scan_punycode_url(self):
        """URL with Punycode should flag homograph risk signal."""
        payload = {"url": "https://xn--pypal-4ve.com/signin"}
        response = self.client.post("/api/v1/scans/url", json=payload)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        signals = [item["signal"] for item in data["evidence"]]
        self.assertIn("punycode_hostname", signals)

    def test_scan_targeted_brand_spoofing_url(self):
        """URL with brand keyword in subdomain while registered on another domain should trigger brand spoofing."""
        payload = {"url": "https://paypal.com.account-update.xyz/login"}
        response = self.client.post("/api/v1/scans/url", json=payload)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["verdict"], "suspicious")
        signals = [item["signal"] for item in data["evidence"]]
        self.assertIn("targeted_brand_spoofing", signals)
        self.assertIn("high_abuse_tld", signals)

    def test_scan_malformed_url_rejected(self):
        """Malformed URLs must be rejected with 422."""
        invalid_urls = [
            "not_a_url",
            "htp:/bad",
            "https://",
            "http://.com",
            "",
            "   ",
        ]
        for bad_url in invalid_urls:
            response = self.client.post("/api/v1/scans/url", json={"url": bad_url})
            self.assertEqual(
                response.status_code,
                422,
                f"Expected 422 for malformed URL '{bad_url}', got {response.status_code}",
            )
            data = response.json()
            self.assertEqual(data["error"], "Validation Error")

    def test_scan_unsupported_schemes_rejected(self):
        """Schemes other than http/https must be rejected with 422."""
        unsupported = [
            "javascript:alert(1)",
            "ftp://files.example.com/data.zip",
            "file:///etc/passwd",
            "data:text/html,<h1>Phishing</h1>",
            "ws://socket.example.com",
        ]
        for bad_scheme_url in unsupported:
            response = self.client.post("/api/v1/scans/url", json={"url": bad_scheme_url})
            self.assertEqual(
                response.status_code,
                422,
                f"Expected 422 for scheme '{bad_scheme_url}', got {response.status_code}",
            )
            data = response.json()
            self.assertEqual(data["error"], "Validation Error")

    def test_scan_embedded_credentials_rejected(self):
        """URLs containing credentials (user:pass@host) must be rejected with 422."""
        credential_urls = [
            "https://user:password@example.com",
            "http://admin@192.168.1.1/dashboard",
            "https://victim:secret123@phishing-target.com/page",
        ]
        for cred_url in credential_urls:
            response = self.client.post("/api/v1/scans/url", json={"url": cred_url})
            self.assertEqual(
                response.status_code,
                422,
                f"Expected 422 for credential URL '{cred_url}', got {response.status_code}",
            )
            data = response.json()
            self.assertEqual(data["error"], "Validation Error")

    def test_scan_excessively_long_url_rejected(self):
        """URLs exceeding 2048 characters must be rejected with 422."""
        long_url = "https://example.com/" + ("a" * 2050)
        response = self.client.post("/api/v1/scans/url", json={"url": long_url})
        self.assertEqual(response.status_code, 422)
        data = response.json()
        self.assertEqual(data["error"], "Validation Error")

    def test_url_evidence_structure(self):
        """Verify evidence items contain required fields: signal, description, severity, weight."""
        payload = {"url": "http://10.0.0.1/verify/account.exe"}
        response = self.client.post("/api/v1/scans/url", json=payload)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertGreater(len(data["evidence"]), 0)
        for item in data["evidence"]:
            self.assertIn("signal", item)
            self.assertIn("description", item)
            self.assertIn("severity", item)
            self.assertIn("weight", item)
            self.assertIn(item["severity"], ["low", "medium", "high"])
            self.assertIsInstance(item["weight"], float)


    def test_cors_headers_allowed_origin(self):
        """Preflight OPTIONS request from allowed frontend origin should receive CORS headers."""
        headers = {
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        }
        response = self.client.options("/api/v1/scans/text", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("access-control-allow-origin"), "http://localhost:5173")
        self.assertEqual(response.headers.get("access-control-allow-credentials"), "true")

    def test_cors_headers_disallowed_origin(self):
        """Preflight OPTIONS request from unapproved origin should not receive allow-origin."""
        headers = {
            "Origin": "http://malicious-external-site.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        }
        response = self.client.options("/api/v1/scans/text", headers=headers)
        self.assertNotEqual(
            response.headers.get("access-control-allow-origin"),
            "http://malicious-external-site.com",
        )


if __name__ == "__main__":
    unittest.main()

