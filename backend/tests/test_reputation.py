"""Automated test suite for Milestone 3A: Threat Intelligence and Reputation Checking."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.reputation import (
    BaseReputationProvider,
    LocalFileReputationProvider,
    ReputationResult,
    get_reputation_provider,
)
from backend.app.url_analyzer import scan_url


class TestReputationLayer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_verified_fixture_exact_url_match(self):
        """A URL matching an exact_url feed entry must return malicious verdict and match details."""
        url = "http://malware-drop.example.com/payload.exe"
        response = self.client.post("/api/v1/scans/url", json={"url": url})
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["verdict"], "malicious")
        self.assertEqual(data["label"], "malicious")
        self.assertEqual(data["risk_level"], "critical")
        self.assertEqual(data["risk_score"], 1.0)

        rep = data["reputation_check"]
        self.assertTrue(rep["feed_available"])
        self.assertTrue(rep["matched"])
        self.assertEqual(rep["match_type"], "exact_url")
        self.assertEqual(rep["threat_type"], "malware_distribution")
        self.assertEqual(rep["feed_source"], "URLhaus")
        self.assertFalse(rep["is_confirmed_safe"])

        # Reputation evidence should be present and distinct
        self.assertGreater(len(data["reputation_evidence"]), 0)
        rep_ev = data["reputation_evidence"][0]
        self.assertEqual(rep_ev["signal"], "reputation_threat_match")
        self.assertEqual(rep_ev["threat_type"], "malware_distribution")

    def test_verified_fixture_host_match(self):
        """A URL whose host matches a feed entry must return malicious verdict."""
        url = "http://phishing-bank-portal.example.com/login"
        response = self.client.post("/api/v1/scans/url", json={"url": url})
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["verdict"], "malicious")
        rep = data["reputation_check"]
        self.assertTrue(rep["matched"])
        self.assertEqual(rep["match_type"], "host")
        self.assertEqual(rep["threat_type"], "phishing")

    def test_verified_fixture_apex_domain_match(self):
        """A URL whose apex domain matches must return malicious verdict."""
        url = "https://subdomain.verified-bad-site.com/session/update"
        response = self.client.post("/api/v1/scans/url", json={"url": url})
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["verdict"], "malicious")
        rep = data["reputation_check"]
        self.assertTrue(rep["matched"])
        self.assertEqual(rep["match_type"], "apex_domain")

    def test_non_matching_url_returns_unknown_status(self):
        """A non-matching URL must return matched: False and status: 'unknown'."""
        url = "https://unlisted-news-blog.example.com/tech-news"
        response = self.client.post("/api/v1/scans/url", json={"url": url})
        self.assertEqual(response.status_code, 200)

        data = response.json()
        rep = data["reputation_check"]
        self.assertTrue(rep["feed_available"])
        self.assertFalse(rep["matched"])
        self.assertEqual(rep["status"], "unknown")
        self.assertIn("UNKNOWN", rep["notes"])

    def test_missing_match_never_claims_confirmed_safe(self):
        """A non-matching URL with zero heuristic risk must NEVER be marked confirmed safe."""
        url = "https://clean-example-site.org/index.html"
        result = scan_url(url)

        rep = result["reputation_check"]
        self.assertFalse(
            rep["is_confirmed_safe"],
            "Non-matching URL must explicitly report is_confirmed_safe=False",
        )
        self.assertNotEqual(
            result["verdict"],
            "safe",
            "Verdict must not claim a URL is 'safe'; absence of proof is not proof of safety.",
        )
        self.assertNotEqual(
            result["verdict"],
            "confirmed_safe",
            "Verdict must never be 'confirmed_safe'.",
        )

    def test_unavailable_feed_handling(self):
        """When feed file is absent, provider reports unavailable and system operates normally."""
        non_existent_path = Path("backend/data/reputation/does_not_exist_xyz.json")
        provider = LocalFileReputationProvider(feed_path=non_existent_path)

        self.assertFalse(provider.is_available())
        result = provider.check_url(
            normalized_url="https://example.com/",
            hostname="example.com",
            apex_domain="example.com",
        )
        self.assertFalse(result.feed_available)
        self.assertFalse(result.matched)
        self.assertEqual(result.status, "unavailable")
        self.assertFalse(result.is_confirmed_safe)

        # Scanning through scan_url with unavailable provider must succeed without crashing
        scan_res = scan_url("https://example.com/", reputation_provider=provider)
        self.assertEqual(scan_res["reputation_check"]["status"], "unavailable")
        self.assertEqual(scan_res["verdict"], "benign")

    def test_malformed_feed_data_handling(self):
        """Malformed JSON or corrupted entries must be rejected gracefully without crashing."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
            tmp.write("{ invalid json content }")
            tmp_path = Path(tmp.name)

        try:
            provider = LocalFileReputationProvider(feed_path=tmp_path)
            self.assertFalse(provider.is_available())
            res = provider.check_url("https://example.com/", "example.com", "example.com")
            self.assertEqual(res.status, "unavailable")
        finally:
            tmp_path.unlink(missing_ok=True)

        # Feed with some valid and some malformed entries
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
            feed_data = {
                "metadata": {"source": "Test Feed"},
                "entries": [
                    "invalid non-dict entry",
                    {"pattern": "missing_pattern_type"},
                    {"pattern": "http://valid.test/bad", "pattern_type": "exact_url", "threat_type": "malware"},
                ],
            }
            json.dump(feed_data, tmp)
            tmp_path = Path(tmp.name)

        try:
            provider = LocalFileReputationProvider(feed_path=tmp_path)
            self.assertTrue(provider.is_available())
            # Should have ingested only the 1 valid entry
            match = provider.check_url("http://valid.test/bad", "valid.test", "valid.test")
            self.assertTrue(match.matched)
            self.assertEqual(match.threat_type, "malware")
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_stale_feed_detection(self):
        """Feed with timestamp older than threshold must be flagged as stale."""
        # Create a feed dated 30 days ago
        old_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
            feed_data = {
                "metadata": {
                    "source": "Stale Feed Source",
                    "retrieved_at": old_time,
                },
                "entries": [
                    {
                        "pattern": "stale-threat.test",
                        "pattern_type": "host",
                        "threat_type": "phishing",
                    }
                ],
            }
            json.dump(feed_data, tmp)
            tmp_path = Path(tmp.name)

        try:
            provider = LocalFileReputationProvider(feed_path=tmp_path, max_age_days=7)
            self.assertTrue(provider.is_available())
            self.assertTrue(provider.is_stale)
            self.assertGreater(provider.feed_age_days, 25.0)

            # Match on stale feed
            res = provider.check_url("https://stale-threat.test/login", "stale-threat.test", "stale-threat.test")
            self.assertTrue(res.matched)
            self.assertEqual(res.status, "stale_match")
            self.assertTrue(res.is_stale)

            # Non-match on stale feed
            unlisted = provider.check_url("https://unlisted.test/", "unlisted.test", "unlisted.test")
            self.assertFalse(unlisted.matched)
            self.assertEqual(unlisted.status, "stale_unknown")
            self.assertTrue(unlisted.is_stale)
            self.assertFalse(unlisted.is_confirmed_safe)
            self.assertIn("UNKNOWN", unlisted.notes)

            # Scanner integration with stale feed must never return safe or confirmed_safe
            scan_res = scan_url("https://unlisted.test/", reputation_provider=provider)
            self.assertNotEqual(scan_res["verdict"], "safe")
            self.assertNotEqual(scan_res["verdict"], "confirmed_safe")
            self.assertFalse(scan_res["reputation_check"]["is_confirmed_safe"])
        finally:
            tmp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
