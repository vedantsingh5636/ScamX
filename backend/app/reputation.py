"""Threat intelligence and reputation provider for ScamShield-AI.
Supports local verified feed snapshots (e.g. URLhaus, OpenPhish) with format validation,
staleness detection, and normalized matching without contacting external networks.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from backend.app.config import REPUTATION_FEED_MAX_AGE_DAYS, REPUTATION_FEED_PATH

logger = logging.getLogger("scamshield.reputation")


@dataclass
class ReputationResult:
    """Structured result of reputation lookup."""
    feed_available: bool = False
    matched: bool = False
    match_type: Optional[str] = None  # 'exact_url', 'host', 'apex_domain'
    threat_type: Optional[str] = None  # 'malware_distribution', 'phishing', 'credential_theft'
    feed_source: Optional[str] = None
    reference_id: Optional[str] = None
    confidence: float = 0.0
    feed_retrieved_at: Optional[str] = None
    feed_age_days: Optional[float] = None
    is_stale: bool = False
    status: str = "unavailable"  # 'matched', 'unknown', 'unavailable', 'stale_match', 'stale_unknown'
    notes: str = ""
    is_confirmed_safe: bool = False  # Explicitly False: missing match is NEVER confirmed safe
    reputation_evidence: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary suitable for JSON responses."""
        return {
            "feed_available": self.feed_available,
            "matched": self.matched,
            "match_type": self.match_type,
            "threat_type": self.threat_type,
            "feed_source": self.feed_source,
            "reference_id": self.reference_id,
            "confidence": self.confidence,
            "feed_retrieved_at": self.feed_retrieved_at,
            "feed_age_days": self.feed_age_days,
            "is_stale": self.is_stale,
            "status": self.status,
            "notes": self.notes,
            "is_confirmed_safe": self.is_confirmed_safe,
            "reputation_evidence": self.reputation_evidence,
        }


class BaseReputationProvider(ABC):
    """Abstract interface for threat intelligence reputation providers."""

    @abstractmethod
    def check_url(self, normalized_url: str, hostname: str, apex_domain: str) -> ReputationResult:
        """Check whether a URL, host, or apex domain matches known threat intelligence."""
        raise NotImplementedError

    @abstractmethod
    def is_available(self) -> bool:
        """Whether the provider feed is currently loaded and available."""
        raise NotImplementedError

    @abstractmethod
    def get_feed_info(self) -> Dict[str, Any]:
        """Metadata about the feed provider."""
        raise NotImplementedError


class LocalFileReputationProvider(BaseReputationProvider):
    """Local offline reputation provider backed by verified JSON snapshot feeds."""

    def __init__(
        self,
        feed_path: Optional[Path | str] = None,
        max_age_days: int = REPUTATION_FEED_MAX_AGE_DAYS,
    ):
        self.feed_path = Path(feed_path) if feed_path else REPUTATION_FEED_PATH
        self.max_age_days = max_age_days

        self.available: bool = False
        self.is_stale: bool = False
        self.feed_retrieved_at: Optional[str] = None
        self.feed_age_days: Optional[float] = None
        self.metadata: Dict[str, Any] = {}

        # In-memory lookup tables
        self.exact_urls: Dict[str, Dict[str, Any]] = {}
        self.hosts: Dict[str, Dict[str, Any]] = {}
        self.apex_domains: Dict[str, Dict[str, Any]] = {}

        self._load_feed()

    def _normalize_pattern(self, pattern: str, pattern_type: str) -> str:
        """Normalize feed pattern for consistent matching."""
        p = pattern.strip().lower()
        if pattern_type == "exact_url":
            # Strip trailing slash for consistency
            return p.rstrip("/")
        # For host and apex domain, strip any trailing dot or port
        if ":" in p and not p.startswith("http"):
            p = p.split(":")[0]
        return p.rstrip(".")

    def _load_feed(self) -> None:
        """Load and validate local threat intelligence JSON feed."""
        if not self.feed_path.exists():
            logger.info(f"Reputation feed file not found at {self.feed_path}. Operating in degraded mode.")
            self.available = False
            return

        try:
            with open(self.feed_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            logger.error(f"Failed to read reputation feed at {self.feed_path}: {exc}")
            self.available = False
            return

        if not isinstance(data, dict) or "entries" not in data:
            logger.warning(f"Malformed reputation feed at {self.feed_path}: Missing 'entries' key.")
            self.available = False
            return

        self.metadata = data.get("metadata", {})
        self.feed_retrieved_at = self.metadata.get("retrieved_at")

        # Evaluate feed freshness
        if self.feed_retrieved_at:
            try:
                # Handle ISO 8601 timestamps
                clean_ts = self.feed_retrieved_at.replace("Z", "+00:00")
                retrieved_dt = datetime.fromisoformat(clean_ts)
                now_dt = datetime.now(timezone.utc)
                age_seconds = (now_dt - retrieved_dt).total_seconds()
                self.feed_age_days = round(max(0.0, age_seconds / 86400.0), 2)
                if self.feed_age_days > self.max_age_days:
                    self.is_stale = True
                    logger.warning(
                        f"Reputation feed is STALE ({self.feed_age_days} days old, max is {self.max_age_days})."
                    )
            except Exception as exc:
                logger.warning(f"Could not parse feed 'retrieved_at' timestamp ({self.feed_retrieved_at}): {exc}")

        # Ingest entries
        valid_entries = 0
        for entry in data.get("entries", []):
            if not isinstance(entry, dict):
                continue
            pattern = entry.get("pattern")
            pattern_type = entry.get("pattern_type")
            if not pattern or not pattern_type or pattern_type not in {"exact_url", "host", "apex_domain"}:
                logger.debug(f"Skipping malformed feed entry: {entry}")
                continue

            norm_pat = self._normalize_pattern(pattern, pattern_type)
            if pattern_type == "exact_url":
                self.exact_urls[norm_pat] = entry
            elif pattern_type == "host":
                self.hosts[norm_pat] = entry
            elif pattern_type == "apex_domain":
                self.apex_domains[norm_pat] = entry
            valid_entries += 1

        self.available = True
        logger.info(
            f"Reputation feed loaded: {valid_entries} verified entries "
            f"({len(self.exact_urls)} URLs, {len(self.hosts)} hosts, {len(self.apex_domains)} apex domains)."
        )

    def is_available(self) -> bool:
        return self.available

    def get_feed_info(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "feed_source": self.metadata.get("source", "Unknown"),
            "feed_retrieved_at": self.feed_retrieved_at,
            "feed_age_days": self.feed_age_days,
            "is_stale": self.is_stale,
            "entries_count": len(self.exact_urls) + len(self.hosts) + len(self.apex_domains),
        }

    def check_url(self, normalized_url: str, hostname: str, apex_domain: str) -> ReputationResult:
        """Check normalized URL, hostname, and apex domain against loaded indices."""
        if not self.available:
            return ReputationResult(
                feed_available=False,
                matched=False,
                status="unavailable",
                notes="No local threat intelligence feed snapshot loaded. Threat reputation is unverified.",
                is_confirmed_safe=False,
            )

        # 1. Exact URL match (strip trailing slash for comparison)
        clean_url = normalized_url.lower().rstrip("/")
        if clean_url in self.exact_urls:
            entry = self.exact_urls[clean_url]
            return self._build_match_result(entry, "exact_url", clean_url)

        # 2. Hostname match
        clean_host = hostname.lower().rstrip(".")
        if clean_host in self.hosts:
            entry = self.hosts[clean_host]
            return self._build_match_result(entry, "host", clean_host)

        # 3. Apex Domain match
        clean_apex = apex_domain.lower().rstrip(".")
        if clean_apex in self.apex_domains:
            entry = self.apex_domains[clean_apex]
            return self._build_match_result(entry, "apex_domain", clean_apex)

        # 4. No match found
        status_str = "stale_unknown" if self.is_stale else "unknown"
        notes_str = (
            "URL not listed in local verified threat intelligence snapshot. "
            "IMPORTANT: Absence of a threat match represents UNKNOWN status and does NOT prove the URL is safe."
        )
        if self.is_stale:
            notes_str += f" (Warning: Threat feed is {self.feed_age_days} days old and may lack recent indicators)."

        return ReputationResult(
            feed_available=True,
            matched=False,
            match_type=None,
            threat_type=None,
            feed_source=self.metadata.get("source"),
            feed_retrieved_at=self.feed_retrieved_at,
            feed_age_days=self.feed_age_days,
            is_stale=self.is_stale,
            status=status_str,
            notes=notes_str,
            is_confirmed_safe=False,  # Crucial: Unlisted != safe
            reputation_evidence=[],
        )

    def _build_match_result(self, entry: Dict[str, Any], match_type: str, matched_pattern: str) -> ReputationResult:
        threat_type = entry.get("threat_type", "unspecified_malicious")
        source = entry.get("source") or self.metadata.get("source", "Verified Feed")
        ref_id = entry.get("reference_id")
        confidence = float(entry.get("confidence", 1.0))

        status_str = "stale_match" if self.is_stale else "matched"
        notes_str = (
            f"CONFIRMED THREAT MATCH: Found in threat intelligence feed ({source}) as {threat_type} "
            f"via {match_type} match on '{matched_pattern}'."
        )
        if self.is_stale:
            notes_str += f" (Note: Feed snapshot is {self.feed_age_days} days old)."

        evidence_item = {
            "signal": "reputation_threat_match",
            "source": source,
            "match_type": match_type,
            "threat_type": threat_type,
            "reference_id": ref_id,
            "matched_pattern": matched_pattern,
            "description": f"Verified match in threat intelligence feed from {source}.",
            "severity": "critical",
            "weight": 1.0,
        }

        return ReputationResult(
            feed_available=True,
            matched=True,
            match_type=match_type,
            threat_type=threat_type,
            feed_source=source,
            reference_id=ref_id,
            confidence=confidence,
            feed_retrieved_at=self.feed_retrieved_at,
            feed_age_days=self.feed_age_days,
            is_stale=self.is_stale,
            status=status_str,
            notes=notes_str,
            is_confirmed_safe=False,
            reputation_evidence=[evidence_item],
        )


# Singleton Cache
_PROVIDER: Optional[BaseReputationProvider] = None
_LOADED_FEED_PATH: Optional[str] = None


def get_reputation_provider(feed_path: Optional[Path | str] = None, force_reload: bool = False) -> BaseReputationProvider:
    """Retrieve or initialize the active threat intelligence reputation provider."""
    global _PROVIDER, _LOADED_FEED_PATH

    path_str = str(feed_path) if feed_path else str(REPUTATION_FEED_PATH)

    if _PROVIDER is None or force_reload or _LOADED_FEED_PATH != path_str:
        _PROVIDER = LocalFileReputationProvider(feed_path=path_str)
        _LOADED_FEED_PATH = path_str

    return _PROVIDER
