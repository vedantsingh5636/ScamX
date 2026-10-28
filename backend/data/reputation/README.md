# Threat Intelligence & Reputation Feed Documentation

## 1. Overview & Provenance
This directory contains offline threat-intelligence feed snapshots and fixtures used by ScamShield-AI's reputation checking layer.

- **Current Snapshot (`threat_feed.json`):**
  - **Type:** Curated test fixture snapshot (`is_production_feed: false`).
  - **Identifiers:** Exclusively uses [RFC 2606](https://tools.ietf.org/html/rfc2606) reserved example domains (`.example.com`, `.example.org`) and [RFC 5737](https://tools.ietf.org/html/rfc5737) TEST-NET-2 documentation IP blocks (`198.51.100.0/24`).
  - **Purpose:** Enables offline testing and pipeline verification without exposing live attacker C2s, targeting real domains, or producing unintended network traffic.
- **Production Reference Schemas:**
  - [URLhaus by abuse.ch](https://urlhaus.abuse.ch/api/) — Verified malicious URLs distributing malware.
  - [OpenPhish Community Feed](https://openphish.com/) — Verified active phishing sites.
- **Initial Retrieval/Creation Date:** 2026-10-26T10:00:00Z
- **License / Terms of Use:**
  - CC0 1.0 Universal (Public Domain Dedication) for test fixtures.
  - Upstream abuse.ch datasets are provided under CC0.
  - Upstream OpenPhish community data is accessible for non-commercial research with attribution.
  - Commercial redistribution of raw upstream feeds is restricted; production deployments must ingest directly from provider APIs.

## 2. File Schema & Entry Validation

The feed file must conform to the following JSON structure:

```json
{
  "metadata": {
    "feed_name": "ScamShield Threat Intelligence Snapshot",
    "source": "abuse.ch URLhaus & OpenPhish Community Feed",
    "retrieved_at": "2026-10-25T12:00:00Z",
    "version": "1.0.0",
    "license": "CC0 1.0 Universal / Open Threat Intelligence",
    "description": "Verified offline threat intelligence feed snapshot."
  },
  "entries": [
    {
      "pattern": "http://malware-drop.example.com/payload.exe",
      "pattern_type": "exact_url",
      "threat_type": "malware_distribution",
      "confidence": 1.0,
      "source": "URLhaus",
      "reference_id": "UH-SAMPLE-001"
    },
    {
      "pattern": "phishing-bank-portal.example.com",
      "pattern_type": "host",
      "threat_type": "phishing",
      "confidence": 1.0,
      "source": "OpenPhish",
      "reference_id": "OP-SAMPLE-002"
    },
    {
      "pattern": "credential-stealer.example.org",
      "pattern_type": "apex_domain",
      "threat_type": "credential_theft",
      "confidence": 0.95,
      "source": "URLhaus",
      "reference_id": "UH-SAMPLE-003"
    }
  ]
}
```

### Validation Rules:
1. `metadata` must contain valid ISO 8601 `retrieved_at` timestamp.
2. `pattern_type` must be one of: `exact_url`, `host`, or `apex_domain`.
3. `pattern` cannot be empty and is normalized during ingestion (lowercase, port-stripped).
4. Malformed entries (missing required fields, invalid pattern types) are rejected with warnings logged during parsing.

## 3. Freshness & Staleness Policy
- The feed is considered **fresh** if `retrieved_at` is within **7 days** of the current system time.
- If older than 7 days, the provider marks `is_stale: true` and logs an alert.
- A stale feed is still queried for known persistent threats, but its stale state is explicitly noted in the API response.

## 4. Threat Status Semantics
- **Confirmed Match (`matched: true`):** The URL or domain appears in the verified threat intelligence feed. Verdict is `malicious`.
- **Unknown Status (`matched: false`):** The URL was NOT found in the feed.
  - **CRITICAL:** A non-matching result is **UNKNOWN**, NEVER "confirmed safe".
  - The API response explicitly sets `is_confirmed_safe: false`.
  - Millions of benign and brand-new malicious domains are not yet indexed in any local feed snapshot.

## 5. Update Procedure
To update the local offline snapshot:
1. Retrieve latest verified entries from upstream API/feed.
2. Filter for verified active indicators.
3. Validate format against the JSON schema.
4. Update `retrieved_at` timestamp in `metadata`.
5. Run `backend/tests/test_reputation.py` to ensure zero regressions.
