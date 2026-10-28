"""Offline, static heuristic URL analyzer for ScamShield-AI.
Evaluates structural signals (IP host, excessive subdomains, punycode, brand spoofing, etc.)
strictly without opening, fetching, or resolving the URL over the network.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

# Maximum permitted URL length
MAX_URL_LENGTH = 2048

# Allowed web schemes
ALLOWED_SCHEMES = {"http", "https"}

# High-risk / frequently abused Top-Level Domains (TLDs)
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "buzz", "fit", "surf", "cn", "click"
}

# Recognized high-target brands for spoofing detection
TARGETED_BRANDS = {
    "paypal", "apple", "google", "microsoft", "netflix", "amazon",
    "chase", "bankofamerica", "wellsfargo", "citibank", "facebook",
    "instagram", "whatsapp", "telegram", "binance", "coinbase"
}

# Sensitive credential/security action keywords
SENSITIVE_KEYWORDS = {
    "login", "signin", "verify", "verification", "account", "update",
    "banking", "secure", "security", "wallet", "recover", "password", "otp"
}

# Common multi-part public suffixes
TWO_PART_TLDS = {
    "co.uk", "gov.uk", "ac.uk", "org.uk", "com.au", "net.au", "org.au",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "co.jp", "ne.jp"
}


def normalize_and_validate_url(raw_url: str) -> str:
    """Validate URL syntax, reject dangerous/unsupported inputs, and return canonical form.

    Raises:
        ValueError: If URL is malformed, unsupported, contains credentials, or is too long.
    """
    if not isinstance(raw_url, str):
        raise ValueError("URL must be a string.")

    cleaned = raw_url.strip()

    if not cleaned:
        raise ValueError("URL cannot be empty or contain only whitespace.")

    if len(cleaned) > MAX_URL_LENGTH:
        raise ValueError(f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters.")

    # Reject leading/trailing control characters or whitespace in parsed input
    try:
        parsed = urlsplit(cleaned)
    except Exception as exc:
        raise ValueError(f"Malformed URL: Unable to parse URL structure ({exc}).")

    # 1. Validate Scheme
    scheme = parsed.scheme.lower() if parsed.scheme else ""
    if not scheme:
        raise ValueError("Malformed URL: Missing scheme (e.g. 'https://').")

    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(
            f"Unsupported scheme '{scheme}'. Only standard web schemes ('http', 'https') are permitted."
        )

    # 2. Reject Embedded Credentials (RFC 3986 security risk)
    if parsed.username or parsed.password or ("@" in (parsed.netloc or "")):
        raise ValueError("URLs containing embedded user credentials (user:pass@host) are rejected.")

    # 3. Validate Hostname
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Malformed URL: Missing or invalid hostname.")

    hostname = hostname.lower().rstrip(".")

    # Reject hosts with illegal characters (spaces, control chars)
    if any(char in hostname for char in " \t\r\n/\\"):
        raise ValueError("Malformed URL: Hostname contains invalid whitespace or slashes.")

    # Basic hostname syntax check (RFC 1123 / IP address)
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        pass

    if not is_ip:
        # Check domain label validity
        labels = hostname.split(".")
        if len(labels) < 2 and hostname != "localhost":
            raise ValueError(f"Malformed URL: Hostname '{hostname}' is not a valid fully qualified domain.")
        for label in labels:
            if not label or len(label) > 63:
                raise ValueError("Malformed URL: Domain label empty or exceeds 63 characters.")
            if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", label):
                raise ValueError(f"Malformed URL: Domain label '{label}' contains invalid characters.")

    # 4. Canonicalize Port & Netloc
    port = parsed.port
    if port is not None:
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            netloc = hostname
        else:
            netloc = f"{hostname}:{port}"
    else:
        netloc = hostname

    # 5. Canonicalize Path
    path = parsed.path
    if not path:
        path = "/"
    else:
        # Normalize redundant duplicate slashes in path
        path = re.sub(r"/{2,}", "/", path)

    normalized = urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))
    return normalized


def extract_apex_and_subdomains(hostname: str) -> Tuple[str, List[str], str]:
    """Extract apex domain (e.g. 'example.com'), subdomain labels, and TLD."""
    labels = hostname.lower().split(".")

    # Check for known 2-part TLD (e.g., 'co.uk', 'co.in')
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_PART_TLDS:
        tld = ".".join(labels[-2:])
        apex = ".".join(labels[-3:])
        subdomains = labels[:-3]
    elif len(labels) >= 2:
        tld = labels[-1]
        apex = ".".join(labels[-2:])
        subdomains = labels[:-2]
    else:
        tld = ""
        apex = hostname
        subdomains = []

    # Strip 'www' from subdomains
    subdomains = [s for s in subdomains if s != "www"]
    return apex, subdomains, tld


def analyze_url_heuristics(normalized_url: str, reputation_provider: Optional[Any] = None) -> Dict[str, Any]:
    """Perform static, offline heuristic risk analysis on a validated normalized URL."""
    parsed = urlsplit(normalized_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    query = (parsed.query or "").lower()
    full_url = normalized_url.lower()

    evidence: List[Dict[str, Any]] = []
    total_risk_score: float = 0.0

    # 1. IP Address Host Signal
    is_ip_host = False
    try:
        ipaddress.ip_address(hostname)
        is_ip_host = True
    except ValueError:
        pass

    if is_ip_host:
        weight = 0.45
        total_risk_score += weight
        evidence.append({
            "signal": "ip_address_host",
            "description": f"Host '{hostname}' is a raw IP address instead of a domain name.",
            "severity": "high",
            "weight": weight,
        })

    # 2. Punycode (IDN Homograph) Signal
    if hostname.startswith("xn--") or ".xn--" in hostname:
        weight = 0.35
        total_risk_score += weight
        evidence.append({
            "signal": "punycode_hostname",
            "description": f"Hostname '{hostname}' uses Punycode encoding, frequently used in homograph spoofing.",
            "severity": "high",
            "weight": weight,
        })

    # 3. Subdomains and Apex Analysis (for domains, not raw IPs)
    if not is_ip_host:
        apex, subdomains, tld = extract_apex_and_subdomains(hostname)

        # Excessive subdomains
        if len(subdomains) >= 3:
            weight = 0.25
            total_risk_score += weight
            evidence.append({
                "signal": "excessive_subdomains",
                "description": f"Hostname has excessive subdomain depth ({len(subdomains)} subdomains: {'.'.join(subdomains)}).",
                "severity": "medium",
                "weight": weight,
            })

        # Suspicious / Free TLD
        if tld in SUSPICIOUS_TLDS:
            weight = 0.25
            total_risk_score += weight
            evidence.append({
                "signal": "high_abuse_tld",
                "description": f"Top-level domain '.{tld}' is statistically associated with high abuse and phishing campaigns.",
                "severity": "medium",
                "weight": weight,
            })

        # Targeted Brand Spoofing in Subdomains
        # (e.g. paypal.com.evil.com or secure-paypal-login.evil.com)
        subdomain_str = ".".join(subdomains)
        for brand in TARGETED_BRANDS:
            if brand in subdomain_str and brand not in apex:
                weight = 0.40
                total_risk_score += weight
                evidence.append({
                    "signal": "targeted_brand_spoofing",
                    "description": f"Targeted brand keyword '{brand}' found in subdomain while registered domain is '{apex}'.",
                    "severity": "high",
                    "weight": weight,
                })
                break

        # Excessive hyphens in domain name
        hyphen_count = hostname.count("-")
        if hyphen_count >= 3:
            weight = 0.20
            total_risk_score += weight
            evidence.append({
                "signal": "excessive_domain_hyphens",
                "description": f"Hostname contains {hyphen_count} hyphens, often used to mimic legitimate services.",
                "severity": "medium",
                "weight": weight,
            })

    # 4. URL Length Signal
    url_len = len(normalized_url)
    if url_len > 120:
        weight = 0.20
        total_risk_score += weight
        evidence.append({
            "signal": "suspicious_url_length",
            "description": f"URL length ({url_len} characters) is unusually long.",
            "severity": "medium",
            "weight": weight,
        })
    elif url_len > 80:
        weight = 0.10
        total_risk_score += weight
        evidence.append({
            "signal": "elevated_url_length",
            "description": f"URL length ({url_len} characters) is moderately long.",
            "severity": "low",
            "weight": weight,
        })

    # 5. Sensitive Keywords in Path/Query
    found_keywords = [kw for kw in SENSITIVE_KEYWORDS if kw in path or kw in query]
    if found_keywords and (is_ip_host or total_risk_score > 0.20):
        weight = 0.15
        total_risk_score += weight
        evidence.append({
            "signal": "sensitive_action_keywords",
            "description": f"Path/query contains sensitive authentication keywords: {', '.join(found_keywords[:3])}.",
            "severity": "medium",
            "weight": weight,
        })

    # 6. Unencrypted HTTP Scheme
    if parsed.scheme.lower() == "http":
        weight = 0.10
        total_risk_score += weight
        evidence.append({
            "signal": "unencrypted_http",
            "description": "URL uses unencrypted HTTP protocol rather than HTTPS.",
            "severity": "low",
            "weight": weight,
        })

    # 7. Suspicious Executable or Double File Extensions in Path
    if re.search(r"\.(exe|scr|bat|cmd|vbs|msi|ps1|apk|jar)(\?|$)", path):
        weight = 0.45
        total_risk_score += weight
        evidence.append({
            "signal": "executable_download_path",
            "description": "URL path targets a direct executable file download.",
            "severity": "high",
            "weight": weight,
        })
    elif re.search(r"\.[a-z0-9]+\.(exe|scr|zip|tar|gz)(\?|$)", path):
        weight = 0.45
        total_risk_score += weight
        evidence.append({
            "signal": "double_extension_path",
            "description": "URL path contains suspicious double file extension.",
            "severity": "high",
            "weight": weight,
        })

    # Clamp heuristic risk score to [0.0, 1.0]
    heuristic_score = round(min(1.0, max(0.0, total_risk_score)), 4)

    # Determine heuristic-only verdict
    if heuristic_score >= 0.60:
        heuristic_level = "high"
        heuristic_verdict = "suspicious"
    elif heuristic_score >= 0.30:
        heuristic_level = "medium"
        heuristic_verdict = "suspicious"
    else:
        heuristic_level = "low"
        heuristic_verdict = "benign"

    # 8. Threat Intelligence Reputation Lookup
    if reputation_provider is None:
        from backend.app.reputation import get_reputation_provider
        reputation_provider = get_reputation_provider()

    apex_domain = "" if is_ip_host else extract_apex_and_subdomains(hostname)[0]
    reputation_result = reputation_provider.check_url(
        normalized_url=normalized_url,
        hostname=hostname,
        apex_domain=apex_domain,
    )

    # Combine Heuristics + Threat Intelligence
    # Confirmed threat match elevates verdict to 'malicious'
    if reputation_result.matched:
        final_verdict = "malicious"
        final_risk_score = 1.0
        final_risk_level = "critical"
    else:
        final_verdict = heuristic_verdict
        final_risk_score = heuristic_score
        final_risk_level = heuristic_level

    # Explicit limitations
    limitations = [
        "Analysis is strictly offline and based on static structural heuristics and local feed snapshots.",
        "No live network requests, active crawling, or dynamic DNS lookups were executed.",
        "Absence of a reputation match indicates UNKNOWN threat status, NOT confirmed safety.",
        "Heuristic risk scores represent structural suspicion, not calibrated mathematical probabilities.",
        "Legitimate newly registered domains or enterprise infrastructure may lack reputation history.",
    ]

    return {
        "normalized_url": normalized_url,
        "verdict": final_verdict,
        "label": final_verdict,
        "risk_score": final_risk_score,
        "risk_level": final_risk_level,
        "heuristic_verdict": heuristic_verdict,
        "evidence": evidence,
        "reputation_evidence": reputation_result.reputation_evidence,
        "analysis_method": "offline_static_heuristic_and_threat_intel_v1",
        "limitations": limitations,
        "reputation_check": reputation_result.to_dict(),
    }


def scan_url(raw_url: str, reputation_provider: Optional[Any] = None) -> Dict[str, Any]:
    """Validate, normalize, and analyze a URL string with heuristics and threat reputation."""
    normalized = normalize_and_validate_url(raw_url)
    results = analyze_url_heuristics(normalized, reputation_provider=reputation_provider)
    results["url"] = raw_url.strip()
    return results

