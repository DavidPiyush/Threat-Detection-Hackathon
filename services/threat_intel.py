"""
Threat Intelligence Service
============================

Responsible for enriching email IOCs with external and local
threat-intelligence information.

Supported intelligence types:
    - IP intelligence
    - Domain intelligence
    - URL intelligence

Design principles:
    - External APIs are optional.
    - Failures must not break email analysis.
    - Never claim attribution from reputation/geolocation alone.
    - Preserve evidence provenance.
    - Return normalized data to the analysis/risk engine.

Environment variables:
    ABUSEIPDB_API_KEY=
    VIRUSTOTAL_API_KEY=
"""

from __future__ import annotations

import base64
import ipaddress
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlparse

import requests
from dotenv import load_dotenv


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

load_dotenv()


ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses"
VIRUSTOTAL_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains"
VIRUSTOTAL_URL_URL = "https://www.virustotal.com/api/v3/urls"


DEFAULT_TIMEOUT = 8


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ThreatIntelError(Exception):
    """Base exception for threat-intelligence failures."""


class ThreatIntelProviderError(ThreatIntelError):
    """Raised when an external TI provider fails."""


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def utc_now() -> str:
    """
    Return current UTC timestamp in ISO-8601 format.
    """
    return datetime.now(timezone.utc).isoformat()


def normalize_ip(value: str) -> str | None:
    """
    Validate and normalize an IP address.

    Returns:
        Normalized IP string or None.
    """
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        return None


def is_public_ip(value: str) -> bool:
    """
    Determine whether an IP is globally routable/public.

    Private, loopback, reserved, link-local and documentation
    addresses are not treated as public threat-intelligence targets.
    """
    normalized = normalize_ip(value)

    if not normalized:
        return False

    try:
        ip = ipaddress.ip_address(normalized)
        return ip.is_global
    except ValueError:
        return False


def normalize_domain(domain: str) -> str | None:
    """
    Normalize a domain name.

    This function intentionally does not perform DNS resolution.
    """
    if not domain:
        return None

    domain = domain.strip().lower().rstrip(".")

    if domain.startswith("@"):
        domain = domain[1:]

    if not domain:
        return None

    return domain


def normalize_url(url: str) -> str | None:
    """
    Normalize a URL for TI lookup.
    """
    if not url:
        return None

    url = url.strip()

    if not url:
        return None

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        return None

    if not parsed.hostname:
        return None

    return url


def extract_url_hostname(url: str) -> str | None:
    """
    Extract hostname from a URL.
    """
    try:
        parsed = urlparse(url)

        if not parsed.hostname:
            return None

        return parsed.hostname.lower().rstrip(".")

    except Exception:
        return None


def build_evidence(
    *,
    provider: str,
    indicator_type: str,
    indicator: str,
    source_url: str | None = None,
) -> dict[str, Any]:
    """
    Create a standard evidence/provenance structure.
    """
    return {
        "provider": provider,
        "indicator_type": indicator_type,
        "indicator": indicator,
        "source": source_url,
        "observed_at": utc_now(),
    }


# ---------------------------------------------------------------------------
# Base result builders
# ---------------------------------------------------------------------------


def empty_ip_result(ip: str) -> dict[str, Any]:
    return {
        "indicator": ip,
        "indicator_type": "ip",
        "available": False,
        "reputation": "unknown",
        "threat_score": 0,
        "abuse_confidence": 0,
        "country": None,
        "country_code": None,
        "asn": None,
        "organization": None,
        "isp": None,
        "is_tor": False,
        "is_vpn": False,
        "is_proxy": False,
        "is_open_relay": False,
        "categories": [],
        "reports": 0,
        "evidence": [],
        "errors": [],
    }


def empty_domain_result(domain: str) -> dict[str, Any]:
    return {
        "indicator": domain,
        "indicator_type": "domain",
        "available": False,
        "reputation": "unknown",
        "threat_score": 0,
        "malicious": False,
        "suspicious": False,
        "categories": [],
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "name_servers": [],
        "resolutions": [],
        "evidence": [],
        "errors": [],
    }


def empty_url_result(url: str) -> dict[str, Any]:
    return {
        "indicator": url,
        "indicator_type": "url",
        "available": False,
        "reputation": "unknown",
        "threat_score": 0,
        "malicious": False,
        "suspicious": False,
        "categories": [],
        "final_url": None,
        "domain": extract_url_hostname(url),
        "evidence": [],
        "errors": [],
    }


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------


def check_abuseipdb(
    ip: str,
    *,
    max_age_days: int = 90,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Query AbuseIPDB for an IP address.

    The API key is optional. If it is not configured, the result
    remains unavailable instead of failing the entire analysis.
    """
    result = empty_ip_result(ip)

    normalized = normalize_ip(ip)

    if not normalized:
        result["errors"].append("Invalid IP address")
        return result

    if not is_public_ip(normalized):
        result["errors"].append("IP is not globally routable")
        return result

    if not ABUSEIPDB_API_KEY:
        result["errors"].append("ABUSEIPDB_API_KEY is not configured")
        return result

    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY,
    }

    params = {
        "ipAddress": normalized,
        "maxAgeInDays": max_age_days,
        "verbose": "",
    }

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=timeout,
        )

        response.raise_for_status()

        payload = response.json()
        data = payload.get("data", {})

        abuse_confidence = int(
            data.get("abuseConfidenceScore") or 0
        )

        reports = int(data.get("totalReports") or 0)

        result.update(
            {
                "available": True,
                "abuse_confidence": abuse_confidence,
                "reports": reports,
                "country": data.get("countryName"),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "organization": data.get("domain"),
                "is_tor": bool(data.get("isTor")),
                "categories": data.get("usageType")
                if data.get("usageType")
                else [],
            }
        )

        if abuse_confidence >= 80:
            result["reputation"] = "malicious"
            result["threat_score"] = min(abuse_confidence, 100)

        elif abuse_confidence >= 50:
            result["reputation"] = "suspicious"
            result["threat_score"] = abuse_confidence

        elif abuse_confidence > 0:
            result["reputation"] = "low_risk"
            result["threat_score"] = abuse_confidence

        else:
            result["reputation"] = "unknown"
            result["threat_score"] = 0

        result["evidence"].append(
            build_evidence(
                provider="AbuseIPDB",
                indicator_type="ip",
                indicator=normalized,
                source_url=ABUSEIPDB_URL,
            )
        )

    except requests.RequestException as exc:
        result["errors"].append(
            f"AbuseIPDB request failed: {exc}"
        )

    except (ValueError, TypeError) as exc:
        result["errors"].append(
            f"AbuseIPDB response parsing failed: {exc}"
        )

    return result


# ---------------------------------------------------------------------------
# VirusTotal helpers
# ---------------------------------------------------------------------------


def _virustotal_headers() -> dict[str, str] | None:
    """
    Return VirusTotal headers when an API key is configured.
    """
    if not VIRUSTOTAL_API_KEY:
        return None

    return {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json",
    }


def _extract_vt_stats(attributes: dict[str, Any]) -> dict[str, int]:
    """
    Normalize VirusTotal engine statistics.
    """
    stats = attributes.get("last_analysis_stats") or {}

    return {
        "malicious": int(stats.get("malicious") or 0),
        "suspicious": int(stats.get("suspicious") or 0),
        "undetected": int(stats.get("undetected") or 0),
        "harmless": int(stats.get("harmless") or 0),
        "timeout": int(stats.get("timeout") or 0),
    }


def _calculate_vt_score(stats: dict[str, int]) -> int:
    """
    Convert VirusTotal detections into a normalized 0-100 score.

    This is a local normalization, not an official VirusTotal score.
    """
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    if total <= 0:
        return 0

    score = (
        (malicious / total) * 100
        + (suspicious / total) * 30
    )

    return min(round(score), 100)


# ---------------------------------------------------------------------------
# VirusTotal IP
# ---------------------------------------------------------------------------


def check_virustotal_ip(
    ip: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Query VirusTotal for an IP address.
    """
    result = empty_ip_result(ip)

    normalized = normalize_ip(ip)

    if not normalized:
        result["errors"].append("Invalid IP address")
        return result

    if not is_public_ip(normalized):
        result["errors"].append("IP is not globally routable")
        return result

    headers = _virustotal_headers()

    if not headers:
        result["errors"].append(
            "VIRUSTOTAL_API_KEY is not configured"
        )
        return result

    url = f"{VIRUSTOTAL_IP_URL}/{normalized}"

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
        )

        response.raise_for_status()

        payload = response.json()
        attributes = (
            payload.get("data", {})
            .get("attributes", {})
        )

        stats = _extract_vt_stats(attributes)
        threat_score = _calculate_vt_score(stats)

        result.update(
            {
                "available": True,
                "threat_score": threat_score,
                "country": attributes.get("country"),
                "country_code": attributes.get("country"),
                "asn": attributes.get("asn"),
                "organization": attributes.get("as_owner"),
            }
        )

        if stats["malicious"] > 0:
            result["reputation"] = "malicious"

        elif stats["suspicious"] > 0:
            result["reputation"] = "suspicious"

        else:
            result["reputation"] = "unknown"

        result["evidence"].append(
            build_evidence(
                provider="VirusTotal",
                indicator_type="ip",
                indicator=normalized,
                source_url=url,
            )
        )

    except requests.RequestException as exc:
        result["errors"].append(
            f"VirusTotal IP request failed: {exc}"
        )

    except (ValueError, TypeError) as exc:
        result["errors"].append(
            f"VirusTotal IP response parsing failed: {exc}"
        )

    return result


# ---------------------------------------------------------------------------
# Combined IP Intelligence
# ---------------------------------------------------------------------------


def enrich_ip(
    ip: str,
    *,
    use_abuseipdb: bool = True,
    use_virustotal: bool = True,
) -> dict[str, Any]:
    """
    Enrich an IP address using configured TI providers.

    Provider results are preserved separately so that investigators
    can see where each signal originated.
    """
    normalized = normalize_ip(ip)

    result = empty_ip_result(ip)

    if not normalized:
        result["errors"].append("Invalid IP address")
        return result

    if not is_public_ip(normalized):
        result["errors"].append(
            "IP is not globally routable"
        )
        return result

    providers: dict[str, Any] = {}

    if use_abuseipdb:
        providers["abuseipdb"] = check_abuseipdb(normalized)

    if use_virustotal:
        providers["virustotal"] = check_virustotal_ip(normalized)

    scores = []
    reputations = []

    for provider_result in providers.values():

        if provider_result.get("available"):
            scores.append(
                int(provider_result.get("threat_score") or 0)
            )

            reputation = provider_result.get("reputation")

            if reputation:
                reputations.append(reputation)

            result["evidence"].extend(
                provider_result.get("evidence", [])
            )

    if scores:
        result["available"] = True
        result["threat_score"] = max(scores)

    if "malicious" in reputations:
        result["reputation"] = "malicious"

    elif "suspicious" in reputations:
        result["reputation"] = "suspicious"

    elif reputations:
        result["reputation"] = reputations[0]

    # Prefer the strongest available metadata.
    for provider_result in providers.values():

        for field in (
            "country",
            "country_code",
            "asn",
            "organization",
            "isp",
        ):
            if not result.get(field) and provider_result.get(field):
                result[field] = provider_result[field]

        if provider_result.get("is_tor"):
            result["is_tor"] = True

        if provider_result.get("is_vpn"):
            result["is_vpn"] = True

        if provider_result.get("is_proxy"):
            result["is_proxy"] = True

    result["providers"] = providers

    return result


# ---------------------------------------------------------------------------
# VirusTotal Domain
# ---------------------------------------------------------------------------


def check_virustotal_domain(
    domain: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Query VirusTotal for a domain.
    """
    result = empty_domain_result(domain)

    normalized = normalize_domain(domain)

    if not normalized:
        result["errors"].append("Invalid domain")
        return result

    headers = _virustotal_headers()

    if not headers:
        result["errors"].append(
            "VIRUSTOTAL_API_KEY is not configured"
        )
        return result

    url = (
        f"{VIRUSTOTAL_DOMAIN_URL}/"
        f"{quote(normalized, safe='')}"
    )

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
        )

        response.raise_for_status()

        payload = response.json()

        attributes = (
            payload.get("data", {})
            .get("attributes", {})
        )

        stats = _extract_vt_stats(attributes)
        threat_score = _calculate_vt_score(stats)

        result.update(
            {
                "available": True,
                "threat_score": threat_score,
                "resolutions": attributes.get(
                    "last_dns_records", []
                ),
            }
        )

        if stats["malicious"] > 0:
            result["malicious"] = True
            result["reputation"] = "malicious"

        elif stats["suspicious"] > 0:
            result["suspicious"] = True
            result["reputation"] = "suspicious"

        else:
            result["reputation"] = "unknown"

        result["evidence"].append(
            build_evidence(
                provider="VirusTotal",
                indicator_type="domain",
                indicator=normalized,
                source_url=url,
            )
        )

    except requests.RequestException as exc:
        result["errors"].append(
            f"VirusTotal domain request failed: {exc}"
        )

    except (ValueError, TypeError) as exc:
        result["errors"].append(
            f"VirusTotal domain response parsing failed: {exc}"
        )

    return result


# ---------------------------------------------------------------------------
# VirusTotal URL
# ---------------------------------------------------------------------------


def check_virustotal_url(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Query VirusTotal for an exact URL.

    VirusTotal URL lookup uses the URL identifier obtained by
    URL-safe base64 encoding without trailing '=' characters.
    """
    result = empty_url_result(url)

    normalized = normalize_url(url)

    if not normalized:
        result["errors"].append("Invalid HTTP/HTTPS URL")
        return result

    headers = _virustotal_headers()

    if not headers:
        result["errors"].append(
            "VIRUSTOTAL_API_KEY is not configured"
        )
        return result

    encoded_url = (
        base64.urlsafe_b64encode(
            normalized.encode("utf-8")
        )
        .decode("utf-8")
        .rstrip("=")
    )

    endpoint = f"{VIRUSTOTAL_URL_URL}/{encoded_url}"

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=timeout,
        )

        response.raise_for_status()

        payload = response.json()

        attributes = (
            payload.get("data", {})
            .get("attributes", {})
        )

        stats = _extract_vt_stats(attributes)
        threat_score = _calculate_vt_score(stats)

        result.update(
            {
                "available": True,
                "threat_score": threat_score,
                "final_url": attributes.get("last_final_url"),
            }
        )

        if stats["malicious"] > 0:
            result["malicious"] = True
            result["reputation"] = "malicious"

        elif stats["suspicious"] > 0:
            result["suspicious"] = True
            result["reputation"] = "suspicious"

        else:
            result["reputation"] = "unknown"

        result["evidence"].append(
            build_evidence(
                provider="VirusTotal",
                indicator_type="url",
                indicator=normalized,
                source_url=endpoint,
            )
        )

    except requests.RequestException as exc:
        result["errors"].append(
            f"VirusTotal URL request failed: {exc}"
        )

    except (ValueError, TypeError) as exc:
        result["errors"].append(
            f"VirusTotal URL response parsing failed: {exc}"
        )

    return result


# ---------------------------------------------------------------------------
# Domain Intelligence
# ---------------------------------------------------------------------------


def enrich_domain(
    domain: str,
    *,
    use_virustotal: bool = True,
) -> dict[str, Any]:
    """
    Enrich a domain with available TI providers.
    """
    normalized = normalize_domain(domain)

    result = empty_domain_result(domain)

    if not normalized:
        result["errors"].append("Invalid domain")
        return result

    providers = {}

    if use_virustotal:
        providers["virustotal"] = check_virustotal_domain(
            normalized
        )

    scores = []
    reputations = []

    for provider_result in providers.values():

        if provider_result.get("available"):
            scores.append(
                int(provider_result.get("threat_score") or 0)
            )

            reputations.append(
                provider_result.get(
                    "reputation",
                    "unknown",
                )
            )

            result["evidence"].extend(
                provider_result.get("evidence", [])
            )

            if provider_result.get("malicious"):
                result["malicious"] = True

            if provider_result.get("suspicious"):
                result["suspicious"] = True

    if scores:
        result["available"] = True
        result["threat_score"] = max(scores)

    if "malicious" in reputations:
        result["reputation"] = "malicious"

    elif "suspicious" in reputations:
        result["reputation"] = "suspicious"

    elif reputations:
        result["reputation"] = reputations[0]

    result["providers"] = providers

    return result


# ---------------------------------------------------------------------------
# URL Intelligence
# ---------------------------------------------------------------------------


def enrich_url(
    url: str,
    *,
    use_virustotal: bool = True,
) -> dict[str, Any]:
    """
    Enrich a URL using available TI providers.
    """
    normalized = normalize_url(url)

    result = empty_url_result(url)

    if not normalized:
        result["errors"].append(
            "Invalid HTTP/HTTPS URL"
        )
        return result

    providers = {}

    if use_virustotal:
        providers["virustotal"] = check_virustotal_url(
            normalized
        )

    scores = []
    reputations = []

    for provider_result in providers.values():

        if provider_result.get("available"):

            scores.append(
                int(provider_result.get("threat_score") or 0)
            )

            reputations.append(
                provider_result.get(
                    "reputation",
                    "unknown",
                )
            )

            result["evidence"].extend(
                provider_result.get("evidence", [])
            )

            if provider_result.get("malicious"):
                result["malicious"] = True

            if provider_result.get("suspicious"):
                result["suspicious"] = True

    if scores:
        result["available"] = True
        result["threat_score"] = max(scores)

    if "malicious" in reputations:
        result["reputation"] = "malicious"

    elif "suspicious" in reputations:
        result["reputation"] = "suspicious"

    elif reputations:
        result["reputation"] = reputations[0]

    result["providers"] = providers

    return result


# ---------------------------------------------------------------------------
# Bulk IOC Enrichment
# ---------------------------------------------------------------------------


def enrich_iocs(
    *,
    ips: list[str] | None = None,
    domains: list[str] | None = None,
    urls: list[str] | None = None,
) -> dict[str, Any]:
    """
    Enrich multiple IOCs.

    This function is intentionally synchronous for the initial MVP.
    Later, this can be moved to async/background workers to avoid
    slowing down the HTTP request.
    """
    ips = ips or []
    domains = domains or []
    urls = urls or []

    ip_results = []
    domain_results = []
    url_results = []

    # De-duplicate while preserving order.
    unique_ips = list(
        dict.fromkeys(
            normalize_ip(ip)
            for ip in ips
            if normalize_ip(ip)
        )
    )

    unique_domains = list(
        dict.fromkeys(
            normalize_domain(domain)
            for domain in domains
            if normalize_domain(domain)
        )
    )

    unique_urls = list(
        dict.fromkeys(
            normalize_url(url)
            for url in urls
            if normalize_url(url)
        )
    )

    for ip in unique_ips:
        ip_results.append(
            enrich_ip(ip)
        )

    for domain in unique_domains:
        domain_results.append(
            enrich_domain(domain)
        )

    for url in unique_urls:
        url_results.append(
            enrich_url(url)
        )

    return {
        "analyzed_at": utc_now(),
        "summary": {
            "ips": len(ip_results),
            "domains": len(domain_results),
            "urls": len(url_results),
            "malicious": sum(
                1
                for item in (
                    ip_results
                    + domain_results
                    + url_results
                )
                if item.get("reputation") == "malicious"
                or item.get("malicious") is True
            ),
            "suspicious": sum(
                1
                for item in (
                    ip_results
                    + domain_results
                    + url_results
                )
                if item.get("reputation") == "suspicious"
                or item.get("suspicious") is True
            ),
        },
        "ips": ip_results,
        "domains": domain_results,
        "urls": url_results,
    }


# ---------------------------------------------------------------------------
# Risk Engine Adapter
# ---------------------------------------------------------------------------


def build_infrastructure_signals(
    ti_results: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Convert TI results into normalized infrastructure signals.

    This output is compatible with the risk-engine concept:

        threat_score
        reputation
        TOR
        VPN
        open relay
        etc.

    Important:
        These signals indicate infrastructure risk.
        They do NOT prove attacker identity or physical location.
    """
    signals: list[dict[str, Any]] = []

    all_results = (
        ti_results.get("ips", [])
        + ti_results.get("domains", [])
        + ti_results.get("urls", [])
    )

    for result in all_results:

        indicator = result.get("indicator")
        indicator_type = result.get("indicator_type")

        threat_score = int(
            result.get("threat_score") or 0
        )

        reputation = result.get(
            "reputation",
            "unknown",
        )

        if threat_score >= 80:
            signals.append(
                {
                    "type": "threat_intelligence_high_risk",
                    "severity": "critical",
                    "description": (
                        f"{indicator_type.upper()} {indicator} "
                        f"has a high threat-intelligence score "
                        f"({threat_score}/100)."
                    ),
                    "evidence": {
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "threat_score": threat_score,
                        "reputation": reputation,
                    },
                }
            )

        elif threat_score >= 60:
            signals.append(
                {
                    "type": "threat_intelligence_suspicious",
                    "severity": "high",
                    "description": (
                        f"{indicator_type.upper()} {indicator} "
                        f"has a suspicious threat-intelligence "
                        f"score ({threat_score}/100)."
                    ),
                    "evidence": {
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "threat_score": threat_score,
                        "reputation": reputation,
                    },
                }
            )

        if reputation == "malicious":
            signals.append(
                {
                    "type": "malicious_reputation",
                    "severity": "critical",
                    "description": (
                        f"{indicator_type.upper()} {indicator} "
                        "has malicious reputation evidence."
                    ),
                    "evidence": {
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "reputation": reputation,
                    },
                }
            )

        elif reputation == "suspicious":
            signals.append(
                {
                    "type": "suspicious_reputation",
                    "severity": "high",
                    "description": (
                        f"{indicator_type.upper()} {indicator} "
                        "has suspicious reputation evidence."
                    ),
                    "evidence": {
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "reputation": reputation,
                    },
                }
            )

        if result.get("is_tor"):
            signals.append(
                {
                    "type": "tor_infrastructure",
                    "severity": "medium",
                    "description": (
                        f"IP {indicator} is associated with "
                        "Tor infrastructure."
                    ),
                    "evidence": {
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "is_tor": True,
                    },
                }
            )

        if result.get("is_vpn"):
            signals.append(
                {
                    "type": "vpn_infrastructure",
                    "severity": "low",
                    "description": (
                        f"IP {indicator} is associated with "
                        "VPN infrastructure."
                    ),
                    "evidence": {
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "is_vpn": True,
                    },
                }
            )

    return signals


# ---------------------------------------------------------------------------
# Health / Configuration
# ---------------------------------------------------------------------------


def get_threat_intel_status() -> dict[str, Any]:
    """
    Return configured TI providers.

    API keys themselves are never returned.
    """
    return {
        "service": "threat_intelligence",
        "status": "ready",
        "providers": {
            "abuseipdb": {
                "configured": bool(ABUSEIPDB_API_KEY),
            },
            "virustotal": {
                "configured": bool(VIRUSTOTAL_API_KEY),
            },
        },
    }


# ---------------------------------------------------------------------------
# Public exports
# ---------------------------------------------------------------------------


__all__ = [
    "ThreatIntelError",
    "ThreatIntelProviderError",
    "check_abuseipdb",
    "check_virustotal_ip",
    "check_virustotal_domain",
    "check_virustotal_url",
    "enrich_ip",
    "enrich_domain",
    "enrich_url",
    "enrich_iocs",
    "build_infrastructure_signals",
    "get_threat_intel_status",
]