"""
Domain Intelligence Service
===========================

Provides domain-level intelligence for email investigations.

Responsibilities:
    - Normalize and validate domains
    - Extract registrable/root domain
    - DNS resolution
    - MX record discovery
    - NS record discovery
    - RDAP registration intelligence
    - Domain age calculation
    - Basic lookalike / typosquatting indicators
    - Infrastructure signals for the risk engine

Important:
    Domain intelligence provides evidence and indicators.
    It does NOT prove attacker identity or malicious intent by itself.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from datetime import datetime, timezone
from typing import Any

import requests


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 5

RDAP_BOOTSTRAP_URL = (
    "https://rdap.org/domain/"
)

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}"
    r"[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class DomainIntelligenceError(Exception):
    """Base exception for domain intelligence errors."""


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def normalize_domain(domain: str) -> str | None:
    """
    Normalize a domain name.

    Examples:

        "Example.COM"      -> "example.com"
        "@example.com"     -> "example.com"
        "example.com."     -> "example.com"
    """

    if not domain:
        return None

    domain = domain.strip().lower()

    if domain.startswith("@"):
        domain = domain[1:]

    domain = domain.rstrip(".")

    if not domain:
        return None

    # Remove surrounding brackets occasionally seen in parsed data.
    if domain.startswith("[") and domain.endswith("]"):
        domain = domain[1:-1]

    return domain


def is_valid_domain(domain: str) -> bool:
    """
    Validate a conventional DNS domain name.

    IP addresses are intentionally rejected because they belong to
    IP intelligence rather than domain intelligence.
    """

    normalized = normalize_domain(domain)

    if not normalized:
        return False

    try:
        ipaddress.ip_address(normalized)
        return False
    except ValueError:
        pass

    return bool(DOMAIN_PATTERN.match(normalized))


# ---------------------------------------------------------------------------
# Domain Structure
# ---------------------------------------------------------------------------


def get_domain_labels(domain: str) -> list[str]:
    """
    Return domain labels.

    Example:

        mail.login.example.com
        ->
        ["mail", "login", "example", "com"]
    """

    normalized = normalize_domain(domain)

    if not normalized:
        return []

    return normalized.split(".")


def get_root_domain(domain: str) -> str | None:
    """
    Return a basic registrable/root domain.

    Example:

        mail.example.com -> example.com

    Note:
        This is a lightweight implementation. Public suffixes such as
        co.uk require a public-suffix database for perfect accuracy.
    """

    normalized = normalize_domain(domain)

    if not normalized or not is_valid_domain(normalized):
        return None

    labels = normalized.split(".")

    if len(labels) < 2:
        return normalized

    return ".".join(labels[-2:])


def get_subdomain(domain: str) -> str | None:
    """
    Return the subdomain portion.

    Example:

        login.secure.example.com
        ->
        login.secure
    """

    normalized = normalize_domain(domain)

    if not normalized:
        return None

    root = get_root_domain(normalized)

    if not root:
        return None

    if normalized == root:
        return None

    return normalized[: -(len(root) + 1)]


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def resolve_dns(
    domain: str,
) -> dict[str, Any]:
    """
    Resolve A/AAAA records using the local system resolver.

    Returns normalized addresses and errors.
    """

    result = {
        "domain": domain,
        "success": False,
        "addresses": [],
        "ipv4": [],
        "ipv6": [],
        "error": None,
    }

    normalized = normalize_domain(domain)

    if not normalized:
        result["error"] = "Invalid domain"
        return result

    if not is_valid_domain(normalized):
        result["error"] = "Invalid domain format"
        return result

    try:
        records = socket.getaddrinfo(
            normalized,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        addresses = []

        for record in records:

            sockaddr = record[4]

            if not sockaddr:
                continue

            address = sockaddr[0]

            if address not in addresses:
                addresses.append(address)

        result["addresses"] = addresses
        result["ipv4"] = [
            address
            for address in addresses
            if ":" not in address
        ]
        result["ipv6"] = [
            address
            for address in addresses
            if ":" in address
        ]

        result["success"] = True

    except socket.gaierror:
        result["error"] = "DNS resolution failed"

    except Exception as exc:
        result["error"] = f"DNS error: {exc}"

    return result


def resolve_mx(
    domain: str,
) -> dict[str, Any]:
    """
    Resolve MX records.

    Uses dnspython when available.

    If dnspython is unavailable, the service returns a controlled
    error instead of breaking the investigation.
    """

    result = {
        "domain": domain,
        "success": False,
        "records": [],
        "error": None,
    }

    normalized = normalize_domain(domain)

    if not normalized:
        result["error"] = "Invalid domain"
        return result

    try:
        import dns.resolver

        answers = dns.resolver.resolve(
            normalized,
            "MX",
            lifetime=DEFAULT_TIMEOUT,
        )

        records = []

        for answer in answers:

            records.append(
                {
                    "priority": int(answer.preference),
                    "host": str(
                        answer.exchange
                    ).rstrip("."),
                }
            )

        records.sort(
            key=lambda item: item["priority"]
        )

        result["records"] = records
        result["success"] = True

    except ImportError:
        result["error"] = (
            "dnspython is not installed"
        )

    except Exception as exc:
        result["error"] = f"MX lookup failed: {exc}"

    return result


def resolve_nameservers(
    domain: str,
) -> dict[str, Any]:
    """
    Resolve NS records.
    """

    result = {
        "domain": domain,
        "success": False,
        "records": [],
        "error": None,
    }

    normalized = normalize_domain(domain)

    if not normalized:
        result["error"] = "Invalid domain"
        return result

    try:
        import dns.resolver

        answers = dns.resolver.resolve(
            normalized,
            "NS",
            lifetime=DEFAULT_TIMEOUT,
        )

        records = []

        for answer in answers:

            host = str(answer).rstrip(".")

            if host not in records:
                records.append(host)

        result["records"] = records
        result["success"] = True

    except ImportError:
        result["error"] = (
            "dnspython is not installed"
        )

    except Exception as exc:
        result["error"] = f"NS lookup failed: {exc}"

    return result


# ---------------------------------------------------------------------------
# RDAP
# ---------------------------------------------------------------------------


def parse_rdap_datetime(
    value: str | None,
) -> datetime | None:
    """
    Parse common RDAP timestamp formats.
    """

    if not value:
        return None

    try:
        value = value.replace(
            "Z",
            "+00:00",
        )

        parsed = datetime.fromisoformat(value)

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed

    except ValueError:
        return None


def extract_rdap_event(
    events: list[dict[str, Any]],
    event_action: str,
) -> str | None:
    """
    Extract a specific RDAP event date.
    """

    for event in events:

        if (
            event.get("eventAction")
            == event_action
        ):
            return event.get("eventDate")

    return None


def query_rdap(
    domain: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Query RDAP for domain registration intelligence.
    """

    result = {
        "domain": domain,
        "success": False,
        "handle": None,
        "status": [],
        "registrar": None,
        "created": None,
        "updated": None,
        "expires": None,
        "nameservers": [],
        "events": [],
        "error": None,
    }

    normalized = normalize_domain(domain)

    if not normalized:
        result["error"] = "Invalid domain"
        return result

    if not is_valid_domain(normalized):
        result["error"] = "Invalid domain format"
        return result

    url = (
        f"{RDAP_BOOTSTRAP_URL}"
        f"{normalized}"
    )

    headers = {
        "Accept": "application/rdap+json, "
                  "application/json",
        "User-Agent": (
            "ThreatDetect-SIH/1.0 "
            "(Email Forensics)"
        ),
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
        )

        response.raise_for_status()

        payload = response.json()

        result["success"] = True

        result["handle"] = payload.get(
            "handle"
        )

        result["status"] = payload.get(
            "status",
            [],
        )

        events = payload.get(
            "events",
            [],
        )

        result["events"] = events

        result["created"] = extract_rdap_event(
            events,
            "registration",
        )

        result["updated"] = extract_rdap_event(
            events,
            "last changed",
        )

        result["expires"] = extract_rdap_event(
            events,
            "expiration",
        )

        nameservers = payload.get(
            "nameservers",
            [],
        )

        for nameserver in nameservers:

            ldh_name = nameserver.get(
                "ldhName"
            )

            if ldh_name:
                result["nameservers"].append(
                    ldh_name.lower()
                )

        # Attempt to identify registrar organization.
        entities = payload.get(
            "entities",
            []
        )

        for entity in entities:

            roles = entity.get(
                "roles",
                []
            )

            if "registrar" not in roles:
                continue

            vcard = entity.get(
                "vcardArray"
            )

            if not vcard or len(vcard) < 2:
                continue

            properties = vcard[1]

            for prop in properties:

                if (
                    len(prop) >= 4
                    and prop[0] == "fn"
                ):
                    result["registrar"] = (
                        prop[3]
                    )
                    break

            if result["registrar"]:
                break

    except requests.HTTPError as exc:

        status_code = (
            exc.response.status_code
            if exc.response is not None
            else None
        )

        result["error"] = (
            f"RDAP HTTP error: "
            f"{status_code}"
        )

    except requests.RequestException as exc:

        result["error"] = (
            f"RDAP request failed: {exc}"
        )

    except ValueError as exc:

        result["error"] = (
            f"RDAP response parsing failed: "
            f"{exc}"
        )

    except Exception as exc:

        result["error"] = (
            f"RDAP error: {exc}"
        )

    return result


# ---------------------------------------------------------------------------
# Domain Age
# ---------------------------------------------------------------------------


def calculate_domain_age(
    registration_date: str | None,
) -> dict[str, Any]:
    """
    Calculate approximate domain age from an RDAP registration date.
    """

    result = {
        "available": False,
        "registration_date": registration_date,
        "age_days": None,
        "age_category": "unknown",
    }

    parsed = parse_rdap_datetime(
        registration_date
    )

    if not parsed:
        return result

    now = datetime.now(timezone.utc)

    age = now - parsed

    age_days = max(
        0,
        age.days,
    )

    result["available"] = True
    result["age_days"] = age_days

    if age_days <= 7:
        result["age_category"] = (
            "very_new"
        )

    elif age_days <= 30:
        result["age_category"] = (
            "new"
        )

    elif age_days <= 90:
        result["age_category"] = (
            "recent"
        )

    elif age_days <= 365:
        result["age_category"] = (
            "less_than_one_year"
        )

    else:
        result["age_category"] = (
            "established"
        )

    return result


# ---------------------------------------------------------------------------
# Lookalike / Typosquatting Analysis
# ---------------------------------------------------------------------------


def normalize_visual_token(
    value: str,
) -> str:
    """
    Normalize common visual substitutions for lightweight
    lookalike detection.

    This is intentionally conservative.
    """

    replacements = {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
    }

    value = value.lower()

    for source, target in replacements.items():
        value = value.replace(
            source,
            target,
        )

    return value


def levenshtein_distance(
    first: str,
    second: str,
) -> int:
    """
    Calculate Levenshtein edit distance.

    Used only for lightweight lookalike analysis.
    """

    if first == second:
        return 0

    if not first:
        return len(second)

    if not second:
        return len(first)

    previous = list(
        range(len(second) + 1)
    )

    for i, char_first in enumerate(
        first,
        start=1,
    ):

        current = [i]

        for j, char_second in enumerate(
            second,
            start=1,
        ):

            insertion = (
                current[j - 1] + 1
            )

            deletion = (
                previous[j] + 1
            )

            substitution = (
                previous[j - 1]
                + (
                    char_first
                    != char_second
                )
            )

            current.append(
                min(
                    insertion,
                    deletion,
                    substitution,
                )
            )

        previous = current

    return previous[-1]


def analyze_lookalike(
    domain: str,
    trusted_domains: list[str] | None = None,
) -> dict[str, Any]:
    """
    Detect simple lookalike relationships against a list of
    trusted domains.

    This is NOT a commercial-grade brand impersonation engine.

    Example:
        micr0soft.com
        vs
        microsoft.com
    """

    normalized = normalize_domain(domain)

    result = {
        "domain": normalized,
        "is_lookalike": False,
        "matches": [],
        "signals": [],
    }

    if not normalized:
        return result

    trusted_domains = trusted_domains or []

    root = get_root_domain(normalized)

    if not root:
        return result

    root_without_tld = root.split(".")[0]

    normalized_token = normalize_visual_token(
        root_without_tld
    )

    for trusted in trusted_domains:

        trusted_normalized = normalize_domain(
            trusted
        )

        if not trusted_normalized:
            continue

        trusted_root = get_root_domain(
            trusted_normalized
        )

        if not trusted_root:
            continue

        if trusted_root == root:
            continue

        trusted_token = normalize_visual_token(
            trusted_root.split(".")[0]
        )

        distance = levenshtein_distance(
            normalized_token,
            trusted_token,
        )

        max_length = max(
            len(normalized_token),
            len(trusted_token),
        )

        if max_length == 0:
            continue

        similarity = 1 - (
            distance / max_length
        )

        if similarity >= 0.80:

            result["is_lookalike"] = True

            result["matches"].append(
                {
                    "trusted_domain": trusted_root,
                    "distance": distance,
                    "similarity": round(
                        similarity,
                        3,
                    ),
                }
            )

            result["signals"].append(
                "lookalike-domain"
            )

    return result


# ---------------------------------------------------------------------------
# Domain Infrastructure Signals
# ---------------------------------------------------------------------------


def build_domain_signals(
    *,
    domain: str,
    dns_result: dict[str, Any],
    mx_result: dict[str, Any],
    rdap_result: dict[str, Any],
    age_result: dict[str, Any],
    lookalike_result: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Generate explainable domain-level signals.
    """

    signals: list[dict[str, Any]] = []

    normalized = normalize_domain(domain)

    if not normalized:
        return signals

    # ---------------------------------------------------------------
    # DNS
    # ---------------------------------------------------------------

    if dns_result.get("success"):

        addresses = dns_result.get(
            "addresses",
            [],
        )

        if addresses:

            signals.append(
                {
                    "type": "domain_resolves",
                    "severity": "informational",
                    "description": (
                        f"{normalized} resolves to "
                        f"{len(addresses)} IP address(es)."
                    ),
                    "evidence": {
                        "domain": normalized,
                        "addresses": addresses,
                    },
                }
            )

    # ---------------------------------------------------------------
    # MX
    # ---------------------------------------------------------------

    if mx_result.get("success"):

        records = mx_result.get(
            "records",
            [],
        )

        if not records:

            signals.append(
                {
                    "type": "no_mx_record",
                    "severity": "low",
                    "description": (
                        f"{normalized} has no "
                        "observable MX record."
                    ),
                    "evidence": {
                        "domain": normalized,
                    },
                }
            )

    # ---------------------------------------------------------------
    # RDAP
    # ---------------------------------------------------------------

    if not rdap_result.get("success"):

        signals.append(
            {
                "type": "rdap_unavailable",
                "severity": "informational",
                "description": (
                    f"Registration intelligence for "
                    f"{normalized} was unavailable."
                ),
                "evidence": {
                    "domain": normalized,
                    "error": rdap_result.get(
                        "error"
                    ),
                },
            }
        )

    # ---------------------------------------------------------------
    # Domain age
    # ---------------------------------------------------------------

    age_days = age_result.get(
        "age_days"
    )

    if age_days is not None:

        if age_days <= 7:

            signals.append(
                {
                    "type": "very_new_domain",
                    "severity": "high",
                    "description": (
                        f"{normalized} was registered "
                        f"approximately {age_days} day(s) ago."
                    ),
                    "evidence": {
                        "domain": normalized,
                        "age_days": age_days,
                        "registration_date":
                            age_result.get(
                                "registration_date"
                            ),
                    },
                }
            )

        elif age_days <= 30:

            signals.append(
                {
                    "type": "new_domain",
                    "severity": "medium",
                    "description": (
                        f"{normalized} was registered "
                        f"approximately {age_days} day(s) ago."
                    ),
                    "evidence": {
                        "domain": normalized,
                        "age_days": age_days,
                        "registration_date":
                            age_result.get(
                                "registration_date"
                            ),
                    },
                }
            )

    # ---------------------------------------------------------------
    # Lookalike
    # ---------------------------------------------------------------

    if lookalike_result.get(
        "is_lookalike"
    ):

        signals.append(
            {
                "type": "lookalike_domain",
                "severity": "high",
                "description": (
                    f"{normalized} resembles one or more "
                    "trusted domains."
                ),
                "evidence": {
                    "domain": normalized,
                    "matches":
                        lookalike_result.get(
                            "matches",
                            [],
                        ),
                },
            }
        )

    return signals


# ---------------------------------------------------------------------------
# Complete Domain Analysis
# ---------------------------------------------------------------------------


def analyze_domain(
    domain: str,
    *,
    trusted_domains: list[str] | None = None,
    perform_dns: bool = True,
    perform_mx: bool = True,
    perform_rdap: bool = True,
) -> dict[str, Any]:
    """
    Perform complete domain intelligence analysis.
    """

    normalized = normalize_domain(domain)

    result: dict[str, Any] = {
        "domain": normalized,
        "valid": False,
        "root_domain": None,
        "subdomain": None,
        "labels": [],
        "dns": None,
        "mx": None,
        "rdap": None,
        "age": None,
        "lookalike": None,
        "signals": [],
    }

    if not normalized:
        result["signals"].append(
            {
                "type": "invalid_domain",
                "severity": "low",
                "description": (
                    "Domain value is empty or invalid."
                ),
                "evidence": {
                    "domain": domain,
                },
            }
        )

        return result

    if not is_valid_domain(normalized):

        result["signals"].append(
            {
                "type": "invalid_domain",
                "severity": "low",
                "description": (
                    f"{normalized} does not match "
                    "expected domain syntax."
                ),
                "evidence": {
                    "domain": normalized,
                },
            }
        )

        return result

    result["valid"] = True
    result["root_domain"] = get_root_domain(
        normalized
    )
    result["subdomain"] = get_subdomain(
        normalized
    )
    result["labels"] = get_domain_labels(
        normalized
    )

    # -----------------------------------------------------------------------
    # DNS
    # -----------------------------------------------------------------------

    dns_result = {
        "success": False,
        "addresses": [],
        "ipv4": [],
        "ipv6": [],
    }

    if perform_dns:
        dns_result = resolve_dns(
            normalized
        )

    result["dns"] = dns_result

    # -----------------------------------------------------------------------
    # MX
    # -----------------------------------------------------------------------

    mx_result = {
        "success": False,
        "records": [],
    }

    if perform_mx:
        mx_result = resolve_mx(
            normalized
        )

    result["mx"] = mx_result

    # -----------------------------------------------------------------------
    # RDAP
    # -----------------------------------------------------------------------

    rdap_result = {
        "success": False,
        "error": "RDAP lookup disabled",
    }

    if perform_rdap:
        rdap_result = query_rdap(
            normalized
        )

    result["rdap"] = rdap_result

    # -----------------------------------------------------------------------
    # Domain age
    # -----------------------------------------------------------------------

    age_result = calculate_domain_age(
        rdap_result.get("created")
    )

    result["age"] = age_result

    # -----------------------------------------------------------------------
    # Lookalike
    # -----------------------------------------------------------------------

    lookalike_result = analyze_lookalike(
        normalized,
        trusted_domains=trusted_domains,
    )

    result["lookalike"] = lookalike_result

    # -----------------------------------------------------------------------
    # Signals
    # -----------------------------------------------------------------------

    result["signals"] = build_domain_signals(
        domain=normalized,
        dns_result=dns_result,
        mx_result=mx_result,
        rdap_result=rdap_result,
        age_result=age_result,
        lookalike_result=lookalike_result,
    )

    return result


# ---------------------------------------------------------------------------
# Bulk Domain Analysis
# ---------------------------------------------------------------------------


def analyze_domains(
    domains: list[str],
    *,
    trusted_domains: list[str] | None = None,
    perform_dns: bool = True,
    perform_mx: bool = True,
    perform_rdap: bool = True,
) -> list[dict[str, Any]]:
    """
    Analyze multiple unique domains.
    """

    results: list[dict[str, Any]] = []

    seen: set[str] = set()

    for domain in domains:

        normalized = normalize_domain(
            domain
        )

        if not normalized:
            results.append(
                analyze_domain(
                    domain,
                    trusted_domains=trusted_domains,
                    perform_dns=False,
                    perform_mx=False,
                    perform_rdap=False,
                )
            )
            continue

        if normalized in seen:
            continue

        seen.add(normalized)

        results.append(
            analyze_domain(
                normalized,
                trusted_domains=trusted_domains,
                perform_dns=perform_dns,
                perform_mx=perform_mx,
                perform_rdap=perform_rdap,
            )
        )

    return results


# ---------------------------------------------------------------------------
# Risk Engine Adapter
# ---------------------------------------------------------------------------


def build_domain_risk_signals(
    analysis: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Convert domain-analysis signals into normalized risk signals.

    These can be passed to risk_engine.py.
    """

    signals = analysis.get(
        "signals",
        [],
    )

    if not isinstance(signals, list):
        return []

    return [
        {
            "type": signal.get(
                "type",
                "unknown_domain_signal",
            ),
            "severity": signal.get(
                "severity",
                "informational",
            ),
            "description": signal.get(
                "description",
                "Domain intelligence signal detected.",
            ),
            "evidence": signal.get(
                "evidence",
                {},
            ),
        }
        for signal in signals
        if isinstance(signal, dict)
    ]


# ---------------------------------------------------------------------------
# Service Status
# ---------------------------------------------------------------------------


def get_domain_intelligence_status() -> dict[str, Any]:
    """
    Return service capabilities.
    """

    try:
        import dns.resolver

        dnspython_available = True

    except ImportError:
        dnspython_available = False

    return {
        "service": "domain_intelligence",
        "status": "ready",
        "capabilities": {
            "domain_validation": True,
            "root_domain_extraction": True,
            "dns_resolution": True,
            "mx_lookup": dnspython_available,
            "nameserver_lookup": dnspython_available,
            "rdap": True,
            "domain_age": True,
            "lookalike_detection": True,
        },
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


__all__ = [
    "DomainIntelligenceError",
    "normalize_domain",
    "is_valid_domain",
    "get_domain_labels",
    "get_root_domain",
    "get_subdomain",
    "resolve_dns",
    "resolve_mx",
    "resolve_nameservers",
    "query_rdap",
    "calculate_domain_age",
    "analyze_lookalike",
    "build_domain_signals",
    "analyze_domain",
    "analyze_domains",
    "build_domain_risk_signals",
    "get_domain_intelligence_status",
]