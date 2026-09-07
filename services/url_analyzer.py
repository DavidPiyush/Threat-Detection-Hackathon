"""
URL Analyzer Service
====================

Analyzes URLs extracted from suspicious emails.

Responsibilities:
    - URL normalization
    - URL parsing
    - Hostname/IP detection
    - Port analysis
    - HTTPS analysis
    - URL encoding detection
    - Obfuscation detection
    - Suspicious hostname/path/query indicators
    - Credential/phishing parameter detection
    - URL risk signals
    - Output compatible with the risk engine

Important:
    This service performs STRUCTURAL analysis.

    It does not:
        - execute URLs
        - download files
        - submit credentials
        - execute JavaScript
        - automatically follow dangerous redirects
        - prove that a URL is malicious

    External reputation checks belong to threat_intel.py.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from typing import Any
from urllib.parse import (
    parse_qsl,
    unquote,
    urlparse,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_URL_LENGTH = 4096

SUSPICIOUS_PORTS = {
    21,
    22,
    23,
    25,
    110,
    143,
    445,
    3389,
    5900,
    8080,
    8443,
}

SUSPICIOUS_TLDS = {
    ".zip",
    ".mov",
    ".click",
    ".top",
    ".xyz",
    ".buzz",
    ".work",
    ".live",
    ".cam",
    ".icu",
}

SUSPICIOUS_HOST_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "credential",
    "wallet",
    "billing",
    "payment",
    "invoice",
    "microsoft",
    "office365",
    "outlook",
    "paypal",
    "apple",
    "google",
    "amazon",
    "bank",
}

SUSPICIOUS_PATH_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "password",
    "credential",
    "reset",
    "unlock",
    "payment",
    "invoice",
    "billing",
    "wallet",
    "confirm",
    "mfa",
    "2fa",
    "security",
}

SUSPICIOUS_QUERY_KEYS = {
    "token",
    "auth",
    "password",
    "passwd",
    "pwd",
    "credential",
    "session",
    "sid",
    "login",
    "user",
    "username",
    "email",
    "redirect",
    "url",
    "return",
    "next",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.one",
}

DANGEROUS_SCHEMES = {
    "javascript",
    "data",
    "vbscript",
    "file",
}

URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"`]+",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class URLAnalyzerError(Exception):
    """Base exception for URL analyzer errors."""


# ---------------------------------------------------------------------------
# Basic Utilities
# ---------------------------------------------------------------------------


def normalize_url(url: str) -> str | None:
    """
    Normalize an HTTP/HTTPS URL.

    Removes surrounding whitespace and common trailing punctuation.
    """

    if not url:
        return None

    url = url.strip()

    if not url:
        return None

    url = url.rstrip(
        ".,;:!?)]}>\"'"
    )

    if len(url) > MAX_URL_LENGTH:
        return None

    parsed = urlparse(url)

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        return None

    if not parsed.hostname:
        return None

    return url


def is_valid_url(url: str) -> bool:
    """
    Check whether a URL is syntactically valid for analysis.
    """

    normalized = normalize_url(url)

    if not normalized:
        return False

    try:
        parsed = urlparse(normalized)

        return bool(
            parsed.scheme
            and parsed.hostname
        )

    except Exception:
        return False


def extract_urls(text: str) -> list[str]:
    """
    Extract HTTP/HTTPS URLs from text.

    Duplicate URLs are removed while preserving order.
    """

    if not text:
        return []

    urls = []

    for match in URL_PATTERN.findall(text):

        normalized = normalize_url(match)

        if normalized and normalized not in urls:
            urls.append(normalized)

    return urls


# ---------------------------------------------------------------------------
# URL Parsing
# ---------------------------------------------------------------------------


def parse_url(url: str) -> dict[str, Any]:
    """
    Parse a URL into structured components.
    """

    result = {
        "url": url,
        "valid": False,
        "scheme": None,
        "hostname": None,
        "port": None,
        "username": None,
        "password_present": False,
        "path": None,
        "query": None,
        "fragment": None,
        "query_parameters": {},
    }

    normalized = normalize_url(url)

    if not normalized:
        return result

    try:
        parsed = urlparse(normalized)

        result.update(
            {
                "url": normalized,
                "valid": True,
                "scheme": parsed.scheme.lower(),
                "hostname": (
                    parsed.hostname.lower()
                    if parsed.hostname
                    else None
                ),
                "port": parsed.port,
                "username": parsed.username,
                "password_present": (
                    parsed.password is not None
                ),
                "path": parsed.path or "/",
                "query": parsed.query or None,
                "fragment": parsed.fragment or None,
                "query_parameters": dict(
                    parse_qsl(
                        parsed.query,
                        keep_blank_values=True,
                    )
                ),
            }
        )

    except ValueError:
        result["valid"] = False

    return result


# ---------------------------------------------------------------------------
# IP Detection
# ---------------------------------------------------------------------------


def hostname_is_ip(hostname: str | None) -> bool:
    """
    Determine whether a hostname is an IPv4/IPv6 address.
    """

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def classify_host(hostname: str | None) -> str:
    """
    Classify URL hostname.
    """

    if not hostname:
        return "unknown"

    if hostname_is_ip(hostname):

        try:
            ip = ipaddress.ip_address(hostname)

            if ip.is_private:
                return "private_ip"

            if ip.is_loopback:
                return "loopback"

            if ip.is_reserved:
                return "reserved_ip"

            if ip.is_global:
                return "public_ip"

        except ValueError:
            pass

        return "ip"

    return "domain"


# ---------------------------------------------------------------------------
# Encoding / Obfuscation
# ---------------------------------------------------------------------------


def count_percent_encoded(url: str) -> int:
    """
    Count percent-encoded sequences.

    Example:
        %2F
        %3A
        %40
    """

    return len(
        re.findall(
            r"%[0-9A-Fa-f]{2}",
            url,
        )
    )


def count_hex_sequences(url: str) -> int:
    """
    Count hexadecimal escape-like sequences.
    """

    return len(
        re.findall(
            r"(?:0x[0-9A-Fa-f]{2,}|\\x[0-9A-Fa-f]{2})",
            url,
        )
    )


def contains_base64_like_value(value: str) -> bool:
    """
    Detect strings that strongly resemble Base64.

    This is heuristic only.
    """

    if not value:
        return False

    compact = re.sub(
        r"\s+",
        "",
        value,
    )

    if len(compact) < 16:
        return False

    if not re.fullmatch(
        r"[A-Za-z0-9+/=_-]+",
        compact,
    ):
        return False

    try:
        padded = compact

        missing_padding = len(
            padded
        ) % 4

        if missing_padding:
            padded += "=" * (
                4 - missing_padding
            )

        base64.urlsafe_b64decode(
            padded
        )

        return True

    except Exception:
        return False


def analyze_encoding(
    url: str,
) -> dict[str, Any]:
    """
    Analyze URL encoding and obfuscation indicators.
    """

    decoded_once = unquote(url)

    percent_encoded = count_percent_encoded(
        url
    )

    hex_sequences = count_hex_sequences(
        url
    )

    double_encoding = (
        "%" in decoded_once
        and decoded_once != url
        and "%" in unquote(decoded_once)
    )

    changed_after_decode = (
        decoded_once != url
    )

    return {
        "percent_encoded_count":
            percent_encoded,
        "hex_sequence_count":
            hex_sequences,
        "changed_after_decode":
            changed_after_decode,
        "double_encoding":
            double_encoding,
        "decoded_url":
            decoded_once
            if changed_after_decode
            else None,
        "base64_like_query_values": [],
    }


# ---------------------------------------------------------------------------
# Hostname Analysis
# ---------------------------------------------------------------------------


def analyze_hostname(
    hostname: str | None,
) -> dict[str, Any]:
    """
    Analyze hostname structure.
    """

    result = {
        "hostname": hostname,
        "valid": False,
        "host_type": "unknown",
        "label_count": 0,
        "labels": [],
        "subdomain_depth": 0,
        "suspicious_keywords": [],
        "suspicious_tld": False,
        "tld": None,
    }

    if not hostname:
        return result

    hostname = hostname.lower().rstrip(".")

    result["host_type"] = classify_host(
        hostname
    )

    if hostname_is_ip(hostname):

        result["valid"] = True

        return result

    labels = hostname.split(".")

    if len(labels) < 2:
        return result

    result["valid"] = True
    result["labels"] = labels
    result["label_count"] = len(labels)

    result["subdomain_depth"] = max(
        0,
        len(labels) - 2,
    )

    tld = "." + labels[-1]

    result["tld"] = tld

    result["suspicious_tld"] = (
        tld in SUSPICIOUS_TLDS
    )

    hostname_lower = hostname.lower()

    result["suspicious_keywords"] = [
        keyword
        for keyword in SUSPICIOUS_HOST_KEYWORDS
        if keyword in hostname_lower
    ]

    return result


# ---------------------------------------------------------------------------
# Path Analysis
# ---------------------------------------------------------------------------


def analyze_path(
    path: str | None,
) -> dict[str, Any]:
    """
    Analyze URL path.
    """

    path = path or "/"

    lower_path = unquote(
        path
    ).lower()

    keywords = [
        keyword
        for keyword in SUSPICIOUS_PATH_KEYWORDS
        if keyword in lower_path
    ]

    return {
        "path": path,
        "decoded_path": (
            unquote(path)
            if unquote(path) != path
            else None
        ),
        "length": len(path),
        "segment_count": len(
            [
                segment
                for segment in path.split("/")
                if segment
            ]
        ),
        "suspicious_keywords": keywords,
    }


# ---------------------------------------------------------------------------
# Query Analysis
# ---------------------------------------------------------------------------


def analyze_query(
    query: str | None,
) -> dict[str, Any]:
    """
    Analyze URL query parameters.
    """

    query = query or ""

    parameters = dict(
        parse_qsl(
            query,
            keep_blank_values=True,
        )
    )

    suspicious_keys = []

    base64_values = []

    for key, value in parameters.items():

        if key.lower() in SUSPICIOUS_QUERY_KEYS:
            suspicious_keys.append(
                key.lower()
            )

        if contains_base64_like_value(
            value
        ):
            base64_values.append(
                key
            )

    return {
        "parameter_count": len(
            parameters
        ),
        "parameters": parameters,
        "suspicious_keys": list(
            dict.fromkeys(
                suspicious_keys
            )
        ),
        "base64_like_values": list(
            dict.fromkeys(
                base64_values
            )
        ),
    }


# ---------------------------------------------------------------------------
# Credential / Userinfo Analysis
# ---------------------------------------------------------------------------


def analyze_userinfo(
    parsed: dict[str, Any],
) -> dict[str, Any]:
    """
    Detect credentials embedded in URL userinfo.

    Example:

        https://user:password@example.com

    This does not expose the password value.
    """

    username = parsed.get(
        "username"
    )

    password_present = bool(
        parsed.get(
            "password_present"
        )
    )

    return {
        "username_present": (
            username is not None
        ),
        "password_present": password_present,
    }


# ---------------------------------------------------------------------------
# Shortener Detection
# ---------------------------------------------------------------------------


def is_url_shortener(
    hostname: str | None,
) -> bool:
    """
    Detect known URL-shortener domains.
    """

    if not hostname:
        return False

    hostname = hostname.lower().rstrip(".")

    return hostname in SHORTENER_DOMAINS


# ---------------------------------------------------------------------------
# Redirect / Destination Indicators
# ---------------------------------------------------------------------------


def detect_redirect_parameters(
    query_analysis: dict[str, Any],
) -> list[str]:
    """
    Identify parameters commonly used to carry redirect destinations.
    """

    redirect_keys = {
        "redirect",
        "url",
        "return",
        "next",
        "continue",
        "dest",
        "destination",
        "target",
    }

    parameters = query_analysis.get(
        "parameters",
        {}
    )

    return [
        key
        for key in parameters
        if key.lower() in redirect_keys
    ]


# ---------------------------------------------------------------------------
# URL Signals
# ---------------------------------------------------------------------------


def build_url_signals(
    analysis: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Generate explainable risk signals from URL analysis.
    """

    signals: list[dict[str, Any]] = []

    url = analysis.get(
        "url"
    )

    if not url:
        return signals

    parsed = analysis.get(
        "parsed",
        {}
    )

    hostname = parsed.get(
        "hostname"
    )

    scheme = parsed.get(
        "scheme"
    )

    port = parsed.get(
        "port"
    )

    host_analysis = analysis.get(
        "hostname_analysis",
        {}
    )

    path_analysis = analysis.get(
        "path_analysis",
        {}
    )

    query_analysis = analysis.get(
        "query_analysis",
        {}
    )

    encoding_analysis = analysis.get(
        "encoding_analysis",
        {}
    )

    userinfo_analysis = analysis.get(
        "userinfo_analysis",
        {}
    )

    # -----------------------------------------------------------------------
    # IP-based URL
    # -----------------------------------------------------------------------

    if host_analysis.get(
        "host_type"
    ) == "public_ip":

        signals.append(
            {
                "type": "ip_based_url",
                "severity": "medium",
                "description": (
                    f"URL uses public IP address "
                    f"{hostname} instead of a domain name."
                ),
                "evidence": {
                    "url": url,
                    "hostname": hostname,
                },
            }
        )

    # -----------------------------------------------------------------------
    # Private IP
    # -----------------------------------------------------------------------

    if host_analysis.get(
        "host_type"
    ) == "private_ip":

        signals.append(
            {
                "type": "private_ip_url",
                "severity": "low",
                "description": (
                    "URL points to a private/internal IP address."
                ),
                "evidence": {
                    "url": url,
                    "hostname": hostname,
                },
            }
        )

    # -----------------------------------------------------------------------
    # HTTP
    # -----------------------------------------------------------------------

    if scheme == "http":

        signals.append(
            {
                "type": "unencrypted_http",
                "severity": "low",
                "description": (
                    "URL uses HTTP instead of HTTPS."
                ),
                "evidence": {
                    "url": url,
                },
            }
        )

    # -----------------------------------------------------------------------
    # Suspicious port
    # -----------------------------------------------------------------------

    if port in SUSPICIOUS_PORTS:

        signals.append(
            {
                "type": "suspicious_url_port",
                "severity": "medium",
                "description": (
                    f"URL uses non-standard or "
                    f"commonly abused port {port}."
                ),
                "evidence": {
                    "url": url,
                    "port": port,
                },
            }
        )

    # -----------------------------------------------------------------------
    # URL credentials
    # -----------------------------------------------------------------------

    if userinfo_analysis.get(
        "password_present"
    ):

        signals.append(
            {
                "type": "url_embedded_credentials",
                "severity": "high",
                "description": (
                    "URL contains embedded userinfo/password "
                    "syntax."
                ),
                "evidence": {
                    "url": url,
                    "username_present":
                        userinfo_analysis.get(
                            "username_present"
                        ),
                    "password_present": True,
                },
            }
        )

    # -----------------------------------------------------------------------
    # URL shortener
    # -----------------------------------------------------------------------

    if is_url_shortener(hostname):

        signals.append(
            {
                "type": "url_shortener",
                "severity": "medium",
                "description": (
                    f"URL uses known URL-shortener "
                    f"infrastructure: {hostname}."
                ),
                "evidence": {
                    "url": url,
                    "hostname": hostname,
                },
            }
        )

    # -----------------------------------------------------------------------
    # Suspicious TLD
    # -----------------------------------------------------------------------

    if host_analysis.get(
        "suspicious_tld"
    ):

        signals.append(
            {
                "type": "suspicious_tld",
                "severity": "low",
                "description": (
                    f"Hostname uses TLD "
                    f"{host_analysis.get('tld')} "
                    "that is included in the configured "
                    "suspicious-TLD heuristic list."
                ),
                "evidence": {
                    "url": url,
                    "hostname": hostname,
                    "tld": host_analysis.get(
                        "tld"
                    ),
                },
            }
        )

    # -----------------------------------------------------------------------
    # Suspicious hostname keywords
    # -----------------------------------------------------------------------

    hostname_keywords = host_analysis.get(
        "suspicious_keywords",
        []
    )

    if hostname_keywords:

        signals.append(
            {
                "type": "suspicious_hostname_keywords",
                "severity": "low",
                "description": (
                    "Hostname contains keywords commonly "
                    "associated with authentication, payment, "
                    "or impersonation workflows."
                ),
                "evidence": {
                    "url": url,
                    "hostname": hostname,
                    "keywords": hostname_keywords,
                },
            }
        )

    # -----------------------------------------------------------------------
    # Deep subdomain
    # -----------------------------------------------------------------------

    if host_analysis.get(
        "subdomain_depth",
        0,
    ) >= 4:

        signals.append(
            {
                "type": "deep_subdomain",
                "severity": "low",
                "description": (
                    "URL hostname contains a deep "
                    "subdomain hierarchy."
                ),
                "evidence": {
                    "url": url,
                    "hostname": hostname,
                    "subdomain_depth":
                        host_analysis.get(
                            "subdomain_depth"
                        ),
                },
            }
        )

    # -----------------------------------------------------------------------
    # Suspicious path keywords
    # -----------------------------------------------------------------------

    path_keywords = path_analysis.get(
        "suspicious_keywords",
        []
    )

    if path_keywords:

        signals.append(
            {
                "type": "credential_or_action_path",
                "severity": "medium",
                "description": (
                    "URL path contains terms commonly "
                    "associated with login, verification, "
                    "payment, or credential workflows."
                ),
                "evidence": {
                    "url": url,
                    "path": path_analysis.get(
                        "path"
                    ),
                    "keywords": path_keywords,
                },
            }
        )

    # -----------------------------------------------------------------------
    # Suspicious query parameters
    # -----------------------------------------------------------------------

    suspicious_keys = query_analysis.get(
        "suspicious_keys",
        []
    )

    if suspicious_keys:

        signals.append(
            {
                "type": "suspicious_query_parameters",
                "severity": "low",
                "description": (
                    "URL contains parameters commonly "
                    "associated with authentication, sessions, "
                    "or redirects."
                ),
                "evidence": {
                    "url": url,
                    "keys": suspicious_keys,
                },
            }
        )

    # -----------------------------------------------------------------------
    # Redirect parameters
    # -----------------------------------------------------------------------

    redirect_keys = detect_redirect_parameters(
        query_analysis
    )

    if redirect_keys:

        signals.append(
            {
                "type": "redirect_parameter",
                "severity": "medium",
                "description": (
                    "URL contains parameters that may "
                    "control a redirect destination."
                ),
                "evidence": {
                    "url": url,
                    "parameters": redirect_keys,
                },
            }
        )

    # -----------------------------------------------------------------------
    # Encoding
    # -----------------------------------------------------------------------

    encoded_count = encoding_analysis.get(
        "percent_encoded_count",
        0,
    )

    if encoded_count >= 5:

        signals.append(
            {
                "type": "heavily_encoded_url",
                "severity": "medium",
                "description": (
                    "URL contains a high number of "
                    "percent-encoded characters."
                ),
                "evidence": {
                    "url": url,
                    "encoded_count": encoded_count,
                },
            }
        )

    if encoding_analysis.get(
        "double_encoding"
    ):

        signals.append(
            {
                "type": "double_encoded_url",
                "severity": "high",
                "description": (
                    "URL contains indicators of multiple "
                    "encoding layers."
                ),
                "evidence": {
                    "url": url,
                },
            }
        )

    # -----------------------------------------------------------------------
    # Base64-like query value
    # -----------------------------------------------------------------------

    base64_values = query_analysis.get(
        "base64_like_values",
        []
    )

    if base64_values:

        signals.append(
            {
                "type": "encoded_query_value",
                "severity": "medium",
                "description": (
                    "URL contains a query parameter value "
                    "that resembles encoded data."
                ),
                "evidence": {
                    "url": url,
                    "parameters": base64_values,
                },
            }
        )

    return signals


# ---------------------------------------------------------------------------
# Complete URL Analysis
# ---------------------------------------------------------------------------


def analyze_url(
    url: str,
) -> dict[str, Any]:
    """
    Perform complete structural analysis of one URL.
    """

    result: dict[str, Any] = {
        "url": url,
        "valid": False,
        "parsed": {},
        "hostname_analysis": {},
        "path_analysis": {},
        "query_analysis": {},
        "encoding_analysis": {},
        "userinfo_analysis": {},
        "signals": [],
    }

    normalized = normalize_url(url)

    if not normalized:

        result["signals"].append(
            {
                "type": "invalid_url",
                "severity": "low",
                "description": (
                    "URL could not be normalized as "
                    "a valid HTTP/HTTPS URL."
                ),
                "evidence": {
                    "url": url,
                },
            }
        )

        return result

    parsed = parse_url(
        normalized
    )

    if not parsed.get(
        "valid"
    ):

        result["signals"].append(
            {
                "type": "invalid_url",
                "severity": "low",
                "description": (
                    "URL parsing failed."
                ),
                "evidence": {
                    "url": normalized,
                },
            }
        )

        return result

    result["valid"] = True
    result["url"] = normalized
    result["parsed"] = parsed

    result["hostname_analysis"] = analyze_hostname(
        parsed.get("hostname")
    )

    result["path_analysis"] = analyze_path(
        parsed.get("path")
    )

    result["query_analysis"] = analyze_query(
        parsed.get("query")
    )

    result["encoding_analysis"] = analyze_encoding(
        normalized
    )

    result["userinfo_analysis"] = analyze_userinfo(
        parsed
    )

    result["signals"] = build_url_signals(
        result
    )

    return result


# ---------------------------------------------------------------------------
# Bulk URL Analysis
# ---------------------------------------------------------------------------


def analyze_urls(
    urls: list[str],
) -> list[dict[str, Any]]:
    """
    Analyze multiple unique URLs.
    """

    results: list[dict[str, Any]] = []

    seen: set[str] = set()

    for url in urls:

        normalized = normalize_url(url)

        if not normalized:

            results.append(
                analyze_url(url)
            )

            continue

        if normalized in seen:
            continue

        seen.add(normalized)

        results.append(
            analyze_url(normalized)
        )

    return results


# ---------------------------------------------------------------------------
# Extract Risk Signals
# ---------------------------------------------------------------------------


def build_url_risk_signals(
    analysis: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Convert URL analysis findings into normalized risk signals.
    """

    signals = analysis.get(
        "signals",
        []
    )

    if not isinstance(
        signals,
        list,
    ):
        return []

    return [
        {
            "type": signal.get(
                "type",
                "unknown_url_signal",
            ),
            "severity": signal.get(
                "severity",
                "informational",
            ),
            "description": signal.get(
                "description",
                "URL analysis signal detected.",
            ),
            "evidence": signal.get(
                "evidence",
                {},
            ),
        }
        for signal in signals
        if isinstance(
            signal,
            dict,
        )
    ]


# ---------------------------------------------------------------------------
# Service Status
# ---------------------------------------------------------------------------


def get_url_analyzer_status() -> dict[str, Any]:
    """
    Return URL analyzer capabilities.
    """

    return {
        "service": "url_analyzer",
        "status": "ready",
        "capabilities": {
            "url_normalization": True,
            "url_parsing": True,
            "hostname_analysis": True,
            "ip_url_detection": True,
            "port_analysis": True,
            "encoding_analysis": True,
            "path_analysis": True,
            "query_analysis": True,
            "credential_detection": True,
            "url_shortener_detection": True,
            "redirect_parameter_detection": True,
            "reputation_lookup": False,
            "redirect_execution": False,
            "sandbox_execution": False,
        },
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


__all__ = [
    "URLAnalyzerError",
    "normalize_url",
    "is_valid_url",
    "extract_urls",
    "parse_url",
    "hostname_is_ip",
    "classify_host",
    "analyze_encoding",
    "analyze_hostname",
    "analyze_path",
    "analyze_query",
    "analyze_userinfo",
    "is_url_shortener",
    "detect_redirect_parameters",
    "build_url_signals",
    "analyze_url",
    "analyze_urls",
    "build_url_risk_signals",
    "get_url_analyzer_status",
]