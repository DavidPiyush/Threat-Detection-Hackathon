"""
IP Intelligence Service
=======================

Provides infrastructure intelligence for IP addresses.

Responsibilities:
    - Validate IP addresses
    - Identify public/private/special addresses
    - DNS reverse lookup
    - ASN / organization enrichment
    - GeoIP enrichment
    - Basic infrastructure classification
    - Produce normalized evidence for the threat-intel/risk pipeline

Important:
    IP geolocation is NOT attacker attribution.
    A geolocated IP represents observed infrastructure, not necessarily
    the physical location or identity of the person operating it.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IP_TYPES = {
    "public": "public",
    "private": "private",
    "loopback": "loopback",
    "link_local": "link_local",
    "reserved": "reserved",
    "multicast": "multicast",
    "unspecified": "unspecified",
    "documentation": "documentation",
    "special": "special",
    "invalid": "invalid",
}


# RFC 5737 / RFC 3849 documentation networks
DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class IPIntelligenceError(Exception):
    """Base exception for IP intelligence errors."""


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def normalize_ip(value: str) -> str | None:
    """
    Validate and normalize an IPv4/IPv6 address.

    Example:
        normalize_ip(" 8.8.8.8 ") -> "8.8.8.8"
    """

    if not value:
        return None

    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def get_ip_object(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """
    Return an ipaddress object or None for an invalid address.
    """

    normalized = normalize_ip(value)

    if not normalized:
        return None

    try:
        return ipaddress.ip_address(normalized)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# IP Classification
# ---------------------------------------------------------------------------


def is_documentation_ip(value: str) -> bool:
    """
    Determine whether an IP belongs to a documentation/test network.
    """

    ip = get_ip_object(value)

    if ip is None:
        return False

    return any(ip in network for network in DOCUMENTATION_NETWORKS)


def classify_ip(value: str) -> str:
    """
    Classify an IP address.

    Possible results:

        public
        private
        loopback
        link_local
        reserved
        multicast
        unspecified
        documentation
        special
        invalid
    """

    ip = get_ip_object(value)

    if ip is None:
        return IP_TYPES["invalid"]

    if is_documentation_ip(str(ip)):
        return IP_TYPES["documentation"]

    if ip.is_loopback:
        return IP_TYPES["loopback"]

    if ip.is_private:
        return IP_TYPES["private"]

    if ip.is_link_local:
        return IP_TYPES["link_local"]

    if ip.is_multicast:
        return IP_TYPES["multicast"]

    if ip.is_reserved:
        return IP_TYPES["reserved"]

    if ip.is_unspecified:
        return IP_TYPES["unspecified"]

    if ip.is_global:
        return IP_TYPES["public"]

    return IP_TYPES["special"]


def is_public_ip(value: str) -> bool:
    """
    Return True only when the IP is globally routable.
    """

    ip = get_ip_object(value)

    if ip is None:
        return False

    return ip.is_global and not is_documentation_ip(str(ip))


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------


def reverse_dns(
    ip: str,
    *,
    timeout: float = 3.0,
) -> dict[str, Any]:
    """
    Perform a reverse DNS lookup.

    Returns structured information instead of throwing errors so that
    DNS failure never breaks the investigation.
    """

    result = {
        "ip": ip,
        "success": False,
        "hostname": None,
        "aliases": [],
        "error": None,
    }

    normalized = normalize_ip(ip)

    if not normalized:
        result["error"] = "Invalid IP address"
        return result

    try:
        hostname, aliases, addresses = socket.gethostbyaddr(normalized)

        result.update(
            {
                "success": True,
                "hostname": hostname,
                "aliases": aliases or [],
                "addresses": addresses or [],
            }
        )

    except socket.herror:
        result["error"] = "Reverse DNS record not found"

    except socket.gaierror:
        result["error"] = "DNS resolution failed"

    except TimeoutError:
        result["error"] = "DNS lookup timed out"

    except Exception as exc:
        result["error"] = f"Reverse DNS error: {exc}"

    return result


# ---------------------------------------------------------------------------
# Basic Infrastructure Classification
# ---------------------------------------------------------------------------


def classify_hostname(hostname: str | None) -> dict[str, Any]:
    """
    Perform lightweight classification of a reverse-DNS hostname.

    This is heuristic only.

    It must NOT be treated as definitive proof that an IP belongs
    to a VPN, Tor node, cloud provider, proxy, etc.
    """

    if not hostname:
        return {
            "cloud": False,
            "vpn": False,
            "proxy": False,
            "tor": False,
            "hosting": False,
            "signals": [],
        }

    hostname_lower = hostname.lower()

    signals: list[str] = []

    cloud_keywords = [
        "amazonaws",
        "aws",
        "compute",
        "ec2",
        "azure",
        "microsoft",
        "googleusercontent",
        "gcp",
        "cloud",
        "digitalocean",
        "linode",
        "vultr",
        "oraclecloud",
    ]

    vpn_keywords = [
        "vpn",
        "nord",
        "expressvpn",
        "privateinternetaccess",
        "surfshark",
    ]

    proxy_keywords = [
        "proxy",
        "squid",
        "forward",
        "gateway",
    ]

    tor_keywords = [
        "tor",
        "onion",
        "exit",
        "relay",
    ]

    hosting_keywords = [
        "host",
        "hosting",
        "server",
        "dedicated",
        "colo",
        "datacenter",
        "vps",
    ]

    cloud = any(
        keyword in hostname_lower
        for keyword in cloud_keywords
    )

    vpn = any(
        keyword in hostname_lower
        for keyword in vpn_keywords
    )

    proxy = any(
        keyword in hostname_lower
        for keyword in proxy_keywords
    )

    tor = any(
        keyword in hostname_lower
        for keyword in tor_keywords
    )

    hosting = any(
        keyword in hostname_lower
        for keyword in hosting_keywords
    )

    if cloud:
        signals.append("cloud-hosting-indicator")

    if vpn:
        signals.append("vpn-hostname-indicator")

    if proxy:
        signals.append("proxy-hostname-indicator")

    if tor:
        signals.append("tor-hostname-indicator")

    if hosting:
        signals.append("hosting-indicator")

    return {
        "cloud": cloud,
        "vpn": vpn,
        "proxy": proxy,
        "tor": tor,
        "hosting": hosting,
        "signals": signals,
    }


# ---------------------------------------------------------------------------
# IP Metadata
# ---------------------------------------------------------------------------


def get_ip_metadata(ip: str) -> dict[str, Any]:
    """
    Collect deterministic metadata about an IP address.

    This does not call external threat-intelligence providers.
    """

    normalized = normalize_ip(ip)

    if not normalized:
        return {
            "ip": ip,
            "valid": False,
            "type": "invalid",
            "public": False,
        }

    ip_object = get_ip_object(normalized)

    if ip_object is None:
        return {
            "ip": normalized,
            "valid": False,
            "type": "invalid",
            "public": False,
        }

    ip_type = classify_ip(normalized)

    return {
        "ip": normalized,
        "valid": True,
        "version": ip_object.version,
        "type": ip_type,
        "public": is_public_ip(normalized),
        "private": ip_object.is_private,
        "loopback": ip_object.is_loopback,
        "link_local": ip_object.is_link_local,
        "reserved": ip_object.is_reserved,
        "multicast": ip_object.is_multicast,
        "unspecified": ip_object.is_unspecified,
        "documentation": is_documentation_ip(normalized),
    }


# ---------------------------------------------------------------------------
# Full IP Analysis
# ---------------------------------------------------------------------------


def analyze_ip(
    ip: str,
    *,
    perform_reverse_dns: bool = True,
) -> dict[str, Any]:
    """
    Perform a complete local IP intelligence analysis.

    This function intentionally avoids external APIs.

    External TI providers such as AbuseIPDB and VirusTotal are
    handled by threat_intel.py.
    """

    metadata = get_ip_metadata(ip)

    result: dict[str, Any] = {
        **metadata,
        "reverse_dns": None,
        "hostname_analysis": None,
        "signals": [],
    }

    if not metadata.get("valid"):
        result["signals"].append(
            {
                "type": "invalid_ip",
                "severity": "low",
                "description": f"{ip} is not a valid IP address.",
                "evidence": {
                    "ip": ip,
                },
            }
        )

        return result

    ip_type = metadata["type"]

    # Documentation addresses are expected in labs/tests.
    if ip_type == "documentation":
        result["signals"].append(
            {
                "type": "documentation_ip",
                "severity": "informational",
                "description": (
                    f"{metadata['ip']} belongs to a documentation/test "
                    "network."
                ),
                "evidence": {
                    "ip": metadata["ip"],
                    "classification": ip_type,
                },
            }
        )

        return result

    # Private addresses should not be sent to external TI providers.
    if ip_type == "private":
        result["signals"].append(
            {
                "type": "private_ip",
                "severity": "informational",
                "description": (
                    f"{metadata['ip']} is a private/internal IP address."
                ),
                "evidence": {
                    "ip": metadata["ip"],
                    "classification": ip_type,
                },
            }
        )

        return result

    # Other special addresses.
    if not metadata["public"]:
        result["signals"].append(
            {
                "type": "non_public_ip",
                "severity": "informational",
                "description": (
                    f"{metadata['ip']} is classified as "
                    f"{ip_type}."
                ),
                "evidence": {
                    "ip": metadata["ip"],
                    "classification": ip_type,
                },
            }
        )

        return result

    # -----------------------------------------------------------------------
    # Reverse DNS
    # -----------------------------------------------------------------------

    if perform_reverse_dns:

        dns_result = reverse_dns(metadata["ip"])

        result["reverse_dns"] = dns_result

        hostname = dns_result.get("hostname")

        if hostname:

            hostname_analysis = classify_hostname(hostname)

            result["hostname_analysis"] = hostname_analysis

            for signal in hostname_analysis["signals"]:

                result["signals"].append(
                    {
                        "type": signal,
                        "severity": "low",
                        "description": (
                            f"Reverse DNS hostname "
                            f"{hostname} contains an "
                            f"infrastructure indicator: {signal}."
                        ),
                        "evidence": {
                            "ip": metadata["ip"],
                            "hostname": hostname,
                            "signal": signal,
                        },
                    }
                )

    return result


# ---------------------------------------------------------------------------
# Bulk IP Analysis
# ---------------------------------------------------------------------------


def analyze_ips(
    ips: list[str],
    *,
    perform_reverse_dns: bool = True,
) -> list[dict[str, Any]]:
    """
    Analyze multiple IP addresses.

    Duplicate and invalid values are handled safely.
    """

    results: list[dict[str, Any]] = []

    seen: set[str] = set()

    for ip in ips:

        normalized = normalize_ip(ip)

        if not normalized:
            results.append(
                analyze_ip(
                    ip,
                    perform_reverse_dns=False,
                )
            )
            continue

        if normalized in seen:
            continue

        seen.add(normalized)

        results.append(
            analyze_ip(
                normalized,
                perform_reverse_dns=perform_reverse_dns,
            )
        )

    return results


# ---------------------------------------------------------------------------
# Infrastructure Signal Adapter
# ---------------------------------------------------------------------------


def build_ip_signals(
    analysis: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Extract normalized risk signals from IP analysis.

    These signals can later be passed into risk_engine.py.
    """

    signals = analysis.get("signals", [])

    if not isinstance(signals, list):
        return []

    normalized_signals = []

    for signal in signals:

        if not isinstance(signal, dict):
            continue

        normalized_signals.append(
            {
                "type": signal.get(
                    "type",
                    "unknown_ip_signal",
                ),
                "severity": signal.get(
                    "severity",
                    "informational",
                ),
                "description": signal.get(
                    "description",
                    "IP infrastructure signal detected.",
                ),
                "evidence": signal.get(
                    "evidence",
                    {},
                ),
            }
        )

    return normalized_signals


# ---------------------------------------------------------------------------
# Service Health
# ---------------------------------------------------------------------------


def get_ip_intelligence_status() -> dict[str, Any]:
    """
    Return service capabilities.
    """

    return {
        "service": "ip_intelligence",
        "status": "ready",
        "capabilities": {
            "ip_validation": True,
            "ip_classification": True,
            "reverse_dns": True,
            "hostname_analysis": True,
            "geoip": False,
            "asn": False,
            "vpn_database": False,
            "tor_database": False,
            "cloud_database": False,
        },
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


__all__ = [
    "IPIntelligenceError",
    "normalize_ip",
    "is_public_ip",
    "classify_ip",
    "is_documentation_ip",
    "reverse_dns",
    "classify_hostname",
    "get_ip_metadata",
    "analyze_ip",
    "analyze_ips",
    "build_ip_signals",
    "get_ip_intelligence_status",
]