from __future__ import annotations

from typing import Any


# ============================================================
# CONSTANTS
# ============================================================

MIN_SCORE = 0
MAX_SCORE = 100


SEVERITY_THRESHOLDS = {
    "critical": 80,
    "high": 60,
    "medium": 30,
    "low": 10,
    "informational": 0,
}


SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 5,
    "informational": 0,
    "info": 0,
}


AUTH_WEIGHTS = {
    "spf": {
        "pass": 0,
        "neutral": 2,
        "none": 3,
        "softfail": 8,
        "temperror": 3,
        "permerror": 5,
        "fail": 20,
        "unknown": 0,
    },
    "dkim": {
        "pass": 0,
        "neutral": 2,
        "none": 3,
        "temperror": 3,
        "permerror": 5,
        "policy": 5,
        "fail": 20,
        "unknown": 0,
    },
    "dmarc": {
        "pass": 0,
        "bestguesspass": 0,
        "none": 3,
        "temperror": 3,
        "permerror": 5,
        "policy": 5,
        "fail": 25,
        "unknown": 0,
    },
}


# ============================================================
# GENERIC HELPERS
# ============================================================

def clamp_score(score: int | float) -> int:
    """
    Keep score within 0-100.
    """
    return max(
        MIN_SCORE,
        min(MAX_SCORE, int(round(score))),
    )

def _severity_rank(severity: str) -> int:
    """
    Convert severity into a numeric ranking.

    Higher number = more severe.
    """

    ranks = {
        "informational": 0,
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    return ranks.get(
        str(severity).strip().lower(),
        0,
    )

def normalize_verdict(
    verdict: Any,
) -> str:
    """
    Normalize SPF/DKIM/DMARC verdicts.
    """

    if verdict is None:
        return "unknown"

    value = str(verdict).strip().lower()

    value = value.replace(
        "_",
        "",
    ).replace(
        "-",
        "",
    ).replace(
        " ",
        "",
    )

    return value or "unknown"


def normalize_severity(
    severity: Any,
) -> str:
    """
    Normalize severity values to one of the
    supported risk-engine levels.
    """

    if severity is None:
        return "informational"

    value = str(severity).strip().lower()
    value = value.replace(
        "_",
        "",
    ).replace(
        "-",
        "",
    ).replace(
        " ",
        "",
    )

    aliases = {
        "info": "informational",
        "informational": "informational",
        "low": "low",
        "medium": "medium",
        "moderate": "medium",
        "med": "medium",
        "high": "high",
        "critical": "critical",
        "urgent": "critical",
        "sev1": "critical",
        "sev2": "high",
        "sev3": "medium",
        "sev4": "low",
    }

    return aliases.get(value, "informational")


def make_signal(
    signal_type: str,
    description: str,
    points: int,
    severity: str = "informational",
    evidence: dict[str, Any] | None = None,
    source: str = "risk_engine",
) -> dict[str, Any]:
    """
    Create a normalized risk signal.
    """

    return {
        "type": signal_type,
        "description": description,
        "points": int(points),
        "severity": normalize_severity(severity),
        "source": source,
        "evidence": evidence or {},
    }


def _safe_list(value: Any) -> list:
    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def _safe_dict(value: Any) -> dict:
    if isinstance(value, dict):
        return value

    return {}


# ============================================================
# FINDING SCORING
# ============================================================

def score_findings(
    findings: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """
    Convert existing security findings into risk signals.

    NOTE:
    Do not pass category findings here if the same findings
    are separately supplied to score_identity(),
    score_authentication(), score_url_analysis(), etc.
    Otherwise evidence may be double-counted.
    """

    signals = []

    for finding in _safe_list(findings):

        if not isinstance(finding, dict):
            continue

        severity = normalize_severity(
            finding.get("severity")
        )

        points = SEVERITY_WEIGHTS.get(
            severity,
            0,
        )

        if points <= 0:
            continue

        signal_type = str(
            finding.get(
                "type",
                "security_finding",
            )
        )

        description = str(
            finding.get(
                "description",
                "Security finding detected.",
            )
        )

        evidence = _safe_dict(
            finding.get("evidence")
        )

        signals.append(
            make_signal(
                signal_type=signal_type,
                description=description,
                points=points,
                severity=severity,
                evidence=evidence,
                source="finding",
            )
        )

    return signals


# ============================================================
# AUTHENTICATION SCORING
# ============================================================

def score_authentication(
    authentication: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """
    Score SPF, DKIM and DMARC results.
    """

    authentication = _safe_dict(
        authentication
    )

    signals = []

    for method in (
        "spf",
        "dkim",
        "dmarc",
    ):

        verdict = normalize_verdict(
            authentication.get(method)
        )

        weight_table = AUTH_WEIGHTS[
            method
        ]

        points = weight_table.get(
            verdict,
            weight_table["unknown"],
        )

        if verdict == "pass":
            continue

        if points <= 0:
            continue

        severity = "low"

        if points >= 20:
            severity = "high"
        elif points >= 8:
            severity = "medium"

        signals.append(
            make_signal(
                signal_type=f"{method}_failure",
                description=(
                    f"{method.upper()} authentication "
                    f"result is '{verdict}'."
                ),
                points=points,
                severity=severity,
                evidence={
                    "method": method,
                    "verdict": verdict,
                },
                source="authentication",
            )
        )

    return signals


# ============================================================
# IDENTITY SCORING
# ============================================================

def score_identity(
    identity: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """
    Score sender identity anomalies.

    Reply-To mismatch is suspicious.

    Return-Path differences alone are informational because
    legitimate mailing/bounce infrastructure frequently uses
    different return-path domains.
    """

    identity = _safe_dict(identity)

    signals = []

    sender_domain = identity.get(
        "sender_domain"
    )

    reply_to_domain = identity.get(
        "reply_to_domain"
    )

    return_path_domain = identity.get(
        "return_path_domain"
    )

    # --------------------------------------------------------
    # Reply-To mismatch
    # --------------------------------------------------------

    if (
        sender_domain
        and reply_to_domain
        and str(sender_domain).lower()
        != str(reply_to_domain).lower()
    ):

        signals.append(
            make_signal(
                signal_type="reply_to_mismatch",
                description=(
                    "Reply-To domain differs from the "
                    "visible sender domain."
                ),
                points=20,
                severity="high",
                evidence={
                    "sender_domain": sender_domain,
                    "reply_to_domain": reply_to_domain,
                    "reply_to": identity.get(
                        "reply_to"
                    ),
                    "sender": identity.get(
                        "sender"
                    ),
                },
                source="identity",
            )
        )

    # --------------------------------------------------------
    # Return-Path difference
    # --------------------------------------------------------

    if (
        sender_domain
        and return_path_domain
        and str(sender_domain).lower()
        != str(return_path_domain).lower()
    ):

        signals.append(
            make_signal(
                signal_type="return_path_difference",
                description=(
                    "Return-Path differs from the visible "
                    "sender domain. This may be normal for "
                    "mailing or bounce infrastructure."
                ),
                points=0,
                severity="informational",
                evidence={
                    "sender_domain": sender_domain,
                    "return_path_domain": return_path_domain,
                },
                source="identity",
            )
        )

    return signals


# ============================================================
# URL SCORING
# ============================================================

def score_url_analysis(
    url_analysis: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """
    Convert URL analyzer findings into risk signals.
    """

    url_analysis = _safe_dict(
        url_analysis
    )

    signals = []

    findings = _safe_list(
        url_analysis.get("findings")
    )

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        severity = normalize_severity(
            finding.get("severity")
        )

        base_points = SEVERITY_WEIGHTS.get(
            severity,
            0,
        )

        # URL-specific weighting.
        finding_type = str(
            finding.get(
                "type",
                "url_anomaly",
            )
        ).lower()

        multiplier = 1.0

        if finding_type in {
            "embedded_credentials",
            "url_embedded_credentials",
        }:
            multiplier = 1.5

        elif finding_type in {
            "suspicious_redirect",
            "redirect_parameter",
        }:
            multiplier = 1.2

        elif finding_type in {
            "suspicious_port",
        }:
            multiplier = 1.1

        points = int(
            round(
                base_points * multiplier
            )
        )

        if points <= 0:
            continue

        signals.append(
            make_signal(
                signal_type=finding_type,
                description=str(
                    finding.get(
                        "description",
                        "Suspicious URL characteristic detected.",
                    )
                ),
                points=points,
                severity=severity,
                evidence=_safe_dict(
                    finding.get("evidence")
                ),
                source="url_analyzer",
            )
        )

    return signals


# ============================================================
# ATTACHMENT SCORING
# ============================================================

def score_attachments(
    attachments: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """
    Score attachment findings.

    The MVP does not execute attachments.
    """

    signals = []

    for attachment in _safe_list(
        attachments
    ):

        if not isinstance(attachment, dict):
            continue

        filename = str(
            attachment.get(
                "filename",
                "",
            )
        )

        content_type = str(
            attachment.get(
                "content_type",
                "",
            )
        ).lower()

        # ----------------------------------------------------
        # Dangerous executable extensions
        # ----------------------------------------------------

        dangerous_extensions = (
            ".exe",
            ".scr",
            ".bat",
            ".cmd",
            ".com",
            ".msi",
            ".dll",
            ".ps1",
            ".vbs",
            ".js",
            ".jar",
            ".hta",
        )

        if filename.lower().endswith(
            dangerous_extensions
        ):

            signals.append(
                make_signal(
                    signal_type="executable_attachment",
                    description=(
                        "Attachment uses an executable "
                        "or script-like file extension."
                    ),
                    points=25,
                    severity="high",
                    evidence={
                        "filename": filename,
                        "content_type": content_type,
                    },
                    source="attachment_analysis",
                )
            )

        # ----------------------------------------------------
        # Macro-enabled Office documents
        # ----------------------------------------------------

        macro_extensions = (
            ".docm",
            ".xlsm",
            ".pptm",
        )

        if filename.lower().endswith(
            macro_extensions
        ):

            signals.append(
                make_signal(
                    signal_type="macro_enabled_document",
                    description=(
                        "Attachment is a macro-enabled "
                        "Office document."
                    ),
                    points=20,
                    severity="high",
                    evidence={
                        "filename": filename,
                        "content_type": content_type,
                    },
                    source="attachment_analysis",
                )
            )

        # ----------------------------------------------------
        # Archive
        # ----------------------------------------------------

        archive_extensions = (
            ".zip",
            ".rar",
            ".7z",
            ".iso",
        )

        if filename.lower().endswith(
            archive_extensions
        ):

            signals.append(
                make_signal(
                    signal_type="archive_attachment",
                    description=(
                        "Email contains an archive attachment "
                        "that may require additional inspection."
                    ),
                    points=8,
                    severity="medium",
                    evidence={
                        "filename": filename,
                        "content_type": content_type,
                    },
                    source="attachment_analysis",
                )
            )

    return signals


# ============================================================
# BEC / SOCIAL ENGINEERING
# ============================================================

def score_bec(
    social_engineering: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """
    Score BEC and social-engineering indicators.
    """

    social_engineering = _safe_dict(
        social_engineering
    )

    signals = []

    findings = _safe_list(
        social_engineering.get("findings")
    )

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        finding_type = str(
            finding.get(
                "type",
                "behavioral_indicator",
            )
        )

        severity = normalize_severity(
            finding.get("severity")
        )

        base_points = SEVERITY_WEIGHTS.get(
            severity,
            0,
        )

        # ----------------------------------------------------
        # BEC pattern
        # ----------------------------------------------------

        if finding_type == "bec_pattern":

            points = 15

            signals.append(
                make_signal(
                    signal_type="bec_pattern",
                    description=(
                        "Behavioral indicators are "
                        "consistent with a potential "
                        "Business Email Compromise pattern."
                    ),
                    points=points,
                    severity="critical",
                    evidence=_safe_dict(
                        finding.get("evidence")
                    ),
                    source="behavioral_analysis",
                )
            )

            continue

        # ----------------------------------------------------
        # Other behavioral indicators
        # ----------------------------------------------------

        if base_points <= 0:
            continue

        signals.append(
            make_signal(
                signal_type=finding_type,
                description=str(
                    finding.get(
                        "description",
                        "Suspicious social-engineering behavior detected.",
                    )
                ),
                points=base_points,
                severity=severity,
                evidence=_safe_dict(
                    finding.get("evidence")
                ),
                source="behavioral_analysis",
            )
        )

    # --------------------------------------------------------
    # BEC level
    # --------------------------------------------------------

    bec_level = str(
        social_engineering.get(
            "bec_level",
            "none",
        )
    ).lower()

    if bec_level == "elevated":

        # Avoid another +15 if an explicit BEC pattern
        # already exists.
        has_bec_signal = any(
            signal["type"] == "bec_pattern"
            for signal in signals
        )

        if not has_bec_signal:
            signals.append(
                make_signal(
                    signal_type="bec_elevated",
                    description=(
                        "Multiple behavioral indicators "
                        "elevate the message to a potential "
                        "BEC scenario."
                    ),
                    points=15,
                    severity="critical",
                    evidence={
                        "bec_level": bec_level,
                    },
                    source="behavioral_analysis",
                )
            )

    elif bec_level == "possible":

        signals.append(
            make_signal(
                signal_type="bec_possible",
                description=(
                    "The message contains behavioral "
                    "indicators associated with BEC."
                ),
                points=5,
                severity="medium",
                evidence={
                    "bec_level": bec_level,
                },
                source="behavioral_analysis",
            )
        )

    return signals


# ============================================================
# INFRASTRUCTURE / THREAT INTELLIGENCE
# ============================================================

def score_infrastructure(
    infrastructure: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """
    Convert infrastructure and threat-intelligence
    information into risk signals.
    """

    infrastructure = _safe_dict(
        infrastructure
    )

    signals = []

    # --------------------------------------------------------
    # Generic threat-intelligence signals
    # --------------------------------------------------------

    for item in _safe_list(
        infrastructure.get("signals")
    ):

        if not isinstance(item, dict):
            continue

        signal_type = str(
            item.get(
                "type",
                "threat_intelligence",
            )
        )

        description = str(
            item.get(
                "description",
                "Threat-intelligence signal detected.",
            )
        )

        points = int(
            item.get(
                "points",
                0,
            )
        )

        severity = normalize_severity(
            item.get("severity")
        )

        if points <= 0:
            continue

        signals.append(
            make_signal(
                signal_type=signal_type,
                description=description,
                points=points,
                severity=severity,
                evidence=_safe_dict(
                    item.get("evidence")
                ),
                source=str(
                    item.get(
                        "source",
                        "threat_intelligence",
                    )
                ),
            )
        )

    # --------------------------------------------------------
    # Threat intelligence result objects
    # --------------------------------------------------------

    threat_intelligence = _safe_dict(
        infrastructure.get(
            "threat_intelligence"
        )
    )

    # --------------------------------------------------------
    # IP results
    # --------------------------------------------------------

    ip_results = _safe_list(
        infrastructure.get("ips")
    )

    for result in ip_results:

        if not isinstance(result, dict):
            continue

        ip = result.get("ip")

        # Some implementations may nest reputation.
        reputation = _safe_dict(
            result.get("reputation")
        )

        threat_score = result.get(
            "threat_score"
        )

        if threat_score is None:
            threat_score = reputation.get(
                "threat_score"
            )

        try:
            threat_score = float(
                threat_score
            )
        except (
            TypeError,
            ValueError,
        ):
            threat_score = None

        if (
            threat_score is not None
            and threat_score >= 80
        ):

            signals.append(
                make_signal(
                    signal_type="malicious_ip_reputation",
                    description=(
                        "IP infrastructure has a "
                        "high threat-intelligence score."
                    ),
                    points=30,
                    severity="critical",
                    evidence={
                        "ip": ip,
                        "threat_score": threat_score,
                    },
                    source="ip_threat_intelligence",
                )
            )

        elif (
            threat_score is not None
            and threat_score >= 60
        ):

            signals.append(
                make_signal(
                    signal_type="suspicious_ip_reputation",
                    description=(
                        "IP infrastructure has an "
                        "elevated threat-intelligence score."
                    ),
                    points=20,
                    severity="high",
                    evidence={
                        "ip": ip,
                        "threat_score": threat_score,
                    },
                    source="ip_threat_intelligence",
                )
            )

        # ----------------------------------------------------
        # TOR
        # ----------------------------------------------------

        is_tor = (
            result.get("is_tor")
            or result.get("tor")
            or reputation.get("is_tor")
        )

        if is_tor:

            signals.append(
                make_signal(
                    signal_type="tor_infrastructure",
                    description=(
                        "Observed infrastructure is "
                        "associated with Tor."
                    ),
                    points=15,
                    severity="medium",
                    evidence={
                        "ip": ip,
                    },
                    source="ip_intelligence",
                )
            )

        # ----------------------------------------------------
        # VPN
        # ----------------------------------------------------

        is_vpn = (
            result.get("is_vpn")
            or result.get("vpn")
            or reputation.get("is_vpn")
        )

        if is_vpn:

            signals.append(
                make_signal(
                    signal_type="vpn_infrastructure",
                    description=(
                        "Observed infrastructure is "
                        "associated with VPN infrastructure."
                    ),
                    points=5,
                    severity="low",
                    evidence={
                        "ip": ip,
                    },
                    source="ip_intelligence",
                )
            )

        # ----------------------------------------------------
        # Open relay
        # ----------------------------------------------------

        is_open_relay = (
            result.get("is_open_relay")
            or result.get("open_relay")
        )

        if is_open_relay:

            signals.append(
                make_signal(
                    signal_type="open_relay",
                    description=(
                        "Infrastructure is associated "
                        "with an open relay condition."
                    ),
                    points=20,
                    severity="high",
                    evidence={
                        "ip": ip,
                    },
                    source="ip_intelligence",
                )
            )

    # --------------------------------------------------------
    # Domain results
    # --------------------------------------------------------

    domain_results = _safe_list(
        infrastructure.get("domains")
    )

    for result in domain_results:

        if not isinstance(result, dict):
            continue

        domain = result.get(
            "domain"
        )

        domain_age_days = result.get(
            "domain_age_days"
        )

        if domain_age_days is None:
            domain_age_days = result.get(
                "age_days"
            )

        try:
            domain_age_days = float(
                domain_age_days
            )
        except (
            TypeError,
            ValueError,
        ):
            domain_age_days = None

        if (
            domain_age_days is not None
            and domain_age_days <= 7
        ):

            signals.append(
                make_signal(
                    signal_type="very_new_domain",
                    description=(
                        "Domain registration age is "
                        "seven days or less."
                    ),
                    points=15,
                    severity="high",
                    evidence={
                        "domain": domain,
                        "age_days": domain_age_days,
                    },
                    source="domain_intelligence",
                )
            )

        elif (
            domain_age_days is not None
            and domain_age_days <= 30
        ):

            signals.append(
                make_signal(
                    signal_type="new_domain",
                    description=(
                        "Domain registration age is "
                        "30 days or less."
                    ),
                    points=8,
                    severity="medium",
                    evidence={
                        "domain": domain,
                        "age_days": domain_age_days,
                    },
                    source="domain_intelligence",
                )
            )

    return signals


# ============================================================
# DEDUPLICATION
# ============================================================

def deduplicate_signals(
    signals: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Remove duplicate risk signals.

    Identity is primarily based on:
        type + evidence identifier

    If no obvious evidence identifier exists,
    type + description is used.
    """

    unique = []
    seen = set()

    for signal in signals:

        if not isinstance(signal, dict):
            continue

        signal_type = str(
            signal.get(
                "type",
                "unknown",
            )
        )

        evidence = _safe_dict(
            signal.get("evidence")
        )

        identifier = (
            evidence.get("ip")
            or evidence.get("domain")
            or evidence.get("url")
            or evidence.get("message_id")
            or evidence.get("gmail_message_id")
        )

        if identifier is None:
            identifier = signal.get(
                "description",
                "",
            )

        key = (
            signal_type,
            str(identifier),
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(signal)

    return unique


# ============================================================
# SCORE BREAKDOWN
# ============================================================

def build_score_breakdown(
    signals: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Summarize where the risk score came from.
    """

    by_source: dict[str, int] = {}
    by_severity: dict[str, int] = {}

    for signal in signals:

        points = int(
            signal.get(
                "points",
                0,
            )
        )

        source = str(
            signal.get(
                "source",
                "unknown",
            )
        )

        severity = normalize_severity(
            signal.get("severity")
        )

        by_source[source] = (
            by_source.get(
                source,
                0,
            )
            + points
        )

        by_severity[severity] = (
            by_severity.get(
                severity,
                0,
            )
            + points
        )

    return {
        "total_points_before_clamp": sum(
            int(
                signal.get(
                    "points",
                    0,
                )
            )
            for signal in signals
        ),
        "by_source": by_source,
        "by_severity": by_severity,
    }


# ============================================================
# CONFIDENCE
# ============================================================

def calculate_confidence(
    signals: list[dict[str, Any]],
) -> int:
    """
    Calculate confidence in the analysis.

    IMPORTANT:
    This is confidence in the evidence-backed assessment,
    NOT probability that the email is malicious.

    More independent evidence sources increase confidence.
    """

    if not signals:
        return 20

    sources = {
        str(
            signal.get(
                "source",
                "unknown",
            )
        )
        for signal in signals
    }

    high_quality_sources = {
        "authentication",
        "identity",
        "url_analyzer",
        "domain_intelligence",
        "ip_intelligence",
        "ip_threat_intelligence",
        "threat_intelligence",
        "behavioral_analysis",
        "attachment_analysis",
        "finding",
    }

    independent_sources = (
        sources
        & high_quality_sources
    )

    confidence = 30

    confidence += (
        len(independent_sources) * 10
    )

    high_severity_count = sum(
        1
        for signal in signals
        if normalize_severity(
            signal.get("severity")
        )
        in {
            "critical",
            "high",
        }
    )

    if high_severity_count >= 1:
        confidence += 10

    if high_severity_count >= 3:
        confidence += 10

    return max(
        0,
        min(100, confidence),
    )


# ============================================================
# CLASSIFICATION
# ============================================================

def classify_risk(
    score: int,
    signals: list[dict[str, Any]],
) -> str:
    """
    Convert numerical risk into an operational classification.
    """

    if score >= 60:
        return "phishing_or_fraud"

    has_critical = any(
        normalize_severity(
            signal.get("severity")
        ) == "critical"
        for signal in signals
    )

    has_high = any(
        normalize_severity(
            signal.get("severity")
        ) == "high"
        for signal in signals
    )

    if (
        score >= 30
        or has_critical
        or has_high
    ):
        return "suspicious"

    return "legitimate"


# ============================================================
# SEVERITY
# ============================================================

def calculate_severity(
    score: int,
    signals: list[dict[str, Any]],
) -> str:
    """
    Calculate final severity.
    """

    if score >= 80:
        return "critical"

    if score >= 60:
        return "high"

    if score >= 30:
        return "medium"

    if score >= 10:
        return "low"

    # Preserve a critical/high finding even if score
    # has been capped or other logic changes.
    if any(
        normalize_severity(
            signal.get("severity")
        ) == "critical"
        for signal in signals
    ):
        return "critical"

    if any(
        normalize_severity(
            signal.get("severity")
        ) == "high"
        for signal in signals
    ):
        return "high"

    return "informational"


# ============================================================
# EXPLANATION
# ============================================================

def build_explanation(
    score: int,
    severity: str,
    classification: str,
    confidence: int,
    signals: list[dict[str, Any]],
) -> str:
    """
    Generate a concise human-readable explanation.
    """

    if not signals:
        return (
            "No significant malicious or suspicious "
            "signals were identified by the current "
            "analysis pipeline."
        )

    ranked = sorted(
        signals,
        key=lambda signal: (
            int(
                signal.get(
                    "points",
                    0,
                )
            ),
            _severity_rank(
                signal.get(
                    "severity",
                    "informational",
                )
            ),
        ),
        reverse=True,
    )

    top_signals = ranked[:3]

    descriptions = [
        str(
            signal.get(
                "description",
                "Suspicious signal detected.",
            )
        )
        for signal in top_signals
    ]

    joined = "; ".join(
        descriptions
    )

    return (
        f"The email received a risk score of {score}/100 "
        f"with {severity} severity and a "
        f"'{classification}' classification. "
        f"Analysis confidence is {confidence}%. "
        f"The strongest contributing evidence was: "
        f"{joined}"
    )


# ============================================================
# MAIN RISK ENGINE
# ============================================================

def calculate_risk(
    findings: list[dict[str, Any]] | None = None,
    authentication: dict[str, Any] | None = None,
    identity: dict[str, Any] | None = None,
    url_analysis: dict[str, Any] | None = None,
    attachments: list[dict[str, Any]] | None = None,
    social_engineering: dict[str, Any] | None = None,
    infrastructure: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Main risk calculation function.

    Inputs:
        findings
        authentication
        identity
        url_analysis
        attachments
        social_engineering
        infrastructure

    Returns:
        score
        severity
        classification
        confidence
        signals
        contributing_signals
        score_breakdown
        explanation
    """

    signals: list[dict[str, Any]] = []

    # --------------------------------------------------------
    # Generic findings
    # --------------------------------------------------------

    signals.extend(
        score_findings(
            findings
        )
    )

    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    signals.extend(
        score_authentication(
            authentication
        )
    )

    # --------------------------------------------------------
    # Identity
    # --------------------------------------------------------

    signals.extend(
        score_identity(
            identity
        )
    )

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    signals.extend(
        score_url_analysis(
            url_analysis
        )
    )

    # --------------------------------------------------------
    # Attachments
    # --------------------------------------------------------

    signals.extend(
        score_attachments(
            attachments
        )
    )

    # --------------------------------------------------------
    # BEC / social engineering
    # --------------------------------------------------------

    signals.extend(
        score_bec(
            social_engineering
        )
    )

    # --------------------------------------------------------
    # Infrastructure / TI
    # --------------------------------------------------------

    signals.extend(
        score_infrastructure(
            infrastructure
        )
    )

    # --------------------------------------------------------
    # Remove duplicate signals
    # --------------------------------------------------------

    signals = deduplicate_signals(
        signals
    )

    # --------------------------------------------------------
    # Calculate score
    # --------------------------------------------------------

    raw_score = sum(
        int(
            signal.get(
                "points",
                0,
            )
        )
        for signal in signals
    )

    score = clamp_score(
        raw_score
    )

    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    severity = calculate_severity(
        score,
        signals,
    )

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    classification = classify_risk(
        score,
        signals,
    )

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    confidence = calculate_confidence(
        signals
    )

    # --------------------------------------------------------
    # Ranking
    # --------------------------------------------------------

    ranked_signals = sorted(
        signals,
        key=lambda signal: (
            int(
                signal.get(
                    "points",
                    0,
                )
            ),
            _severity_rank(
                signal.get(
                    "severity",
                    "informational",
                )
            ),
        ),
        reverse=True,
    )

    contributing_signals = ranked_signals[:10]

    # --------------------------------------------------------
    # Breakdown
    # --------------------------------------------------------

    score_breakdown = (
        build_score_breakdown(
            signals
        )
    )

    score_breakdown[
        "final_score"
    ] = score

    # --------------------------------------------------------
    # Explanation
    # --------------------------------------------------------

    explanation = build_explanation(
        score=score,
        severity=severity,
        classification=classification,
        confidence=confidence,
        signals=signals,
    )

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    return {
        "score": score,
        "severity": severity,
        "classification": classification,
        "confidence": confidence,
        "signal_count": len(signals),
        "signals": signals,
        "contributing_signals": contributing_signals,
        "score_breakdown": score_breakdown,
        "explanation": explanation,
    }


# ============================================================
# COMPATIBILITY WRAPPER
# ============================================================

def calculate_simple_risk(
    findings: list[dict[str, Any]] | None = None,
    authentication: dict[str, Any] | None = None,
    identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Simple compatibility wrapper for older code.
    """

    return calculate_risk(
        findings=findings,
        authentication=authentication,
        identity=identity,
    )


# ============================================================
# SERVICE STATUS
# ============================================================

def get_risk_engine_status() -> dict[str, Any]:
    """
    Health/status information for the risk engine.
    """

    return {
        "service": "risk_engine",
        "status": "ready",
        "score_range": {
            "min": MIN_SCORE,
            "max": MAX_SCORE,
        },
        "supported_sources": [
            "findings",
            "authentication",
            "identity",
            "url_analysis",
            "attachments",
            "social_engineering",
            "infrastructure",
        ],
        "classifications": [
            "legitimate",
            "suspicious",
            "phishing_or_fraud",
        ],
        "severity_levels": [
            "informational",
            "low",
            "medium",
            "high",
            "critical",
        ],
    }