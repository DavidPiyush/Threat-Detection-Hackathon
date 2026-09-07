"""
Analysis Data Models
====================

Pydantic models for the complete email-threat analysis pipeline.

Pipeline:

    Parsed Email
        ↓
    Authentication
        ↓
    Identity
        ↓
    URL / Domain / IP Intelligence
        ↓
    Threat Intelligence
        ↓
    Behavioral Analysis
        ↓
    Risk Engine
        ↓
    Investigation Result
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Generic Signal
# ---------------------------------------------------------------------------


class AnalysisSignal(BaseModel):
    """
    A normalized explainable security signal.
    """

    type: str

    severity: str = "informational"

    description: str

    evidence: dict[str, Any] = Field(
        default_factory=dict
    )

    source: str = "analysis"

    score: int = 0


# ---------------------------------------------------------------------------
# URL Intelligence
# ---------------------------------------------------------------------------


class URLIntelligenceResult(BaseModel):
    """
    Result of URL structural/reputation analysis.
    """

    url: str

    valid: bool = False

    domain: str | None = None

    threat_score: int = Field(
        default=0,
        ge=0,
        le=100,
    )

    reputation: str = "unknown"

    malicious: bool = False

    suspicious: bool = False

    analysis: dict[str, Any] = Field(
        default_factory=dict
    )

    signals: list[AnalysisSignal] = Field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# Domain Intelligence
# ---------------------------------------------------------------------------


class DomainIntelligenceResult(BaseModel):
    """
    Result of domain infrastructure analysis.
    """

    domain: str

    valid: bool = False

    root_domain: str | None = None

    subdomain: str | None = None

    threat_score: int = Field(
        default=0,
        ge=0,
        le=100,
    )

    reputation: str = "unknown"

    malicious: bool = False

    suspicious: bool = False

    dns: dict[str, Any] = Field(
        default_factory=dict
    )

    mx: dict[str, Any] = Field(
        default_factory=dict
    )

    rdap: dict[str, Any] = Field(
        default_factory=dict
    )

    age: dict[str, Any] = Field(
        default_factory=dict
    )

    lookalike: dict[str, Any] = Field(
        default_factory=dict
    )

    signals: list[AnalysisSignal] = Field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# IP Intelligence
# ---------------------------------------------------------------------------


class IPIntelligenceResult(BaseModel):
    """
    Result of IP infrastructure analysis.
    """

    ip: str

    valid: bool = False

    version: int | None = None

    type: str = "invalid"

    public: bool = False

    country: str | None = None

    country_code: str | None = None

    city: str | None = None

    latitude: float | None = None

    longitude: float | None = None

    asn: int | None = None

    organization: str | None = None

    isp: str | None = None

    reverse_dns: dict[str, Any] = Field(
        default_factory=dict
    )

    infrastructure: dict[str, Any] = Field(
        default_factory=dict
    )

    threat_score: int = Field(
        default=0,
        ge=0,
        le=100,
    )

    reputation: str = "unknown"

    signals: list[AnalysisSignal] = Field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# Threat Intelligence
# ---------------------------------------------------------------------------


class ThreatIntelligenceResult(BaseModel):
    """
    Combined external TI results.
    """

    indicator: str

    indicator_type: str

    available: bool = False

    threat_score: int = Field(
        default=0,
        ge=0,
        le=100,
    )

    reputation: str = "unknown"

    malicious: bool = False

    suspicious: bool = False

    providers: dict[str, Any] = Field(
        default_factory=dict
    )

    evidence: list[dict[str, Any]] = Field(
        default_factory=list
    )

    errors: list[str] = Field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# Behavioral Analysis
# ---------------------------------------------------------------------------


class BehavioralAnalysis(BaseModel):
    """
    NLP / social engineering / BEC analysis.
    """

    phishing_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    bec_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    social_engineering_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    urgency_detected: bool = False

    impersonation_detected: bool = False

    credential_harvesting: bool = False

    payment_request: bool = False

    invoice_fraud: bool = False

    executive_impersonation: bool = False

    suspicious_phrases: list[str] = Field(
        default_factory=list
    )

    signals: list[AnalysisSignal] = Field(
        default_factory=list
    )

    model_name: str = "rule-based"

    model_version: str = "1.0"


# ---------------------------------------------------------------------------
# Risk Signal
# ---------------------------------------------------------------------------


class RiskSignal(BaseModel):
    """
    Signal contributing to the final risk score.
    """

    type: str

    severity: str

    description: str

    score: int = 0

    evidence: dict[str, Any] = Field(
        default_factory=dict
    )


# ---------------------------------------------------------------------------
# Risk Breakdown
# ---------------------------------------------------------------------------


class RiskScoreBreakdown(BaseModel):
    """
    Breakdown of risk contribution.
    """

    authentication: int = 0

    identity: int = 0

    urls: int = 0

    attachments: int = 0

    behavioral: int = 0

    infrastructure: int = 0

    findings: int = 0

    total_before_cap: int = 0

    final_score: int = 0


# ---------------------------------------------------------------------------
# Risk Result
# ---------------------------------------------------------------------------


class RiskAnalysis(BaseModel):
    """
    Final explainable risk-engine result.
    """

    score: int = Field(
        default=0,
        ge=0,
        le=100,
    )

    severity: str = "informational"

    classification: str = "unknown"

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    signal_count: int = 0

    signals: list[RiskSignal] = Field(
        default_factory=list
    )

    contributing_signals: list[RiskSignal] = Field(
        default_factory=list
    )

    score_breakdown: dict[str, Any] = Field(
        default_factory=dict
    )

    explanation: str = ""


# ---------------------------------------------------------------------------
# GeoLocation
# ---------------------------------------------------------------------------


class GeoLocation(BaseModel):
    """
    Geolocation of observed infrastructure.

    This represents infrastructure location, not attacker attribution.
    """

    ip: str

    country: str | None = None

    country_code: str | None = None

    region: str | None = None

    city: str | None = None

    latitude: float | None = None

    longitude: float | None = None

    timezone: str | None = None

    accuracy_radius_km: float | None = None

    source: str | None = None

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )


# ---------------------------------------------------------------------------
# Attribution Assessment
# ---------------------------------------------------------------------------


class AttributionAssessment(BaseModel):
    """
    Conservative infrastructure attribution assessment.

    The platform should never claim exact attacker identity/location
    from IP intelligence alone.
    """

    status: str = "unknown"

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    observed_infrastructure: list[str] = Field(
        default_factory=list
    )

    supporting_evidence: list[str] = Field(
        default_factory=list
    )

    limitations: list[str] = Field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# Complete Analysis Response
# ---------------------------------------------------------------------------


class EmailAnalysisResult(BaseModel):
    """
    Complete result returned by the analysis pipeline.
    """

    analysis_id: str

    case_id: str | None = None

    email_hash: str

    analyzed_at: datetime

    parser_version: str = "1.0"

    analysis_version: str = "1.0"

    email: dict[str, Any] = Field(
        default_factory=dict
    )

    authentication: dict[str, Any] = Field(
        default_factory=dict
    )

    identity: dict[str, Any] = Field(
        default_factory=dict
    )

    relay: dict[str, Any] = Field(
        default_factory=dict
    )

    urls: list[URLIntelligenceResult] = Field(
        default_factory=list
    )

    domains: list[DomainIntelligenceResult] = Field(
        default_factory=list
    )

    ips: list[IPIntelligenceResult] = Field(
        default_factory=list
    )

    threat_intelligence: list[
        ThreatIntelligenceResult
    ] = Field(
        default_factory=list
    )

    behavioral: BehavioralAnalysis = Field(
        default_factory=BehavioralAnalysis
    )

    risk: RiskAnalysis = Field(
        default_factory=RiskAnalysis
    )

    geolocation: list[GeoLocation] = Field(
        default_factory=list
    )

    attribution: AttributionAssessment = Field(
        default_factory=AttributionAssessment
    )

    iocs: dict[str, list[str]] = Field(
        default_factory=dict
    )

    evidence: list[dict[str, Any]] = Field(
        default_factory=list
    )

    findings: list[AnalysisSignal] = Field(
        default_factory=list
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


# ---------------------------------------------------------------------------
# Public Exports
# ---------------------------------------------------------------------------


__all__ = [
    "AnalysisSignal",
    "URLIntelligenceResult",
    "DomainIntelligenceResult",
    "IPIntelligenceResult",
    "ThreatIntelligenceResult",
    "BehavioralAnalysis",
    "RiskSignal",
    "RiskScoreBreakdown",
    "RiskAnalysis",
    "GeoLocation",
    "AttributionAssessment",
    "EmailAnalysisResult",
]