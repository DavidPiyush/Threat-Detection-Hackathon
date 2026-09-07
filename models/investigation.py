# model/investigation.py

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, ConfigDict


# ============================================================
# ENUM-LIKE VALUES
# ============================================================

INVESTIGATION_STATUSES = {
    "open",
    "investigating",
    "resolved",
    "closed",
}

INVESTIGATION_PRIORITIES = {
    "low",
    "medium",
    "high",
    "critical",
}


# ============================================================
# INVESTIGATION CREATE
# ============================================================

class InvestigationCreate(BaseModel):
    """
    Data required to create a new investigation case.
    """

    title: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Investigation title",
    )

    description: str | None = Field(
        default=None,
        max_length=5000,
        description="Investigation description",
    )

    priority: str = Field(
        default="medium",
        description="Investigation priority",
    )

    analyst: str | None = Field(
        default=None,
        max_length=100,
        description="Assigned analyst",
    )


# ============================================================
# INVESTIGATION UPDATE
# ============================================================

class InvestigationUpdate(BaseModel):
    """
    Fields that can be modified after case creation.
    """

    title: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
    )

    description: str | None = Field(
        default=None,
        max_length=5000,
    )

    priority: str | None = None

    status: str | None = None

    analyst: str | None = Field(
        default=None,
        max_length=100,
    )

    notes: str | None = Field(
        default=None,
        max_length=10000,
    )


# ============================================================
# RISK
# ============================================================

class InvestigationRisk(BaseModel):
    """
    Current risk state of an investigation.
    """

    score: int = Field(
        default=0,
        ge=0,
        le=100,
    )

    severity: str = Field(
        default="low",
    )

    classification: str = Field(
        default="unknown",
    )


# ============================================================
# IOC COLLECTION
# ============================================================

class InvestigationIOCs(BaseModel):
    """
    Indicators collected across all emails belonging
    to an investigation.
    """

    urls: list[str] = Field(
        default_factory=list
    )

    domains: list[str] = Field(
        default_factory=list
    )

    ips: list[str] = Field(
        default_factory=list
    )

    hashes: list[str] = Field(
        default_factory=list
    )


# ============================================================
# INVESTIGATED EMAIL
# ============================================================

class InvestigatedEmail(BaseModel):
    """
    Email attached to an investigation.
    """

    gmail_message_id: str | None = None

    thread_id: str | None = None

    message_id: str | None = None

    sender: str | None = None

    reply_to: str | None = None

    return_path: str | None = None

    subject: str | None = None

    received: list[str] = Field(
        default_factory=list
    )

    authentication: dict[str, Any] = Field(
        default_factory=dict
    )

    analysis: dict[str, Any] = Field(
        default_factory=dict
    )

    analyzed_at: datetime | None = None


# ============================================================
# FINDING
# ============================================================

class InvestigationFinding(BaseModel):
    """
    Individual forensic finding generated during analysis.
    """

    finding_id: str

    gmail_message_id: str | None = None

    type: str

    severity: str

    description: str

    evidence: dict[str, Any] = Field(
        default_factory=dict
    )

    created_at: datetime | None = None


# ============================================================
# INVESTIGATION RESPONSE
# ============================================================

class InvestigationResponse(BaseModel):
    """
    Complete investigation returned by the API.
    """

    model_config = ConfigDict(
        from_attributes=True
    )

    case_id: str

    title: str

    description: str | None = None

    priority: str

    status: str

    analyst: str | None = None

    created_at: datetime

    updated_at: datetime

    emails: list[InvestigatedEmail] = Field(
        default_factory=list
    )

    findings: list[InvestigationFinding] = Field(
        default_factory=list
    )

    iocs: InvestigationIOCs = Field(
        default_factory=InvestigationIOCs
    )

    risk: InvestigationRisk = Field(
        default_factory=InvestigationRisk
    )

    notes: str = ""


# ============================================================
# INVESTIGATION LIST ITEM
# ============================================================

class InvestigationListItem(BaseModel):
    """
    Lightweight investigation representation for
    dashboard/list views.
    """

    case_id: str

    title: str

    priority: str

    status: str

    analyst: str | None = None

    created_at: datetime

    updated_at: datetime

    email_count: int = 0

    finding_count: int = 0

    risk_score: int = 0

    severity: str = "low"

    classification: str = "unknown"