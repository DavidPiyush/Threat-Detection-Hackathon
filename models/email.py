"""
Email Data Models
=================

Pydantic models representing parsed and investigated emails.

These models define the data contract between:

    email_parser
        ↓
    analysis pipeline
        ↓
    PostgreSQL
        ↓
    FastAPI
        ↓
    Frontend
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Header Models
# ---------------------------------------------------------------------------


class EmailHeader(BaseModel):
    """
    Represents a single email header.
    """

    name: str
    value: str


class EmailHeaders(BaseModel):
    """
    Important RFC 5322 email headers.
    """

    from_: str | None = Field(
        default=None,
        alias="from",
    )

    to: str | None = None

    cc: str | None = None

    bcc: str | None = None

    subject: str | None = None

    date: str | None = None

    reply_to: str | None = None

    return_path: str | None = None

    message_id: str | None = None

    received: list[str] = Field(
        default_factory=list
    )

    authentication_results: list[str] = Field(
        default_factory=list
    )

    dkim_signature: list[str] = Field(
        default_factory=list
    )

    model_config = ConfigDict(
        populate_by_name=True
    )


# ---------------------------------------------------------------------------
# Email Identity
# ---------------------------------------------------------------------------


class EmailIdentity(BaseModel):
    """
    Sender identity information.
    """

    sender_name: str | None = None

    sender: str | None = None

    sender_email: str | None = None

    sender_domain: str | None = None

    reply_to: str | None = None

    reply_to_email: str | None = None

    reply_to_domain: str | None = None

    return_path: str | None = None

    return_path_email: str | None = None

    return_path_domain: str | None = None

    display_name: str | None = None

    identity_relationship: str | None = None


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class EmailAuthentication(BaseModel):
    """
    SPF/DKIM/DMARC authentication results.
    """

    spf: str = "unknown"

    dkim: str = "unknown"

    dmarc: str = "unknown"

    headers: list[str] = Field(
        default_factory=list
    )

    alignment: dict[str, Any] = Field(
        default_factory=dict
    )


# ---------------------------------------------------------------------------
# Received / Relay Information
# ---------------------------------------------------------------------------


class ReceivedHop(BaseModel):
    """
    One hop in the SMTP Received chain.
    """

    raw: str

    from_host: str | None = None

    from_ip: str | None = None

    by_host: str | None = None

    protocol: str | None = None

    timestamp: str | None = None


class EmailRelayAnalysis(BaseModel):
    """
    SMTP relay path analysis.
    """

    received_count: int = 0

    headers: list[str] = Field(
        default_factory=list
    )

    ips: list[str] = Field(
        default_factory=list
    )

    public_ips: list[str] = Field(
        default_factory=list
    )

    private_ips: list[str] = Field(
        default_factory=list
    )

    special_ips: list[str] = Field(
        default_factory=list
    )

    hops: list[ReceivedHop] = Field(
        default_factory=list
    )

    earliest_observable_ip: str | None = None

    earliest_observable_host: str | None = None


# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------


class EmailURL(BaseModel):
    """
    URL extracted from email content.
    """

    url: str

    domain: str | None = None

    scheme: str | None = None

    path: str | None = None

    query: str | None = None

    risk: str = "unknown"

    analysis: dict[str, Any] = Field(
        default_factory=dict
    )


# ---------------------------------------------------------------------------
# Attachments
# ---------------------------------------------------------------------------


class EmailAttachment(BaseModel):
    """
    Attachment metadata.

    Files are NOT executed by the MVP.
    """

    filename: str | None = None

    content_type: str | None = None

    size: int = 0

    sha256: str | None = None

    disposition: str | None = None

    suspicious: bool = False

    analysis: dict[str, Any] = Field(
        default_factory=dict
    )


# ---------------------------------------------------------------------------
# Email Body
# ---------------------------------------------------------------------------


class EmailBody(BaseModel):
    """
    Parsed email body.
    """

    plain_text: str | None = None

    html: str | None = None

    normalized_text: str | None = None


# ---------------------------------------------------------------------------
# IOC Collection
# ---------------------------------------------------------------------------


class EmailIOCs(BaseModel):
    """
    Indicators of compromise extracted from an email.
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


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class EvidenceItem(BaseModel):
    """
    Evidence item used for explainability and forensic reporting.
    """

    evidence_id: str

    category: str

    type: str

    description: str

    source: str = "email"

    value: Any = None

    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
    )

    observed_at: datetime | None = None

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


# ---------------------------------------------------------------------------
# Parsed Email
# ---------------------------------------------------------------------------


class ParsedEmail(BaseModel):
    """
    Complete deterministic representation of a parsed email.
    """

    model_config = ConfigDict(
        populate_by_name=True
    )

    email_hash: str

    headers: EmailHeaders = Field(
        default_factory=EmailHeaders
    )

    identity: EmailIdentity = Field(
        default_factory=EmailIdentity
    )

    authentication: EmailAuthentication = Field(
        default_factory=EmailAuthentication
    )

    relay: EmailRelayAnalysis = Field(
        default_factory=EmailRelayAnalysis
    )

    body: EmailBody = Field(
        default_factory=EmailBody
    )

    urls: list[EmailURL] = Field(
        default_factory=list
    )

    attachments: list[EmailAttachment] = Field(
        default_factory=list
    )

    iocs: EmailIOCs = Field(
        default_factory=EmailIOCs
    )

    raw_size: int = 0

    parsed_at: datetime | None = None

    parser_version: str = "1.0"

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


# ---------------------------------------------------------------------------
# Email Analysis Request
# ---------------------------------------------------------------------------


class EmailAnalysisRequest(BaseModel):
    """
    Request body for direct email analysis.
    """

    raw_email: str = Field(
        ...,
        min_length=1,
        description=(
            "Raw RFC 5322 email content."
        ),
    )

    case_id: str | None = Field(
        default=None,
        max_length=50,
    )


# ---------------------------------------------------------------------------
# Gmail Analysis Request
# ---------------------------------------------------------------------------


class GmailAnalysisRequest(BaseModel):
    """
    Request model for Gmail message analysis.
    """

    message_id: str = Field(
        ...,
        min_length=1,
        max_length=255,
    )

    case_id: str | None = Field(
        default=None,
        max_length=50,
    )


# ---------------------------------------------------------------------------
# Public Exports
# ---------------------------------------------------------------------------


__all__ = [
    "EmailHeader",
    "EmailHeaders",
    "EmailIdentity",
    "EmailAuthentication",
    "ReceivedHop",
    "EmailRelayAnalysis",
    "EmailURL",
    "EmailAttachment",
    "EmailBody",
    "EmailIOCs",
    "EvidenceItem",
    "ParsedEmail",
    "EmailAnalysisRequest",
    "GmailAnalysisRequest",
]