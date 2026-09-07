from __future__ import annotations

import hashlib
import io
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    SimpleDocTemplate,
    KeepTogether,
)

from database.connect import get_db_connection


router = APIRouter(
    prefix="/reports",
    tags=["Reports"],
)


# ============================================================
# HELPERS
# ============================================================

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_json(value: Any) -> Any:
    """
    Convert values into JSON-safe structures.
    """
    if value is None:
        return None

    if isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, dict):
        return {
            str(key): _safe_json(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [_safe_json(item) for item in value]

    return str(value)


def _json_hash(data: Any) -> str:
    """
    SHA-256 hash of canonical JSON representation.
    """
    canonical = json.dumps(
        _safe_json(data),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return hashlib.sha256(canonical).hexdigest()


def _row_to_dict(cursor, row) -> dict[str, Any]:
    columns = [description.name for description in cursor.description]
    return dict(zip(columns, row))


def _severity_rank(severity: str) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "informational": 0,
        "info": 0,
    }.get(str(severity).lower(), 0)


# ============================================================
# DATABASE RETRIEVAL
# ============================================================

def _get_investigation(case_id: str) -> dict[str, Any]:
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    case_id,
                    title,
                    description,
                    priority,
                    status,
                    analyst,
                    notes,
                    risk_score,
                    risk_severity,
                    classification,
                    created_at,
                    updated_at
                FROM investigations
                WHERE case_id = %s
                """,
                (case_id,),
            )

            row = cursor.fetchone()

            if not row:
                raise HTTPException(
                    status_code=404,
                    detail=f"Investigation '{case_id}' not found",
                )

            return _row_to_dict(cursor, row)

    finally:
        connection.close()


def _get_emails(investigation_id: int) -> list[dict[str, Any]]:
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    gmail_message_id,
                    thread_id,
                    message_id,
                    sender,
                    reply_to,
                    return_path,
                    subject,
                    received,
                    authentication,
                    analysis,
                    analyzed_at
                FROM investigated_emails
                WHERE investigation_id = %s
                ORDER BY analyzed_at ASC, id ASC
                """,
                (investigation_id,),
            )

            return [
                _row_to_dict(cursor, row)
                for row in cursor.fetchall()
            ]

    finally:
        connection.close()


def _get_findings(investigation_id: int) -> list[dict[str, Any]]:
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    finding_id,
                    email_id,
                    gmail_message_id,
                    type,
                    severity,
                    description,
                    evidence,
                    created_at
                FROM findings
                WHERE investigation_id = %s
                ORDER BY
                    CASE LOWER(severity)
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3
                        ELSE 4
                    END,
                    created_at ASC,
                    id ASC
                """,
                (investigation_id,),
            )

            return [
                _row_to_dict(cursor, row)
                for row in cursor.fetchall()
            ]

    finally:
        connection.close()


def _get_iocs(investigation_id: int) -> list[dict[str, Any]]:
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    type,
                    value,
                    created_at
                FROM iocs
                WHERE investigation_id = %s
                ORDER BY type ASC, value ASC
                """,
                (investigation_id,),
            )

            return [
                _row_to_dict(cursor, row)
                for row in cursor.fetchall()
            ]

    finally:
        connection.close()


# ============================================================
# REPORT BUILDER
# ============================================================

def _build_report(case_id: str) -> dict[str, Any]:
    investigation = _get_investigation(case_id)

    investigation_id = investigation["id"]

    emails = _get_emails(investigation_id)
    findings = _get_findings(investigation_id)
    iocs = _get_iocs(investigation_id)

    # --------------------------------------------------------
    # Evidence summary
    # --------------------------------------------------------

    evidence_hashes = []

    for email in emails:
        analysis = email.get("analysis") or {}

        if isinstance(analysis, dict):
            email_hash = (
                analysis.get("email_hash")
                or analysis.get("sha256")
                or analysis.get("evidence_hash")
            )

            if email_hash:
                evidence_hashes.append(email_hash)

    # --------------------------------------------------------
    # Finding statistics
    # --------------------------------------------------------

    finding_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }

    for finding in findings:
        severity = str(
            finding.get("severity", "informational")
        ).lower()

        if severity == "info":
            severity = "informational"

        if severity not in finding_counts:
            severity = "informational"

        finding_counts[severity] += 1

    # --------------------------------------------------------
    # IOC statistics
    # --------------------------------------------------------

    ioc_counts: dict[str, int] = {}

    for ioc in iocs:
        ioc_type = str(ioc.get("type", "unknown")).lower()
        ioc_counts[ioc_type] = ioc_counts.get(ioc_type, 0) + 1

    # --------------------------------------------------------
    # Authentication summary
    # --------------------------------------------------------

    authentication_summary = []

    for email in emails:
        authentication = email.get("authentication") or {}

        authentication_summary.append(
            {
                "gmail_message_id": email.get("gmail_message_id"),
                "spf": authentication.get("spf", "unknown"),
                "dkim": authentication.get("dkim", "unknown"),
                "dmarc": authentication.get("dmarc", "unknown"),
            }
        )

    # --------------------------------------------------------
    # Relay path summary
    # --------------------------------------------------------

    relay_paths = []

    for email in emails:
        analysis = email.get("analysis") or {}

        received_analysis = (
            analysis.get("received_analysis")
            or analysis.get("relay")
            or {}
        )

        relay_paths.append(
            {
                "gmail_message_id": email.get("gmail_message_id"),
                "received": email.get("received") or [],
                "analysis": received_analysis,
            }
        )

    # --------------------------------------------------------
    # Analysis summary
    # --------------------------------------------------------

    analysis_summaries = []

    for email in emails:
        analysis = email.get("analysis") or {}

        analysis_summaries.append(
            {
                "gmail_message_id": email.get("gmail_message_id"),
                "analysis": analysis,
            }
        )

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    risk = {
        "score": investigation.get("risk_score", 0),
        "severity": investigation.get("risk_severity", "low"),
        "classification": investigation.get(
            "classification",
            "unknown",
        ),
    }

    # Pull richer risk information from email analysis if present.
    for item in analysis_summaries:
        analysis = item.get("analysis") or {}

        if not isinstance(analysis, dict):
            continue

        risk_analysis = analysis.get("risk")

        if isinstance(risk_analysis, dict):
            risk.update(
                {
                    "score": risk_analysis.get(
                        "score",
                        risk["score"],
                    ),
                    "severity": risk_analysis.get(
                        "severity",
                        risk["severity"],
                    ),
                    "classification": risk_analysis.get(
                        "classification",
                        risk["classification"],
                    ),
                    "confidence": risk_analysis.get(
                        "confidence"
                    ),
                    "explanation": risk_analysis.get(
                        "explanation"
                    ),
                    "contributing_signals": risk_analysis.get(
                        "contributing_signals",
                        [],
                    ),
                    "score_breakdown": risk_analysis.get(
                        "score_breakdown",
                        {},
                    ),
                }
            )

    # --------------------------------------------------------
    # Evidence manifest
    # --------------------------------------------------------

    evidence_manifest = {
        "case_id": case_id,
        "email_count": len(emails),
        "email_hashes": evidence_hashes,
        "finding_count": len(findings),
        "ioc_count": len(iocs),
        "generated_at": _utc_now(),
    }

    report_hash = _json_hash(
        {
            "investigation": investigation,
            "emails": emails,
            "findings": findings,
            "iocs": iocs,
        }
    )

    return {
        "report": {
            "report_type": "email_forensic_investigation",
            "generated_at": _utc_now(),
            "report_hash": report_hash,
            "case_id": case_id,
        },

        "case": {
            "case_id": investigation["case_id"],
            "title": investigation["title"],
            "description": investigation.get("description"),
            "priority": investigation["priority"],
            "status": investigation["status"],
            "analyst": investigation.get("analyst"),
            "notes": investigation.get("notes") or "",
            "created_at": investigation["created_at"],
            "updated_at": investigation["updated_at"],
        },

        "risk": risk,

        "evidence": {
            "manifest": evidence_manifest,
            "chain_of_custody": {
                "case_id": case_id,
                "evidence_hashes": evidence_hashes,
                "report_hash": report_hash,
                "generated_at": _utc_now(),
                "preservation_note": (
                    "Original evidence hashes should be retained "
                    "with the original source material."
                ),
            },
        },

        "emails": emails,

        "authentication": authentication_summary,

        "relay_paths": relay_paths,

        "analysis": analysis_summaries,

        "findings": findings,

        "iocs": {
            "items": iocs,
            "counts": ioc_counts,
        },

        "finding_summary": {
            "total": len(findings),
            "by_severity": finding_counts,
        },

        "investigation_summary": {
            "email_count": len(emails),
            "finding_count": len(findings),
            "ioc_count": len(iocs),
            "critical_findings": finding_counts["critical"],
            "high_findings": finding_counts["high"],
        },
    }


# ============================================================
# JSON REPORT
# ============================================================

@router.get("/{case_id}")
async def get_report(case_id: str):
    """
    Generate a structured forensic investigation report.
    """
    report = _build_report(case_id)

    return {
        "success": True,
        "data": _safe_json(report),
    }


# ============================================================
# PDF HELPERS
# ============================================================

def _pdf_paragraph(
    text: str,
    style: ParagraphStyle,
) -> Paragraph:
    safe_text = (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

    return Paragraph(safe_text, style)


def _make_pdf(report: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=(
            f"Forensic Report - "
            f"{report['case']['case_id']}"
        ),
        author="Threat Detection Platform",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=20,
        leading=24,
        alignment=TA_CENTER,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        alignment=TA_CENTER,
        spaceAfter=16,
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        spaceBefore=12,
        spaceAfter=7,
    )

    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        spaceAfter=5,
    )

    small_style = ParagraphStyle(
        "Small",
        parent=styles["BodyText"],
        fontSize=7.5,
        leading=10,
        spaceAfter=3,
    )

    mono_style = ParagraphStyle(
        "Mono",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=7,
        leading=9,
        spaceAfter=3,
    )

    story = []

    case = report["case"]
    risk = report["risk"]
    summary = report["investigation_summary"]
    findings_summary = report["finding_summary"]
    evidence = report["evidence"]
    report_meta = report["report"]

    # --------------------------------------------------------
    # Cover
    # --------------------------------------------------------

    story.append(
        _pdf_paragraph(
            "EMAIL FORENSIC INVESTIGATION REPORT",
            title_style,
        )
    )

    story.append(
        _pdf_paragraph(
            f"Case: {case['case_id']}",
            subtitle_style,
        )
    )

    # --------------------------------------------------------
    # Executive summary
    # --------------------------------------------------------

    story.append(
        _pdf_paragraph(
            "1. Executive Summary",
            heading_style,
        )
    )

    executive_data = [
        ["Case", case["case_id"]],
        ["Title", case["title"]],
        ["Status", case["status"]],
        ["Priority", case["priority"]],
        ["Classification", risk.get("classification", "unknown")],
        ["Risk Score", str(risk.get("score", 0))],
        ["Risk Severity", risk.get("severity", "low")],
        [
            "Confidence",
            str(risk.get("confidence", "N/A")),
        ],
        ["Emails", str(summary["email_count"])],
        ["Findings", str(summary["finding_count"])],
        ["IOCs", str(summary["ioc_count"])],
    ]

    table = Table(
        executive_data,
        colWidths=[45 * mm, 125 * mm],
    )

    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    story.append(table)
    story.append(Spacer(1, 8))

    explanation = risk.get("explanation")

    if explanation:
        story.append(
            _pdf_paragraph(
                f"<b>Risk explanation:</b> {explanation}",
                body_style,
            )
        )

    # --------------------------------------------------------
    # Case details
    # --------------------------------------------------------

    story.append(
        _pdf_paragraph(
            "2. Case Details",
            heading_style,
        )
    )

    story.append(
        _pdf_paragraph(
            f"<b>Description:</b> "
            f"{case.get('description') or 'No description provided.'}",
            body_style,
        )
    )

    story.append(
        _pdf_paragraph(
            f"<b>Analyst:</b> "
            f"{case.get('analyst') or 'Not assigned'}",
            body_style,
        )
    )

    story.append(
        _pdf_paragraph(
            f"<b>Created:</b> {case['created_at']}",
            body_style,
        )
    )

    # --------------------------------------------------------
    # Evidence
    # --------------------------------------------------------

    story.append(
        _pdf_paragraph(
            "3. Evidence & Chain of Custody",
            heading_style,
        )
    )

    story.append(
        _pdf_paragraph(
            f"<b>Report SHA-256:</b> "
            f"{report_meta['report_hash']}",
            mono_style,
        )
    )

    for evidence_hash in evidence["manifest"]["email_hashes"]:
        story.append(
            _pdf_paragraph(
                f"<b>Email evidence SHA-256:</b> "
                f"{evidence_hash}",
                mono_style,
            )
        )

    story.append(
        _pdf_paragraph(
            "Evidence should be preserved in its original form. "
            "The report records hashes and analytical provenance "
            "to support later verification.",
            body_style,
        )
    )

    # --------------------------------------------------------
    # Email evidence
    # --------------------------------------------------------

    story.append(
        _pdf_paragraph(
            "4. Email Evidence",
            heading_style,
        )
    )

    for index, email in enumerate(
        report["emails"],
        start=1,
    ):
        story.append(
            KeepTogether(
                [
                    _pdf_paragraph(
                        f"Email #{index}",
                        ParagraphStyle(
                            f"EmailHeading{index}",
                            parent=body_style,
                            fontName="Helvetica-Bold",
                            spaceBefore=5,
                        ),
                    ),
                    _pdf_paragraph(
                        f"<b>Message ID:</b> "
                        f"{email.get('message_id') or 'N/A'}",
                        small_style,
                    ),
                    _pdf_paragraph(
                        f"<b>Sender:</b> "
                        f"{email.get('sender') or 'N/A'}",
                        small_style,
                    ),
                    _pdf_paragraph(
                        f"<b>Reply-To:</b> "
                        f"{email.get('reply_to') or 'N/A'}",
                        small_style,
                    ),
                    _pdf_paragraph(
                        f"<b>Return-Path:</b> "
                        f"{email.get('return_path') or 'N/A'}",
                        small_style,
                    ),
                    _pdf_paragraph(
                        f"<b>Subject:</b> "
                        f"{email.get('subject') or 'N/A'}",
                        small_style,
                    ),
                ]
            )
        )

    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    story.append(
        _pdf_paragraph(
            "5. Sender Authentication",
            heading_style,
        )
    )

    auth_rows = [
        ["Email", "SPF", "DKIM", "DMARC"],
    ]

    for index, item in enumerate(
        report["authentication"],
        start=1,
    ):
        auth_rows.append(
            [
                str(index),
                str(item.get("spf", "unknown")),
                str(item.get("dkim", "unknown")),
                str(item.get("dmarc", "unknown")),
            ]
        )

    if len(auth_rows) > 1:
        table = Table(
            auth_rows,
            colWidths=[
                25 * mm,
                35 * mm,
                35 * mm,
                35 * mm,
            ],
        )

        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.lightgrey,
                    ),
                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold",
                    ),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ]
            )
        )

        story.append(table)

    # --------------------------------------------------------
    # Relay paths
    # --------------------------------------------------------

    story.append(
        _pdf_paragraph(
            "6. SMTP Relay / Received Path",
            heading_style,
        )
    )

    for index, relay in enumerate(
        report["relay_paths"],
        start=1,
    ):
        story.append(
            _pdf_paragraph(
                f"<b>Email #{index}</b>",
                body_style,
            )
        )

        received = relay.get("received") or []

        if not received:
            story.append(
                _pdf_paragraph(
                    "No Received headers recorded.",
                    small_style,
                )
            )
        else:
            for hop_number, hop in enumerate(
                received,
                start=1,
            ):
                story.append(
                    _pdf_paragraph(
                        f"{hop_number}. {hop}",
                        mono_style,
                    )
                )

    # --------------------------------------------------------
    # Findings
    # --------------------------------------------------------

    story.append(
        _pdf_paragraph(
            "7. Security Findings",
            heading_style,
        )
    )

    story.append(
        _pdf_paragraph(
            (
                f"Critical: {findings_summary['by_severity']['critical']} | "
                f"High: {findings_summary['by_severity']['high']} | "
                f"Medium: {findings_summary['by_severity']['medium']} | "
                f"Low: {findings_summary['by_severity']['low']} | "
                f"Informational: "
                f"{findings_summary['by_severity']['informational']}"
            ),
            body_style,
        )
    )

    for finding in report["findings"]:
        severity = finding.get("severity", "informational")

        story.append(
            KeepTogether(
                [
                    _pdf_paragraph(
                        (
                            f"<b>[{severity.upper()}] "
                            f"{finding.get('type', 'finding')}</b>"
                        ),
                        body_style,
                    ),
                    _pdf_paragraph(
                        finding.get(
                            "description",
                            "No description.",
                        ),
                        small_style,
                    ),
                ]
            )
        )

    # --------------------------------------------------------
    # IOC section
    # --------------------------------------------------------

    story.append(
        _pdf_paragraph(
            "8. Indicators of Compromise",
            heading_style,
        )
    )

    for ioc in report["iocs"]["items"]:
        story.append(
            _pdf_paragraph(
                (
                    f"<b>{ioc.get('type', 'unknown')}:</b> "
                    f"{ioc.get('value', '')}"
                ),
                mono_style,
            )
        )

    if not report["iocs"]["items"]:
        story.append(
            _pdf_paragraph(
                "No IOCs recorded.",
                body_style,
            )
        )

    # --------------------------------------------------------
    # Risk analysis
    # --------------------------------------------------------

    story.append(
        _pdf_paragraph(
            "9. Risk Analysis",
            heading_style,
        )
    )

    story.append(
        _pdf_paragraph(
            (
                f"<b>Score:</b> {risk.get('score', 0)}/100<br/>"
                f"<b>Severity:</b> {risk.get('severity', 'low')}<br/>"
                f"<b>Classification:</b> "
                f"{risk.get('classification', 'unknown')}"
            ),
            body_style,
        )
    )

    contributing = risk.get("contributing_signals") or []

    if contributing:
        story.append(
            _pdf_paragraph(
                "<b>Contributing signals:</b>",
                body_style,
            )
        )

        for signal in contributing:
            if isinstance(signal, dict):
                signal_type = signal.get(
                    "type",
                    "signal",
                )
                description = signal.get(
                    "description",
                    "",
                )
                points = signal.get(
                    "points",
                    0,
                )

                story.append(
                    _pdf_paragraph(
                        (
                            f"• {signal_type}: "
                            f"{description} "
                            f"({points} points)"
                        ),
                        small_style,
                    )
                )

    # --------------------------------------------------------
    # Analyst notes
    # --------------------------------------------------------

    if case.get("notes"):
        story.append(
            _pdf_paragraph(
                "10. Analyst Notes",
                heading_style,
            )
        )

        story.append(
            _pdf_paragraph(
                case["notes"],
                body_style,
            )
        )

    # --------------------------------------------------------
    # Attribution disclaimer
    # --------------------------------------------------------

    story.append(
        _pdf_paragraph(
            "11. Attribution & Geolocation Boundary",
            heading_style,
        )
    )

    story.append(
        _pdf_paragraph(
            (
                "Infrastructure geolocation and threat-intelligence "
                "results identify observable infrastructure and "
                "support investigative correlation. They do not, "
                "by themselves, establish the physical identity or "
                "exact location of an attacker."
            ),
            body_style,
        )
    )

    # --------------------------------------------------------
    # Footer
    # --------------------------------------------------------

    story.append(Spacer(1, 12))

    story.append(
        _pdf_paragraph(
            (
                f"Generated by Threat Detection Platform • "
                f"{report_meta['generated_at']} • "
                f"Report SHA-256: {report_meta['report_hash']}"
            ),
            subtitle_style,
        )
    )

    document.build(story)

    buffer.seek(0)

    return buffer.read()


# ============================================================
# PDF REPORT
# ============================================================

@router.get("/{case_id}/pdf")
async def get_report_pdf(case_id: str):
    """
    Generate a PDF forensic report.
    """
    report = _build_report(case_id)

    pdf_bytes = _make_pdf(report)

    filename = (
        f"forensic-report-{case_id}.pdf"
    )

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            )
        },
    )