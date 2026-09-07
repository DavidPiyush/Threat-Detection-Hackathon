from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from psycopg.types.json import Jsonb

from database.connect import get_db_connection


# ============================================================
# CONSTANTS
# ============================================================

VALID_PRIORITIES = {
    "low",
    "medium",
    "high",
    "critical",
}

VALID_STATUSES = {
    "open",
    "investigating",
    "resolved",
    "closed",
}


# ============================================================
# HELPERS
# ============================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_case_id() -> str:
    return f"CASE-{uuid.uuid4().hex[:8].upper()}"


def generate_finding_id() -> str:
    return f"FIND-{uuid.uuid4().hex[:8].upper()}"


def _safe_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value

    return {}


def _safe_list(value: Any) -> list:
    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def _normalize_priority(
    priority: str,
) -> str:

    value = str(priority).strip().lower()

    if value not in VALID_PRIORITIES:
        raise ValueError(
            f"Invalid investigation priority: {priority}"
        )

    return value


def _normalize_status(
    status: str,
) -> str:

    value = str(status).strip().lower()

    if value not in VALID_STATUSES:
        raise ValueError(
            f"Invalid investigation status: {status}"
        )

    return value


def _row_to_dict(
    cursor,
    row,
) -> dict[str, Any]:

    columns = [
        column.name
        for column in cursor.description
    ]

    return dict(
        zip(columns, row)
    )


# ============================================================
# INVESTIGATION SERVICE
# ============================================================

class InvestigationService:

    # ========================================================
    # CREATE
    # ========================================================

    @staticmethod
    def create_investigation(
        title: str,
        description: str | None = None,
        priority: str = "medium",
        analyst: str | None = None,
    ) -> dict[str, Any]:

        if not title or not title.strip():
            raise ValueError(
                "Investigation title is required."
            )

        priority = _normalize_priority(
            priority
        )

        case_id = generate_case_id()

        connection = get_db_connection()

        try:

            with connection.transaction():

                with connection.cursor() as cursor:

                    cursor.execute(
                        """
                        INSERT INTO investigations (
                            case_id,
                            title,
                            description,
                            priority,
                            status,
                            analyst,
                            notes
                        )
                        VALUES (
                            %s,
                            %s,
                            %s,
                            %s,
                            'open',
                            %s,
                            ''
                        )
                        RETURNING
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
                        """,
                        (
                            case_id,
                            title.strip(),
                            description,
                            priority,
                            analyst,
                        ),
                    )

                    row = cursor.fetchone()

                    return _row_to_dict(
                        cursor,
                        row,
                    )

        finally:
            connection.close()

    # ========================================================
    # GET SINGLE CASE
    # ========================================================

    @staticmethod
    def get_investigation(
        case_id: str,
    ) -> dict[str, Any] | None:

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
                    (
                        case_id,
                    ),
                )

                row = cursor.fetchone()

                if not row:
                    return None

                return _row_to_dict(
                    cursor,
                    row,
                )

        finally:
            connection.close()

    # ========================================================
    # LIST CASES
    # ========================================================

    @staticmethod
    def list_investigations() -> list[dict[str, Any]]:

        connection = get_db_connection()

        try:

            with connection.cursor() as cursor:

                cursor.execute(
                    """
                    SELECT
                        i.case_id,
                        i.title,
                        i.priority,
                        i.status,
                        i.analyst,
                        i.created_at,
                        i.updated_at,

                        COUNT(
                            DISTINCT e.id
                        ) AS email_count,

                        COUNT(
                            DISTINCT f.id
                        ) AS finding_count,

                        i.risk_score,
                        i.risk_severity,
                        i.classification

                    FROM investigations i

                    LEFT JOIN investigated_emails e
                        ON e.investigation_id = i.id

                    LEFT JOIN findings f
                        ON f.investigation_id = i.id

                    GROUP BY
                        i.id,
                        i.case_id,
                        i.title,
                        i.priority,
                        i.status,
                        i.analyst,
                        i.created_at,
                        i.updated_at,
                        i.risk_score,
                        i.risk_severity,
                        i.classification

                    ORDER BY
                        i.updated_at DESC
                    """
                )

                rows = cursor.fetchall()

                return [
                    _row_to_dict(
                        cursor,
                        row,
                    )
                    for row in rows
                ]

        finally:
            connection.close()

    # ========================================================
    # UPDATE CASE
    # ========================================================

    @staticmethod
    def update_investigation(
        case_id: str,
        *,
        title: str | None = None,
        description: str | None = None,
        priority: str | None = None,
        status: str | None = None,
        analyst: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any] | None:

        fields = []
        values = []

        if title is not None:

            if not title.strip():
                raise ValueError(
                    "Title cannot be empty."
                )

            fields.append(
                "title = %s"
            )

            values.append(
                title.strip()
            )

        if description is not None:

            fields.append(
                "description = %s"
            )

            values.append(
                description
            )

        if priority is not None:

            priority = _normalize_priority(
                priority
            )

            fields.append(
                "priority = %s"
            )

            values.append(
                priority
            )

        if status is not None:

            status = _normalize_status(
                status
            )

            fields.append(
                "status = %s"
            )

            values.append(
                status
            )

        if analyst is not None:

            fields.append(
                "analyst = %s"
            )

            values.append(
                analyst
            )

        if notes is not None:

            fields.append(
                "notes = %s"
            )

            values.append(
                notes
            )

        if not fields:
            return (
                InvestigationService
                .get_investigation(
                    case_id
                )
            )

        fields.append(
            "updated_at = NOW()"
        )

        values.append(
            case_id
        )

        connection = get_db_connection()

        try:

            with connection.transaction():

                with connection.cursor() as cursor:

                    query = f"""
                        UPDATE investigations

                        SET
                            {", ".join(fields)}

                        WHERE case_id = %s

                        RETURNING
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
                    """

                    cursor.execute(
                        query,
                        values,
                    )

                    row = cursor.fetchone()

                    if not row:
                        return None

                    return _row_to_dict(
                        cursor,
                        row,
                    )

        finally:
            connection.close()

    # ========================================================
    # SAVE COMPLETE ANALYSIS
    # ========================================================

    @staticmethod
    def save_analysis(
        case_id: str,
        analysis_result: dict[str, Any],
        gmail_message_id: str | None = None,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Persist an entire email investigation atomically.

        If any database operation fails:

            email
            findings
            IOCs
            risk

        are all rolled back together.
        """

        analysis_result = _safe_dict(
            analysis_result
        )

        parsed_email = _safe_dict(
            analysis_result.get(
                "email"
            )
        )

        headers = _safe_dict(
            parsed_email.get(
                "headers"
            )
        )

        identity = _safe_dict(
            parsed_email.get(
                "identity"
            )
        )

        authentication = _safe_dict(
            analysis_result.get(
                "authentication"
            )
        )

        risk = _safe_dict(
            analysis_result.get(
                "risk"
            )
        )

        findings = _safe_list(
            analysis_result.get(
                "findings"
            )
        )

        connection = get_db_connection()

        try:

            # =================================================
            # ONE DATABASE TRANSACTION
            # =================================================

            with connection.transaction():

                with connection.cursor() as cursor:

                    # -----------------------------------------
                    # Lock investigation
                    # -----------------------------------------

                    cursor.execute(
                        """
                        SELECT
                            id,
                            case_id

                        FROM investigations

                        WHERE case_id = %s

                        FOR UPDATE
                        """,
                        (
                            case_id,
                        ),
                    )

                    investigation = (
                        cursor.fetchone()
                    )

                    if not investigation:
                        raise ValueError(
                            f"Investigation "
                            f"'{case_id}' not found."
                        )

                    investigation_id = (
                        investigation[0]
                    )

                    # -----------------------------------------
                    # Email metadata
                    # -----------------------------------------

                    message_id = (
                        headers.get(
                            "message-id"
                        )
                        or headers.get(
                            "Message-ID"
                        )
                        or headers.get(
                            "message_id"
                        )
                        or parsed_email.get(
                            "message_id"
                        )
                    )

                    sender = (
                        identity.get(
                            "sender"
                        )
                        or identity.get(
                            "sender_email"
                        )
                        or headers.get(
                            "from"
                        )
                    )

                    reply_to = (
                        identity.get(
                            "reply_to"
                        )
                        or identity.get(
                            "reply_to_email"
                        )
                        or headers.get(
                            "reply-to"
                        )
                    )

                    return_path = (
                        identity.get(
                            "return_path"
                        )
                        or identity.get(
                            "return_path_email"
                        )
                        or headers.get(
                            "return-path"
                        )
                    )

                    subject = (
                        headers.get(
                            "subject"
                        )
                        or parsed_email.get(
                            "subject"
                        )
                    )

                    received = (
                        parsed_email.get(
                            "received"
                        )
                    )

                    if received is None:
                        received = (
                            parsed_email
                            .get(
                                "relay_analysis",
                                {}
                            )
                            .get(
                                "headers",
                                []
                            )
                            if isinstance(
                                parsed_email.get(
                                    "relay_analysis"
                                ),
                                dict,
                            )
                            else []
                        )

                    # -----------------------------------------
                    # Insert analyzed email
                    # -----------------------------------------

                    cursor.execute(
                        """
                        INSERT INTO investigated_emails (
                            investigation_id,
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
                        )
                        VALUES (
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            NOW()
                        )
                        RETURNING id
                        """,
                        (
                            investigation_id,
                            gmail_message_id,
                            thread_id,
                            message_id,
                            sender,
                            reply_to,
                            return_path,
                            subject,

                            Jsonb(
                                _safe_list(
                                    received
                                )
                            ),

                            Jsonb(
                                authentication
                            ),

                            Jsonb(
                                analysis_result
                            ),
                        ),
                    )

                    email_id = (
                        cursor.fetchone()[0]
                    )

                    # -----------------------------------------
                    # Store findings
                    # -----------------------------------------

                    findings_saved = 0

                    for finding in findings:

                        if not isinstance(
                            finding,
                            dict,
                        ):
                            continue

                        finding_id = (
                            finding.get(
                                "finding_id"
                            )
                            or generate_finding_id()
                        )

                        finding_type = str(
                            finding.get(
                                "type",
                                "unknown",
                            )
                        )

                        severity = str(
                            finding.get(
                                "severity",
                                "informational",
                            )
                        ).lower()

                        description = str(
                            finding.get(
                                "description",
                                "",
                            )
                        )

                        evidence = _safe_dict(
                            finding.get(
                                "evidence"
                            )
                        )

                        cursor.execute(
                            """
                            INSERT INTO findings (
                                finding_id,
                                investigation_id,
                                email_id,
                                gmail_message_id,
                                type,
                                severity,
                                description,
                                evidence,
                                created_at
                            )
                            VALUES (
                                %s,
                                %s,
                                %s,
                                %s,
                                %s,
                                %s,
                                %s,
                                %s,
                                NOW()
                            )
                            """,
                            (
                                finding_id,
                                investigation_id,
                                email_id,
                                gmail_message_id,
                                finding_type,
                                severity,
                                description,
                                Jsonb(
                                    evidence
                                ),
                            ),
                        )

                        findings_saved += 1

                    # -----------------------------------------
                    # IOC collection
                    # -----------------------------------------

                    urls = _safe_list(
                        parsed_email.get(
                            "urls"
                        )
                    )

                    domains = _safe_list(
                        parsed_email.get(
                            "domains"
                        )
                    )

                    ips = _safe_list(
                        parsed_email.get(
                            "ips"
                        )
                    )

                    hashes = []

                    evidence_hash = (
                        parsed_email.get(
                            "email_hash"
                        )
                        or parsed_email.get(
                            "sha256"
                        )
                        or parsed_email.get(
                            "evidence_hash"
                        )
                    )

                    if evidence_hash:

                        hashes.append(
                            str(
                                evidence_hash
                            )
                        )

                    ioc_map = {
                        "url": urls,
                        "domain": domains,
                        "ip": ips,
                        "hash": hashes,
                    }

                    iocs_saved = 0

                    # -----------------------------------------
                    # Store IOCs
                    # -----------------------------------------

                    for (
                        ioc_type,
                        values,
                    ) in ioc_map.items():

                        for value in values:

                            if value is None:
                                continue

                            value = str(
                                value
                            ).strip()

                            if not value:
                                continue

                            cursor.execute(
                                """
                                INSERT INTO iocs (
                                    investigation_id,
                                    type,
                                    value,
                                    created_at
                                )
                                VALUES (
                                    %s,
                                    %s,
                                    %s,
                                    NOW()
                                )

                                ON CONFLICT (
                                    investigation_id,
                                    type,
                                    value
                                )

                                DO NOTHING
                                """,
                                (
                                    investigation_id,
                                    ioc_type,
                                    value,
                                ),
                            )

                            if cursor.rowcount > 0:
                                iocs_saved += 1

                    # -----------------------------------------
                    # Investigation risk
                    # -----------------------------------------

                    score = int(
                        risk.get(
                            "score",
                            0,
                        )
                    )

                    score = max(
                        0,
                        min(
                            100,
                            score,
                        ),
                    )

                    severity = str(
                        risk.get(
                            "severity",
                            "informational",
                        )
                    )

                    classification = str(
                        risk.get(
                            "classification",
                            "unknown",
                        )
                    )

                    cursor.execute(
                        """
                        UPDATE investigations

                        SET
                            risk_score = %s,
                            risk_severity = %s,
                            classification = %s,
                            status = CASE
                                WHEN status = 'open'
                                    THEN 'investigating'
                                ELSE status
                            END,
                            updated_at = NOW()

                        WHERE id = %s
                        """,
                        (
                            score,
                            severity,
                            classification,
                            investigation_id,
                        ),
                    )

                    # -----------------------------------------
                    # Return only after everything succeeded
                    # -----------------------------------------

                    return {
                        "case_id": case_id,

                        "investigation_id": (
                            investigation_id
                        ),

                        "email_id": email_id,

                        "gmail_message_id": (
                            gmail_message_id
                        ),

                        "findings_saved": (
                            findings_saved
                        ),

                        "iocs_saved": (
                            iocs_saved
                        ),

                        "risk": {
                            "score": score,
                            "severity": severity,
                            "classification": (
                                classification
                            ),
                        },

                        "saved_at": (
                            utc_now()
                        ),
                    }

        finally:
            connection.close()

    # ========================================================
    # COMPLETE CASE
    # ========================================================

    @staticmethod
    def get_complete_investigation(
        case_id: str,
    ) -> dict[str, Any] | None:

        investigation = (
            InvestigationService
            .get_investigation(
                case_id
            )
        )

        if not investigation:
            return None

        investigation_id = (
            investigation["id"]
        )

        connection = get_db_connection()

        try:

            with connection.cursor() as cursor:

                # -----------------------------------------
                # Emails
                # -----------------------------------------

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

                    ORDER BY
                        analyzed_at ASC,
                        id ASC
                    """,
                    (
                        investigation_id,
                    ),
                )

                email_rows = (
                    cursor.fetchall()
                )

                emails = [
                    _row_to_dict(
                        cursor,
                        row,
                    )
                    for row in email_rows
                ]

                # -----------------------------------------
                # Findings
                # -----------------------------------------

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
                        created_at ASC
                    """,
                    (
                        investigation_id,
                    ),
                )

                finding_rows = (
                    cursor.fetchall()
                )

                findings = [
                    _row_to_dict(
                        cursor,
                        row,
                    )
                    for row in finding_rows
                ]

                # -----------------------------------------
                # IOCs
                # -----------------------------------------

                cursor.execute(
                    """
                    SELECT
                        id,
                        type,
                        value,
                        created_at

                    FROM iocs

                    WHERE investigation_id = %s

                    ORDER BY
                        type ASC,
                        value ASC
                    """,
                    (
                        investigation_id,
                    ),
                )

                ioc_rows = (
                    cursor.fetchall()
                )

                iocs = [
                    _row_to_dict(
                        cursor,
                        row,
                    )
                    for row in ioc_rows
                ]

                return {
                    "investigation": (
                        investigation
                    ),
                    "emails": emails,
                    "findings": findings,
                    "iocs": iocs,
                }

        finally:
            connection.close()

    # ========================================================
    # FINDINGS
    # ========================================================

    @staticmethod
    def get_findings(
        case_id: str,
    ) -> list[dict[str, Any]] | None:

        investigation = (
            InvestigationService
            .get_investigation(
                case_id
            )
        )

        if not investigation:
            return None

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
                        created_at ASC
                    """,
                    (
                        investigation["id"],
                    ),
                )

                rows = cursor.fetchall()

                return [
                    _row_to_dict(
                        cursor,
                        row,
                    )
                    for row in rows
                ]

        finally:
            connection.close()

    # ========================================================
    # IOCs
    # ========================================================

    @staticmethod
    def get_iocs(
        case_id: str,
    ) -> list[dict[str, Any]] | None:

        investigation = (
            InvestigationService
            .get_investigation(
                case_id
            )
        )

        if not investigation:
            return None

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

                    ORDER BY
                        type ASC,
                        value ASC
                    """,
                    (
                        investigation["id"],
                    ),
                )

                rows = cursor.fetchall()

                return [
                    _row_to_dict(
                        cursor,
                        row,
                    )
                    for row in rows
                ]

        finally:
            connection.close()

    # ========================================================
    # DELETE
    # ========================================================

    @staticmethod
    def delete_investigation(
        case_id: str,
    ) -> bool:

        connection = get_db_connection()

        try:

            with connection.transaction():

                with connection.cursor() as cursor:

                    cursor.execute(
                        """
                        DELETE FROM investigations

                        WHERE case_id = %s

                        RETURNING id
                        """,
                        (
                            case_id,
                        ),
                    )

                    deleted = (
                        cursor.fetchone()
                    )

                    return (
                        deleted is not None
                    )

        finally:
            connection.close()