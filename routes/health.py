"""
Health Check Routes
===================

Provides backend and service health information.

Endpoints:
    GET /health
    GET /health/services
    GET /health/database
    GET /health/threat-intel
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter

from database.connect import get_db_connection
from services.domain_intelligence import (
    get_domain_intelligence_status,
)
from services.ip_intelligence import (
    get_ip_intelligence_status,
)
from services.risk_engine import (
    MIN_SCORE,
    MAX_SCORE,
)
from services.threat_intel import (
    get_threat_intel_status,
)
from services.url_analyzer import (
    get_url_analyzer_status,
)


router = APIRouter(
    prefix="/health",
    tags=["Health"],
)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def utc_now() -> str:
    """
    Return current UTC timestamp.
    """

    return datetime.now(
        timezone.utc
    ).isoformat()


# ---------------------------------------------------------------------------
# Basic Health
# ---------------------------------------------------------------------------


@router.get("")
async def health_check() -> dict[str, Any]:
    """
    Basic API health check.

    Returns HTTP 200 when the FastAPI application itself is running.
    """

    return {
        "success": True,
        "status": "healthy",
        "service": "ThreatDetect API",
        "timestamp": utc_now(),
    }


# ---------------------------------------------------------------------------
# Database Health
# ---------------------------------------------------------------------------


@router.get("/database")
async def database_health() -> dict[str, Any]:
    """
    Check PostgreSQL connectivity.
    """

    connection = None

    try:
        connection = get_db_connection()

        with connection.cursor() as cursor:

            cursor.execute(
                "SELECT version();"
            )

            row = cursor.fetchone()

        return {
            "success": True,
            "status": "healthy",
            "database": "PostgreSQL",
            "version": (
                row[0]
                if row
                else None
            ),
            "timestamp": utc_now(),
        }

    except Exception as exc:

        return {
            "success": False,
            "status": "unhealthy",
            "database": "PostgreSQL",
            "error": str(exc),
            "timestamp": utc_now(),
        }

    finally:

        if connection is not None:

            try:
                connection.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Threat Intelligence Health
# ---------------------------------------------------------------------------


@router.get("/threat-intel")
async def threat_intel_health() -> dict[str, Any]:
    """
    Return configured threat-intelligence providers.

    API keys themselves are never exposed.
    """

    try:

        status = get_threat_intel_status()

        return {
            "success": True,
            "status": status.get(
                "status",
                "unknown",
            ),
            **status,
            "timestamp": utc_now(),
        }

    except Exception as exc:

        return {
            "success": False,
            "status": "unhealthy",
            "service": "threat_intelligence",
            "error": str(exc),
            "timestamp": utc_now(),
        }


# ---------------------------------------------------------------------------
# Individual Service Health
# ---------------------------------------------------------------------------


@router.get("/services")
async def services_health() -> dict[str, Any]:
    """
    Return health/capability information for internal services.
    """

    services = {}

    # ---------------------------------------------------------------
    # IP Intelligence
    # ---------------------------------------------------------------

    try:

        services["ip_intelligence"] = (
            get_ip_intelligence_status()
        )

    except Exception as exc:

        services["ip_intelligence"] = {
            "status": "unhealthy",
            "error": str(exc),
        }

    # ---------------------------------------------------------------
    # Domain Intelligence
    # ---------------------------------------------------------------

    try:

        services["domain_intelligence"] = (
            get_domain_intelligence_status()
        )

    except Exception as exc:

        services["domain_intelligence"] = {
            "status": "unhealthy",
            "error": str(exc),
        }

    # ---------------------------------------------------------------
    # URL Analyzer
    # ---------------------------------------------------------------

    try:

        services["url_analyzer"] = (
            get_url_analyzer_status()
        )

    except Exception as exc:

        services["url_analyzer"] = {
            "status": "unhealthy",
            "error": str(exc),
        }

    # ---------------------------------------------------------------
    # Threat Intelligence
    # ---------------------------------------------------------------

    try:

        services["threat_intelligence"] = (
            get_threat_intel_status()
        )

    except Exception as exc:

        services["threat_intelligence"] = {
            "status": "unhealthy",
            "error": str(exc),
        }

    # ---------------------------------------------------------------
    # Risk Engine
    # ---------------------------------------------------------------

    services["risk_engine"] = {
        "service": "risk_engine",
        "status": "ready",
        "score_range": {
            "minimum": MIN_SCORE,
            "maximum": MAX_SCORE,
        },
    }

    # ---------------------------------------------------------------
    # Overall Status
    # ---------------------------------------------------------------

    unhealthy_services = [
        name
        for name, service in services.items()
        if service.get("status")
        not in {
            "ready",
            "healthy",
        }
    ]

    overall_status = (
        "degraded"
        if unhealthy_services
        else "healthy"
    )

    return {
        "success": True,
        "status": overall_status,
        "services": services,
        "unhealthy_services": unhealthy_services,
        "timestamp": utc_now(),
    }


# ---------------------------------------------------------------------------
# Full System Health
# ---------------------------------------------------------------------------


@router.get("/full")
async def full_health_check() -> dict[str, Any]:
    """
    Combined application, database and service health.

    This endpoint will be useful during final integration testing.
    """

    # ---------------------------------------------------------------
    # Database
    # ---------------------------------------------------------------

    database_connection = None

    database_status = "unhealthy"
    database_error = None
    database_version = None

    try:

        database_connection = get_db_connection()

        with database_connection.cursor() as cursor:

            cursor.execute(
                "SELECT version();"
            )

            row = cursor.fetchone()

            database_version = (
                row[0]
                if row
                else None
            )

        database_status = "healthy"

    except Exception as exc:

        database_error = str(exc)

    finally:

        if database_connection is not None:

            try:
                database_connection.close()
            except Exception:
                pass

    # ---------------------------------------------------------------
    # Internal Services
    # ---------------------------------------------------------------

    service_statuses = {}

    service_functions = {
        "ip_intelligence":
            get_ip_intelligence_status,

        "domain_intelligence":
            get_domain_intelligence_status,

        "url_analyzer":
            get_url_analyzer_status,

        "threat_intelligence":
            get_threat_intel_status,
    }

    for name, function in service_functions.items():

        try:

            service_statuses[name] = function()

        except Exception as exc:

            service_statuses[name] = {
                "status": "unhealthy",
                "error": str(exc),
            }

    # ---------------------------------------------------------------
    # Determine Overall Health
    # ---------------------------------------------------------------

    unhealthy = []

    if database_status != "healthy":
        unhealthy.append("database")

    for name, service in service_statuses.items():

        if service.get("status") not in {
            "ready",
            "healthy",
        }:

            unhealthy.append(name)

    if unhealthy:

        overall_status = "degraded"

    else:

        overall_status = "healthy"

    return {
        "success": True,
        "status": overall_status,
        "timestamp": utc_now(),
        "application": {
            "name": "ThreatDetect API",
            "status": "healthy",
        },
        "database": {
            "status": database_status,
            "engine": "PostgreSQL",
            "version": database_version,
            "error": database_error,
        },
        "services": service_statuses,
        "risk_engine": {
            "status": "ready",
            "score_range": {
                "minimum": MIN_SCORE,
                "maximum": MAX_SCORE,
            },
        },
        "unhealthy_components": unhealthy,
    }


# ---------------------------------------------------------------------------
# Router Export
# ---------------------------------------------------------------------------


__all__ = [
    "router",
]