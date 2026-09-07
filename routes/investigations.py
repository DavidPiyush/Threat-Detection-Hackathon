from fastapi import APIRouter, HTTPException, Query

from models.investigation import (
    InvestigationCreate,
    InvestigationUpdate,
)

from services.investigation_services import InvestigationService
from services.gmail_services import (
    GmailService,
    GmailServiceError,
)

from routes.analysis import _analyze_raw_email


router = APIRouter(
    prefix="/investigations",
    tags=["Investigations"],
)


# ============================================================
# CREATE INVESTIGATION
# ============================================================

@router.post("")
async def create_investigation(request: InvestigationCreate):
    """
    Create a new investigation case.
    """

    try:
        result = InvestigationService.create_investigation(
            title=request.title,
            description=request.description,
            priority=request.priority,
            analyst=request.analyst,
        )

        return {
            "success": True,
            "message": "Investigation created successfully",
            "data": result,
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create investigation: {exc}",
        )


# ============================================================
# LIST INVESTIGATIONS
# ============================================================

@router.get("")
async def list_investigations(
    status: str | None = Query(default=None),
    priority: str | None = Query(default=None),
    analyst: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    """
    List investigation cases.

    Supports optional filtering by:
    - status
    - priority
    - analyst
    """

    try:
        result = InvestigationService.list_investigations(
            status=status,
            priority=priority,
            analyst=analyst,
            limit=limit,
            offset=offset,
        )

        return {
            "success": True,
            **result,
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list investigations: {exc}",
        )


# ============================================================
# GET COMPLETE INVESTIGATION
# ============================================================

@router.get("/{case_id}")
async def get_investigation(case_id: str):
    """
    Get complete investigation including:

    - case metadata
    - analyzed emails
    - findings
    - IOCs
    - risk information
    """

    try:
        result = InvestigationService.get_complete_investigation(
            case_id
        )

        if not result:
            raise HTTPException(
                status_code=404,
                detail=f"Investigation '{case_id}' not found",
            )

        return {
            "success": True,
            "data": result,
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve investigation: {exc}",
        )


# ============================================================
# UPDATE INVESTIGATION
# ============================================================

@router.patch("/{case_id}")
async def update_investigation(
    case_id: str,
    request: InvestigationUpdate,
):
    """
    Update investigation metadata.

    Possible fields:
    - title
    - description
    - priority
    - status
    - analyst
    - notes
    """

    try:
        update_data = request.model_dump(
            exclude_unset=True
        )

        if not update_data:
            raise HTTPException(
                status_code=400,
                detail="No fields provided for update",
            )

        result = InvestigationService.update_investigation(
            case_id=case_id,
            **update_data,
        )

        if not result:
            raise HTTPException(
                status_code=404,
                detail=f"Investigation '{case_id}' not found",
            )

        return {
            "success": True,
            "message": "Investigation updated successfully",
            "data": result,
        }

    except HTTPException:
        raise

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update investigation: {exc}",
        )


# ============================================================
# ANALYZE GMAIL MESSAGE INSIDE CASE
# ============================================================

@router.post(
    "/{case_id}/analyze-gmail/{message_id}"
)
async def analyze_gmail_message(
    case_id: str,
    message_id: str,
):
    """
    Fetch a Gmail message as raw RFC 5322 email,
    analyze it and persist the complete result
    into the investigation.
    """

    # --------------------------------------------------------
    # Verify investigation exists
    # --------------------------------------------------------

    try:
        investigation = InvestigationService.get_investigation(
            case_id
        )

        if not investigation:
            raise HTTPException(
                status_code=404,
                detail=f"Investigation '{case_id}' not found",
            )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to verify investigation: {exc}",
        )

    # --------------------------------------------------------
    # Fetch Gmail message
    # --------------------------------------------------------

    try:
        gmail = GmailService()

        raw_email = gmail.get_raw_message(
            message_id
        )

    except GmailServiceError as exc:
        raise HTTPException(
            status_code=401,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve Gmail message: {exc}",
        )

    # --------------------------------------------------------
    # Analyze email
    # --------------------------------------------------------

    try:
        analysis_result = _analyze_raw_email(
            raw_email=raw_email,
            gmail_message_id=message_id,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Email analysis failed: {exc}",
        )

    # --------------------------------------------------------
    # Persist analysis atomically
    # --------------------------------------------------------

    try:
        saved_result = InvestigationService.save_analysis(
            case_id=case_id,
            analysis=analysis_result,
            gmail_message_id=message_id,
        )

        return {
            "success": True,
            "message": "Gmail message analyzed and saved",
            "data": saved_result,
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to save analysis: {exc}",
        )


# ============================================================
# GET FINDINGS
# ============================================================

@router.get("/{case_id}/findings")
async def get_findings(
    case_id: str,
    severity: str | None = Query(default=None),
    finding_type: str | None = Query(default=None),
):
    """
    Retrieve findings belonging to an investigation.
    """

    try:
        investigation = InvestigationService.get_investigation(
            case_id
        )

        if not investigation:
            raise HTTPException(
                status_code=404,
                detail=f"Investigation '{case_id}' not found",
            )

        findings = InvestigationService.get_findings(
            case_id=case_id,
            severity=severity,
            finding_type=finding_type,
        )

        return {
            "success": True,
            "case_id": case_id,
            "count": len(findings),
            "findings": findings,
        }

    except HTTPException:
        raise

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve findings: {exc}",
        )


# ============================================================
# GET IOCs
# ============================================================

@router.get("/{case_id}/iocs")
async def get_iocs(
    case_id: str,
    ioc_type: str | None = Query(default=None),
):
    """
    Retrieve IOCs associated with an investigation.
    """

    try:
        investigation = InvestigationService.get_investigation(
            case_id
        )

        if not investigation:
            raise HTTPException(
                status_code=404,
                detail=f"Investigation '{case_id}' not found",
            )

        iocs = InvestigationService.get_iocs(
            case_id=case_id,
            ioc_type=ioc_type,
        )

        return {
            "success": True,
            "case_id": case_id,
            "count": len(iocs),
            "iocs": iocs,
        }

    except HTTPException:
        raise

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve IOCs: {exc}",
        )


# ============================================================
# DELETE INVESTIGATION
# ============================================================

@router.delete("/{case_id}")
async def delete_investigation(case_id: str):
    """
    Delete an investigation and its dependent data.

    PostgreSQL foreign keys with ON DELETE CASCADE
    remove associated emails, findings and IOCs.
    """

    try:
        deleted = InvestigationService.delete_investigation(
            case_id
        )

        if not deleted:
            raise HTTPException(
                status_code=404,
                detail=f"Investigation '{case_id}' not found",
            )

        return {
            "success": True,
            "message": "Investigation deleted successfully",
            "case_id": case_id,
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete investigation: {exc}",
        )