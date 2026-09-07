from fastapi import APIRouter, HTTPException

from services.gmail_services import (
    GmailService,
    GmailServiceError,
)


router = APIRouter(
    prefix="/gmail",
    tags=["Gmail"],
)


# ============================================================
# PROFILE
# ============================================================

@router.get("/profile")
async def gmail_profile():

    try:

        service = GmailService()

        profile = service.get_profile()

        return {
            "success": True,
            **profile,
        }

    except GmailServiceError as exc:

        raise HTTPException(
            status_code=401,
            detail=str(exc),
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=f"Gmail profile error: {exc}",
        )


# ============================================================
# LIST MESSAGES
# ============================================================

@router.get("/messages")
async def get_gmail_messages(
    max_results: int = 20,
    page_token: str | None = None,
    query: str | None = None,
):

    try:

        service = GmailService()

        result = service.list_messages(
            max_results=max_results,
            page_token=page_token,
            query=query,
        )

        return {
            "success": True,
            **result,
        }

    except GmailServiceError as exc:

        raise HTTPException(
            status_code=401,
            detail=str(exc),
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=f"Gmail messages error: {exc}",
        )


# ============================================================
# GET MESSAGE
# ============================================================

@router.get("/messages/{message_id}")
async def get_gmail_message(
    message_id: str,
):

    try:

        service = GmailService()

        message = service.get_message(
            message_id=message_id,
            format="full",
        )

        metadata = (
            service.extract_message_metadata(
                message
            )
        )

        return {
            "success": True,
            "metadata": metadata,
            "message": message,
        }

    except GmailServiceError as exc:

        raise HTTPException(
            status_code=401,
            detail=str(exc),
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=f"Gmail message error: {exc}",
        )