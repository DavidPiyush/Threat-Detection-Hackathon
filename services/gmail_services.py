import base64
from typing import Any

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from routes.auth import google_tokens


# ============================================================
# GMAIL SERVICE
# ============================================================
#
# Responsibilities:
#
#   - Get authenticated Gmail credentials
#   - Create Gmail API service
#   - Get Gmail profile
#   - List Gmail messages
#   - Get a Gmail message
#   - Convert Gmail API message -> raw email
#
# Does NOT:
#
#   - Parse email forensics
#   - Detect phishing
#   - Calculate risk
#   - Perform threat intelligence
#
# Those responsibilities belong to other services.
# ============================================================


class GmailServiceError(Exception):
    """
    Custom exception for Gmail service failures.
    """

    pass


class GmailService:
    """
    Service layer for Gmail API operations.
    """

    def __init__(self):
        self.service = self._build_service()

    # ========================================================
    # CREDENTIALS
    # ========================================================

    @staticmethod
    def _get_credentials() -> Credentials:
        """
        Build Google OAuth credentials from the credentials
        stored by routes.auth.
        """

        token_data = google_tokens.get(
            "default"
        )

        if not token_data:
            raise GmailServiceError(
                "Google authentication required. "
                "Visit /auth/google first."
            )

        try:

            credentials = Credentials(
                token=token_data.get(
                    "token"
                ),
                refresh_token=token_data.get(
                    "refresh_token"
                ),
                token_uri=token_data.get(
                    "token_uri"
                ),
                client_id=token_data.get(
                    "client_id"
                ),
                client_secret=token_data.get(
                    "client_secret"
                ),
                scopes=token_data.get(
                    "scopes"
                ),
            )

            return credentials

        except Exception as exc:

            raise GmailServiceError(
                f"Unable to create Gmail credentials: {exc}"
            ) from exc

    # ========================================================
    # BUILD GMAIL API SERVICE
    # ========================================================

    @classmethod
    def _build_service(cls):
        """
        Create Gmail API client.
        """

        credentials = cls._get_credentials()

        try:

            return build(
                "gmail",
                "v1",
                credentials=credentials,
                cache_discovery=False,
            )

        except Exception as exc:

            raise GmailServiceError(
                f"Unable to initialize Gmail API: {exc}"
            ) from exc

    # ========================================================
    # PROFILE
    # ========================================================

    def get_profile(self) -> dict:
        """
        Get authenticated Gmail profile.
        """

        try:

            profile = (
                self.service.users()
                .getProfile(
                    userId="me"
                )
                .execute()
            )

            return {
                "email": profile.get(
                    "emailAddress"
                ),
                "messages_total": profile.get(
                    "messagesTotal"
                ),
                "threads_total": profile.get(
                    "threadsTotal"
                ),
                "history_id": profile.get(
                    "historyId"
                ),
            }

        except HttpError as exc:

            raise GmailServiceError(
                f"Gmail profile request failed: {exc}"
            ) from exc

        except Exception as exc:

            raise GmailServiceError(
                f"Gmail profile error: {exc}"
            ) from exc

    # ========================================================
    # LIST MESSAGES
    # ========================================================

    def list_messages(
        self,
        max_results: int = 20,
        page_token: str | None = None,
        query: str | None = None,
        label_ids: list[str] | None = None,
    ) -> dict:
        """
        List Gmail messages.

        Parameters
        ----------
        max_results:
            Maximum number of messages returned.

        page_token:
            Gmail pagination token.

        query:
            Gmail search query.

            Example:
                "is:unread"
                "from:example.com"
                "subject:invoice"

        label_ids:
            Optional Gmail label filters.
        """

        # Keep API requests bounded.
        max_results = max(
            1,
            min(
                max_results,
                100,
            ),
        )

        try:

            request_kwargs = {
                "userId": "me",
                "maxResults": max_results,
            }

            if page_token:
                request_kwargs[
                    "pageToken"
                ] = page_token

            if query:
                request_kwargs[
                    "q"
                ] = query

            if label_ids:
                request_kwargs[
                    "labelIds"
                ] = label_ids

            response = (
                self.service.users()
                .messages()
                .list(
                    **request_kwargs
                )
                .execute()
            )

            messages = (
                response.get(
                    "messages",
                    []
                )
            )

            return {
                "messages": messages,
                "count": len(messages),
                "next_page_token": (
                    response.get(
                        "nextPageToken"
                    )
                ),
                "result_size_estimate": (
                    response.get(
                        "resultSizeEstimate"
                    )
                ),
            }

        except HttpError as exc:

            raise GmailServiceError(
                f"Gmail message listing failed: {exc}"
            ) from exc

        except Exception as exc:

            raise GmailServiceError(
                f"Gmail message listing error: {exc}"
            ) from exc

    # ========================================================
    # GET MESSAGE
    # ========================================================

    def get_message(
        self,
        message_id: str,
        format: str = "full",
    ) -> dict:
        """
        Retrieve a Gmail message.

        Supported Gmail formats include:

            minimal
            full
            raw
            metadata
        """

        allowed_formats = {
            "minimal",
            "full",
            "raw",
            "metadata",
        }

        if format not in allowed_formats:

            raise GmailServiceError(
                f"Unsupported Gmail message format: {format}"
            )

        if not message_id:

            raise GmailServiceError(
                "Gmail message ID is required."
            )

        try:

            message = (
                self.service.users()
                .messages()
                .get(
                    userId="me",
                    id=message_id,
                    format=format,
                )
                .execute()
            )

            return message

        except HttpError as exc:

            raise GmailServiceError(
                f"Gmail message retrieval failed: {exc}"
            ) from exc

        except Exception as exc:

            raise GmailServiceError(
                f"Gmail message retrieval error: {exc}"
            ) from exc

    # ========================================================
    # GET RAW MESSAGE
    # ========================================================

    def get_raw_message(
        self,
        message_id: str,
    ) -> bytes:
        """
        Retrieve the original Gmail message as RFC 5322 bytes.

        This is the preferred method for forensic analysis
        because it preserves the original message representation
        returned by Gmail.
        """

        if not message_id:

            raise GmailServiceError(
                "Gmail message ID is required."
            )

        try:

            message = (
                self.service.users()
                .messages()
                .get(
                    userId="me",
                    id=message_id,
                    format="raw",
                )
                .execute()
            )

            raw_data = message.get(
                "raw"
            )

            if not raw_data:

                raise GmailServiceError(
                    "Gmail returned an empty raw message."
                )

            try:

                return base64.urlsafe_b64decode(
                    raw_data
                    + "="
                    * (
                        -len(raw_data)
                        % 4
                    )
                )

            except Exception as exc:

                raise GmailServiceError(
                    f"Unable to decode Gmail raw message: {exc}"
                ) from exc

        except GmailServiceError:
            raise

        except HttpError as exc:

            raise GmailServiceError(
                f"Gmail raw message retrieval failed: {exc}"
            ) from exc

        except Exception as exc:

            raise GmailServiceError(
                f"Gmail raw message error: {exc}"
            ) from exc

    # ========================================================
    # GMAIL MESSAGE -> RAW EMAIL
    # ========================================================

    def message_to_raw(
        self,
        message: dict,
    ) -> bytes:
        """
        Convert a Gmail API 'full' message object into an
        RFC-like email representation.

        NOTE:
        For forensic fidelity, prefer get_raw_message().

        This method exists for compatibility with situations
        where a 'full' Gmail API message has already been fetched.
        """

        payload = message.get(
            "payload",
            {}
        )

        raw_parts = []

        # ----------------------------------------------------
        # Headers
        # ----------------------------------------------------

        headers = payload.get(
            "headers",
            []
        )

        for header in headers:

            name = header.get(
                "name"
            )

            value = header.get(
                "value"
            )

            if name and value:

                raw_parts.append(
                    f"{name}: {value}"
                )

        raw_parts.append("")

        # ----------------------------------------------------
        # Body
        # ----------------------------------------------------

        body_parts = []

        self._collect_body_parts(
            payload,
            body_parts,
        )

        raw_parts.append(
            "\n".join(
                body_parts
            )
        )

        return "\n".join(
            raw_parts
        ).encode(
            "utf-8",
            errors="replace",
        )

    # ========================================================
    # RECURSIVE BODY EXTRACTION
    # ========================================================

    @classmethod
    def _collect_body_parts(
        cls,
        part: dict,
        output: list[str],
    ) -> None:
        """
        Recursively collect text/plain and text/html body
        content from Gmail MIME parts.
        """

        mime_type = part.get(
            "mimeType",
            "",
        )

        body = part.get(
            "body",
            {}
        )

        data = body.get(
            "data"
        )

        if data and mime_type in {
            "text/plain",
            "text/html",
        }:

            try:

                decoded = base64.urlsafe_b64decode(
                    data
                    + "="
                    * (
                        -len(data)
                        % 4
                    )
                ).decode(
                    "utf-8",
                    errors="replace",
                )

                output.append(
                    decoded
                )

            except Exception:
                pass

        for child in part.get(
            "parts",
            []
        ):

            cls._collect_body_parts(
                child,
                output,
            )

    # ========================================================
    # MESSAGE METADATA
    # ========================================================

    @staticmethod
    def extract_message_metadata(
        message: dict,
    ) -> dict:
        """
        Extract lightweight metadata without performing
        forensic analysis.
        """

        payload = message.get(
            "payload",
            {}
        )

        headers = payload.get(
            "headers",
            []
        )

        header_map = {}

        for header in headers:

            name = header.get(
                "name"
            )

            value = header.get(
                "value"
            )

            if name and value:

                header_map[
                    name.lower()
                ] = value

        return {
            "message_id": message.get(
                "id"
            ),
            "thread_id": message.get(
                "threadId"
            ),
            "label_ids": message.get(
                "labelIds",
                []
            ),
            "internal_date": message.get(
                "internalDate"
            ),
            "size_estimate": message.get(
                "sizeEstimate"
            ),
            "snippet": message.get(
                "snippet"
            ),
            "subject": header_map.get(
                "subject"
            ),
            "from": header_map.get(
                "from"
            ),
            "to": header_map.get(
                "to"
            ),
            "date": header_map.get(
                "date"
            ),
        }


# ============================================================
# CONVENIENCE FUNCTIONS
# ============================================================

def get_gmail_service() -> GmailService:
    """
    Return an initialized GmailService.
    """

    return GmailService()


def get_gmail_profile() -> dict:
    """
    Convenience wrapper for Gmail profile.
    """

    service = GmailService()

    return service.get_profile()


def list_gmail_messages(
    max_results: int = 20,
    page_token: str | None = None,
    query: str | None = None,
    label_ids: list[str] | None = None,
) -> dict:
    """
    Convenience wrapper for listing messages.
    """

    service = GmailService()

    return service.list_messages(
        max_results=max_results,
        page_token=page_token,
        query=query,
        label_ids=label_ids,
    )


def get_gmail_message(
    message_id: str,
    format: str = "full",
) -> dict:
    """
    Convenience wrapper for retrieving a Gmail message.
    """

    service = GmailService()

    return service.get_message(
        message_id=message_id,
        format=format,
    )


def get_gmail_raw_message(
    message_id: str,
) -> bytes:
    """
    Convenience wrapper for retrieving the original raw
    Gmail message.
    """

    service = GmailService()

    return service.get_raw_message(
        message_id
    )