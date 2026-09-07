import hashlib
import html
import ipaddress
import re

from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse


# ============================================================
# EMAIL PARSER
# ============================================================
#
# Responsibilities:
#   - Parse RFC 5322 email
#   - Extract headers
#   - Extract body
#   - Extract URLs
#   - Extract IP addresses
#   - Extract domains
#   - Extract attachments
#   - Analyze Received headers
#   - Parse Authentication-Results
#   - Build deterministic email metadata
#   - Calculate SHA-256 evidence hash
#
# This module DOES NOT:
#   - Decide whether an email is malicious
#   - Calculate the final risk score
#   - Call threat-intelligence APIs
#   - Perform GeoIP lookups
#   - Perform DNS/RDAP lookups
#
# Those belong to separate analysis/intelligence services.
# ============================================================


# ============================================================
# CONSTANTS
# ============================================================

URL_REGEX = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE,
)

IP_REGEX = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

DANGEROUS_ATTACHMENT_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".js",
    ".vbs",
    ".vbe",
    ".ps1",
    ".hta",
    ".jar",
    ".iso",
    ".img",
    ".lnk",
    ".docm",
    ".xlsm",
    ".pptm",
}


# ============================================================
# GENERAL HELPERS
# ============================================================

def sha256_bytes(data: bytes) -> str:
    """
    Calculate SHA-256 hash of raw email bytes.

    This is the primary evidence fingerprint for the email.
    """

    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """
    Calculate SHA-256 hash of text.
    """

    return sha256_bytes(
        text.encode(
            "utf-8",
            errors="replace",
        )
    )


def clean_text(value: str | None) -> str:
    """
    Normalize whitespace and HTML entities.
    """

    if not value:
        return ""

    value = html.unescape(value)

    value = re.sub(
        r"\s+",
        " ",
        value,
    )

    return value.strip()


def unique_list(
    values: list[str],
) -> list[str]:
    """
    Preserve order while removing duplicates.
    """

    result = []
    seen = set()

    for value in values:

        if not value:
            continue

        if value not in seen:

            seen.add(value)
            result.append(value)

    return result


def normalize_domain(
    domain: str | None,
) -> str | None:
    """
    Normalize a domain name.
    """

    if not domain:
        return None

    domain = (
        domain
        .strip()
        .lower()
        .rstrip(".")
    )

    if domain.startswith("@"):
        domain = domain[1:]

    return domain or None


def extract_email_address(
    value: str | None,
) -> str | None:
    """
    Extract the actual email address from a header.

    Example:

        John Doe <john@example.com>

    becomes:

        john@example.com
    """

    if not value:
        return None

    _, address = parseaddr(value)

    if not address:
        return None

    return address.lower().strip()


def extract_domain_from_email(
    value: str | None,
) -> str | None:
    """
    Extract domain from an email address/header.
    """

    address = extract_email_address(value)

    if not address:
        return None

    if "@" not in address:
        return None

    domain = address.split(
        "@",
        1,
    )[1]

    return normalize_domain(domain)


# ============================================================
# EMAIL PARSER CLASS
# ============================================================

class EmailParser:
    """
    Deterministic RFC 5322 email parser.

    The parser accepts raw bytes or raw text and produces
    structured forensic metadata.
    """

    def __init__(
        self,
        raw_email: bytes | str,
    ):
        self.raw_bytes = self._normalize_input(
            raw_email
        )

        self.email_hash = sha256_bytes(
            self.raw_bytes
        )

        try:

            self.message: Message = (
                BytesParser(
                    policy=policy.default
                ).parsebytes(
                    self.raw_bytes
                )
            )

        except Exception as exc:

            raise ValueError(
                f"Unable to parse email: {exc}"
            ) from exc

    # ========================================================
    # INPUT
    # ========================================================

    @staticmethod
    def _normalize_input(
        raw_email: bytes | str,
    ) -> bytes:

        if isinstance(
            raw_email,
            bytes,
        ):
            return raw_email

        if isinstance(
            raw_email,
            str,
        ):
            return raw_email.encode(
                "utf-8",
                errors="replace",
            )

        raise TypeError(
            "raw_email must be bytes or str"
        )

    # ========================================================
    # HEADERS
    # ========================================================

    def get_header(
        self,
        name: str,
    ) -> str | None:

        value = self.message.get(name)

        if value is None:
            return None

        return str(value).strip()

    def get_all_headers(
        self,
        name: str,
    ) -> list[str]:

        values = self.message.get_all(
            name,
            [],
        )

        return [
            str(value).strip()
            for value in values
            if value
        ]

    def extract_headers(self) -> dict:
        """
        Extract important email headers.
        """

        return {
            "from": self.get_header("From"),
            "to": self.get_header("To"),
            "cc": self.get_header("Cc"),
            "bcc": self.get_header("Bcc"),
            "reply_to": self.get_header("Reply-To"),
            "return_path": self.get_header("Return-Path"),
            "subject": self.get_header("Subject"),
            "date": self.get_header("Date"),
            "message_id": self.get_header("Message-ID"),
            "in_reply_to": self.get_header("In-Reply-To"),
            "references": self.get_header("References"),
            "delivered_to": self.get_header("Delivered-To"),
            "authentication_results": (
                self.get_all_headers(
                    "Authentication-Results"
                )
            ),
            "received": self.get_all_headers(
                "Received"
            ),
            "dkim_signature": (
                self.get_all_headers(
                    "DKIM-Signature"
                )
            ),
            "arc_authentication_results": (
                self.get_all_headers(
                    "ARC-Authentication-Results"
                )
            ),
            "arc_seal": (
                self.get_all_headers(
                    "ARC-Seal"
                )
            ),
            "arc_message_signature": (
                self.get_all_headers(
                    "ARC-Message-Signature"
                )
            ),
            "x_originating_ip": (
                self.get_all_headers(
                    "X-Originating-IP"
                )
            ),
        }

    # ========================================================
    # SENDER IDENTITY
    # ========================================================

    def extract_identity(self) -> dict:
        """
        Extract sender identity relationships.

        Important distinction:

        From:
            User-visible sender identity.

        Reply-To:
            Address to which replies are directed.

        Return-Path:
            SMTP envelope return address.

        A difference does not automatically mean maliciousness.
        """

        from_header = self.get_header(
            "From"
        )

        reply_to = self.get_header(
            "Reply-To"
        )

        return_path = self.get_header(
            "Return-Path"
        )

        sender_name, sender_address = (
            parseaddr(
                from_header or ""
            )
        )

        sender_email = (
            extract_email_address(
                from_header
            )
        )

        sender_domain = (
            extract_domain_from_email(
                from_header
            )
        )

        reply_to_email = (
            extract_email_address(
                reply_to
            )
        )

        reply_to_domain = (
            extract_domain_from_email(
                reply_to
            )
        )

        return_path_email = (
            extract_email_address(
                return_path
            )
        )

        return_path_domain = (
            extract_domain_from_email(
                return_path
            )
        )

        return {
            "sender_name": (
                sender_name.strip()
                if sender_name
                else None
            ),
            "sender": from_header,
            "sender_email": sender_email,
            "sender_domain": sender_domain,
            "reply_to": reply_to,
            "reply_to_email": reply_to_email,
            "reply_to_domain": reply_to_domain,
            "return_path": return_path,
            "return_path_email": return_path_email,
            "return_path_domain": return_path_domain,
        }

    # ========================================================
    # BODY
    # ========================================================

    def extract_body(
        self,
    ) -> dict:
        """
        Extract both plain-text and HTML body.

        We retain both representations because HTML structure
        can be useful for later phishing analysis.
        """

        plain_parts = []
        html_parts = []

        if self.message.is_multipart():

            for part in self.message.walk():

                content_type = (
                    part.get_content_type()
                )

                if content_type == "text/plain":

                    try:
                        content = part.get_content()
                    except Exception:
                        content = ""

                    if content:
                        plain_parts.append(
                            str(content)
                        )

                elif content_type == "text/html":

                    try:
                        content = part.get_content()
                    except Exception:
                        content = ""

                    if content:
                        html_parts.append(
                            str(content)
                        )

        else:

            content_type = (
                self.message.get_content_type()
            )

            try:
                content = (
                    self.message.get_content()
                )
            except Exception:
                content = ""

            if content_type == "text/plain":
                plain_parts.append(
                    str(content)
                )

            elif content_type == "text/html":
                html_parts.append(
                    str(content)
                )

        plain_text = clean_text(
            "\n".join(
                plain_parts
            )
        )

        html_text = (
            "\n".join(
                html_parts
            )
        )

        html_text_clean = clean_text(
            re.sub(
                r"<[^>]+>",
                " ",
                html_text,
            )
        )

        # Prefer plain text when available.
        visible_text = (
            plain_text
            if plain_text
            else html_text_clean
        )

        return {
            "plain_text": plain_text,
            "html": html_text,
            "visible_text": visible_text,
            "plain_text_length": len(
                plain_text
            ),
            "html_length": len(
                html_text
            ),
        }

    # ========================================================
    # URL EXTRACTION
    # ========================================================

    def extract_urls(
        self,
        body: dict | None = None,
    ) -> list[str]:
        """
        Extract URLs from:

        1. Plain/visible body
        2. HTML href attributes

        HTML entities are normalized before deduplication.
        """

        if body is None:
            body = self.extract_body()

        urls = []

        visible_text = body.get(
            "visible_text",
            "",
        )

        html_content = body.get(
            "html",
            "",
        )

        # ----------------------------------------------------
        # URLs from visible text
        # ----------------------------------------------------

        urls.extend(
            URL_REGEX.findall(
                html.unescape(
                    visible_text
                )
            )
        )

        # ----------------------------------------------------
        # URLs from HTML
        # ----------------------------------------------------

        html_content = html.unescape(
            html_content
        )

        hrefs = re.findall(
            r'href\s*=\s*["\']'
            r'(https?://[^"\']+)'
            r'["\']',
            html_content,
            re.IGNORECASE,
        )

        urls.extend(
            hrefs
        )

        normalized = []

        for url in urls:

            url = html.unescape(
                url
            ).strip()

            # Remove punctuation commonly captured
            # immediately after URLs.
            url = url.rstrip(
                ".,;:!?)]}>\"'"
            )

            if not url:
                continue

            normalized.append(
                url
            )

        return unique_list(
            normalized
        )

    # ========================================================
    # URL METADATA
    # ========================================================

    def analyze_url_structure(
        self,
        urls: list[str],
    ) -> list[dict]:
        """
        Extract structural metadata from URLs.

        No reputation lookup is performed here.
        """

        results = []

        for url in urls:

            try:

                parsed = urlparse(
                    url
                )

                hostname = (
                    parsed.hostname
                    or ""
                ).lower()

                path = (
                    parsed.path
                    or ""
                )

                query = (
                    parsed.query
                    or ""
                )

                is_ip = False

                try:

                    ipaddress.ip_address(
                        hostname
                    )

                    is_ip = True

                except ValueError:
                    pass

                results.append({
                    "url": url,
                    "scheme": (
                        parsed.scheme.lower()
                    ),
                    "domain": hostname or None,
                    "path": path,
                    "query_present": bool(
                        query
                    ),
                    "is_ip_literal": is_ip,
                    "port": parsed.port,
                })

            except Exception:

                results.append({
                    "url": url,
                    "scheme": None,
                    "domain": None,
                    "path": None,
                    "query_present": False,
                    "is_ip_literal": False,
                    "port": None,
                })

        return results

    # ========================================================
    # IP EXTRACTION
    # ========================================================

    def extract_ips(
        self,
        text: str | None = None,
    ) -> list[str]:
        """
        Extract valid IPv4 addresses.
        """

        if text is None:
            text = self.raw_bytes.decode(
                "utf-8",
                errors="replace",
            )

        candidates = IP_REGEX.findall(
            text
        )

        valid_ips = []

        for candidate in candidates:

            try:

                ip = ipaddress.ip_address(
                    candidate
                )

                if ip.version == 4:
                    valid_ips.append(
                        candidate
                    )

            except ValueError:
                continue

        return unique_list(
            valid_ips
        )

    # ========================================================
    # RECEIVED / SMTP TRACE
    # ========================================================

    def analyze_received_headers(
        self,
    ) -> dict:
        """
        Analyze Received headers.

        RFC email trace fields are preserved exactly as
        observed. We do not reorder or rewrite them.

        Note:
        Received headers are normally listed newest first
        in the message. Later forensic logic can reconstruct
        the relay chain carefully.
        """

        received_headers = (
            self.get_all_headers(
                "Received"
            )
        )

        all_ips = []

        for header in received_headers:

            all_ips.extend(
                self.extract_ips(
                    header
                )
            )

        all_ips = unique_list(
            all_ips
        )

        public_ips = []
        private_ips = []
        special_ips = []

        for ip_string in all_ips:

            try:

                ip = ipaddress.ip_address(
                    ip_string
                )

                if ip.is_private:
                    private_ips.append(
                        ip_string
                    )

                elif ip.is_loopback:
                    special_ips.append(
                        ip_string
                    )

                elif ip.is_link_local:
                    special_ips.append(
                        ip_string
                    )

                elif ip.is_reserved:
                    special_ips.append(
                        ip_string
                    )

                else:
                    public_ips.append(
                        ip_string
                    )

            except ValueError:
                continue

        return {
            "received_count": len(
                received_headers
            ),
            "headers": received_headers,
            "ips": all_ips,
            "public_ips": unique_list(
                public_ips
            ),
            "private_ips": unique_list(
                private_ips
            ),
            "special_ips": unique_list(
                special_ips
            ),
        }

    # ========================================================
    # AUTHENTICATION RESULTS
    # ========================================================

    def parse_authentication_results(
        self,
    ) -> dict:
        """
        Parse Authentication-Results headers.

        This extracts the authentication verdicts already
        recorded by the receiving mail infrastructure.

        It does NOT perform SPF/DKIM/DMARC verification itself.
        """

        headers = (
            self.get_all_headers(
                "Authentication-Results"
            )
        )

        combined = " ".join(
            headers
        ).lower()

        result = {
            "spf": "unknown",
            "dkim": "unknown",
            "dmarc": "unknown",
            "headers": headers,
        }

        # IMPORTANT:
        # softfail must be explicitly matched rather than
        # searching for the substring "fail".

        spf_match = re.search(
            r"\bspf\s*=\s*"
            r"(pass|softfail|fail|neutral|none|"
            r"temperror|permerror)\b",
            combined,
        )

        if spf_match:
            result["spf"] = (
                spf_match.group(1)
            )

        dkim_match = re.search(
            r"\bdkim\s*=\s*"
            r"(pass|fail|neutral|none|"
            r"temperror|permerror|policy)\b",
            combined,
        )

        if dkim_match:
            result["dkim"] = (
                dkim_match.group(1)
            )

        dmarc_match = re.search(
            r"\bdmarc\s*=\s*"
            r"(pass|fail|bestguesspass|none|"
            r"temperror|permerror|policy)\b",
            combined,
        )

        if dmarc_match:
            result["dmarc"] = (
                dmarc_match.group(1)
            )

        # ----------------------------------------------------
        # Useful Authentication-Results parameters
        # ----------------------------------------------------

        header_from_match = re.search(
            r"\bheader\.from=([^\s;]+)",
            combined,
        )

        if header_from_match:

            result["header_from"] = (
                header_from_match.group(1)
            )

        dkim_identity_match = re.search(
            r"\bheader\.i=([^\s;]+)",
            combined,
        )

        if dkim_identity_match:

            result["header_i"] = (
                dkim_identity_match.group(1)
            )

        return result

    # ========================================================
    # ATTACHMENTS
    # ========================================================

    def extract_attachments(
        self,
    ) -> list[dict]:
        """
        Extract attachment metadata.

        IMPORTANT:
        No attachment is executed or opened.
        """

        attachments = []

        for part in self.message.walk():

            filename = part.get_filename()

            if not filename:
                continue

            filename = str(
                filename
            )

            payload = (
                part.get_payload(
                    decode=True
                )
                or b""
            )

            extension = ""

            if "." in filename:

                extension = (
                    "."
                    + filename.rsplit(
                        ".",
                        1
                    )[1].lower()
                )

            attachment_hash = (
                sha256_bytes(
                    payload
                )
                if payload
                else None
            )

            attachments.append({
                "filename": filename,
                "content_type": (
                    part.get_content_type()
                ),
                "size": len(
                    payload
                ),
                "extension": extension,
                "sha256": attachment_hash,
                "suspicious_extension": (
                    extension
                    in DANGEROUS_ATTACHMENT_EXTENSIONS
                ),
            })

        return attachments

    # ========================================================
    # DOMAINS
    # ========================================================

    def extract_domains(
        self,
        urls: list[str] | None = None,
    ) -> list[str]:
        """
        Extract domains from URLs.
        """

        if urls is None:
            urls = self.extract_urls()

        domains = []

        for url in urls:

            try:

                hostname = (
                    urlparse(
                        url
                    ).hostname
                )

                if hostname:

                    domains.append(
                        normalize_domain(
                            hostname
                        )
                    )

            except Exception:
                continue

        return unique_list(
            domains
        )

    # ========================================================
    # COMPLETE PARSE
    # ========================================================

    def parse(self) -> dict:
        """
        Execute the complete deterministic parser.
        """

        headers = (
            self.extract_headers()
        )

        identity = (
            self.extract_identity()
        )

        body = (
            self.extract_body()
        )

        urls = (
            self.extract_urls(
                body
            )
        )

        url_metadata = (
            self.analyze_url_structure(
                urls
            )
        )

        domains = (
            self.extract_domains(
                urls
            )
        )

        received = (
            self.analyze_received_headers()
        )

        authentication = (
            self.parse_authentication_results()
        )

        attachments = (
            self.extract_attachments()
        )

        all_text = (
            self.raw_bytes.decode(
                "utf-8",
                errors="replace",
            )
        )

        ips = self.extract_ips(
            all_text
        )

        return {
            "email_hash": self.email_hash,

            "size_bytes": len(
                self.raw_bytes
            ),

            "headers": headers,

            "identity": identity,

            "body": body,

            "urls": urls,

            "url_metadata": url_metadata,

            "domains": domains,

            "ips": ips,

            "received": received,

            "authentication": authentication,

            "attachments": attachments,

            "metadata": {
                "is_multipart": (
                    self.message.is_multipart()
                ),
                "content_type": (
                    self.message.get_content_type()
                ),
                "mime_version": (
                    self.get_header(
                        "MIME-Version"
                    )
                ),
                "charset": (
                    self.message.get_content_charset()
                ),
            },
        }


# ============================================================
# CONVENIENCE FUNCTION
# ============================================================

def parse_email(
    raw_email: bytes | str,
) -> dict:
    """
    Convenience wrapper.

    Example:

        result = parse_email(raw_email)
    """

    parser = EmailParser(
        raw_email
    )

    return parser.parse()