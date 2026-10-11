import re
from dataclasses import dataclass
from email import policy
from email.errors import MessageError
from email.headerregistry import HeaderRegistry
from email.parser import BytesParser
from ipaddress import ip_address
from typing import Any

from src.parsers.attachment_parser import parse_attachment
from src.parsers.html_parser import parse_html

MAX_EMAIL_BYTES = 5 * 1024 * 1024
MAX_MIME_PARTS = 100
MAX_MIME_DEPTH = 20
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


class EmailParseError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ParsedEmail:
    raw_for_analyzers: dict[str, Any]
    # Deliberately unavailable until a real redactor exists. Never alias raw data.
    redacted_for_llm: dict[str, Any] | None = None


def _addresses(values: list[str], *, allow_null: bool = False) -> list[dict[str, str]]:
    if not values or (allow_null and len(values) == 1 and values[0].strip() == "<>"):
        return []
    header = HeaderRegistry()("Reply-To", ",".join(values))
    if header.defects or not header.addresses:
        raise EmailParseError("INVALID_ADDRESS", "Malformed email address header")
    addresses = []
    for address in header.addresses:
        local, domain = address.username, address.domain
        if not local or not domain or any(ord(char) < 32 or ord(char) == 127 for char in address.addr_spec):
            raise EmailParseError("INVALID_ADDRESS", "Malformed email address header")
        try:
            domain = domain.rstrip(".").encode("idna").decode("ascii").lower()
            if domain.startswith("[") and domain.endswith("]"):
                ip_address(domain[1:-1].removeprefix("ipv6:"))
            elif len(domain) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in domain.split(".")
            ):
                raise ValueError("Invalid domain labels")
        except (UnicodeError, ValueError) as exc:
            raise EmailParseError("INVALID_ADDRESS", "Malformed email address domain") from exc
        addresses.append({"display_name": address.display_name, "address": address.addr_spec, "domain": domain})
    return addresses


def parse_email(raw_email: bytes | str) -> ParsedEmail:
    """Parse bounded RFC email bytes without fetching URLs or executing attachments."""
    content = raw_email.encode("utf-8") if isinstance(raw_email, str) else raw_email
    if not content or not content.strip():
        raise EmailParseError("EMPTY_EMAIL", "Email file is empty")
    if len(content) > MAX_EMAIL_BYTES:
        raise EmailParseError("EMAIL_TOO_LARGE", "Email exceeds the 5 MiB limit")
    try:
        return _parse(content)
    except EmailParseError:
        raise
    except (MessageError, ValueError, LookupError, UnicodeError, RecursionError, IndexError) as exc:
        raise EmailParseError("MALFORMED_EMAIL", "Unable to parse email structure") from exc


def _parse(content: bytes) -> ParsedEmail:
    message = BytesParser(policy=policy.default).parsebytes(content)
    if any(type(d).__name__ in {"NoBoundaryInMultipartDefect", "StartBoundaryNotFoundDefect",
                               "MultipartInvariantViolationDefect"} for d in message.defects):
        raise EmailParseError("MALFORMED_EMAIL", "Invalid MIME structure")
    warnings: list[dict[str, str]] = []
    unavailable: set[str] = set()
    raw_headers = list(message.raw_items())
    headers: dict[str, list[str]] = {}

    def warn(code: str, field: str):
        warning = {"code": code, "field": field}
        if warning not in warnings:
            warnings.append(warning)

    # Fetch each structured header separately: one malformed Message-ID must not
    # prevent extraction of other headers or inert body/attachment bytes.
    for name, value in raw_headers:
        name = name.lower()
        try:
            decoded = message.policy.header_fetch_parse(name, value)
            if getattr(decoded, "defects", ()):
                unavailable.add(name)
                warn("MALFORMED_HEADER", name)
            headers.setdefault(name, []).append(str(decoded))
        except (MessageError, ValueError, LookupError, UnicodeError, RecursionError, IndexError):
            unavailable.add(name)
            warn("HEADER_PARSE_ERROR", name)
            headers.setdefault(name, []).append(value)
    for name in ("from", "reply-to", "return-path", "subject", "content-type"):
        if len(headers.get(name, [])) > 1:
            if name == "content-type":
                raise EmailParseError("MALFORMED_MIME", "Ambiguous MIME Content-Type")
            unavailable.add(name)
            warn("DUPLICATE_HEADER", name)

    def addresses(name: str, *, allow_null: bool = False):
        if name in unavailable:
            return []
        try:
            values = _addresses(headers.get(name, []), allow_null=allow_null)
            if name == "from" and len(values) != 1:
                raise EmailParseError("INVALID_FROM", "Email must have exactly one From mailbox")
            return values
        except (ValueError, IndexError, RecursionError):
            unavailable.add(name)
            warn("INVALID_ADDRESS" if name != "from" else "INVALID_FROM", name)
            return []

    senders = addresses("from")
    reply_to = addresses("reply-to")
    return_path = addresses("return-path", allow_null=True)
    # Unreliable semantic fields are unavailable, while raw occurrences stay intact.
    headers = {name: values for name, values in headers.items() if name not in unavailable}

    def check_mime(part):
        for defect in part.defects:
            code = type(defect).__name__
            if code not in {
                "CloseBoundaryNotFoundDefect", "MissingHeaderBodySeparatorDefect",
                "InvalidMultipartContentTransferEncodingDefect",
                "InvalidBase64CharactersDefect", "InvalidBase64PaddingDefect", "InvalidBase64LengthDefect",
            }:
                raise EmailParseError("MALFORMED_MIME", "Invalid MIME part")
            warn(code, "mime")

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict[str, Any]] = []
    stack = [(message, 0)]
    count = 0
    while stack:
        part, depth = stack.pop()
        count += 1
        if count > MAX_MIME_PARTS or depth > MAX_MIME_DEPTH:
            raise EmailParseError("MIME_LIMIT", "Email exceeds MIME nesting or part limits")
        check_mime(part)
        if len(part.get_all("Content-Type", [])) > 1:
            raise EmailParseError("MALFORMED_MIME", "Ambiguous MIME Content-Type")
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        content_type = part.get_content_type()
        is_attachment = filename is not None or disposition == "attachment" or content_type == "message/rfc822"
        if part.is_multipart() and not is_attachment:
            stack.extend((child, depth + 1) for child in reversed(part.get_payload()))
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            payload = part.as_bytes(policy=policy.default)
        check_mime(part)
        if is_attachment or part.get_content_maintype() != "text":
            attachments.append(
                parse_attachment(
                    filename,
                    payload,
                    content_type=content_type,
                    disposition=disposition,
                    content_id=part.get("Content-ID"),
                )
            )
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            body = payload.decode(charset, errors="replace")
        except LookupError:
            body = payload.decode("utf-8", errors="replace")
        if content_type == "text/plain":
            text_parts.append(body)
        elif content_type == "text/html":
            html_parts.append(body)
        else:
            attachments.append(
                parse_attachment(
                    filename,
                    payload,
                    content_type=content_type,
                    disposition=disposition,
                    content_id=part.get("Content-ID"),
                )
            )
    text_body, html_body = "\n".join(text_parts), "\n".join(html_parts)
    html = parse_html(html_body)
    candidates = [url.rstrip(".,;)") for url in [*URL_PATTERN.findall(text_body), *URL_PATTERN.findall(html["text"])]]
    candidates.extend(url.strip() for url in html["resources"])
    urls = list(dict.fromkeys(url for url in candidates if url.lower().startswith(("http://", "https://"))))
    return ParsedEmail(
        raw_for_analyzers={
            "raw_bytes": content,
            "raw_headers": raw_headers,
            "parser_warnings": warnings,
            "unavailable_headers": sorted(unavailable),
            "partial_parse": bool(warnings),
            "headers": headers,
            "from": senders[0] if senders else {},
            "reply_to": reply_to,
            "return_path": return_path,
            "received": headers.get("received", []),
            "authentication_results": headers.get("authentication-results", []),
            "subject": " ".join(headers.get("subject", [])),
            "text_body": text_body,
            "html_body": html_body,
            "html": html,
            "urls": urls,
            "attachments": attachments,
        }
    )
