"""Offline redaction policy. Regex recognizers are deliberately not a PII guarantee."""

import re
from html import unescape
from typing import Any, Protocol
from urllib.parse import unquote

from pydantic import JsonValue

from src.evidence.models import Contract


class RedactionResult(Contract):
    data: dict[str, JsonValue]
    counts: dict[str, int]
    policy: str = "vn_regex:v1"


class PIIRedactor(Protocol):
    """A Presidio-backed adapter may implement this boundary when provisioned."""

    def redact(self, raw: dict[str, Any]) -> RedactionResult: ...


PATTERNS = (
    ("EMAIL", re.compile(r"(?<![\w.+-])[\w.!#$%&'*+/=?^`{|}~-]+@(?:[\w-]+\.)+[\w-]+"), None),
    (
        "VN_PHONE",
        re.compile(r"(?<!\w)(?:\+84|0084|0)[ .-]?(?:3[2-9]|5[2689]|7[06789]|8[1-9]|9\d)(?:[ .-]?\d){7}(?!\d)"),
        None,
    ),
    ("VN_PHONE", re.compile(r"(?<!\w)(?:\+84|0084|0)[ .-]?2\d(?:[ .-]?\d){8}(?!\d)"), None),
    ("VN_ID", re.compile(r"(?<!\w)\d{12}(?!\w)"), None),
    (
        "VN_ID",
        re.compile(
            r"\b(?:cccd|cmnd|căn cước(?: công dân)?|chứng minh(?: nhân dân)?)(?:\s+số)?\s*[:#-]?\s*(\d{9}|\d{12})(?!\d)",
            re.IGNORECASE,
        ),
        1,
    ),
    (
        "BANK_ACCOUNT",
        re.compile(
            r"\b(?:số\s+tài\s+khoản|tài\s+khoản|stk|account(?:\s+number)?)\s*[:#-]?\s*(\d(?:[ -]?\d){7,17})(?![ -]?\d)",
            re.IGNORECASE,
        ),
        1,
    ),
)


class RegexPIIRedactor:
    def redact(self, raw: dict[str, Any]) -> RedactionResult:
        # The map lives only for this redacted copy, and is never returned to a provider.
        tokens: dict[tuple[str, str], str] = {}
        counts: dict[str, int] = {}

        def redact_text(text: str) -> str:
            # Decode common textual encodings only in the LLM copy; raw IOC values stay intact.
            text = re.sub(
                r"data:[^\s;,\"']+;base64,[A-Za-z0-9+/=\s]+", "[BINARY_CONTENT_REMOVED]", text, flags=re.IGNORECASE
            )
            text = unescape(unquote(text, errors="replace"))
            spans = []
            for kind, pattern, group in PATTERNS:
                for match in pattern.finditer(text):
                    start, end = match.span(group or 0)
                    spans.append((start, end, kind))
            # Prefer the longest overlapping span (e.g. full +84 phone vs ID substring).
            spans.sort(key=lambda span: (span[0], -(span[1] - span[0])))
            parts, cursor = [], 0
            for start, end, kind in spans:
                if start < cursor:
                    continue
                key = (kind, text[start:end])
                if key not in tokens:
                    counts[kind] = counts.get(kind, 0) + 1
                    tokens[key] = f"[{kind}_{counts[kind]}]"
                parts.extend((text[cursor:start], tokens[key]))
                cursor = end
            return "".join([*parts, text[cursor:]])

        def copy(value: Any) -> JsonValue:
            if isinstance(value, str):
                return redact_text(value)
            if isinstance(value, dict):
                # Drop binary content; never serialize attachment bytes/base64 for LLM use.
                return {str(key): copy(child) for key, child in value.items() if not isinstance(child, bytes)}
            if isinstance(value, (list, tuple)):
                return [copy(child) for child in value if not isinstance(child, bytes)]
            if value is None or isinstance(value, (bool, int, float)):
                return value
            return None

        data = copy(raw)
        return RedactionResult(data=data, counts=counts)
