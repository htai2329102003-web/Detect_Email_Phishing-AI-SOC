"""Exact-match IOC boundary. No network requests or implicit feed ingestion."""

import re
from datetime import datetime
from ipaddress import ip_address
from typing import Literal, Protocol, Self
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from pydantic import Field, JsonValue, model_validator

from src.evidence.models import Contract, NonEmpty
from src.schemas.tool import ToolResult
from src.utils.normalization import normalize_domain

IOCKind = Literal["domain", "url", "ip", "hash"]
UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def _percent(value: str) -> str:
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise ValueError("Invalid URL percent encoding")
    return re.sub(
        r"%([0-9a-fA-F]{2})",
        lambda m: chr(int(m[1], 16)) if chr(int(m[1], 16)) in UNRESERVED else "%" + m[1].upper(),
        value,
    )


def normalize_ioc(kind: IOCKind, value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Empty indicator")
    if kind == "ip":
        return ip_address(value).compressed
    if kind == "hash":
        if not re.fullmatch(r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", value):
            raise ValueError("Expected MD5, SHA-1 or SHA-256 hex")
        return value.lower()
    if kind == "domain":
        host = normalize_domain(value).encode("idna").decode("ascii")
        if len(host) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")
        ):
            raise ValueError("Invalid domain")
        return host
    if kind != "url":
        raise ValueError("Unsupported IOC kind")
    if any(ord(char) <= 32 or ord(char) == 127 for char in value) or "\\" in value:
        raise ValueError("Ambiguous URL characters")
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Expected HTTP(S) URL")
    host = parsed.hostname
    try:
        host = normalize_ioc("ip", host)
        host = f"[{host}]" if ":" in host else host
    except ValueError:
        _percent(host)  # Validate escapes before decoding UTF-8 host labels.
        host = normalize_ioc("domain", unquote(host, errors="strict"))
    port = parsed.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    if port is not None and (parsed.scheme.lower(), port) not in {("http", 80), ("https", 443)}:
        host += f":{port}"
    if "@" in parsed.netloc:
        host = _percent(parsed.netloc.rsplit("@", 1)[0]) + "@" + host
    safe = "%/:@!$&'()*+,;=-._~?[]"
    return urlunsplit(
        (
            parsed.scheme.lower(),
            host,
            quote(_percent(parsed.path or "/"), safe=safe),
            quote(_percent(parsed.query), safe=safe),
            "",
        )
    )


class IOCRecord(Contract):
    kind: IOCKind
    value: NonEmpty
    source: NonEmpty
    confidence: float = Field(default=1.0, ge=0, le=1)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: tuple[NonEmpty, ...] = ()
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def canonicalize(self) -> Self:
        object.__setattr__(self, "value", normalize_ioc(self.kind, self.value))
        for stamp in (self.first_seen, self.last_seen):
            if stamp is not None and (stamp.tzinfo is None or stamp.utcoffset() is None):
                raise ValueError("IOC times must be timezone aware")
        if self.first_seen and self.last_seen and self.first_seen > self.last_seen:
            raise ValueError("IOC time ordering")
        return self


class IOCIngestRecord(IOCRecord):
    """Feed input: explicit source/confidence/times, SHA-256-only hash ingestion."""

    confidence: float = Field(ge=0, le=1)
    first_seen: datetime
    last_seen: datetime

    @model_validator(mode="after")
    def sha256_only(self) -> Self:
        if self.kind == "hash" and len(self.value) != 64:
            raise ValueError("Ingestion requires SHA-256")
        return self


class IOCClient(Protocol):
    def lookup(self, kind: IOCKind, value: str) -> ToolResult[IOCRecord]: ...


class UnconfiguredIOCClient:
    def lookup(self, kind: IOCKind, value: str) -> ToolResult[IOCRecord]:
        return ToolResult(status="ERROR", error_code="IOC_NOT_CONFIGURED", latency_ms=0)


class InMemoryIOCStore:
    """Explicit local snapshot; a miss only means absent from this snapshot."""

    def __init__(self, records: tuple[IOCRecord, ...] = ()):
        self._records = {(record.kind, record.value): record for record in records}

    def lookup(self, kind: IOCKind, value: str) -> ToolResult[IOCRecord]:
        return ToolResult(status="OK", data=self._records.get((kind, normalize_ioc(kind, value))), latency_ms=0)

    def ingest(self, records: list[dict | IOCIngestRecord]) -> ToolResult[int]:
        """Validate the entire bounded batch before replacing the local snapshot."""
        try:
            if not isinstance(records, list) or len(records) > 1000:
                raise ValueError("IOC batch limit")
            validated = [
                IOCIngestRecord.model_validate(record.model_dump() if isinstance(record, IOCIngestRecord) else record)
                for record in records
            ]
            updated = {**self._records, **{(record.kind, record.value): record for record in validated}}
            self._records = updated
            return ToolResult(status="OK", data=len(validated), latency_ms=0)
        except Exception:
            return ToolResult(status="ERROR", error_code="IOC_INVALID_BATCH", latency_ms=0)


def lookup_ioc(client: IOCClient, kind: IOCKind, value: str) -> ToolResult[IOCRecord]:
    """Normalize, contain client failures and reject non-exact transport responses."""
    try:
        canonical = normalize_ioc(kind, value)
        response = ToolResult[IOCRecord].model_validate(client.lookup(kind, canonical).model_dump())
        if response.data is not None and (response.data.kind != kind or response.data.value != canonical):
            raise ValueError("Non-exact IOC response")
        return response
    except Exception:
        return ToolResult(status="ERROR", error_code="IOC_LOOKUP_ERROR", latency_ms=0)
