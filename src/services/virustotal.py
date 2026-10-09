"""VirusTotal SHA-256 report lookup only; no file upload or rescan API."""

from datetime import UTC, datetime
from typing import Annotated, Protocol

from pydantic import Field, StrictInt, model_validator

from src.evidence.models import Contract, NonEmpty
from src.schemas.tool import ToolResult
from src.services.external import HTTPTransport, HTTPXTransport, controlled_call, provider_json
from src.services.ioc_store import normalize_ioc

Count = Annotated[StrictInt, Field(ge=0)]


class FileReputation(Contract):
    sha256: str
    malicious: Count
    suspicious: Count
    harmless: Count
    undetected: Count
    last_analysis_at: datetime | None = None
    source_reference: NonEmpty

    @model_validator(mode="after")
    def validate_binding(self):
        if normalize_ioc("hash", self.sha256) != self.sha256 or len(self.sha256) != 64:
            raise ValueError("Expected canonical SHA-256")
        if self.last_analysis_at is not None and self.last_analysis_at.utcoffset() is None:
            raise ValueError("Analysis time must be timezone aware")
        return self


class HashReputationClient(Protocol):
    def lookup_hash(self, sha256: str) -> ToolResult[FileReputation]: ...


class VirusTotalClient:
    def __init__(self, *, api_key: str = "", transport: HTTPTransport | None = None, timeout: float = 5):
        self.api_key, self.transport, self.timeout = api_key, transport, timeout

    @classmethod
    def from_settings(cls, settings):
        return cls(
            api_key=settings.virustotal_api_key,
            transport=HTTPXTransport(settings.virustotal_base_url),
            timeout=settings.external_timeout_seconds,
        )

    def lookup_hash(self, sha256: str) -> ToolResult[FileReputation]:
        def lookup():
            digest = normalize_ioc("hash", sha256)
            if len(digest) != 64:
                raise ValueError("Only SHA-256 supported")
            payload = provider_json(
                self.transport, f"/files/{digest}", headers={"x-apikey": self.api_key}, params={}, timeout=self.timeout
            )
            data = payload["data"]
            attributes = data["attributes"]
            if data["type"] != "file" or normalize_ioc("hash", attributes["sha256"]) != digest:
                raise ValueError("Report hash mismatch")
            if normalize_ioc("hash", data["id"]) != digest:
                raise ValueError("Report ID mismatch")
            stats = attributes["last_analysis_stats"]
            stamp = attributes.get("last_analysis_date")
            if stamp is not None and (type(stamp) is not int or stamp < 0):
                raise ValueError("Invalid analysis time")
            return FileReputation(
                sha256=digest,
                malicious=stats["malicious"],
                suspicious=stats["suspicious"],
                harmless=stats["harmless"],
                undetected=stats["undetected"],
                last_analysis_at=datetime.fromtimestamp(stamp, UTC) if stamp is not None else None,
                source_reference=f"virustotal:files/{digest}",
            )

        return controlled_call("VT", lookup, configured=bool(self.api_key and self.transport))
