import hashlib
import json
from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints, model_validator

NonEmpty = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
EvidenceResult = Literal["PASS", "FAIL", "UNKNOWN"]
ToolStatus = Literal["OK", "TIMEOUT", "RATE_LIMITED", "ERROR"]
RiskLabel = Literal["SAFE", "SUSPICIOUS", "PHISHING", "NEEDS_ANALYST_REVIEW"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class Provenance(Contract):
    source: Literal["local", "external", "llm"]
    reference: NonEmpty


class Evidence(Contract):
    """A check result: FAIL means a detected risk; UNKNOWN never means clean."""

    evidence_id: str = ""
    analyzer: NonEmpty
    tool: NonEmpty
    signal_type: NonEmpty
    family: NonEmpty
    indicator: NonEmpty
    value: JsonValue
    result: EvidenceResult
    tool_status: ToolStatus
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: Provenance
    collected_at: datetime

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if self.tool_status != "OK" and self.result != "UNKNOWN":
            raise ValueError("A failed tool must produce UNKNOWN")
        if self.collected_at.tzinfo is None or self.collected_at.utcoffset() is None:
            raise ValueError("collected_at must have a timezone")
        if self.provenance.source == "llm" and self.family != "content_bec":
            raise ValueError("LLM evidence must belong to content_bec")
        # Exclude time so repeated observations of the same fact dedupe.
        payload = self.model_dump(mode="json", exclude={"evidence_id", "collected_at"})
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        expected = "ev_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if self.evidence_id and self.evidence_id != expected:
            raise ValueError("evidence_id does not match its contents")
        object.__setattr__(self, "evidence_id", expected)
        return self


class ValidationIssue(Contract):
    index: int
    code: Literal["INVALID_SCHEMA", "INVALID_TIMESTAMP"]


class Gate1Result(Contract):
    evidence: tuple[Evidence, ...] = ()
    issues: tuple[ValidationIssue, ...] = ()
    duplicate_ids: tuple[str, ...] = ()


class Coverage(Contract):
    required: tuple[str, ...]
    applicable: tuple[str, ...]
    completed: tuple[str, ...]
    missing: tuple[str, ...]
    unknown: tuple[str, ...]
    ratio: float = Field(ge=0.0, le=1.0)
    complete: bool


class Contribution(Contract):
    evidence_id: str
    signal_type: str
    family: str
    strength: float = Field(ge=0.0, le=1.0)
    applied_strength: float = Field(ge=0.0, le=1.0)


class RiskResult(Contract):
    """Deterministic output; a verdict consumer cannot assign score or label."""

    score: float = Field(ge=0.0, le=100.0)
    label_candidate: RiskLabel
    coverage: Coverage
    contributions: tuple[Contribution, ...] = ()
    overrides: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()

    @property
    def level(self) -> str:
        """Compatibility with the existing graph/API skeleton."""
        return {"SAFE": "low", "SUSPICIOUS": "medium", "PHISHING": "high", "NEEDS_ANALYST_REVIEW": "unknown"}[
            self.label_candidate
        ]
