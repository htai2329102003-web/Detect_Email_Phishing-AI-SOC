from __future__ import annotations

from operator import add
from typing import Annotated, Any, TypedDict

from src.evidence.models import Evidence, Gate1Result, RiskResult
from src.schemas.verdict import ClaimValidationResult, Verdict
from src.services.rag import RetrievedChunk


class AgentState(TypedDict, total=False):
    """Shared state for the PhishHunter analysis workflow."""

    case_id: str
    raw_email: bytes | str
    parsed_email: dict[str, Any]
    redacted_for_llm: dict[str, Any] | None
    redaction_policy: str
    pii_counts: dict[str, int]
    privacy_errors: tuple[str, ...]
    evidence: Annotated[list[Evidence], add]
    validated_evidence: list[Evidence]
    evidence_validation: Gate1Result
    risk_result: RiskResult
    applicable_signals: Annotated[list[str], add]
    analyzer_runs: Annotated[list[dict[str, str]], add]
    risk_score: float
    risk_level: str
    verdict: str
    verdict_summary: str
    verdict_proposal: Verdict | dict[str, Any] | None
    verdict_attempts: int
    verdict_errors: tuple[str, ...]
    verdict_llm_status: str
    claim_validation: ClaimValidationResult
    retry_feedback: tuple[str, ...]
    retry_requested: bool
    guardrail_signals: tuple[str, ...]
    claims_valid: bool
    requires_review: bool
    review_status: str
    errors: Annotated[list[str], add]
    external_enrichment: bool
    rag_context: tuple[RetrievedChunk, ...]
    rag_status: str
    knowledge_evidence: list[Evidence]
    knowledge_validation: Gate1Result
