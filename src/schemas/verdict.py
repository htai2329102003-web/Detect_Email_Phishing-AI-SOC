from typing import Literal

from pydantic import Field

from src.evidence.models import Contract, EvidenceResult, NonEmpty, RiskLabel, RiskResult
from src.services.guardrails import UntrustedEmail
from src.services.rag import RetrievedChunk

ClaimType = Literal["AUTHENTICATION", "IDENTITY", "URL", "ATTACHMENT", "QR", "IOC", "CONTENT_BEC", "UNCERTAINTY"]
Action = Literal["REVIEW_EVIDENCE", "VERIFY_SENDER_OUT_OF_BAND"]


class IndicatorReference(Contract):
    evidence_id: NonEmpty
    path: NonEmpty
    value: NonEmpty


class Claim(Contract):
    claim_type: ClaimType
    text: NonEmpty
    evidence_ids: tuple[NonEmpty, ...] = Field(min_length=1, max_length=32)
    # Optional in a provider proposal. Gate 2 fills canonical references itself.
    indicators: tuple[IndicatorReference, ...] = ()


class Verdict(Contract):
    score: float = Field(ge=0.0, le=100.0)
    label_candidate: RiskLabel
    claims: tuple[Claim, ...] = Field(default=(), max_length=64)
    recommended_actions: tuple[Action, ...] = ("REVIEW_EVIDENCE",)
    analyst_summary: NonEmpty


class EvidenceFact(Contract):
    """Provider metadata only: no raw indicators, evidence values or attachments."""

    evidence_id: NonEmpty
    signal_type: NonEmpty
    family: NonEmpty
    result: EvidenceResult


class VerdictRequest(Contract):
    risk: RiskResult
    evidence: tuple[EvidenceFact, ...]
    email: UntrustedEmail
    knowledge_context: tuple[RetrievedChunk, ...] = Field(default=(), max_length=10)


class ClaimValidationResult(Contract):
    verdict: Verdict
    accepted: bool
    status: Literal["PASS", "FILTERED", "REJECTED"]
    assessment_label: RiskLabel
    reasons: tuple[str, ...] = ()
    rejected_claim_indices: tuple[int, ...] = ()


def render_claim(facts: tuple[EvidenceFact, ...]) -> str:
    return " ".join(f"{fact.signal_type}: {fact.result}." for fact in facts)


def render_summary(risk: RiskResult, claim_count: int) -> str:
    coverage = "complete" if risk.coverage.complete else "incomplete"
    return (
        f"Risk Engine: {risk.label_candidate}; score {risk.score:g}; coverage {coverage}. "
        f"{claim_count} grounded claims. Analyst review required."
    )
