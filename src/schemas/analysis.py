from typing import Literal

from pydantic import BaseModel

from src.agents.state import AgentState
from src.evidence.models import Contribution, Coverage, Evidence, RiskLabel
from src.schemas.verdict import Action, Claim

AnalysisScope = Literal["static_local", "static_local_partial", "static_enriched", "static_enriched_partial"]


class AnalysisResponse(BaseModel):
    case_id: str
    status: str
    evidence: list[Evidence]
    score: float
    label_candidate: RiskLabel
    coverage: Coverage
    contributions: tuple[Contribution, ...]
    analysis_scope: AnalysisScope
    analyzer_runs: list[dict[str, str]]
    reasons: tuple[str, ...]
    risk_score: float
    risk_level: str
    verdict: str
    requires_review: bool
    claims: tuple[Claim, ...]
    recommended_actions: tuple[Action, ...]
    analyst_summary: str
    assessment_label: RiskLabel
    claim_validation_status: Literal["PASS", "FILTERED", "REJECTED"]
    trust_warnings: tuple[str, ...]
    guardrail_signals: tuple[str, ...]
    pii_redaction_counts: dict[str, int]
    verdict_attempts: int
    rag_status: str | None = None
    verdict_llm_status: str = "DISABLED"

    @classmethod
    def from_agent_state(cls, state: AgentState) -> "AnalysisResponse":
        risk = state["risk_result"]
        gate = state["claim_validation"]  # No response can be built from an unvalidated proposal.
        scope = "static_enriched" if state.get("external_enrichment") else "static_local"
        if any(run["status"] != "OK" for run in state.get("analyzer_runs", [])):
            scope += "_partial"
        return cls(
            case_id=state.get("case_id", ""),
            analysis_scope=scope,
            analyzer_runs=sorted(state.get("analyzer_runs", []), key=lambda run: run["analyzer"]),
            status=state.get("review_status", "pending"),
            evidence=[*state.get("validated_evidence", []), *state.get("knowledge_evidence", [])],
            score=risk.score,
            label_candidate=risk.label_candidate,
            coverage=risk.coverage,
            contributions=risk.contributions,
            reasons=risk.reasons,
            risk_score=risk.score,
            risk_level=risk.level,
            verdict=state.get("verdict", "pending_review"),
            requires_review=state.get("requires_review", True),
            claims=gate.verdict.claims,
            recommended_actions=gate.verdict.recommended_actions,
            analyst_summary=gate.verdict.analyst_summary,
            assessment_label=gate.assessment_label,
            claim_validation_status=gate.status,
            trust_warnings=gate.reasons,
            guardrail_signals=state.get("guardrail_signals", ()),
            pii_redaction_counts=state.get("pii_counts", {}),
            verdict_attempts=state["verdict_attempts"],
            rag_status=state.get("rag_status"),
            verdict_llm_status=state.get("verdict_llm_status", "DISABLED"),
        )
