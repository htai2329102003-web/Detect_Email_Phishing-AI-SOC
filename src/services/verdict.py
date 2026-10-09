from typing import Any, Protocol

from src.evidence.claim_validator import compatible_claim
from src.evidence.risk_engine import load_risk_policy
from src.schemas.verdict import Claim, Verdict, VerdictRequest, render_claim, render_summary


class VerdictProvider(Protocol):
    is_llm: bool

    def generate(self, request: VerdictRequest, *, feedback: tuple[str, ...] = ()) -> Verdict | dict[str, Any]: ...


class DeterministicVerdictProvider:
    """Actual evidence-driven reporting, with no fabricated model response."""

    is_llm = False

    def generate(self, request: VerdictRequest, *, feedback: tuple[str, ...] = ()) -> Verdict:
        policy = load_risk_policy()
        selected = [fact for fact in request.evidence if fact.result != "PASS"]
        if not selected:
            selected = [fact for fact in request.evidence if fact.family == "email_auth"]
        claims = []
        for fact in selected[:64]:
            claim_type = compatible_claim(fact, policy)
            if claim_type is not None:
                claims.append(
                    Claim(claim_type=claim_type, text=render_claim((fact,)), evidence_ids=(fact.evidence_id,))
                )
        return Verdict(
            score=request.risk.score,
            label_candidate=request.risk.label_candidate,
            claims=tuple(claims),
            analyst_summary=render_summary(request.risk, len(claims)),
        )
