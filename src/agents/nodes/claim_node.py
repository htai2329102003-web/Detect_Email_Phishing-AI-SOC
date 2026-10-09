from src.agents.state import AgentState
from src.evidence.claim_validator import validate_verdict_claims
from src.services.verdict import VerdictProvider


def claim_node(state: AgentState, *, provider: VerdictProvider | None = None) -> dict:
    """Mandatory Gate 2. Escalation is separate from immutable Risk Engine output."""
    result = validate_verdict_claims(
        state.get("verdict_proposal"),
        state.get("validated_evidence", []),
        state["risk_result"],
    )
    errors = (*state.get("privacy_errors", ()), *state.get("verdict_errors", ()))
    if errors:
        result = result.model_copy(
            update={
                "accepted": False,
                "status": "REJECTED",
                "assessment_label": "NEEDS_ANALYST_REVIEW",
                "reasons": tuple(sorted(set(result.reasons) | set(errors))),
            }
        )
    blocked = any(code in errors for code in ("PII_REDACTION_UNAVAILABLE", "GUARDRAIL_UNAVAILABLE"))
    retry = (
        not result.accepted
        and provider is not None
        and provider.is_llm
        and state.get("verdict_attempts", 0) < 2
        and not blocked
    )
    return {
        "claim_validation": result,
        "claims_valid": result.accepted,
        "retry_requested": retry,
        "retry_feedback": result.reasons,
        "verdict": "pending_review",
        "verdict_summary": result.verdict.analyst_summary,
        "requires_review": True,
        "review_status": "pending",
    }
