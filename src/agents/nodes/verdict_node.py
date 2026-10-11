from src.agents.state import AgentState
from src.evidence.claim_validator import fact_view
from src.schemas.verdict import VerdictRequest
from src.services.guardrails import GuardrailProvider, LocalGuardrails
from src.services.pii import RedactionResult
from src.services.verdict import DeterministicVerdictProvider, VerdictProvider, VerdictProviderError


def verdict_node(
    state: AgentState, *, provider: VerdictProvider | None = None, guardrails: GuardrailProvider | None = None
) -> dict:
    """A provider sees a copy of immutable risk/facts and only redacted email data."""
    attempts = state.get("verdict_attempts", 0) + 1
    if state.get("privacy_errors") or state.get("redacted_for_llm") is None:
        return {
            "verdict_proposal": None,
            "verdict_attempts": attempts,
            "verdict_errors": ("PII_REDACTION_UNAVAILABLE",),
            "verdict_llm_status": "ERROR" if provider is not None and provider.is_llm else "DISABLED",
        }
    try:
        redacted = RedactionResult(
            data=state["redacted_for_llm"], counts=state.get("pii_counts", {}), policy=state["redaction_policy"]
        )
        email = (guardrails or LocalGuardrails()).prepare(redacted)
        request = VerdictRequest(
            risk=state["risk_result"].model_copy(deep=True),
            evidence=tuple(fact_view(item) for item in [*state.get("validated_evidence", []),
                                                       *state.get("knowledge_evidence", [])]),
            email=email.model_copy(deep=True),
            knowledge_context=state.get("rag_context", ()),
        )
    except Exception:
        return {"verdict_proposal": None, "verdict_attempts": attempts, "verdict_errors": ("GUARDRAIL_UNAVAILABLE",),
                "verdict_llm_status": "ERROR" if provider is not None and provider.is_llm else "DISABLED"}
    try:
        proposal = (provider or DeterministicVerdictProvider()).generate(
            request, feedback=state.get("retry_feedback", ())
        )
    except VerdictProviderError as exc:
        return {"verdict_proposal": None, "verdict_attempts": attempts,
                "verdict_errors": (exc.code,), "verdict_llm_status": exc.status,
                "guardrail_signals": email.injection_signals}
    except Exception:
        return {
            "verdict_proposal": None,
            "verdict_attempts": attempts,
            "verdict_errors": ("VERDICT_PROVIDER_ERROR",),
            "guardrail_signals": email.injection_signals,
            "verdict_llm_status": "ERROR" if provider is not None and provider.is_llm else "DISABLED",
        }
    return {
        "verdict_proposal": proposal,
        "verdict_attempts": attempts,
        "verdict_errors": (),
        "guardrail_signals": email.injection_signals,
        "verdict_llm_status": "OK" if provider is not None and provider.is_llm else "DISABLED",
    }
