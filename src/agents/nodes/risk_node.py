from src.agents.state import AgentState
from src.evidence.risk_engine import score_evidence


def risk_node(state: AgentState) -> dict:
    """Apply the deterministic risk engine to validated evidence."""
    score = score_evidence(
        state.get("evidence_validation", state.get("validated_evidence", [])),
        applicable_signals=state.get("applicable_signals", []),
    )
    return {"risk_result": score, "risk_score": score.score, "risk_level": score.level}
