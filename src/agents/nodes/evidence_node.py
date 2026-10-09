from src.agents.state import AgentState
from src.evidence.validation import validate_evidence


def evidence_node(state: AgentState) -> dict:
    """Validate evidence contracts before risk scoring."""
    result = validate_evidence(state.get("evidence", []))
    return {"validated_evidence": list(result.evidence), "evidence_validation": result}
