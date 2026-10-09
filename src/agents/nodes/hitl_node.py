from src.agents.state import AgentState


def hitl_node(state: AgentState) -> dict:
    """Mark analysis for analyst review; persistence is added in a later phase."""
    return {"requires_review": True, "review_status": "pending"}
