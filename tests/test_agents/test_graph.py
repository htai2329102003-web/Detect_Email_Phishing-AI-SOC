from pathlib import Path

import pytest

from src.agents.graph import agent

EMAILS = Path(__file__).resolve().parents[1] / "fixtures" / "emails"


@pytest.mark.asyncio
async def test_agent_basic_flow():
    result = await agent.ainvoke(
        {"case_id": "case-1", "raw_email": (EMAILS / "clean.eml").read_bytes(), "evidence": [], "errors": []}
    )
    assert result["verdict"] == "pending_review"
    assert result["review_status"] == "pending"
    assert result["requires_review"] is True
    assert result["redacted_for_llm"] is not None
    assert result["redacted_for_llm"] is not result["parsed_email"]
    assert result["claim_validation"].status == "PASS"
    assert "text_body" in result["parsed_email"]


@pytest.mark.asyncio
async def test_agent_state_structure():
    result = await agent.ainvoke(
        {"case_id": "case-2", "raw_email": (EMAILS / "auth_fail.eml").read_bytes(), "evidence": [], "errors": []}
    )
    assert isinstance(result, dict)
    assert result["case_id"] == "case-2"
    assert "validated_evidence" in result
    assert "risk_score" in result
    assert result["risk_result"].score == result["risk_score"]
    assert set(agent.get_graph().nodes) == {
        "__start__",
        "parse",
        "header",
        "url",
        "attachment",
        "qr",
        "validate_evidence",
        "score_risk",
        "create_verdict",
        "validate_claims",
        "__end__",
    }
