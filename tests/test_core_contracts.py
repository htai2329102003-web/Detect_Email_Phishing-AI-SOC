from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from src.agents.nodes.evidence_node import evidence_node
from src.agents.nodes.risk_node import risk_node
from src.evidence.models import Evidence
from src.evidence.risk_engine import RiskPolicy, load_risk_policy, score_evidence
from src.evidence.validation import validate_evidence
from src.schemas.tool import ToolResult

NOW = datetime(2026, 10, 9, 0, 0, tzinfo=UTC)


def evidence(signal="SPF_FAIL", result="FAIL", **changes):
    policy = load_risk_policy()
    values = {
        "analyzer": "test_analyzer",
        "tool": "local_rules",
        "signal_type": signal,
        "family": policy.weights[signal].family,
        "indicator": "message-1",
        "value": {"observed": result},
        "result": result,
        "tool_status": "OK",
        "severity": "medium",
        "confidence": 1.0,
        "provenance": {"source": "local", "reference": "rules:v1"},
        "collected_at": NOW,
    }
    values.update(changes)
    return Evidence(**values)


def auth(result="PASS"):
    return [evidence(signal, result) for signal in ("SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL")]


def score(items, **kwargs):
    return score_evidence(items, now=NOW, **kwargs)


def test_gate_accepts_and_dedupes_stable_ids():
    first = evidence(value={"b": 2, "a": 1})
    repeat = evidence(value={"a": 1, "b": 2}, collected_at=NOW + timedelta(seconds=1))
    assert first.evidence_id == repeat.evidence_id
    gate = validate_evidence([first.model_dump(), repeat], now=NOW)
    assert gate.evidence == (repeat,)
    assert gate.duplicate_ids == (first.evidence_id,)
    assert not gate.issues


@pytest.mark.parametrize("status", ["TIMEOUT", "RATE_LIMITED", "ERROR"])
def test_failed_tools_require_unknown(status):
    with pytest.raises(ValidationError, match="UNKNOWN"):
        evidence(result="PASS", tool_status=status)
    result = score([*auth(), evidence("HREF_MISMATCH", "UNKNOWN", tool_status=status)])
    assert result.label_candidate == "NEEDS_ANALYST_REVIEW"
    assert result.score == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"provenance": {"source": "external", "reference": " "}},
        {"collected_at": NOW.replace(tzinfo=None)},
        {"collected_at": None},
        {"collected_at": NOW - timedelta(days=8)},
        {"collected_at": NOW + timedelta(minutes=6)},
        {"confidence": float("nan")},
        {"evidence_id": "forged"},
        {"tool_status": "TIMEOUT", "result": "PASS"},
    ],
)
def test_gate_rejects_bad_item_without_crashing_or_hiding_failure(changes):
    bad = evidence("HREF_MISMATCH").model_dump(exclude={"evidence_id"})
    bad.update(changes)
    gate = validate_evidence([*auth(), bad], now=NOW)
    assert len(gate.evidence) == 3
    assert len(gate.issues) == 1
    result = score(gate)
    assert result.label_candidate == "NEEDS_ANALYST_REVIEW"
    assert "EVIDENCE_REJECTED" in result.reasons


def test_mutated_evidence_cannot_keep_its_previous_identity():
    item = evidence()
    item.value["observed"] = "tampered"
    assert validate_evidence([item], now=NOW).issues


def test_gate_requires_original_timestamp_and_rechecks_age_at_scoring():
    raw = evidence().model_dump(exclude={"evidence_id", "collected_at"})
    assert validate_evidence([raw], now=NOW).issues
    gate = validate_evidence(auth(), now=NOW)
    expired = score_evidence(gate, now=NOW + timedelta(days=8))
    assert expired.label_candidate == "NEEDS_ANALYST_REVIEW"
    assert "EVIDENCE_REJECTED" in expired.reasons


def test_complete_clean_checks_allow_safe_and_risk_output_is_frozen():
    result = score(auth())
    assert result.score == 0
    assert result.label_candidate == "SAFE"
    assert result.coverage.complete and result.coverage.ratio == 1
    with pytest.raises(ValidationError):
        result.score = 100
    with pytest.raises(ValidationError):
        result.label_candidate = "PHISHING"


def test_required_and_applicable_coverage_cannot_be_inferred_or_opted_out():
    assert score([]).label_candidate == "NEEDS_ANALYST_REVIEW"
    missing = score(auth()[:2], applicable_signals=[])
    assert missing.coverage.missing == ("DMARC_FAIL",)
    assert missing.coverage.ratio == pytest.approx(2 / 3)
    applicable = score(auth(), applicable_signals=["HREF_MISMATCH"])
    assert applicable.coverage.missing == ("HREF_MISMATCH",)
    assert applicable.label_candidate == "NEEDS_ANALYST_REVIEW"
    with pytest.raises(ValueError, match="Applicable"):
        score(auth(), applicable_signals=["UNKNOWN_CHECK"])


def test_family_max_then_noisy_or_is_correct_and_order_independent():
    inputs = [*auth("FAIL"), evidence("REPLY_TO_MISMATCH")]
    result = score(inputs)
    # email_auth=max(.25,.35,.45), identity=.40 => 1-(1-.45)*(1-.40)
    assert result.score == pytest.approx(67)
    assert result.label_candidate == "PHISHING"  # Round-2 threshold is 62; arithmetic remains 67.
    assert sum(c.applied_strength > 0 for c in result.contributions) == 2
    assert score(list(reversed(inputs))) == result
    assert score([*inputs, inputs[0]]) == result
    one_auth_failure = [evidence("SPF_FAIL", "PASS"), evidence("DKIM_FAIL", "PASS"), evidence("DMARC_FAIL")]
    assert score(one_auth_failure).score == score(auth("FAIL")).score == 45
    phishing = score([*auth("FAIL"), evidence("HREF_MISMATCH")])
    assert phishing.score == 78 and phishing.label_candidate == "PHISHING"


def test_configured_override_requires_known_confident_failure_but_not_auth_coverage():
    policy_data = load_risk_policy().model_dump()
    policy_data["weights"]["IOC_MATCH"]["weight"] = 0.2
    policy = RiskPolicy.model_validate(policy_data)
    hit = evidence("IOC_MATCH", provenance={"source": "external", "reference": "fake-request:1"})
    result = score([*auth(), hit], policy=policy)
    assert result.score == 95 and result.label_candidate == "PHISHING"
    assert result.overrides == (hit.evidence_id,)
    partial = score([hit], policy=policy)
    assert partial.label_candidate == "PHISHING" and not partial.coverage.complete
    assert score([*auth(), evidence("IOC_MATCH", confidence=0.8)], policy=policy).score == 16
    assert not score([*auth(), evidence("IOC_MATCH", "UNKNOWN")], policy=policy).overrides


def test_conflicts_unknown_zero_confidence_and_wrong_family_require_review():
    cases = [
        [*auth(), evidence("SPF_FAIL")],
        [*auth(), evidence("HREF_MISMATCH", "UNKNOWN")],
        [*auth(), evidence("HREF_MISMATCH", "PASS", confidence=0)],
        [*auth(), evidence("HREF_MISMATCH", family="identity")],
        [*auth(), evidence("HREF_MISMATCH", signal_type="UNCONFIGURED")],
    ]
    for inputs in cases:
        assert score(inputs).label_candidate == "NEEDS_ANALYST_REVIEW"


def test_llm_evidence_is_bounded_and_cannot_activate_strong_override():
    data = load_risk_policy().model_dump()
    data["weights"]["BEC_REQUEST"]["weight"] = 1
    policy = RiskPolicy.model_validate(data)
    item = evidence("BEC_REQUEST", provenance={"source": "llm", "reference": "fake-model:v1"})
    assert score([*auth(), item], policy=policy).score == 10
    with pytest.raises(ValidationError, match="content_bec"):
        evidence(provenance={"source": "llm", "reference": "fake-model:v1"})
    data["overrides"]["BEC_REQUEST"] = {"min_score": 100, "min_confidence": 0.9}
    with pytest.raises(ValidationError, match="overrides"):
        RiskPolicy.model_validate(data)


def test_invalid_policy_fails_explicitly(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("version: 1\nweights: {}\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_risk_policy(path)


def test_tool_result_success_and_failure_are_distinct():
    ok = ToolResult[dict](status="OK", data={"found": False}, latency_ms=12)
    assert ok.data == {"found": False}
    failed = ToolResult[dict](status="TIMEOUT", error_code="deadline", error_message="Timed out", latency_ms=1000)
    assert failed.data is None
    with pytest.raises(ValidationError):
        ToolResult[dict](status="ERROR", data={"found": False}, latency_ms=1)
    with pytest.raises(ValidationError):
        ToolResult(status="OK", error_code="failure", latency_ms=1)
    with pytest.raises(ValidationError):
        ToolResult(status="OK", latency_ms=-1)


def test_graph_core_nodes_preserve_gate_rejections_for_risk():
    # Exercise only the existing Gate/Risk nodes; no parser or analyzer implementation.
    state = evidence_node({"evidence": [{"broken": True}]})
    result = risk_node(state)["risk_result"]
    assert result.label_candidate == "NEEDS_ANALYST_REVIEW"
    assert "EVIDENCE_REJECTED" in result.reasons
