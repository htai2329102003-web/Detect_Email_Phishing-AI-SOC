from pathlib import Path

import pytest

from src.agents.graph import build_graph
from src.analyzers.header_analyzer import analyze_headers
from src.evidence.risk_engine import RiskPolicy, load_risk_policy
from src.parsers.email_parser import EmailParseError, parse_email
from src.services.ioc_store import InMemoryIOCStore
from tests.test_core_contracts import auth, evidence
from tests.test_core_contracts import score as configured_score


def score(items):
    # Freeze the P0 policy in this P0 regression; Round-1 tests exercise the new
    # opt-in partial SUSPICIOUS contract and tuned threshold separately.
    data = load_risk_policy().model_dump()
    data["thresholds"]["phishing"] = 70
    data["allow_partial_suspicious"] = False
    return configured_score(items, policy=RiskPolicy.model_validate(data))


def test_partial_coverage_requires_independent_deterministic_phishing_strength():
    unknown_auth = auth("UNKNOWN")
    assert score(unknown_auth).label_candidate == "NEEDS_ANALYST_REVIEW"
    assert score([*unknown_auth, evidence("HREF_MISMATCH")]).label_candidate == "NEEDS_ANALYST_REVIEW"
    strong = [*unknown_auth, evidence("HREF_MISMATCH"), evidence("REPLY_TO_MISMATCH")]
    result = score(strong)
    assert result.score == 76 and result.label_candidate == "PHISHING"
    assert not result.coverage.complete and len(result.coverage.unknown) == 3
    assert score([*strong, evidence("HREF_MISMATCH", "PASS")]).label_candidate == "NEEDS_ANALYST_REVIEW"
    rejected = {"broken": "contract"}
    assert score([*strong, rejected]).label_candidate == "NEEDS_ANALYST_REVIEW"
    # LLM evidence cannot supply the missing strength for this exception.
    llm = evidence("BEC_REQUEST", provenance={"source": "llm", "reference": "test"})
    near = evidence("REPLY_TO_MISMATCH", confidence=0.5)
    assert score([*unknown_auth, evidence("HREF_MISMATCH"), near, llm]).score > 70
    assert score([*unknown_auth, evidence("HREF_MISMATCH"), near, llm]).label_candidate == "NEEDS_ANALYST_REVIEW"
    failed = evidence("URL_IOC_CHECK", "UNKNOWN", tool_status="TIMEOUT")
    assert score([*auth(), failed]).label_candidate == "NEEDS_ANALYST_REVIEW"


@pytest.mark.parametrize("headers,field", [
    (b"From: bad\n", "from"),
    (b"From: one@example.test\nReply-To: bad\n", "reply-to"),
    (b"From: one@example.test\nReply-To: a@a.test\nReply-To: b@b.test\n", "reply-to"),
    (b"From: one@example.test\nReturn-Path: <a@a.test>\nReturn-Path: <b@b.test>\n", "return-path"),
    (b"From: one@example.test\nSubject: first\nSubject: second\n", "subject"),
])
@pytest.mark.asyncio
async def test_partial_parse_preserves_raw_and_runs_all_static_branches(headers, field):
    raw = headers + b"\nVisit https://example.test/path"
    state = await build_graph(ioc_client=InMemoryIOCStore()).ainvoke({"raw_email": raw})
    parsed = state["parsed_email"]
    assert parsed["raw_bytes"] == raw and parsed["partial_parse"]
    assert field in parsed["unavailable_headers"] and field not in parsed["headers"]
    assert len(parsed["raw_headers"]) == len(headers.splitlines())
    assert "https://example.test/path" in parsed["urls"]
    assert {r["analyzer"] for r in state["analyzer_runs"]} == {"header", "url", "attachment", "qr"}
    assert "HEADER_ANALYSIS" in state["risk_result"].coverage.unknown
    assert state["risk_result"].label_candidate == "NEEDS_ANALYST_REVIEW"
    assert "raw_bytes" not in state["redacted_for_llm"]
    if field == "reply-to":
        assert next(e for e in analyze_headers(parsed) if e.signal_type == "REPLY_TO_MISMATCH").result == "UNKNOWN"


def test_header_fetch_index_error_is_isolated(monkeypatch):
    from email.policy import EmailPolicy

    original = EmailPolicy.header_fetch_parse

    def broken(self, name, value):
        if name.lower() == "message-id":
            raise IndexError("stdlib malformed Message-ID regression")
        return original(self, name, value)

    monkeypatch.setattr(EmailPolicy, "header_fetch_parse", broken)
    raw = b"From: a@example.test\nMessage-ID: <broken>\n\nhttps://example.test"
    parsed = parse_email(raw).raw_for_analyzers
    assert parsed["from"]["domain"] == "example.test" and parsed["urls"]
    assert {"code": "HEADER_PARSE_ERROR", "field": "message-id"} in parsed["parser_warnings"]


@pytest.mark.parametrize("content_type", [b"multipart/mixed", b'multipart/mixed; boundary="missing"'])
def test_unrecoverable_mime_remains_rejected(content_type):
    with pytest.raises(EmailParseError, match="MIME"):
        parse_email(b"From: a@example.test\nContent-Type: " + content_type + b"\n\nno parts")


def test_clean_parser_has_no_recovery_warnings():
    parsed = parse_email((Path(__file__).parent / "fixtures/emails/clean.eml").read_bytes()).raw_for_analyzers
    assert not parsed["partial_parse"] and not parsed["parser_warnings"]


def test_headerless_body_and_damaged_base64_are_only_partial():
    for raw in (b"unstructured body without headers",
                b"From: a@example.test\nContent-Transfer-Encoding: base64\n\naGVsbG8"):
        parsed = parse_email(raw).raw_for_analyzers
        assert parsed["partial_parse"] and parsed["parser_warnings"]
        assert parsed["raw_bytes"] == raw and parsed["text_body"]
        if not parsed["headers"]:
            assert not parsed["from"]
