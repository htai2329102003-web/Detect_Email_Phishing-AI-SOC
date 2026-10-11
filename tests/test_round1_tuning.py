import pytest

from src.analyzers.common import ioc_evidence
from src.evidence.risk_engine import RiskPolicy, load_risk_policy, score_evidence
from src.services.ioc_store import InMemoryIOCStore, IOCRecord
from tests.test_core_contracts import auth, evidence
from tests.test_core_contracts import score as configured_score


def score(items):
    # Historical C4 regression; Round-2 tests exercise the current policy.
    values = load_risk_policy().model_dump()
    values["thresholds"]["phishing"] = 65
    values["weights"]["URL_IP_LITERAL"]["weight"] = .4
    values["allow_partial_header_suspicious"] = False
    return configured_score(items, policy=RiskPolicy.model_validate(values))


def test_partial_positive_triage_does_not_unlock_safe_or_fabricate_auth():
    result = score([*auth("UNKNOWN"), evidence("HREF_MISMATCH")])
    assert result.label_candidate == "SUSPICIOUS" and result.score == 60
    assert set(result.coverage.unknown) == {"SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"}
    assert not result.coverage.complete
    assert score(auth("UNKNOWN")).label_candidate == "NEEDS_ANALYST_REVIEW"
    assert score(auth()).label_candidate == "SAFE"


@pytest.mark.parametrize("signal,status", [
    ("URL_ANALYSIS", "OK"), ("HEADER_ANALYSIS", "OK"),
    ("ATTACHMENT_ANALYSIS", "OK"), ("QR_ANALYSIS", "OK"), ("URL_IOC_CHECK", "TIMEOUT"),
])
def test_partial_suspicious_cannot_bypass_critical_gaps_or_failed_tools(signal, status):
    result = score([*auth("UNKNOWN"), evidence("HREF_MISMATCH"), evidence(signal, "UNKNOWN", tool_status=status)])
    assert result.label_candidate == "NEEDS_ANALYST_REVIEW"


def test_llm_cannot_push_partial_positive_decision_over_phishing_threshold():
    items = [*auth("UNKNOWN"), evidence("HREF_MISMATCH"), evidence("REPLY_TO_MISMATCH", confidence=.25)]
    llm = evidence("BEC_REQUEST", provenance={"source": "llm", "reference": "test-fixture"})
    result = score([*items, llm])
    assert result.score > 65 and result.label_candidate == "SUSPICIOUS"
    assert score([*auth("UNKNOWN"), llm]).label_candidate == "NEEDS_ANALYST_REVIEW"


@pytest.mark.parametrize("kind,value,derived,expected", [
    ("domain", "shared.test", True, "IOC_DERIVED_DOMAIN"),
    ("domain", "dedicated.test", False, "IOC_MATCH"),
    ("url", "https://shared.test/bad", False, "IOC_MATCH"),
    ("ip", "192.0.2.1", False, "IOC_MATCH"),
    ("hash", "a" * 64, False, "IOC_MATCH"),
])
def test_exact_scope_is_preserved_without_inheriting_url_malice_to_a_whole_host(kind, value, derived, expected):
    record = IOCRecord(kind=kind, value=value, source="local-fixture", derived=derived,
                       derived_from="https://shared.test/bad" if derived else None)
    facts = ioc_evidence("url", value, [(kind, value)], InMemoryIOCStore((record,)), "URL_IOC_CHECK")
    hit = next(e for e in facts if e.result == "FAIL")
    assert hit.signal_type == expected and hit.value["derived"] == derived
    result = score_evidence(facts)
    if derived:
        assert result.score == 20 and not result.overrides
        assert result.label_candidate == "NEEDS_ANALYST_REVIEW"
    else:
        assert result.score == 95 and result.overrides
        assert result.label_candidate == "PHISHING"


def test_direct_malicious_domain_assertion_survives_a_derived_record_collision():
    record = IOCRecord(kind="domain", value="bad.test", source="fixture", derived=True,
                       matched_records=({"role": "MALICIOUS", "derived": False},))
    facts = ioc_evidence("url", "bad.test", [("domain", "bad.test")], InMemoryIOCStore((record,)), "URL_IOC_CHECK")
    assert next(e for e in facts if e.result == "FAIL").signal_type == "IOC_MATCH"
    assert score_evidence(facts).label_candidate == "PHISHING"
