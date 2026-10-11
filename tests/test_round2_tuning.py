import pytest
from pydantic import ValidationError

from eval.round2 import bounded_partial, candidate_policy, transitions
from src.evidence.models import Evidence
from src.evidence.risk_engine import RiskPolicy, load_risk_policy
from tests.test_core_contracts import auth, evidence, score


def partial_items(signal="HREF_MISMATCH", marker="URL_ANALYSIS"):
    return [*auth("UNKNOWN"), evidence("HEADER_ANALYSIS", "UNKNOWN"),
            evidence(signal), evidence(marker, "PASS")]


def test_bounded_partial_header_retains_unknown_and_requires_positive_local_scan():
    result = score(partial_items())
    assert result.label_candidate == "SUSPICIOUS" and result.score == 60
    assert not result.coverage.complete and "HEADER_ANALYSIS" in result.coverage.unknown
    assert {"SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"} <= set(result.coverage.missing)
    assert score(partial_items("ATTACHMENT_EXECUTABLE", "ATTACHMENT_ANALYSIS")).label_candidate == "SUSPICIOUS"
    assert score(auth("UNKNOWN")).label_candidate == "NEEDS_ANALYST_REVIEW"
    assert score(auth()).label_candidate == "SAFE"
    assert score(partial_items("URL_SHORTENER")).label_candidate == "NEEDS_ANALYST_REVIEW"


@pytest.mark.parametrize("gap,status", [("URL_ANALYSIS", "OK"), ("ATTACHMENT_ANALYSIS", "OK"),
                                      ("QR_ANALYSIS", "OK"), ("URL_IOC_CHECK", "TIMEOUT"),
                                      ("BEC_REQUEST", "ERROR")])
def test_static_gaps_and_failed_tools_still_block_partial_header_exception(gap, status):
    items = [e for e in partial_items() if e.signal_type != gap]
    items.append(evidence(gap, "UNKNOWN", tool_status=status))
    assert score(items).label_candidate == "NEEDS_ANALYST_REVIEW"


def test_no_marker_llm_external_conflicts_or_rejections_can_unlock_exception():
    assert score(partial_items()[:-1]).label_candidate == "NEEDS_ANALYST_REVIEW"
    with pytest.raises(ValidationError, match="LLM evidence must belong to content_bec"):
        evidence("HREF_MISMATCH", provenance={"source": "llm", "reference": "fixture"})
    items = partial_items()
    items[4] = evidence("HREF_MISMATCH", provenance={"source": "external", "reference": "fixture"})
    assert score(items).label_candidate == "NEEDS_ANALYST_REVIEW"
    items[4] = evidence("BEC_REQUEST", provenance={"source": "llm", "reference": "fixture"})
    assert score(items).label_candidate == "NEEDS_ANALYST_REVIEW"
    assert score([*partial_items(), evidence("HREF_MISMATCH", "PASS")]).label_candidate == "NEEDS_ANALYST_REVIEW"
    assert score([*partial_items(), {"broken": True}]).label_candidate == "NEEDS_ANALYST_REVIEW"
    assert score([*auth("UNKNOWN"), evidence("HEADER_ANALYSIS", "UNKNOWN"),
                  evidence("REPLY_TO_MISMATCH"), evidence("URL_ANALYSIS", "PASS")]).label_candidate == "NEEDS_ANALYST_REVIEW"


def test_ip_literal_alone_needs_corroboration_for_phishing_and_family_max_remains():
    items = [*auth("UNKNOWN"), evidence("URL_IP_LITERAL")]
    assert score(items).score == 55 and score(items).label_candidate == "SUSPICIOUS"
    assert score([*items, evidence("URL_OBFUSCATED")]).score == 55
    positive = score([*items, evidence("RETURN_PATH_MISMATCH")])
    assert positive.score == 66.25 and positive.label_candidate == "PHISHING"
    assert load_risk_policy().llm_weight_cap == .1
    assert load_risk_policy().weights["IOC_DERIVED_DOMAIN"].weight == .2


def test_search_hypothesis_matches_production_but_opt_in_is_required():
    base = load_risk_policy()
    values = base.model_dump()
    values["allow_partial_header_suspicious"] = False
    old = RiskPolicy.model_validate(values)
    items = partial_items()
    prior = score(items, policy=old)
    assert prior.label_candidate == "NEEDS_ANALYST_REVIEW"
    assert bounded_partial(prior, items, old)
    assert score(items, policy=base).label_candidate == "SUSPICIOUS"
    weaker = candidate_policy(base, {"ip_weight": .4, "phishing": 65})
    assert weaker.weights["URL_IP_LITERAL"].weight == .4
    assert transitions([{"case_id": "x", "status": "success", "expected_label": "PHISHING",
                         "predicted_label": "NEEDS_ANALYST_REVIEW"}],
                       [{"case_id": "x", "predicted_label": "SUSPICIOUS"}]) == {
                           "PHISHING: NEEDS_ANALYST_REVIEW -> SUSPICIOUS": 1}
    assert all(isinstance(item, Evidence) for item in items)
