from datetime import UTC, datetime

from eval.post_stage7 import impact_category, upper_bound_evidence
from src.evidence.models import Coverage, RiskResult


def risk(score, label, *, complete=True):
    coverage = Coverage(required=(), applicable=(), completed=(), missing=() if complete else ("SPF_FAIL",),
                        unknown=() if complete else ("SPF_FAIL",), ratio=1 if complete else 0, complete=complete)
    return RiskResult(score=score, label_candidate=label, coverage=coverage)


def test_impact_categories_distinguish_threshold_coverage_and_review_paths():
    assert impact_category(risk(64, "SUSPICIOUS"), risk(67.6, "PHISHING")) == "BEC_COULD_CHANGE_SCORE_THRESHOLD"
    assert impact_category(risk(0, "NEEDS_ANALYST_REVIEW", complete=False),
                           risk(0, "SAFE")) == "BEC_COULD_CHANGE_COVERAGE"
    assert impact_category(risk(30, "NEEDS_ANALYST_REVIEW", complete=False),
                           risk(30, "SUSPICIOUS", complete=False)) == "BEC_COULD_CHANGE_REVIEW_TO_SUSPICIOUS"
    assert impact_category(risk(65, "NEEDS_ANALYST_REVIEW", complete=False),
                           risk(65, "PHISHING", complete=False)) == "BEC_COULD_CHANGE_REVIEW_TO_PHISHING"
    assert impact_category(risk(20, "SAFE"), risk(28, "SAFE")) == "BEC_CANNOT_CHANGE_RESULT"


def test_upper_bound_is_exact_weak_llm_contract():
    item = upper_bound_evidence(datetime.now(UTC))
    assert item.signal_type == "BEC_REQUEST" and item.family == "content_bec"
    assert item.provenance.source == "llm" and item.confidence == 1 and item.result == "FAIL"
