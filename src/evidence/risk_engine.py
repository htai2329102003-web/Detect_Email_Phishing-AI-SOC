from collections.abc import Iterable
from datetime import datetime
from math import prod
from pathlib import Path
from typing import Any, Literal, Self

import yaml
from pydantic import Field, model_validator

from src.evidence.models import Contract, Contribution, Coverage, Evidence, Gate1Result, NonEmpty, RiskResult
from src.evidence.validation import validate_evidence


class FamilyPolicy(Contract):
    cap: float = Field(ge=0.0, le=1.0)


class SignalPolicy(Contract):
    family: NonEmpty
    weight: float = Field(ge=0.0, le=1.0)


class Thresholds(Contract):
    suspicious: float = Field(gt=0.0, le=100.0)
    phishing: float = Field(gt=0.0, le=100.0)


class OverridePolicy(Contract):
    min_score: float = Field(ge=0.0, le=100.0)
    min_confidence: float = Field(gt=0.0, le=1.0)


class RiskPolicy(Contract):
    version: Literal[1]
    thresholds: Thresholds
    required_signals: tuple[NonEmpty, ...] = Field(min_length=1)
    llm_weight_cap: float = Field(ge=0.0, le=0.15)
    families: dict[NonEmpty, FamilyPolicy]
    weights: dict[NonEmpty, SignalPolicy]
    overrides: dict[NonEmpty, OverridePolicy] = Field(default_factory=dict)

    @model_validator(mode="after")
    def check_policy(self) -> Self:
        if self.thresholds.suspicious >= self.thresholds.phishing:
            raise ValueError("Suspicious threshold must be below phishing threshold")
        if any(signal.family not in self.families for signal in self.weights.values()):
            raise ValueError("All signals must reference configured families")
        if not set(self.required_signals).issubset(self.weights):
            raise ValueError("Required signals must be configured")
        if not set(self.overrides).issubset(self.weights):
            raise ValueError("Overrides must reference configured signals")
        if any(self.weights[name].family == "content_bec" for name in self.overrides):
            raise ValueError("Content/LLM signals cannot trigger strong overrides")
        if "content_bec" in self.families and self.families["content_bec"].cap > 0.15:
            raise ValueError("content_bec family must have a low cap")
        return self


def load_risk_policy(path: str | Path | None = None) -> RiskPolicy:
    """Fail explicitly on invalid policy rather than silently scoring with defaults."""
    path = Path(path) if path is not None else Path(__file__).resolve().parents[2] / "config" / "risk_weights.yaml"
    with path.open(encoding="utf-8") as handle:
        return RiskPolicy.model_validate(yaml.safe_load(handle))


def score_evidence(
    evidence: Iterable[Any] | Gate1Result,
    *,
    applicable_signals: Iterable[str] = (),
    policy: RiskPolicy | None = None,
    now: datetime | None = None,
) -> RiskResult:
    """Max within each family, then noisy-OR across families. No LLM is involved.

    Required checks cannot be opted out. Callers must additionally enumerate checks
    applicable to the case (e.g. URL checks when URLs exist); absent PASS is not inferred.
    """
    policy = policy or load_risk_policy()
    # Revalidate a Gate result at scoring time as timestamps/data may have changed.
    prior_issues = evidence.issues if isinstance(evidence, Gate1Result) else ()
    gate = validate_evidence(evidence.evidence if isinstance(evidence, Gate1Result) else evidence, now=now)
    applicable = set(applicable_signals)
    if not applicable.issubset(policy.weights):
        raise ValueError("Applicable checks must be configured signals")
    # Observed configured checks are necessarily applicable, even if omitted by caller.
    applicable |= {item.signal_type for item in gate.evidence if item.signal_type in policy.weights}
    applicable -= set(policy.required_signals)
    expected = set(policy.required_signals) | applicable
    reasons: set[str] = set()
    if prior_issues or gate.issues:
        reasons.add("EVIDENCE_REJECTED")
    usable: list[Evidence] = []
    for item in gate.evidence:
        rule = policy.weights.get(item.signal_type)
        if rule is None or rule.family != item.family:
            reasons.add("UNCONFIGURED_SIGNAL_OR_FAMILY")
        else:
            usable.append(item)

    unknown = {item.signal_type for item in usable if item.result == "UNKNOWN" or item.confidence == 0.0}
    # Contradictory outcomes for the same check/target require analyst review.
    outcomes: dict[tuple[str, str, str, str], set[str]] = {}
    for item in usable:
        key = (item.analyzer, item.tool, item.signal_type, item.indicator)
        outcomes.setdefault(key, set()).add(item.result)
    for key, results in outcomes.items():
        if "PASS" in results and "FAIL" in results:
            unknown.add(key[2])
            reasons.add("CONFLICTING_EVIDENCE")
    completed = {item.signal_type for item in usable if item.result != "UNKNOWN" and item.confidence > 0.0} - unknown
    missing = expected - completed
    if unknown:
        reasons.add("UNKNOWN_EVIDENCE")
    if missing:
        reasons.add("MISSING_COVERAGE")
    coverage = Coverage(
        required=tuple(sorted(set(policy.required_signals))),
        applicable=tuple(sorted(applicable)),
        completed=tuple(sorted(completed)),
        missing=tuple(sorted(missing)),
        unknown=tuple(sorted(unknown)),
        ratio=len(expected & completed) / len(expected),
        complete=not reasons,
    )

    strengths: dict[str, float] = {}
    failures = [item for item in usable if item.result == "FAIL"]
    for item in failures:
        weight = policy.weights[item.signal_type].weight
        if item.provenance.source == "llm":
            weight = min(weight, policy.llm_weight_cap)
        strengths[item.evidence_id] = min(weight * item.confidence, policy.families[item.family].cap)
    winners: dict[str, Evidence] = {}
    for item in sorted(failures, key=lambda item: item.evidence_id):
        previous = winners.get(item.family)
        if previous is None or strengths[item.evidence_id] > strengths[previous.evidence_id]:
            winners[item.family] = item
    contributions = tuple(
        Contribution(
            evidence_id=item.evidence_id,
            signal_type=item.signal_type,
            family=item.family,
            strength=strengths[item.evidence_id],
            applied_strength=strengths[item.evidence_id] if winners[item.family] == item else 0.0,
        )
        for item in sorted(failures, key=lambda item: item.evidence_id)
    )
    score = 100.0 * (1.0 - prod(1.0 - strengths[winners[family].evidence_id] for family in sorted(winners)))
    overrides: set[str] = set()
    for item in failures:
        override = policy.overrides.get(item.signal_type)
        if override is not None and item.provenance.source != "llm" and item.confidence >= override.min_confidence:
            score = max(score, override.min_score)
            overrides.add(item.evidence_id)
    score = round(score, 6)
    # Coverage takes precedence over overrides; strong evidence still retains its score.
    if not coverage.complete:
        label = "NEEDS_ANALYST_REVIEW"
    elif score >= policy.thresholds.phishing:
        label = "PHISHING"
    elif score >= policy.thresholds.suspicious:
        label = "SUSPICIOUS"
    else:
        label = "SAFE"
    return RiskResult(
        score=score,
        label_candidate=label,
        coverage=coverage,
        contributions=contributions,
        overrides=tuple(sorted(overrides)),
        reasons=tuple(sorted(reasons)),
    )
