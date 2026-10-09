from typing import Any

from pydantic import ValidationError

from src.evidence.models import Evidence, RiskResult
from src.evidence.risk_engine import RiskPolicy, load_risk_policy
from src.schemas.verdict import (
    Claim,
    ClaimType,
    ClaimValidationResult,
    EvidenceFact,
    IndicatorReference,
    Verdict,
    render_claim,
    render_summary,
)

FAMILY_CLAIMS: dict[str, ClaimType] = {
    "email_auth": "AUTHENTICATION",
    "identity": "IDENTITY",
    "url_deception": "URL",
    "attachment": "ATTACHMENT",
    "qr": "QR",
    "threat_intel": "IOC",
    "content_bec": "CONTENT_BEC",
}


def fact_view(item: Evidence) -> EvidenceFact:
    return EvidenceFact(
        evidence_id=item.evidence_id, signal_type=item.signal_type, family=item.family, result=item.result
    )


def compatible_claim(fact: EvidenceFact, policy: RiskPolicy) -> ClaimType | None:
    rule = policy.weights.get(fact.signal_type)
    if rule is None or rule.family != fact.family:
        return None
    return "UNCERTAINTY" if fact.result == "UNKNOWN" else FAMILY_CLAIMS.get(rule.family)


def canonical_indicators(item: Evidence) -> tuple[IndicatorReference, ...]:
    """Typed paths are resolved from the referenced fact, never from generated prose."""
    values = {"indicator": item.indicator}
    value = item.value
    if isinstance(value, dict):
        for key in ("canonical_url", "displayed_url", "protected_domain", "from_domain", "sha256"):
            if isinstance(value.get(key), str) and value[key]:
                values[f"value.{key}"] = value[key]
        if value.get("kind") in {"domain", "url", "ip", "hash"}:
            for key in ("value", "indicator"):
                if isinstance(value.get(key), str) and value[key]:
                    values[f"value.{key}"] = value[key]
        for key in ("observed_domains", "displayed_domains"):
            for index, domain in enumerate(value.get(key, [])):
                if isinstance(domain, str) and domain:
                    values[f"value.{key}.{index}"] = domain
    return tuple(
        IndicatorReference(evidence_id=item.evidence_id, path=path, value=value)
        for path, value in sorted(values.items())
    )


def validate_verdict_claims(
    proposal: Verdict | dict[str, Any] | None,
    evidence: list[Evidence] | tuple[Evidence, ...],
    risk: RiskResult,
    *,
    policy: RiskPolicy | None = None,
) -> ClaimValidationResult:
    """Conservative Gate 2: exact fact templates, canonical bindings, bounded actions.

    Arbitrary paraphrases are deliberately rejected: matching an IOC substring cannot
    establish the truth of free prose or of an unrelated analyst summary.
    """
    policy = policy or load_risk_policy()
    by_id = {item.evidence_id: item for item in evidence}
    payload = proposal.model_dump() if isinstance(proposal, Verdict) else proposal
    fallback = Verdict(score=risk.score, label_candidate=risk.label_candidate, analyst_summary=render_summary(risk, 0))
    if not isinstance(payload, dict):
        return ClaimValidationResult(
            verdict=fallback,
            accepted=False,
            status="REJECTED",
            assessment_label="NEEDS_ANALYST_REVIEW",
            reasons=("UNGROUNDED_CLAIM", "INVALID_VERDICT_SCHEMA"),
        )
    try:
        # Validate each claim separately so one malformed claim does not hide good ones.
        envelope = Verdict.model_validate({**payload, "claims": ()})
        raw_claims = payload.get("claims", ())
        if not isinstance(raw_claims, (tuple, list)) or len(raw_claims) > 64:
            raise ValueError("Invalid claim collection")
    except (ValidationError, ValueError, TypeError):
        return ClaimValidationResult(
            verdict=fallback,
            accepted=False,
            status="REJECTED",
            assessment_label="NEEDS_ANALYST_REVIEW",
            reasons=("UNGROUNDED_CLAIM", "INVALID_VERDICT_SCHEMA"),
        )
    reasons: set[str] = set()
    if envelope.score != risk.score:
        reasons.add("SCORE_MISMATCH")
    if envelope.label_candidate != risk.label_candidate:
        reasons.add("LABEL_MISMATCH")
    if envelope.analyst_summary != render_summary(risk, len(raw_claims)):
        reasons.add("UNGROUNDED_SUMMARY")
    valid: list[Claim] = []
    rejected: list[int] = []
    for index, raw_claim in enumerate(raw_claims):
        try:
            claim = Claim.model_validate(raw_claim)
            if len(set(claim.evidence_ids)) != len(claim.evidence_ids):
                raise ValueError("Duplicate references")
            items = tuple(by_id[key] for key in claim.evidence_ids)
            facts = tuple(fact_view(item) for item in items)
            if any(compatible_claim(fact, policy) != claim.claim_type for fact in facts):
                raise ValueError("Incompatible claim type/signal")
            if claim.text != render_claim(facts):
                raise ValueError("Unsupported claim text")
            canonical = tuple(reference for item in items for reference in canonical_indicators(item))
            if claim.indicators and claim.indicators != canonical:
                raise ValueError("Invented or non-canonical indicator")
            valid.append(claim.model_copy(update={"indicators": canonical}))
        except (ValidationError, ValueError, TypeError, KeyError):
            rejected.append(index)
    if rejected:
        reasons.add("UNGROUNDED_CLAIM")
    actions = envelope.recommended_actions
    if "VERIFY_SENDER_OUT_OF_BAND" in actions and not any(
        item.family == "identity" and item.result == "FAIL" for item in evidence
    ):
        reasons.add("UNGROUNDED_ACTION")
        actions = ("REVIEW_EVIDENCE",)
    if reasons:
        reasons.add("UNGROUNDED_CLAIM")
    grounded = Verdict(
        score=risk.score,
        label_candidate=risk.label_candidate,
        claims=tuple(valid),
        recommended_actions=actions,
        analyst_summary=render_summary(risk, len(valid)),
    )
    return ClaimValidationResult(
        verdict=grounded,
        accepted=not reasons,
        status="FILTERED" if reasons else "PASS",
        assessment_label="NEEDS_ANALYST_REVIEW" if reasons or not risk.coverage.complete else risk.label_candidate,
        reasons=tuple(sorted(reasons)),
        rejected_claim_indices=tuple(rejected),
    )
