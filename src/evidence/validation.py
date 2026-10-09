from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import ValidationError

from src.evidence.models import Evidence, Gate1Result, ValidationIssue


def validate_evidence(
    items: Iterable[Any],
    *,
    now: datetime | None = None,
    max_age: timedelta = timedelta(days=7),
    future_skew: timedelta = timedelta(minutes=5),
) -> Gate1Result:
    """Reject individual bad items without hiding errors or losing good evidence."""
    now = now or datetime.now(UTC)
    if now.tzinfo is None or now.utcoffset() is None or max_age < timedelta(0) or future_skew < timedelta(0):
        raise ValueError("Validation clock must be aware and time windows non-negative")
    accepted: dict[str, Evidence] = {}
    issues: list[ValidationIssue] = []
    duplicates: set[str] = set()
    for index, item in enumerate(items):
        try:
            candidate = Evidence.model_validate(item.model_dump() if isinstance(item, Evidence) else item)
        except (ValidationError, ValueError, TypeError, OverflowError):
            issues.append(ValidationIssue(index=index, code="INVALID_SCHEMA"))
            continue
        if not now - max_age <= candidate.collected_at <= now + future_skew:
            issues.append(ValidationIssue(index=index, code="INVALID_TIMESTAMP"))
            continue
        if candidate.evidence_id in accepted:
            duplicates.add(candidate.evidence_id)
        previous = accepted.get(candidate.evidence_id)
        if previous is None or candidate.collected_at > previous.collected_at:
            accepted[candidate.evidence_id] = candidate
    return Gate1Result(
        evidence=tuple(accepted[key] for key in sorted(accepted)),
        issues=tuple(issues),
        duplicate_ids=tuple(sorted(duplicates)),
    )
