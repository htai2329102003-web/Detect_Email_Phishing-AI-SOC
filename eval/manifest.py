import json
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from eval.schemas import EvalCase, EvalError


@dataclass(frozen=True)
class ManifestEntry:
    line: int
    case_id: str
    case: EvalCase | None = None
    error: EvalError | None = None


def _invalid_constant(value):
    raise ValueError("Non-finite JSON constant")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON property")
        result[key] = value
    return result


def load_manifest(path: str | Path) -> list[ManifestEntry]:
    """Keep invalid rows as failures; never silently drop a nonblank case."""
    entries, seen = [], set()
    with Path(path).open(encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            identifier = f"manifest-line-{line_number}"
            try:
                payload = json.loads(line, parse_constant=_invalid_constant, object_pairs_hook=_unique_object)
                case = EvalCase.model_validate(payload)
                identifier = case.id
                if case.id in seen:
                    entries.append(
                        ManifestEntry(
                            line_number,
                            identifier,
                            error=EvalError(
                                stage="manifest",
                                code="DUPLICATE_CASE_ID",
                                message="Case ID already appeared in this manifest",
                            ),
                        )
                    )
                    continue
                seen.add(case.id)
                entries.append(ManifestEntry(line_number, identifier, case=case))
            except (ValueError, TypeError, ValidationError) as exc:
                fields = (
                    ", ".join(".".join(str(p) for p in error["loc"]) for error in exc.errors())
                    if isinstance(exc, ValidationError)
                    else "JSON"
                )
                entries.append(
                    ManifestEntry(
                        line_number,
                        identifier,
                        error=EvalError(
                            stage="manifest",
                            code="INVALID_MANIFEST_CASE",
                            message=f"Invalid case fields: {fields}",
                            exception_type=type(exc).__name__,
                        ),
                    )
                )
    return entries
