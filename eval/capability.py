"""Frozen-package capability catalog; independent of email EvalCase/RiskLabel."""

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import Field, JsonValue

from eval.manifest import _invalid_constant, _unique_object
from src.evidence.models import Contract, Evidence, EvidenceResult, NonEmpty

Capability = Literal["vietnamese_url", "bec", "qr_analyzer", "prompt_injection", "auth_header", "attachment"]


class CapabilityCase(Contract):
    capability: Capability
    sample_id: NonEmpty
    file: NonEmpty
    input_type: Literal["url", "content", "image", "email"]
    expected_label: str | None = None  # Source vocabulary, never coerced to RiskLabel.
    expected_signals: tuple[str, ...] = ()
    expected_results: dict[str, EvidenceResult] = Field(default_factory=dict)
    source: NonEmpty
    language: str | None = None
    split: str
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    payload: dict[str, JsonValue] = Field(default_factory=dict, repr=False)


class CapabilityResult(Contract):
    case: CapabilityCase
    execution_target: str
    status: Literal["OK", "UNKNOWN", "UNAVAILABLE", "ERROR"]
    predicted_positive: bool | None = None
    evidence: tuple[Evidence, ...] = ()
    observations: dict[str, JsonValue] = Field(default_factory=dict)
    error_code: str | None = None
    latency_ms: float = Field(default=0, ge=0)


def resolve_input(root: Path, filename: str) -> Path:
    path = (root / filename).resolve()
    if Path(filename).is_absolute() or not path.is_relative_to(root.resolve()):
        raise ValueError("CAPABILITY_PATH_OUTSIDE_DATA_ROOT")
    return path


def jsonl(path: Path):
    with path.open(encoding="utf-8-sig") as stream:
        for number, line in enumerate(stream, 1):
            if line.strip():
                try:
                    row = json.loads(line, parse_constant=_invalid_constant, object_pairs_hook=_unique_object)
                    if not isinstance(row, dict):
                        raise ValueError("Object required")
                    yield number, row
                except (ValueError, TypeError) as exc:
                    raise ValueError(f"INVALID_CAPABILITY_MANIFEST:{path.name}:{number}") from exc


def load_catalog(root: Path) -> list[CapabilityCase]:
    """Expand the actual aggregate URL row and indexed CSV; retain every source row.

    Reading TEST metadata for inventory is not evaluation. Runner selection excludes TEST.
    """
    cases, csv_cache = [], {}
    for name, split in (("capability", "capability"), ("security", "security"),
                        ("dev", "dev"), ("test", "test"), ("auxiliary", "auxiliary")):
        manifest = root / "manifests" / f"{name}_manifest.jsonl"
        for _, row in jsonl(manifest):
            path = resolve_input(root, row["file"])
            capabilities = row.get("capabilities", [])
            meta = row.get("metadata", {})
            base = dict(sample_id=row["id"], file=row["file"], source=row["source"], split=split,
                        expected_label=row.get("expected_label"), language=row.get("language"), metadata=meta,
                        expected_signals=tuple(row.get("expected_signals", [])),
                        expected_results=row.get("expected_results", {}))
            if "vietnamese_url" in capabilities:
                for number, url in jsonl(path):
                    cases.append(CapabilityCase(**{**base, "sample_id": url.get("id", f"{row['id']}:{number}"),
                        "expected_label": url["expected_label"], "language": url.get("language"),
                        "metadata": {**meta, **url.get("metadata", {}), "tier": url.get("tier"),
                                     "manifest_record": row, "record_number": number}},
                        capability="vietnamese_url", input_type="url", payload=url))
            if "bec" in capabilities:
                if path not in csv_cache:
                    with path.open(encoding="utf-8-sig", newline="") as stream:
                        csv_cache[path] = list(csv.DictReader(stream))
                index = meta["row_index"]
                if isinstance(index, bool) or not isinstance(index, int) or not 1 <= index <= len(csv_cache[path]):
                    raise ValueError("BEC_ROW_INDEX_INVALID")
                content = csv_cache[path][index - 1]
                cases.append(CapabilityCase(**{**base, "expected_label": content["Human"],
                    "metadata": {**meta, "manifest_expected_label": row.get("expected_label")}},
                    capability="bec", input_type="content", payload=content))
            if "qr_analyzer" in capabilities:
                cases.append(CapabilityCase(**base, capability="qr_analyzer", input_type="image"))
            if "prompt_injection" in capabilities:
                cases.append(CapabilityCase(**base, capability="prompt_injection", input_type="email"))
            if meta.get("auth_headers_present") is True:
                cases.append(CapabilityCase(**base, capability="auth_header", input_type="email"))
            if "attachment" in capabilities:
                cases.append(CapabilityCase(**base, capability="attachment", input_type="email"))
    ids = [(case.capability, case.sample_id) for case in cases]
    if len(set(ids)) != len(ids):
        raise ValueError("DUPLICATE_CAPABILITY_SAMPLE_ID")
    return cases


def verify_catalog(cases: list[CapabilityCase], root: Path) -> dict:
    expected = {"vietnamese_url": 53116, "bec": 279, "qr_analyzer": 1000,
                "prompt_injection": 3149, "auth_header": 180}
    result = {}
    for capability in (*expected, "attachment"):
        selected = [case for case in cases if case.capability == capability]
        labels = dict(Counter(case.expected_label for case in selected))
        languages = dict(Counter(case.language for case in selected if case.language))
        broken = sum(not resolve_input(root, case.file).is_file() for case in selected)
        blockers = []
        if capability in expected and len(selected) != expected[capability]:
            blockers.append("CANONICAL_COUNT_MISMATCH")
        expected_labels = {"vietnamese_url": {"PHISHING": 36706, "SAFE": 16410},
                           "bec": {"positive": 276, "neutral": 3},
                           "qr_analyzer": {"SAFE": 500, "PHISHING": 500},
                           "prompt_injection": {"PROMPT_INJECTION": 3149}}
        if capability in expected_labels and labels != expected_labels[capability]:
            blockers.append("CANONICAL_LABEL_COUNTS_MISMATCH")
        if capability == "vietnamese_url" and languages != {"vi": 46827, "mixed": 6289}:
            blockers.append("CANONICAL_LANGUAGE_COUNTS_MISMATCH")
        if capability == "bec" and any(any(case.metadata.get(key) is not value for key, value in
            (("synthetic", True), ("human_validated", True), ("real_world", False))) for case in selected):
            blockers.append("BEC_PROVENANCE_FLAGS_MISMATCH")
        if capability == "qr_analyzer":
            parents = {resolve_input(root, case.file).parent for case in selected}
            physical = sum(sum(p.is_file() and p.suffix.lower() in {".png", ".jpg", ".jpeg"}
                               for p in parent.iterdir()) for parent in parents if parent.is_dir())
            if physical != expected[capability]:
                blockers.append("QR_PHYSICAL_COUNT_MISMATCH")
            if broken:
                blockers.append("QR_BROKEN_PATHS")
            if any(case.metadata.get("email_with_qr") is not False for case in selected):
                blockers.append("QR_INPUT_TYPE_MISMATCH")
        result[capability] = dict(expected=expected.get(capability), actual=len(selected), labels=labels,
            languages=languages, broken_paths=broken, available=len(selected)-broken,
            splits=dict(Counter(case.split for case in selected)), blocked=bool(blockers), blockers=blockers)
        if capability == "qr_analyzer":
            result[capability]["physical_images"] = physical
    return result
