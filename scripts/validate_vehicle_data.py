#!/usr/bin/env python3
"""Validate vehicle JSON structure without checking real-world specifications."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
COMBINED_FILE = ROOT / "vehicles.json"
EXPECTED_IDS = {
    "vinfast-amio-s2",
    "vinfast-evo",
    "vinfast-evo-grand-limited",
    "vinfast-feliz-2025",
    "vinfast-feliz-ii",
    "vinfast-flazz-max",
    "vinfast-kinet",
    "vinfast-kyo",
    "vinfast-viper",
    "vinfast-zgoo",
}
REQUIRED_SECTIONS = {
    "identity",
    "sales",
    "performance",
    "battery",
    "charging",
    "utility",
    "features",
    "source",
}
NUMBER_OR_NULL_FIELDS = {
    "sales.price_vnd",
    "sales.price_with_battery_vnd",
    "performance.max_speed_kmh",
    "performance.rated_power_w",
    "performance.max_power_w",
    "performance.range_standard_km",
    "performance.range_mixed_km",
    "performance.range_max_km",
    "performance.acceleration_0_40_kmh_seconds",
    "performance.acceleration_0_50_kmh_seconds",
    "battery.capacity_each_kwh",
    "battery.total_capacity_kwh",
    "charging.charging_time_standard_hours",
    "charging.charger_power_w",
    "charging.fast_charging_time_hours",
    "utility.storage_liters",
    "utility.seat_height_mm",
    "utility.ground_clearance_mm",
    "utility.vehicle_weight_kg",
    "utility.payload_kg",
    "capability.hill_climb_percent",
    "capability.hill_climb_speed_kmh",
}
OPERATOR_FIELDS = {
    "performance.acceleration_0_40_kmh_operator",
    "performance.acceleration_0_50_kmh_operator",
}
VALID_OPERATORS = {"<", "<=", "=", ">", ">="}
BOOLEAN_OR_ENUM_FIELDS = {
    "features.smart_key",
    "features.reverse",
    "features.auto_hold",
    "features.anti_theft",
    "features.tft_display",
}
VALID_FEATURE_ENUMS = {
    "standard",
    "optional",
    "not_equipped",
    "not_available",
    "unknown",
}
MISSING = object()


def load_json_detect_duplicates(path: Path) -> tuple[Any | None, list[str], str | None]:
    duplicate_keys: list[str] = []

    def object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        counts = Counter(key for key, _ in pairs)
        duplicate_keys.extend(key for key, count in counts.items() if count > 1)
        return dict(pairs)

    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            data = json.load(handle, object_pairs_hook=object_pairs_hook)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, duplicate_keys, str(exc)
    return data, duplicate_keys, None


def get_nested(data: dict[str, Any], field_path: str) -> Any:
    current: Any = data
    for part in field_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return MISSING
        current = current[part]
    return current


def validate_types(data: dict[str, Any]) -> list[str]:
    issues: list[str] = []

    for field_path in sorted(NUMBER_OR_NULL_FIELDS):
        value = get_nested(data, field_path)
        if value is MISSING:
            continue
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, (int, float))
        ):
            issues.append(
                f"{field_path} must be a number or null, got {value!r}"
            )

    for field_path in sorted(OPERATOR_FIELDS):
        value = get_nested(data, field_path)
        if value is MISSING:
            continue
        if value not in VALID_OPERATORS:
            issues.append(
                f"{field_path} must be one of {sorted(VALID_OPERATORS)}, got {value!r}"
            )

    for field_path in sorted(BOOLEAN_OR_ENUM_FIELDS):
        value = get_nested(data, field_path)
        if value is MISSING:
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, str) and value in VALID_FEATURE_ENUMS:
            continue
        issues.append(
            f"{field_path} must be boolean or a valid feature enum, got {value!r}"
        )

    return issues


def main() -> int:
    errors: list[str] = []
    model_files = sorted(ROOT.glob("vinfast-*.json"))
    parsed_models: list[dict[str, Any]] = []
    vehicle_ids: list[str] = []
    syntax_errors = 0
    duplicate_key_count = 0
    type_error_count = 0

    if len(model_files) != len(EXPECTED_IDS):
        errors.append(
            f"expected {len(EXPECTED_IDS)} model files, found {len(model_files)}"
        )

    for path in model_files:
        data, duplicate_keys, parse_error = load_json_detect_duplicates(path)
        duplicate_key_count += len(duplicate_keys)
        if duplicate_keys:
            errors.append(
                f"{path.name}: duplicate keys: {', '.join(sorted(duplicate_keys))}"
            )
        if parse_error is not None:
            syntax_errors += 1
            errors.append(f"{path.name}: JSON parse error: {parse_error}")
            continue
        if not isinstance(data, dict):
            errors.append(f"{path.name}: root must be an object")
            continue

        parsed_models.append(data)
        missing = sorted(REQUIRED_SECTIONS - data.keys())
        if missing:
            errors.append(f"{path.name}: missing sections: {', '.join(missing)}")

        type_issues = validate_types(data)
        type_error_count += len(type_issues)
        errors.extend(f"{path.name}: {issue}" for issue in type_issues)

        identity = data.get("identity")
        if not isinstance(identity, dict):
            errors.append(f"{path.name}: identity must be an object")
            continue
        vehicle_id = identity.get("vehicle_id")
        if not isinstance(vehicle_id, str) or not vehicle_id:
            errors.append(f"{path.name}: identity.vehicle_id must be a non-empty string")
            continue
        vehicle_ids.append(vehicle_id)

    duplicate_ids = sorted(
        vehicle_id
        for vehicle_id, count in Counter(vehicle_ids).items()
        if count > 1
    )
    if duplicate_ids:
        errors.append(f"duplicate vehicle_id values: {', '.join(duplicate_ids)}")
    if set(vehicle_ids) != EXPECTED_IDS:
        missing_ids = sorted(EXPECTED_IDS - set(vehicle_ids))
        unexpected_ids = sorted(set(vehicle_ids) - EXPECTED_IDS)
        if missing_ids:
            errors.append(f"missing vehicle_id values: {', '.join(missing_ids)}")
        if unexpected_ids:
            errors.append(f"unexpected vehicle_id values: {', '.join(unexpected_ids)}")

    combined, combined_duplicates, combined_error = load_json_detect_duplicates(COMBINED_FILE)
    duplicate_key_count += len(combined_duplicates)
    if combined_duplicates:
        errors.append(
            f"{COMBINED_FILE.name}: duplicate keys: "
            + ", ".join(sorted(combined_duplicates))
        )
    if combined_error is not None:
        errors.append(f"{COMBINED_FILE.name}: JSON parse error: {combined_error}")
    elif not isinstance(combined, list):
        errors.append(f"{COMBINED_FILE.name}: root must be an array")
    else:
        if len(combined) != len(EXPECTED_IDS):
            errors.append(
                f"{COMBINED_FILE.name}: expected {len(EXPECTED_IDS)} records, "
                f"found {len(combined)}"
            )
        expected_combined = sorted(
            parsed_models,
            key=lambda item: item.get("identity", {}).get("vehicle_id", ""),
        )
        if combined != expected_combined:
            errors.append(
                f"{COMBINED_FILE.name}: records do not exactly match sorted model files"
            )

    valid_json_count = len(model_files) - syntax_errors
    unique_id_count = len(set(vehicle_ids))
    status = "PASS" if not errors else "FAIL"
    print(status)
    print(f"Models: {len(model_files)}")
    print(f"Valid JSON: {valid_json_count}/{len(EXPECTED_IDS)}")
    print(f"Unique IDs: {unique_id_count}/{len(EXPECTED_IDS)}")
    print(f"Duplicate keys: {duplicate_key_count}")
    print(f"Syntax errors: {syntax_errors}")
    print(f"Type errors: {type_error_count}")
    if errors:
        print("Errors:")
        for error in errors:
            print(f"- {error}")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
