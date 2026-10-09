from datetime import UTC, datetime
from typing import Any

from src.evidence.models import Evidence, EvidenceResult, ToolStatus
from src.services.ioc_store import IOCClient, IOCKind, lookup_ioc


def finding(
    analyzer: str,
    signal: str,
    family: str,
    indicator: str,
    value: Any,
    result: EvidenceResult = "FAIL",
    *,
    status: ToolStatus = "OK",
    confidence: float = 1.0,
    tool: str = "static_rules",
) -> Evidence:
    return Evidence(
        analyzer=analyzer,
        tool=tool,
        signal_type=signal,
        family=family,
        indicator=indicator,
        value=value,
        result=result,
        tool_status=status,
        severity="medium" if result == "FAIL" else "info",
        confidence=confidence,
        provenance={"source": "local", "reference": f"{analyzer}:{tool}:v1"},
        collected_at=datetime.now(UTC),
    )


def ioc_evidence(
    analyzer: str, indicator: str, queries: list[tuple[IOCKind, str]], client: IOCClient, check_signal: str
) -> list[Evidence]:
    output = []
    for kind, value in queries:
        result = lookup_ioc(client, kind, value)
        output.append(
            finding(
                analyzer,
                check_signal,
                "threat_intel",
                f"{indicator}:{kind}",
                {
                    "kind": kind,
                    "indicator": value,
                    "error_code": result.error_code,
                    "scope": "configured_snapshot_only",
                },
                "UNKNOWN" if result.status != "OK" else "PASS",
                status=result.status,
                tool="exact_match_ioc",
            )
        )
        if result.status == "OK" and result.data is not None:
            output.append(
                finding(
                    analyzer,
                    "IOC_MATCH",
                    "threat_intel",
                    f"{indicator}:{kind}",
                    result.data.model_dump(mode="json"),
                    tool="exact_match_ioc",
                    confidence=result.data.confidence,
                )
            )
    return output
