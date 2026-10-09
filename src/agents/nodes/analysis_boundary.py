from collections.abc import Callable

from src.analyzers.common import finding
from src.evidence.models import Evidence


def run_analyzer(name: str, signal: str, family: str, operation: Callable[[], list[Evidence]], *, required=()) -> dict:
    """One analyzer failure must become UNKNOWN, never stop the remaining branches."""
    try:
        evidence = operation()
        status = "OK"
        # Returned UNKNOWN tool failures still make the branch visibly incomplete.
        if any(item.result == "UNKNOWN" for item in evidence):
            status = "PARTIAL"
        errors = []
    except Exception:
        evidence = [
            finding(
                name, signal, family, f"{name}:analyzer", {"error_code": "ANALYZER_FAILED"}, "UNKNOWN", status="ERROR"
            )
        ]
        status = "ERROR"
        errors = [f"{name}:ANALYZER_FAILED"]
    return {
        "evidence": evidence,
        "applicable_signals": list(required) or [signal],
        "analyzer_runs": [{"analyzer": name, "status": status}],
        "errors": errors,
    }
