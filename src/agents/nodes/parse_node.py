from src.agents.state import AgentState
from src.parsers.email_parser import parse_email
from src.services.pii import PIIRedactor, RedactionResult, RegexPIIRedactor


def parse_node(state: AgentState, *, redactor: PIIRedactor | None = None) -> dict:
    """Create a separate redacted copy; raw parser data remains the analyzer input."""
    parsed = parse_email(state.get("raw_email", b""))
    try:
        result = (redactor or RegexPIIRedactor()).redact(parsed.raw_for_analyzers)
        result = RedactionResult.model_validate(result.model_dump())
    except Exception:
        return {
            "parsed_email": parsed.raw_for_analyzers,
            "redacted_for_llm": None,
            "privacy_errors": ("PII_REDACTION_UNAVAILABLE",),
            "pii_counts": {},
            "errors": ["PII_REDACTION_UNAVAILABLE"],
        }
    return {
        "parsed_email": parsed.raw_for_analyzers,
        "redacted_for_llm": result.data,
        "redaction_policy": result.policy,
        "pii_counts": result.counts,
        "privacy_errors": (),
    }
