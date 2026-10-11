from src.agents.nodes.analysis_boundary import run_analyzer
from src.agents.state import AgentState
from src.analyzers.common import finding
from src.analyzers.header_analyzer import HEADER_SIGNALS, analyze_headers
from src.config import get_settings


def header_node(state: AgentState) -> dict:
    """Collect authentication and routing evidence from email headers."""
    settings = get_settings()
    parsed = state.get("parsed_email", {})
    result = run_analyzer(
        "header",
        "HEADER_ANALYSIS",
        "identity",
        lambda: analyze_headers(parsed, trusted_authserv_ids=tuple(settings.header_trusted_authserv_ids.split(","))),
        required=HEADER_SIGNALS,
    )
    if parsed.get("partial_parse"):
        result["evidence"].append(finding(
            "header", "HEADER_ANALYSIS", "identity", "parser:partial",
            {"warnings": parsed["parser_warnings"], "unavailable_headers": parsed["unavailable_headers"]},
            "UNKNOWN",
        ))
        result["applicable_signals"].append("HEADER_ANALYSIS")
        if result["analyzer_runs"][0]["status"] != "ERROR":
            result["analyzer_runs"][0]["status"] = "PARTIAL"
    return result
