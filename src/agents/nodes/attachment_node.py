from src.agents.nodes.analysis_boundary import run_analyzer
from src.agents.state import AgentState
from src.analyzers.attachment_analyzer import analyze_attachments
from src.services.ioc_store import IOCClient


def attachment_node(state: AgentState, *, ioc_client: IOCClient | None = None) -> dict:
    """Collect static evidence for message attachments."""
    return run_analyzer(
        "attachment",
        "ATTACHMENT_ANALYSIS",
        "attachment",
        lambda: analyze_attachments(state.get("parsed_email", {}), ioc_client=ioc_client),
    )
