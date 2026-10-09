from src.agents.nodes.analysis_boundary import run_analyzer
from src.agents.state import AgentState
from src.analyzers.url_analyzer import analyze_urls
from src.config import get_settings
from src.services.ioc_store import IOCClient


def url_node(state: AgentState, *, ioc_client: IOCClient | None = None) -> dict:
    """Collect evidence for URLs extracted from the message."""
    return run_analyzer(
        "url",
        "URL_ANALYSIS",
        "url_deception",
        lambda: analyze_urls(
            state.get("parsed_email", {}),
            ioc_client=ioc_client,
            protected_domains=tuple(
                item.strip() for item in get_settings().url_protected_domains.split(",") if item.strip()
            ),
        ),
    )
