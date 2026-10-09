from src.agents.nodes.analysis_boundary import run_analyzer
from src.agents.state import AgentState
from src.analyzers.qr_analyzer import QRDecoder, analyze_qr_codes
from src.config import get_settings
from src.services.ioc_store import IOCClient


def qr_node(state: AgentState, *, ioc_client: IOCClient | None = None, decoder: QRDecoder | None = None) -> dict:
    """Collect evidence for QR codes found in message content or attachments."""
    return run_analyzer(
        "qr",
        "QR_ANALYSIS",
        "qr",
        lambda: analyze_qr_codes(
            state.get("parsed_email", {}),
            ioc_client=ioc_client,
            decoder=decoder,
            protected_domains=tuple(
                item.strip() for item in get_settings().url_protected_domains.split(",") if item.strip()
            ),
        ),
    )
