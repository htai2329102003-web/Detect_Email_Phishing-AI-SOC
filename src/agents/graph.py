from functools import partial

from langgraph.graph import END, START, StateGraph

from src.agents.nodes.attachment_node import attachment_node
from src.agents.nodes.claim_node import claim_node
from src.agents.nodes.enrichment_node import enrichment_node, rag_node
from src.agents.nodes.evidence_node import evidence_node
from src.agents.nodes.header_node import header_node
from src.agents.nodes.parse_node import parse_node
from src.agents.nodes.qr_node import qr_node
from src.agents.nodes.risk_node import risk_node
from src.agents.nodes.url_node import url_node
from src.agents.nodes.verdict_node import verdict_node
from src.agents.state import AgentState
from src.analyzers.qr_analyzer import QRDecoder
from src.config import get_settings
from src.services.enrichment import ExternalServices
from src.services.guardrails import GuardrailProvider
from src.services.ioc_store import IOCClient
from src.services.pii import PIIRedactor
from src.services.verdict import VerdictProvider


def build_graph(
    *,
    ioc_client: IOCClient | None = None,
    qr_decoder: QRDecoder | None = None,
    verdict_provider: VerdictProvider | None = None,
    pii_redactor: PIIRedactor | None = None,
    guardrails: GuardrailProvider | None = None,
    external_services: ExternalServices | None = None,
):
    """Run independent static branches, then join once before Gate 1."""
    builder = StateGraph(AgentState)

    builder.add_node("parse", partial(parse_node, redactor=pii_redactor))
    builder.add_node("header", header_node)
    builder.add_node("url", partial(url_node, ioc_client=ioc_client))
    builder.add_node("attachment", partial(attachment_node, ioc_client=ioc_client))
    builder.add_node("qr", partial(qr_node, ioc_client=ioc_client, decoder=qr_decoder))
    builder.add_node("validate_evidence", evidence_node)
    builder.add_node("score_risk", risk_node)
    builder.add_node("create_verdict", partial(verdict_node, provider=verdict_provider, guardrails=guardrails))
    builder.add_node("validate_claims", partial(claim_node, provider=verdict_provider))

    builder.add_edge(START, "parse")
    for name in ("header", "url", "attachment", "qr"):
        builder.add_edge("parse", name)
    if external_services is not None:
        builder.add_node("external_enrichment", partial(enrichment_node, services=external_services))
        builder.add_node("knowledge_context", partial(rag_node, services=external_services))
        builder.add_edge(["header", "url", "attachment", "qr"], "external_enrichment")
        builder.add_edge("external_enrichment", "validate_evidence")
        builder.add_edge("score_risk", "knowledge_context")
        builder.add_edge("knowledge_context", "create_verdict")
    else:
        builder.add_edge(["header", "url", "attachment", "qr"], "validate_evidence")
        builder.add_edge("score_risk", "create_verdict")
    builder.add_edge("validate_evidence", "score_risk")
    builder.add_edge("create_verdict", "validate_claims")
    builder.add_conditional_edges(
        "validate_claims",
        lambda state: "retry" if state["retry_requested"] else "done",
        {"retry": "create_verdict", "done": END},
    )

    return builder.compile()


agent = build_graph(
    external_services=ExternalServices.from_settings(get_settings())
    if get_settings().external_enrichment_enabled
    else None
)
