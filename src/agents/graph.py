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
from src.services.ioc_index import SQLiteIOCClient
from src.services.ioc_store import IOCClient
from src.services.llm import LLMClient
from src.services.observability import observed_node
from src.services.pii import PIIRedactor
from src.services.rag import RAGService
from src.services.verdict import LLMVerdictProvider, VerdictProvider


def build_graph(
    *,
    ioc_client: IOCClient | None = None,
    qr_decoder: QRDecoder | None = None,
    verdict_provider: VerdictProvider | None = None,
    pii_redactor: PIIRedactor | None = None,
    guardrails: GuardrailProvider | None = None,
    external_services: ExternalServices | None = None,
    rag_service: RAGService | None = None,
):
    """Run independent static branches, then join once before Gate 1."""
    builder = StateGraph(AgentState)

    def add_node(name, action):
        builder.add_node(name, observed_node(name, action))

    add_node("parse", partial(parse_node, redactor=pii_redactor))
    add_node("header", header_node)
    add_node("url", partial(url_node, ioc_client=ioc_client))
    add_node("attachment", partial(attachment_node, ioc_client=ioc_client))
    add_node("qr", partial(qr_node, ioc_client=ioc_client, decoder=qr_decoder))
    add_node("validate_evidence", evidence_node)
    add_node("score_risk", risk_node)
    add_node("create_verdict", partial(verdict_node, provider=verdict_provider, guardrails=guardrails))
    add_node("validate_claims", partial(claim_node, provider=verdict_provider))

    builder.add_edge(START, "parse")
    for name in ("header", "url", "attachment", "qr"):
        builder.add_edge("parse", name)
    if external_services is not None:
        add_node("external_enrichment", partial(enrichment_node, services=external_services,
                                                      ioc_client=ioc_client))
        builder.add_edge(["header", "url", "attachment", "qr"], "external_enrichment")
        builder.add_edge("external_enrichment", "validate_evidence")
    else:
        builder.add_edge(["header", "url", "attachment", "qr"], "validate_evidence")
    if rag_service is not None or (external_services is not None and external_services.rag_enabled):
        service = rag_service if rag_service is not None else external_services.rag
        add_node("knowledge_context", partial(rag_node, rag=service))
        builder.add_edge("score_risk", "knowledge_context")
        builder.add_edge("knowledge_context", "create_verdict")
    else:
        builder.add_edge("score_risk", "create_verdict")
    builder.add_edge("validate_evidence", "score_risk")
    builder.add_edge("create_verdict", "validate_claims")
    builder.add_conditional_edges(
        "validate_claims",
        lambda state: "retry" if state["retry_requested"] else "done",
        {"retry": "create_verdict", "done": END},
    )

    return builder.compile()


def build_production_graph(settings=None):
    settings = settings or get_settings()
    return build_graph(
        ioc_client=SQLiteIOCClient(settings.ioc_data_path, settings.ioc_index_path),
        rag_service=RAGService.from_settings(settings) if settings.rag_enabled else None,
        external_services=ExternalServices.from_settings(settings)
        if settings.external_enrichment_enabled or settings.content_bec_enabled else None,
        verdict_provider=LLMVerdictProvider(LLMClient.from_settings(settings)) if settings.verdict_llm_enabled else None,
    )


agent = build_production_graph()
