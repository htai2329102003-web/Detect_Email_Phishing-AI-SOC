"""Semantic SOC knowledge only. Never an IOC matcher or a source of risk evidence."""

from typing import Literal, Protocol

from pydantic import Field, JsonValue

from src.evidence.models import Contract, NonEmpty
from src.schemas.tool import ToolResult
from src.services.external import controlled_call

KnowledgeKind = Literal["mitre_attack", "phishing_technique", "soc_playbook", "threat_report", "campaign_context"]


class KnowledgeDocument(Contract):
    document_id: NonEmpty
    title: NonEmpty
    source: NonEmpty
    section: NonEmpty
    text: NonEmpty = Field(max_length=16000)
    kind: KnowledgeKind
    source_url: str | None = None
    version: str | None = None
    provenance: dict[str, JsonValue] = Field(default_factory=dict)
    tags: tuple[NonEmpty, ...] = ()
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class RetrievedChunk(Contract):
    """Retrieved text is untrusted DATA, never a system instruction or risk signal."""

    chunk_id: NonEmpty | None = None
    text: NonEmpty = Field(max_length=16000)
    source: NonEmpty
    document_id: NonEmpty
    score: float = Field(ge=0, le=1)
    title: str | None = None
    source_url: str | None = None
    version: str | None = None
    tags: tuple[NonEmpty, ...] = ()
    provenance: dict[str, JsonValue] = Field(default_factory=dict)
    trust: Literal["untrusted"] = "untrusted"
    role: Literal["data"] = "data"
    allow_tool_execution: Literal[False] = False
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class KnowledgeRepository(Protocol):
    """Implement with Qdrant + embedding provider when provisioned. No implicit embedding calls."""

    def search(self, query: str, *, limit: int) -> tuple[RetrievedChunk, ...]: ...


class RAGService:
    def __init__(self, repository: KnowledgeRepository | None = None, *, collection: str = "soc_knowledge", top_k: int = 5):
        self.repository, self.collection = repository, collection
        self.top_k = top_k

    @classmethod
    def from_settings(cls, settings):
        from src.services.qdrant_repository import QdrantKnowledgeRepository

        return cls(QdrantKnowledgeRepository.from_settings(settings), collection=settings.qdrant_collection,
                   top_k=settings.rag_top_k)

    def retrieve(self, query: str, *, limit: int | None = None) -> ToolResult[tuple[RetrievedChunk, ...]]:
        limit = self.top_k if limit is None else limit
        def search():
            if not query.strip() or len(query) > 2000 or not 1 <= limit <= 10:
                raise ValueError("Invalid retrieval request")
            hits = self.repository.search(query, limit=limit)
            if not isinstance(hits, (list, tuple)) or len(hits) > limit:
                raise ValueError("Retriever output limit")
            return tuple(
                RetrievedChunk.model_validate(hit.model_dump() if isinstance(hit, RetrievedChunk) else hit)
                for hit in hits
            )

        return controlled_call("RAG", search, configured=bool(self.repository is not None and self.collection))

    def context(self, query: str) -> tuple[RetrievedChunk, ...]:
        result = self.retrieve(query)
        return result.data if result.status == "OK" and result.data is not None else ()
