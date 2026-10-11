"""Composition root for optional integrations; fake implementations are injected only by tests."""

from dataclasses import dataclass, field

from src.analyzers.content_analyzer import ContentAnalyzer, StructuredContentAnalyzer
from src.services.llm import LLMClient
from src.services.rag import RAGService
from src.services.urlscan import URLReputationClient, URLScanClient
from src.services.virustotal import HashReputationClient, VirusTotalClient


@dataclass(frozen=True)
class ExternalServices:
    virustotal: HashReputationClient = field(default_factory=VirusTotalClient)
    urlscan: URLReputationClient = field(default_factory=URLScanClient)
    content: ContentAnalyzer = field(default_factory=lambda: StructuredContentAnalyzer(LLMClient()))
    rag: RAGService = field(default_factory=RAGService)
    max_urls: int = 16
    max_hashes: int = 16
    content_enabled: bool = True
    virustotal_enabled: bool = True
    urlscan_enabled: bool = True
    rag_enabled: bool = True

    def __post_init__(self):
        if not 1 <= self.max_urls <= 64 or not 1 <= self.max_hashes <= 64:
            raise ValueError("Enrichment request budgets must be between 1 and 64")

    @classmethod
    def from_settings(cls, settings):
        def configured(client):
            try:
                return client.from_settings(settings)
            except (ValueError, TypeError):
                return client()  # Invalid provider config remains unavailable, not an import-time crash.

        return cls(
            virustotal=configured(VirusTotalClient),
            urlscan=configured(URLScanClient),
            rag=RAGService.from_settings(settings),
            content=StructuredContentAnalyzer(LLMClient.from_settings(settings)),
            content_enabled=settings.content_bec_enabled,
            virustotal_enabled=settings.external_enrichment_enabled and settings.virustotal_enabled,
            urlscan_enabled=settings.external_enrichment_enabled and settings.urlscan_enabled,
            rag_enabled=settings.rag_enabled,
            max_urls=settings.enrichment_max_urls,
            max_hashes=settings.enrichment_max_hashes,
        )
