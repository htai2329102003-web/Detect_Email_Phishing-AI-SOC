"""Tiny provider fixtures; imported only by tests/explicit smoke factory."""

import json
from uuid import NAMESPACE_URL, uuid5

import httpx

from src.analyzers.content_analyzer import StructuredContentAnalyzer
from src.services.enrichment import ExternalServices
from src.services.ioc_store import InMemoryIOCStore
from src.services.llm import LLMClient
from src.services.rag import RAGService, RetrievedChunk
from src.services.urlscan import URLScanClient
from src.services.virustotal import VirusTotalClient


class FakeTransport:
    def __init__(self, *, failure=None, malicious=False, empty=False):
        self.failure, self.malicious, self.empty = failure, malicious, empty
        self.calls, self.urls = [], {}

    def get(self, path, *, headers, params, timeout):
        self.calls.append((path, params))
        if self.failure == "timeout":
            raise httpx.ReadTimeout("synthetic timeout")
        if self.failure == "network":
            raise httpx.ConnectError("synthetic network failure")
        if self.failure == "malformed":
            return httpx.Response(200, content=b"{not-json")
        if isinstance(self.failure, int):
            return httpx.Response(self.failure, json={"error": "synthetic upstream failure"})
        if path.startswith("/files/"):
            digest = path.rsplit("/", 1)[-1]
            body = {
                "data": {
                    "id": digest,
                    "type": "file",
                    "attributes": {
                        "sha256": digest,
                        "last_analysis_stats": {
                            "malicious": 3 if self.malicious else 0,
                            "suspicious": 0,
                            "harmless": 1,
                            "undetected": 9,
                        },
                        "last_analysis_date": 1700000000,
                    },
                }
            }
        elif path == "/search/":
            url = json.loads(params["q"].removeprefix("task.url:"))
            scan_id = str(uuid5(NAMESPACE_URL, url))
            self.urls[scan_id] = url
            body = {"results": [] if self.empty else [{"_id": scan_id, "task": {"url": url}}]}
        else:
            url = self.urls[path.split("/")[2]]
            body = {
                "task": {"url": url},
                "page": {"url": url},
                "lists": {"domains": [], "ips": []},
                "verdicts": {"overall": {"malicious": self.malicious}},
                "data": {"requests": []},
            }
        return httpx.Response(200, json=body)


class FakeStructuredModel:
    def __init__(self, *, positive=False, failure=None):
        self.positive, self.failure, self.messages = positive, failure, []

    def generate(self, messages, schema, *, timeout):
        self.messages.append(messages)
        if self.failure == "timeout":
            raise TimeoutError("synthetic model timeout")
        if self.failure:
            raise RuntimeError("synthetic model error")
        return {"signals": [{"kind": "payment_request", "confidence": 0.9}] if self.positive else []}


class FakeKnowledgeRepository:
    def __init__(self, *, empty=False, failure=False):
        self.empty, self.failure, self.queries = empty, failure, []

    def search(self, query, *, limit):
        self.queries.append(query)
        if self.failure:
            raise ConnectionError("synthetic Qdrant outage")
        return (
            ()
            if self.empty
            else (
                RetrievedChunk(
                    text="Verify payment changes out of band.",
                    source="synthetic SOC playbook",
                    document_id="test-playbook-1",
                    score=0.99,
                ),
            )
        )


def fake_services(scenario="success"):
    if scenario == "unavailable":
        return ExternalServices(), None
    transport = FakeTransport(failure="timeout" if scenario == "timeout" else None)
    model = FakeStructuredModel(positive=scenario == "bec")
    return ExternalServices(
        virustotal=VirusTotalClient(api_key="test-only-key", transport=transport),
        urlscan=URLScanClient(api_key="test-only-key", transport=transport, strict_privacy=False),
        content=StructuredContentAnalyzer(LLMClient(model)),
        rag=RAGService(FakeKnowledgeRepository()),
    ), InMemoryIOCStore()
