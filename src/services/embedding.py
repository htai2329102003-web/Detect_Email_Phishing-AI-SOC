"""Bounded OpenAI-compatible embedding interface, separate from LLM generation."""

import math
from typing import Protocol
from urllib.parse import urlsplit

import httpx

from src.services.external import ProviderHTTPError


class EmbeddingProvider(Protocol):
    base_url: str
    model: str
    dimension: int | None
    batch_size: int

    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...
    def embed_query(self, text: str) -> list[float]: ...


def validate_vectors(vectors, count: int, dimension: int | None = None) -> list[list[float]]:
    if not isinstance(vectors, list) or len(vectors) != count or not vectors:
        raise ValueError("Embedding count mismatch")
    actual = len(vectors[0])
    if not 1 <= actual <= 65536 or (dimension is not None and actual != dimension):
        raise ValueError("Embedding dimension mismatch")
    for vector in vectors:
        if not isinstance(vector, list) or len(vector) != actual or any(
            isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x) for x in vector
        ) or not any(vector):
            raise ValueError("Invalid embedding vector")
    return vectors


class CompatibleEmbeddingClient:
    def __init__(self, *, base_url: str, api_key: str, model: str, dimension: int | None = None,
                 batch_size: int = 32, timeout: float = 30, transport=None):
        self.base_url, self._api_key, self.model = base_url.rstrip("/"), api_key, model
        self.dimension, self.batch_size, self.timeout, self._transport = dimension, batch_size, timeout, transport
        self.batch_count, self.total_tokens = 0, 0

    @classmethod
    def from_settings(cls, settings):
        return cls(base_url=settings.embedding_base_url,
                   api_key=settings.embedding_api_key.get_secret_value() or settings.openai_api_key,
                   model=settings.embedding_model, dimension=settings.embedding_dimension,
                   batch_size=settings.embedding_batch_size, timeout=settings.embedding_timeout_seconds)

    def ensure_configured(self):
        url = urlsplit(self.base_url)
        if not self.base_url or not self.model or not self._api_key:
            raise ValueError("REAL INGESTION BLOCKED BY MISSING PROVIDER CONFIG")
        if url.scheme not in {"https", "http"} or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("Invalid embedding provider URL")
        if url.scheme == "http" and url.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Remote embedding provider requires HTTPS")
        if not 1 <= self.batch_size <= 128 or not 0 < self.timeout <= 120:
            raise ValueError("Invalid embedding request limits")

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        self.ensure_configured()
        if not texts or len(texts) > 2000 or any(not text.strip() or len(text) > 16000 for text in texts):
            raise ValueError("Invalid embedding input")
        output = []
        with httpx.Client(timeout=self.timeout, trust_env=False, follow_redirects=False,
                          transport=self._transport) as client:
            for offset in range(0, len(texts), self.batch_size):
                batch = texts[offset:offset + self.batch_size]
                # Configured dimension is an expected output size; do not assume provider
                # supports a dimensions request parameter or silently truncate vectors.
                with client.stream("POST", self.base_url + "/embeddings",
                                   headers={"Authorization": "Bearer " + self._api_key},
                                   json={"model": self.model, "input": batch, "encoding_format": "float"}) as response:
                    if response.status_code != 200:
                        raise ProviderHTTPError(response.status_code)
                    content = bytearray()
                    for block in response.iter_bytes():
                        content.extend(block)
                        if len(content) > 32 * 1024 * 1024:
                            raise ValueError("Embedding response limit")
                    import json

                    body = json.loads(content)
                if body.get("model") and body["model"] != self.model:
                    raise ValueError("Embedding response model mismatch")
                rows = sorted(body["data"], key=lambda item: item["index"])
                if [row["index"] for row in rows] != list(range(len(batch))):
                    raise ValueError("Embedding index mismatch")
                vectors = validate_vectors([row["embedding"] for row in rows], len(batch), self.dimension)
                self.dimension = len(vectors[0])
                output.extend(vectors)
                self.batch_count += 1
                self.total_tokens += body.get("usage", {}).get("total_tokens", 0)
        return output

    def embed_query(self, text: str) -> list[float]:
        return self.embed_documents([text])[0]
