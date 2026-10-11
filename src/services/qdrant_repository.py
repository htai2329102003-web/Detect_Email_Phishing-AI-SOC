"""Qdrant REST repository and explicit ingestion; never an IOC/risk classifier."""

import hashlib
import json
import math
import re
from time import perf_counter
from urllib.parse import quote, urlsplit
from uuid import NAMESPACE_URL, uuid5

import httpx

from src.services.embedding import CompatibleEmbeddingClient, EmbeddingProvider, validate_vectors
from src.services.external import ProviderHTTPError
from src.services.rag import RetrievedChunk
from src.services.rag_dataset import KnowledgeChunk, RAGDataset


def point_id(chunk_id: str) -> str:
    return str(uuid5(NAMESPACE_URL, "phishhunter:knowledge:" + chunk_id))


class QdrantREST:
    def __init__(self, base_url: str, collection: str, *, api_key: str = "", timeout: float = 10, transport=None):
        self.base_url, self.collection, self._api_key = base_url.rstrip("/"), collection, api_key
        self.timeout, self._transport = timeout, transport
        # Reuse keep-alive connections: a Windows-to-Docker TCP handshake was taking
        # about 2.2 seconds per REST call when constructing a new client each time.
        self._client = httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False,
                                    transport=transport)

    def close(self):
        self._client.close()

    def request(self, method, suffix="", body=None, *, missing_ok=False):
        url = urlsplit(self.base_url)
        if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("QDRANT_NOT_CONFIGURED: invalid endpoint")
        if url.scheme == "http" and url.hostname not in {"localhost", "127.0.0.1", "::1", "qdrant"}:
            raise ValueError("Remote Qdrant endpoint requires HTTPS")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", self.collection):
            raise ValueError("Invalid Qdrant collection name")
        with self._client.stream(method, self.base_url + "/collections/" + quote(self.collection, safe="") + suffix,
                                 headers={"api-key": self._api_key} if self._api_key else {}, json=body) as response:
            if response.status_code == 404 and missing_ok:
                return None
            if response.status_code != 200:
                raise ProviderHTTPError(response.status_code)
            content = bytearray()
            for block in response.iter_bytes():
                content.extend(block)
                if len(content) > 16 * 1024 * 1024:
                    raise ValueError("Qdrant response limit")
            result = json.loads(content)
            if result.get("status") != "ok":
                raise ValueError("Qdrant operation failed")
            return result["result"]

    def count(self, conditions=()):
        body = {"exact": True}
        if conditions:
            body["filter"] = {"must": [{"key": key, "match": {"value": value}} for key, value in conditions]}
        count = self.request("POST", "/points/count", body)["count"]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("Invalid Qdrant point count")
        return count

    def points(self, ids, *, vectors=False):
        return self.request("POST", "/points", {"ids": ids, "with_payload": True, "with_vector": vectors})

    def upsert(self, points):
        result = self.request("PUT", "/points?wait=true", {"points": points})
        if result.get("status") != "completed":
            raise ValueError("Qdrant upsert did not complete")


class QdrantKnowledgeRepository:
    def __init__(self, embedding: EmbeddingProvider, qdrant: QdrantREST, *, dataset: RAGDataset | None = None,
                 documents_path="data/rag/documents.jsonl", chunks_path="data/rag/chunks.jsonl",
                 score_threshold: float = 0.5):
        self.embedding, self.qdrant, self._dataset = embedding, qdrant, dataset
        self.documents_path, self.chunks_path = documents_path, chunks_path
        if not 0 <= score_threshold <= 1:
            raise ValueError("Invalid RAG score threshold")
        self.score_threshold = score_threshold

    @classmethod
    def from_settings(cls, settings):
        return cls(CompatibleEmbeddingClient.from_settings(settings),
                   QdrantREST(settings.qdrant_url, settings.qdrant_collection,
                              api_key=settings.qdrant_api_key.get_secret_value(), timeout=settings.external_timeout_seconds),
                   documents_path=settings.rag_documents_path, chunks_path=settings.rag_chunks_path,
                   score_threshold=settings.rag_score_threshold)

    @property
    def dataset(self):
        if self._dataset is None:
            dataset = RAGDataset(self.documents_path, self.chunks_path)
            dataset.verify_canonical()
            self._dataset = dataset
        self._dataset.assert_unchanged()
        return self._dataset

    @property
    def manifest_id(self):
        return str(uuid5(NAMESPACE_URL, "phishhunter:manifest:" + self.qdrant.collection))

    def identity(self, dimension):
        identity = {
            "format_version": 1, "dataset_version": "1.1.1",
            "documents_sha256": self.dataset.documents_sha256,
            "chunks_sha256": self.dataset.chunks_sha256,
            "embedding_provider": self.embedding.base_url.rstrip("/"), "embedding_model": self.embedding.model,
            "embedding_dimension": dimension, "chunk_count": len(self.dataset.chunks), "distance": "Cosine",
        }
        identity["fingerprint"] = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        return identity

    def manifest(self):
        rows = self.qdrant.points([self.manifest_id])
        if not rows:
            return None
        if len(rows) != 1 or str(rows[0]["id"]) != self.manifest_id or rows[0]["payload"].get("record_type") != "manifest":
            raise ValueError("Invalid RAG collection manifest")
        return rows[0]["payload"]

    def check_collection(self, dimension, *, create=False):
        info = self.qdrant.request("GET", missing_ok=create)
        created = info is None
        if created:
            self.qdrant.request("PUT", body={"vectors": {"size": dimension, "distance": "Cosine"}})
        else:
            vector = info["config"]["params"]["vectors"]
            if vector != {"size": dimension, "distance": "Cosine"}:
                # Qdrant may supply optional defaults alongside size/distance.
                if not isinstance(vector, dict) or vector.get("size") != dimension or vector.get("distance") != "Cosine":
                    raise ValueError("RAG_COLLECTION_CONFIG_MISMATCH: use a new collection; no deletion performed")
            if vector.get("datatype") not in {None, "float32"} or vector.get("multivector_config") is not None:
                raise ValueError("RAG_COLLECTION_CONFIG_MISMATCH: unsupported vector configuration")
        return created

    def verify(self, *, dimension=None, full=True, require_complete=True):
        if dimension is None:
            dimension = self.embedding.dimension
            if dimension is None:
                dimension = len(validate_vectors([self.embedding.embed_query("SOC knowledge dimension probe")], 1)[0])
        self.check_collection(dimension)
        identity = self.identity(dimension)
        manifest = self.manifest()
        if (manifest is None or manifest.get("identity") != identity
                or manifest.get("state") not in ({"complete"} if require_complete else {"building", "complete"})):
            raise ValueError("RAG_COLLECTION_STALE_OR_INCOMPLETE: ingest into a compatible collection")
        count = self.qdrant.count((("record_type", "chunk"), ("identity", identity["fingerprint"])))
        total = self.qdrant.count()
        if count != len(self.dataset.chunks) or total != count + 1:
            raise ValueError("RAG_COLLECTION_COUNT_MISMATCH")
        if full:
            chunks = list(self.dataset.chunks.values())
            for offset in range(0, len(chunks), 128):
                batch = chunks[offset:offset + 128]
                points = self.qdrant.points([point_id(chunk.chunk_id) for chunk in batch], vectors=True)
                by_id = {str(row["id"]): row for row in points}
                if len(by_id) != len(batch):
                    raise ValueError("RAG_COLLECTION_IDS_MISMATCH")
                for chunk in batch:
                    row = by_id[point_id(chunk.chunk_id)]
                    self.validate_payload(row, identity)
                    validate_vectors([row["vector"]], 1, dimension)
        self.dataset.assert_unchanged()
        return {"identity": identity, "chunk_points": count, "metadata_points": 1, "total_points": total}

    def validate_payload(self, row, identity):
        payload = row["payload"]
        chunk = KnowledgeChunk.model_validate(payload["chunk"])
        expected = self.dataset.chunks.get(chunk.chunk_id)
        if (payload.get("record_type") != "chunk" or payload.get("identity") != identity["fingerprint"]
                or chunk != expected or str(row["id"]) != point_id(chunk.chunk_id)):
            raise ValueError("RAG_CHUNK_PROVENANCE_MISMATCH")
        return chunk

    def ingest(self):
        started = perf_counter()
        chunks = list(self.dataset.chunks.values())
        if not chunks:
            raise ValueError("Empty RAG dataset")
        # One actual chunk also probes dimension. It is reused in the first upsert batch.
        embedding_time, qdrant_time = 0.0, 0.0
        dimension = self.embedding.dimension
        began = perf_counter()
        first_vector = validate_vectors(self.embedding.embed_documents([chunks[0].text]), 1, dimension)[0]
        dimension = len(first_vector)
        embedding_time += perf_counter() - began
        created = self.check_collection(dimension, create=True)
        identity = self.identity(dimension)
        manifest = self.manifest()
        if manifest is not None and manifest.get("identity") != identity:
            raise ValueError("RAG_COLLECTION_STALE: choose a new collection; existing points untouched")
        if manifest is None and self.qdrant.count():
            raise ValueError("RAG_COLLECTION_UNOWNED: existing points untouched")
        if manifest is not None and manifest.get("state") == "complete":
            verified = self.verify(dimension=dimension)
            return {**verified, "created": created, "reused": True, "chunks_read": len(chunks),
                    "chunks_embedded": int(first_vector is not None), "chunks_upserted": 0,
                    "embedding_seconds": embedding_time, "qdrant_seconds": 0,
                    "total_seconds": perf_counter() - started}
        manifest_point = {"id": self.manifest_id, "vector": first_vector,
                          "payload": {"record_type": "manifest", "identity": identity, "state": "building"}}
        began = perf_counter()
        self.qdrant.upsert([manifest_point])
        qdrant_time += perf_counter() - began
        embedded = 1
        for offset in range(0, len(chunks), self.embedding.batch_size):
            batch = chunks[offset:offset + self.embedding.batch_size]
            texts = [chunk.text for chunk in (batch[1:] if offset == 0 else batch)]
            began = perf_counter()
            vectors = validate_vectors(self.embedding.embed_documents(texts), len(texts), dimension) if texts else []
            embedded += len(texts)
            if offset == 0:
                vectors.insert(0, first_vector)
            embedding_time += perf_counter() - began
            self.dataset.assert_unchanged()
            points = [{"id": point_id(chunk.chunk_id), "vector": vector,
                       "payload": {"record_type": "chunk", "identity": identity["fingerprint"],
                                   "chunk": chunk.model_dump(mode="json")}}
                      for chunk, vector in zip(batch, vectors, strict=True)]
            began = perf_counter()
            self.qdrant.upsert(points)
            qdrant_time += perf_counter() - began
        if self.qdrant.count((("record_type", "chunk"), ("identity", identity["fingerprint"]))) != len(chunks):
            raise ValueError("RAG ingest chunk count mismatch; manifest remains incomplete")
        if self.qdrant.count() != len(chunks) + 1:
            raise ValueError("RAG ingest unexpected points; manifest remains incomplete")
        verified = self.verify(dimension=dimension, require_complete=False)
        manifest_point["payload"]["state"] = "complete"
        began = perf_counter()
        self.qdrant.upsert([manifest_point])
        qdrant_time += perf_counter() - began
        return {**verified, "created": created, "reused": False, "chunks_read": len(chunks),
                "chunks_embedded": embedded, "chunks_upserted": len(chunks),
                "embedding_seconds": embedding_time, "qdrant_seconds": qdrant_time,
                "total_seconds": perf_counter() - started}

    def search(self, query: str, *, limit: int, source: str | None = None) -> tuple[RetrievedChunk, ...]:
        if not query.strip() or len(query) > 2000 or not 1 <= limit <= 10:
            raise ValueError("Invalid RAG query")
        if source is not None and source not in {"MITRE ATT&CK", "NIST"}:
            raise ValueError("Unsupported RAG source filter")
        vector = validate_vectors([self.embedding.embed_query(query)], 1, self.embedding.dimension)[0]
        verified = self.verify(dimension=len(vector), full=False)
        identity = verified["identity"]
        conditions = [("record_type", "chunk"), ("identity", identity["fingerprint"])]
        if source:
            conditions.append(("chunk.source", source))
        rows = self.qdrant.request("POST", "/points/search", {
            "vector": vector, "limit": limit, "with_payload": True,
            "score_threshold": self.score_threshold,
            "filter": {"must": [{"key": key, "match": {"value": value}} for key, value in conditions]},
        })
        if not isinstance(rows, list) or len(rows) > limit:
            raise ValueError("Qdrant search result limit")
        hits = []
        for row in rows:
            score = row["score"]
            if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not -1.000001 <= score <= 1.000001:
                raise ValueError("Invalid cosine similarity")
            if score < self.score_threshold:
                continue
            chunk = self.validate_payload(row, identity)
            if source is not None and chunk.source != source:
                raise ValueError("Qdrant source filter mismatch")
            hits.append(RetrievedChunk(
                **chunk.model_dump(exclude={"section", "chunk_index"}), score=min(1.0, max(0.0, score)),
            ))
        self.dataset.assert_unchanged()
        return tuple(hits)
