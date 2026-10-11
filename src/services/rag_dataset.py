"""Read-only adapter for frozen RAG v1.1.1 documents/chunks."""

import hashlib
import json
from pathlib import Path

from pydantic import Field, JsonValue

from src.evidence.models import Contract, NonEmpty
from src.services.rag import KnowledgeDocument

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DOCUMENTS_SHA256 = "ac0c28575eb88e62e8e4e932952929a722423852290eb87d24c12ad0e8958565"
CHUNKS_SHA256 = "b0a03ebb285a8464bda724348b25179de15676aeb8f0768fa2a07d6b017f5133"


def dataset_path(value: str | Path) -> Path:
    path = Path(value)
    return (path if path.is_absolute() else PROJECT_ROOT / path).resolve()


def digest_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class KnowledgeChunk(Contract):
    chunk_id: NonEmpty
    document_id: NonEmpty
    title: NonEmpty
    text: NonEmpty = Field(max_length=16000)
    source: NonEmpty
    source_url: str | None = None
    version: str | None = None
    tags: tuple[NonEmpty, ...] = ()
    section: str
    chunk_index: int = Field(ge=0)
    provenance: dict[str, JsonValue]
    metadata: dict[str, JsonValue]


class RAGDataset:
    def __init__(self, documents_path: str | Path, chunks_path: str | Path):
        self.documents_path, self.chunks_path = dataset_path(documents_path), dataset_path(chunks_path)
        before = self.stat_signature()
        self.documents = {}
        documents = [json.loads(line) for line in self.documents_path.read_text(encoding="utf-8").splitlines()]
        chunks = [json.loads(line) for line in self.chunks_path.read_text(encoding="utf-8").splitlines()]
        for row in documents:
            if row["document_id"] in self.documents:
                raise ValueError("Duplicate document ID")
            if row["source"] == "MITRE ATT&CK":
                kind = "mitre_attack"
            elif row["source"] == "NIST":
                kind = "soc_playbook"
            else:
                raise ValueError("Unsupported knowledge source")
            self.documents[row["document_id"]] = KnowledgeDocument(
                document_id=row["document_id"], title=row["title"], source=row["source"],
                section=row["section"], text=row["text"], kind=kind, tags=row["tags"],
                source_url=row.get("source_url"), version=row.get("version"),
                metadata={**row.get("metadata", {}), "original_document": row},
                provenance={"source_url": row.get("source_url"), "license": row.get("license"),
                            "published_at": row.get("published_at")},
            )
        self.chunks = {}
        for row in chunks:
            if row["chunk_id"] in self.chunks:
                raise ValueError("Duplicate chunk ID")
            document = self.documents[row["document_id"]]
            for key in ("source", "title", "section", "source_url", "version", "tags"):
                expected = list(document.tags) if key == "tags" else getattr(document, key)
                if row.get(key) != expected:
                    raise ValueError("Chunk/document provenance mismatch")
            self.chunks[row["chunk_id"]] = KnowledgeChunk(
                **row, provenance=document.provenance,
                metadata={"document_metadata": document.metadata, "original_chunk": row, "kind": document.kind},
            )
        self.documents_sha256 = digest_file(self.documents_path)
        self.chunks_sha256 = digest_file(self.chunks_path)
        self._stats = self.stat_signature()
        if before != self._stats:
            raise ValueError("RAG source changed during load")

    def stat_signature(self):
        return tuple((p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ctime_ns)
                     for p in (self.documents_path, self.chunks_path))

    def assert_unchanged(self):
        if self._stats != self.stat_signature():
            raise ValueError("RAG_DATASET_STALE: reload dataset before using collection")

    def verify_canonical(self):
        if (len(self.documents), len(self.chunks), self.documents_sha256, self.chunks_sha256) != (
            788, 1161, DOCUMENTS_SHA256, CHUNKS_SHA256,
        ):
            raise ValueError("RAG canonical counts/hash mismatch")
