"""Explicit frozen-chunk ingestion/verification. Never edits data or deletes collections."""

import argparse
import json

from src.config import get_settings
from src.services.embedding import CompatibleEmbeddingClient
from src.services.qdrant_repository import QdrantKnowledgeRepository
from src.services.rag_dataset import RAGDataset


def main():
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Ingest/verify frozen RAG chunks in configured Qdrant collection")
    parser.add_argument("command", choices=("ingest", "build", "verify"))
    parser.add_argument("--documents", default=settings.rag_documents_path)
    parser.add_argument("--chunks", default=settings.rag_chunks_path)
    args = parser.parse_args()
    try:
        dataset = RAGDataset(args.documents, args.chunks)
        dataset.verify_canonical()
        embedding = CompatibleEmbeddingClient.from_settings(settings)
        embedding.ensure_configured()
        repository = QdrantKnowledgeRepository.from_settings(settings)
        repository._dataset = dataset
        repository.embedding = embedding
        result = repository.verify() if args.command == "verify" else repository.ingest()
        print(json.dumps({"status": "OK", **result, "embedding_batches": embedding.batch_count,
                          "embedding_total_tokens": embedding.total_tokens}, indent=2))
        return 0
    except Exception as exc:
        # Never print transport response bodies, request headers or credentials.
        message = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print(json.dumps({"status": "ERROR", "error": message}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
