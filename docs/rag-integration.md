# Frozen RAG production integration

The retrieval unit is each of the 1,161 chunks in v1.1.1. The 788 documents
provide metadata; they are not embedded separately. The CLI checks both canonical
hashes and counts before any provider calls or Qdrant writes. Source files remain
read-only. MITRE documents map to `mitre_attack`, NIST to `soc_playbook`; complete
original document/chunk metadata is retained alongside typed citation fields.

Configure `.env` explicitly, without committing secrets:

```dotenv
EMBEDDING_BASE_URL=<OpenAI-compatible embeddings API base, including /v1 when required>
EMBEDDING_MODEL=<provider embedding model>
EMBEDDING_API_KEY=<private credential>
QDRANT_URL=http://localhost:6333
QDRANT_COLLECTION=soc_knowledge
RAG_ENABLED=true
```

When embedding-specific credentials are absent, the existing `OPENAI_API_KEY`
is reused; model and base URL still must be configured explicitly. Never use the
generation `MODEL_NAME` as an embedding model. `EMBEDDING_DIMENSION` is an optional
expected output size; omit it to measure actual output. It is not sent as a
provider-specific request parameter. A sample chunk probes size and is reused in
the first batch. A completed second ingest embeds only this one probe and reuses
the existing verified vectors; it does not duplicate or re-embed the full corpus.
Batch size defaults to 32 and timeout to 30 seconds. Calls are bounded, have no
automatic retries and never log response bodies or credentials. Remote provider
origins require HTTPS; loopback HTTP is available for explicitly configured local
providers. No mock embedding or lexical fallback exists in production.

Run from the project root:

```powershell
python -m scripts.ingest_rag ingest
python -m scripts.ingest_rag verify
python -m scripts.ingest_rag ingest
```

`build` is an alias for `ingest`. Optional `--documents` and `--chunks` override
relative paths; canonical v1.1.1 validation still applies. With missing provider
configuration the command exits 1 with
`REAL INGESTION BLOCKED BY MISSING PROVIDER CONFIG` and does not create vectors.

The Qdrant repository uses the existing HTTP dependency and the deployed v1.12
REST API; no new SDK is required. Cosine vectors use UUIDv5 point IDs derived from
chunk IDs. There are **1,161 searchable chunk points plus one metadata point**,
1,162 total. The metadata point carries dataset version, both hashes, provider
origin, model, dimension, chunk count, distance and format version. Every chunk
also carries the identity fingerprint. Searches filter out the metadata point.

Ingestion creates a missing collection or reuses a compatible collection. A
nonempty unowned collection, stale identity, named/multivector configuration or
wrong dimension/distance fails explicitly. Nothing deletes/recreates collections.
Use a new collection name for a different snapshot/model and explicitly configure
the application to use it after verification. An interrupted same-identity build
remains `building` and can be retried with deterministic upserts. Retrieval refuses
incomplete builds. Before publishing `complete`, ingestion verifies exact counts,
all expected IDs, payloads/provenance and vector dimensions. The manifest is stored
in Qdrant's existing persisted volume, outside frozen `data/`.

Retrieval embeds a bounded query, checks collection identity/configuration/counts,
searches by cosine similarity, and validates returned payloads against the local
frozen chunks. Scores originate in Qdrant responses. Repository-level optional
source filters accept `MITRE ATT&CK` and `NIST`. `RAG_TOP_K` defaults to 5;
`RAG_SCORE_THRESHOLD=0.5` is provisional, configurable and **not calibrated**.
An unrelated query can return an actual corpus chunk above threshold; no semantic
relevance guarantee is claimed. Below-threshold results are discarded and no
source/citation is fabricated. Future threshold tuning belongs on DEV, never TEST.

`RAG_ENABLED` independently wires retrieval into the production graph, without
enabling VirusTotal, urlscan or LLM generation. It is off by default. IOC wiring
is unchanged. Query text is fixed metadata from validated signal families, never
raw email, PII or arbitrary indicators.

Risk scoring still runs only on deterministic analyzer evidence. Retrieved facts
take a **separate Gate 1** before Verdict context and Gate 2. They use
`knowledge_context`/`RAG_CONTEXT`, cannot contribute risk, and are included in the
public/persisted evidence list so knowledge claims have resolvable references.
Gate 2 supports only existing exact fact templates and canonical citation fields;
it does not validate arbitrary LLM narratives or infer ATT&CK attribution from
similarity. `KNOWLEDGE` claims cannot be recast as IOC claims. Corpus text stays
typed untrusted DATA, and `VerdictRequest.messages()` puts it only in JSON user
content, never in privileged instructions. Score and risk label remain immutable.

Provider/collection failures produce explicit failed ToolResults, empty context
and UNKNOWN knowledge evidence. `rag_status` and trust warnings expose the outage;
assessment escalates to `NEEDS_ANALYST_REVIEW`. The deterministic risk result is
preserved, including an independently calculated SAFE label when applicable; that
label is never evidence that retrieval succeeded. HITL remains required.

The static `analysis_scope` continues to describe analyzer execution; the separate
`rag_status` reports knowledge availability. Missing RAG does not claim successful
knowledge coverage, nor change analyzer coverage, risk weights or IOC semantics.

Protocol references: [Qdrant v1.12 search](https://api.qdrant.tech/v-1-12-x/api-reference/search/points),
[count](https://api.qdrant.tech/v-1-12-x/api-reference/points/count-points),
[retrieve](https://api.qdrant.tech/v-1-12-x/api-reference/points/get-points).
