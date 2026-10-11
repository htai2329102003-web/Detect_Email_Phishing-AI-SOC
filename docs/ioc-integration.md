# Local IOC production snapshot

Build (or reuse an identical source snapshot) before starting the backend:

```powershell
python -m scripts.build_ioc_index
```

`IOC_DATA_PATH` defaults to `data/ioc/ioc_normalized.jsonl`;
`IOC_INDEX_PATH` defaults to `runtime/ioc.sqlite3`. Relative paths resolve from the
project root. The builder refuses to write into `data/` or the source directory.
The JSONL remains the source of truth. No network service, feed ingestion, or
database migration is involved. The SQLite file is only a disposable IOC index;
case/HITL persistence still uses PostgreSQL.

The production graph injects the read-only client into URL, attachment and QR
analyzers. Explicit `build_graph()` calls retain offline injectable dependencies.
The first lookup validates the source SHA-256, format, SQLite integrity and row
count. Subsequent lookups use file stat checks and an indexed exact query, without
reading the JSONL. Changed snapshots trigger validation; stale, missing, corrupt
or failed backends return tool errors and UNKNOWN evidence. Run the builder after
source changes. Requests never build indexes. An explicit build atomically replaces
an incompatible index and reuses an unchanged valid one.

In containers, run the same build command **inside the backend container** with
the frozen source available there. Host-built runtime files are excluded from
the Docker build context. Persist the configured index directory with an operator
managed volume if it must survive container recreation; otherwise rebuild it.
Missing provisioning is reported as unavailable, with no in-memory/SQLite case
database fallback and no fabricated IOC results.

Lookup keys are `(kind, normalize_ioc(kind, input))`. Source rows are normalized
with the existing production normalizer too; paths and query case remain significant.
Every original JSON row is retained in SQLite, including source canonical value,
metadata and all provenance. Colliding normalized keys retain all matching rows
in `matched_records`, combine their sources, and select MALICIOUS over a benign
reference if both occur. This never performs suffix, fuzzy or vector matching.

The v1.1.1 snapshot has 1,105,349 rows. Existing strict normalization changes
5,245 values, produces 305 duplicate normalized keys and rejects 79 source values
(38 URLs, 41 domains). These 79 rows remain stored with `normalization_error` and
NULL lookup key; build metadata reports the counts and reasons explicitly. They
cannot produce IOC hits through the current valid-input contract. No source data
or analyzer normalization policy is repaired/relaxed here. Snapshot coverage is
therefore limited to 1,105,270 searchable records; it is not complete threat coverage.
Malformed lookup input returns an error, never a clean match/miss.

Only MALICIOUS hits produce positive IOC risk evidence. Direct URL/IP/hash or
explicit domain assertions use `IOC_MATCH` and its configured strong override.
A domain derived only from a malicious URL uses `IOC_DERIVED_DOMAIN` (weight
0.20, no override): a malicious path does not establish that its whole host is
malicious. An independent direct malicious domain assertion is retained even
when lookup normalization merges it with a derived record. Exact lookup and
source provenance remain unchanged. BENIGN_REFERENCE hits are
reported with provenance in lookup evidence and do not subtract risk or assign
SAFE. An OK/PASS lookup means the exact query completed in this configured
snapshot; a miss or benign reference does not establish that an email is safe.
Both validation gates, the risk engine, verdict and human review policy remain
in the existing flow. Nothing deletes, blocks or quarantines email automatically.
