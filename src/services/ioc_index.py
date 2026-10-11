"""Explicit, atomic snapshot build and read-only exact IOC lookup; no network IO."""

import hashlib
import json
import os
import sqlite3
import tempfile
from collections import Counter
from contextlib import closing
from pathlib import Path
from threading import Lock
from time import perf_counter

from src.schemas.tool import ToolResult
from src.services.ioc_store import IOCKind, IOCRecord, normalize_ioc

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FORMAT_VERSION = "1"


def resolve_path(value: str | Path) -> Path:
    path = Path(value)
    return (path if path.is_absolute() else PROJECT_ROOT / path).resolve()


def source_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def format_signature() -> str:
    # Contract/normalization changes must invalidate previously built indexes too.
    digest = hashlib.sha256(FORMAT_VERSION.encode())
    for name in ("src/services/ioc_store.py", "src/utils/normalization.py"):
        digest.update((PROJECT_ROOT / name).read_bytes())
    return digest.hexdigest()


def _signature(path: Path) -> tuple[int, int, int, int]:
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_ino


def _connect(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)


def _metadata(connection: sqlite3.Connection) -> dict:
    row = connection.execute("SELECT payload FROM index_metadata WHERE id = 1").fetchone()
    if row is None:
        raise ValueError("Missing IOC index metadata")
    metadata = json.loads(row[0])
    if metadata["format_signature"] != format_signature():
        raise ValueError("IOC index format is stale; rebuild required")
    return metadata


def adapt_dataset_record(row: dict) -> IOCRecord:
    """Keep original canonical value and every provenance field alongside runtime value."""
    return IOCRecord(
        kind=row["type"],
        value=row["canonical_value"],
        source="; ".join(dict.fromkeys(source["name"] for source in row["sources"])),
        sources=tuple(row["sources"]),
        role=row["role"],
        threat_type=row.get("threat_type"),
        derived=row.get("derived", False),
        derived_from=row.get("derived_from"),
        ioc_id=row.get("ioc_id"),
        raw_value=row.get("raw_value"),
        source_canonical_value=row["canonical_value"],
        first_seen=row.get("first_seen"),
        last_seen=row.get("last_seen"),
        metadata=row.get("metadata", {}),
    )


def build_index(source: str | Path, index: str | Path) -> dict:
    """Build outside data, retain all source rows, atomically publish or reuse by hash."""
    started = perf_counter()
    source, index = resolve_path(source), resolve_path(index)
    protected = {PROJECT_ROOT / "data", *(parent for parent in source.parents if parent.name == "data")}
    if any(index.is_relative_to(root) for root in protected) or index.parent == source.parent:
        raise ValueError("IOC index must be outside data/source directories")
    before = _signature(source)
    checksum = source_sha256(source)
    if index.exists():
        try:
            with closing(_connect(index)) as connection:
                metadata = _metadata(connection)
                if (
                    metadata["source_sha256"] == checksum
                    and connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
                    and connection.execute("SELECT count(*) FROM records").fetchone()[0] == metadata["record_count"]
                    and _signature(source) == before
                ):
                    return {**metadata, "reused": True, "elapsed_seconds": perf_counter() - started}
        except (sqlite3.Error, ValueError, KeyError, TypeError):
            pass  # An explicit build replaces stale/corrupt artifacts; requests never rebuild.
    index.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=index.name + ".", suffix=".tmp", dir=index.parent)
    os.close(descriptor)
    temporary = Path(temporary)
    counts, rejected, changed = Counter(), Counter(), 0
    digest = hashlib.sha256()
    try:
        with closing(sqlite3.connect(temporary)) as connection:
            connection.execute("CREATE TABLE records (kind TEXT NOT NULL, canonical_value TEXT, role TEXT NOT NULL, payload TEXT NOT NULL, normalization_error TEXT)")
            connection.execute("CREATE TABLE index_metadata (id INTEGER PRIMARY KEY CHECK (id = 1), payload TEXT NOT NULL)")
            batch = []
            with source.open("rb") as stream:
                for line in stream:
                    digest.update(line)
                    row = json.loads(line)
                    kind, role = row["type"], row["role"]
                    if kind not in {"url", "domain", "ip", "hash"} or role not in {"MALICIOUS", "BENIGN_REFERENCE"}:
                        raise ValueError("Unsupported IOC kind/role in source")
                    error, canonical = None, None
                    try:
                        canonical = normalize_ioc(kind, row["canonical_value"])
                    except ValueError as exc:
                        error = str(exc)
                        rejected[error] += 1
                    if canonical is not None:
                        adapt_dataset_record(row)  # Validate full contract before publishing.
                        changed += canonical != row["canonical_value"]
                    counts["total"] += 1
                    counts[kind] += 1
                    counts[role] += 1
                    batch.append((kind, canonical, role, json.dumps(row, ensure_ascii=True), error))
                    if len(batch) == 5000:
                        connection.executemany("INSERT INTO records VALUES (?, ?, ?, ?, ?)", batch)
                        batch.clear()
            connection.executemany("INSERT INTO records VALUES (?, ?, ?, ?, ?)", batch)
            if digest.hexdigest() != checksum or before != _signature(source):
                raise ValueError("IOC source changed during build")
            connection.execute("CREATE INDEX exact_ioc ON records(kind, canonical_value)")
            searchable = counts["total"] - sum(rejected.values())
            unique = connection.execute("SELECT count(*) FROM (SELECT 1 FROM records WHERE canonical_value IS NOT NULL GROUP BY kind, canonical_value)").fetchone()[0]
            metadata = {
                "format_signature": format_signature(), "source_sha256": checksum,
                "record_count": counts["total"], "counts": dict(counts),
                "searchable_records": searchable, "unsearchable_records": sum(rejected.values()),
                "normalization_errors": dict(rejected), "normalized_values_changed": changed,
                "normalization_collisions": searchable - unique,
            }
            connection.execute("INSERT INTO index_metadata VALUES (1, ?)", (json.dumps(metadata),))
            connection.commit()
        os.replace(temporary, index)
        return {**metadata, "reused": False, "elapsed_seconds": perf_counter() - started}
    finally:
        temporary.unlink(missing_ok=True)


class SQLiteIOCClient:
    """Lazy, once-per-snapshot validation; each request only stats files + indexed SQL."""

    def __init__(self, source: str | Path, index: str | Path):
        self.source, self.index = resolve_path(source), resolve_path(index)
        self._lock = Lock()
        self._validated = None
        self._failed = None
        self._failure_code = None
        self.metadata: dict = {}

    def lookup(self, kind: IOCKind, value: str) -> ToolResult[IOCRecord]:
        started = perf_counter()
        code = "IOC_INDEX_ERROR"
        signatures = None
        try:
            canonical = normalize_ioc(kind, value)
            with self._lock:
                if not self.source.is_file():
                    code = "IOC_SOURCE_MISSING"
                    raise FileNotFoundError()
                if not self.index.is_file():
                    code = "IOC_INDEX_MISSING"
                    raise FileNotFoundError()
                signatures = (_signature(self.source), _signature(self.index))
                if self._failed == signatures:
                    code = self._failure_code
                    raise ValueError("IOC snapshot validation previously failed")
                with closing(_connect(self.index)) as connection:
                    if signatures != self._validated:
                        metadata = _metadata(connection)
                        if metadata["source_sha256"] != source_sha256(self.source):
                            code = "IOC_INDEX_STALE"
                            raise ValueError("IOC source hash mismatch")
                        if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                            raise ValueError("Corrupt IOC index")
                        if connection.execute("SELECT count(*) FROM records").fetchone()[0] != metadata["record_count"]:
                            raise ValueError("IOC index row count mismatch")
                        if signatures != (_signature(self.source), _signature(self.index)):
                            raise ValueError("IOC snapshot changed during validation")
                        self.metadata = metadata
                        self._validated = signatures
                    rows = [json.loads(row[0]) for row in connection.execute(
                        "SELECT payload FROM records WHERE kind = ? AND canonical_value = ? ORDER BY role DESC, rowid",
                        (kind, canonical),
                    )]
                    # MALICIOUS wins over a reference if normalized keys overlap. Preserve every row.
                    record = adapt_dataset_record(rows[0]) if rows else None
                    if record is not None:
                        sources = []
                        for row in rows:
                            for source in row["sources"]:
                                if source not in sources:
                                    sources.append(source)
                        record = record.model_copy(update={
                            "sources": tuple(sources),
                            "matched_records": tuple(rows),
                            "source": "; ".join(dict.fromkeys(item["name"] for item in sources)),
                        })
                    if signatures != (_signature(self.source), _signature(self.index)):
                        raise ValueError("IOC snapshot changed during lookup")
                    self._failed = None
            return ToolResult(status="OK", data=record, latency_ms=(perf_counter() - started) * 1000)
        except Exception:
            if signatures is not None:
                self._failed, self._failure_code = signatures, code
            return ToolResult(status="ERROR", error_code=code, latency_ms=(perf_counter() - started) * 1000)
