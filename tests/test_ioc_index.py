import json
import sqlite3
from pathlib import Path

import pytest

from src.agents.graph import build_graph
from src.analyzers.url_analyzer import analyze_urls
from src.config import get_settings
from src.services.ioc_index import SQLiteIOCClient, build_index
from src.services.ioc_store import InMemoryIOCStore, lookup_ioc


def dataset_row(kind, value, role="MALICIOUS", source="test-feed"):
    return {
        "ioc_id": source, "type": kind, "canonical_value": value, "raw_value": value,
        "role": role, "sources": [{"name": source, "url": "local-fixture"}],
        "threat_type": "phishing" if role == "MALICIOUS" else "benign",
        "derived": kind == "domain", "derived_from": None,
        "metadata": {"fixture": True}, "first_seen": None, "last_seen": None,
    }


def test_build_reuse_normalization_and_full_provenance(tmp_path):
    source, index = tmp_path / "source.jsonl", tmp_path / "runtime" / "ioc.sqlite3"
    rows = [
        dataset_row("url", "HTTPS://BAD.test:443/%7eAccount#fragment", source="one"),
        dataset_row("url", "https://bad.test/~Account", "BENIGN_REFERENCE", source="two"),
        dataset_row("domain", "REFERENCE.test.", "BENIGN_REFERENCE"),
        dataset_row("domain", "_invalid.test"),
    ]
    source.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    built = build_index(source, index)
    stamp = index.stat().st_mtime_ns
    assert built["record_count"] == 4 and built["unsearchable_records"] == 1
    assert built["normalization_collisions"] == 1
    assert build_index(source, index)["reused"] and index.stat().st_mtime_ns == stamp
    client = SQLiteIOCClient(source, index)
    hit = lookup_ioc(client, "url", "https://BAD.test:443/~Account#anything").data
    assert hit.role == "MALICIOUS" and hit.metadata == {"fixture": True}
    assert hit.sources == tuple(row["sources"][0] for row in rows[:2])
    assert hit.matched_records == tuple(rows[:2])
    assert hit.source_canonical_value == rows[0]["canonical_value"]
    assert lookup_ioc(client, "domain", "REFERENCE.TEST.").data.role == "BENIGN_REFERENCE"
    assert lookup_ioc(client, "url", "https://bad.test/~account").data is None
    assert lookup_ioc(client, "domain", "sub.reference.test").data is None
    assert lookup_ioc(client, "domain", "_invalid.test").status == "ERROR"
    with pytest.raises(ValueError, match="outside"):
        build_index(source, tmp_path / "ioc.sqlite3")


@pytest.mark.asyncio
async def test_roles_flow_through_gates_without_benign_allowlisting(tmp_path, monkeypatch):
    source, index = tmp_path / "source.jsonl", tmp_path / "runtime" / "ioc.sqlite3"
    row = dataset_row("domain", "other.test", "BENIGN_REFERENCE")
    source.write_text(json.dumps(row) + "\n", encoding="utf-8")
    build_index(source, index)
    monkeypatch.setattr(get_settings(), "header_trusted_authserv_ids", "mx.recipient.test")
    raw = (Path(__file__).parent / "fixtures/emails/href_mismatch.eml").read_bytes()
    benign = await build_graph(ioc_client=SQLiteIOCClient(source, index)).ainvoke({"raw_email": raw})
    baseline = await build_graph(ioc_client=InMemoryIOCStore()).ainvoke({"raw_email": raw})
    assert benign["risk_score"] == baseline["risk_score"]
    assert benign["risk_result"].label_candidate == baseline["risk_result"].label_candidate
    assert benign["risk_result"].coverage == baseline["risk_result"].coverage
    assert benign["risk_result"].label_candidate != "SAFE" and benign["risk_score"] > 0
    assert not any(e.signal_type == "IOC_MATCH" for e in benign["validated_evidence"])
    assert any(e.value.get("matched_record", {}).get("role") == "BENIGN_REFERENCE"
               for e in benign["validated_evidence"] if isinstance(e.value, dict) and e.value.get("matched_record"))
    row["role"] = "MALICIOUS"
    source.write_text(json.dumps(row) + "\n", encoding="utf-8")
    assert not build_index(source, index)["reused"]
    malicious = await build_graph(ioc_client=SQLiteIOCClient(source, index)).ainvoke({"raw_email": raw})
    assert malicious["risk_score"] > benign["risk_score"]
    assert any(e.signal_type == "IOC_DERIVED_DOMAIN" for e in malicious["validated_evidence"])
    assert not malicious["risk_result"].overrides  # Fixture is a derived domain, not a direct assertion.
    assert not malicious["evidence_validation"].issues and malicious["claims_valid"]


def test_unavailable_corrupt_stale_and_query_failure_are_unknown(tmp_path):
    source, index = tmp_path / "source.jsonl", tmp_path / "runtime" / "ioc.sqlite3"
    row = dataset_row("domain", "bad.test")

    def unknown(client):
        evidence = analyze_urls({"urls": ["https://bad.test/"]}, ioc_client=client)
        checks = [item for item in evidence if item.tool == "exact_match_ioc"]
        assert checks and all(item.result == "UNKNOWN" and item.tool_status == "ERROR" for item in checks)
        assert not any(item.signal_type == "IOC_MATCH" for item in evidence)

    unknown(SQLiteIOCClient(source, index))  # Missing source.
    source.write_text(json.dumps(row) + "\n", encoding="utf-8")
    unknown(SQLiteIOCClient(source, index))  # Missing index.
    build_index(source, index)
    client = SQLiteIOCClient(source, index)
    assert client.lookup("domain", "bad.test").data is not None
    source.write_text(json.dumps({**row, "metadata": {"changed": True}}) + "\n", encoding="utf-8")
    assert client.lookup("domain", "bad.test").error_code == "IOC_INDEX_STALE"
    unknown(client)
    build_index(source, index)
    index.write_bytes(b"corrupt sqlite")
    unknown(SQLiteIOCClient(source, index))
    build_index(source, index)
    client = SQLiteIOCClient(source, index)
    assert client.lookup("domain", "bad.test").status == "OK"
    with sqlite3.connect(index) as connection:
        connection.execute("DROP TABLE records")
    unknown(client)
