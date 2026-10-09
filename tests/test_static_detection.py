import base64
import io
import zipfile
from pathlib import Path

import pytest
from PIL import Image
from pydantic import ValidationError

from src.agents.graph import build_graph
from src.analyzers.attachment_analyzer import analyze_attachments
from src.analyzers.common import finding
from src.analyzers.content_analyzer import ContentResult
from src.analyzers.header_analyzer import analyze_headers
from src.analyzers.qr_analyzer import analyze_qr_codes
from src.analyzers.url_analyzer import analyze_urls
from src.config import get_settings
from src.evidence.risk_engine import score_evidence
from src.evidence.validation import validate_evidence
from src.parsers.attachment_parser import parse_attachment
from src.parsers.email_parser import parse_email
from src.schemas.tool import ToolResult
from src.services.ioc_store import InMemoryIOCStore, IOCRecord, lookup_ioc, normalize_ioc

EMAILS = Path(__file__).parent / "fixtures" / "emails"


class FakeIOCClient(InMemoryIOCStore):
    def __init__(self, records=(), *, status="OK"):
        super().__init__(records)
        self.status = status

    def lookup(self, kind, value):
        if self.status != "OK":
            return ToolResult(status=self.status, error_code="fake_failure", latency_ms=0)
        return super().lookup(kind, value)


def raw(name):
    return parse_email((EMAILS / name).read_bytes()).raw_for_analyzers


def failures(items):
    assert not validate_evidence(items).issues
    return {item.signal_type for item in items if item.result == "FAIL"}


def test_ioc_normalization_and_exact_matches_are_conservative():
    values = [
        ("domain", "EXAMPLE.test.", "example.test"),
        ("url", "HTTPS://Example.test:443/%7eAccount?q=1#fragment", "https://example.test/~Account?q=1"),
        ("ip", "2001:0db8::1", "2001:db8::1"),
        ("hash", "A" * 64, "a" * 64),
    ]
    client = FakeIOCClient(
        tuple(IOCRecord(kind=kind, value=canonical, source="test-snapshot") for kind, _, canonical in values)
    )
    for kind, value, canonical in values:
        assert normalize_ioc(kind, value) == canonical
        assert lookup_ioc(client, kind, value).data.value == canonical
    assert lookup_ioc(client, "domain", "sub.example.test").data is None
    assert lookup_ioc(client, "url", "https://example.test/~account?q=1").data is None
    assert normalize_ioc("url", "https://example.test/a%2fb") != normalize_ioc("url", "https://example.test/a/b")
    assert normalize_ioc("url", "https://example.test/café") == normalize_ioc("url", "https://example.test/caf%C3%A9")
    with pytest.raises(ValueError):
        normalize_ioc("hash", "not-a-hash")


def test_ioc_refuses_non_exact_transport_data():
    class BadClient:
        def lookup(self, kind, value):
            return ToolResult(
                status="OK", data=IOCRecord(kind="domain", value="other.test", source="bad-client"), latency_ms=0
            )

    assert lookup_ioc(BadClient(), "domain", "example.test").status == "ERROR"


def test_url_rules_clean_equivalent_and_lookalikes():
    client = FakeIOCClient()
    assert "HREF_MISMATCH" in failures(analyze_urls(raw("href_mismatch.eml"), ioc_client=client))
    lookalike = analyze_urls(raw("lookalike.eml"), ioc_client=client, protected_domains=("paypal.test",))
    assert {"URL_PUNYCODE", "URL_LOOKALIKE"} <= failures(lookalike)
    urls = [
        "https://192.0.2.10:8443/%6cogin",
        "https://a.b.c.d.e.example.test/",
        "https://bit.ly/sample",
        "https://user@example.test/",
    ]
    assert {
        "URL_IP_LITERAL",
        "URL_SUSPICIOUS_PORT",
        "URL_OBFUSCATED",
        "URL_EXCESSIVE_SUBDOMAIN",
        "URL_SHORTENER",
    } <= failures(analyze_urls({"urls": urls}, ioc_client=client))
    clean = analyze_urls(
        {
            "urls": ["https://example.test/Info"],
            "html": {
                "links": [{"href": "https://example.test/Info", "text": "HTTPS://EXAMPLE.test:443/Info#fragment"}]
            },
        },
        ioc_client=client,
    )
    assert not failures(clean) and all(item.result == "PASS" for item in clean)


@pytest.mark.parametrize("status", ["TIMEOUT", "RATE_LIMITED", "ERROR"])
def test_ioc_failure_and_default_unconfigured_never_become_safe(status):
    parsed = raw("href_mismatch.eml")
    items = analyze_urls(parsed, ioc_client=FakeIOCClient(status=status))
    assert any(item.tool_status == status and item.result == "UNKNOWN" for item in items)
    headers = analyze_headers(parsed, trusted_authserv_ids=("mx.recipient.test",))
    assert score_evidence([*headers, *items]).label_candidate == "NEEDS_ANALYST_REVIEW"
    assert any(item.result == "UNKNOWN" for item in analyze_urls(parsed))


def attachment(content, name, mime="application/octet-stream"):
    return {"attachments": [parse_attachment(name, content, content_type=mime)]}


def test_attachment_static_rules_and_clean_equivalent():
    client = FakeIOCClient()
    assert {
        "ATTACHMENT_EXECUTABLE",
        "ATTACHMENT_DOUBLE_EXTENSION",
        "ATTACHMENT_MIME_MISMATCH",
        "ATTACHMENT_MAGIC_MISMATCH",
    } <= failures(analyze_attachments(raw("suspicious_attachment.eml"), ioc_client=client))
    assert "ATTACHMENT_MAGIC_MISMATCH" in failures(
        analyze_attachments(attachment(b"not a PDF", "invoice.pdf", "application/pdf"), ioc_client=client)
    )
    pdf = analyze_attachments(
        attachment(b"%PDF-1.4\n/JavaScript /OpenAction\n%%EOF", "invoice.pdf", "application/pdf"), ioc_client=client
    )
    assert "PDF_ACTIVE_METADATA" in failures(pdf)
    clean = analyze_attachments(attachment(b"plain notes", "notes.txt", "text/plain"), ioc_client=client)
    assert not failures(clean) and all(item.result == "PASS" for item in clean)


def zip_bytes(entries, compression=zipfile.ZIP_STORED):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return buffer.getvalue()


def test_archive_listing_macros_and_limits(monkeypatch):
    client = FakeIOCClient()
    content = zip_bytes([("word/vbaProject.bin", b"inert"), ("../invoice.exe", b"inert")])
    assert {"OFFICE_MACRO_MEMBER", "ARCHIVE_DANGEROUS_MEMBER"} <= failures(
        analyze_attachments(attachment(content, "sample.zip"), ioc_client=client)
    )
    bomb = zip_bytes([("large.txt", b"0" * 100_000)], compression=zipfile.ZIP_DEFLATED)
    nested = zip_bytes(
        [("level1.zip", zip_bytes([("level2.zip", zip_bytes([("level3.zip", zip_bytes([("notes.txt", b"hi")]))]))]))]
    )
    cases = [bomb, nested, b"PK\x03\x04truncated"]
    for case in cases:
        result = analyze_attachments(attachment(case, "limited.zip"), ioc_client=client)
        assert any(item.signal_type == "ARCHIVE_INSPECTION" and item.result == "UNKNOWN" for item in result)
    monkeypatch.setattr("src.analyzers.attachment_analyzer.MAX_ARCHIVE_ENTRIES", 1)
    assert any(
        item.result == "UNKNOWN" for item in analyze_attachments(attachment(content, "many.zip"), ioc_client=client)
    )


def test_qr_real_decode_inline_and_clean_image(monkeypatch):
    client = FakeIOCClient()
    parsed = raw("qr_url.eml")
    items = analyze_qr_codes(parsed, ioc_client=client)
    assert "URL_IP_LITERAL" in failures(items)
    assert any(
        item.signal_type == "QR_DECODE" and item.value["decoded_payloads"] == ["https://192.0.2.10/login"]
        for item in items
    )
    image = parsed["attachments"][0]["content"]
    inline = {"html": {"resources": ["data:image/png;base64," + base64.b64encode(image).decode()]}}
    assert "URL_IP_LITERAL" in failures(analyze_qr_codes(inline, ioc_client=client))
    buffer = io.BytesIO()
    with Image.new("L", (16, 16), 255) as blank:
        blank.save(buffer, format="PNG")
    clean = analyze_qr_codes(attachment(buffer.getvalue(), "clean.png", "image/png"), ioc_client=client)
    assert not failures(clean) and all(item.result == "PASS" for item in clean)
    monkeypatch.setattr("src.analyzers.qr_analyzer.MAX_IMAGE_PIXELS", 100)
    limited = analyze_qr_codes(parsed, ioc_client=client)
    assert any(item.tool_status == "ERROR" and item.result == "UNKNOWN" for item in limited)


@pytest.mark.parametrize(
    "name,signal",
    [
        ("href_mismatch.eml", "HREF_MISMATCH"),
        ("suspicious_attachment.eml", "ATTACHMENT_DOUBLE_EXTENSION"),
        ("qr_url.eml", "URL_IP_LITERAL"),
    ],
)
@pytest.mark.asyncio
async def test_api_static_cases_use_real_analyzers_and_report_missing_intel(client, monkeypatch, name, signal):
    monkeypatch.setattr(get_settings(), "header_trusted_authserv_ids", "mx.recipient.test")
    response = await client.post("/api/v1/analysis", files={"file": (name, (EMAILS / name).read_bytes())})
    assert response.status_code == 200
    body = response.json()
    assert body["analysis_scope"] == "static_local_partial"
    assert body["label_candidate"] == "NEEDS_ANALYST_REVIEW" and body["score"] > 0
    assert signal in {item["signal_type"] for item in body["evidence"] if item["result"] == "FAIL"}
    assert len(body["analyzer_runs"]) == 4
    assert "content" not in str(body)


@pytest.mark.parametrize(
    "name,module,function",
    [
        ("header", "header_node", "analyze_headers"),
        ("url", "url_node", "analyze_urls"),
        ("attachment", "attachment_node", "analyze_attachments"),
        ("qr", "qr_node", "analyze_qr_codes"),
    ],
)
@pytest.mark.asyncio
async def test_analyzer_exceptions_do_not_crash_join(monkeypatch, name, module, function):
    def broken(*args, **kwargs):
        raise RuntimeError("simulated local analyzer failure")

    monkeypatch.setattr(f"src.agents.nodes.{module}.{function}", broken)
    result = await build_graph(ioc_client=FakeIOCClient()).ainvoke({"raw_email": (EMAILS / "clean.eml").read_bytes()})
    assert len(result["analyzer_runs"]) == 4
    assert {"analyzer": name, "status": "ERROR"} in result["analyzer_runs"]
    assert result["risk_result"].label_candidate == "NEEDS_ANALYST_REVIEW"
    assert result["requires_review"]


@pytest.mark.asyncio
async def test_fake_ioc_can_run_through_graph_and_content_contract_stays_bounded(monkeypatch):
    monkeypatch.setattr(get_settings(), "header_trusted_authserv_ids", "mx.recipient.test")
    client = FakeIOCClient((IOCRecord(kind="domain", value="other.test", source="test-snapshot"),))
    result = await build_graph(ioc_client=client).ainvoke({"raw_email": (EMAILS / "href_mismatch.eml").read_bytes()})
    assert result["risk_result"].label_candidate == "PHISHING" and result["risk_score"] >= 95
    assert result["risk_result"].coverage.complete
    assert "IOC_MATCH" in failures(result["validated_evidence"])
    with pytest.raises(ValidationError, match="content_bec"):
        ContentResult(evidence=(result["validated_evidence"][0],))
    content = ContentResult(
        evidence=(finding("content", "BEC_REQUEST", "content_bec", "redacted-fixture", "fake-provider"),)
    )
    seeded = await build_graph(ioc_client=FakeIOCClient()).ainvoke(
        {
            "raw_email": (EMAILS / "clean.eml").read_bytes(),
            "evidence": list(content.evidence),
        }
    )
    assert seeded["risk_score"] == 10
    assert any(item.family == "content_bec" for item in seeded["validated_evidence"])
