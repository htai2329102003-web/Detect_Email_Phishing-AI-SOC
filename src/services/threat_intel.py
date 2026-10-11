"""Canonical exact-match IOC facade. Semantic knowledge lives exclusively in rag.py."""

from src.schemas.tool import ToolResult
from src.services.external import controlled_call
from src.services.ioc_store import IOCClient, IOCKind, IOCRecord, UnconfiguredIOCClient, lookup_ioc


class ThreatIntelService:
    def __init__(self, repository: IOCClient | None = None, *, virustotal=None, urlscan=None):
        self.repository = repository if repository is not None else UnconfiguredIOCClient()
        self.virustotal, self.urlscan = virustotal, urlscan

    @staticmethod
    def confirmed_file_malicious(report) -> bool:
        # Require at least three independent vendor detections. A lone vendor hit
        # remains report context, not the high-confidence IOC override.
        return report is not None and report.malicious >= 3

    def external_hash(self, value):
        return self.virustotal.lookup_hash(value)

    def external_url(self, value):
        return self.urlscan.lookup_url(value)

    def enrich(self, kind: IOCKind, value: str) -> dict[str, ToolResult]:
        """Local first, optional external second; never merge source verdicts."""
        local = self.lookup(kind, value)
        results = {"local_ioc": local}
        if local.status == "OK" and local.data is not None and local.data.role == "MALICIOUS":
            return results
        if kind == "hash" and self.virustotal is not None:
            wrapped = controlled_call("VT", lambda: self.external_hash(value))
            results["virustotal"] = wrapped.data if wrapped.status == "OK" else wrapped
        if kind == "url" and self.urlscan is not None:
            wrapped = controlled_call("URLSCAN", lambda: self.external_url(value))
            results["urlscan"] = wrapped.data if wrapped.status == "OK" else wrapped
        return results

    def lookup(self, kind: IOCKind, value: str) -> ToolResult[IOCRecord]:
        return lookup_ioc(self.repository, kind, value)

    def lookup_domain(self, domain: str) -> ToolResult[IOCRecord]:
        return self.lookup("domain", domain)

    def lookup_url(self, url: str) -> ToolResult[IOCRecord]:
        return self.lookup("url", url)

    def lookup_ip(self, ip: str) -> ToolResult[IOCRecord]:
        return self.lookup("ip", ip)

    def lookup_hash(self, sha256: str) -> ToolResult[IOCRecord]:
        return self.lookup("hash", sha256)
