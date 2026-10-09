"""Canonical exact-match IOC facade. Semantic knowledge lives exclusively in rag.py."""

from src.schemas.tool import ToolResult
from src.services.ioc_store import IOCClient, IOCKind, IOCRecord, UnconfiguredIOCClient, lookup_ioc


class ThreatIntelService:
    def __init__(self, repository: IOCClient | None = None):
        self.repository = repository if repository is not None else UnconfiguredIOCClient()

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
