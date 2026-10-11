"""Read existing scans via search + result retrieval. Submission is not exposed."""

import json
import re
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import unquote, urlsplit
from uuid import UUID

from pydantic import Field, StrictBool, model_validator

from src.evidence.models import Contract, NonEmpty
from src.schemas.tool import ToolResult
from src.services.external import HTTPTransport, HTTPXTransport, LookupCache, controlled_call, provider_json
from src.services.ioc_store import normalize_ioc


class URLReport(Contract):
    scanned_url: str
    final_url: str
    redirect_chain: tuple[str, ...] = ()
    malicious: StrictBool | None = None
    domains: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    source_reference: NonEmpty
    looked_up_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def validate_binding(self):
        for value in (self.scanned_url, self.final_url, *self.redirect_chain):
            if normalize_ioc("url", value) != value:
                raise ValueError("Expected canonical URL")
        for kind, values in (("domain", self.domains), ("ip", self.ips)):
            if any(normalize_ioc(kind, item) != item for item in values):
                raise ValueError("Expected canonical related indicators")
        return self


class URLReputationClient(Protocol):
    def lookup_url(self, url: str) -> ToolResult[URLReport]: ...


def public_lookup_url(value: str) -> bool:
    """Conservative production disclosure boundary: no query, credentials, tokens or PII paths."""
    from src.services.pii import RegexPIIRedactor

    parts = urlsplit(value)
    decoded = unquote(value)
    if parts.query or parts.fragment or parts.username or parts.password:
        return False
    if RegexPIIRedactor().redact({"url": decoded}).counts:
        return False
    return not bool(re.search(r"@|\d{6,}|[A-Za-z0-9_-]{32,}|\.[A-Za-z0-9_-]+\.", unquote(parts.path)))


class URLScanClient:
    def __init__(self, *, api_key: str = "", transport: HTTPTransport | None = None, timeout: float = 5,
                 cache_ttl: float = 3600, min_interval: float = 0, strict_privacy: bool = True):
        self.api_key, self.transport, self.timeout = api_key, transport, timeout
        self.cache = LookupCache(ttl=cache_ttl, min_interval=min_interval)
        self.strict_privacy = strict_privacy

    @classmethod
    def from_settings(cls, settings):
        return cls(
            api_key=settings.urlscan_api_key if settings.urlscan_enabled else "",
            transport=HTTPXTransport(settings.urlscan_base_url),
            timeout=settings.urlscan_timeout_seconds,
            cache_ttl=settings.urlscan_cache_ttl_seconds,
            min_interval=settings.urlscan_min_interval_seconds,
        )

    def lookup_url(self, url: str) -> ToolResult[URLReport]:
        def lookup():
            canonical = normalize_ioc("url", url)
            headers = {"api-key": self.api_key}
            payload = provider_json(
                self.transport,
                "/search/",
                headers=headers,
                params={"q": "task.url:" + json.dumps(canonical), "size": "10"},
                timeout=self.timeout,
            )
            results = payload["results"]
            if not isinstance(results, list) or len(results) > 10:
                raise ValueError("Invalid search results")
            for hit in results:
                if normalize_ioc("url", hit["task"]["url"]) != canonical:
                    continue
                scan_id = str(UUID(hit["_id"]))
                result = provider_json(
                    self.transport, f"/result/{scan_id}/", headers=headers, params={}, timeout=self.timeout
                )
                if normalize_ioc("url", result["task"]["url"]) != canonical:
                    raise ValueError("Result URL mismatch")
                final = normalize_ioc("url", result["page"]["url"])
                lists = result.get("lists", {})
                domains, ips = lists.get("domains", []), lists.get("ips", [])
                if not isinstance(domains, list) or not isinstance(ips, list) or len(domains) + len(ips) > 512:
                    raise ValueError("Invalid related indicators")
                requests = result.get("data", {}).get("requests", [])
                if not isinstance(requests, list) or len(requests) > 512:
                    raise ValueError("Request listing limit")
                redirects = []
                for entry in requests:
                    response = entry.get("request", {}).get("redirectResponse")
                    if response and response.get("url"):
                        redirects.append(normalize_ioc("url", response["url"]))
                return URLReport(
                    scanned_url=canonical,
                    final_url=final,
                    redirect_chain=tuple(dict.fromkeys(redirects)),
                    malicious=result.get("verdicts", {}).get("overall", {}).get("malicious"),
                    domains=tuple(normalize_ioc("domain", item) for item in domains),
                    ips=tuple(normalize_ioc("ip", item) for item in ips),
                    source_reference=f"urlscan:result/{scan_id}",
                )
            return None  # No report is UNKNOWN, never a harmless scan.

        if not self.api_key or self.transport is None:
            return controlled_call("URLSCAN", lookup, configured=False)
        try:
            canonical = normalize_ioc("url", url)
            if self.strict_privacy and not public_lookup_url(url):
                return ToolResult(status="ERROR", error_code="URLSCAN_PRIVACY_BLOCKED", latency_ms=0)
        except ValueError:
            return ToolResult(status="ERROR", error_code="URLSCAN_INVALID_QUERY", latency_ms=0)
        return self.cache.call("URLSCAN", canonical, lambda: controlled_call("URLSCAN", lookup))
