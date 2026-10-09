"""Read existing scans via search + result retrieval. Submission is not exposed."""

import json
from typing import Protocol
from uuid import UUID

from pydantic import StrictBool, model_validator

from src.evidence.models import Contract, NonEmpty
from src.schemas.tool import ToolResult
from src.services.external import HTTPTransport, HTTPXTransport, controlled_call, provider_json
from src.services.ioc_store import normalize_ioc


class URLReport(Contract):
    scanned_url: str
    final_url: str
    redirect_chain: tuple[str, ...] = ()
    malicious: StrictBool | None = None
    domains: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    source_reference: NonEmpty

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


class URLScanClient:
    def __init__(self, *, api_key: str = "", transport: HTTPTransport | None = None, timeout: float = 5):
        self.api_key, self.transport, self.timeout = api_key, transport, timeout

    @classmethod
    def from_settings(cls, settings):
        return cls(
            api_key=settings.urlscan_api_key,
            transport=HTTPXTransport(settings.urlscan_base_url),
            timeout=settings.external_timeout_seconds,
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

        return controlled_call("URLSCAN", lookup, configured=bool(self.api_key and self.transport))
