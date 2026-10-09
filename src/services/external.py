"""Shared, bounded GET transport and ToolResult error mapping. No automatic retry."""

from collections.abc import Callable
from time import perf_counter
from typing import Protocol, TypeVar
from urllib.parse import urlsplit

import httpx

from src.schemas.tool import ToolResult

T = TypeVar("T")
MAX_RESPONSE_BYTES = 1024 * 1024


class HTTPTransport(Protocol):
    def get(self, path: str, *, headers: dict[str, str], params: dict[str, str], timeout: float) -> httpx.Response: ...


class HTTPXTransport:
    """Only talks to a configured HTTPS provider origin; never follows IOC URLs."""

    def __init__(self, base_url: str):
        url = urlsplit(base_url)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("Provider base URL must be HTTPS without credentials/query/fragment")
        self.base_url = base_url.rstrip("/")

    def get(self, path: str, *, headers: dict[str, str], params: dict[str, str], timeout: float) -> httpx.Response:
        if not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path:
            raise ValueError("Expected a provider-relative path")
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=timeout) as client:
            with client.stream("GET", self.base_url + path, headers=headers, params=params) as response:
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > MAX_RESPONSE_BYTES:
                        raise ValueError("Provider response limit")
                return httpx.Response(response.status_code, content=bytes(content))


class ProviderHTTPError(Exception):
    def __init__(self, status: int):
        self.status = status


def provider_json(
    transport: HTTPTransport, path: str, *, headers: dict[str, str], params: dict[str, str], timeout: float
):
    response = transport.get(path, headers=headers, params=params, timeout=timeout)
    if response.status_code != 200:
        raise ProviderHTTPError(response.status_code)
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise ValueError("Provider response limit")
    return response.json()


def controlled_call(provider: str, operation: Callable[[], T], *, configured: bool = True) -> ToolResult[T]:
    started = perf_counter()
    status = "ERROR"
    code = f"{provider}_NOT_CONFIGURED"
    if configured:
        try:
            return ToolResult(status="OK", data=operation(), latency_ms=(perf_counter() - started) * 1000)
        except (httpx.TimeoutException, TimeoutError):
            status, code = "TIMEOUT", f"{provider}_TIMEOUT"
        except ProviderHTTPError as exc:
            if exc.status == 429:
                status, code = "RATE_LIMITED", f"{provider}_RATE_LIMITED"
            elif exc.status in {401, 403}:
                code = f"{provider}_UNAUTHORIZED"
            elif exc.status in {404, 410}:
                code = f"{provider}_NOT_FOUND"
            else:
                code = f"{provider}_UPSTREAM_ERROR"
        except (httpx.NetworkError, httpx.RemoteProtocolError, ConnectionError):
            code = f"{provider}_NETWORK_ERROR"
        except (ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError):
            code = f"{provider}_INVALID_RESPONSE"
        except Exception:
            code = f"{provider}_PROVIDER_ERROR"
    return ToolResult(status=status, error_code=code, latency_ms=(perf_counter() - started) * 1000)
