import re
import unicodedata
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

from src.analyzers.common import finding, ioc_evidence
from src.evidence.models import Evidence
from src.services.ioc_store import IOCClient, UnconfiguredIOCClient, normalize_ioc

SHORTENERS = frozenset({"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", "cutt.ly", "rb.gy"})
CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "α": "a",
        "ο": "o",
        "ρ": "p",
        "0": "o",
        "1": "l",
    }
)


def _one_edit(left: str, right: str) -> bool:
    if abs(len(left) - len(right)) > 1 or left == right:
        return False
    if len(left) == len(right):
        positions = [i for i, (a, b) in enumerate(zip(left, right)) if a != b]
        return len(positions) == 1 or (
            len(positions) == 2
            and positions[1] == positions[0] + 1
            and left[positions[0]] == right[positions[1]]
            and left[positions[1]] == right[positions[0]]
        )
    short, long = (left, right) if len(left) < len(right) else (right, left)
    index = next((i for i in range(len(short)) if short[i] != long[i]), len(short))
    return short[index:] == long[index + 1 :]


def _lookalike(host: str, protected: tuple[str, ...]) -> str | None:
    unicode_host = host.encode("ascii").decode("idna")
    skeleton = unicodedata.normalize("NFKC", unicode_host).lower().translate(CONFUSABLES)
    for target in protected:
        target = normalize_ioc("domain", target)
        if host == target or host.endswith("." + target):
            continue
        # Limited confusable/typo heuristic, not a complete Unicode confusable database.
        if skeleton == target or _one_edit(host, target):
            return target
    return None


def analyze_urls(
    parsed_email: dict[str, Any],
    *,
    ioc_client: IOCClient | None = None,
    protected_domains: tuple[str, ...] = (),
    analyzer: str = "url",
) -> list[Evidence]:
    """Static URL heuristics and exact-match lookups. Never fetch/resolve a URL."""
    client = ioc_client if ioc_client is not None else UnconfiguredIOCClient()
    links = parsed_email.get("html", {}).get("links", [])
    candidates = list(dict.fromkeys([*parsed_email.get("urls", []), *(link["href"] for link in links)]))
    candidates = [url for url in candidates if not url.lower().startswith(("mailto:", "tel:", "cid:", "#"))]
    output: list[Evidence] = []
    complete = True
    if len(candidates) > 256:
        complete = False
    for raw in candidates[:256]:
        try:
            if len(raw) > 8192:
                raise ValueError("URL length limit")
            canonical = normalize_ioc("url", raw)
        except (ValueError, UnicodeError):
            complete = False
            output.append(
                finding(
                    analyzer,
                    "URL_OBFUSCATED",
                    "url_deception",
                    raw or "empty-url",
                    {"raw_url": raw, "normalizable": False},
                )
            )
            continue
        parsed = urlsplit(canonical)
        host = parsed.hostname
        details = {"raw_url": raw, "canonical_url": canonical}
        signals = []
        try:
            ip_address(host)
            signals.append("URL_IP_LITERAL")
        except ValueError:
            pass
        if any(label.startswith("xn--") for label in host.split(".")):
            signals.append("URL_PUNYCODE")
        if len(host.split(".")) > 5:
            signals.append("URL_EXCESSIVE_SUBDOMAIN")
        if host in SHORTENERS:
            signals.append("URL_SHORTENER")
        if parsed.port is not None and parsed.port not in {80, 443}:
            signals.append("URL_SUSPICIOUS_PORT")
        if (
            parsed.username is not None
            or any(ord(char) <= 32 or ord(char) == 127 for char in raw)
            or re.search(r"%[0-9a-f]{2}", raw, re.IGNORECASE)
            or re.fullmatch(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}", host)
        ):
            signals.append("URL_OBFUSCATED")
        try:
            target = _lookalike(host, protected_domains) if ":" not in host else None
        except (ValueError, UnicodeError):
            target = None
            complete = False
        if target:
            output.append(
                finding(
                    analyzer,
                    "URL_LOOKALIKE",
                    "url_deception",
                    canonical,
                    {**details, "protected_domain": target},
                    confidence=0.8,
                )
            )
        for signal in signals:
            output.append(finding(analyzer, signal, "url_deception", canonical, details))
        for link in links:
            if link["href"] != raw:
                continue
            displayed = re.search(r"https?://[^\s<>]+", link.get("text", ""), re.IGNORECASE)
            if displayed:
                try:
                    shown = normalize_ioc("url", displayed[0].rstrip(".,;)"))
                    if shown != canonical:
                        output.append(
                            finding(
                                analyzer,
                                "HREF_MISMATCH",
                                "url_deception",
                                canonical,
                                {**details, "displayed_url": shown},
                            )
                        )
                except ValueError:
                    complete = False
        queries = [("url", canonical)]
        try:
            queries.append(("ip", normalize_ioc("ip", host)))
        except ValueError:
            queries.append(("domain", host))
        output.extend(ioc_evidence(analyzer, canonical, queries, client, "URL_IOC_CHECK"))
    output.append(
        finding(
            analyzer,
            "URL_ANALYSIS",
            "url_deception",
            f"{analyzer}:url_checks",
            {"checked": len(candidates), "scope": "local_static"},
            "PASS" if complete else "UNKNOWN",
        )
    )
    return output
