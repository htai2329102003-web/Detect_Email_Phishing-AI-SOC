import re
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

from src.evidence.models import Evidence

HEADER_SIGNALS = (
    "SPF_FAIL",
    "DKIM_FAIL",
    "DMARC_FAIL",
    "REPLY_TO_MISMATCH",
    "RETURN_PATH_MISMATCH",
    "DISPLAY_NAME_DOMAIN_MISMATCH",
    "RECEIVED_CHAIN_ANOMALY",
)


def _auth_clauses(value: str) -> list[str] | None:
    """Split reported auth clauses while ignoring comments and quoted semicolons."""
    clauses, current = [], []
    depth, quoted, escaped = 0, False, False
    for char in value:
        if escaped:
            if not depth:
                current.append(" " if quoted else char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"' and not depth:
            quoted = not quoted
            current.append(" ")
        elif char == "(" and not quoted:
            if not depth:
                current.append(" ")
            depth += 1
        elif char == ")" and not quoted:
            if not depth:
                return None
            depth -= 1
        elif char == ";" and not depth and not quoted:
            clauses.append("".join(current).strip())
            current = []
        elif not depth:
            current.append(" " if quoted else char)
    if depth or quoted or escaped:
        return None
    clauses.append("".join(current).strip())
    return clauses


def _reported_auth(values: list[str], trusted: set[str]) -> tuple[dict[str, list[str]], str | None]:
    # Only the topmost Authentication-Results is eligible. Never search lower headers
    # for a matching authserv-id; those may be sender-supplied copies.
    clauses = _auth_clauses(values[0]) if values else None
    authserv = clauses[0].split()[0].lower().rstrip(".") if clauses and clauses[0] else None
    results: dict[str, list[str]] = {}
    if authserv not in trusted:
        return results, authserv
    for clause in clauses[1:]:
        match = re.match(r"(spf|dkim|dmarc)(?:/\d+)?\s*=\s*([a-z]+)(?=\s|$)", clause, re.IGNORECASE)
        if match:
            results.setdefault(match[1].lower(), []).append(match[2].lower())
    return results, authserv


def analyze_headers(
    parsed_email: dict[str, Any],
    *,
    trusted_authserv_ids: tuple[str, ...] = (),
    now: datetime | None = None,
) -> list[Evidence]:
    """Analyze local header facts; reported auth is not cryptographic verification.

    Trust configuration assumes the .eml was exported from that receiver, which strips
    forged Authentication-Results. Upload alone cannot authenticate that assumption.
    """
    now = now or datetime.now(UTC)
    output: list[Evidence] = []

    def emit(signal: str, result: str, indicator: str, value: Any, *, confidence: float = 1.0):
        output.append(
            Evidence(
                analyzer="header",
                tool="local_header_rules",
                signal_type=signal,
                family="email_auth" if signal in {"SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"} else "identity",
                indicator=indicator,
                value=value,
                result=result,
                tool_status="OK",
                severity="medium" if result == "FAIL" else "info",
                confidence=confidence,
                provenance={"source": "local", "reference": "header_rules:v1"},
                collected_at=now,
            )
        )

    trusted = {value.strip().lower().rstrip(".") for value in trusted_authserv_ids if value.strip()}
    auth, authserv = _reported_auth(parsed_email.get("authentication_results", []), trusted)
    for method in ("spf", "dkim", "dmarc"):
        reported = auth.get(method, [])
        observed = reported[0] if len(reported) == 1 else None
        result = "PASS" if observed == "pass" else "FAIL" if observed in {"fail", "softfail"} else "UNKNOWN"
        emit(
            f"{method.upper()}_FAIL",
            result,
            f"Authentication-Results:{method}",
            {
                "reported_results": reported,
                "authserv_id": authserv,
                "trusted_receiver": authserv in trusted,
                "verification": "reported_header_only",
            },
        )

    sender = parsed_email.get("from", {})
    domain = sender.get("domain")
    for field, signal in (("reply_to", "REPLY_TO_MISMATCH"), ("return_path", "RETURN_PATH_MISMATCH")):
        addresses = parsed_email.get(field, [])
        domains = [address["domain"] for address in addresses]
        if not domain or (field == "return_path" and not domains):
            result = "UNKNOWN"
        else:
            # An absent Reply-To uses From. Compare exact domains; no PSL guessing.
            result = "FAIL" if any(item != domain for item in domains) else "PASS"
        emit(signal, result, field, {"from_domain": domain, "observed_domains": domains})

    display = sender.get("display_name", "")
    displayed_domains = re.findall(r"(?<![\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,63}(?![\w.-])", display, re.IGNORECASE)
    mismatch = any(value.lower().rstrip(".") != domain for value in displayed_domains)
    emit(
        "DISPLAY_NAME_DOMAIN_MISMATCH",
        "FAIL" if mismatch else "PASS" if domain else "UNKNOWN",
        "From:display-name",
        {"from_domain": domain, "displayed_domains": displayed_domains},
    )

    received = parsed_email.get("received", [])
    dates = []
    for hop in received:
        try:
            timestamp = parsedate_to_datetime(hop.rsplit(";", 1)[1].strip())
            if timestamp.tzinfo is None:
                raise ValueError("Missing Received timezone")
            dates.append(timestamp)
        except (ValueError, TypeError, IndexError, OverflowError):
            break
    anomaly = len(received) > 30 or len(set(received)) != len(received)
    if len(dates) == len(received):
        anomaly |= any(older - newer > timedelta(minutes=5) for newer, older in zip(dates, dates[1:]))
    result = "FAIL" if anomaly else "UNKNOWN" if not received or len(dates) != len(received) else "PASS"
    emit(
        "RECEIVED_CHAIN_ANOMALY",
        result,
        "Received",
        {
            "hop_count": len(received),
            "parsed_timestamp_count": len(dates),
            "basic_anomaly": anomaly,
        },
        confidence=0.8,
    )
    return output
