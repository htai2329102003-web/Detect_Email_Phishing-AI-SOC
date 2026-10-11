"""Direct capability boundaries. No navigation, attachment execution, or risk tuning."""

from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Protocol

from eval.capability import CapabilityCase, CapabilityResult, resolve_input
from eval.injection import evaluate_attack, inject_email
from eval.schemas import EvalCase, InjectionSpec
from eval.targets import AnalysisTarget, GraphTarget
from src.analyzers.attachment_analyzer import analyze_attachments
from src.analyzers.content_analyzer import ContentAnalyzer, RedactedContent, StructuredContentAnalyzer
from src.analyzers.header_analyzer import analyze_headers
from src.analyzers.qr_analyzer import MAX_IMAGE_BYTES, QRDecoder, analyze_qr_codes
from src.analyzers.url_analyzer import analyze_urls
from src.config import get_settings
from src.evidence.validation import validate_evidence
from src.parsers.email_parser import MAX_EMAIL_BYTES, parse_email
from src.services.ioc_store import IOCClient
from src.services.llm import LLMClient
from src.services.pii import RegexPIIRedactor


class CapabilityAdapter(Protocol):
    async def evaluate(self, case: CapabilityCase, root: Path) -> CapabilityResult: ...


def read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError("CAPABILITY_INPUT_TOO_LARGE")
    return content


@dataclass
class AnalyzerAdapter:
    ioc_client: IOCClient | None = None
    content: ContentAnalyzer | None = None
    decoder: QRDecoder | None = None
    security_target: AnalysisTarget | None = None
    security_spec: InjectionSpec | None = None

    async def evaluate(self, case: CapabilityCase, root: Path) -> CapabilityResult:
        target = {"vietnamese_url": "url/IOC", "bec": "content_bec", "qr_analyzer": "qr/url/IOC",
                  "prompt_injection": "graph/Gate1/risk/verdict/Gate2", "auth_header": "header",
                  "attachment": "attachment/static/IOC"}[case.capability]
        start = perf_counter()
        base = dict(case=case, execution_target=target)
        try:
            path = resolve_input(root, case.file)
            if not path.is_file():
                raise FileNotFoundError
            result = await self._analyze(case, path, base, root)
        except Exception as exc:
            result = CapabilityResult(**base, status="ERROR", error_code=(
                "FILE_NOT_FOUND" if isinstance(exc, FileNotFoundError) else "CAPABILITY_EXECUTION_ERROR"),
                observations={"exception_type": type(exc).__name__})
        return result.model_copy(update={"latency_ms": (perf_counter()-start)*1000})

    async def _analyze(self, case, path, base, root):
        capability, observations = case.capability, {}
        settings = get_settings()
        protected = tuple(x.strip() for x in settings.url_protected_domains.split(",") if x.strip())
        if capability == "vietnamese_url":
            evidence = analyze_urls({"urls": [case.payload.get("url_norm") or case.payload["url"]]},
                                    ioc_client=self.ioc_client, protected_domains=protected)
        elif capability == "bec":
            raw = {"text": f"{case.payload['subject']}\n{case.payload['body']}"}
            redacted = RegexPIIRedactor().redact(raw)
            provider = self.content if self.content is not None else StructuredContentAnalyzer(LLMClient())
            output = provider.analyze(RedactedContent(text=redacted.data["text"], redaction_reference=redacted.policy))
            observations = {"redaction_policy": redacted.policy, "redaction_counts": redacted.counts,
                            "provider_status": output.status}
            if output.status != "OK" or output.data is None:
                return CapabilityResult(**base, status="UNAVAILABLE", error_code=output.error_code or "BEC_EMPTY_RESULT",
                                        observations=observations)
            evidence = list(output.data.evidence)
            if not any(e.signal_type == "BEC_REQUEST" for e in evidence):
                return CapabilityResult(**base, status="UNKNOWN", error_code="BEC_ORACLE_UNAVAILABLE")
        elif capability == "qr_analyzer":
            content = read_bounded(path, MAX_IMAGE_BYTES)
            evidence = analyze_qr_codes({"attachments": [{"content": content, "content_type": "image/png"}]},
                decoder=self.decoder, ioc_client=self.ioc_client, protected_domains=protected)
            payloads = [payload for e in evidence if e.signal_type == "QR_DECODE" and isinstance(e.value, dict)
                        for payload in e.value.get("decoded_payloads", [])]
            observations = {"decoded_payloads": payloads, "expected_payload": case.metadata.get("payload"),
                "payload_matches": case.metadata["payload"] in payloads if "payload" in case.metadata else None}
            if not payloads:
                return CapabilityResult(**base, status="UNKNOWN", evidence=tuple(evidence),
                                        observations=observations, error_code="QR_PAYLOAD_UNAVAILABLE")
        elif capability == "prompt_injection":
            # Existing security target and ASR oracle; no capability label enters RiskLabel.
            raw = read_bounded(path, MAX_EMAIL_BYTES)
            email_case = EvalCase(id=case.sample_id, file=case.file, expected_label=None,
                capabilities=("prompt_injection",), language=case.language or "unknown", source=case.source)
            target = self.security_target if self.security_target is not None else GraphTarget()
            # No paired baseline exists in this corpus: check rule integrity, never assert unchanged risk.
            spec = self.security_spec or InjectionSpec(baseline_file=case.file, expect_same_risk=False)
            baseline = None
            if self.security_spec is not None:
                baseline_raw = read_bounded(resolve_input(root, spec.baseline_file), MAX_EMAIL_BYTES) if spec.baseline_file else raw
                baseline = await target.analyze(baseline_raw, email_case)
                if spec.payload:
                    raw = inject_email(raw, spec.payload)
            observed = await target.analyze(raw, email_case)
            attack = evaluate_attack(spec, observed, baseline if baseline is not None else observed)
            return CapabilityResult(**base, status="OK", evidence=tuple(observed.response.evidence),
                observations={"attack_attempted": True, "attack": attack.model_dump(mode="json"),
                              "oracle_scope": "explicit paired specification" if self.security_spec else
                                              "rule integrity; no paired baseline or secret-leak oracle",
                              "guardrail_passed": None if attack.attack_success is None else not attack.attack_success})
        else:
            parsed = parse_email(read_bounded(path, MAX_EMAIL_BYTES)).raw_for_analyzers
            if capability == "auth_header":
                evidence = analyze_headers(parsed,
                    trusted_authserv_ids=tuple(settings.header_trusted_authserv_ids.split(",")))
            else:
                evidence = analyze_attachments(parsed, ioc_client=self.ioc_client)
                observations["attachment_count"] = len(parsed["attachments"])
                if not parsed["attachments"]:
                    return CapabilityResult(**base, status="UNKNOWN", error_code="NO_ATTACHMENT",
                                            evidence=tuple(evidence), observations=observations)
        gate = validate_evidence(evidence)
        if gate.issues:
            return CapabilityResult(**base, status="ERROR", error_code="INVALID_ANALYZER_EVIDENCE")
        evidence = gate.evidence
        complete = bool(evidence) and all(e.result != "UNKNOWN" and e.tool_status == "OK" for e in evidence)
        positive = any(e.result == "FAIL" for e in evidence)
        # Classification is a static detector result, never an email RiskLabel or a safety guarantee.
        prediction = (True if positive else False if complete else None) if capability in {
            "vietnamese_url", "bec", "qr_analyzer"} else None
        return CapabilityResult(**base, status="OK" if complete else "UNKNOWN", predicted_positive=prediction,
            evidence=evidence, observations={**observations, "evidence_complete": complete,
                "failed_tool_checks": sum(e.tool_status != "OK" for e in evidence),
                "classification_policy": "any validated FAIL; negative only when all applicable checks complete"})
