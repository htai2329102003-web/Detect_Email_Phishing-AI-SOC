from datetime import datetime
from typing import Literal

from pydantic import Field, JsonValue, model_validator

from src.evidence.models import Contract, EvidenceResult, NonEmpty, RiskLabel
from src.schemas.analysis import AnalysisScope
from src.schemas.verdict import Claim
from src.services.ioc_store import IOCRecord

Profile = Literal["offline", "fake-success", "fake-bec", "fake-timeout", "fake-unavailable", "fake-ungrounded"]


class InjectionSpec(Contract):
    """Paired oracle: append data to a base email, or supply a pre-existing attack file."""

    payload: NonEmpty | None = Field(default=None, max_length=8192)
    baseline_file: NonEmpty | None = None
    required_analyzers: tuple[NonEmpty, ...] = ("header", "url", "attachment", "qr")
    expect_same_risk: bool = True
    secret_canaries: tuple[NonEmpty, ...] = Field(default=(), repr=False)

    @model_validator(mode="after")
    def has_pair(self):
        if self.payload is None and self.baseline_file is None:
            raise ValueError("Injection requires a payload or baseline_file")
        return self


class EvalCase(Contract):
    id: NonEmpty = Field(max_length=128)
    file: NonEmpty
    expected_label: RiskLabel | None
    expected_signals: tuple[NonEmpty, ...] = ()
    # Risk signals default to FAIL. Explicit PASS supports decode/completion checks.
    expected_results: dict[NonEmpty, EvidenceResult] = Field(default_factory=dict)
    capabilities: tuple[NonEmpty, ...] = Field(min_length=1)
    language: NonEmpty
    source: NonEmpty
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    profile: Profile | None = None
    ioc_records: tuple[IOCRecord, ...] = Field(default=(), max_length=1000)
    injection: InjectionSpec | None = None
    expected_error: NonEmpty | None = None

    @model_validator(mode="after")
    def check_sets(self):
        if len(set(self.expected_signals)) != len(self.expected_signals) or len(set(self.capabilities)) != len(
            self.capabilities
        ):
            raise ValueError("Duplicate signal or capability")
        if not set(self.expected_results).issubset(self.expected_signals):
            raise ValueError("expected_results must refer to expected_signals")
        if self.injection is not None and "prompt_injection" not in self.capabilities:
            raise ValueError("Injection needs prompt_injection capability")
        return self


class EvalError(Contract):
    stage: Literal["manifest", "input", "analysis", "observation"]
    code: NonEmpty
    message: NonEmpty
    exception_type: str | None = None


class ClaimAudit(Contract):
    attempt: int = Field(ge=1)
    total: int = Field(ge=0)
    grounded: int = Field(ge=0)
    rejected: int = Field(ge=0)
    gate_status: str
    reasons: tuple[str, ...] = ()

    @model_validator(mode="after")
    def check_counts(self):
        if self.grounded + self.rejected != self.total:
            raise ValueError("Claim audit counts do not balance")
        return self


class AttackResult(Contract):
    detected: bool | None = None
    attack_success: bool | None = None
    required_analyzers_ran: bool | None = None
    rule_score_consistent: bool | None = None
    risk_label_consistent: bool | None = None
    baseline_score_unchanged: bool | None = None
    baseline_label_unchanged: bool | None = None
    secret_leaked: bool | None = None
    violations: tuple[str, ...] = ()
    error: EvalError | None = None
    baseline_latency_ms: float | None = Field(default=None, ge=0)


class PredictionRecord(Contract):
    case_id: NonEmpty
    manifest_line: int = Field(ge=1)
    file: str | None = None
    expected_label: RiskLabel | None = None
    predicted_label: RiskLabel | None = None
    assessment_label: RiskLabel | None = None
    profile: Profile = "offline"
    capabilities: tuple[str, ...] = ()
    language: str | None = None
    source: str | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    status: Literal["success", "failed"]
    score: float | None = Field(default=None, ge=0, le=100)
    analysis_scope: AnalysisScope | None = None
    requires_review: bool | None = None
    expected_signals: tuple[str, ...] = ()
    expected_results: dict[str, EvidenceResult] = Field(default_factory=dict)
    produced_signals: tuple[str, ...] = ()
    signal_results: dict[str, tuple[EvidenceResult, ...]] = Field(default_factory=dict)
    claims: tuple[Claim, ...] = ()
    # Candidate claims across every attempt, including rejected/retried proposals.
    grounded_claim_count: int | None = Field(default=None, ge=0)
    total_claim_count: int | None = Field(default=None, ge=0)
    claim_audits: tuple[ClaimAudit, ...] = ()
    emitted_claim_count: int | None = Field(default=None, ge=0)
    latency_ms: float | None = Field(default=None, ge=0)
    cost_usd: float | None = Field(default=None, ge=0)
    cost_source: str | None = None
    coverage_complete: bool | None = None
    attack: AttackResult | None = None
    expected_failure: bool = False
    error: EvalError | None = None

    @model_validator(mode="after")
    def check_observations(self):
        if self.status == "failed" and self.error is None:
            raise ValueError("Failed records require an error")
        if (
            self.grounded_claim_count is not None
            and self.total_claim_count is not None
            and self.grounded_claim_count > self.total_claim_count
        ):
            raise ValueError("Grounded claims exceed total")
        if self.cost_usd is not None and not self.cost_source:
            raise ValueError("Observed cost requires metadata source")
        return self


class Ratio(Contract):
    value: float | None = Field(default=None, ge=0, le=1)
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)


class EvaluationReport(Contract):
    schema_version: Literal[1] = 1
    generated_at: datetime
    split: Literal["dev", "test"]
    manifest: str
    configuration: dict[str, JsonValue]
    label_policy: dict[str, JsonValue]
    summary: dict[str, JsonValue]
    capabilities: dict[str, dict[str, JsonValue]]
    cases: tuple[PredictionRecord, ...]
