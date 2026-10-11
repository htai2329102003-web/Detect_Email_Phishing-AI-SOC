"""Graph adapter and verdict observation. Only offline/explicit fake profiles are exposed."""

from copy import deepcopy
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel

from eval.schemas import ClaimAudit, EvalCase, Profile
from src.agents.graph import build_graph
from src.agents.state import AgentState
from src.evidence.claim_validator import validate_verdict_claims
from src.evidence.risk_engine import score_evidence
from src.schemas.analysis import AnalysisResponse
from src.schemas.verdict import render_summary
from src.services.ioc_store import InMemoryIOCStore
from src.services.verdict import DeterministicVerdictProvider


@dataclass(frozen=True)
class Observation:
    response: AnalysisResponse
    state: AgentState
    claim_audits: tuple[ClaimAudit, ...] = ()
    cost_usd: float | None = None
    cost_source: str | None = None


class AnalysisTarget(Protocol):
    async def analyze(self, raw: bytes, case: EvalCase) -> Observation: ...


class RecordingVerdict:
    def __init__(self, provider):
        self.provider = provider
        self.is_llm = provider.is_llm
        self.proposals = []

    def generate(self, request, *, feedback=()):
        proposal = self.provider.generate(request, feedback=feedback)
        self.proposals.append(deepcopy(proposal.model_dump() if isinstance(proposal, BaseModel) else proposal))
        return proposal


class UngroundedFixtureVerdict(DeterministicVerdictProvider):
    """Deliberately bad synthetic provider, to prove discarded claims affect the denominator."""

    is_llm = True

    def generate(self, request, *, feedback=()):
        proposal = super().generate(request, feedback=feedback).model_dump()
        proposal["claims"] = [
            *proposal["claims"],
            {"claim_type": "IOC", "text": "Invented malicious indicator.", "evidence_ids": ["ev_synthetic_missing"]},
        ]
        proposal["analyst_summary"] = render_summary(request.risk, len(proposal["claims"]))
        return proposal


def audit_proposals(proposals, state: AgentState) -> tuple[ClaimAudit, ...]:
    oracle = score_evidence(state["evidence_validation"], applicable_signals=state.get("applicable_signals", []))
    audits = []
    for attempt, proposal in enumerate(proposals, 1):
        claims = proposal.get("claims", ()) if isinstance(proposal, dict) else ()
        total = len(claims) if isinstance(claims, (list, tuple)) else 0
        gate = validate_verdict_claims(proposal, state["validated_evidence"], oracle)
        grounded = len(gate.verdict.claims)
        audits.append(
            ClaimAudit(
                attempt=attempt,
                total=total,
                grounded=grounded,
                rejected=total - grounded,
                gate_status=gate.status,
                reasons=gate.reasons,
            )
        )
    return tuple(audits)


class GraphTarget:
    def __init__(self, *, profile: Profile = "offline", ioc_client=None):
        self.profile = profile
        self.ioc_client = ioc_client

    async def analyze(self, raw: bytes, case: EvalCase) -> Observation:
        profile = case.profile or self.profile
        services, iocs = None, self.ioc_client
        if profile.startswith("fake-"):
            # Reuse GROUP 7 fakes; these are development/test assets, never provider fallbacks.
            from tests.external_fakes import fake_services

            scenario = "success" if profile == "fake-ungrounded" else profile.removeprefix("fake-")
            services, iocs = fake_services(scenario)
        if case.ioc_records:
            iocs = InMemoryIOCStore(case.ioc_records)
        provider = RecordingVerdict(
            UngroundedFixtureVerdict() if profile == "fake-ungrounded" else DeterministicVerdictProvider()
        )
        graph = build_graph(ioc_client=iocs, external_services=services, verdict_provider=provider)
        state = await graph.ainvoke({"case_id": case.id, "raw_email": raw, "evidence": [], "errors": []})
        return Observation(
            response=AnalysisResponse.from_agent_state(state),
            state=state,
            claim_audits=audit_proposals(provider.proposals, state),
        )
