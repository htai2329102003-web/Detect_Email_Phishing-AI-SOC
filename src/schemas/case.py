from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.db.types import ActionKind, ActionState, ReviewStatus
from src.evidence.models import RiskLabel
from src.schemas.analysis import AnalysisResponse, AnalysisScope


class CaseInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AnalystAssessment(CaseInput):
    label: RiskLabel
    summary: str = Field(min_length=1, max_length=4000)


class ReviewRequest(CaseInput):
    decision: Literal["APPROVE", "REJECT", "MODIFY"]
    reason: str | None = Field(default=None, min_length=1, max_length=2000)
    analyst_assessment: AnalystAssessment | None = None
    allowed_actions: list[ActionKind] = Field(default_factory=list, max_length=3)

    @model_validator(mode="after")
    def validate_decision(self):
        if self.decision == "MODIFY":
            if not self.reason or self.analyst_assessment is None:
                raise ValueError("MODIFY requires reason and analyst_assessment")
        elif self.analyst_assessment is not None or self.allowed_actions:
            raise ValueError("Analyst assessment/action restrictions belong to MODIFY")
        if len(set(self.allowed_actions)) != len(self.allowed_actions):
            raise ValueError("Duplicate allowed actions")
        return self


class ActionRequest(CaseInput):
    kind: ActionKind


class AuthorizeRequest(CaseInput):
    reason: str = Field(min_length=1, max_length=2000)


class ActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    action_id: UUID
    case_id: UUID
    kind: ActionKind
    state: ActionState
    proposed_by: UUID
    authorized_by: UUID | None
    authorization_reason: str | None
    created_at: datetime
    authorized_at: datetime | None


class CaseSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    case_id: UUID
    original_filename: str
    submitted_by: UUID
    review_status: ReviewStatus
    created_at: datetime
    updated_at: datetime
    risk_score: float
    label_candidate: RiskLabel
    assessment_label: RiskLabel
    analysis_scope: AnalysisScope
    reviewer_id: UUID | None
    reviewed_at: datetime | None


class CaseDetail(CaseSummary):
    ai_assessment: AnalysisResponse
    analyst_assessment: AnalystAssessment | None
    review_reason: str | None
    allowed_actions: list[ActionKind]
    actions: list[ActionResponse] = Field(default_factory=list)


class AuditResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    audit_id: UUID
    case_id: UUID | None
    actor_id: UUID
    event: str
    old_state: str | None
    new_state: str | None
    reason: str | None
    timestamp: datetime
    event_metadata: dict


class PersistedAnalysisResponse(AnalysisResponse):
    status: Literal["PENDING"] = "PENDING"
    review_status: Literal["PENDING"] = "PENDING"
