from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import select

from src.api.deps import Analyst, DBSession
from src.db.models import AnalysisCase, AuditLog
from src.schemas.case import (
    ActionRequest,
    ActionResponse,
    AuditResponse,
    AuthorizeRequest,
    CaseDetail,
    CaseSummary,
    ReviewRequest,
)
from src.services.cases import authorize_action, case_detail, get_case, propose_action, review_case

router = APIRouter()


@router.get("", response_model=list[CaseSummary])
def list_cases(
    user: Analyst,
    session: DBSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    return session.scalars(
        select(AnalysisCase).order_by(AnalysisCase.created_at.desc(), AnalysisCase.case_id).limit(limit).offset(offset)
    ).all()


@router.get("/{case_id}", response_model=CaseDetail)
def read_case(case_id: UUID, user: Analyst, session: DBSession):
    return case_detail(session, get_case(session, case_id))


@router.post("/{case_id}/review", response_model=CaseDetail)
def review(case_id: UUID, request: ReviewRequest, user: Analyst, session: DBSession):
    return case_detail(session, review_case(session, case_id, request, user))


@router.post("/{case_id}/actions", response_model=ActionResponse, status_code=201)
def propose(case_id: UUID, request: ActionRequest, user: Analyst, session: DBSession):
    return propose_action(session, case_id, request, user)


@router.post("/{case_id}/actions/{action_id}/authorize", response_model=ActionResponse)
def authorize(case_id: UUID, action_id: UUID, request: AuthorizeRequest, user: Analyst, session: DBSession):
    return authorize_action(session, case_id, action_id, request, user)


@router.get("/{case_id}/audit", response_model=list[AuditResponse])
def case_audit(
    case_id: UUID,
    user: Analyst,
    session: DBSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    get_case(session, case_id)
    return session.scalars(
        select(AuditLog)
        .where(AuditLog.case_id == case_id)
        .order_by(AuditLog.timestamp, AuditLog.audit_id)
        .limit(limit)
        .offset(offset)
    ).all()
