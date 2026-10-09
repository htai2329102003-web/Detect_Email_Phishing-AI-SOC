from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.db.base import utcnow
from src.db.models import AnalysisCase, CaseAction, User
from src.db.types import ActionState, ReviewStatus
from src.schemas.analysis import AnalysisResponse
from src.schemas.case import ActionRequest, ActionResponse, AuthorizeRequest, CaseDetail, ReviewRequest
from src.services.audit import append_audit


def get_case(session: Session, case_id: UUID) -> AnalysisCase:
    case = session.get(AnalysisCase, case_id)
    if case is None:
        raise HTTPException(404, detail={"code": "CASE_NOT_FOUND"})
    return case


def case_detail(session: Session, case: AnalysisCase) -> CaseDetail:
    result = CaseDetail.model_validate(case)
    actions = session.scalars(
        select(CaseAction)
        .where(CaseAction.case_id == case.case_id)
        .order_by(CaseAction.created_at, CaseAction.action_id)
    ).all()
    return result.model_copy(update={"actions": [ActionResponse.model_validate(action) for action in actions]})


def persist_analysis(session: Session, result: AnalysisResponse, filename: str, actor: User) -> AnalysisCase:
    # Persist only the bounded public result; no raw email/attachment payloads.
    case = AnalysisCase(
        case_id=UUID(result.case_id),
        original_filename=filename,
        submitted_by=actor.user_id,
        ai_assessment=result.model_dump(mode="json"),
        risk_score=result.score,
        label_candidate=result.label_candidate,
        assessment_label=result.assessment_label,
        analysis_scope=result.analysis_scope,
        review_status=ReviewStatus.PENDING,
    )
    session.add(case)
    session.flush()
    append_audit(session, actor_id=actor.user_id, case_id=case.case_id, event="CASE_CREATED", new_state="PENDING")
    append_audit(
        session,
        actor_id=actor.user_id,
        case_id=case.case_id,
        event="ANALYSIS_COMPLETED",
        old_state="PENDING",
        new_state="PENDING",
        metadata={"claim_validation_status": result.claim_validation_status},
    )
    session.commit()  # Case and both audit records are one transaction.
    return case


def review_case(session: Session, case_id: UUID, request: ReviewRequest, actor: User) -> AnalysisCase:
    case = get_case(session, case_id)
    status = {"APPROVE": ReviewStatus.APPROVED, "REJECT": ReviewStatus.REJECTED, "MODIFY": ReviewStatus.MODIFIED}[
        request.decision
    ]
    now = utcnow()
    # Compare-and-set prevents two reviewers from finalizing the same PENDING case.
    changed = session.execute(
        update(AnalysisCase)
        .where(AnalysisCase.case_id == case_id, AnalysisCase.review_status == ReviewStatus.PENDING)
        .values(
            review_status=status,
            reviewer_id=actor.user_id,
            reviewed_at=now,
            updated_at=now,
            review_reason=request.reason,
            analyst_assessment=request.analyst_assessment.model_dump(mode="json")
            if request.analyst_assessment
            else None,
            allowed_actions=[item.value for item in request.allowed_actions],
        )
        .execution_options(synchronize_session=False)
    ).rowcount
    if changed != 1:
        session.refresh(case)
        append_audit(
            session,
            actor_id=actor.user_id,
            case_id=case_id,
            event="REVIEW_DENIED",
            old_state=case.review_status.value,
            new_state=case.review_status.value,
            reason="CASE_ALREADY_FINAL",
        )
        session.commit()
        raise HTTPException(409, detail={"code": "CASE_ALREADY_FINAL"})
    append_audit(
        session,
        actor_id=actor.user_id,
        case_id=case_id,
        event=f"REVIEW_{status.value}",
        old_state="PENDING",
        new_state=status.value,
        reason=request.reason,
    )
    session.commit()
    session.refresh(case)
    return case


def propose_action(session: Session, case_id: UUID, request: ActionRequest, actor: User) -> CaseAction:
    get_case(session, case_id)
    action = CaseAction(case_id=case_id, kind=request.kind, proposed_by=actor.user_id)
    session.add(action)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(409, detail={"code": "ACTION_ALREADY_PROPOSED"}) from None
    append_audit(
        session,
        actor_id=actor.user_id,
        case_id=case_id,
        event="ACTION_PROPOSED",
        new_state="PROPOSED",
        metadata={"action_id": str(action.action_id), "action_kind": action.kind.value},
    )
    session.commit()
    return action


def authorize_action(
    session: Session, case_id: UUID, action_id: UUID, request: AuthorizeRequest, actor: User
) -> CaseAction:
    case = get_case(session, case_id)
    action = session.scalar(
        select(CaseAction).where(CaseAction.case_id == case_id, CaseAction.action_id == action_id).with_for_update()
    )
    if action is None:
        raise HTTPException(404, detail={"code": "ACTION_NOT_FOUND"})
    allowed = case.review_status == ReviewStatus.APPROVED or (
        case.review_status == ReviewStatus.MODIFIED and action.kind.value in case.allowed_actions
    )
    if not allowed or action.state != ActionState.PROPOSED:
        append_audit(
            session,
            actor_id=actor.user_id,
            case_id=case_id,
            event="ACTION_DENIED",
            old_state=action.state.value,
            new_state=action.state.value,
            reason="REVIEW_NOT_AUTHORIZING_ACTION" if not allowed else "ACTION_NOT_PROPOSED",
            metadata={"action_id": str(action_id), "action_kind": action.kind.value},
        )
        session.commit()  # The denial must survive the HTTP error.
        raise HTTPException(409, detail={"code": "ACTION_DENIED"})
    # Row lock serializes authorization; final review decisions cannot be reopened.
    action.state = ActionState.AUTHORIZED
    action.authorized_by = actor.user_id
    action.authorized_at = utcnow()
    action.authorization_reason = request.reason
    append_audit(
        session,
        actor_id=actor.user_id,
        case_id=case_id,
        event="ACTION_AUTHORIZED",
        old_state="PROPOSED",
        new_state="AUTHORIZED",
        reason=request.reason,
        metadata={"action_id": str(action_id), "action_kind": action.kind.value},
    )
    session.commit()
    return action
