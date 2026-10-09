from typing import Literal
from uuid import UUID

from sqlalchemy import event
from sqlalchemy.orm import Session

from src.db.models.audit_log import AuditLog

AuditEvent = Literal[
    "CASE_CREATED",
    "ANALYSIS_COMPLETED",
    "REVIEW_APPROVED",
    "REVIEW_REJECTED",
    "REVIEW_MODIFIED",
    "REVIEW_DENIED",
    "ACTION_PROPOSED",
    "ACTION_AUTHORIZED",
    "ACTION_DENIED",
    "USER_CREATED",
    "USER_UPDATED",
]


def append_audit(
    session: Session,
    *,
    actor_id: UUID,
    event: AuditEvent,
    case_id: UUID | None = None,
    old_state: str | None = None,
    new_state: str | None = None,
    reason: str | None = None,
    metadata: dict | None = None,
) -> AuditLog:
    # No free-form request dumps, exception strings, passwords or tokens in metadata.
    metadata = metadata or {}
    if set(metadata) - {"action_id", "action_kind", "user_id", "role", "active", "claim_validation_status"}:
        raise ValueError("Unsupported audit metadata key")
    row = AuditLog(
        actor_id=actor_id,
        case_id=case_id,
        event=event,
        old_state=old_state,
        new_state=new_state,
        reason=reason,
        event_metadata=metadata,
    )
    session.add(row)
    return row


@event.listens_for(Session, "before_flush")
def reject_audit_mutation(session, flush_context, instances):
    if any(isinstance(row, AuditLog) for row in (*session.dirty, *session.deleted)):
        raise ValueError("AUDIT_APPEND_ONLY")


@event.listens_for(Session, "do_orm_execute")
def reject_bulk_audit_mutation(execute_state):
    if execute_state.is_update or execute_state.is_delete:
        table = getattr(execute_state.statement, "table", None)
        if table is not None and table.name == AuditLog.__tablename__:
            raise ValueError("AUDIT_APPEND_ONLY")
