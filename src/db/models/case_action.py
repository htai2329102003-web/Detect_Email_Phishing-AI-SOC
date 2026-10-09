from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, ForeignKey, String, UniqueConstraint, Uuid, event
from sqlalchemy.orm import Mapped, mapped_column

from src.db.base import Base, UTCDateTime, utcnow
from src.db.types import ActionKind, ActionState, db_enum


class CaseAction(Base):
    __tablename__ = "case_actions"
    __table_args__ = (
        UniqueConstraint("case_id", "kind"),
        CheckConstraint(
            "(state = 'PROPOSED' AND authorized_by IS NULL AND authorized_at IS NULL) OR "
            "(state IN ('AUTHORIZED', 'EXECUTED') AND authorized_by IS NOT NULL AND authorized_at IS NOT NULL)",
            name="authorization_identity",
        ),
    )

    action_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    case_id: Mapped[UUID] = mapped_column(ForeignKey("analysis_cases.case_id"), nullable=False, index=True)
    kind: Mapped[ActionKind] = mapped_column(db_enum(ActionKind), nullable=False)
    state: Mapped[ActionState] = mapped_column(db_enum(ActionState), default=ActionState.PROPOSED, nullable=False)
    proposed_by: Mapped[UUID] = mapped_column(ForeignKey("users.user_id"), nullable=False)
    authorized_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.user_id"), nullable=True)
    authorization_reason: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    authorized_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


@event.listens_for(CaseAction, "before_update")
@event.listens_for(CaseAction, "before_insert")
def prevent_execution(mapper, connection, action):
    if action.state == ActionState.EXECUTED:
        raise ValueError("ACTION_EXECUTION_DISABLED")
