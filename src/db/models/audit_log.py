from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from src.db.base import JSON_DOCUMENT, Base, UTCDateTime, utcnow


class AuditLog(Base):
    __tablename__ = "audit_logs"

    audit_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    case_id: Mapped[UUID | None] = mapped_column(ForeignKey("analysis_cases.case_id"), nullable=True, index=True)
    actor_id: Mapped[UUID] = mapped_column(ForeignKey("users.user_id"), nullable=False)
    event: Mapped[str] = mapped_column(String(64), nullable=False)
    old_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    new_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False, index=True)
    event_metadata: Mapped[dict] = mapped_column(JSON_DOCUMENT, default=dict, nullable=False)
