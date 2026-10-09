from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, Float, ForeignKey, String, Text, Uuid, event, inspect
from sqlalchemy.orm import Mapped, mapped_column

from src.db.base import JSON_DOCUMENT, Base, UTCDateTime, utcnow
from src.db.types import ReviewStatus, db_enum


class AnalysisCase(Base):
    __tablename__ = "analysis_cases"
    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="risk_range"),
        CheckConstraint(
            "(review_status = 'PENDING' AND reviewer_id IS NULL AND reviewed_at IS NULL) OR "
            "(review_status <> 'PENDING' AND reviewer_id IS NOT NULL AND reviewed_at IS NOT NULL)",
            name="review_identity",
        ),
        CheckConstraint(
            "review_status <> 'MODIFIED' OR "
            "(analyst_assessment IS NOT NULL AND review_reason IS NOT NULL AND length(trim(review_reason)) > 0)",
            name="modified_reason",
        ),
    )

    case_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    submitted_by: Mapped[UUID] = mapped_column(ForeignKey("users.user_id"), nullable=False)
    ai_assessment: Mapped[dict] = mapped_column(JSON_DOCUMENT, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    label_candidate: Mapped[str] = mapped_column(String(32), nullable=False)
    assessment_label: Mapped[str] = mapped_column(String(32), nullable=False)
    analysis_scope: Mapped[str] = mapped_column(String(32), nullable=False)
    review_status: Mapped[ReviewStatus] = mapped_column(db_enum(ReviewStatus), default=ReviewStatus.PENDING, index=True)
    analyst_assessment: Mapped[dict | None] = mapped_column(JSON_DOCUMENT, nullable=True)
    review_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewer_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.user_id"), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    allowed_actions: Mapped[list] = mapped_column(JSON_DOCUMENT, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)


@event.listens_for(AnalysisCase, "before_update")
def protect_ai_snapshot(mapper, connection, case):
    immutable = (
        "case_id",
        "original_filename",
        "submitted_by",
        "ai_assessment",
        "risk_score",
        "label_candidate",
        "assessment_label",
        "analysis_scope",
        "created_at",
    )
    if any(inspect(case).attrs[field].history.has_changes() for field in immutable):
        raise ValueError("AI_ASSESSMENT_IMMUTABLE")
