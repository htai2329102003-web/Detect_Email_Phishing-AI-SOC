"""GROUP 5: users, immutable AI cases, action proposals and append-only audit."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_group5"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Initial schema snapshot, independent of future ORM changes.
    op.create_table(
        "users",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column(
            "role",
            sa.Enum("SOC_ANALYST", "ADMIN", name="role", native_enum=False, create_constraint=True),
            nullable=False,
        ),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("user_id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
    )
    op.create_table(
        "analysis_cases",
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("original_filename", sa.String(length=255), nullable=False),
        sa.Column("submitted_by", sa.Uuid(), nullable=False),
        sa.Column(
            "ai_assessment",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("label_candidate", sa.String(length=32), nullable=False),
        sa.Column("assessment_label", sa.String(length=32), nullable=False),
        sa.Column("analysis_scope", sa.String(length=32), nullable=False),
        sa.Column(
            "review_status",
            sa.Enum(
                "PENDING",
                "APPROVED",
                "REJECTED",
                "MODIFIED",
                name="reviewstatus",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "analyst_assessment",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("review_reason", sa.Text(), nullable=True),
        sa.Column("reviewer_id", sa.Uuid(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "allowed_actions",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "(review_status = 'PENDING' AND reviewer_id IS NULL AND reviewed_at IS NULL) OR (review_status <> 'PENDING' AND reviewer_id IS NOT NULL AND reviewed_at IS NOT NULL)",
            name=op.f("ck_analysis_cases_review_identity"),
        ),
        sa.CheckConstraint(
            "review_status <> 'MODIFIED' OR (analyst_assessment IS NOT NULL AND review_reason IS NOT NULL AND length(trim(review_reason)) > 0)",
            name=op.f("ck_analysis_cases_modified_reason"),
        ),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name=op.f("ck_analysis_cases_risk_range")),
        sa.ForeignKeyConstraint(["reviewer_id"], ["users.user_id"], name=op.f("fk_analysis_cases_reviewer_id_users")),
        sa.ForeignKeyConstraint(["submitted_by"], ["users.user_id"], name=op.f("fk_analysis_cases_submitted_by_users")),
        sa.PrimaryKeyConstraint("case_id", name=op.f("pk_analysis_cases")),
    )
    op.create_index(op.f("ix_analysis_cases_created_at"), "analysis_cases", ["created_at"], unique=False)
    op.create_index(op.f("ix_analysis_cases_review_status"), "analysis_cases", ["review_status"], unique=False)
    op.create_table(
        "audit_logs",
        sa.Column("audit_id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=True),
        sa.Column("actor_id", sa.Uuid(), nullable=False),
        sa.Column("event", sa.String(length=64), nullable=False),
        sa.Column("old_state", sa.String(length=32), nullable=True),
        sa.Column("new_state", sa.String(length=32), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "event_metadata",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["actor_id"], ["users.user_id"], name=op.f("fk_audit_logs_actor_id_users")),
        sa.ForeignKeyConstraint(
            ["case_id"], ["analysis_cases.case_id"], name=op.f("fk_audit_logs_case_id_analysis_cases")
        ),
        sa.PrimaryKeyConstraint("audit_id", name=op.f("pk_audit_logs")),
    )
    op.create_index(op.f("ix_audit_logs_case_id"), "audit_logs", ["case_id"], unique=False)
    op.create_index(op.f("ix_audit_logs_timestamp"), "audit_logs", ["timestamp"], unique=False)
    op.create_table(
        "case_actions",
        sa.Column("action_id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column(
            "kind",
            sa.Enum(
                "QUARANTINE",
                "BLOCK_SENDER",
                "DELETE_EMAIL",
                name="actionkind",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "state",
            sa.Enum(
                "PROPOSED", "AUTHORIZED", "EXECUTED", name="actionstate", native_enum=False, create_constraint=True
            ),
            nullable=False,
        ),
        sa.Column("proposed_by", sa.Uuid(), nullable=False),
        sa.Column("authorized_by", sa.Uuid(), nullable=True),
        sa.Column("authorization_reason", sa.String(length=2000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(state = 'PROPOSED' AND authorized_by IS NULL AND authorized_at IS NULL) OR (state IN ('AUTHORIZED', 'EXECUTED') AND authorized_by IS NOT NULL AND authorized_at IS NOT NULL)",
            name=op.f("ck_case_actions_authorization_identity"),
        ),
        sa.ForeignKeyConstraint(["authorized_by"], ["users.user_id"], name=op.f("fk_case_actions_authorized_by_users")),
        sa.ForeignKeyConstraint(
            ["case_id"], ["analysis_cases.case_id"], name=op.f("fk_case_actions_case_id_analysis_cases")
        ),
        sa.ForeignKeyConstraint(["proposed_by"], ["users.user_id"], name=op.f("fk_case_actions_proposed_by_users")),
        sa.PrimaryKeyConstraint("action_id", name=op.f("pk_case_actions")),
        sa.UniqueConstraint("case_id", "kind", name=op.f("uq_case_actions_case_id")),
    )
    op.create_index(op.f("ix_case_actions_case_id"), "case_actions", ["case_id"], unique=False)


def downgrade():
    raise RuntimeError("Destructive downgrade is intentionally disabled; use a reviewed backup/restore plan")
