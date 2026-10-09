from enum import StrEnum

from sqlalchemy import Enum


class Role(StrEnum):
    SOC_ANALYST = "SOC_ANALYST"
    ADMIN = "ADMIN"


class ReviewStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    MODIFIED = "MODIFIED"


class ActionState(StrEnum):
    PROPOSED = "PROPOSED"
    AUTHORIZED = "AUTHORIZED"
    EXECUTED = "EXECUTED"  # Reserved; no application transition/executor in GROUP 5.


class ActionKind(StrEnum):
    QUARANTINE = "QUARANTINE"
    BLOCK_SENDER = "BLOCK_SENDER"
    DELETE_EMAIL = "DELETE_EMAIL"


def db_enum(kind):
    return Enum(
        kind,
        native_enum=False,
        create_constraint=True,
        validate_strings=True,
        values_callable=lambda members: [item.value for item in members],
        name=kind.__name__.lower(),
    )
