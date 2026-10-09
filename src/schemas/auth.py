from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StringConstraints, field_validator

from src.db.types import Role

Email = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, to_lower=True, min_length=3, max_length=320, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
    ),
]


class AuthInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(AuthInput):
    email: Email
    password: SecretStr = Field(min_length=1, max_length=256)


class UserCreate(AuthInput):
    email: Email
    password: SecretStr = Field(min_length=12, max_length=256)
    role: Role = Role.SOC_ANALYST


class UserUpdate(AuthInput):
    role: Role | None = None
    active: bool | None = None

    @field_validator("role", "active")
    @classmethod
    def reject_explicit_null(cls, value):
        if value is None:
            raise ValueError("Omit unchanged fields instead of setting null")
        return value


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    user_id: UUID
    email: str
    role: Role
    active: bool
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
