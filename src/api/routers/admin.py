from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from src.api.deps import Admin, DBSession
from src.db.models import AuditLog, User
from src.schemas.auth import UserCreate, UserResponse, UserUpdate
from src.schemas.case import AuditResponse
from src.services.audit import append_audit
from src.services.auth import create_user

router = APIRouter()


@router.post("/users", response_model=UserResponse, status_code=201)
def add_user(request: UserCreate, actor: Admin, session: DBSession):
    user = create_user(session, request)
    append_audit(
        session,
        actor_id=actor.user_id,
        event="USER_CREATED",
        new_state=user.role.value,
        metadata={"user_id": str(user.user_id), "role": user.role.value},
    )
    session.commit()
    return user


@router.get("/users", response_model=list[UserResponse])
def users(
    actor: Admin,
    session: DBSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    return session.scalars(select(User).order_by(User.created_at, User.user_id).limit(limit).offset(offset)).all()


@router.patch("/users/{user_id}", response_model=UserResponse)
def change_user(user_id: UUID, request: UserUpdate, actor: Admin, session: DBSession):
    if user_id == actor.user_id and (
        request.active is False or request.role is not None and request.role != actor.role
    ):
        raise HTTPException(409, detail={"code": "CANNOT_DISABLE_OWN_ADMIN_ACCESS"})
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(404, detail={"code": "USER_NOT_FOUND"})
    old_role = user.role.value
    for field, value in request.model_dump(exclude_unset=True).items():
        setattr(user, field, value)
    append_audit(
        session,
        actor_id=actor.user_id,
        event="USER_UPDATED",
        old_state=old_role,
        new_state=user.role.value,
        metadata={"user_id": str(user_id), "role": user.role.value, "active": user.active},
    )
    session.commit()
    return user


@router.get("/audit", response_model=list[AuditResponse])
def audit(
    actor: Admin,
    session: DBSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    return session.scalars(
        select(AuditLog).order_by(AuditLog.timestamp.desc(), AuditLog.audit_id).limit(limit).offset(offset)
    ).all()
