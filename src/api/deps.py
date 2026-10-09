from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from src.config import Settings, get_settings
from src.db.models.user import User
from src.db.session import get_session
from src.db.types import Role
from src.services.auth import decode_token

bearer = HTTPBearer(auto_error=False)
DBSession = Annotated[Session, Depends(get_session)]


def token_subject(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> UUID:
    if credentials is None:
        raise HTTPException(401, detail={"code": "AUTHENTICATION_REQUIRED"}, headers={"WWW-Authenticate": "Bearer"})
    return decode_token(credentials.credentials, settings)


def get_current_user(subject: Annotated[UUID, Depends(token_subject)], session: DBSession) -> User:
    user = session.get(User, subject)
    if user is None or not user.active:
        raise HTTPException(401, detail={"code": "INVALID_TOKEN"}, headers={"WWW-Authenticate": "Bearer"})
    return user


def require_roles(*roles: Role):
    def dependency(user: Annotated[User, Depends(get_current_user)]) -> User:
        # Current DB role, not a stale/untrusted JWT role claim.
        if user.role not in roles:
            raise HTTPException(403, detail={"code": "FORBIDDEN"})
        return user

    return dependency


Analyst = Annotated[User, Depends(require_roles(Role.SOC_ANALYST, Role.ADMIN))]
Admin = Annotated[User, Depends(require_roles(Role.ADMIN))]
