from typing import Annotated

from fastapi import APIRouter, Depends

from src.api.deps import DBSession, get_current_user
from src.config import Settings, get_settings
from src.db.models.user import User
from src.schemas.auth import LoginRequest, TokenResponse, UserResponse
from src.services.auth import authenticate, issue_token, jwt_key

router = APIRouter()


@router.get("/status")
def auth_status() -> dict[str, str]:
    return {"status": "implemented", "scheme": "bearer"}


@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest, session: DBSession, settings: Annotated[Settings, Depends(get_settings)]):
    jwt_key(settings)  # Fail closed if the operator has not provisioned a persistent key.
    user = authenticate(session, request.email, request.password.get_secret_value())
    return TokenResponse(access_token=issue_token(user, settings), expires_in=settings.jwt_access_minutes * 60)


@router.get("/me", response_model=UserResponse)
def me(user: Annotated[User, Depends(get_current_user)]):
    return user
