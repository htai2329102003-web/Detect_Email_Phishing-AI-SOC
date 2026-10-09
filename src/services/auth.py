from datetime import timedelta
from uuid import UUID, uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.config import Settings
from src.db.base import utcnow
from src.db.models.user import User
from src.schemas.auth import UserCreate

PASSWORDS = PasswordHasher()  # argon2-cffi defaults: Argon2id, random salt.


def hash_password(password: str) -> str:
    return PASSWORDS.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return PASSWORDS.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


# A fresh random dummy hash equalizes the missing-user password verification path.
_DUMMY_HASH = hash_password(str(uuid4()))


def jwt_key(settings: Settings) -> str:
    key = settings.jwt_secret.get_secret_value()
    if len(key.encode("utf-8")) < 32:
        raise HTTPException(503, detail={"code": "AUTH_NOT_CONFIGURED"})
    return key


def issue_token(user: User, settings: Settings) -> str:
    now = utcnow()
    return jwt.encode(
        {
            "sub": str(user.user_id),
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=settings.jwt_access_minutes),
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "jti": str(uuid4()),
            "type": "access",
        },
        jwt_key(settings),
        algorithm="HS256",
    )


def decode_token(token: str, settings: Settings) -> UUID:
    key = jwt_key(settings)
    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=["HS256"],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["sub", "exp", "iat", "nbf", "iss", "aud", "jti", "type"]},
        )
        if payload["type"] != "access":
            raise ValueError("Wrong token type")
        return UUID(payload["sub"])
    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise HTTPException(401, detail={"code": "INVALID_TOKEN"}, headers={"WWW-Authenticate": "Bearer"}) from None


def authenticate(session: Session, email: str, password: str) -> User:
    user = session.scalar(select(User).where(User.email == email))
    valid = verify_password(password, user.password_hash if user else _DUMMY_HASH)
    if not valid or user is None or not user.active:
        raise HTTPException(401, detail={"code": "INVALID_CREDENTIALS"}, headers={"WWW-Authenticate": "Bearer"})
    if PASSWORDS.check_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        session.commit()
    return user


def create_user(session: Session, request: UserCreate) -> User:
    user = User(
        email=request.email, password_hash=hash_password(request.password.get_secret_value()), role=request.role
    )
    session.add(user)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(409, detail={"code": "USER_ALREADY_EXISTS"}) from None
    return user
