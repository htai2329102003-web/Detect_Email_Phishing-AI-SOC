"""Local operator bootstrap: python -m scripts.create_admin --email admin@example.test."""

import argparse
from getpass import getpass

from sqlalchemy import select

from src.db.models import User
from src.db.session import get_session_factory
from src.db.types import Role
from src.schemas.auth import UserCreate
from src.services.audit import append_audit
from src.services.auth import create_user


def main():
    parser = argparse.ArgumentParser(description="Bootstrap the first active admin after migrations")
    parser.add_argument("--email", required=True)
    args = parser.parse_args()
    with get_session_factory()() as session:
        if session.scalar(select(User).where(User.role == Role.ADMIN, User.active.is_(True)).limit(1)):
            parser.error("An active admin exists; use authenticated admin user management")
        password = getpass("New admin password (at least 12 characters): ")
        if getpass("Confirm password: ") != password:
            parser.error("Password confirmation differs")
        user = create_user(session, UserCreate(email=args.email, password=password, role=Role.ADMIN))
        append_audit(
            session,
            actor_id=user.user_id,
            event="USER_CREATED",
            new_state="ADMIN",
            metadata={"user_id": str(user.user_id), "role": "ADMIN"},
        )
        session.commit()
        print("Initial admin created")


if __name__ == "__main__":
    main()
