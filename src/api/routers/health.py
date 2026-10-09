from fastapi import APIRouter

from src.config import get_settings

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Return a lightweight liveness response."""
    settings = get_settings()
    return {"status": "ok", "service": settings.app_name, "env": settings.app_env}
