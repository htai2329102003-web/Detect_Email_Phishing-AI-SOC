import asyncio
import logging
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from src.api.routers import api_router
from src.config import get_settings
from src.services.observability import LOGGER, LangfuseExporter, OperationalMiddleware

settings = get_settings()


@asynccontextmanager
async def lifespan(application):
    LOGGER.setLevel(settings.log_level)
    for name in ("httpx", "httpcore", "openai"):
        logging.getLogger(name).setLevel(logging.WARNING)
    exporter = LangfuseExporter(settings)
    application.state.telemetry_exporter = exporter
    worker = asyncio.create_task(exporter.worker()) if exporter.enabled else None
    try:
        yield
    finally:
        if worker:
            with suppress(TimeoutError):
                await asyncio.wait_for(exporter.queue.join(), timeout=3)
            worker.cancel()
            with suppress(asyncio.CancelledError):
                await worker


app = FastAPI(
    title=settings.app_name,
    description="Phishing email analysis and SOC case triage API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")
app.add_middleware(OperationalMiddleware)
# Kubernetes/container concepts at root; retain the existing API health route.
from src.api.routers.health import health_check, readiness_check  # noqa: E402

app.add_api_route("/healthz", health_check, tags=["health"])
app.add_api_route("/readyz", readiness_check, tags=["health"])


@app.exception_handler(SQLAlchemyError)
async def database_error(request, exc):
    # No connection URL, SQL parameters or driver messages in the public response.
    return JSONResponse(status_code=503, content={"detail": {"code": "DATABASE_UNAVAILABLE"}})


@app.exception_handler(RequestValidationError)
async def request_validation_error(request, exc):
    # FastAPI's default error input can echo submitted passwords or bearer tokens.
    details = [{key: item[key] for key in ("loc", "msg", "type")} for item in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": details})
