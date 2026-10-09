from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from src.api.routers import api_router
from src.config import get_settings

settings = get_settings()
app = FastAPI(
    title=settings.app_name,
    description="Phishing email analysis and SOC case triage API",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")


@app.exception_handler(SQLAlchemyError)
async def database_error(request, exc):
    # No connection URL, SQL parameters or driver messages in the public response.
    return JSONResponse(status_code=503, content={"detail": {"code": "DATABASE_UNAVAILABLE"}})


@app.exception_handler(RequestValidationError)
async def request_validation_error(request, exc):
    # FastAPI's default error input can echo submitted passwords or bearer tokens.
    details = [{key: item[key] for key in ("loc", "msg", "type")} for item in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": details})
