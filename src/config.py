from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # App
    app_name: str = "PhishHunter"
    app_env: Literal["development", "production", "test"] = "development"
    app_port: int = Field(default=8000, ge=1, le=65535)
    app_host: str = "0.0.0.0"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    cors_origins: str = "http://localhost:3000"
    header_trusted_authserv_ids: str = ""
    url_protected_domains: str = ""

    # LLM
    openai_api_key: str = ""
    model_name: str = "gpt-4o-mini"
    llm_temperature: float = Field(default=0.7, ge=0.0, le=2.0)

    # Database
    database_url: SecretStr = SecretStr("")

    # Auth: unset credentials fail closed; never generate a transient production key.
    jwt_secret: SecretStr = SecretStr("")
    jwt_access_minutes: int = Field(default=30, ge=1, le=1440)
    jwt_issuer: str = "phishhunter"
    jwt_audience: str = "phishhunter-api"

    # Integrations (optional during the architecture phase)
    virustotal_api_key: str = ""
    urlscan_api_key: str = ""
    qdrant_url: str = ""
    qdrant_collection: str = "soc_knowledge"
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"
    urlscan_base_url: str = "https://urlscan.io/api/v1"
    external_timeout_seconds: float = Field(default=5, gt=0, le=30)
    external_enrichment_enabled: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
