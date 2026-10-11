from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
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
    langfuse_enabled: bool = False
    langfuse_base_url: str = "https://cloud.langfuse.com"
    langfuse_public_key: SecretStr = SecretStr("")
    langfuse_secret_key: SecretStr = SecretStr("")
    langfuse_timeout_seconds: float = Field(default=2, gt=0, le=10)
    cors_origins: str = "http://localhost:3000"
    header_trusted_authserv_ids: str = ""
    url_protected_domains: str = ""
    ioc_data_path: str = "data/ioc/ioc_normalized.jsonl"
    ioc_index_path: str = "runtime/ioc.sqlite3"

    # LLM
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    model_name: str = "gpt-4o-mini"
    llm_temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    llm_timeout_seconds: float = Field(default=30, gt=0, le=120)
    content_bec_enabled: bool = False
    verdict_llm_enabled: bool = False

    # Database
    database_url: SecretStr = SecretStr("")

    # Auth: unset credentials fail closed; never generate a transient production key.
    jwt_secret: SecretStr = SecretStr("")
    jwt_access_minutes: int = Field(default=30, ge=1, le=1440)
    jwt_issuer: str = "phishhunter"
    jwt_audience: str = "phishhunter-api"

    # Integrations (optional during the architecture phase)
    virustotal_api_key: str = ""
    virustotal_enabled: bool = False
    virustotal_timeout_seconds: float = Field(default=5, gt=0, le=30)
    virustotal_cache_ttl_seconds: float = Field(default=3600, ge=0, le=86400)
    virustotal_min_interval_seconds: float = Field(default=15, ge=0, le=3600)
    urlscan_api_key: str = ""
    urlscan_enabled: bool = False
    urlscan_timeout_seconds: float = Field(default=5, gt=0, le=30)
    urlscan_cache_ttl_seconds: float = Field(default=3600, ge=0, le=86400)
    urlscan_min_interval_seconds: float = Field(default=10, ge=0, le=3600)
    enrichment_max_urls: int = Field(default=2, ge=1, le=64)
    enrichment_max_hashes: int = Field(default=2, ge=1, le=64)
    qdrant_url: str = ""
    qdrant_collection: str = "soc_knowledge"
    qdrant_api_key: SecretStr = SecretStr("")
    rag_enabled: bool = False
    rag_documents_path: str = "data/rag/documents.jsonl"
    rag_chunks_path: str = "data/rag/chunks.jsonl"
    rag_top_k: int = Field(default=5, ge=1, le=10)
    rag_score_threshold: float = Field(default=0.5, ge=0, le=1)
    embedding_base_url: str = ""
    embedding_api_key: SecretStr = SecretStr("")
    embedding_model: str = ""
    embedding_dimension: int | None = Field(default=None, ge=1, le=65536)
    embedding_batch_size: int = Field(default=32, ge=1, le=128)
    embedding_timeout_seconds: float = Field(default=30, gt=0, le=120)
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"
    urlscan_base_url: str = "https://urlscan.io/api/v1"
    external_timeout_seconds: float = Field(default=5, gt=0, le=30)
    external_enrichment_enabled: bool = False

    @field_validator("embedding_dimension", mode="before")
    @classmethod
    def optional_embedding_dimension(cls, value):
        return None if value == "" else value


@lru_cache
def get_settings() -> Settings:
    return Settings()
