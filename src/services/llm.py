"""Single LLM module: structured model injection; missing configuration never returns fake output."""

from typing import Protocol, TypeVar
from urllib.parse import urlsplit

import httpx
from langchain_openai import ChatOpenAI
from openai import APIStatusError, APITimeoutError, OpenAI
from pydantic import BaseModel

from src.config import get_settings
from src.schemas.tool import ToolResult
from src.services.external import ProviderHTTPError, controlled_call

T = TypeVar("T", bound=BaseModel)


class StructuredModel(Protocol):
    def generate(self, messages: tuple[dict[str, str], ...], schema: type[BaseModel], *, timeout: float) -> object: ...


class LLMClient:
    """A real structured provider adapter can be supplied explicitly; GROUP 7 makes no LLM calls."""

    def __init__(self, model: StructuredModel | None = None, *, timeout: float = 10):
        self.model, self.timeout = model, timeout

    @classmethod
    def from_settings(cls, settings):
        model = ConfiguredStructuredModel(settings) if settings.openai_api_key else None
        return cls(model, timeout=settings.llm_timeout_seconds)

    def classify(self, messages: tuple[dict[str, str], ...], schema: type[T]) -> ToolResult[T]:
        def generate():
            output = self.model.generate(messages, schema, timeout=self.timeout)
            return schema.model_validate(output.model_dump() if isinstance(output, BaseModel) else output)

        return controlled_call("LLM", generate, configured=self.model is not None)


class ConfiguredStructuredModel:
    """Real OpenAI-compatible structured generation, no tools or automatic retries."""

    def __init__(self, settings):
        self.settings = settings
        self.call_count = 0

    def generate(self, messages, schema, *, timeout):
        parts = urlsplit(self.settings.openai_base_url)
        if (not parts.hostname or parts.username or parts.password or parts.query or parts.fragment
                or (parts.scheme != "https" and not (
                    parts.scheme == "http" and parts.hostname in {"localhost", "127.0.0.1", "::1"}))):
            raise ValueError("Invalid LLM provider URL")
        with OpenAI(api_key=self.settings.openai_api_key, base_url=self.settings.openai_base_url,
                    max_retries=0, timeout=timeout,
                    http_client=httpx.Client(trust_env=False, follow_redirects=False, timeout=timeout)) as client:
            self.call_count += 1
            try:
                completion = client.chat.completions.parse(
                    model=self.settings.model_name, messages=list(messages), response_format=schema,
                    temperature=0, max_tokens=2400, timeout=timeout,
                )
            except APITimeoutError as exc:
                raise TimeoutError("LLM timeout") from exc
            except APIStatusError as exc:
                raise ProviderHTTPError(exc.status_code) from exc
        message = completion.choices[0].message
        if message.refusal or message.parsed is None:
            raise ValueError("LLM refused or returned no structured output")
        return message.parsed


def get_llm() -> ChatOpenAI:
    settings = get_settings()
    if not settings.openai_api_key:
        raise ValueError("LLM_NOT_CONFIGURED")
    return ChatOpenAI(
        model=settings.model_name,
        base_url=settings.openai_base_url,
        api_key=settings.openai_api_key,
        temperature=settings.llm_temperature,
    )
