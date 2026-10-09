"""Single LLM module: structured model injection; missing configuration never returns fake output."""

from typing import Protocol, TypeVar

from langchain_openai import ChatOpenAI
from pydantic import BaseModel

from src.config import get_settings
from src.schemas.tool import ToolResult
from src.services.external import controlled_call

T = TypeVar("T", bound=BaseModel)


class StructuredModel(Protocol):
    def generate(self, messages: tuple[dict[str, str], ...], schema: type[BaseModel], *, timeout: float) -> object: ...


class LLMClient:
    """A real structured provider adapter can be supplied explicitly; GROUP 7 makes no LLM calls."""

    def __init__(self, model: StructuredModel | None = None, *, timeout: float = 10):
        self.model, self.timeout = model, timeout

    def classify(self, messages: tuple[dict[str, str], ...], schema: type[T]) -> ToolResult[T]:
        def generate():
            output = self.model.generate(messages, schema, timeout=self.timeout)
            return schema.model_validate(output.model_dump() if isinstance(output, BaseModel) else output)

        return controlled_call("LLM", generate, configured=self.model is not None)


def get_llm() -> ChatOpenAI:
    settings = get_settings()
    if not settings.openai_api_key:
        raise ValueError("LLM_NOT_CONFIGURED")
    return ChatOpenAI(
        model=settings.model_name,
        api_key=settings.openai_api_key,
        temperature=settings.llm_temperature,
    )
