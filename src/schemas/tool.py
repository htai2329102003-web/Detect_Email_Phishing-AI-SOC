from typing import Generic, TypeVar

from pydantic import Field, model_validator

from src.evidence.models import Contract, NonEmpty, ToolStatus

T = TypeVar("T")


class ToolResult(Contract, Generic[T]):
    """Transport-neutral result. A failed lookup cannot be interpreted as clean."""

    status: ToolStatus
    data: T | None = None
    error_code: NonEmpty | None = None
    error_message: NonEmpty | None = None
    latency_ms: float = Field(ge=0.0)

    @model_validator(mode="after")
    def check_status(self):
        if self.status != "OK" and self.data is not None:
            raise ValueError("Failed tools cannot return success data")
        if self.status == "OK" and (self.error_code is not None or self.error_message is not None):
            raise ValueError("Successful tools cannot carry an error")
        return self
