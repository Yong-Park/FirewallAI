"""Structured collection results: data, structured errors, or partial data. Never silent failure."""

from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from firewallai.core.sensitivity import DataClass, sensitivity

_ABSTRACT = sensitivity(DataClass.DERIVED_ABSTRACT)


class CollectorErrorCode(StrEnum):
    ACCESS_DENIED = "access_denied"
    NOT_FOUND = "not_found"
    TIMEOUT = "timeout"
    OUTPUT_TOO_LARGE = "output_too_large"
    PARSE_ERROR = "parse_error"
    INVALID_VALUE = "invalid_value"
    EXECUTION_FAILED = "execution_failed"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    CANCELLED = "cancelled"
    BUSY = "busy"  # another heavy firewall query is already running (single-flight)


class CollectorError(BaseModel):
    """A structured, non-localized error.

    ``detail`` holds stable technical identifiers only (error category, error id, field name, enum
    value). It never holds OS-localized message text or raw host data.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: CollectorErrorCode = Field(json_schema_extra=_ABSTRACT)
    source: str = Field(min_length=1, max_length=100, json_schema_extra=_ABSTRACT)
    detail: str = Field(default="", max_length=300, json_schema_extra=_ABSTRACT)


class CollectorResult[T](BaseModel):
    """Either data, or errors, or partial data with errors."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    data: T | None = Field(default=None, json_schema_extra=_ABSTRACT)
    errors: tuple[CollectorError, ...] = Field(default=(), json_schema_extra=_ABSTRACT)
    partial: bool = Field(default=False, json_schema_extra=_ABSTRACT)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.data is None and not self.errors:
            raise ValueError("a result without data must carry at least one error")
        if self.partial and (self.data is None or not self.errors):
            raise ValueError("a partial result needs both data and errors")
        if self.data is not None and self.errors and not self.partial:
            raise ValueError("a result with data and errors must be marked partial")
        return self

    @property
    def ok(self) -> bool:
        return self.data is not None and not self.errors
