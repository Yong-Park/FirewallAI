"""Field-level data-sensitivity metadata (ADR 0021 §5, §9).

Every model field that can leave the process (reports, exports, future AI requests) declares a
``DataClass``. v0.1 uses it for report redaction. v0.2+ uses it to gate cloud requests (SB-16).
Unclassified fields are treated as ``HOST_SENSITIVE`` (fail-safe).
"""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel

SENSITIVITY_KEY = "sensitivity"


class DataClass(StrEnum):
    """Sensitivity classes from ADR 0021 §5."""

    PUBLIC_REFERENCE = "public_reference"
    DERIVED_ABSTRACT = "derived_abstract"
    HOST_SENSITIVE = "host_sensitive"


def sensitivity(data_class: DataClass) -> dict[str, Any]:
    """Return ``json_schema_extra`` metadata marking a field's data class."""
    return {SENSITIVITY_KEY: data_class.value}


def field_sensitivity(model: type[BaseModel], field_name: str) -> DataClass:
    """Return the declared data class of ``field_name``; unclassified fields are host-sensitive."""
    info = model.model_fields[field_name]
    extra = info.json_schema_extra
    if isinstance(extra, dict):
        value = extra.get(SENSITIVITY_KEY)
        if isinstance(value, str):
            return DataClass(value)
    return DataClass.HOST_SENSITIVE


def unclassified_fields(model: type[BaseModel]) -> frozenset[str]:
    """Fields with no explicit sensitivity declaration (should be empty for domain models)."""
    result: set[str] = set()
    for name, info in model.model_fields.items():
        extra = info.json_schema_extra
        if not (isinstance(extra, dict) and isinstance(extra.get(SENSITIVITY_KEY), str)):
            result.add(name)
    return frozenset(result)


def fields_of_class(model: type[BaseModel], data_class: DataClass) -> frozenset[str]:
    """All fields of ``model`` whose (effective) data class is ``data_class``."""
    return frozenset(
        name for name in model.model_fields if field_sensitivity(model, name) is data_class
    )
