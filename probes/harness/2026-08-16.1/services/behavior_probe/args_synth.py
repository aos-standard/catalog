"""Deterministic MCP tool argument synthesis from inputSchema (no LLM)."""

from __future__ import annotations

from typing import Any


class SchemaError(ValueError):
    """inputSchema is unusable; caller should mark the tool not_measured."""


def synthesize_arguments(input_schema: Any) -> dict[str, Any]:
    """Fill only required properties with deterministic defaults.

    Rules:
    - required properties only
    - string → "test"; integer/number → 1; boolean → false; array → []; object → recurse
    - enum → first value; default preferred over type default
    - broken schema → SchemaError
    """
    if input_schema is None:
        return {}
    if not isinstance(input_schema, dict):
        raise SchemaError(f"inputSchema must be object, got {type(input_schema).__name__}")
    return _fill_object(input_schema)


def _fill_object(schema: dict[str, Any]) -> dict[str, Any]:
    typ = schema.get("type")
    if typ is not None and typ != "object" and "properties" not in schema:
        raise SchemaError(f"root inputSchema type is {typ!r}, not object")

    props = schema.get("properties")
    if props is None:
        props = {}
    if not isinstance(props, dict):
        raise SchemaError("properties must be an object")

    required = schema.get("required") or []
    if not isinstance(required, list):
        raise SchemaError("required must be a list")

    out: dict[str, Any] = {}
    for key in required:
        if not isinstance(key, str):
            raise SchemaError(f"required key not a string: {key!r}")
        if key not in props:
            raise SchemaError(f"required property {key!r} missing from properties")
        out[key] = _fill_value(props[key])
    return out


def _resolve_type(schema: dict[str, Any]) -> str | None:
    typ = schema.get("type")
    if isinstance(typ, list):
        concrete = [t for t in typ if t != "null"]
        return concrete[0] if concrete else "null"
    if typ is None and "properties" in schema:
        return "object"
    return typ


def _fill_value(schema: Any) -> Any:
    if not isinstance(schema, dict):
        raise SchemaError(f"property schema must be object, got {type(schema).__name__}")

    if "default" in schema:
        return schema["default"]

    if "enum" in schema:
        enum = schema["enum"]
        if not isinstance(enum, list) or not enum:
            raise SchemaError("enum must be a non-empty list")
        return enum[0]

    typ = _resolve_type(schema)
    if typ == "string" or typ is None:
        return "test"
    if typ in ("integer", "number"):
        return 1
    if typ == "boolean":
        return False
    if typ == "array":
        return []
    if typ == "object":
        return _fill_object(schema)
    if typ == "null":
        return None
    raise SchemaError(f"unsupported or broken type: {typ!r}")
