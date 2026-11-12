"""Message format of netplay: JSON objects with a size limit and validation. No pickle anywhere.

A message is a dict with a string "t" (type) and JSON-compatible values only. Encoding refuses
anything else; decoding refuses oversized data, non-objects, NaN/Infinity and nesting deeper than MAX_DEPTH.
"""
from __future__ import annotations

import json
from typing import Any

MAX_MESSAGE = 256 * 1024  # bytes after encoding
MAX_DEPTH = 32

Message = dict[str, Any]


class WireError(ValueError):
    """A message is too large, malformed or not allowed."""


def _reject_constant(name: str) -> Any:
    raise WireError(f"non-finite number {name} not allowed")


def _check_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise WireError("message nested too deeply")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise WireError("object keys must be strings")
            _check_depth(v, depth + 1)
    elif isinstance(value, list):
        for v in value:
            _check_depth(v, depth + 1)


def encode(message: Message, limit: int = MAX_MESSAGE) -> bytes:
    if not isinstance(message, dict) or not isinstance(message.get("t"), str):
        raise WireError('a message must be a dict with a string field "t"')
    try:
        data = json.dumps(message, separators=(",", ":"), allow_nan=False, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WireError(f"not JSON-compatible: {exc}") from exc
    if len(data) > limit:
        raise WireError(f"message too large ({len(data)} > {limit} bytes)")
    return data


def decode(data: bytes, limit: int = MAX_MESSAGE) -> Message:
    if len(data) > limit:
        raise WireError(f"message too large ({len(data)} > {limit} bytes)")
    try:
        value = json.loads(data.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WireError(f"not valid JSON: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("t"), str):
        raise WireError('a message must be an object with a string field "t"')
    _check_depth(value)
    return value
