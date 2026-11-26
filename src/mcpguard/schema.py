"""A small JSON Schema validator for tool arguments.

Tools declare an ``inputSchema``; checking calls against it stops malformed or
oversized arguments before they reach the server. This covers the keywords tool
schemas use in practice (type, required, properties, additionalProperties, enum,
const, string/number/array bounds, pattern, items, anyOf/oneOf/allOf, not).
Unknown keywords and ``$ref`` are ignored rather than guessed at, so a schema we
don't fully understand never blocks a valid call.
"""

from __future__ import annotations

import math
import re
from typing import Any

MAX_DEPTH = 32
MAX_ERRORS = 10
_PATTERN_CACHE: dict[str, re.Pattern | None] = {}

_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
    "integer": lambda v: (isinstance(v, int) and not isinstance(v, bool))
    or (isinstance(v, float) and v.is_integer()),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v),
}


_REPEATED_GROUP = re.compile(r"\)[*+{]")
_BACKREF = re.compile(r"\\[1-9]|\(\?P=")
_UNBOUNDED = re.compile(r"(?<!\\)(?:[*+]|\{\d+,\})")
MAX_PATTERN = 300
MAX_PATTERNED_VALUE = 2000


def _risky(p: str) -> bool:
    """A pattern that could take exponential or high-degree polynomial time on a crafted string.
    The pattern comes from a tool server and the string from the model, and Python's re cannot be
    interrupted, so one hostile server could stall the whole gateway: `^(a+)+$` takes 10 s on 28 characters."""
    return (len(p) > MAX_PATTERN or bool(_REPEATED_GROUP.search(p)) or bool(_BACKREF.search(p))
            or len(_UNBOUNDED.findall(p)) > 3)


def _pattern(p: str) -> re.Pattern | None:
    if p not in _PATTERN_CACHE:
        try:
            _PATTERN_CACHE[p] = None if _risky(p) else re.compile(p)  # such a pattern is ignored, like an invalid one
        except (re.error, TypeError):
            _PATTERN_CACHE[p] = None  # an invalid pattern in a schema is ignored
    return _PATTERN_CACHE[p]


def _type_name(v: Any) -> str:
    for name in ("null", "boolean", "integer", "number", "string", "array", "object"):
        if _TYPES[name](v):
            return name
    return type(v).__name__


def validate(instance: Any, schema: Any) -> list[str]:
    """Return a list of problems (empty when the instance is valid)."""
    errors: list[str] = []
    _check(instance, schema, "", errors, 0)
    return errors[:MAX_ERRORS]


def _check(v: Any, s: Any, path: str, errors: list[str], depth: int) -> None:
    if len(errors) >= MAX_ERRORS or not isinstance(s, dict) or depth > MAX_DEPTH:
        return
    where = path or "arguments"

    t = s.get("type")
    if t is not None:
        names = t if isinstance(t, list) else [t]
        known = [n for n in names if n in _TYPES]
        if known and not any(_TYPES[n](v) for n in known):
            errors.append(f"{where}: expected {' or '.join(known)}, got {_type_name(v)}")
            return

    if "enum" in s and isinstance(s["enum"], list) and v not in s["enum"]:
        errors.append(f"{where}: must be one of {s['enum'][:10]}")
    if "const" in s and v != s["const"]:
        errors.append(f"{where}: must equal {s['const']!r}")

    if isinstance(v, str):
        if isinstance(s.get("maxLength"), int) and len(v) > s["maxLength"]:
            errors.append(f"{where}: longer than {s['maxLength']} characters")
        if isinstance(s.get("minLength"), int) and len(v) < s["minLength"]:
            errors.append(f"{where}: shorter than {s['minLength']} characters")
        if isinstance(s.get("pattern"), str):
            pat = _pattern(s["pattern"]) if len(v) <= MAX_PATTERNED_VALUE else None
            if pat is not None and not pat.search(v):
                errors.append(f"{where}: does not match the required pattern")

    if _TYPES["number"](v):
        for key, ok in (("minimum", lambda b: v >= b), ("maximum", lambda b: v <= b),
                        ("exclusiveMinimum", lambda b: v > b), ("exclusiveMaximum", lambda b: v < b)):
            bound = s.get(key)
            if _TYPES["number"](bound) and not ok(bound):
                errors.append(f"{where}: violates {key} {bound}")

    if isinstance(v, list):
        if isinstance(s.get("maxItems"), int) and len(v) > s["maxItems"]:
            errors.append(f"{where}: more than {s['maxItems']} items")
        if isinstance(s.get("minItems"), int) and len(v) < s["minItems"]:
            errors.append(f"{where}: fewer than {s['minItems']} items")
        if isinstance(s.get("items"), dict):
            for i, item in enumerate(v):
                _check(item, s["items"], f"{where}[{i}]", errors, depth + 1)

    if isinstance(v, dict):
        raw_props = s.get("properties")
        props: dict = raw_props if isinstance(raw_props, dict) else {}
        raw_required = s.get("required")
        required: list = raw_required if isinstance(raw_required, list) else []
        errors.extend(f"{where}: missing required '{name}'" for name in required
                      if isinstance(name, str) and name not in v)
        extra = s.get("additionalProperties", True)
        for key, val in v.items():
            child = f"{path}.{key}" if path else str(key)
            if key in props:
                _check(val, props[key], child, errors, depth + 1)
            elif extra is False:
                errors.append(f"{where}: unexpected property '{key}'")
            elif isinstance(extra, dict):
                _check(val, extra, child, errors, depth + 1)

    for key in ("allOf", "anyOf", "oneOf"):
        subs = s.get(key)
        if not isinstance(subs, list) or not subs:
            continue
        results = []
        for sub in subs:
            sub_errors: list[str] = []
            _check(v, sub, path, sub_errors, depth + 1)
            results.append(sub_errors)
        passing = sum(1 for r in results if not r)
        if key == "allOf" and passing < len(subs):
            errors.extend(next(r for r in results if r)[:2])
        elif key == "anyOf" and passing == 0:
            errors.append(f"{where}: matches none of the allowed shapes")
        elif key == "oneOf" and passing != 1:
            errors.append(f"{where}: must match exactly one allowed shape (matched {passing})")

    if isinstance(s.get("not"), dict):
        sub_errors = []
        _check(v, s["not"], path, sub_errors, depth + 1)
        if not sub_errors:
            errors.append(f"{where}: matches a disallowed shape")
