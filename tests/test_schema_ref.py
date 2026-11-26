"""Local $ref support in the argument validator, and its limits."""

import time

from mcpguard.schema import validate

SCHEMA = {
    "type": "object",
    "required": ["target"],
    "properties": {
        "target": {"$ref": "#/$defs/target"},
        "tags": {"type": "array", "items": {"$ref": "#/definitions/tag"}},
    },
    "$defs": {
        "target": {"type": "object", "required": ["host"],
                   "properties": {"host": {"type": "string", "maxLength": 5}}},
    },
    "definitions": {"tag": {"type": "string", "maxLength": 3}},
}


def test_valid_call_passes():
    assert validate({"target": {"host": "abc"}, "tags": ["a", "bc"]}, SCHEMA) == []


def test_ref_is_followed_for_properties_and_items():
    assert validate({"target": {"host": "toolong"}}, SCHEMA)
    assert validate({"target": {}}, SCHEMA)
    assert validate({"target": {"host": "a"}, "tags": ["toolong"]}, SCHEMA)


def test_wrong_type_through_ref():
    assert validate({"target": "not an object"}, SCHEMA)


def test_ref_inside_any_of():
    schema = {"anyOf": [{"$ref": "#/$defs/n"}, {"type": "null"}], "$defs": {"n": {"type": "integer"}}}
    assert validate(5, schema) == []
    assert validate(None, schema) == []
    assert validate("x", schema)


def test_json_pointer_escapes():
    schema = {"$ref": "#/$defs/a~1b", "$defs": {"a/b": {"type": "integer"}}}
    assert validate(1, schema) == []
    assert validate("x", schema)


def test_unresolvable_refs_do_not_block():
    for ref in ("#/$defs/missing", "https://example.com/schema.json", "other.json#/x", "#/$defs", 5, "#/a/9"):
        assert validate("anything", {"$ref": ref, "$defs": {"t": {"type": "integer"}}}) == [], ref


def test_remote_ref_is_never_fetched(monkeypatch):
    import socket

    def boom(*a, **k):
        raise AssertionError("network used")

    monkeypatch.setattr(socket, "create_connection", boom)
    assert validate(1, {"$ref": "http://127.0.0.1:1/x.json"}) == []


def test_self_reference_terminates():
    assert validate({"a": {"a": {}}}, {"$ref": "#"}) == []
    tree = {"type": "object", "properties": {"child": {"$ref": "#"}}, "required": ["name"]}
    deep: dict = {"name": "x"}
    node = deep
    for _ in range(100):
        node["child"] = {"name": "x"}
        node = node["child"]
    validate(deep, tree)  # must return, whatever the answer


def test_exponential_schema_is_bounded():
    schema = {"$ref": "#/$defs/a", "$defs": {"a": {"anyOf": [{"$ref": "#/$defs/a"}, {"$ref": "#/$defs/a"}]}}}
    start = time.monotonic()
    validate("x", schema)
    assert time.monotonic() - start < 2
