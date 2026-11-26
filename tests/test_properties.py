"""Property-based tests: invariants checked against generated inputs.

Run a bigger campaign with:  HYPOTHESIS_PROFILE=campaign pytest tests/test_properties.py
"""

import asyncio
import contextlib
import fnmatch
import itertools
import json
import os
import string
import time

import pytest
import tomli_w
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from mcpguard.audit import AuditLog, read_log, verify
from mcpguard.config import ConfigError, DetectorConfig, load_config
from mcpguard.detect import SECRET_PATTERNS, Engine, redact_secrets, texts_of
from mcpguard.policy import Policy
from mcpguard.schema import validate
from timing import scaled

settings.register_profile("default", max_examples=60, deadline=None,
                          suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
settings.register_profile("campaign", max_examples=1500, deadline=None,
                          suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))

json_scalars = (st.none() | st.booleans() | st.integers(-10**6, 10**6) | st.floats(allow_nan=False)
                | st.text(max_size=40))
json_values = st.recursive(
    json_scalars,
    lambda c: st.lists(c, max_size=5) | st.dictionaries(st.text(max_size=10), c, max_size=5),
    max_leaves=25)
names = st.text(alphabet=string.ascii_lowercase + "_", min_size=1, max_size=8)


# ------------------------------------------------------------------ audit chain

events = st.lists(st.tuples(names, st.dictionaries(names, json_scalars, max_size=3)), min_size=2, max_size=12)


_counter = itertools.count()


def _write(tmp_path, evs, key):
    p = tmp_path / f"a{next(_counter)}.jsonl"  # a clock is not unique enough: Windows ticks every ~16 ms
    log = AuditLog(p, key=key)
    for name, fields in evs:
        fields = {k: v for k, v in fields.items() if k not in ("seq", "ts", "event", "prev", "hash", "alg")}
        log.write(name, **fields)
    return p


@given(evs=events, key=st.sampled_from([None, b"k" * 32]))
def test_any_log_verifies(tmp_path, evs, key):
    assert verify(_write(tmp_path, evs, key), key)[0]


@given(evs=events, data=st.data())
def test_any_single_edit_is_detected_with_a_key(tmp_path, evs, data):
    key = b"k" * 32
    p = _write(tmp_path, evs, key)
    recs = read_log(p)
    i = data.draw(st.integers(0, len(recs) - 1))
    field = data.draw(st.sampled_from(sorted(k for k in recs[i] if k not in ("alg",))))
    new = data.draw(json_scalars)
    assume(recs[i][field] != new)
    recs[i][field] = new
    p.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in recs), encoding="utf-8")
    assert not verify(p, key)[0]


@given(evs=events, data=st.data())
def test_deleting_or_swapping_records_is_detected(tmp_path, evs, data):
    p = _write(tmp_path, evs, None)
    recs = read_log(p)
    i = data.draw(st.integers(0, len(recs) - 2))  # deleting the last record needs a checkpoint
    if data.draw(st.booleans()):
        del recs[i]
    else:
        recs[i], recs[i + 1] = recs[i + 1], recs[i]
    p.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in recs), encoding="utf-8")
    assert not verify(p)[0]


# ------------------------------------------------------------------ redaction and detectors


secret_samples = st.sampled_from([
    "AKIA" + "ABCDEFGHIJKLMNOP", "ghp_" + "a" * 36, "sk-ant-" + "b" * 30, "xoxb-" + "1234567890abc",
    "AIza" + "C" * 35, "sk_live_" + "d1" * 12, "postgres://u:p4ss@h/db",
    "-----BEGIN RSA PRIVATE KEY-----", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefghijklmnop",
])


@given(prefix=st.text(max_size=30), secret=secret_samples, suffix=st.text(max_size=30))
def test_redaction_removes_secrets_and_is_idempotent(prefix, secret, suffix):
    text = f"{prefix} {secret} {suffix}"
    once = redact_secrets(text, 4.3)
    assert secret not in once
    assert redact_secrets(once, 4.3) == once
    import re
    for _name, pattern, _sev in SECRET_PATTERNS:
        assert not re.search(pattern, once)


attack_fragments = st.sampled_from(["../", "; rm -rf /", "$(curl x)", "http://127.0.0.1/", "http://0x7f.1/",
                                    "file:///etc/passwd", "![a](https://e.x/?d=", "' OR '1'='1", "\x1b[2K",
                                    "/home/u/.ssh/id_rsa", "\\\\h\\s", "UNION SELECT", "aWdub3Jl"])


@given(parts=st.lists(st.text(max_size=40) | attack_fragments, max_size=8))
def test_attack_checks_never_raise_on_mixed_input(parts):
    text = "".join(parts)
    e = Engine(DetectorConfig())
    e.scan_args("t", {"v": text})
    e.scan_texts("t", [text])
    e.scan_definition({"name": text[:30] or "t", "description": text})


@given(text=st.text(max_size=400))
def test_detectors_never_raise(text):
    e = Engine(DetectorConfig())
    e.scan_texts("t", [text])
    e.scan_args("t", {"x": text, text[:10]: [text]})
    e.scan_definition({"name": "t", "description": text, "inputSchema": {"properties": {text[:30]: {}}}})
    e.redact(text)


@pytest.mark.parametrize("chunk", ["a", "ab", " ", "send ", "ignore all ", "-", "eyJ", "=", "x" * 7 + ".",
                                   "read ", "postgres://", "../", "$(", "; ", "![a](", "](http://", "[x",
                                   "http://1", "\x1b[", "' or ", "union ", "<img src=", "execute any ",
                                   "/.ssh/", "A", "%2", "\\\\"])
def test_detectors_have_no_catastrophic_backtracking(chunk):
    e = Engine(DetectorConfig())
    adversarial = chunk * (20_000 // len(chunk))
    start = time.perf_counter()
    e.scan_texts("t", [adversarial])
    e.redact(adversarial)
    assert time.perf_counter() - start < scaled(2.0)


@given(result=json_values)
def test_result_text_extraction_never_raises(result):
    if isinstance(result, dict):
        texts_of(result)
        texts_of({"content": [result], "contents": [result], "messages": [{"content": result}]})


# ------------------------------------------------------------------ policy


rule_st = st.fixed_dictionaries(
    {"match": st.sampled_from(["*", "a/*", "a/x", "b/*", "*/x", "*/del*", "a/resource:*"]),
     "action": st.sampled_from(["allow", "deny", "ask"])},
    optional={"args": st.dictionaries(st.sampled_from(["p", "q"]), st.sampled_from(["*", "/etc/*", "1", "x*"]),
                                      min_size=1, max_size=2),
              "clients": st.lists(st.sampled_from(["ci", "ci-*", "dev", "*"]), min_size=1, max_size=2)})


def reference(rules, default, target, args, client):
    for r in rules:
        if not fnmatch.fnmatch(target, r["match"]):
            continue
        if "clients" in r and (client is None or not any(fnmatch.fnmatch(client, c) for c in r["clients"])):
            continue
        if "args" in r:
            if args is None:
                continue
            def text(value):
                return value if isinstance(value, str) else json.dumps(value, sort_keys=True)
            ok = all(k in args and fnmatch.fnmatch(text(args[k]), str(pattern)) for k, pattern in r["args"].items())
            if not ok:
                continue
        return r["action"]
    return default


@given(rules=st.lists(rule_st, max_size=6), default=st.sampled_from(["allow", "deny", "ask"]),
       target=st.sampled_from(["a/x", "a/y", "b/x", "b/delete", "a/resource:notes://1", "c/z"]),
       args=st.none() | st.dictionaries(st.sampled_from(["p", "q", "r"]),
                                        st.sampled_from(["/etc/hosts", "1", "xyz", 1, None]), max_size=3),
       client=st.none() | st.sampled_from(["ci", "ci-bot", "dev", "stdio"]))
def test_policy_matches_reference_implementation(rules, default, target, args, client):
    p = Policy.from_dict({"rules": rules, "default": default})
    assert p.evaluate(target, args, client).action == reference(rules, default, target, args, client)
    assert p.visible(target, client) == (reference(rules, default, target, None, client) != "deny")


@given(n=st.integers(1, 30), limit=st.integers(1, 10))
def test_rate_limit_never_exceeded_in_a_window(n, limit):
    p = Policy.from_dict({"rate_limit_per_minute": limit})
    allowed = 0
    for i in range(n):
        if p.check_budget("t", now=float(i)) is None:
            p.record_call("t", now=float(i))
            allowed += 1
    assert allowed == min(n, limit)


# ------------------------------------------------------------------ schema validator


schemaish = st.recursive(
    st.fixed_dictionaries({}, optional={
        "type": st.sampled_from(["object", "array", "string", "integer", "number", "boolean", "null", "nope"])
        | st.lists(st.sampled_from(["string", "integer", "null"]), max_size=3),
        "maxLength": st.integers(-1, 10), "minimum": st.integers(-5, 5) | st.text(max_size=2),
        "pattern": st.sampled_from(["^a", "(", "[0-9]+", ""]), "enum": st.lists(json_scalars, max_size=3),
        "required": st.lists(names, max_size=2) | st.text(max_size=3), "additionalProperties": st.booleans(),
    }),
    lambda c: st.fixed_dictionaries({}, optional={
        "properties": st.dictionaries(names, c, max_size=3), "items": c,
        "anyOf": st.lists(c, max_size=3), "oneOf": st.lists(c, max_size=3), "allOf": st.lists(c, max_size=3),
        "not": c}),
    max_leaves=12)


@given(instance=json_values, schema=schemaish)
def test_schema_validation_never_raises(instance, schema):
    errors = validate(instance, schema)
    assert isinstance(errors, list)
    assert len(errors) <= 10


@given(instance=json_values)
def test_empty_schema_accepts_everything(instance):
    assert validate(instance, {}) == []


# ------------------------------------------------------------------ config loader


cfg_values = st.recursive(
    st.booleans() | st.integers(-5, 70000) | st.text(max_size=12) | st.floats(-1, 1e6, allow_nan=False),
    lambda c: st.lists(c, max_size=3) | st.dictionaries(st.text(string.ascii_lowercase + "_-", min_size=1, max_size=10),
                                                        c, max_size=4),
    max_leaves=15)
sections = st.dictionaries(
    st.sampled_from(["mode", "policy", "servers", "detectors", "approvals", "dashboard", "anomaly", "audit",
                     "logging", "alerts", "http", "clients", "pins"]),
    cfg_values, max_size=5)


@given(doc=sections)
@settings(max_examples=int(os.environ.get("CONFIG_EXAMPLES", "60")))
def test_config_loader_only_raises_config_error(tmp_path, doc):
    p = tmp_path / "fuzz.toml"
    try:
        p.write_text(tomli_w.dumps(doc), encoding="utf-8")
    except (TypeError, ValueError):
        assume(False)
    with contextlib.suppress(ConfigError):  # anything else escaping is a bug
        load_config(p)


# ------------------------------------------------------------------ HTTP request parser


@given(data=st.binary(max_size=600))
def test_http_parser_never_raises(data):
    from mcpguard.httpserve import HttpFrontend, Request

    async def go():
        reader = asyncio.StreamReader(limit=16 * 1024)
        reader.feed_data(data)
        reader.feed_eof()
        front = HttpFrontend.__new__(HttpFrontend)
        result = await HttpFrontend._read_request(front, reader)
        assert result is None or isinstance(result, (int, Request))
    asyncio.run(go())


# ------------------------------------------------------------------ regressions found by the campaign


def test_regression_non_ascii_hash_does_not_crash_verify(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p, key=b"k" * 32)
    log.write("_")
    log.write("_")
    recs = read_log(p)
    recs[0]["hash"] = "\x80"
    p.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in recs), encoding="utf-8")
    ok, _ = verify(p, b"k" * 32)
    assert not ok


@pytest.mark.parametrize("doc", [{"policy": []}, {"detectors": []}, {"servers": {"a": 5}},
                                 {"policy": {"rules": "x"}}, {"audit": {"path": 5}}, {"mode": [1]}])
def test_regression_wrong_section_types_are_config_errors(tmp_path, doc):
    p = tmp_path / "c.toml"
    p.write_text(tomli_w.dumps(doc), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(p)


@given(text=st.text(max_size=500), params=st.lists(st.text(max_size=20), max_size=5))
def test_ioc_matching_never_raises(text, params):
    from mcpguard.iocs import load_feeds
    feed = load_feeds()
    feed.match_text(text, "x")
    feed.match_name(text[:40], "x")
    feed.match_params(params, "x")
    feed.match_domains(text, "x")


# ---- Claude Desktop integration -------------------------------------------------------------

_text = st.text(st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"), max_size=40)
_server = st.fixed_dictionaries({"command": _text.filter(bool), "args": st.lists(_text, max_size=5)},
                                optional={"env": st.dictionaries(_text.filter(bool), _text, max_size=3)})


@given(servers=st.dictionaries(st.text(string.ascii_letters + string.digits + "-_ .é", min_size=1, max_size=20),
                               _server, min_size=1, max_size=4))
def test_moved_servers_round_trip_through_toml(tmp_path_factory, servers):
    """Whatever Claude Desktop had (Windows paths, quotes, unicode), mcpguard runs it unchanged."""
    from mcpguard.desktop import safe_names, servers_to_toml
    p = tmp_path_factory.mktemp("rt") / "mcpguard.toml"
    p.write_text(servers_to_toml(servers), encoding="utf-8")
    loaded = {s.name: s for s in load_config(p).servers}
    names = safe_names(list(servers))
    assert set(loaded) == set(names.values())
    for original, spec in servers.items():
        name = names[original]
        assert loaded[name].command == spec["command"]
        assert loaded[name].args == spec["args"]
        assert loaded[name].env == spec.get("env", {})


@given(st.text(max_size=300) | st.lists(st.dictionaries(_text, _text, max_size=3), max_size=3).map(
    lambda objs: "\n".join(json.dumps(o) for o in objs)))
def test_desktop_parse_only_raises_desktop_error(text):
    from mcpguard.desktop import DesktopError, parse
    try:
        data, _ = parse(text)
    except DesktopError:
        return
    assert isinstance(data, dict)
