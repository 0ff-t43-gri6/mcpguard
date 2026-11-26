"""Schema validation, checkpoints, metrics and event streams."""

import asyncio
import json
import socket
import threading
import urllib.request

import pytest
from conftest import call, is_err, run, text

from mcpguard.audit import AuditLog, append_checkpoint, check_checkpoints, make_checkpoint, read_log
from mcpguard.cli import main
from mcpguard.config import load_config
from mcpguard.gateway import Gateway
from mcpguard.httpserve import serve_http
from mcpguard.metrics import Metrics
from mcpguard.schema import validate

# ------------------------------------------------------------------ schema


SCHEMA = {
    "type": "object",
    "required": ["path"],
    "additionalProperties": False,
    "properties": {
        "path": {"type": "string", "maxLength": 20, "pattern": "^/"},
        "mode": {"enum": ["r", "w"]},
        "count": {"type": "integer", "minimum": 0, "maximum": 10},
        "tags": {"type": "array", "items": {"type": "string"}, "maxItems": 3},
    },
}


@pytest.mark.parametrize(("args", "fragment"), [
    ({}, "missing required 'path'"),
    ({"path": 5}, "expected string"),
    ({"path": "relative"}, "pattern"),
    ({"path": "/" + "a" * 30}, "longer than 20"),
    ({"path": "/x", "mode": "x"}, "one of"),
    ({"path": "/x", "count": 11}, "maximum"),
    ({"path": "/x", "count": True}, "expected integer"),
    ({"path": "/x", "tags": ["a", 1]}, "tags[1]"),
    ({"path": "/x", "tags": ["a"] * 4}, "more than 3"),
    ({"path": "/x", "extra": 1}, "unexpected property 'extra'"),
])
def test_schema_rejects(args, fragment):
    errors = validate(args, SCHEMA)
    assert errors
    assert any(fragment in e for e in errors), errors


def test_schema_accepts_valid_and_ignores_unknown_keywords():
    assert validate({"path": "/x", "mode": "r", "count": 3, "tags": ["a"]}, SCHEMA) == []
    assert validate({"anything": 1}, {"$ref": "#/defs/x", "x-custom": True}) == []
    assert validate(1.0, {"type": "integer"}) == []
    assert validate({"a": 1}, {"type": "object", "properties": {"a": {"pattern": "("}}}) == []


def test_schema_combinators():
    s = {"oneOf": [{"type": "string"}, {"type": "integer"}]}
    assert validate("x", s) == []
    assert validate(1, s) == []
    assert validate(1.5, s)
    assert validate("x", {"not": {"type": "string"}})
    assert validate(5, {"anyOf": [{"maximum": 1}, {"minimum": 10}]})


def test_gateway_blocks_calls_that_break_the_schema(gateway):
    async def go():
        async with gateway() as gw:
            r = await call(gw, "srv__sized", {"n": "lots"})
            assert is_err(r)
            assert "schema" in text(r)
            assert not is_err(await call(gw, "srv__sized", {"n": 5}))
    run(go())


def test_schema_validation_can_be_turned_off(gateway):
    async def go():
        async with gateway("[policy]\nvalidate_arguments = false\n") as gw:
            assert not is_err(await call(gw, "srv__echo", {"text": 123}))
    run(go())


# ------------------------------------------------------------------ checkpoints


def test_checkpoint_detects_truncation_and_rewrites(tmp_path):
    p = tmp_path / "a.jsonl"
    key = b"k" * 32
    log = AuditLog(p, key=key)
    for i in range(5):
        log.write("e", n=i)
    cp = make_checkpoint(p, key)
    assert cp["seq"] == 4
    assert "sig" in cp
    assert check_checkpoints(p, [cp], key)[0]

    lines = p.read_text(encoding="utf-8").splitlines()
    p.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")  # drop the newest two records: still a valid chain
    ok, msg = check_checkpoints(p, [cp], key)
    assert not ok
    assert "truncated" in msg

    forged = dict(cp, hash="0" * 64)
    ok, msg = check_checkpoints(p, [forged], key)
    assert not ok
    assert "signature" in msg


def test_checkpoint_cli_and_gateway_schedule(gateway, tmp_path, capsys):
    cpfile = tmp_path / "elsewhere" / "cps.jsonl"
    body = f'[audit]\ncheckpoint_path = "{cpfile.as_posix()}"\ncheckpoint_minutes = 0.0001\n'

    async def go():
        async with gateway(body) as gw:
            await call(gw, "srv__echo", {"text": "x"})
            await asyncio.sleep(0.05)
            await gw.tick()
            return gw.cfg.source
    cfg = run(go())
    assert len(cpfile.read_text(encoding="utf-8").splitlines()) >= 2  # one from tick, one at shutdown
    assert main(["-c", cfg, "verify"]) == 0
    assert "checkpoints confirmed" in capsys.readouterr().out

    audit = tmp_path / "mcpguard-audit.jsonl"
    lines = audit.read_text(encoding="utf-8").splitlines()
    audit.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    assert main(["-c", cfg, "verify"]) == 3
    assert "truncated" in capsys.readouterr().out


# ------------------------------------------------------------------ metrics


def test_metrics_render():
    m = Metrics()
    m({"event": "call.allowed", "tool": "fs__read", "latency_ms": 12.5,
       "findings": [{"rule": "secret.jwt", "severity": "high"}]})
    m({"event": "call.blocked", "tool": 'we"ird__x'})
    out = m.render({"mcpguard_servers_up": ("Servers up.", 2)})
    assert 'mcpguard_calls_total{outcome="allowed",server="fs"} 1' in out
    assert 'mcpguard_findings_total{rule="secret.jwt",severity="high"} 1' in out
    assert 'server="we\\"ird"' in out
    assert "mcpguard_servers_up 2" in out
    assert "# TYPE mcpguard_servers_up gauge" in out


# ------------------------------------------------------------------ HTTP: metrics and event stream


def _serve(cfg_path, scenario):
    cfg = load_config(cfg_path)

    async def go():
        stop = asyncio.Event()
        ready = asyncio.get_running_loop().create_future()
        task = asyncio.create_task(serve_http(Gateway(cfg), "127.0.0.1", 0, "/mcp", ready=ready, stop=stop))
        front = await asyncio.wait_for(ready, 10)
        front.ping_seconds = 0.2
        try:
            await scenario(front)
        finally:
            stop.set()
            await task
    asyncio.run(go())


def _post(port, msg, sid=None):
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if sid:
        h["Mcp-Session-Id"] = sid
    req = urllib.request.Request(f"http://127.0.0.1:{port}/mcp", json.dumps(msg).encode(), h, method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.headers.get("Mcp-Session-Id")


def test_metrics_endpoint(make_config):
    async def scenario(front):
        def work():
            sid = _post(front.port, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            _post(front.port, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                               "params": {"name": "srv__echo", "arguments": {"text": "x"}}}, sid)
            with urllib.request.urlopen(f"http://127.0.0.1:{front.port}/metrics", timeout=5) as r:
                return r.read().decode(), r.headers.get("Content-Type")
        body, ctype = await asyncio.to_thread(work)
        assert ctype.startswith("text/plain")
        assert 'mcpguard_calls_total{outcome="allowed",server="srv"} 1' in body
        assert "mcpguard_servers_up 1" in body
        assert "mcpguard_http_sessions 1" in body
    _serve(make_config(), scenario)


def test_event_stream_delivers_list_changed(make_config):
    p = make_config()

    async def scenario(front):
        sid = await asyncio.to_thread(_post, front.port, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                                          "params": {}})
        received = []

        def listen():
            s = socket.create_connection(("127.0.0.1", front.port), timeout=5)
            s.sendall(f"GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n"
                      f"Mcp-Session-Id: {sid}\r\n\r\n".encode())
            buf = b""
            while b"list_changed" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            received.append(buf.decode())
            s.close()
        t = threading.Thread(target=listen)
        t.start()
        for _ in range(50):
            await asyncio.sleep(0.02)
            if front.streams:
                break
        assert front.streams
        await front.broadcast({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
        await asyncio.to_thread(t.join, 5)
        out = received[0]
        assert out.startswith("HTTP/1.1 200")
        assert "text/event-stream" in out
        assert 'data: {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}' in out
    _serve(p, scenario)


def test_event_stream_needs_a_session_and_closes_on_delete(make_config):
    async def scenario(front):
        def raw(req):
            s = socket.create_connection(("127.0.0.1", front.port), timeout=5)
            s.sendall(req.encode())
            data = s.recv(4096).decode()
            return s, data
        s, data = await asyncio.to_thread(raw, "GET /mcp HTTP/1.1\r\nAccept: text/event-stream\r\n"
                                               "Mcp-Session-Id: nope\r\n\r\n")
        s.close()
        assert data.startswith("HTTP/1.1 404")
        sid = await asyncio.to_thread(_post, front.port, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                                          "params": {}})
        s, data = await asyncio.to_thread(raw, f"GET /mcp HTTP/1.1\r\nAccept: text/event-stream\r\n"
                                               f"Mcp-Session-Id: {sid}\r\n\r\n")
        assert data.startswith("HTTP/1.1 200")

        def delete():
            req = urllib.request.Request(f"http://127.0.0.1:{front.port}/mcp", method="DELETE",
                                         headers={"Mcp-Session-Id": sid})
            return urllib.request.urlopen(req, timeout=5).status
        assert await asyncio.to_thread(delete) == 204
        def drain():
            while True:  # the server closes the stream once the session is gone
                if not s.recv(4096):
                    return True
        assert await asyncio.to_thread(drain)
        s.close()
        for _ in range(50):
            await asyncio.sleep(0.02)
            if not front.streams:
                break
        assert not front.streams
    _serve(make_config(), scenario)


def test_audit_checkpoint_skips_empty_log(tmp_path):
    assert make_checkpoint(tmp_path / "none.jsonl") is None
    append_checkpoint(tmp_path / "c.jsonl", {"seq": 0, "hash": "x", "ts": 1})
    assert read_log(tmp_path / "none.jsonl") == []
