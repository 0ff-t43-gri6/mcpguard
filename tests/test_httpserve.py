"""The gateway served to clients over Streamable HTTP."""

import asyncio
import json
import urllib.error
import urllib.request

import pytest

from mcpguard.config import load_config
from mcpguard.gateway import Gateway
from mcpguard.httpserve import HttpFrontend, ServeError, serve_http


def _post(url, msg, token=None, session=None, headers=None):
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if session:
        h["Mcp-Session-Id"] = session
    h.update(headers or {})
    req = urllib.request.Request(url, data=json.dumps(msg).encode(), headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read()
            return r.status, json.loads(body) if body else None, dict(r.headers)
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, json.loads(body) if body else None, dict(e.headers)


def _serve(make_config, body, env, monkeypatch, scenario):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    cfg = load_config(make_config(body))

    async def go():
        stop = asyncio.Event()
        ready = asyncio.get_running_loop().create_future()
        server = asyncio.create_task(serve_http(Gateway(cfg), "127.0.0.1", 0, "/mcp", ready=ready, stop=stop))
        front = await asyncio.wait_for(ready, 10)
        try:
            await asyncio.to_thread(scenario, f"http://127.0.0.1:{front.port}", front)
        finally:
            stop.set()
            await server
    asyncio.run(go())


CLIENTS = '[clients.ci]\ntoken_env = "TOK_CI"\n[clients.dev]\ntoken_env = "TOK_DEV"\n' \
          '[[policy.rules]]\nmatch = "srv/send_email"\nclients = ["ci"]\naction = "deny"\n'


def test_http_session_flow_and_client_policy(make_config, monkeypatch):
    def scenario(url, front):
        mcp = url + "/mcp"
        st, body, h = _post(mcp, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, "ci-secret")
        assert st == 200
        assert body["result"]["serverInfo"]["name"] == "mcpguard"
        sid = h["Mcp-Session-Id"]
        st, _, _ = _post(mcp, {"jsonrpc": "2.0", "method": "notifications/initialized"}, "ci-secret", sid)
        assert st == 202
        st, body, _ = _post(mcp, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, "ci-secret", sid)
        names = {t["name"] for t in body["result"]["tools"]}
        assert "srv__echo" in names
        assert "srv__send_email" not in names
        # the dev client still sees it
        st, body, h2 = _post(mcp, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, "dev-secret")
        dev = h2["Mcp-Session-Id"]
        st, body, _ = _post(mcp, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                  "params": {"name": "srv__send_email", "arguments": {"body": "hi"}}},
                            "dev-secret", dev)
        assert body["result"]["content"][0]["text"] == "sent"
        # sessions are bound to their client
        st, _, _ = _post(mcp, {"jsonrpc": "2.0", "id": 4, "method": "tools/list"}, "dev-secret", sid)
        assert st == 404
        # health check
        with urllib.request.urlopen(url + "/healthz") as r:
            assert json.loads(r.read())["ok"] is True
    _serve(make_config, CLIENTS, {"TOK_CI": "ci-secret", "TOK_DEV": "dev-secret"}, monkeypatch, scenario)


def test_http_rejects_bad_requests(make_config, monkeypatch):
    def scenario(url, front):
        mcp = url + "/mcp"
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        assert _post(mcp, init)[0] == 401
        assert _post(mcp, init, "wrong")[0] == 401
        assert _post(mcp, init, "ci-secret", headers={"Origin": "https://evil.example"})[0] == 403
        assert _post(mcp, init, "ci-secret", headers={"Origin": "http://localhost:3000"})[0] == 200
        assert _post(mcp, init, "ci-secret", headers={"Content-Type": "text/plain"})[0] == 415
        assert _post(mcp, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, "ci-secret")[0] == 400
        assert _post(mcp, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, "ci-secret", "nope")[0] == 404
        assert _post(mcp, [init], "ci-secret")[0] == 400
        req = urllib.request.Request(mcp, headers={"Authorization": "Bearer ci-secret"})
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req)
        assert e.value.code == 405
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(url + "/elsewhere")
        assert e.value.code == 404
    _serve(make_config, CLIENTS, {"TOK_CI": "ci-secret", "TOK_DEV": "dev-secret"}, monkeypatch, scenario)


def test_http_delete_ends_session(make_config, monkeypatch):
    def scenario(url, front):
        mcp = url + "/mcp"
        _, _, h = _post(mcp, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        sid = h["Mcp-Session-Id"]
        req = urllib.request.Request(mcp, method="DELETE", headers={"Mcp-Session-Id": sid})
        assert urllib.request.urlopen(req).status == 204
        assert _post(mcp, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, session=sid)[0] == 404
    _serve(make_config, "", {}, monkeypatch, scenario)  # no clients: loopback-only anonymous mode


def test_refuses_public_bind_without_tokens(make_config):
    gw = Gateway(load_config(make_config()))
    with pytest.raises(ServeError, match="without client tokens"):
        HttpFrontend(gw, "0.0.0.0", 0, "/mcp")


def test_refuses_missing_token_env(make_config, monkeypatch):
    monkeypatch.delenv("TOK_CI", raising=False)
    gw = Gateway(load_config(make_config('[clients.ci]\ntoken_env = "TOK_CI"\n')))
    with pytest.raises(ServeError, match="TOK_CI"):
        HttpFrontend(gw, "127.0.0.1", 0, "/mcp")


def test_unauthorized_flood_is_logged_once_with_a_count(make_config, monkeypatch, tmp_path):
    def scenario(url, front):
        for _ in range(50):
            assert _post(url + "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "initialize"}, "wrong")[0] == 401
    _serve(make_config, CLIENTS, {"TOK_CI": "ci-secret", "TOK_DEV": "dev-secret"}, monkeypatch, scenario)
    lines = [json.loads(x) for x in (tmp_path / "mcpguard-audit.jsonl").read_text(encoding="utf-8").splitlines()
             if "http.unauthorized" in x]
    assert len(lines) == 1


def test_sessions_per_client_are_capped(make_config, monkeypatch):
    from mcpguard.httpserve import MAX_SESSIONS_PER_CLIENT

    def scenario(url, front):
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        for _ in range(MAX_SESSIONS_PER_CLIENT + 10):
            _post(url + "/mcp", init)
        assert len(front.sessions) == MAX_SESSIONS_PER_CLIENT
    _serve(make_config, "", {}, monkeypatch, scenario)


def test_shared_tokens_are_refused(make_config, monkeypatch):
    monkeypatch.setenv("TOK_A", "same")
    monkeypatch.setenv("TOK_B", "same")
    gw = Gateway(load_config(make_config('[clients.a]\ntoken_env = "TOK_A"\n[clients.b]\ntoken_env = "TOK_B"\n')))
    with pytest.raises(ServeError, match="share the same token"):
        HttpFrontend(gw, "127.0.0.1", 0, "/mcp")


def test_a_busy_port_stops_the_tool_servers_it_had_started(make_config):
    import socket
    from mcpguard.config import load_config
    busy = socket.socket()
    busy.bind(("127.0.0.1", 0))
    busy.listen(1)
    gw = Gateway(load_config(make_config()))

    async def go():
        with pytest.raises(OSError):
            await serve_http(gw, "127.0.0.1", busy.getsockname()[1], "/mcp")
        return [up.alive for up in gw.upstreams.values()]
    try:
        assert asyncio.run(go()) == [False]  # nothing left running
    finally:
        busy.close()
