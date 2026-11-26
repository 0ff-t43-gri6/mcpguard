import http_fake
import pytest
from conftest import call, run, text

from mcpguard.config import ConfigError


@pytest.mark.parametrize("sse", [False, True])
def test_http_upstream(gateway, monkeypatch, sse):
    srv, url, calls = http_fake.start(use_sse=sse, token="t0k")
    monkeypatch.setenv("HTTP_TOKEN", "t0k")

    async def go():
        async with gateway(servers=f'[servers.web]\nurl = "{url}"\nbearer_env = "HTTP_TOKEN"\n') as gw:
            assert "web__hello" in gw.tools
            assert text(await call(gw, "web__hello")) == "hello from http"
    try:
        run(go())
    finally:
        srv.shutdown()
    headers = [{k.lower(): v for k, v in h.items()} for m, h in calls if m.get("method") == "tools/list"]
    assert headers[0]["mcp-session-id"] == "sess-123"
    assert headers[0]["mcp-protocol-version"] == "2025-06-18"


def test_expired_http_session_is_renewed(gateway):
    srv, url, calls = http_fake.start(expire_after=3)

    async def go():
        async with gateway(servers=f'[servers.web]\nurl = "{url}"\n') as gw:
            for _ in range(3):
                assert text(await call(gw, "web__hello")) == "hello from http"
    try:
        run(go())
    finally:
        srv.shutdown()
    assert sum(1 for m, _ in calls if m.get("method") == "initialize") == 2


def test_wrong_token_marks_server_down(gateway, monkeypatch):
    srv, url, _ = http_fake.start(token="right")
    monkeypatch.setenv("HTTP_TOKEN", "wrong")

    async def go():
        async with gateway(servers=f'[servers.web]\nurl = "{url}"\nbearer_env = "HTTP_TOKEN"\n') as gw:
            assert gw.servers["web"].status == "down"
            assert "401" in gw.servers["web"].last_error
    try:
        run(go())
    finally:
        srv.shutdown()


def test_plain_http_to_remote_hosts_is_refused(make_config):
    from mcpguard.config import load_config
    with pytest.raises(ConfigError):
        load_config(make_config(servers='[servers.bad]\nurl = "http://example.com/mcp"\n'))


def test_safe_opener_refuses_other_schemes_and_redirects():
    import threading
    import urllib.error
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from mcpguard.net import UnsafeURL, open_url

    with pytest.raises(UnsafeURL):
        open_url("file:///etc/passwd", timeout=2)

    class Redirect(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with pytest.raises(urllib.error.HTTPError) as e:
            open_url(f"http://127.0.0.1:{srv.server_address[1]}/", timeout=5)
        assert e.value.code == 302  # reported, not followed
    finally:
        srv.shutdown()
