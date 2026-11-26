"""Serve the gateway to MCP clients over Streamable HTTP.

    POST   <path>   one JSON-RPC message; the reply is application/json
    GET    <path>   server-to-client event stream (text/event-stream) for a session;
                    carries list_changed notifications
    DELETE <path>   end the session named in Mcp-Session-Id (closes its streams)
    GET    /healthz liveness for supervisors and load balancers (no auth)
    GET    /readyz  200 when every configured server is up, else 503 (no auth)
    GET    /metrics Prometheus metrics (same auth as <path>)

Clients authenticate with ``Authorization: Bearer <token>``; each configured token
maps to a client name that policy rules can target. Without configured clients
the server only runs on a loopback address, as the single client ``local``.

Hardening: Origin is checked (DNS rebinding), bodies are capped, sessions are bound
to the client that created them and expire when idle, and tokens are compared in
constant time. TLS is not terminated here; put a reverse proxy in front of any
non-loopback bind.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import ipaddress
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import __version__
from .approvals import list_pending
from .gateway import Caller, Gateway
from .metrics import Metrics

log = logging.getLogger("mcpguard.http")

MAX_BODY = 4 * 1024 * 1024
MAX_HEADER = 16 * 1024
HEADER_TIMEOUT = 30.0
SESSION_IDLE = 3600.0
MAX_SESSIONS_PER_CLIENT = 64
UNAUTHORIZED_LOG_WINDOW = 60.0
STREAMS_PER_SESSION = 2
STREAM_QUEUE = 100
STREAM_PING_SECONDS = 15.0
STREAM = -1  # internal status: hand the connection over to an event stream
LOCAL_CLIENT = "local"
REASONS = {200: "OK", 202: "Accepted", 204: "No Content", 400: "Bad Request", 401: "Unauthorized",
           403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 409: "Conflict", 411: "Length Required",
           413: "Payload Too Large", 415: "Unsupported Media Type", 500: "Internal Server Error"}


class ServeError(Exception):
    """The server cannot start with this configuration."""


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


@dataclass
class Session:
    client: str
    created: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


@dataclass
class Request:
    method: str
    target: str
    headers: dict[str, str]
    body: bytes


class HttpFrontend:
    def __init__(self, gw: Gateway, host: str, port: int, path: str):
        self.gw = gw
        self.host, self.port, self.path = host, port, path
        clients = gw.cfg.clients
        missing = [c.token_env for c in clients if not c.token]
        if missing:
            raise ServeError(f"token environment variables not set: {', '.join(missing)}")
        self.tokens = [(c.token.encode(), c.name) for c in clients]
        if len({t for t, _ in self.tokens}) != len(self.tokens):
            raise ServeError("two clients share the same token; give each client its own")
        if not self.tokens and not is_loopback(host):
            raise ServeError(f"refusing to listen on {host} without client tokens; "
                             "add [clients.<name>] entries or bind to 127.0.0.1")
        self.sessions: dict[str, Session] = {}
        self.server: asyncio.base_events.Server | None = None
        self._unauthorized = 0
        self._unauthorized_logged_at = float("-inf")  # the first failure is always logged
        self.streams: dict[str, set[asyncio.Queue]] = {}
        self.ping_seconds = STREAM_PING_SECONDS
        self.metrics = Metrics()
        gw.audit.listeners.append(self.metrics)
        gw.notify_client = self.broadcast

    # ------------------------------------------------------------ lifecycle

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._connection, self.host, self.port,
                                                 limit=MAX_HEADER)
        sock = self.server.sockets[0].getsockname()
        self.port = sock[1]
        log.warning("serving MCP over HTTP at http://%s:%d%s", self.host, self.port, self.path)
        if not self.tokens:
            log.warning("no [clients] tokens are configured: any program on this machine can call your tools over "
                        "HTTP. Add a [clients.NAME] with token_env to require a bearer token.")

    async def close(self) -> None:
        for sid in list(self.streams):
            self._close_streams(sid)
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    # ------------------------------------------------------------ event streams

    async def broadcast(self, msg: dict) -> None:
        """Send a notification to every open event stream. Slow readers lose messages, not memory."""
        for queues in self.streams.values():
            for q in queues:
                with contextlib.suppress(asyncio.QueueFull):
                    q.put_nowait(msg)

    def _close_streams(self, sid: str) -> None:
        for q in self.streams.pop(sid, set()):
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(None)

    async def _stream(self, writer: asyncio.StreamWriter, sid: str) -> None:
        queue: asyncio.Queue = asyncio.Queue(STREAM_QUEUE)
        self.streams.setdefault(sid, set()).add(queue)
        try:
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\n"
                         b"Connection: keep-alive\r\nX-Accel-Buffering: no\r\n\r\n: connected\n\n")
            await writer.drain()
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), self.ping_seconds)
                except TimeoutError:
                    writer.write(b": ping\n\n")
                    await writer.drain()
                    continue
                if msg is None:
                    return
                writer.write(f"event: message\ndata: {json.dumps(msg)}\n\n".encode())
                await writer.drain()
        except (ConnectionError, OSError):
            return
        finally:
            queues = self.streams.get(sid)
            if queues is not None:
                queues.discard(queue)
                if not queues:
                    self.streams.pop(sid, None)

    def metrics_text(self) -> str:
        servers = self.gw.servers.values()
        pending = len(list_pending(self.gw.cfg.approvals_dir)) if self.gw.cfg.approval_mode == "dashboard" else 0
        return self.metrics.render({
            "mcpguard_servers_up": ("Upstream servers currently up.", sum(s.status == "up" for s in servers)),
            "mcpguard_servers": ("Configured upstream servers.", len(self.gw.servers)),
            "mcpguard_http_sessions": ("Open HTTP sessions.", len(self.sessions)),
            "mcpguard_http_streams": ("Open event streams.", sum(len(q) for q in self.streams.values())),
            "mcpguard_approvals_pending": ("Approval requests waiting.", pending),
            "mcpguard_audit_records": ("Records in the audit log.", self.gw.audit.count),
        })

    # ------------------------------------------------------------ auth

    def _authenticate(self, headers: dict[str, str]) -> str | None:
        if not self.tokens:
            return LOCAL_CLIENT
        auth = headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return None
        given = auth[7:].strip().encode()
        found = None
        for token, name in self.tokens:  # compare against every token: constant work per request
            if hmac.compare_digest(given, token):
                found = name
        return found

    @staticmethod
    def _origin_ok(headers: dict[str, str]) -> bool:
        origin = headers.get("origin")
        if not origin:
            return True  # non-browser clients don't send Origin
        host = urlsplit(origin).hostname or ""
        return is_loopback(host)

    def _host_ok(self, headers: dict[str, str]) -> bool:
        """Listening on loopback only, the Host header must name a loopback address too. A web page on
        another name that was re-pointed to 127.0.0.1 (DNS rebinding) sends its own name here."""
        if not is_loopback(self.host):
            return True
        host = headers.get("host", "")
        name = urlsplit("//" + host).hostname or ""
        return not host or is_loopback(name)

    def _note_unauthorized(self) -> None:
        """Audit failed logins at most once a minute, with a count, so a flood can't fill the log."""
        self._unauthorized += 1
        now = time.monotonic()
        if now - self._unauthorized_logged_at >= UNAUTHORIZED_LOG_WINDOW:
            self.gw.audit.write("http.unauthorized", attempts=self._unauthorized,
                                reason="missing or invalid bearer token")
            self._unauthorized, self._unauthorized_logged_at = 0, now

    def _new_session(self, client: str) -> str:
        mine = sorted((s.last_seen, sid) for sid, s in self.sessions.items() if s.client == client)
        for _, sid in mine[: max(0, len(mine) - MAX_SESSIONS_PER_CLIENT + 1)]:
            del self.sessions[sid]  # drop the least recently used
            self._close_streams(sid)
        sid = secrets.token_urlsafe(24)
        self.sessions[sid] = Session(client)
        return sid

    def _expire_sessions(self) -> None:
        cutoff = time.time() - SESSION_IDLE
        for sid in [s for s, v in self.sessions.items() if v.last_seen < cutoff and s not in self.streams]:
            del self.sessions[sid]

    # ------------------------------------------------------------ HTTP plumbing

    async def _read_request(self, reader: asyncio.StreamReader) -> Request | int | None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEADER_TIMEOUT)
        except (asyncio.IncompleteReadError, ConnectionError, TimeoutError):
            return None
        except asyncio.LimitOverrunError:
            return 400
        lines = head.decode("latin-1").split("\r\n")
        try:
            method, target, _version = lines[0].split(" ", 2)
        except ValueError:
            return 400
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            name, sep, value = line.partition(":")
            if not sep:
                return 400
            key = name.strip().lower()
            if key in ("host", "content-length") and key in headers:
                return 400  # two of these are how different parsers get made to disagree
            headers[key] = value.strip()
        if "chunked" in headers.get("transfer-encoding", "").lower():
            return 411
        try:
            length = int(headers.get("content-length", "0"))
        except ValueError:
            return 400
        if length < 0:
            return 400
        if length > MAX_BODY:
            return 413
        try:
            body = await asyncio.wait_for(reader.readexactly(length), HEADER_TIMEOUT) if length else b""
        except (asyncio.IncompleteReadError, ConnectionError, TimeoutError):
            return None
        return Request(method.upper(), target, headers, body)

    @staticmethod
    async def _write(writer: asyncio.StreamWriter, status: int, body: dict | str | None = None,
                     headers: dict[str, str] | None = None, keep_alive: bool = True) -> None:
        if isinstance(body, str):
            data, ctype = body.encode(), "text/plain; version=0.0.4; charset=utf-8"
        else:
            data, ctype = (json.dumps(body).encode(), "application/json") if body is not None else (b"", "")
        lines = [f"HTTP/1.1 {status} {REASONS.get(status, 'Status')}",
                 f"Content-Length: {len(data)}", "Cache-Control: no-store",
                 f"Connection: {'keep-alive' if keep_alive else 'close'}"]
        if ctype:
            lines.append(f"Content-Type: {ctype}")
        lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + data)
        await writer.drain()

    async def _connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                req = await self._read_request(reader)
                if req is None:
                    return
                if isinstance(req, int):
                    await self._write(writer, req, {"error": REASONS.get(req, "bad request")}, keep_alive=False)
                    return
                status, body, headers = await self._route(req)
                if status == STREAM:
                    await self._stream(writer, headers["Mcp-Session-Id"])
                    return
                keep = req.headers.get("connection", "").lower() != "close"
                await self._write(writer, status, body, headers, keep)
                if not keep:
                    return
        except Exception:
            log.exception("HTTP connection failed")
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    # ------------------------------------------------------------ routing

    async def _route(self, req: Request) -> tuple[int, dict | str | None, dict[str, str]]:
        path = urlsplit(req.target).path
        if path == "/healthz" and req.method == "GET":
            up = sum(1 for s in self.gw.servers.values() if s.status == "up")
            return 200, {"ok": True, "version": __version__, "servers_up": up,
                         "servers": len(self.gw.servers)}, {}
        if path == "/readyz" and req.method == "GET":
            # Ready when every configured server is up: for load balancers and rollout checks.
            down = sorted(n for n, sv in self.gw.servers.items() if sv.status != "up")
            return (503 if down else 200), {"ready": not down, "servers_down": down}, {}
        if path not in (self.path, "/metrics"):
            return 404, {"error": "not found"}, {}
        if not self._origin_ok(req.headers):
            return 403, {"error": "origin not allowed"}, {}
        if not self._host_ok(req.headers):
            return 403, {"error": "host not allowed"}, {}
        client = self._authenticate(req.headers)
        if client is None:
            self._note_unauthorized()
            return 401, {"error": "missing or invalid bearer token"}, {"WWW-Authenticate": "Bearer"}
        if path == "/metrics":
            if req.method != "GET":
                return 405, {"error": "method not allowed"}, {"Allow": "GET"}
            return 200, self.metrics_text(), {}
        if req.method == "GET":
            return self._open_stream(req, client)
        if req.method == "DELETE":
            sid = req.headers.get("mcp-session-id", "")
            sess = self.sessions.get(sid)
            if sess and sess.client == client:
                del self.sessions[sid]
                self._close_streams(sid)
                return 204, None, {}
            return 404, {"error": "unknown session"}, {}
        if req.method != "POST":
            return 405, {"error": "method not allowed"}, {"Allow": "GET, POST, DELETE"}
        if "json" not in req.headers.get("content-type", ""):
            return 415, {"error": "Content-Type must be application/json"}, {}
        return await self._rpc(req, client)

    def _open_stream(self, req: Request, client: str) -> tuple[int, dict | None, dict[str, str]]:
        if "text/event-stream" not in req.headers.get("accept", ""):
            return 405, {"error": "GET opens an event stream; send Accept: text/event-stream"}, \
                {"Allow": "GET, POST, DELETE"}
        sid = req.headers.get("mcp-session-id", "")
        sess = self.sessions.get(sid)
        if sess is None or sess.client != client:
            return 404, {"error": "session not found or expired; send initialize again"}, {}
        if len(self.streams.get(sid, ())) >= STREAMS_PER_SESSION:
            return 409, {"error": f"at most {STREAMS_PER_SESSION} streams per session"}, {}
        sess.last_seen = time.time()
        return STREAM, None, {"Mcp-Session-Id": sid}

    async def _rpc(self, req: Request, client: str) -> tuple[int, dict | None, dict[str, str]]:
        try:
            msg = json.loads(req.body)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return 400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}, {}
        if not isinstance(msg, dict):
            return 400, {"jsonrpc": "2.0", "id": None,
                         "error": {"code": -32600, "message": "Batch requests are not supported"}}, {}
        self._expire_sessions()
        headers: dict[str, str] = {}
        if msg.get("method") == "initialize":
            sid = self._new_session(client)
            headers["Mcp-Session-Id"] = sid
            self.gw.audit.write("http.session", client=client)
        else:
            sid = req.headers.get("mcp-session-id", "")
            if not sid:
                return 400, {"error": "Mcp-Session-Id header required; send initialize first"}, {}
            sess = self.sessions.get(sid)
            if sess is None or sess.client != client:
                return 404, {"error": "session not found or expired; send initialize again"}, {}
            sess.last_seen = time.time()
        resp = await self.gw.handle(msg, Caller(client, sid))
        if resp is None:
            return 202, None, headers
        return 200, resp, headers


async def serve_http(gw: Gateway, host: str, port: int, path: str, tick_seconds: float = 2.0,
                     ready: asyncio.Future | None = None, stop: asyncio.Event | None = None) -> HttpFrontend:
    """Run the HTTP front end until ``stop`` is set (or forever).

    ``ready`` receives the running front end, whose ``port`` is the bound port.
    """
    front = HttpFrontend(gw, host, port, path)
    await gw.start()
    try:
        await front.start()
    except BaseException:
        # The port is taken (or the address is bad): the tool servers are already running and
        # must be stopped, or they are left behind as orphaned processes.
        await gw.stop()
        raise
    if ready and not ready.done():
        ready.set_result(front)

    async def ticker() -> None:
        while True:
            await asyncio.sleep(tick_seconds)
            try:
                await gw.tick()
            except Exception:
                log.exception("background tick failed")

    tick_task = asyncio.create_task(ticker())
    try:
        await (stop.wait() if stop else asyncio.Event().wait())
    finally:
        tick_task.cancel()
        await front.close()
        await gw.stop()
    return front
