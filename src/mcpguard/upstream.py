"""Clients for upstream MCP servers: stdio subprocesses and Streamable HTTP."""

from __future__ import annotations

import asyncio
import fnmatch
import contextlib
import json
import re
import logging
import os
import shutil
import time
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Callable

from .net import local_or_https, open_url

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "mcpguard", "version": "1.0.0rc1"}
STREAM_LIMIT = 16 * 1024 * 1024  # longest single line read from a server
MAX_RESPONSE = 64 * 1024 * 1024  # most one HTTP response or event stream may carry
INIT_PARAMS = {
    "protocolVersion": PROTOCOL_VERSION,
    "capabilities": {},  # no sampling/roots/elicitation: upstreams cannot call back into the model
    "clientInfo": CLIENT_INFO,
}


class SessionExpired(Exception):
    """The HTTP server no longer recognises our session id."""


class RequestCancelled(Exception):
    """The client cancelled this request; no response should be sent."""


class UpstreamError(Exception):
    def __init__(self, error):
        if not isinstance(error, dict):  # a misbehaving server may send anything here
            error = {"code": -32603, "message": str(error)[:200]}
        code = error.get("code")
        self.error = {"code": code if isinstance(code, int) else -32603,
                      "message": str(error.get("message", "upstream error"))}
        super().__init__(self.error["message"])


class BaseUpstream:
    name: str
    server_info: dict
    capabilities: dict

    async def start(self) -> None:  # pragma: no cover
        raise NotImplementedError

    async def stop(self) -> None:  # pragma: no cover
        raise NotImplementedError

    async def request(self, method: str, params: dict | None = None, tag=None) -> dict:  # pragma: no cover
        raise NotImplementedError

    async def notify(self, method: str, params: dict | None = None) -> None:  # pragma: no cover
        raise NotImplementedError

    _tags: dict
    _cancelled: set

    async def cancel(self, tag, reason: str = "cancelled by client") -> bool:
        """Forward a client's cancellation for the request registered under ``tag``."""
        rid = self._tags.pop(tag, None)
        if rid is None:
            return False
        self._cancelled.add(rid)
        with contextlib.suppress(Exception):
            await self.notify("notifications/cancelled", {"requestId": rid, "reason": reason})
        self._on_cancel(rid)
        return True

    def _on_cancel(self, rid: int) -> None:
        pass

    @property
    def started(self) -> bool:  # pragma: no cover
        raise NotImplementedError

    @property
    def alive(self) -> bool:
        return self.started

    def diagnostics(self) -> list[str]:
        """Recent stderr lines or transport errors, for error messages."""
        return []

    async def list_all(self, method: str, key: str) -> list[dict]:
        items, cursor = [], None
        while True:
            res = await self.request(method, {"cursor": cursor} if cursor else {})
            items += res.get(key, [])
            cursor = res.get("nextCursor")
            if not cursor:
                return items

    async def list_tools(self) -> list[dict]:
        return await self.list_all("tools/list", "tools")

    def supports(self, feature: str) -> bool:
        return feature in (self.capabilities or {})


# ------------------------------------------------------------------ stdio

class Upstream(BaseUpstream):
    def __init__(self, name: str, command: str, args: list[str] | None = None,
                 env: dict[str, str] | None = None, timeout: float = 60.0,
                 on_notification: Callable[[str, dict], None] | None = None, withhold: frozenset = frozenset(),
                 pass_env: list[str] | None = None, sandbox=None):
        self.name = name
        self.withhold = withhold
        self.pass_env = pass_env or []
        self.sandbox = sandbox
        self.withheld: list[str] = []  # names held back at the last start, for the audit log
        self.command = command
        self.args = args or []
        self.env = env or {}
        self.timeout = timeout
        self.on_notification = on_notification
        self.proc: asyncio.subprocess.Process | None = None
        self._pending: dict[int, asyncio.Future] = {}
        self._next_id = 1
        self._reader: asyncio.Task | None = None
        self._stderr_task: asyncio.Task | None = None
        self._stderr: deque[str] = deque(maxlen=40)
        self._tags: dict = {}
        self._cancelled: set[int] = set()
        self.server_info: dict = {}
        self.capabilities: dict = {}
        self.log = logging.getLogger(f"mcpguard.upstream.{name}")

    @property
    def started(self) -> bool:
        return self.proc is not None

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.returncode is None

    def diagnostics(self) -> list[str]:
        return list(self._stderr)

    def _resolve_command(self) -> str:
        # On Windows, "npx" or "uvx" are .cmd shims that CreateProcess won't find by bare name.
        if self.sandbox is not None:
            return self.command  # resolved inside the container, not on this machine
        found = shutil.which(self.command, path=self.env.get("PATH") or os.environ.get("PATH"))
        if not found:
            raise FileNotFoundError(f"command not found: {self.command}")
        return found

    async def start(self):
        self._pending.clear()
        command, args = self._resolve_command(), self.args
        if self.sandbox is not None:
            runtime, args = self.sandbox.wrap(self.command, self.args, list(self.env))
            command = shutil.which(runtime)
            if not command:
                raise FileNotFoundError(f"sandbox runtime not found: {runtime}")
        self.proc = await asyncio.create_subprocess_exec(
            command, *args,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, env=self.child_env(), limit=STREAM_LIMIT,
        )
        self._reader = asyncio.create_task(self._read_loop())
        self._stderr_task = asyncio.create_task(self._drain_stderr())
        try:
            res = await self.request("initialize", INIT_PARAMS)
        except Exception as e:
            await self.stop()
            tail = "; ".join(self._stderr) or "no output on stderr"
            raise ConnectionError(f"initialize failed ({e or type(e).__name__}): {tail[-300:]}") from e
        self.server_info = res.get("serverInfo", {})
        self.capabilities = res.get("capabilities", {})
        await self.notify("notifications/initialized")

    async def _drain_stderr(self):
        if not self.proc or not self.proc.stderr:
            return
        while True:
            line = await self.proc.stderr.readline()
            if not line:
                return
            text = line.decode(errors="replace").rstrip()
            self._stderr.append(text)
            self.log.debug("%s", text)

    async def _send(self, msg: dict):
        if not self.proc or not self.proc.stdin or self.proc.returncode is not None:
            raise ConnectionError(f"upstream '{self.name}' is not running")
        try:
            self.proc.stdin.write((json.dumps(msg) + "\n").encode())
            await self.proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError) as e:
            raise ConnectionError(f"upstream '{self.name}' closed its input") from e

    async def _read_loop(self):
        if not self.proc or not self.proc.stdout:
            return
        why = f"upstream '{self.name}' exited"
        try:
            while True:
                try:
                    line = await self.proc.stdout.readline()
                except (ValueError, asyncio.LimitOverrunError):
                    # One message longer than the stream limit leaves the stream unusable, and an
                    # unhandled error here used to leave every waiting request hanging.
                    why = f"upstream '{self.name}' sent a message larger than {STREAM_LIMIT // (1024 * 1024)} MB"
                    self.log.warning("%s; stopping it", why)
                    with contextlib.suppress(ProcessLookupError, OSError):
                        self.proc.kill()
                    break
                if not line:
                    break
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                except RecursionError:
                    # Nested too deeply to parse. Fail the request it answers instead of letting this
                    # exception end the read loop, which used to cut the server off for good.
                    self._fail_unparseable(line)
                    continue
                if not isinstance(msg, dict):
                    continue
                if "id" in msg and ("result" in msg or "error" in msg):
                    fut = self._pending.pop(msg["id"], None)
                    if fut and not fut.done():
                        fut.set_result(msg)
                elif "method" in msg and "id" in msg:
                    try:
                        await self._send({"jsonrpc": "2.0", "id": msg["id"],
                                          "error": {"code": -32601, "message": "blocked by mcpguard"}})
                    except ConnectionError:
                        break
                elif "method" in msg and self.on_notification:
                    self.on_notification(self.name, msg)
        finally:
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(ConnectionError(why))
            self._pending.clear()

    def child_env(self) -> dict[str, str]:
        """What the server process is started with: the gateway's environment without
        mcpguard's own secrets (never passed) and without anything that looks like a secret
        unless ``pass_env`` names it, then the server's own ``env`` on top."""
        inherited, held = {}, []
        for k, v in os.environ.items():
            allowed = any(fnmatch.fnmatchcase(k.upper(), p.upper()) for p in self.pass_env)
            if k in self.withhold or (not allowed and looks_like_secret_env(k, v)):
                held.append(k)
            else:
                inherited[k] = v
        self.withheld = sorted(k for k in held if k not in self.env)
        return {**inherited, **self.env}

    def _fail_unparseable(self, line: bytes) -> None:
        for m in re.finditer(rb'"id"\s*:\s*(\d+)', line[:4096] + line[-4096:]):
            fut = self._pending.pop(int(m.group(1)), None)
            if fut and not fut.done():
                fut.set_result({"jsonrpc": "2.0", "id": int(m.group(1)), "error": {
                    "code": -32603, "message": "response refused by mcpguard: nested too deeply to read safely"}})
                return

    async def request(self, method: str, params: dict | None = None, tag=None) -> dict:
        rid = self._next_id
        self._next_id += 1
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[rid] = fut
        if tag is not None:
            self._tags[tag] = rid
        try:
            await self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
            msg = await asyncio.wait_for(fut, self.timeout)
        except TimeoutError:
            raise TimeoutError(f"upstream '{self.name}' did not answer {method} within {self.timeout:.0f}s") from None
        finally:
            self._pending.pop(rid, None)
            if tag is not None:
                self._tags.pop(tag, None)
        if rid in self._cancelled:
            self._cancelled.discard(rid)
            raise RequestCancelled()
        if "error" in msg:
            raise UpstreamError(msg["error"])
        result = msg.get("result")
        return result if isinstance(result, dict) else {}

    async def notify(self, method: str, params: dict | None = None):
        await self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def _on_cancel(self, rid: int) -> None:
        fut = self._pending.get(rid)
        if fut and not fut.done():
            fut.set_result({"jsonrpc": "2.0", "id": rid, "result": {}})

    async def stop(self):
        if self.proc and self.proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), 5)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    self.proc.kill()
        for task in (self._reader, self._stderr_task):
            if task:
                task.cancel()


# ------------------------------------------------------------------ Streamable HTTP

class HttpUpstream(BaseUpstream):
    """MCP Streamable HTTP client (JSON or SSE responses, session header, bearer auth)."""

    def __init__(self, name: str, url: str, headers: dict[str, str] | None = None,
                 bearer_env: str = "", timeout: float = 60.0,
                 on_notification: Callable[[str, dict], None] | None = None):
        if not local_or_https(url):
            raise ValueError(f"server '{name}': remote URLs must use https://")
        self.name = name
        self.url = url
        self.headers = dict(headers or {})
        self.bearer_env = bearer_env
        self.timeout = timeout
        self.on_notification = on_notification
        self.session_id: str | None = None
        self.protocol_version: str | None = None
        self.server_info: dict = {}
        self.capabilities: dict = {}
        self._started = False
        self._next_id = 1
        self._last_error = ""
        self._tags: dict = {}
        self._cancelled: set[int] = set()

    @property
    def started(self) -> bool:
        return self._started

    def diagnostics(self) -> list[str]:
        return [self._last_error] if self._last_error else []

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", **self.headers}
        if self.bearer_env:
            token = os.environ.get(self.bearer_env)
            if not token:
                raise RuntimeError(f"environment variable {self.bearer_env} is not set")
            h["Authorization"] = f"Bearer {token}"
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        if self.protocol_version:
            h["MCP-Protocol-Version"] = self.protocol_version
        return h

    def _post(self, msg: dict, want_id=None):
        req = urllib.request.Request(  # noqa: S310 - open_url only allows http(s)
            self.url, data=json.dumps(msg).encode(), headers=self._headers(), method="POST")
        try:
            resp = open_url(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            if e.code == 404 and self.session_id:
                raise SessionExpired(self.name) from e
            hint = {401: "unauthorized: check the bearer token", 403: "forbidden"}.get(e.code, e.reason)
            self._last_error = f"HTTP {e.code} {hint}"
            raise ConnectionError(f"upstream '{self.name}': HTTP {e.code} ({hint})") from e
        except (urllib.error.URLError, OSError) as e:
            self._last_error = str(getattr(e, "reason", e))
            raise ConnectionError(f"upstream '{self.name}': {self._last_error}") from e
        with resp:
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                self.session_id = sid
            if resp.status == 202 or want_id is None:
                return None
            ctype = resp.headers.get("Content-Type", "")
            if "text/event-stream" in ctype:
                return self._read_sse(resp, want_id)
            raw = resp.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise ConnectionError(
                    f"upstream '{self.name}': response larger than {MAX_RESPONSE // (1024 * 1024)} MB")
            try:
                body = json.loads(raw or b"null")
            except ValueError as e:
                raise ConnectionError(f"upstream '{self.name}': the response is not JSON") from e
            except RecursionError as e:
                raise UpstreamError({"code": -32603,
                                     "message": "response refused by mcpguard: nested too deeply"}) from e
            for m in body if isinstance(body, list) else [body]:
                if isinstance(m, dict) and m.get("id") == want_id:
                    return m
                if isinstance(m, dict) and "method" in m and "id" not in m and self.on_notification:
                    self.on_notification(self.name, m)
            raise ConnectionError(f"upstream '{self.name}': no response for request {want_id}")

    def _read_sse(self, resp, want_id):
        data: list[str] = []
        size = 0
        deadline = time.monotonic() + self.timeout * 10  # the socket timeout covers silence, not a slow trickle
        for raw in resp:
            size += len(raw)
            if size > MAX_RESPONSE or time.monotonic() > deadline:
                raise ConnectionError(f"upstream '{self.name}': the stream is too long or too slow")
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line.startswith("data:"):
                data.append(line[5:].lstrip())
                continue
            if line or not data:
                continue
            try:
                try:
                    m = json.loads("\n".join(data))
                except RecursionError:
                    continue
            except json.JSONDecodeError:
                m = None
            data = []
            if not isinstance(m, dict):
                continue
            if m.get("id") == want_id and ("result" in m or "error" in m):
                return m
            if "method" in m and "id" in m:  # server-initiated request: refuse
                self._post({"jsonrpc": "2.0", "id": m["id"],
                            "error": {"code": -32601, "message": "blocked by mcpguard"}})
            elif "method" in m and self.on_notification:
                self.on_notification(self.name, m)
        raise ConnectionError(f"upstream '{self.name}': stream ended without a response")

    async def request(self, method: str, params: dict | None = None, tag=None, _retry: bool = True) -> dict:
        rid = self._next_id
        self._next_id += 1
        msg = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}
        if tag is not None:
            self._tags[tag] = rid
        try:
            resp = await asyncio.wait_for(asyncio.to_thread(self._post, msg, rid), self.timeout + 5)
        except SessionExpired:
            if not _retry or method == "initialize":
                raise ConnectionError(f"upstream '{self.name}': session expired") from None
            # The server dropped our session: start a new one and replay this request once.
            self.session_id = None
            await self.start()
            return await self.request(method, params, tag, _retry=False)
        except TimeoutError:
            raise TimeoutError(f"upstream '{self.name}' did not answer {method} within {self.timeout:.0f}s") from None
        finally:
            if tag is not None:
                self._tags.pop(tag, None)
        if rid in self._cancelled:
            self._cancelled.discard(rid)
            raise RequestCancelled()
        if "error" in resp:
            raise UpstreamError(resp["error"])
        result = resp.get("result")
        return result if isinstance(result, dict) else {}

    async def notify(self, method: str, params: dict | None = None):
        await asyncio.to_thread(self._post, {"jsonrpc": "2.0", "method": method, "params": params or {}})

    async def start(self):
        res = await self.request("initialize", INIT_PARAMS)
        self.server_info = res.get("serverInfo", {})
        self.capabilities = res.get("capabilities", {})
        self.protocol_version = res.get("protocolVersion", PROTOCOL_VERSION)
        await self.notify("notifications/initialized")
        self._started = True

    async def stop(self):
        if not self.session_id:
            self._started = False
            return

        def delete():
            with contextlib.suppress(Exception):
                open_url(urllib.request.Request(  # noqa: S310 - open_url only allows http(s)
                    self.url, headers=self._headers(), method="DELETE"), timeout=5).close()
        await asyncio.to_thread(delete)
        self.session_id = None
        self._started = False


# Variable names that usually hold credentials. SSH_AUTH_SOCK is included: it grants use of the
# user's SSH keys.
_SECRET_ENV_NAME = re.compile(
    r"(?i)(TOKEN(?!IZER)|SECRET|PASSW|PASSPHRASE|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH(?!ORS?(?:_|$))|COOKIE"
    r"|SESSION_?(?:ID|KEY|TOKEN|SECRET)|_SESSION$"
    r"|_PAT$|^PAT_|WEBHOOK|DSN$|CONNECTION_?STRING|DATABASE_URL|_KEY$|^KEY_"
    r"|_PASS$|^PASS_|_SK$|PASSFILE|(?<!^)_PWD$|^[A-Z0-9]+_PWD$|^KUBECONFIG$|^NETRC$|^VAULT_(?:ADDR|NAMESPACE)$|BEARER|_PIN$)")


# A connection URL that carries a password: redis://:pass@host, https://user:pass@proxy.
_URL_WITH_PASSWORD = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^/\s:@]*:[^/\s@]+@")


def looks_like_secret_env(name: str, value: str) -> bool:
    """True for a variable whose name or value suggests a credential."""
    if _SECRET_ENV_NAME.search(name) or _URL_WITH_PASSWORD.search(value[:4096]):
        return True
    from .detect import find_secrets
    return bool(value) and len(value) < 4096 and bool(find_secrets(value, ""))


def make_upstream(spec, on_notification=None, withhold: frozenset = frozenset({"MCPGUARD_AUDIT_KEY"})) -> BaseUpstream:
    if spec.kind == "http":
        return HttpUpstream(spec.name, spec.url, spec.headers, spec.bearer_env, spec.timeout,
                            on_notification=on_notification)
    return Upstream(spec.name, spec.command, spec.args, spec.env, spec.timeout, on_notification=on_notification,
                    withhold=withhold, pass_env=spec.pass_env, sandbox=getattr(spec, "sandbox", None))
