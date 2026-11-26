"""Local dashboard: live activity, server health, tool inventory and approvals.

Runs inside the gateway process (``[dashboard] enabled = true``) or on its own
(``mcpguard dashboard``). It only reads files the gateway writes (audit log,
state snapshot, approval queue), so both modes behave the same.

Security: binds to 127.0.0.1; rejects requests whose Host header is not local
(DNS rebinding); state-changing requests need a per-install token that is
embedded in the page, which other origins cannot read.
"""

from __future__ import annotations

import hmac
import json
import threading
import time
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path

from .approvals import decide, list_pending, token_for
from .audit import ChainVerifier, load_key, segments
from .metrics import Metrics
from .modeswitch import read_override
from .state import is_live, read_merged

TIMELINE_MINUTES = 60
RECENT_EVENTS = 300
SEVERITY_ORDER = ("low", "medium", "high", "critical")


def _identity(p: Path) -> tuple[int, int]:
    st = p.stat()
    return st.st_dev, st.st_ino


class AuditIndex:
    """Incrementally folds the audit log into counters, a timeline and recent events."""

    def __init__(self, path: str | Path, key: bytes | None = None):
        self.path = Path(path)
        self.verifier = ChainVerifier(path, key=key)
        self._lock = threading.Lock()
        self._reset()

    def _reset(self) -> None:
        self.events: Counter[str] = Counter()
        self.rules: dict[str, dict] = {}
        self.recent: deque[dict] = deque(maxlen=RECENT_EVENTS)
        self.minutes: Counter[tuple[int, str]] = Counter()
        self.metrics = Metrics()
        self.total = 0
        self._seen: list[tuple[tuple[int, int], int]] = []

    def _fold(self, rec: dict) -> None:
        ev = rec.get("event", "")
        self.events[ev] += 1
        self.total += 1
        self.metrics.observe(rec)
        outcome = {"call.allowed": "allowed", "call.blocked": "blocked",
                   "call.would_block": "would_block"}.get(ev)
        if outcome:
            self.minutes[(int(rec["ts"] // 60), outcome)] += 1
        for f in rec.get("findings", []) or []:
            d = self.rules.setdefault(f["rule"], {"count": 0, "severity": f["severity"], "last": 0})
            d["count"] += 1
            d["last"] = rec["ts"]
            if SEVERITY_ORDER.index(f["severity"]) > SEVERITY_ORDER.index(d["severity"]):
                d["severity"] = f["severity"]
        self.recent.append(rec)

    def update(self) -> None:
        with self._lock:
            segs = [s for s in segments(self.path) if s.exists()]
            ids = [_identity(s) for s in segs]
            sizes = [s.stat().st_size for s in segs]
            intact = all(i < len(ids) and ids[i] == ident and sizes[i] >= done
                         for i, (ident, done) in enumerate(self._seen))
            if not intact:
                self._reset()
            for i, seg in enumerate(segs):
                if i >= len(self._seen):
                    self._seen.append((ids[i], 0))
                done = self._seen[i][1]
                if sizes[i] == done:
                    continue
                with seg.open("rb") as f:
                    f.seek(done)
                    for raw in f:
                        if not raw.endswith(b"\n"):
                            break
                        done += len(raw)
                        if raw.strip():
                            try:
                                self._fold(json.loads(raw))
                            except (ValueError, KeyError):
                                continue
                self._seen[i] = (ids[i], done)

    def timeline(self, now: float | None = None) -> list[dict]:
        end = int((now or time.time()) // 60)
        return [{"minute": m * 60,
                 "allowed": self.minutes[(m, "allowed")],
                 "blocked": self.minutes[(m, "blocked")],
                 "would_block": self.minutes[(m, "would_block")]}
                for m in range(end - TIMELINE_MINUTES + 1, end + 1)]


def _read_state(path: str) -> dict:
    return read_merged(path)


def _event_view(rec: dict) -> dict:
    keep = ("seq", "ts", "event", "tool", "server", "client", "reason", "error", "approved", "latency_ms",
            "severity", "mode", "direction", "args_hash", "hash", "prev", "alg", "servers_added",
            "servers_removed", "remember_until", "forwarded")
    view = {k: rec[k] for k in keep if k in rec}
    if rec.get("findings"):
        view["findings"] = rec["findings"][:8]
    return view


def build_state(cfg, index: AuditIndex) -> dict:
    index.update()
    ok, message = index.verifier.check()
    snap = _read_state(cfg.state_path)
    running = is_live(snap)
    baseline: dict = {}
    if Path(cfg.baseline_path).exists():
        from .anomaly import Baselines
        baseline = Baselines(cfg.baseline_path).summary()
    ev = index.events
    return {
        "gateway": {"running": running, "mode": snap.get("mode", cfg.mode), "version": snap.get("version"),
                    "mode_source": str(snap.get("mode_source", "config"))[:60],
                    "config_mode": snap.get("config_mode", cfg.mode),
                    "wanted_mode": (read_override(cfg.approvals_dir) or {}).get("mode"),
                    "started_at": snap.get("started_at"), "updated_at": snap.get("updated_at"),
                    "config": cfg.source, "processes": snap.get("processes", 1 if running else 0)},
        "integrity": {"ok": ok, "message": message, "records": index.total},
        "counts": {
            "allowed": ev["call.allowed"], "blocked": ev["call.blocked"], "would_block": ev["call.would_block"],
            "quarantined": sum(v for k, v in ev.items() if k.endswith(".quarantined")),
            "approvals": ev["call.approval"],
        },
        "timeline": index.timeline(),
        "events": [_event_view(r) for r in reversed(index.recent)],
        "rules": index.rules,
        "servers": snap.get("servers", []),
        "inventory": snap.get("inventory", []),
        "pending": list_pending(cfg.approvals_dir),
        "grants": [g for g in snap.get("grants", []) if g.get("until", 0) > time.time()],
        "remember_minutes": cfg.approval_remember_minutes,
        "baselines": baseline,
        "now": time.time(),
    }


def _page(token: str) -> bytes:
    html = resources.files("mcpguard").joinpath("dashboard.html").read_text(encoding="utf-8")
    return html.replace("__MCPGUARD_TOKEN__", token).encode()


def make_server(cfg, port: int | None = None) -> ThreadingHTTPServer:
    port = cfg.dashboard_port if port is None else port
    token = token_for(cfg.approvals_dir)
    page = _page(token)
    index = AuditIndex(cfg.audit_path, load_key(cfg.audit_key_file) if cfg.audit_sign else None)

    class Handler(BaseHTTPRequestHandler):
        server_version = "mcpguard"
        timeout = 30  # a client that stops sending must not hold a thread for ever
        sys_version = ""

        def log_message(self, *args):  # stdout carries MCP; never print request logs
            pass

        def _host_ok(self) -> bool:
            raw = self.headers.get("Host") or ""
            host = raw.rsplit(":", 1)[0].strip("[]") if raw.count(":") <= 1 or raw.startswith("[") else raw.strip("[]")
            return bool(raw) and host in ("127.0.0.1", "localhost", "::1")

        def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                             "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj) -> None:
            self._send(code, json.dumps(obj, default=str).encode())

        def do_GET(self):
            if not self._host_ok():
                return self._json(403, {"error": "requests must use localhost"})
            if self.path in ("/", "/index.html"):
                return self._send(200, page, "text/html; charset=utf-8")
            if self.path == "/metrics":
                index.update()
                snap = _read_state(cfg.state_path)
                servers = snap.get("servers", [])
                text = index.metrics.render({
                    "mcpguard_servers_up": ("Upstream servers currently up.",
                                            sum(s.get("status") == "up" for s in servers)),
                    "mcpguard_servers": ("Configured upstream servers.", len(servers)),
                    "mcpguard_approvals_pending": ("Approval requests waiting.", len(list_pending(cfg.approvals_dir))),
                    "mcpguard_audit_records": ("Records in the audit log.", index.total),
                })
                return self._send(200, text.encode(), "text/plain; version=0.0.4; charset=utf-8")
            if self.path == "/api/state":
                try:
                    return self._json(200, build_state(cfg, index))
                except Exception as e:  # noqa: BLE001 - surface errors to the page, never crash the thread
                    return self._json(500, {"error": f"could not read gateway files: {e}"})
            if self.path == "/api/coverage":
                try:
                    from . import advisories
                    from .config import load_config
                    # Re-read the config so the view follows edits made while the dashboard runs.
                    live = load_config(cfg.source) if Path(cfg.source).exists() else cfg
                    return self._json(200, advisories.coverage(live))
                except Exception as e:  # noqa: BLE001 - an invalid edit must not take the page down
                    return self._json(500, {"error": f"could not work out coverage: {e}"})
            self._json(404, {"error": "not found"})

        def do_POST(self):
            given = (self.headers.get("X-Token") or "").encode("utf-8", "surrogateescape")
            if not token or not self._host_ok() or not hmac.compare_digest(given, token.encode()):
                return self._json(403, {"error": "forbidden"})
            if self.path == "/api/mode":
                return self._set_mode()
            if self.path != "/api/decide":
                return self._json(404, {"error": "not found"})
            try:
                length = max(0, min(int(self.headers.get("Content-Length") or 0), 4096))
                body = json.loads(self.rfile.read(length) or b"{}")
                if body["approved"] not in (True, False):  # "false" is a string, and a string is true
                    raise ValueError("approved must be true or false")
                remember = min(int(body.get("remember_minutes") or 0), cfg.approval_remember_minutes)
                ok = decide(cfg.approvals_dir, str(body["id"]), body["approved"], remember)
            except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
                return self._json(400, {"error": "expected {id, approved}"})
            if not ok:
                return self._json(404, {"error": "that request is no longer waiting"})
            self._json(200, {"ok": True})

        def _set_mode(self):
            from .modeswitch import MODES, set_override
            try:
                length = max(0, min(int(self.headers.get("Content-Length") or 0), 1024))
                body = json.loads(self.rfile.read(length) or b"{}")
                mode = body["mode"]
                if mode not in MODES:
                    raise ValueError("mode must be monitor or enforce")
                set_override(cfg.approvals_dir, mode, "dashboard")
            except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
                return self._json(400, {"error": "expected {mode: \"monitor\" or \"enforce\"}"})
            except OSError:
                return self._json(500, {"error": "could not save the choice"})
            self._json(200, {"ok": True, "mode": mode})

    class _Server(ThreadingHTTPServer):
        request_queue_size = 128  # the default of 5 drops connections when a page fires several requests at once

    srv = _Server(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    return srv


def start_background(cfg) -> ThreadingHTTPServer | None:
    try:
        srv = make_server(cfg)
    except OSError:
        return None
    threading.Thread(target=srv.serve_forever, name="mcpguard-dashboard", daemon=True).start()
    return srv
