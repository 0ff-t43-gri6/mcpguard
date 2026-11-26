"""The gateway: one MCP server facing the client, many upstream servers behind it.

Request path for tools/call, prompts/get and resources/read (``_guarded``):

    quarantine -> policy (allow/deny/ask, argument conditions) -> budget
    -> argument scan and exfiltration check -> upstream call
    -> result scan, taint tracking, baseline check -> redaction/truncation -> audit

Runtime behaviour:
- The config file is watched. A valid edit is applied in place (policy, detectors,
  approvals, mode, servers); an invalid one is rejected and logged.
- Each upstream is supervised. A crashed or unreachable server is restarted with
  exponential backoff, and its catalog is re-scanned when it comes back.
- The client is notified when the visible tools, prompts or resources change.
- A JSON snapshot of server health and the tool inventory is written for the dashboard.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any
from collections import OrderedDict
from dataclasses import asdict, dataclass, field

from . import __version__, dlp
from .alerts import Alerter
from .forward import Forwarder
from .anomaly import Baselines
from . import advisories
from .approvals import Approvals, Verdict, load_grants, save_grant
from .trust import digest_bytes, digest_of, is_trusted_digest
from .audit import (KEY_ENV, AuditLog, append_checkpoint, check_checkpoints, has_signed_records, load_key,
                    make_checkpoint, read_checkpoints, verify)
from .config import Config, ConfigError, load_config
from .checks import CATALOG, cross_server_names
from .flows import FlowTracker
from .detect import (
    MAX_DEPTH, Engine, _scrub, Finding, PinStore, SessionTaint, at_least, cross_tool_references, json_depth,
    is_egress_tool, max_severity, texts_of,
)
from .policy import ALLOW, ASK, DENY, Decision, own_files_problem, scope_violation
from .schema import validate as validate_schema
from .state import process_state_path
from .upstream import BaseUpstream, RequestCancelled, UpstreamError, make_upstream

log = logging.getLogger("mcpguard")
_RULE_SUMMARIES = {c.rule: c.summary for c in CATALOG}
SCAN_LIMIT = 1_000_000  # characters scanned and passed on per text when max_result_chars = 0
MAX_CATALOG = 2000  # tools, prompts or resources taken from one server
MAX_ARGS_CHARS = 4_000_000  # arguments of one call, as JSON

SEP = "__"
SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
LIST_CHANGED = {
    "tools": "notifications/tools/list_changed",
    "prompts": "notifications/prompts/list_changed",
    "resources": "notifications/resources/list_changed",
}
MAX_BACKOFF = 60.0


@dataclass(frozen=True)
class Caller:
    """Who is making a request: a configured client name and its session."""

    client: str = "stdio"
    session: str = "stdio"


STDIO = Caller()


def _sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:16]


@dataclass
class ServerState:
    name: str
    kind: str
    status: str = "starting"          # starting | up | down | disabled
    last_error: str = ""
    restarts: int = 0
    failures: int = 0
    next_retry: float = 0.0
    since: float = field(default_factory=time.time)

    def set(self, status: str, error: str = "") -> bool:
        changed = status != self.status
        if changed:
            self.since = time.time()
        self.status, self.last_error = status, error
        return changed


class Gateway:
    def __init__(self, config: Config, upstreams: dict[str, BaseUpstream] | None = None,
                 approver=None, notify_client=None, require_trusted_reload: bool = False):
        self.cfg = config
        # When set (the command line sets it), a changed config is reloaded only if its exact contents were
        # trusted with `mcpguard trust`. A tool or a program that can write the file cannot change a running
        # gateway's rules, servers or mode by editing it.
        self.require_trusted_reload = require_trusted_reload
        self._running_digest = digest_of(config.source) if config.source else ""
        self._reload_refused = False
        if (config.audit_sign and not os.environ.get(KEY_ENV) and config.audit_key_file
                and not Path(config.audit_key_file).exists() and has_signed_records(config.audit_path)):
            raise ConfigError(
                f"the audit log {config.audit_path} holds signed records but its key {config.audit_key_file} is "
                "missing (was the project folder moved or copied?). A new key would make every old record fail "
                "verification. Put the old key back, or set [audit] key_file to it; to start over on purpose, "
                "run 'mcpguard audit-new'.")
        key = load_key(config.audit_key_file, create=True) if config.audit_sign else None
        self.audit = AuditLog(config.audit_path, config.audit_rotate_bytes, key)
        self.alerter: Alerter | None = None
        self.forwarder: Forwarder | None = None
        self._tamper: str | None = None  # why the gateway stopped acting, until the operator clears it
        self._tamper_ts = 0.0
        self._last_verify = time.monotonic()
        self._configure_alerts(config)
        self._configure_forward(config)
        self.grants: dict[tuple[str, str], float] = {}  # (client, target) -> expiry (epoch seconds)
        self._inflight: dict[tuple[str, object], str] = {}  # (session, request id) -> server
        self.pins = PinStore(config.pins_path)
        self.flows = FlowTracker(config.flows)
        self.taint = SessionTaint(entropy_threshold=config.detectors.entropy_threshold)
        self.pii_seen: OrderedDict[str, str] = OrderedDict()  # normalised personal data -> tool that returned it
        self._advised: dict[str, list[str]] = {}  # advisory notes already logged, per server
        self.pii_pieces = dlp.PieceTracker()
        self.notify_client = notify_client
        self._custom_approver = approver
        self.policy = config.policy
        self.engine = Engine(config.detectors)
        self.approver = approver or Approvals(config.approval_mode, config.approvals_dir, config.approval_timeout,
                                              config.approval_remember_minutes)
        self.baselines = Baselines(config.baseline_path, config.anomaly_min_samples, config.anomaly_z)

        specs = {s.name: s for s in config.servers}
        self.upstreams: dict[str, BaseUpstream] = upstreams if upstreams is not None else {
            n: make_upstream(s, self._on_upstream_note, config.secret_env | {"MCPGUARD_AUDIT_KEY"})
            for n, s in specs.items() if s.enabled}
        self._specs = {n: s.key() for n, s in specs.items()}
        self.servers: dict[str, ServerState] = {
            n: ServerState(n, s.kind, "starting" if s.enabled else "disabled") for n, s in specs.items()}
        for n in self.upstreams:
            self.servers.setdefault(n, ServerState(n, "custom"))

        self.tools: dict[str, tuple[str, dict]] = {}
        self.prompts: dict[str, tuple[str, dict]] = {}
        self.resources: dict[str, tuple[str, dict]] = {}
        self.templates: list[tuple[str, dict]] = []
        self.quarantined: dict[str, tuple[str, list[Finding]]] = {}
        self._finding_sigs: dict[str, str] = {}
        self._dirty = False
        self._signature: dict[str, str] = {}
        self._mtime = os.path.getmtime(config.source) if config.source else None
        self._refresh_lock = asyncio.Lock()
        self._started_at = time.time()
        self._last_state_write = 0.0
        self._last_checkpoint = time.monotonic()
        self._file_mode = config.mode      # what the config file says; a switch from the dashboard sits on top
        self.mode_source = "config"

    # ------------------------------------------------------------ config

    def _own_paths(self) -> list[str]:
        """Files and folders mcpguard itself uses: a tool has no business reading or changing them."""
        from .trust import trust_file
        c = self.cfg
        paths = [c.source, c.audit_path, c.audit_key_file, c.checkpoint_path, c.pins_path, c.state_path,
                 c.baseline_path, c.approvals_dir, str(trust_file().parent)]
        paths += [str(Path(c.audit_path).parent / "audit-archive")]
        return [str(Path(p).resolve()) for p in paths if p]

    def _configure_forward(self, cfg: Config) -> None:
        old = self.forwarder
        if old and old.url == cfg.forward_url and old.audit_path == Path(cfg.audit_path):
            return
        if old:
            with contextlib.suppress(ValueError):
                self.audit.listeners.remove(old)
            old.close()
        self.forwarder = Forwarder(cfg.forward_url, cfg.audit_path, key=self.audit.key) if cfg.forward_url else None
        if self.forwarder:
            self.audit.listeners.append(self.forwarder)

    # ---------------------------------------------------------------- log integrity

    def _flag_tamper(self, detail: str) -> None:
        if self._tamper == detail:
            return
        self._tamper, self._tamper_ts = detail, time.time()
        log.error("audit log tampering: %s", detail)
        # Written to whatever file is there now, and (through the listeners) sent to the alert
        # webhook and the forwarder, which an attacker on this machine cannot reach back into.
        self.audit.write("audit.tampered", detail=detail, action=self.cfg.audit_on_tamper)

    def _log_was_archived_since(self, ts: float) -> bool:
        """`mcpguard audit-new` started a fresh log after the tampering was flagged."""
        try:
            with Path(self.cfg.audit_path).open("rb") as f:
                first = json.loads(f.readline() or b"{}")
        except (OSError, ValueError):
            return False
        return isinstance(first, dict) and bool(first.get("archived")) and float(first.get("ts", 0)) >= ts

    async def _check_log(self) -> None:
        if self._tamper:
            if self._log_was_archived_since(self._tamper_ts):
                self.audit.write("audit.tamper_cleared", previous=self._tamper)
                self._tamper = None
            return
        problem = self.audit.check_intact()
        every = self.cfg.audit_verify_minutes * 60
        if not problem and every and time.monotonic() - self._last_verify >= every:
            self._last_verify = time.monotonic()
            problem = await asyncio.to_thread(self._full_check)
        if problem:
            self._flag_tamper(problem)

    def _full_check(self) -> str | None:
        """Verify the whole chain and the checkpoints; a failure is confirmed once more before it counts."""
        for attempt in (0, 1):
            ok, msg = verify(self.cfg.audit_path, self.audit.key)
            if ok and self.cfg.checkpoint_path and Path(self.cfg.checkpoint_path).exists():
                try:
                    ok, msg = check_checkpoints(self.cfg.audit_path, read_checkpoints(self.cfg.checkpoint_path),
                                                self.audit.key)
                except (OSError, ValueError) as e:
                    ok, msg = False, f"checkpoint file unreadable: {e}"
            if ok:
                return None
            if attempt == 0:
                time.sleep(1.0)
        return msg

    def _configure_alerts(self, cfg: Config) -> None:
        old = self.alerter
        if old and (old.url, list(old.events), old.min_interval) == (cfg.alert_url, cfg.alert_events,
                                                                     cfg.alert_interval):
            return
        if old:
            self.audit.listeners.remove(old)
            old.close()
        self.alerter = Alerter(cfg.alert_url, cfg.alert_events, cfg.alert_interval) if cfg.alert_url else None
        if self.alerter:
            self.audit.listeners.append(self.alerter)

    def _swap_config(self, cfg: Config) -> None:
        """Build every new component first, then swap, so a failure leaves the old ones intact."""
        engine = Engine(cfg.detectors)
        approver = self._custom_approver or Approvals(cfg.approval_mode, cfg.approvals_dir, cfg.approval_timeout,
                                                       cfg.approval_remember_minutes)
        policy = cfg.policy
        policy.inherit_counters(self.policy)
        if cfg.baseline_path != self.cfg.baseline_path:
            self.baselines.save()
            self.baselines = Baselines(cfg.baseline_path, cfg.anomaly_min_samples, cfg.anomaly_z)
        else:
            self.baselines.min_samples, self.baselines.z = cfg.anomaly_min_samples, cfg.anomaly_z
        self.cfg, self.policy, self.engine, self.approver = cfg, policy, engine, approver
        self.flows.set_rules(cfg.flows)
        self._file_mode = cfg.mode
        self._apply_mode(announce=False)
        self.audit.max_bytes = cfg.audit_rotate_bytes
        self._configure_alerts(cfg)
        self._configure_forward(cfg)

    def _apply_mode(self, announce: bool = True) -> bool:
        """Use the monitor/enforce choice saved by the dashboard or `mcpguard mode`, else the config's mode."""
        from .modeswitch import read_override
        saved = read_override(self.cfg.approvals_dir)
        want, source = (saved["mode"], f"switch ({saved['by']})") if saved else (self._file_mode, "config")
        self.mode_source = source
        if want == self.cfg.mode:
            return False
        before = self.cfg.mode
        self.cfg = dataclasses.replace(self.cfg, mode=want)
        self._dirty = True  # definitions are admitted or quarantined by mode: look again
        if announce:
            self.audit.write("mode.changed", before=before, after=want, source=source)
            log.warning("mode changed from %s to %s (%s)", before, want, source)
        return True

    async def maybe_reload(self) -> bool:
        if not self.cfg.source:
            return False
        try:
            mtime = os.path.getmtime(self.cfg.source)
        except OSError:
            return False
        if mtime == self._mtime and not self._reload_refused:
            return False
        self._mtime = mtime
        try:
            raw = Path(self.cfg.source).read_bytes()  # read once: what is checked is what is loaded
        except OSError:
            return False
        digest = digest_bytes(raw)
        if digest == self._running_digest:
            self._reload_refused = False
            return False  # touched, but the contents are what is already running
        if self.require_trusted_reload and not is_trusted_digest(self.cfg.source, digest):
            if not self._reload_refused:  # say it once, then wait quietly until it is trusted or reverted
                self._reload_refused = True
                self.audit.write("config.reload_refused", reason="the changed config has not been trusted",
                                 digest=digest[:16])
                log.warning("config changed on disk but not reloaded: run 'mcpguard trust' to accept it")
            return False
        self._reload_refused = False
        try:
            new = load_config(self.cfg.source, source_bytes=raw)
            self._swap_config(new)
            self._running_digest = digest
        except (ConfigError, Exception) as e:  # noqa: BLE001 - any failure must keep the old config
            log.warning("config reload rejected: %s", e)
            self.audit.write("config.reload_failed", error=self._safe(e))
            return False
        added, removed = await self._sync_servers(new)
        self.audit.write("config.reloaded", mode=new.mode, servers_added=added, servers_removed=removed)
        log.info("config reloaded (mode=%s, added=%s, removed=%s)", new.mode, added, removed)
        await self.refresh()
        return True

    async def _sync_servers(self, cfg: Config) -> tuple[list[str], list[str]]:
        wanted = {s.name: s for s in cfg.servers}
        changed = [n for n, s in wanted.items() if n in self._specs and s.key() != self._specs[n]]
        gone = [n for n in self.servers if n not in wanted]
        toggled = [n for n, s in wanted.items()
                   if n in self.servers and (self.servers[n].status == "disabled") == s.enabled]
        for n in {*gone, *changed, *toggled}:
            up = self.upstreams.pop(n, None)
            if up:
                await up.stop()
            if n in gone:
                self.servers.pop(n, None)
                self._specs.pop(n, None)
        added = []
        for n, spec in wanted.items():
            self._specs[n] = spec.key()
            if not spec.enabled:
                self.servers[n] = ServerState(n, spec.kind, "disabled")
                continue
            if n in self.upstreams:
                continue
            self.upstreams[n] = make_upstream(spec, self._on_upstream_note, cfg.secret_env | {"MCPGUARD_AUDIT_KEY"})
            state = self.servers.get(n)
            if state is None or n in changed or n in toggled:
                self.servers[n] = ServerState(n, spec.kind)
                added.append(n)
            await self._start_one(n)
        return added, gone

    # ------------------------------------------------------------ supervision

    async def _start_one(self, name: str) -> bool:
        up, state = self.upstreams[name], self.servers[name]
        spec = next((sv for sv in self.cfg.servers if sv.name == name), None)
        known = advisories.check_launch(name, spec.command, spec.args, spec.url) if spec else []
        if self._refuse_server(name, state, known):
            return False
        try:
            if not up.alive:
                await up.start()
        except Exception as e:  # noqa: BLE001 - report every start failure the same way
            state.failures += 1
            delay = min(MAX_BACKOFF, 2.0 ** (state.failures - 1))
            state.next_retry = time.monotonic() + delay
            if state.set("down", self._safe(e)) or state.failures == 1:
                self.audit.write("server.failed", server=name, error=state.last_error, retry_in=delay)
            log.warning("server %s failed to start: %s (retrying in %.0fs)", name, state.last_error, delay)
            return False
        reported = advisories.check_server_info(name, getattr(up, "server_info", None))
        if self._refuse_server(name, state, reported):
            await up.stop()
            return False
        notes = [f for f in [*known, *reported] if f.severity != "critical"]
        if notes and self._advised.get(name) != [f.message for f in notes]:
            self._advised[name] = [f.message for f in notes]
            self.audit.write("server.advisory", server=name, findings=[f.to_dict() for f in notes])
            for f in notes:
                log.warning("server %s: %s", name, f.message)
        if state.status == "down":
            state.restarts += 1
        state.failures = 0
        state.set("up")
        withheld = getattr(up, "withheld", [])
        self.audit.write("server.start", server=name, info=up.server_info,
                         **({"env_withheld": withheld} if withheld else {}))
        if withheld:
            log.info("server %s: withheld %d secret-looking environment variables (%s); "
                     "list any it needs in pass_env", name, len(withheld), ", ".join(withheld[:10]))
        log.info("server %s is up", name)
        return True

    def _refuse_server(self, name: str, state, findings) -> bool:
        """Do not run a server that matches a known malicious campaign (enforce mode)."""
        bad = [f for f in findings if f.rule == "advisory.malicious"]
        if not bad:
            return False
        first = state.set("down", f"refused: {bad[0].message}")
        state.failures += 1
        state.next_retry = time.monotonic() + MAX_BACKOFF
        if self.cfg.mode != "enforce":
            if first:
                self.audit.write("server.would_refuse", server=name, findings=[f.to_dict() for f in bad])
            return False
        if first:
            self.audit.write("server.refused", server=name, findings=[f.to_dict() for f in bad])
            log.warning("server %s was not started: %s", name, bad[0].message)
        return True

    async def _check_health(self) -> bool:
        """Detect exits and retry failed servers. Returns True if the catalog may have changed."""
        changed = False
        now = time.monotonic()
        for name, up in list(self.upstreams.items()):
            state = self.servers[name]
            if state.status == "up" and not up.alive:
                detail = "; ".join(up.diagnostics()[-3:])
                state.set("down", self._safe(f"exited unexpectedly. {detail}".strip()))
                state.failures, state.next_retry = 1, now + 1.0
                self.audit.write("server.exited", server=name, error=state.last_error)
                log.warning("server %s exited: %s", name, state.last_error)
                changed = True
            elif state.status in ("down", "starting") and now >= state.next_retry:
                changed |= await self._start_one(name)
        return changed

    def _mark_failed_call(self, server: str, error: Exception) -> None:
        up, state = self.upstreams.get(server), self.servers.get(server)
        if up and state and state.status == "up" and not up.alive:
            state.set("down", self._safe(error))
            state.failures, state.next_retry = 1, time.monotonic() + 1.0
            self.audit.write("server.exited", server=server, error=state.last_error)

    async def start(self) -> None:
        self._apply_mode(announce=False)
        for name in self.upstreams:
            await self._start_one(name)
        await self.refresh()
        self.checkpoint()  # anchor what is already in the log before any traffic arrives

    async def stop(self) -> None:
        for up in self.upstreams.values():
            with contextlib.suppress(Exception):
                await up.stop()
        self.pins.save()
        self.baselines.save()
        self._write_state(stopped=True)
        self.checkpoint()
        if self.alerter:
            self.alerter.close()
        if self.forwarder:
            self.forwarder.close()

    def _on_upstream_note(self, server: str, msg: dict) -> None:
        if msg.get("method", "").endswith("/list_changed"):
            # Record it once per refresh: a server sending these in a loop must not fill the disk.
            if not self._dirty:
                self.audit.write("upstream.list_changed", server=server, method=msg["method"])
            self._dirty = True

    # ------------------------------------------------------------ discovery

    async def refresh(self) -> None:
        async with self._refresh_lock:
            await self._refresh()

    async def _refresh(self) -> None:
        self._dirty = False
        self.pins.reload()  # a `pins forget` takes effect at the next listing, without a restart
        tools: dict = {}
        prompts: dict = {}
        resources: dict = {}
        templates: list = []
        quarantined: dict = {}
        for server, up in list(self.upstreams.items()):
            if self.servers[server].status != "up":
                # Keep the last known catalog so the model's view stays stable while it restarts.
                for bucket, old in ((tools, self.tools), (prompts, self.prompts), (resources, self.resources)):
                    bucket.update({k: v for k, v in old.items() if v[0] == server})
                quarantined.update({k: v for k, v in self.quarantined.items() if v[0] == server})
                templates += [t for t in self.templates if t[0] == server]
                continue
            await self._discover_tools(server, up, tools, quarantined)
            if up.supports("prompts"):
                await self._discover(server, up, "prompts", "prompt", prompts, quarantined)
            if up.supports("resources"):
                await self._discover(server, up, "resources", "resource", resources, quarantined)
                templates += await self._discover_templates(server, up)
        self.tools, self.prompts, self.resources = tools, prompts, resources
        self.templates, self.quarantined = templates, quarantined
        catalog: dict[str, list[str]] = {}
        for q, (server, _item) in [*tools.items(), *((k, v) for k, v in quarantined.items() if SEP in k)]:
            catalog.setdefault(server, []).append(q.split(SEP, 1)[1])
        by_server: dict[str, list[dict]] = {}
        for server, item in tools.values():
            by_server.setdefault(server, []).append(item)
        self._record_findings("*", "catalog", self.engine.finalize(
            cross_server_names(catalog) + cross_tool_references(by_server)))
        self.pins.save()
        self._record_first_seen()
        self._write_state()
        await self._announce_changes()

    def _record_findings(self, server: str, kind: str, findings: list[Finding]) -> None:
        """Audit non-blocking definition findings once, not on every re-scan."""
        sig = _sha([f.to_dict() for f in findings])
        key = f"{server}/{kind}"
        if findings and self._finding_sigs.get(key) != sig:
            self.audit.write(f"{kind}s.findings", server=server, findings=[f.to_dict() for f in findings])
        self._finding_sigs[key] = sig

    def _admit(self, server, item, kind, q, findings, bucket, quarantined) -> list[Finding]:
        """Quarantine an item with blocking findings; return the findings that did not block."""
        bad = at_least(findings, self.cfg.static_block_severity)
        if bad:
            sig_key = f"{server}/{kind}:{q}"
            sig = _sha([f.to_dict() for f in bad])
            if self._finding_sigs.get(sig_key) != sig:
                self.audit.write(f"{kind}.quarantined", server=server, tool=item.get("name") or item.get("uri"),
                                 mode=self.cfg.mode, findings=[f.to_dict() for f in bad])
                self._finding_sigs[sig_key] = sig
            if self.cfg.mode == "enforce":
                quarantined[q] = (server, bad)
                return [f for f in findings if f not in bad]
        bucket[q] = (server, item)
        return [f for f in findings if f not in bad]

    def _record_first_seen(self) -> None:
        """Definitions trusted on sight are written to the audit log, so 'what did I trust without
        looking' always has an answer; held ones are listed by `mcpguard pins pending`."""
        keys = self.pins.take_first_seen()
        if keys:
            self.audit.write("pins.first_seen", count=len(keys), keys=sorted(keys)[:200])

    def _capped(self, server: str, kind: str, items) -> list:
        """At most MAX_CATALOG well-formed entries: a server listing 50,000 tools must not stall
        every other server's refresh."""
        items = [it for it in items if isinstance(it, dict)] if isinstance(items, list) else []
        if len(items) > MAX_CATALOG:
            key = f"{server}/{kind}:oversized"
            if self._finding_sigs.get(key) != str(len(items)):
                self._finding_sigs[key] = str(len(items))
                self.audit.write("catalog.truncated", server=server, kind=kind, offered=len(items), kept=MAX_CATALOG)
                log.warning("server %s offers %d %ss; only the first %d are used", server, len(items), kind,
                            MAX_CATALOG)
            items = items[:MAX_CATALOG]
        return items

    async def _discover_templates(self, server, up) -> list:
        """Resource templates, with their descriptions scanned like any other definition."""
        try:
            raw = self._capped(server, "template", await up.list_all("resources/templates/list",
                                                                     "resourceTemplates"))
        except Exception:  # noqa: BLE001 - templates are optional; a server without them is fine
            return []
        kept, minor = [], []
        for t in raw:
            if not isinstance(t.get("uriTemplate"), str) or not t["uriTemplate"]:
                continue
            findings = self.engine.scan_definition({**t, "name": str(t.get("name") or t["uriTemplate"])}, server,
                                                   "resource")
            bad = at_least(findings, self.cfg.static_block_severity)
            if bad:
                key = f"{server}/template:{t['uriTemplate']}"
                sig = _sha([f.to_dict() for f in bad])
                if self._finding_sigs.get(key) != sig:
                    self._finding_sigs[key] = sig
                    self.audit.write("resource.quarantined", server=server, tool=t["uriTemplate"],
                                     mode=self.cfg.mode, findings=[f.to_dict() for f in bad])
                if self.cfg.mode == "enforce":
                    continue
            minor += [f for f in findings if f not in bad]
            kept.append((server, t))
        self._record_findings(server, "template", minor)
        return kept

    async def _discover_tools(self, server, up, out, quarantined) -> None:
        try:
            # A name that is not a non-empty string cannot be called or pinned; drop the entry.
            raw = [t for t in self._capped(server, "tool", await up.list_tools())
                   if isinstance(t.get("name"), str) and t["name"]]
            raw = list({t["name"]: t for t in reversed(raw)}.values())[::-1]  # first of each name wins
        except Exception as e:  # noqa: BLE001 - a failing server must not take the gateway down
            self.audit.write("tools.list_failed", server=server, error=self._safe(e))
            return
        per_tool: dict[str, list[Finding]] = {t["name"]: self.engine.scan_definition(t, server) for t in raw}
        for t in raw:
            pin = self.pins.check(server, t, hold_new=self.cfg.pins_first_seen == "approve")
            if pin:
                per_tool[t["name"]].append(pin)
        minor = self.pins.removed(server, {t["name"] for t in raw})
        for t in raw:
            minor += self._admit(server, t, "tool", f"{server}{SEP}{t['name']}", per_tool[t["name"]],
                                 out, quarantined)
        self._record_findings(server, "tool", minor)

    async def _discover(self, server, up, plural, kind, out, quarantined) -> None:
        try:
            items = self._capped(server, kind, await up.list_all(f"{plural}/list", plural))
        except Exception as e:  # noqa: BLE001 - a failing server must not take the gateway down
            self.audit.write(f"{plural}.list_failed", server=server, error=self._safe(e))
            return
        minor: list[Finding] = []
        for it in items:
            name = it.get("name") if kind == "prompt" else it.get("uri")
            if not isinstance(name, str) or not name:
                continue
            findings = self.engine.scan_definition(it, server, kind)
            pin = self.pins.check(server, {**it, "name": name}, kind,
                                  hold_new=self.cfg.pins_first_seen == "approve")
            if pin:
                findings.append(pin)
            q = f"{server}{SEP}{name}" if kind == "prompt" else name
            if kind == "resource" and (q in out or q in quarantined):
                self.audit.write("resource.collision", uri=q, servers=[(out.get(q) or quarantined[q])[0], server])
                continue
            minor += self._admit(server, it, kind, q, findings, out, quarantined)
        self._record_findings(server, kind, minor)

    async def _announce_changes(self) -> None:
        sig = {
            "tools": _sha(sorted(t["name"] for t in self._visible_tools())),
            "prompts": _sha(sorted(p["name"] for p in self._visible_prompts())),
            "resources": _sha(sorted(r["uri"] for r in self._visible_resources())),
        }
        changed = [k for k in sig if self._signature and sig[k] != self._signature.get(k)]
        self._signature = sig
        if self.notify_client:
            for k in changed:
                await self.notify_client({"jsonrpc": "2.0", "method": LIST_CHANGED[k]})

    def checkpoint(self) -> dict | None:
        """Append a checkpoint of the audit head to the configured external file."""
        self._last_checkpoint = time.monotonic()
        if not self.cfg.checkpoint_path:
            return None
        cp = make_checkpoint(self.cfg.audit_path, self.audit.key)
        if cp is None:
            return None
        try:
            append_checkpoint(self.cfg.checkpoint_path, cp)
        except OSError as e:
            log.warning("could not write checkpoint to %s: %s", self.cfg.checkpoint_path, e)
            return None
        if self.cfg.witness_url:
            self._send_witness(cp)
        return cp

    def _send_witness(self, cp: dict) -> None:
        """Send the checkpoint to the witness server on a thread: a slow server must not stall calls."""
        import threading
        import urllib.request

        from .net import open_url
        url, body = self.cfg.witness_url, json.dumps(cp, sort_keys=True).encode()

        def post() -> None:
            req = urllib.request.Request(url, data=body, method="POST",  # noqa: S310 - open_url checks the scheme
                                         headers={"Content-Type": "application/json", "User-Agent": "mcpguard"})
            try:
                open_url(req, timeout=10).close()
            except Exception as e:  # noqa: BLE001 - best effort; the local checkpoint is already written
                log.warning("witness %s did not accept the checkpoint: %s", url, e)

        threading.Thread(target=post, name="mcpguard-witness", daemon=True).start()

    async def tick(self) -> None:
        """Periodic work: config reload, health checks, checkpoints, re-scan after upstream changes."""
        if self.cfg.checkpoint_path and \
                time.monotonic() - self._last_checkpoint >= self.cfg.checkpoint_minutes * 60:
            self.checkpoint()
        self._apply_mode()
        reloaded = await self.maybe_reload()
        health_changed = await self._check_health()
        if (self._dirty or health_changed) and not reloaded:
            await self.refresh()
        else:
            self._write_state(heartbeat=True)  # lets the dashboard tell a live gateway from a stopped one

    # ------------------------------------------------------------ dashboard snapshot

    def inventory(self) -> list[dict]:
        rows = []
        for q, (server, t) in sorted(self.tools.items()):
            d = self.policy.evaluate(f"{server}/{t['name']}")
            conditional = self.policy.conditional(f"{server}/{t['name']}")
            status = {"allow": "allowed", "deny": "denied", "ask": "ask"}[d.action]
            rows.append({"server": server, "name": t["name"], "qualified": q, "kind": "tool",
                         "status": status, "conditional": conditional, "reason": d.reason})
        for q, (server, findings) in sorted(self.quarantined.items()):
            rows.append({"server": server, "name": q.split(SEP, 1)[-1], "qualified": q,
                         "kind": "tool" if SEP in q else "resource", "status": "quarantined",
                         "conditional": False, "reason": findings[0].message, "rule": findings[0].rule})
        return rows

    def _write_state(self, stopped: bool = False, heartbeat: bool = False) -> None:
        now = time.monotonic()
        if heartbeat and now - self._last_state_write < 2.0:
            return
        self._last_state_write = now
        state = {
            "version": __version__, "pid": os.getpid(), "started_at": self._started_at,
            "updated_at": time.time(), "running": not stopped, "mode": self.cfg.mode,
            "mode_source": self.mode_source, "config_mode": self._file_mode,
            "config": self.cfg.source, "audit_head": self.audit.head,
            "servers": [asdict(s) for s in self.servers.values()],
            "inventory": self.inventory(),
            "grants": [{"client": c, "target": t, "until": u} for (c, t), u in self.grants.items()
                       if u > time.time()],
            "clients": ["stdio", *[c.name for c in self.cfg.clients]],
            "counts": {"prompts": len(self.prompts), "resources": len(self.resources)},
        }
        # One file per process: Claude Desktop may run several gateways on one config, and a
        # shared file made the dashboard show whichever wrote last (or "stopped" after one exited).
        path = process_state_path(self.cfg.state_path)
        tmp = path.with_suffix(path.suffix + ".tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(state, indent=1, default=str), encoding="utf-8")
            os.replace(tmp, path)
        except OSError as e:
            log.debug("could not write state snapshot: %s", e)

    # ------------------------------------------------------------ dispatch

    async def handle(self, msg: Any, caller: Caller = STDIO) -> dict | None:
        if not isinstance(msg, dict):
            return self._err(None, -32600, "Invalid request: expected a JSON object")
        method, rid = msg.get("method"), msg.get("id")
        if rid is not None and not isinstance(rid, (str, int, float)):
            return self._err(None, -32600, "Invalid request: 'id' must be a string or a number")
        if rid is None:
            params = msg.get("params")
            target = params.get("requestId") if isinstance(params, dict) else None
            if method == "notifications/cancelled" and isinstance(target, (str, int)):
                await self._cancel(caller, target)
            return None
        if not isinstance(method, str):
            return self._err(rid, -32600, "Invalid request: 'method' must be a string")
        try:
            await self.tick()
            await self._check_log()
            if self._tamper and self.cfg.audit_on_tamper == "block" and method in (
                    "tools/call", "prompts/get", "resources/read"):
                return self._tool_error(rid, "Blocked: the audit log was changed outside mcpguard, so "
                                             "nothing can be run safely. Run 'mcpguard verify', then "
                                             "'mcpguard audit-new' once you have looked into it.")
            params = msg.get("params") or {}
            if not isinstance(params, dict):
                return self._err(rid, -32602, "Invalid params: expected an object")
            if method == "initialize":
                requested = params.get("protocolVersion")
                return self._ok(rid, {
                    "protocolVersion": requested if requested in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[0],
                    "capabilities": {"tools": {"listChanged": True}, "prompts": {"listChanged": True},
                                     "resources": {"listChanged": True}},
                    "serverInfo": {"name": "mcpguard", "version": __version__},
                    "instructions": "Tools are provided through the mcpguard gateway and are named <server>__<tool>.",
                })
            if method == "ping":
                return self._ok(rid, {})
            if method == "tools/list":
                return self._ok(rid, {"tools": self._visible_tools(caller.client)})
            if method == "prompts/list":
                return self._ok(rid, {"prompts": self._visible_prompts(caller.client)})
            if method == "resources/list":
                return self._ok(rid, {"resources": self._visible_resources(caller.client)})
            if method == "resources/templates/list":
                return self._ok(rid, {"resourceTemplates": [t for _, t in self.templates]})
            if method == "tools/call":
                return await self._tool_call(rid, params, caller)
            if method == "prompts/get":
                return await self._prompt_get(rid, params, caller)
            if method == "resources/read":
                return await self._resource_read(rid, params, caller)
            return self._err(rid, -32601, f"Method not found: {method}")
        except Exception as e:
            log.exception("error handling %s", method)
            self.audit.write("gateway.error", method=method, error=self._safe(repr(e)))
            return self._err(rid, -32603, "Internal gateway error; details are in the audit log")

    def _visible_tools(self, client: str = "stdio") -> list[dict]:
        return [{**t, "name": q} for q, (s, t) in self.tools.items()
                if self.policy.visible(f"{s}/{t['name']}", client)]

    def _visible_prompts(self, client: str = "stdio") -> list[dict]:
        return [{**p, "name": q} for q, (s, p) in self.prompts.items()
                if self.policy.visible(f"{s}/prompt:{p['name']}", client)]

    def _visible_resources(self, client: str = "stdio") -> list[dict]:
        return [r for q, (s, r) in self.resources.items() if self.policy.visible(f"{s}/resource:{q}", client)]

    async def _cancel(self, caller: Caller, request_id) -> None:
        server = self._inflight.get((caller.session, request_id))
        if server and server in self.upstreams:
            forwarded = await self.upstreams[server].cancel((caller.session, request_id))
            self.audit.write("call.cancelled", client=caller.client, server=server, forwarded=forwarded)

    # ------------------------------------------------------------ guarded execution

    def _would_block(self, q, reason, args_hash, findings=None, direction="call", client="stdio") -> bool:
        """Record a block. Returns True when the request must actually stop (enforce mode)."""
        event = "call.blocked" if self.cfg.mode == "enforce" else "call.would_block"
        self.audit.write(event, tool=q, client=client, reason=reason, args_hash=args_hash, direction=direction,
                         findings=[f.to_dict() for f in (findings or [])])
        return self.cfg.mode == "enforce"

    def _has_grant(self, client: str, slash: str) -> bool:
        until = self.grants.get((client, slash))
        if until is None:  # another gateway process may have been granted it
            until = load_grants(self.cfg.approvals_dir).get((client, slash))
            if until is None:
                return False
            self.grants[(client, slash)] = until
        if until <= time.time():
            del self.grants[(client, slash)]
            return False
        return True

    async def _ask(self, q: str, slash: str, args: dict, reason: str, args_hash: str, client: str) -> bool:
        if self._has_grant(client, slash):
            return True
        verdict = Verdict.of(await self.approver(q, args, reason))
        record = {"tool": q, "client": client, "approved": verdict.approved, "args_hash": args_hash}
        if verdict.approved and verdict.remember_seconds:
            until = time.time() + verdict.remember_seconds
            self.grants[(client, slash)] = until
            try:
                save_grant(self.cfg.approvals_dir, client, slash, until)
            except OSError as e:
                log.warning("could not share the approval with other gateway processes: %s", e)
            record["remember_until"] = round(until, 3)
            self._write_state()
        self.audit.write("call.approval", **record)
        return verdict.approved

    async def _guarded(self, rid, *, q, slash, server, item, args, method, params, caller: Caller,
                       is_tool=False, egress_hint: bool | None = None):
        client = caller.client
        if json_depth(args) > MAX_DEPTH:  # before hashing: json.dumps of hostile nesting would crash
            self.audit.write("call.blocked", tool=q, client=client, reason=f"arguments nested deeper than {MAX_DEPTH}",
                             args_hash="", direction="call", findings=[])
            return self._tool_error(rid, f"mcpguard blocked '{q}': its arguments are nested more than "
                                         f"{MAX_DEPTH} levels deep.")
        size = len(json.dumps(args, ensure_ascii=False))
        if size > MAX_ARGS_CHARS:  # the HTTP endpoint already caps bodies; stdio had no limit
            self.audit.write("call.blocked", tool=q, client=client, reason=f"arguments larger than {MAX_ARGS_CHARS} "
                             "characters", args_hash="", direction="call", findings=[])
            return self._tool_error(rid, f"mcpguard blocked '{q}': its arguments are {size:,} characters; the "
                                         f"limit is {MAX_ARGS_CHARS:,}.")
        args_hash = _sha(args)

        def block(reason, findings=None, direction="call") -> bool:
            return self._would_block(q, reason, args_hash, findings, direction, client)

        if q in self.quarantined:
            bad = self.quarantined[q][1]
            if block(f"Quarantined. {bad[0].message}", bad):
                return self._tool_error(rid, f"mcpguard blocked '{q}': it is quarantined ({bad[0].rule}). "
                                             "Review the server, then clear its pin with 'mcpguard pins forget'.")

        if self.policy.protect_own_files:
            own = own_files_problem(args, self._own_paths(), slash)
            if own and block(own):
                return self._tool_error(rid, f"mcpguard blocked '{q}': {own}.")
        decision = self.policy.evaluate(slash, args, client)
        if decision.action == DENY and block(decision.reason):
            return self._tool_error(rid, f"mcpguard blocked '{q}': denied by {decision.reason}.")
        spec = next((sv for sv in self.cfg.servers if sv.name == server), None)
        if spec is not None and (spec.allowed_paths or spec.allowed_hosts):
            outside = scope_violation(args, spec.allowed_paths, spec.allowed_hosts)
            if outside and block(outside):
                return self._tool_error(rid, f"mcpguard blocked '{q}': {outside}.")
        if (decision.action == ALLOW and decision.reason == "default policy" and self.policy.ask_sensitive
                and is_tool and (item.get("annotations") or {}).get("destructiveHint") is True):
            decision = Decision(ASK, "ask_sensitive: the server marks this tool as destructive")
        hit = self.flows.check(slash, client, caller.session)
        if hit is not None:
            finding = [Finding("flow.chained", "high", hit.reason, q)]
            if hit.rule.action == DENY:
                if block(hit.reason, finding):
                    return self._tool_error(rid, f"mcpguard blocked '{q}': {hit.reason}.")
            elif self.cfg.mode != "enforce":
                block(hit.reason, finding)  # monitor mode: record it, do not interrupt anyone
            elif decision.action == ALLOW:  # a plain allow becomes a question; a stricter decision stays
                self.audit.write("flow.matched", tool=q, client=client, flow=hit.rule.name, earlier=hit.earlier)
                decision = Decision(ASK, hit.reason)
        budget = self.policy.check_budget(slash, client=client)
        if budget and block(budget.reason):
            return self._tool_error(rid, f"mcpguard blocked '{q}': {budget.reason}.")
        if decision.action == ASK and not await self._ask(q, slash, args, decision.reason, args_hash, client) \
                and block("approval denied or timed out"):
            return self._tool_error(rid, f"mcpguard blocked '{q}': approval was denied or timed out.")

        outbound = self.engine.scan_args(q, args)
        if is_tool and self.policy.validate_arguments and isinstance(item.get("inputSchema"), dict):
            problems = validate_schema(args, item["inputSchema"])
            if problems:
                outbound.append(Finding("schema.invalid_arguments", "high",
                                        f"arguments do not match the tool's schema ({problems[0]})", q))
        # Tools that send data out are checked against everything read this session. Any other
        # call is still checked for credentials on their way to a different server than the one
        # they came from: "create_issue" or "search" on another server leaks just as well.
        egress = egress_hint if egress_hint is not None else (
            is_tool and is_egress_tool(item, self.policy.egress_tools))
        leaks = self.taint.leaks_in(args) if egress else [
            (v, origin) for v, origin in self.taint.leaks_in(args, secrets_only=True)
            if origin.split(SEP, 1)[0] != server]
        for _, origin in leaks:
            outbound.append(Finding("exfiltration.tainted_data", "critical",
                                    f"data returned by '{origin}' is being sent out through '{q}'", q))
        outbound += self._dlp_outbound(q, args, egress)
        outbound = self.engine.finalize(outbound)
        blocking = at_least(outbound, self.policy.block_severity)
        if blocking and block(blocking[0].message, blocking):
            return self._tool_error(rid, f"mcpguard blocked '{q}': {blocking[0].message}.")

        state = self.servers.get(server)
        if state and state.status != "up":
            self.audit.write("call.failed", tool=q, client=client, args_hash=args_hash,
                             error=f"server {state.status}")
            return self._tool_error(rid, f"The '{server}' server is unavailable ({state.status}); "
                                         "mcpguard is restarting it. Try again shortly.")

        self.policy.record_call(slash, client=client)
        tag = (caller.session, rid)
        self._inflight[tag] = server
        t0 = time.monotonic()
        try:
            result = await self.upstreams[server].request(method, params, tag=tag)
        except RequestCancelled:
            return None
        except UpstreamError as e:
            self.audit.write("call.upstream_error", tool=q, client=client, args_hash=args_hash,
                             error=self._safe(e.error))
            # The model reads error text too: scan it like a result, and pass on the message only.
            message = self._safe(e.error.get("message", "")) if isinstance(e.error, dict) else ""
            code = e.error.get("code") if isinstance(e.error, dict) else None
            hostile = at_least(self.engine.scan_texts(q, [str(e.error)[:SCAN_LIMIT]]), self.policy.block_severity)
            if hostile and block(hostile[0].message, hostile, "result"):
                message = "the server returned an error whose text mcpguard withheld"
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": code if isinstance(code, int) else -32000, "message": message}}
        except Exception as e:  # noqa: BLE001 - a failing server must not take the gateway down
            self._mark_failed_call(server, e)
            self.audit.write("call.failed", tool=q, client=client, args_hash=args_hash, error=self._safe(e))
            return self._tool_error(rid, f"The '{server}' server did not complete the request: {self._safe(e)}")
        finally:
            self._inflight.pop(tag, None)
        latency = (time.monotonic() - t0) * 1000

        if json_depth(result) > MAX_DEPTH:
            self.audit.write("call.blocked", tool=q, client=client, reason=f"result nested deeper than {MAX_DEPTH}",
                             args_hash=args_hash, direction="result", findings=[])
            return self._tool_error(rid, f"mcpguard withheld the result of '{q}': it is nested more than "
                                         f"{MAX_DEPTH} levels deep.")
        texts = texts_of(result)
        # Scan exactly what the model will be given: results are truncated to max_result_chars,
        # and with no limit nothing past SCAN_LIMIT is passed on unscanned. Scanning a 10 MB
        # result in full froze the gateway (one thread) for every caller.
        limit = self.policy.max_result_chars or SCAN_LIMIT
        texts = [t[:limit] for t in texts]
        found = self.engine.scan_texts(q, texts)
        for t in texts:
            self.taint.record_result(q, t)
        found += self._dlp_result(q, texts)
        if self.cfg.anomaly_enabled:
            found += self.engine.finalize(self.baselines.update(
                slash, result_chars=sum(map(len, texts)), latency_ms=latency, arg_chars=len(json.dumps(args))))
        injected = at_least([f for f in found if not f.rule.startswith(("secret", "anomaly"))],
                            self.policy.block_severity)
        if injected and block(injected[0].message, injected, "result"):
            return self._tool_error(rid, f"mcpguard withheld the result of '{q}': {self._for_model(injected[0])}.")

        result = self._sanitize(result)
        self.flows.record(slash, client, caller.session)
        self.audit.write("call.allowed", tool=q, client=client, args_hash=args_hash, latency_ms=round(latency, 1),
                         findings=[f.to_dict() for f in found], result_hash=_sha(result),
                         severity=max_severity(found))
        return self._ok(rid, result)

    @staticmethod
    def _for_model(finding: Finding) -> str:
        """Why a result was withheld, in mcpguard's words only. The finding's own message quotes
        the offending text, and quoting an attacker's sentence to the model inside a trusted
        notice would deliver part of the attack."""
        summary = _RULE_SUMMARIES.get(finding.rule) or "it matched a detection rule"
        return f"{summary[0].lower()}{summary[1:]} (rule {finding.rule}; details are in the audit log)"

    def _lookup(self, table: dict, q: str):
        if q in table:
            return table[q]
        if q in self.quarantined:
            server = self.quarantined[q][0]
            return server, {"name": q.split(SEP, 1)[-1]}
        return None

    async def _tool_call(self, rid, params, caller: Caller = STDIO):
        q, args = params.get("name", ""), params.get("arguments") or {}
        if not isinstance(q, str):
            return self._err(rid, -32602, "Invalid params: 'name' must be a string")
        if not isinstance(args, dict):
            return self._err(rid, -32602, "Invalid params: 'arguments' must be an object")
        found = self._lookup(self.tools, q)
        if not found:
            return self._err(rid, -32602, f"Unknown tool: {q}")
        server, tool = found
        return await self._guarded(rid, q=q, slash=f"{server}/{tool['name']}", server=server, item=tool,
                                   args=args, method="tools/call", caller=caller,
                                   params={"name": tool["name"], "arguments": args}, is_tool=True)

    async def _prompt_get(self, rid, params, caller: Caller = STDIO):
        q, args = params.get("name", ""), params.get("arguments") or {}
        if not isinstance(q, str):
            return self._err(rid, -32602, "Invalid params: 'name' must be a string")
        if not isinstance(args, dict):
            return self._err(rid, -32602, "Invalid params: 'arguments' must be an object")
        found = self._lookup(self.prompts, q)
        if not found:
            return self._err(rid, -32602, f"Unknown prompt: {q}")
        server, prompt = found
        return await self._guarded(rid, q=q, slash=f"{server}/prompt:{prompt['name']}", server=server,
                                   item=prompt, args=args, method="prompts/get", caller=caller,
                                   params={"name": prompt["name"], "arguments": args})

    async def _resource_read(self, rid, params, caller: Caller = STDIO):
        uri = params.get("uri", "")
        if not isinstance(uri, str) or not uri:
            return self._err(rid, -32602, "Invalid params: 'uri' is required")
        found = self._lookup(self.resources, uri)
        server = found[0] if found else None
        if server is None:
            for s, t in self.templates:
                prefix = t.get("uriTemplate", "").split("{", 1)[0]
                if prefix and uri.startswith(prefix):
                    server = s
                    break
        if server is None:
            return self._err(rid, -32002, f"Resource not found: {uri}")
        # A URI built from a template is chosen by the model, so it can carry data out; a listed
        # resource's URI was chosen by the server.
        return await self._guarded(rid, q=uri, slash=f"{server}/resource:{uri}", server=server, caller=caller,
                                   item={"name": uri}, args={} if found else {"uri": uri},
                                   method="resources/read", params={"uri": uri}, egress_hint=not found)

    # ------------------------------------------------------------ output hygiene

    def _safe(self, value) -> str:
        """Redact and shorten anything copied from upstreams into logs."""
        text = value if isinstance(value, str) else json.dumps(value, default=str) \
            if isinstance(value, (dict, list)) else str(value) or type(value).__name__
        return _scrub(self.engine.redact(text))[:500]

    # ------------------------------------------------------------ data leakage prevention

    def _dlp_outbound(self, q: str, args: dict, egress: bool) -> list[Finding]:
        d = self.cfg.dlp
        if not d.enabled or not args:
            return []
        blob = json.dumps(args, ensure_ascii=False)
        # 'block' applies to tools that send data out; elsewhere the same data is only logged.
        actions = d.outbound if egress else {k: ("log" if v == "block" else v) for k, v in d.outbound.items()}
        found = dlp.scan(blob, actions, "outbound", q)
        if egress and d.track_pii and self.pii_seen:
            flat = dlp.normalise(blob)
            for value, origin in list(self.pii_seen.items()):
                if value in flat:
                    found.append(Finding("dlp.tracked_pii", "high", f"personal data returned by '{origin}' is "
                                                                    f"being sent out through '{q}'", q))
                    break
            else:
                pieces = self.pii_pieces.check(blob, self.pii_seen)
                if pieces:
                    found.append(Finding("dlp.tracked_pii", "high", f"personal data returned by '{pieces[1]}' is "
                                                                    f"being sent out in pieces through '{q}'", q))
        return found

    def _dlp_result(self, q: str, texts: list[str]) -> list[Finding]:
        d = self.cfg.dlp
        if not d.enabled:
            return []
        found: list[Finding] = []
        for t in texts:
            found += dlp.scan(t, d.results, "results", q)
            if d.track_pii:
                for value in dlp.tracked_values(t):
                    self.pii_seen[value] = q
                    self.pii_seen.move_to_end(value)
        while len(self.pii_seen) > 2000:
            self.pii_pieces.forget(self.pii_seen.popitem(last=False)[0])
        return found

    def _clean(self, text: str) -> str:
        if self.cfg.dlp.enabled:
            text, _counts = dlp.redact(text, self.cfg.dlp.results)
        if self.policy.redact_secrets:
            text = self.engine.redact(text)
        limit = self.policy.max_result_chars or SCAN_LIMIT
        if len(text) > limit:
            text = text[:limit] + f"\n[truncated by mcpguard: {len(text) - limit} more characters]"
        return text

    def _sanitize(self, result: dict) -> dict:
        result = json.loads(json.dumps(result))  # deep copy
        for item in result.get("content", []) or []:
            if isinstance(item, dict):
                if isinstance(item.get("text"), str):
                    item["text"] = self._clean(item["text"])
                if isinstance(item.get("resource"), dict) and isinstance(item["resource"].get("text"), str):
                    item["resource"]["text"] = self._clean(item["resource"]["text"])
        for item in result.get("contents", []) or []:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                item["text"] = self._clean(item["text"])
        for msg in result.get("messages", []) or []:
            c = msg.get("content") if isinstance(msg, dict) else None
            if isinstance(c, dict) and isinstance(c.get("text"), str):
                c["text"] = self._clean(c["text"])
        if "structuredContent" in result:
            blob = json.dumps(result["structuredContent"], ensure_ascii=False)
            if self.cfg.dlp.enabled:
                blob, _counts = dlp.redact(blob, self.cfg.dlp.results)
            if self.policy.redact_secrets:
                blob = self.engine.redact(blob)
            result["structuredContent"] = json.loads(blob)
        return result

    # ------------------------------------------------------------ responses

    @staticmethod
    def _ok(rid, result):
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    @staticmethod
    def _err(rid, code, message):
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}

    @staticmethod
    def _tool_error(rid, text):
        return {"jsonrpc": "2.0", "id": rid,
                "result": {"isError": True, "content": [{"type": "text", "text": text}]}}


async def serve_stdio(gw: Gateway, tick_seconds: float = 2.0, stop: asyncio.Event | None = None) -> None:
    """Speak MCP over stdin/stdout until stdin closes or ``stop`` is set.

    Requests run concurrently, so a pending approval never stalls other calls.
    stdin is read on a daemon thread: asyncio pipes on stdin don't work on Windows,
    and a daemon thread can't keep the process alive after a shutdown signal.
    """
    loop = asyncio.get_running_loop()
    write_lock = asyncio.Lock()
    lines: asyncio.Queue[bytes] = asyncio.Queue()
    stop = stop or asyncio.Event()

    def pump() -> None:
        for raw in iter(sys.stdin.buffer.readline, b""):
            loop.call_soon_threadsafe(lines.put_nowait, raw)
        loop.call_soon_threadsafe(lines.put_nowait, b"")

    threading.Thread(target=pump, name="mcpguard-stdin", daemon=True).start()

    async def readline() -> bytes:
        get = asyncio.ensure_future(lines.get())
        halt = asyncio.ensure_future(stop.wait())
        done, pending = await asyncio.wait({get, halt}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        return get.result() if get in done else b""

    async def send(msg: dict) -> None:
        async with write_lock:
            try:
                sys.stdout.write(json.dumps(msg) + "\n")
                sys.stdout.flush()
            except (BrokenPipeError, ValueError, OSError):
                # The client closed its read end (or the stream): nobody is left to answer.
                log.info("client closed its output; shutting down")
                stop.set()

    gw.notify_client = send
    await gw.start()

    async def ticker() -> None:
        while True:
            await asyncio.sleep(tick_seconds)
            try:
                await gw.tick()
            except Exception as e:
                log.exception("background tick failed")
                gw.audit.write("gateway.error", method="tick", error=gw._safe(repr(e)))

    async def run_one(msg: dict) -> None:
        resp = await gw.handle(msg)
        if resp is not None:
            await send(resp)

    tick_task = asyncio.create_task(ticker())
    tasks: set[asyncio.Task] = set()
    try:
        while True:
            line = await readline()
            if not line:
                break
            try:
                msg = json.loads(line)
            except (ValueError, RecursionError):  # bad JSON, bad UTF-8 (both ValueError), or nested too deeply
                await send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
                continue
            if not isinstance(msg, dict):
                await send({"jsonrpc": "2.0", "id": None,
                            "error": {"code": -32600, "message": "Batch requests are not supported"}})
                continue
            if msg.get("method") == "initialize":
                await run_one(msg)  # complete the handshake before anything else
                continue
            t = asyncio.create_task(run_one(msg))
            tasks.add(t)
            t.add_done_callback(tasks.discard)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        tick_task.cancel()
        await gw.stop()
