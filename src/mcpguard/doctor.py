"""`mcpguard doctor`: check the whole setup and say what to fix.

Each check reports ok, warn or fail with one line of advice. Nothing is changed and no
server is started, so it is safe to run while the gateway is running.
"""

from __future__ import annotations

import os
import shutil
import socket
import sys
from dataclasses import dataclass
from pathlib import Path

from . import desktop
from .audit import load_key, verify
from .config import Config, ConfigError, load_config

OK, WARN, FAIL = "ok", "warn", "fail"
_NODE_LAUNCHERS = {"npx", "npm", "node", "pnpm", "yarn", "bunx", "bun"}
_PY_LAUNCHERS = {"uvx", "uv", "pipx"}


@dataclass
class Check:
    status: str
    name: str
    detail: str


def _which(command: str) -> str | None:
    if Path(command).is_file():
        return command
    return shutil.which(command)


def check_servers(cfg: Config) -> list[Check]:
    out = []
    if not cfg.servers:
        return [Check(FAIL, "servers", "No [servers] in the config: the gateway would offer no tools.")]
    for s in cfg.servers:
        name = f"server {s.name}"
        if not s.enabled:
            out.append(Check(OK, name, "disabled"))
            continue
        if s.kind == "http":
            token = f", token from ${s.bearer_env}" if s.bearer_env else ""
            if s.bearer_env and not os.environ.get(s.bearer_env):
                out.append(Check(WARN, name, f"{s.url}: ${s.bearer_env} is not set in this environment."))
            else:
                out.append(Check(OK, name, f"remote {s.url}{token}"))
            continue
        if "my_mcp_server" in s.args:
            out.append(Check(FAIL, name, "this is the example from `mcpguard init`, not a real server. Replace it "
                                         "with yours, or run `mcpguard claude-desktop install --take-over`."))
            continue
        exe = Path(s.command).stem.lower()
        found = _which(s.command)
        if not found:
            hint = ""
            if exe in _NODE_LAUNCHERS:
                hint = " Install Node.js from https://nodejs.org and open a new terminal."
            elif exe in _PY_LAUNCHERS:
                hint = f" Install {exe} (https://docs.astral.sh/uv/) or use python -m instead."
            out.append(Check(FAIL, name, f"'{s.command}' was not found on PATH.{hint}"))
            continue
        missing = [a for a in s.args if _looks_like_local_path(a) and not Path(a).exists()]
        if missing:
            out.append(Check(WARN, name, f"found {found}, but these paths do not exist: {', '.join(missing)}"))
        else:
            out.append(Check(OK, name, f"{s.command} found ({found})"))
    return out


def _looks_like_local_path(arg: str) -> bool:
    if arg.startswith(("-", "@")) or "://" in arg:
        return False
    return (len(arg) > 2 and arg[1] == ":" and arg[2] in "\\/") or arg.startswith(("/", "~/", "./", "..\\", ".\\"))


def check_port(cfg: Config) -> Check:
    if not cfg.dashboard_enabled:
        return Check(OK, "dashboard", "disabled")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", cfg.dashboard_port))
        except OSError:
            return Check(WARN, "dashboard", f"port {cfg.dashboard_port} is in use. If a gateway is running that "
                                            "is expected; otherwise set [dashboard] port to a free one.")
    return Check(OK, "dashboard", f"http://127.0.0.1:{cfg.dashboard_port} (free)")


def check_policy(cfg: Config) -> list[Check]:
    out = []
    from .modeswitch import read_override
    saved = read_override(cfg.approvals_dir)
    mode = saved["mode"] if saved else cfg.mode
    if mode == "monitor":
        out.append(Check(WARN, "mode", "monitor: calls are logged but nothing is blocked. Switch to enforce with "
                                       "`mcpguard mode enforce` or the switch in the dashboard when the findings "
                                       "look right."))
    elif saved:
        out.append(Check(OK, "mode", f"enforce (switched on from {saved['by']}; the config file says {cfg.mode}). "
                                     "`mcpguard mode config` goes back to the file's setting."))
    asks = [r["match"] for r in cfg.policy.rules if r.get("action") == "ask"] + (
        ["(default)"] if cfg.policy.default == "ask" else [])
    if not asks:
        return out
    shown = ", ".join(asks[:3]) + ("..." if len(asks) > 3 else "")
    if cfg.approval_mode == "tty" and cfg.dashboard_enabled:
        out.append(Check(OK, "approvals", f"{len(asks)} 'ask' rule(s): asked on the console when there is one, "
                                          "otherwise in the dashboard"))
    elif cfg.approval_mode == "tty":
        out.append(Check(WARN, "approvals", f"'ask' rules ({shown}) use terminal approvals. A client such as "
                                            "Claude Desktop starts the gateway without a terminal, so every "
                                            "request would be denied. Set [approvals] mode = \"dashboard\"."))
    elif cfg.approval_mode == "dashboard" and not cfg.dashboard_enabled:
        out.append(Check(FAIL, "approvals", f"'ask' rules ({shown}) wait for the dashboard, but the dashboard "
                                            "is disabled, so every request would time out and be denied. "
                                            "Set [dashboard] enabled = true."))
    elif cfg.approval_mode in ("allow", "deny"):
        out.append(Check(WARN, "approvals", f"'ask' rules ({shown}) are answered '{cfg.approval_mode}' "
                                            "automatically ([approvals] mode)."))
    else:
        out.append(Check(OK, "approvals", f"{len(asks)} 'ask' rule(s), answered in the dashboard"))
    return out


def check_key_location(cfg: Config) -> Check | None:
    """A signing key kept in the same folder as the log lets anything that can read the folder forge the log."""
    if not cfg.audit_sign:
        return None
    key = Path(cfg.audit_key_file).resolve()
    log_dir = Path(cfg.audit_path).resolve().parent
    if key.parent == log_dir or log_dir in key.parents:
        return Check(WARN, "audit key", f"the signing key {key.name} is in the same folder as the log, so a tool "
                     "that can read that folder can forge the log. Move it (for example to ~/.mcpguard/keys/) and "
                     "set [audit] key_file to the new place")
    return None


def check_witness(cfg: Config) -> Check:
    if not cfg.checkpoint_path:
        return Check(WARN, "log witness", "no outside copy of the log head is kept; someone with access to this "
                                          "machine could delete the newest records unnoticed")
    where = f"{cfg.checkpoint_path}" + (" and a witness server" if cfg.witness_url else "")
    if cfg.forward_url:
        return Check(OK, "log witness", f"every record is sent to {cfg.forward_url}; log head is copied to {where}")
    note = "" if cfg.witness_url else " (set [audit] forward_url to keep a full copy off this machine)"
    return Check(OK, "log witness", f"log head is copied to {where}{note}")


def check_gateway(cfg: Config) -> Check:
    """Is a gateway running now? A leftover one keeps old settings until Claude Desktop is fully quit."""
    from .state import is_live, read_merged
    snap = read_merged(cfg.state_path)
    if not snap or not is_live(snap):
        return Check(OK, "gateway", "none running (Claude Desktop starts one when it opens)")
    from .state import _num
    n = int(_num(snap.get("processes"), 1))
    return Check(OK, "gateway", f"{n} running ({str(snap.get('mode', '?'))[:20]} mode). After editing the config, quit "
                                "Claude Desktop from the tray icon (not just the window) so it restarts.")


def check_pins(cfg: Config) -> Check:
    from .detect import PinStore
    store = PinStore(cfg.pins_path)
    if store.changed:
        return Check(WARN, "pins", f"{len(store.changed)} definition(s) changed since you trusted them. "
                                   "Run `mcpguard pins diff <server>`; approve only changes you expect.")
    if store.pending:
        return Check(WARN, "pins", f"{len(store.pending)} new definition(s) wait for review: "
                                   "`mcpguard pins pending`.")
    return Check(OK, "pins", f"{len(store.pins)} definition(s) pinned, none waiting")


def check_audit(cfg: Config) -> Check:
    path = Path(cfg.audit_path)
    if not path.exists():
        return Check(OK, "audit log", f"{path.name} will be created on first run")
    key = None
    if cfg.audit_sign:
        if not Path(cfg.audit_key_file).exists() and not os.environ.get("MCPGUARD_AUDIT_KEY"):
            return Check(FAIL, "audit log", f"{path.name} exists but the signing key {cfg.audit_key_file} is "
                                            "missing, so it cannot be verified.")
        key = load_key(cfg.audit_key_file)
    ok, msg = verify(path, key)
    if ok:
        return Check(OK, "audit log", msg)
    return Check(FAIL, "audit log", f"{msg}. See `mcpguard verify` for details; `mcpguard audit-new` "
                                    "archives this log and starts a fresh one.")


def check_desktop(config_path: Path, desktop_file: Path | None) -> Check:
    path = desktop_file or desktop.default_path()
    if not path.exists():
        return Check(OK, "Claude Desktop", "not installed here (skipped)")
    ok, lines = desktop.status(path, config_path)
    problems = [ln for ln in lines[1:] if not ln.startswith("'guarded' is installed")]
    return Check(OK if ok else WARN, "Claude Desktop", "; ".join(problems) if problems else lines[-1])


def run(config_path: Path, desktop_file: Path | None = None) -> list[Check]:
    checks = [Check(OK if sys.version_info >= (3, 11) else FAIL, "python",
                    f"{sys.version.split()[0]} at {sys.executable}")]
    try:
        cfg = load_config(config_path)
    except FileNotFoundError:
        return [*checks, Check(FAIL, "config", f"{config_path} not found. Run `mcpguard init`.")]
    except ConfigError as e:
        return [*checks, Check(FAIL, "config", str(e))]
    checks.append(Check(OK, "config", f"{config_path} ({cfg.mode} mode, {len(cfg.servers)} server(s))"))
    checks += [Check(WARN, "config", f"{w}: ignored") for w in cfg.warnings]
    checks += check_servers(cfg)
    checks += check_policy(cfg)
    checks.append(check_port(cfg))
    checks.append(check_gateway(cfg))
    checks.append(check_pins(cfg))
    checks.append(check_audit(cfg))
    checks.append(check_witness(cfg))
    if (key_check := check_key_location(cfg)) is not None:
        checks.append(key_check)
    checks.append(check_desktop(config_path, desktop_file))
    return checks
