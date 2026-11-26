"""Live state snapshots shared between gateway processes and the dashboard.

Each gateway process writes ``<state stem>.<pid><suffix>`` (for example
``mcpguard-state.4120.json``) every few seconds. The dashboard merges the snapshots of the
processes that are still running, so two gateways started from one config (as Claude Desktop
can do) show up as one gateway with every server, and one of them stopping does not make the
dashboard report the gateway as stopped.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from pathlib import Path

HEARTBEAT_STALE_SECONDS = 15
FORGET_AFTER_SECONDS = 24 * 3600  # snapshots of processes gone this long are deleted


def process_state_path(state_path: str | Path, pid: int | None = None) -> Path:
    p = Path(state_path)
    return p.with_name(f"{p.stem}.{os.getpid() if pid is None else pid}{p.suffix}")


def _snapshots(state_path: str | Path) -> list[tuple[Path, dict]]:
    p = Path(state_path)
    out = []
    for f in [p, *p.parent.glob(f"{p.stem}.*{p.suffix}")]:
        if f.name.endswith(".tmp"):
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            out.append((f, data))
    return out


def _num(value, default: float = 0.0) -> float:
    """A number from a snapshot field; a damaged file (text, null, nan) counts as the default."""
    try:
        out = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return out if out == out and abs(out) != float("inf") else default


def _dicts(value) -> list[dict]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def is_live(snap: dict, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    age = now - _num(snap.get("updated_at"))
    return bool(snap.get("running")) and -60 < age < HEARTBEAT_STALE_SECONDS  # a date far ahead is not "live"


def read_merged(state_path: str | Path, now: float | None = None) -> dict:
    """One snapshot for the dashboard: every live process merged, or else the latest one."""
    now = time.time() if now is None else now
    snaps = _snapshots(state_path)
    for f, s in snaps:  # tidy up after processes that ended long ago
        if f != Path(state_path) and now - _num(s.get("updated_at")) > FORGET_AFTER_SECONDS:
            with contextlib.suppress(OSError):
                f.unlink()
    if not snaps:
        return {}
    live = [s for _f, s in snaps if is_live(s, now)]
    if not live:
        return max((s for _f, s in snaps), key=lambda s: _num(s.get("updated_at")))
    live.sort(key=lambda s: _num(s.get("updated_at")), reverse=True)
    merged = dict(live[0])
    servers: dict[str, dict] = {}
    for s in reversed(live):  # newest last, so it wins; but an "up" report beats a "down" one
        for srv in _dicts(s.get("servers")):
            name = srv.get("name")
            if name and (name not in servers or srv.get("status") == "up" or servers[name].get("status") != "up"):
                servers[name] = srv
    merged["servers"] = list(servers.values())
    inventory: dict[str, dict] = {}
    for s in live:
        for item in _dicts(s.get("inventory")):
            inventory.setdefault(json.dumps(item, sort_keys=True), item)
    merged["inventory"] = list(inventory.values())
    merged["grants"] = [g for s in live for g in _dicts(s.get("grants"))]
    merged["processes"] = len(live)
    merged["started_at"] = min(_num(s.get("started_at"), now) or now for s in live)
    return merged
