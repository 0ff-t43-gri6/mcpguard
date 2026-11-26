"""Merging per-process state snapshots for the dashboard."""

import json
import os
import time

from mcpguard.state import FORGET_AFTER_SECONDS, is_live, process_state_path, read_merged


def snap(path, pid, running=True, age=0.0, servers=(), grants=()):
    p = process_state_path(path, pid)
    p.write_text(json.dumps({"pid": pid, "running": running, "updated_at": time.time() - age,
                             "started_at": time.time() - 100 - pid, "mode": "enforce",
                             "servers": list(servers), "grants": list(grants), "inventory": []}), encoding="utf-8")
    return p


def test_live_processes_are_merged(tmp_path):
    base = tmp_path / "mcpguard-state.json"
    snap(base, 1, servers=[{"name": "files", "status": "down"}], grants=[{"client": "stdio", "until": 1}])
    snap(base, 2, servers=[{"name": "files", "status": "up"}, {"name": "mail", "status": "up"}])
    snap(base, 3, running=False, servers=[{"name": "old", "status": "up"}])           # stopped
    snap(base, 4, age=60, servers=[{"name": "stale", "status": "up"}])                # no heartbeat
    merged = read_merged(base)
    assert is_live(merged)
    assert merged["processes"] == 2
    assert {s["name"]: s["status"] for s in merged["servers"]} == {"files": "up", "mail": "up"}
    assert len(merged["grants"]) == 1


def test_nothing_live_shows_the_latest_snapshot_and_old_ones_are_removed(tmp_path):
    base = tmp_path / "mcpguard-state.json"
    snap(base, 1, running=False, age=5)
    old = snap(base, 2, running=False, age=FORGET_AFTER_SECONDS + 60)
    merged = read_merged(base)
    assert not is_live(merged)
    assert merged["pid"] == 1
    assert not old.exists()
    assert read_merged(tmp_path / "none.json") == {}


def test_process_path_uses_the_pid(tmp_path):
    assert process_state_path(tmp_path / "s.json").name == f"s.{os.getpid()}.json"
