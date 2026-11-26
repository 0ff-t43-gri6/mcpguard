"""Switch between monitor and enforce without editing the config.

The dashboard (or ``mcpguard mode``) writes a small file in the approvals folder; every gateway reads it
within a few seconds. The config file is left alone, so nothing needs trusting again, and the file is one of
mcpguard's own files, which tools may not read or change. Every change is written to the audit log.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .fileio import write_atomic

MODES = ("monitor", "enforce")
MAX_BYTES = 2048


def mode_path(approvals_dir: str | Path) -> Path:
    return Path(approvals_dir) / "mode.json"


def read_override(approvals_dir: str | Path) -> dict | None:
    """The saved choice ({"mode", "by", "ts"}), or None when there is none or the file is not valid."""
    path = mode_path(approvals_dir)
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None
    if not isinstance(data, dict) or data.get("mode") not in MODES:
        return None
    by = data.get("by")
    ts = data.get("ts")
    return {"mode": data["mode"], "by": by if isinstance(by, str) else "unknown",
            "ts": ts if isinstance(ts, int | float) and not isinstance(ts, bool) else 0.0}


def set_override(approvals_dir: str | Path, mode: str, by: str) -> None:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}")
    write_atomic(mode_path(approvals_dir), json.dumps({"mode": mode, "by": by[:40], "ts": time.time()}))


def clear_override(approvals_dir: str | Path) -> bool:
    path = mode_path(approvals_dir)
    existed = path.exists()
    path.unlink(missing_ok=True)
    return existed
