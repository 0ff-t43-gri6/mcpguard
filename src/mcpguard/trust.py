"""Which config files this machine has agreed to run, and the exact contents it agreed to.

A config can start programs and import code. The record lives in the mcpguard home folder, away
from the project folder a tool server or a downloaded project can write to, and ties each path to the
SHA-256 of the file as it was when you trusted it. Anything that changes the file afterwards has to be
trusted again before it is used, at start-up and when a running gateway reloads it.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .fileio import write_atomic


def trust_file() -> Path:
    return Path(os.environ.get("MCPGUARD_HOME") or Path.home() / ".mcpguard") / "trusted-configs.json"


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_of(config: str | Path) -> str:
    try:
        return digest_bytes(Path(config).read_bytes())
    except OSError:
        return ""


def trusted() -> dict[str, str]:
    """Trusted config paths, each with the digest of the file as it was when trusted."""
    try:
        data = json.loads(trust_file().read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):  # unreadable, not JSON, or nested too deeply to parse
        return {}
    if isinstance(data, dict):
        return {str(k): str(v) for k, v in data.items()}
    return {}  # the old format kept paths only; those are trusted again once, by content


def set_trust(config: str | Path, is_trusted: bool) -> None:
    entries = trusted()
    key = str(Path(config).resolve())
    if is_trusted:
        entries[key] = digest_of(config)
    else:
        entries.pop(key, None)
    f = trust_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    write_atomic(f, json.dumps(dict(sorted(entries.items())), indent=1))


def is_trusted_digest(config: str | Path, digest: str) -> bool:
    known = trusted().get(str(Path(config).resolve()))
    return known is not None and digest != "" and known == digest
