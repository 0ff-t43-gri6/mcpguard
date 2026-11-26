"""Connect mcpguard to Claude Desktop without hand-editing JSON.

``mcpguard claude-desktop install`` adds one entry to ``claude_desktop_config.json`` that
starts the gateway, keeping every other setting. A timestamped backup is written first and
the file is replaced atomically. With ``--take-over`` the servers Claude Desktop already
runs directly are moved into mcpguard's config, so they are reached only through the
gateway.

A config made of several JSON objects one after another (the result of pasting a snippet
below the existing content) is merged into one; anything else that is not valid JSON is
reported with its line and column and left untouched.
"""

from __future__ import annotations

import json
import os
import re
import shutil
# Used only to run the configured Python and test that it can import mcpguard.
import subprocess  # nosec B404
import sys
import time
from pathlib import Path
from typing import Any

from .fileio import write_atomic

DEFAULT_NAME = "guarded"
# The example server written by `mcpguard init` (keep in step with DEFAULT_CONFIG; a test checks).
PLACEHOLDER = '[servers.example]\ncommand = "python"\nargs = ["-m", "my_mcp_server"]'



class DesktopError(Exception):
    pass


def default_path() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library/Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "Claude/claude_desktop_config.json"


def parse(text: str) -> tuple[dict, bool]:
    """Parse the config. Returns (data, repaired) where repaired means several top-level
    objects were merged into one."""
    if not text.strip():
        return {}, False
    try:
        data = json.loads(text)
    except json.JSONDecodeError as first_error:
        dec, pos, parts = json.JSONDecoder(), 0, []
        try:
            while pos < len(text):
                while pos < len(text) and text[pos].isspace():
                    pos += 1
                if pos >= len(text):
                    break
                obj, pos = dec.raw_decode(text, pos)
                parts.append(obj)
        except json.JSONDecodeError:
            parts = []
        if len(parts) < 2 or not all(isinstance(p, dict) for p in parts):
            raise DesktopError(f"not valid JSON: {first_error.msg} at line {first_error.lineno}, "
                               f"column {first_error.colno}") from first_error
        merged: dict = {}
        for p in parts:
            for k, v in p.items():
                if isinstance(v, dict) and isinstance(merged.get(k), dict):
                    merged[k] = {**merged[k], **v}
                else:
                    merged[k] = v
        return merged, True
    if not isinstance(data, dict):
        raise DesktopError("the config must be a JSON object")
    return data, False


def entry(config: Path) -> dict:
    return {"command": sys.executable, "args": ["-m", "mcpguard.cli", "-c", str(config.resolve()), "run"]}


def is_gateway(server: Any) -> bool:
    args = server.get("args", []) if isinstance(server, dict) else []
    return isinstance(args, list) and ("mcpguard.cli" in args or "mcpguard" in str(server.get("command", "")))


def _toml_str(s: str) -> str:
    # A JSON string is a TOML basic string, except that TOML also forbids a raw DEL.
    return json.dumps(s, ensure_ascii=False).replace("\x7f", "\\u007f")


def safe_names(names: list[str]) -> dict[str, str]:
    """Claude Desktop allows any server name; mcpguard allows letters, digits, '-' and '_'.
    Returns original -> mcpguard name, unique."""
    out: dict[str, str] = {}
    used: set[str] = set()
    for name in names:
        # '__' separates server and tool names in the gateway, so it cannot appear in a name.
        base = re.sub(r"_{2,}", "_", re.sub(r"[^A-Za-z0-9_-]+", "-", name)).strip("-_") or "server"
        candidate, n = base, 2
        while candidate in used:
            candidate, n = f"{base}-{n}", n + 1
        used.add(candidate)
        out[name] = candidate
    return out


def servers_to_toml(servers: dict[str, dict]) -> str:
    """mcpguard [servers.*] sections for Claude Desktop stdio entries (names made safe first)."""
    out = []
    names = safe_names(list(servers))
    for name, spec in servers.items():
        out.append(f"\n[servers.{names[name]}]")
        out.append(f"command = {_toml_str(str(spec['command']))}")
        args = [str(a) for a in spec.get("args", [])]
        out.append("args = [" + ", ".join(_toml_str(a) for a in args) + "]")
        env = spec.get("env") or {}
        if env:
            out.append("env = { " + ", ".join(f"{_toml_str(k)} = {_toml_str(str(v))}" for k, v in env.items()) + " }")
    return "\n".join(out) + "\n"


def _load(path: Path) -> tuple[dict, bool]:
    if not path.exists():
        return {}, False
    return parse(path.read_text(encoding="utf-8-sig"))


def _save(path: Path, data: dict) -> Path | None:
    backup = None
    if path.exists():
        backup = path.with_name(f"{path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(path, backup)
    write_atomic(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    return backup


def install(path: Path, config: Path, name: str = DEFAULT_NAME, take_over: bool = False) -> list[str]:
    """Add the gateway entry. Returns lines describing what changed."""
    if not config.exists():
        raise DesktopError(f"{config} does not exist; run `mcpguard init` first")
    data, repaired = _load(path)
    servers = data.get("mcpServers", {})
    if not isinstance(servers, dict):
        raise DesktopError("mcpServers in the Claude Desktop config is not an object")
    notes = ["Merged several JSON blocks into one."] if repaired else []
    moved = {}
    if take_over:
        for n, spec in list(servers.items()):
            if n == name or is_gateway(spec):
                continue
            if not isinstance(spec, dict) or "command" not in spec:
                notes.append(f"Left '{n}' in place: only local (command) servers can be moved.")
                continue
            moved[n] = servers.pop(n)
        if moved:
            text = config.read_text(encoding="utf-8")
            renamed = {a: b for a, b in safe_names(list(moved)).items() if a != b}
            clash = [n for n in safe_names(list(moved)).values() if f"[servers.{n}]" in text]
            if clash:
                raise DesktopError(f"mcpguard config already has server(s) {', '.join(clash)}; "
                                   "remove them or install without --take-over")
            text_before = text
            if PLACEHOLDER in text:  # the starter's example server, untouched: the real ones replace it
                text = text.replace(PLACEHOLDER, "\n".join("# " + ln for ln in PLACEHOLDER.splitlines()))
                notes.append("Commented out the example server from `mcpguard init`.")
            write_atomic(config, text.rstrip("\n") + "\n" + servers_to_toml(moved))
            try:
                from .config import load_config
                load_config(config)
            except Exception as e:
                write_atomic(config, text_before)  # leave the config exactly as it was
                raise DesktopError(f"the moved servers would make {config.name} invalid ({e}); nothing changed") from e
            notes.append(f"Moved {', '.join(moved)} into {config.name}; they now run behind the gateway.")
            notes += [f"'{a}' is called '{b}' in mcpguard (names there use letters, digits, - and _)."
                      for a, b in renamed.items()]
    wanted = entry(config)
    if servers.get(name) == wanted and not moved and not repaired:
        return [f"Already installed as '{name}' in {path}."]
    servers[name] = wanted
    data["mcpServers"] = servers
    backup = _save(path, data)
    notes.append(f"Added '{name}' to {path}.")
    if backup:
        notes.append(f"Backup of the previous file: {backup.name}")
    notes.append("Fully quit Claude Desktop (tray icon > Quit) and open it again. If it was open while this ran, "
                 "check with `mcpguard claude-desktop status` afterwards: Claude Desktop saves its own settings to "
                 "this file and can overwrite the change; if so, quit it first and run install again.")
    return notes


def uninstall(path: Path, name: str = DEFAULT_NAME) -> list[str]:
    data, _ = _load(path)
    servers = data.get("mcpServers", {})
    if not isinstance(servers, dict) or name not in servers:
        return [f"No '{name}' entry in {path}; nothing to do."]
    del servers[name]
    backup = _save(path, data)
    return [f"Removed '{name}' from {path}." + (f" Backup: {backup.name}" if backup else ""),
            "Servers moved with --take-over stay in mcpguard's config; add them back to Claude Desktop "
            "yourself if you want them to run unguarded."]


def _imports_mcpguard(python: str, entry_env: dict | None = None) -> bool:
    # Test the way Claude Desktop will start it: not with this shell's PYTHONPATH, but with the
    # entry's own env (if any) on top of the normal environment.
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP")}
    env.update({str(k): str(v) for k, v in (entry_env or {}).items()})
    try:
        r = subprocess.run([python, "-c", "import mcpguard.cli"], capture_output=True, timeout=20, check=False,
                           env=env)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def status(path: Path, config: Path, name: str = DEFAULT_NAME) -> tuple[bool, list[str]]:
    """(ok, lines). ok means the entry exists and points at this config and a working Python."""
    if not path.exists():
        return False, [f"Claude Desktop config not found at {path}. Is Claude Desktop installed?"]
    try:
        data, repaired = _load(path)
    except DesktopError as e:
        return False, [f"{path}: {e}"]
    lines = [f"Claude Desktop config: {path}"]
    if repaired:
        lines.append("Problem: the file holds several JSON blocks; Claude Desktop cannot read it. "
                     "`mcpguard claude-desktop install` fixes it.")
    servers = data.get("mcpServers", {}) if isinstance(data.get("mcpServers"), dict) else {}
    spec = servers.get(name)
    if not spec:
        lines.append(f"No '{name}' entry. Run `mcpguard claude-desktop install`.")
        return False, lines
    args = spec.get("args", [])
    ok = not repaired
    target = Path(args[args.index("-c") + 1]) if "-c" in args and args.index("-c") + 1 < len(args) else None
    if target is None or target.resolve() != config.resolve():
        lines.append(f"'{name}' uses config {target}, not {config.resolve()}.")
        ok = False
    command = str(spec.get("command", ""))
    if not (Path(command).exists() or shutil.which(command)):
        lines.append(f"'{name}' starts {command!r}, which was not found.")
        ok = False
    elif "mcpguard.cli" in args and not _imports_mcpguard(command, spec.get("env")):
        lines.append(f"'{name}' starts {command!r}, but that Python cannot import mcpguard. "
                     f"Install it there (pip install -e <mcpguard folder>) or run install again from the right Python.")
        ok = False
    unguarded = [n for n, s in servers.items() if n != name and not is_gateway(s)]
    if unguarded:
        lines.append(f"Not behind the gateway: {', '.join(unguarded)} (`install --take-over` moves them).")
    if ok:
        lines.append(f"'{name}' is installed and points at {config.resolve()}.")
    return ok, lines
