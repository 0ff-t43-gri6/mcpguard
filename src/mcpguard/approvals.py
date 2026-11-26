"""Human approval channels for 'ask' rules.

tty        prompt on the console (y = allow once, a = allow for a while, anything else = deny)
dashboard  queue the request on disk and answer it in the dashboard
allow/deny fixed answer (useful for CI and unattended runs)

Unanswered requests are denied when the timeout passes (fail closed). An answer
can carry a time window ("allow for 15 minutes"); the gateway then lets the same
client call the same target without asking again until the window ends.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import fileio
from .detect import _scrub, redact_secrets


@dataclass(frozen=True)
class Verdict:
    approved: bool
    remember_seconds: float = 0.0

    @classmethod
    def of(cls, value) -> Verdict:
        """Accept a Verdict, a bool, or an (approved, minutes) pair from custom approvers."""
        if isinstance(value, Verdict):
            return value
        if isinstance(value, tuple):
            approved, minutes = value
            return cls(bool(approved), max(0.0, float(minutes)) * 60 if approved else 0.0)
        return cls(bool(value))


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")

# "Allow for N minutes" grants, shared by every gateway process that uses this approvals
# folder: approving in the dashboard once covers all of them.
GRANTS_FILE = "grants.json"
MAX_PENDING = 20


def _grant_key(client: str, target: str) -> str:
    return f"{client}\x1f{target}"


def load_grants(directory: str | Path, now: float | None = None) -> dict[tuple[str, str], float]:
    now = time.time() if now is None else now
    raw = fileio.load_json(Path(directory) / GRANTS_FILE, {})
    out = {}
    for key, until in raw.items():
        client, _, target = str(key).partition("\x1f")
        if isinstance(until, int | float) and until > now and target:
            out[(client, target)] = float(until)
    return out


def save_grant(directory: str | Path, client: str, target: str, until: float) -> None:
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    with fileio.locked(d / (GRANTS_FILE + ".lock")):
        now = time.time()
        grants = {_grant_key(c, t): u for (c, t), u in load_grants(d, now).items()}  # drops expired ones
        grants[_grant_key(client, target)] = until
        fileio.write_atomic(d / GRANTS_FILE, json.dumps(grants, indent=1))


class Approvals:
    def __init__(self, mode: str = "tty", directory: str | Path = "mcpguard-approvals", timeout: float = 120,
                 remember_minutes: int = 15):
        if mode not in ("tty", "dashboard", "allow", "deny"):
            raise ValueError(f"unknown approval mode: {mode}")
        self.mode = mode
        self.dir = Path(directory)
        self.timeout = timeout
        self.remember_minutes = remember_minutes
        if mode == "dashboard":
            (self.dir / "pending").mkdir(parents=True, exist_ok=True)
            (self.dir / "decided").mkdir(parents=True, exist_ok=True)

    async def __call__(self, name: str, args: dict, reason: str = "") -> Verdict:
        if self.mode == "allow":
            return Verdict(True)
        if self.mode == "deny":
            return Verdict(False)
        if self.mode == "tty":
            return await asyncio.get_running_loop().run_in_executor(None, self._tty, name, args)
        return await self._queue(name, args, reason)

    def _tty(self, name: str, args: dict) -> Verdict:
        """Prompt on the console. stdin/stdout carry the protocol, so open the console directly."""
        shown = _scrub(redact_secrets(json.dumps(args, ensure_ascii=False)))[:300]
        name = _CONTROL.sub("?", name)[:120]  # a server picks the tool name: no escape codes, no fake second question
        options = "[y]es once" + (f", [a]llow for {self.remember_minutes} min" if self.remember_minutes else "")
        prompt = f"\nmcpguard: allow {name}?\n  arguments: {shown}\n  {options}, anything else denies: "
        try:
            if os.name == "nt":
                with open("CONOUT$", "w", encoding="locale") as out, open("CONIN$", encoding="locale") as inp:
                    out.write(prompt)
                    out.flush()
                    answer = inp.readline()
            else:
                with open("/dev/tty", "r+", encoding="locale") as tty:
                    tty.write(prompt)
                    tty.flush()
                    answer = tty.readline()
        except OSError:
            return Verdict(False)  # no console attached: fail closed
        answer = answer.strip().lower()
        if answer in ("a", "always") and self.remember_minutes:
            return Verdict(True, self.remember_minutes * 60)
        return Verdict(answer in ("y", "yes"))

    async def _queue(self, name: str, args: dict, reason: str) -> Verdict:
        # A model (or an injection steering it) can fire 'ask' calls in a loop; past this many
        # waiting at once, new ones are denied instead of burying the real one in the dashboard.
        if len(list(self.dir.glob("pending/*.json"))) >= MAX_PENDING:
            return Verdict(False)
        rid = uuid.uuid4().hex[:12]
        pending = self.dir / "pending" / f"{rid}.json"
        decided = self.dir / "decided" / f"{rid}.json"
        # Pending requests are files on disk and appear in the dashboard: no secrets, no personal data.
        shown = json.loads(_scrub(redact_secrets(json.dumps(args, ensure_ascii=False))))
        tmp = pending.with_suffix(".tmp")
        now = time.time()
        request = {"id": rid, "tool": name, "args": shown, "reason": reason, "ts": now,
                   "expires": now + self.timeout, "remember_minutes": self.remember_minutes}
        tmp.write_text(json.dumps(request), encoding="utf-8")
        os.replace(tmp, pending)  # the dashboard never sees a half-written request
        try:
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                if decided.exists():
                    try:
                        answer = json.loads(decided.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        answer = None
                    if isinstance(answer, dict):
                        approved = bool(answer.get("approved"))
                        minutes = min(max(int(answer.get("remember_minutes") or 0), 0), self.remember_minutes)
                        return Verdict(approved, minutes * 60 if approved else 0.0)
                await asyncio.sleep(0.25)
            return Verdict(False)
        finally:
            pending.unlink(missing_ok=True)
            decided.unlink(missing_ok=True)


# ---- used by the dashboard process

def token_for(directory: str | Path) -> str:
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    # A process that lost the race could read an empty token, and the dashboard then rejected decisions.
    return fileio.create_once(d / ".token", lambda: secrets.token_urlsafe(24))


def list_pending(directory: str | Path) -> list[dict]:
    """Requests still waiting. Stale files left by a crashed gateway are skipped."""
    out = []
    now = time.time()
    for p in sorted((Path(directory) / "pending").glob("*.json")):
        try:
            req = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if req.get("expires", 0) > now:
            out.append(req)
    return out


def decide(directory: str | Path, rid: str, approved: bool, remember_minutes: int = 0) -> bool:
    if not rid.isalnum() or not (Path(directory) / "pending" / f"{rid}.json").exists():
        return False
    decided = Path(directory) / "decided"
    decided.mkdir(parents=True, exist_ok=True)
    tmp = decided / f"{rid}.tmp"
    tmp.write_text(json.dumps({"approved": approved, "remember_minutes": max(0, int(remember_minutes)),
                               "ts": time.time()}), encoding="utf-8")
    os.replace(tmp, decided / f"{rid}.json")
    return True
