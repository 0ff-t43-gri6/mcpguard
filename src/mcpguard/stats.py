"""`mcpguard stats`: what the gateway did recently, from the audit log, in the terminal."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .audit import read_log

BLOCKED = ("call.blocked", "call.would_block")
FAILED = ("call.failed", "call.upstream_error")


@dataclass
class Stats:
    since: float
    calls: Counter = field(default_factory=Counter)       # tool -> allowed calls
    blocked: Counter = field(default_factory=Counter)     # tool -> blocked (or would-block) calls
    failed: Counter = field(default_factory=Counter)      # tool -> failed calls
    approvals: Counter = field(default_factory=Counter)   # "approved" / "denied"
    rules: Counter = field(default_factory=Counter)       # rule -> findings
    reasons: Counter = field(default_factory=Counter)     # block reason -> count
    servers: Counter = field(default_factory=Counter)     # event (server.failed, ...) -> count
    latency: dict = field(default_factory=dict)           # tool -> [ms]
    quarantined: set = field(default_factory=set)
    would_block_only: bool = True


def collect(path: str | Path, hours: float = 24.0, now: float | None = None) -> Stats:
    now = time.time() if now is None else now
    st = Stats(since=now - hours * 3600)
    for r in read_log(path):
        if r.get("ts", 0) < st.since:
            continue
        ev, tool = r.get("event", ""), r.get("tool", "?")
        if ev == "call.allowed":
            st.calls[tool] += 1
            if isinstance(r.get("latency_ms"), int | float):
                st.latency.setdefault(tool, []).append(r["latency_ms"])
        elif ev in BLOCKED:
            st.blocked[tool] += 1
            st.reasons[str(r.get("reason", ""))[:80]] += 1
            st.would_block_only &= ev == "call.would_block"
        elif ev in FAILED:
            st.failed[tool] += 1
        elif ev == "call.approval":
            st.approvals["approved" if r.get("approved") else "denied"] += 1
        elif ev.startswith("server.") and ev != "server.start":
            st.servers[ev] += 1
        elif ev.endswith(".quarantined"):
            st.quarantined.add(str(r.get("tool") or r.get("name") or "?"))
        for f in r.get("findings", []) or []:
            if isinstance(f, dict) and f.get("rule"):
                st.rules[f["rule"]] += 1
    return st


def printable(text: str) -> str:
    """Names come from servers: never print their control characters (terminal escapes) raw."""
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in str(text))


def _p95(values: list[float]) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, round(0.95 * (len(s) - 1)))]


def current_state(state_path: str | Path) -> list[str]:
    """What is true right now (not history): live gateways and what each is holding back."""
    from .state import _dicts, _num, is_live, read_merged
    snap = read_merged(state_path)
    if not snap:
        return ["Right now: no gateway has run yet."]
    if not is_live(snap):
        lines = ["Right now: no gateway is running (the numbers below are history)."]
    else:
        source = str(snap.get("mode_source", "config"))
        via = f" ({printable(source)[:40]})" if source != "config" else ""
        lines = [f"Right now: {int(_num(snap.get('processes'), 1))} gateway process(es) running, "
                 f"mode {printable(str(snap.get('mode', '?')))[:20]}{via}."]
    held = [i for i in _dicts(snap.get("inventory")) if i.get("status") == "quarantined"]
    if held:
        lines.append("Quarantined now: " + ", ".join(printable(i.get("name", "?"))[:60] for i in held[:30])
                     + (f" and {len(held) - 30} more" if len(held) > 30 else ""))
        lines.append("  Why: " + printable(str(held[0].get("reason", "")))[:160])
        lines.append("  Next: mcpguard pins pending, then mcpguard pins diff <server>")
    elif is_live(snap):
        lines.append("Quarantined now: none.")
    return lines


def render(st: Stats, hours: float, top: int = 10) -> str:
    total = sum(st.calls.values())
    blocked = sum(st.blocked.values())
    lines = [f"Last {hours:g} hours: {total} call(s) allowed, {blocked} "
             + ("would have been blocked (monitor mode)" if blocked and st.would_block_only else "blocked")
             + f", {sum(st.failed.values())} failed."]
    if st.approvals:
        lines.append(f"Approvals: {st.approvals['approved']} approved, {st.approvals['denied']} denied.")
    if st.calls or st.blocked:
        lines += ["", f"{'Tool':<40} {'allowed':>8} {'blocked':>8} {'p95 ms':>8}"]
        tools = sorted(set(st.calls) | set(st.blocked), key=lambda t: -(st.calls[t] + st.blocked[t]))
        for t in tools[:top]:
            p95 = f"{_p95(st.latency[t]):.0f}" if st.latency.get(t) else "-"
            lines.append(f"{printable(t)[:40]:<40} {st.calls[t]:>8} {st.blocked[t]:>8} {p95:>8}")
        if len(tools) > top:
            lines.append(f"... and {len(tools) - top} more")
    if st.reasons:
        lines += ["", "Why calls were blocked:"] + [f"  {n:>4}  {printable(r)}" for r, n in st.reasons.most_common(5)]
    if st.rules:
        lines += ["", "Findings by rule:"] + [f"  {n:>4}  {printable(r)}" for r, n in st.rules.most_common(top)]
    if st.quarantined:
        lines += ["", "Quarantined at some point in this period: "
                  + ", ".join(printable(q) for q in sorted(st.quarantined))]
    if st.servers:
        lines += ["", "Server problems: " + ", ".join(f"{e} x{n}" for e, n in st.servers.most_common())]
    return "\n".join(lines)
