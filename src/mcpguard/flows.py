"""Flow rules: tool sequences that need a decision.

Each tool can be harmless alone. Reading customer records and then sending an email is how data
leaves, and the data itself need not look sensitive. A flow rule names the two steps::

    [[flows]]
    name = "crm-to-email"
    after = ["crm/*"]            # if one of these was used earlier in this session...
    then = ["email/send_*"]      # ...a call to one of these needs a decision
    within_minutes = 30
    action = "ask"               # or "deny"

The tracker remembers recent calls per client session, in memory and bounded. It matches by tool
name, so it shows that a risky sequence happened, not that data flowed from one step to the other.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass

from .policy import ASK, DENY, _name_matches

ACTIONS = (ASK, DENY)
MAX_FLOWS = 100
MAX_PATTERNS = 50
MAX_TEXT = 200
MAX_MINUTES = 24 * 60
DEFAULT_MINUTES = 30.0
MAX_CALLS_KEPT = 200  # per session
MAX_SESSIONS = 2000


@dataclass(frozen=True)
class FlowRule:
    name: str
    after: tuple[str, ...]
    then: tuple[str, ...]
    action: str = ASK
    within_minutes: float = DEFAULT_MINUTES
    clients: tuple[str, ...] = ()


@dataclass(frozen=True)
class FlowHit:
    rule: FlowRule
    earlier: str  # the earlier tool that set the rule off

    @property
    def reason(self) -> str:
        return f"flow '{self.rule.name}': '{self.earlier}' was used earlier in this session"


def _strings(value, where: str) -> tuple[str, ...]:
    if (not isinstance(value, list) or not value or len(value) > MAX_PATTERNS
            or not all(isinstance(v, str) and 0 < len(v) <= MAX_TEXT for v in value)):
        raise ValueError(f"{where} must be a list of 1 to {MAX_PATTERNS} tool name patterns")
    return tuple(value)


def parse_flows(raw) -> tuple[FlowRule, ...]:
    """Turn the [[flows]] tables into rules. Raises ValueError with a readable message."""
    if raw in (None, []):
        return ()
    if not isinstance(raw, list) or not all(isinstance(r, dict) for r in raw):
        raise ValueError("flows must be a list of tables ([[flows]])")
    if len(raw) > MAX_FLOWS:
        raise ValueError(f"flows: at most {MAX_FLOWS} rules")
    rules, seen = [], set()
    for i, r in enumerate(raw):
        where = f"flows[{i}]"
        name = r.get("name")
        if (not isinstance(name, str) or not name.strip() or len(name) > 60
                or not name.isprintable()):  # the name is shown to whoever approves a call
            raise ValueError(f"{where} needs a 'name' (up to 60 printable characters)")
        if name in seen:
            raise ValueError(f"{where}: the name '{name}' is used twice")
        seen.add(name)
        action = r.get("action", ASK)
        if action not in ACTIONS:
            raise ValueError(f"{where}.action must be one of {', '.join(ACTIONS)}; got {action!r}")
        minutes = r.get("within_minutes", DEFAULT_MINUTES)
        if isinstance(minutes, bool) or not isinstance(minutes, int | float) or not 0 < minutes <= MAX_MINUTES:
            raise ValueError(f"{where}.within_minutes must be more than 0 and at most {MAX_MINUTES}")
        clients = _strings(r["clients"], f"{where}.clients") if "clients" in r else ()
        rules.append(FlowRule(name, _strings(r.get("after"), f"{where}.after"),
                              _strings(r.get("then"), f"{where}.then"), action, float(minutes), clients))
    return tuple(rules)


class FlowTracker:
    """Recent tool calls for each client session, and the check against the rules."""

    def __init__(self, rules: tuple[FlowRule, ...] = ()) -> None:
        self.rules = rules
        self._recent: dict[tuple[str, str], deque[tuple[float, str]]] = {}

    def set_rules(self, rules: tuple[FlowRule, ...]) -> None:
        self.rules = rules  # what was seen so far is kept: a reload must not make the gateway forget

    def _relevant(self, slash: str) -> bool:
        return any(_name_matches(slash, p) for r in self.rules for p in r.after)

    def record(self, slash: str, client: str, session: str, now: float | None = None) -> None:
        """Remember a call that went through, but only if some rule cares about it."""
        if not self.rules or not self._relevant(slash):
            return
        key = (client, session)
        calls = self._recent.get(key)
        if calls is None:
            if len(self._recent) >= MAX_SESSIONS:  # drop the session that was quiet the longest
                oldest = min(self._recent, key=lambda k: self._recent[k][-1][0] if self._recent[k] else 0.0)
                del self._recent[oldest]
            calls = self._recent[key] = deque(maxlen=MAX_CALLS_KEPT)
        calls.append((time.time() if now is None else now, slash))

    def check(self, slash: str, client: str, session: str, now: float | None = None) -> FlowHit | None:
        """The strictest rule this call sets off (deny before ask), or None."""
        calls = self._recent.get((client, session))
        if not self.rules or not calls:
            return None
        now = time.time() if now is None else now
        best: FlowHit | None = None
        for rule in self.rules:
            if rule.clients and not any(_name_matches(client, p) for p in rule.clients):
                continue
            if not any(_name_matches(slash, p) for p in rule.then):
                continue
            horizon = now - rule.within_minutes * 60
            earlier = next((s for t, s in reversed(calls) if t >= horizon and s != slash
                            and any(_name_matches(s, p) for p in rule.after)), None)
            if earlier is None:
                continue
            if best is None or (rule.action == DENY and best.rule.action != DENY):
                best = FlowHit(rule, earlier)
        return best
