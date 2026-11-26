"""Prometheus metrics derived from audit records.

The same ``Metrics`` object is fed from the gateway's audit listener (``serve``)
and from the dashboard's audit index (``run`` + dashboard), so both expose the
same series. Labels are kept to low-cardinality values: event names, outcomes,
server names, rule names and severities. Tool arguments never appear.
"""

from __future__ import annotations

import threading
from collections import Counter

SEP = "__"
OUTCOMES = {"call.allowed": "allowed", "call.blocked": "blocked", "call.would_block": "would_block",
            "call.failed": "failed", "call.upstream_error": "upstream_error"}


def _label(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _server_of(rec: dict) -> str:
    tool = rec.get("tool") or ""
    if SEP in tool:
        return tool.split(SEP, 1)[0]
    return rec.get("server") or "unknown"


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.events: Counter[str] = Counter()
        self.calls: Counter[tuple[str, str]] = Counter()
        self.findings: Counter[tuple[str, str]] = Counter()
        self.latency_sum: Counter[str] = Counter()
        self.latency_count: Counter[str] = Counter()

    def observe(self, rec: dict) -> None:
        with self._lock:
            event = rec.get("event", "")
            self.events[event] += 1
            outcome = OUTCOMES.get(event)
            if outcome:
                server = _server_of(rec)
                self.calls[(outcome, server)] += 1
                if event == "call.allowed" and isinstance(rec.get("latency_ms"), (int, float)):
                    self.latency_sum[server] += rec["latency_ms"]
                    self.latency_count[server] += 1
            for f in rec.get("findings") or []:
                self.findings[(f.get("rule", "?"), f.get("severity", "?"))] += 1

    __call__ = observe  # usable directly as an AuditLog listener

    def render(self, gauges: dict[str, tuple[str, float]] | None = None) -> str:
        """Prometheus text exposition. ``gauges`` maps name -> (help, value)."""
        out: list[str] = []

        def family(name: str, kind: str, help_text: str, samples: list[tuple[dict, float]]) -> None:
            out.append(f"# HELP {name} {help_text}")
            out.append(f"# TYPE {name} {kind}")
            for labels, value in samples:
                lab = ",".join(f'{k}="{_label(v)}"' for k, v in labels.items())
                out.append(f"{name}{{{lab}}} {value:g}" if lab else f"{name} {value:g}")

        with self._lock:
            family("mcpguard_events_total", "counter", "Audit events by type.",
                   [({"event": e}, n) for e, n in sorted(self.events.items())])
            family("mcpguard_calls_total", "counter", "Tool, prompt and resource requests by outcome.",
                   [({"outcome": o, "server": s}, n) for (o, s), n in sorted(self.calls.items())])
            family("mcpguard_findings_total", "counter", "Detector findings by rule and severity.",
                   [({"rule": r, "severity": sv}, n) for (r, sv), n in sorted(self.findings.items())])
            family("mcpguard_call_latency_ms_sum", "counter", "Total latency of allowed calls, in milliseconds.",
                   [({"server": s}, v) for s, v in sorted(self.latency_sum.items())])
            family("mcpguard_call_latency_ms_count", "counter", "Number of allowed calls with a latency.",
                   [({"server": s}, v) for s, v in sorted(self.latency_count.items())])
        for name, (help_text, value) in sorted((gauges or {}).items()):
            family(name, "gauge", help_text, [({}, value)])
        return "\n".join(out) + "\n"
