"""Compliance report built from the audit log, as Markdown or as one self-contained HTML page."""

from __future__ import annotations

import datetime as dt
import html
from collections import Counter

from .audit import read_log, verify


def _ts(rec: dict) -> str:
    return dt.datetime.fromtimestamp(rec["ts"], dt.UTC).strftime("%Y-%m-%d %H:%M:%SZ")


def _safe(text: str) -> str:
    """Names and reasons come from servers: show control characters (terminal escapes) as \\xNN."""
    return "".join(c if c.isprintable() or c == "\n" else f"\\x{ord(c):02x}" for c in text)


def _cell(value) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def _table(header: list[str], rows: list[list]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(_cell(v) for v in row) + " |" for row in rows]
    return out


def build_report(audit_path: str, limit: int = 200, key: bytes | None = None) -> str:
    records = read_log(audit_path)
    ok, msg = verify(audit_path, key)
    by_event: dict[str, list[dict]] = {}
    for r in records:
        by_event.setdefault(r["event"], []).append(r)

    def events(*names: str) -> list[dict]:
        return [r for n in names for r in by_event.get(n, [])]

    blocked = events("call.blocked")
    would = events("call.would_block")
    allowed = events("call.allowed")
    approvals = events("call.approval")
    quarantined = [r for r in records if r["event"].endswith(".quarantined")]
    outages = events("server.failed", "server.exited")
    reloads = events("config.reloaded")
    findings = [f for r in records for f in r.get("findings", []) or []]
    severity: Counter[str] = Counter(f["severity"] for f in findings)
    rule_counts: Counter[str] = Counter(f["rule"] for f in findings)
    rug_pulls = sum(1 for f in findings if f["rule"].startswith("rug_pull.changed"))
    data_events = sum(1 for f in findings if f["rule"].startswith(("secret", "exfiltration")))
    anomalies = sum(1 for f in findings if f["rule"].startswith("anomaly"))

    lines = ["# mcpguard report", ""]
    if records:
        lines.append(f"Covers {_ts(records[0])} to {_ts(records[-1])}, {len(records)} audit records.")
    else:
        lines.append("The audit log is empty.")
    lines += ["", f"Log integrity: **{'PASS' if ok else 'FAIL'}**. {msg[0].upper()}{msg[1:]}.", "", "## Summary", ""]
    lines += _table(["Measure", "Count"], [
        ["Tool calls allowed", len(allowed)],
        ["Tool calls blocked", len(blocked)],
        ["Would have blocked (monitor mode)", len(would)],
        ["Definitions quarantined", len(quarantined)],
        ["Definition changes caught (rug pulls)", rug_pulls],
        ["Approvals requested / granted", f"{len(approvals)} / {sum(1 for a in approvals if a.get('approved'))}"],
        ["Secret or exfiltration findings", data_events],
        ["Behavioural anomalies", anomalies],
        ["Server outages", len(outages)],
        ["Live config changes", len(reloads)],
    ])
    if severity:
        order = ("critical", "high", "medium", "low")
        lines += ["", "Findings by severity: " + ", ".join(f"{s} {severity[s]}" for s in order if severity[s]) + "."]

    for title, rows in (("Blocked calls", blocked), ("Would have blocked (monitor mode)", would)):
        if rows:
            lines += ["", f"## {title}", ""]
            shown = [[_ts(r), r.get("tool"), r.get("reason")] for r in rows[-limit:]]
            lines += _table(["Time", "Target", "Reason"], shown)
            if len(rows) > limit:
                lines.append(f"\nShowing the latest {limit} of {len(rows)}.")
    if quarantined:
        lines += ["", "## Quarantined definitions", ""]
        lines += _table(["Time", "Server", "Name", "Rules"], [
            [_ts(r), r.get("server"), r.get("tool"), ", ".join(sorted({f["rule"] for f in r.get("findings", [])}))]
            for r in quarantined])
    if rule_counts:
        lines += ["", "## Detector activity", ""]
        lines += _table(["Rule", "Count"], [[rule, n] for rule, n in rule_counts.most_common()])
    if outages:
        lines += ["", "## Server outages", ""]
        lines += _table(["Time", "Server", "Error"], [[_ts(r), r.get("server"), r.get("error")] for r in outages])

    lines += ["", "## Control evidence", ""]
    lines += _table(["Control", "Evidence"], [
        ["Access control", f"Per-tool allow/deny/ask policy with argument conditions; {len(blocked)} calls blocked, "
                           f"{len(approvals)} human decisions recorded."],
        ["Change management", f"Every tool, prompt and resource definition is pinned by hash; "
                              f"{rug_pulls} unapproved changes caught."],
        ["Logging integrity", f"Hash-chained audit log; verification {'passed' if ok else 'FAILED'}."],
        ["Data protection", f"Secrets redacted from results and blocked in arguments; {data_events} related findings."],
        ["Availability", f"Supervised upstream servers; {len(outages)} outages recorded."],
    ])
    lines.append("")
    return _safe("\n".join(lines))


_CSS = """
:root{--bg:#0f0f0f;--surface:#1a1a1a;--ink:#fff;--muted:#a3a3a3;--accent:#dafa9c;--accent-ink:#0f0f0f;
--line:#2a2a2a;--bad:#ff8a80;--ok:#dafa9c;--sans:"Instrument Sans",system-ui,-apple-system,"Segoe UI",sans-serif;
--mono:"DM Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:400 16px/1.55 var(--sans)}
main{max-width:1040px;margin:0 auto;padding:64px 24px 96px}
.brand{display:flex;align-items:center;gap:10px;font-weight:500;color:var(--muted);margin-bottom:40px}
.mark{width:20px;height:20px;border:3px solid var(--accent);border-bottom:0;border-radius:10px 10px 0 0}
h1{font-size:clamp(36px,6vw,64px);line-height:1.04;letter-spacing:-.035em;font-weight:500;margin:0 0 16px}
h2{font-size:24px;letter-spacing:-.02em;font-weight:500;margin:56px 0 16px}
p{margin:0 0 12px}.lede{color:var(--muted);font-size:18px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font:500 13px var(--mono);
background:var(--accent);color:var(--accent-ink)}
.badge.fail{background:var(--bad);color:#0f0f0f}
.sev{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
.sev span{padding:4px 12px;border:1px solid var(--line);border-radius:999px;font-size:14px}
.sev b{font-family:var(--mono);font-weight:500;margin-left:6px;color:var(--accent)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:15px}
th,td{text-align:left;padding:10px 16px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:500;font-size:13px}
tr:last-child td{border-bottom:0}
td:last-child,td.n{font-family:var(--mono);font-size:14px}
.note{color:var(--muted);font-size:14px}
@media print{:root{--bg:#fff;--surface:#fff;--ink:#0f0f0f;--muted:#4d4d4d;--line:#cfcfcf;
--accent:#0f0f0f;--accent-ink:#fff}
main{padding:0}h2{break-after:avoid}.card{break-inside:avoid;overflow:visible}
.badge.fail{background:#b00020;color:#fff}}
"""


def _inline(text: str) -> str:
    out = html.escape(text.replace("\\|", "|"), quote=True)
    parts = out.split("**")
    return "".join(f"<strong>{p}</strong>" if i % 2 else p for i, p in enumerate(parts))


def _split_row(line: str) -> list[str]:
    cells, cur, esc = [], [], False
    for ch in line.strip()[1:-1]:
        if esc:
            cur.append("|" if ch == "|" else "\\" + ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == "|":
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    cells.append("".join(cur).strip())
    return cells


def build_report_html(audit_path: str, limit: int = 200, key: bytes | None = None) -> str:
    """The same report as build_report, as one HTML file with its own style and no external requests."""
    lines = build_report(audit_path, limit, key).split("\n")
    body: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("# "):
            body.append(f"<h1>{_inline(line[2:])}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{_inline(line[3:])}</h2>")
        elif line.startswith("|"):
            header = _split_row(line)
            i += 2
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append(_split_row(lines[i]))
                i += 1
            head = "".join(f"<th>{html.escape(c)}</th>" for c in header)
            trs = "".join("<tr>" + "".join(f"<td>{html.escape(c)}</td>" for c in r) + "</tr>" for r in rows)
            body.append(
                f'<div class="card"><table><thead><tr>{head}</tr></thead><tbody>{trs}</tbody></table></div>'
            )
            continue
        elif line.startswith("Log integrity:"):
            ok = "**PASS**" in line
            rest = line.split("**", 2)[2].lstrip(". ")
            badge = f'<span class="badge{"" if ok else " fail"}">{"PASS" if ok else "FAIL"}</span>'
            body.append(f"<p>Log integrity {badge} {html.escape(rest)}</p>")
        elif line.startswith("Findings by severity:"):
            pairs = [p.rsplit(" ", 1) for p in line.split(": ", 1)[1].split(", ")]
            chips = "".join(f"<span>{html.escape(n)}<b>{html.escape(c.rstrip('.'))}</b></span>" for n, c in pairs)
            body.append(f'<div class="sev">{chips}</div>')
        elif line.startswith("Showing the latest"):
            body.append(f'<p class="note">{html.escape(line)}</p>')
        elif line.strip():
            cls = ' class="lede"' if line.startswith(("Covers", "The audit log")) else ""
            body.append(f"<p{cls}>{_inline(line)}</p>")
        i += 1
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>mcpguard report</title>"
        f"<style>{_CSS}</style></head><body><main>"
        '<div class="brand"><span class="mark" aria-hidden="true"></span>mcpguard</div>'
        + "\n".join(body)
        + "</main></body></html>\n"
    )
