"""``mcpguard export``: the audit log in formats other tools read.

    jsonl  one JSON object per line (as stored, without chain fields unless --raw)
    csv    one row per record, fixed columns
    cef    ArcSight Common Event Format, for SIEMs (Splunk, QRadar, Sentinel, ...)

Exported records carry no arguments or results: the audit log never stores them.
"""

from __future__ import annotations

import csv
import io
import json
import re
import time
from collections.abc import Iterable, Iterator

from . import __version__
from .detect import SEVERITIES

COLUMNS = ["time", "seq", "event", "client", "server", "tool", "severity", "rules", "reason"]
_CHAIN = ("hash", "prev", "sig", "alg")
# CEF severity is 0-10.
_CEF_SEVERITY = {"": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _severity(rec: dict) -> str:
    worst = rec.get("severity") or ""
    for f in rec.get("findings") or []:
        s = f.get("severity", "")
        if SEVERITIES.get(s, 0) > SEVERITIES.get(worst, 0):
            worst = s
    if not worst and rec.get("event", "").endswith((".blocked", ".quarantined", ".denied")):
        worst = "high"
    return worst


_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069]")


_DIRECTION = re.compile("[\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def _plain(value):
    """Terminal control characters (escape sequences) shown as \\xNN, so opening or `cat`-ing the export
    cannot move the cursor, retitle the window or hide text."""
    if isinstance(value, str):
        return _CONTROL.sub(lambda m: f"\\x{ord(m.group(0)):02x}" if ord(m.group(0)) < 256
                            else f"\\u{ord(m.group(0)):04x}", value)
    return value


def flatten(rec: dict) -> dict:
    tool = rec.get("tool") or ""
    server = rec.get("server") or (tool.split("__", 1)[0] if "__" in tool else "")
    rules = sorted({f.get("rule", "") for f in rec.get("findings") or [] if f.get("rule")})
    return {"time": _iso(rec.get("ts", 0)), "seq": rec.get("seq", ""), "event": rec.get("event", ""),
            "client": rec.get("client", ""), "server": server, "tool": tool, "severity": _severity(rec),
            "rules": " ".join(rules), "reason": str(rec.get("reason", ""))}


def _cef_escape(value: str, header: bool = False) -> str:
    value = value.replace("\\", "\\\\").replace("\r", " ").replace("\n", " ")
    return value.replace("|", "\\|") if header else value.replace("=", "\\=")


def cef_line(rec: dict) -> str:
    row = {k: _plain(v) for k, v in flatten(rec).items()}
    ext = {"rt": int(rec.get("ts", 0) * 1000), "externalId": row["seq"], "suser": row["client"],
           "dhost": row["server"], "act": row["event"].rsplit(".", 1)[-1], "cs1Label": "tool", "cs1": row["tool"],
           "cs2Label": "rules", "cs2": row["rules"], "msg": row["reason"]}
    body = " ".join(f"{k}={_cef_escape(str(v))}" for k, v in ext.items() if v not in ("", None))
    name = _cef_escape(row["event"], header=True)
    return f"CEF:0|mcpguard|mcpguard|{__version__}|{name}|{name}|{_CEF_SEVERITY.get(row['severity'], 1)}|{body}"


def export(records: Iterable[dict], fmt: str, raw: bool = False) -> Iterator[str]:
    """Lines of the export, without trailing newlines."""
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="")
        writer.writerow(COLUMNS)
        yield buf.getvalue()
        for rec in records:
            buf.seek(0)
            buf.truncate()
            row = {k: _plain(v) for k, v in flatten(rec).items()}
            # A leading =, +, - or @ (also after a tab or carriage return) would run as a formula
            # when the file is opened in a spreadsheet.
            writer.writerow([("'" + v if isinstance(v, str) and v.lstrip("\t\r\n ")[:1] in ("=", "+", "-", "@") else v)
                             for v in (row[c] for c in COLUMNS)])
            yield buf.getvalue()
    elif fmt == "cef":
        for rec in records:
            yield _plain(cef_line(rec))
    else:
        for rec in records:
            line = json.dumps(rec if raw else {k: v for k, v in rec.items() if k not in _CHAIN},
                              ensure_ascii=False, sort_keys=True)
            # Direction overrides are written as \uXXXX: still the same JSON string, but a terminal shows it as typed.
            yield _DIRECTION.sub(lambda m: f"\\u{ord(m.group(0)):04x}", line)
