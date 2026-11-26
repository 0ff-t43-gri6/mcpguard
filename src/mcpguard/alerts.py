"""Webhook alerts for security-relevant audit events.

Matching records are collected for ``min_interval`` seconds and sent as one POST,
so a burst of blocks produces one message rather than hundreds. The payload has a
``text`` field (Slack and most chat webhooks accept it as is) plus the records
themselves for machine consumers.

Delivery runs on a background thread and never blocks the gateway. Failures are
logged and the batch is dropped; alerts are best effort, the audit log is the record.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import threading
import urllib.request
from collections import deque

from .net import open_url

log = logging.getLogger("mcpguard.alerts")

DEFAULT_EVENTS = ("call.blocked", "audit.tampered", "*.quarantined", "server.exited", "server.failed",
                  "config.reload_failed", "audit.recovered", "gateway.error")
MAX_BATCH = 50
KEEP_FIELDS = ("seq", "ts", "event", "tool", "server", "client", "reason", "error", "mode")


def _plain(text: str) -> str:
    """Chat webhooks read <!channel>, <@U123> and <url|label> as markup, and tool names and reasons come from
    servers: escape the three characters Slack asks for so nothing a server wrote can ping people or hide a link."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def describe(rec: dict) -> str:
    target = rec.get("tool") or rec.get("server") or ""
    detail = rec.get("reason") or rec.get("error") or ""
    if not detail and rec.get("findings"):
        detail = rec["findings"][0].get("message", "")
    who = f" (client {rec['client']})" if rec.get("client") not in (None, "stdio") else ""
    parts = [rec.get("event", "?"), target + who, detail]
    return ": ".join(p for p in parts if p)


class Alerter:
    def __init__(self, url: str, events: list[str] | tuple[str, ...] = DEFAULT_EVENTS,
                 min_interval: float = 10.0, timeout: float = 10.0):
        self.url = url
        self.events = tuple(events)
        self.min_interval = min_interval
        self.timeout = timeout
        self.sent = 0
        self.failed = 0
        self._queue: deque[dict] = deque(maxlen=1000)
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="mcpguard-alerts", daemon=True)
        self._thread.start()

    def matches(self, rec: dict) -> bool:
        return any(fnmatch.fnmatch(rec.get("event", ""), pat) for pat in self.events)

    def __call__(self, rec: dict) -> None:
        if self.matches(rec):
            self._queue.append({k: rec[k] for k in KEEP_FIELDS if k in rec}
                               | ({"findings": rec["findings"][:3]} if rec.get("findings") else {}))
            self._wake.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait()
            self._wake.clear()
            # Let a burst accumulate, unless we are shutting down.
            self._stop.wait(self.min_interval)
            self._flush()

    def _flush(self) -> None:
        batch: list[dict] = []
        while self._queue and len(batch) < MAX_BATCH:
            batch.append(self._queue.popleft())
        if not batch:
            return
        lines = [f"- {_plain(describe(r))}" for r in batch]
        more = len(self._queue)
        header = f"mcpguard: {len(batch)} security event{'s' * (len(batch) != 1)}"
        text = "\n".join([header, *lines] + ([f"...and {more} more"] if more else []))
        body = json.dumps({"text": text, "records": batch}).encode()
        req = urllib.request.Request(self.url, data=body, method="POST",  # noqa: S310 - open_url checks the scheme
                                     headers={"Content-Type": "application/json", "User-Agent": "mcpguard"})
        try:
            open_url(req, timeout=self.timeout).close()
            self.sent += len(batch)
        except Exception as e:  # noqa: BLE001 - delivery problems are logged, never raised
            self.failed += len(batch)
            log.warning("alert delivery failed (%d events dropped): %s", len(batch), e)
        if self._queue:
            self._wake.set()

    def close(self, flush: bool = True) -> None:
        self._stop.set()
        self._wake.set()
        self._thread.join(timeout=self.timeout + 1)
        if flush:
            self._flush()
