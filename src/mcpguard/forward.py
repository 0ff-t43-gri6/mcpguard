"""Stream every audit record to a server you control, as it is written.

A log kept only on the machine it describes can be deleted by whoever controls that machine.
A copy that already left cannot. The forwarder sends records in batches (newline-delimited
JSON in one POST body), remembers how far it got in a small cursor file, retries with backoff
while the server is unreachable, and after an outage or restart catches up from the log itself.

The records are the signed audit records, so the receiver can keep them as they are and
anyone holding the audit key can check them with the same rules ``mcpguard verify`` uses.
Delivery is best effort and never blocks the gateway: if the server is down, calls go on and
the records are sent later.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.request
from collections import deque
from pathlib import Path

from .audit import read_log
from .fileio import load_json, write_atomic
from .net import open_url

log = logging.getLogger("mcpguard.forward")

BATCH = 200
MAX_BACKOFF = 300.0


class Forwarder:
    def __init__(self, url: str, audit_path: str | Path, interval: float = 5.0, timeout: float = 10.0,
                 batch: int = BATCH, key: bytes | None = None):
        self.url = url
        self.audit_path = Path(audit_path)
        self.cursor_path = self.audit_path.with_name(self.audit_path.name + ".forward")
        self.interval = interval
        self.timeout = timeout
        self.batch = batch
        self.sent = 0
        self.failed = 0
        self.key = key
        cur = load_json(self.cursor_path, {})
        if self.key and isinstance(cur, dict) and not self._cursor_valid(cur):
            # Edited, or not written by this gateway: it could be hiding records from the copy. Start again.
            log.warning("the forwarding cursor %s does not carry a valid signature; sending the log from the start",
                        self.cursor_path.name)
            cur = {}
        self._cursor_hash: str = cur.get("hash", "") if isinstance(cur, dict) else ""
        self._cursor_seq: int = cur.get("seq", -1) if isinstance(cur, dict) else -1
        self._buffer: deque[dict] = deque(maxlen=20000)
        self._backoff = 0.0
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._catch_up = True  # first batch comes from the log, so nothing written before start is missed
        self._thread = threading.Thread(target=self._run, name="mcpguard-forward", daemon=True)
        self._thread.start()

    def _cursor_sig(self, seq: int, h: str) -> str:
        import hashlib
        import hmac
        return hmac.new(self.key or b"", f"cursor:{seq}:{h}".encode(), hashlib.sha256).hexdigest()

    def _cursor_valid(self, cur: dict) -> bool:
        import hmac
        if not cur:
            return True  # no cursor yet
        want = self._cursor_sig(int(cur.get("seq", -1)), str(cur.get("hash", "")))
        return hmac.compare_digest(str(cur.get("sig", "")), want)

    # called by the audit log for every record
    def __call__(self, rec: dict) -> None:
        self._buffer.append(rec)
        self._wake.set()

    def _next_batch(self) -> list[dict]:
        buf = self._buffer
        if not self._catch_up and buf and buf[0].get("prev") == (self._cursor_hash or buf[0].get("prev")):
            return [buf[i] for i in range(min(self.batch, len(buf)))]
        # Start, restart, an outage that overflowed the buffer, or a new log after `audit-new`:
        # find where we were in the log itself and send what follows.
        records = read_log(self.audit_path)
        at = next((i for i, r in enumerate(records) if r.get("hash") == self._cursor_hash), -1)
        todo = records[at + 1:] if at >= 0 else records  # cursor not in this log: it is a new log
        self._catch_up = False
        self._buffer.clear()
        self._buffer.extend(todo)
        return todo[: self.batch]

    def _post(self, batch: list[dict]) -> None:
        body = "\n".join(json.dumps(r, sort_keys=True) for r in batch).encode()
        req = urllib.request.Request(self.url, data=body, method="POST",  # noqa: S310 - open_url checks the scheme
                                     headers={"Content-Type": "application/x-ndjson", "User-Agent": "mcpguard",
                                              "X-Mcpguard-Log": self.audit_path.name,
                                              "X-Mcpguard-First-Seq": str(batch[0].get("seq")),
                                              "X-Mcpguard-Last-Seq": str(batch[-1].get("seq"))})
        open_url(req, timeout=self.timeout).close()

    def flush_once(self) -> bool:
        """Send one batch. True if something was sent. Used by the thread and by tests."""
        try:
            batch = self._next_batch()
        except (OSError, ValueError) as e:
            log.warning("forwarder could not read the audit log: %s", e)
            return False
        if not batch:
            return False
        try:
            self._post(batch)
        except Exception as e:  # noqa: BLE001 - delivery problems are logged and retried, never raised
            self.failed += 1
            self._backoff = min(MAX_BACKOFF, max(self.interval, self._backoff * 2 or self.interval))
            log.warning("audit forwarding to %s failed (will retry in %.0fs): %s", self.url, self._backoff, e)
            return False
        self._backoff = 0.0
        self.sent += len(batch)
        last = batch[-1]
        self._cursor_hash, self._cursor_seq = last.get("hash", ""), last.get("seq", -1)
        for _ in batch:
            if self._buffer:
                self._buffer.popleft()
        try:
            cursor = {"hash": self._cursor_hash, "seq": self._cursor_seq}
            if self.key:
                cursor["sig"] = self._cursor_sig(self._cursor_seq, self._cursor_hash)
            write_atomic(self.cursor_path, json.dumps(cursor))
        except OSError as e:
            log.warning("could not save the forwarding cursor: %s", e)
        return True

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(self._backoff or self.interval)
            self._wake.clear()
            if self._stop.is_set():
                break
            while self.flush_once():  # drain everything waiting, a batch at a time
                if self._stop.is_set():
                    break

    def close(self, flush: bool = True) -> None:
        self._stop.set()
        self._wake.set()
        self._thread.join(timeout=2)
        if flush:
            for _ in range(5):  # a last try at shutdown, so the final records are not left behind
                if not self.flush_once():
                    break
