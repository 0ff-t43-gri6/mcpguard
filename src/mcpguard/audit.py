"""Tamper-evident audit log.

Each record is one JSON line carrying the SHA-256 of the previous record, so the
records form a hash chain. Editing, deleting or reordering a record breaks
verification from that point on.

The active file rotates once it exceeds ``max_bytes``. Rotated segments are
renamed ``<stem>.<UTC timestamp><suffix>`` and the chain continues across them,
so ``verify`` checks the whole history.

Several gateway processes may share one log (Claude Desktop, for example, can start
the gateway more than once). Every write holds an exclusive lock on ``<name>.lock``
and re-reads the end of the log first, so the processes extend one chain in turn
instead of forking it.

If the process dies mid-write, the next start moves the partial final line into
``<name>.partial`` and records an ``audit.recovered`` event. The chain stays
valid and the incident is visible.

Signing: a plain hash chain only shows accidental or naive edits, because anyone
who can edit the file can recompute every hash. With a key, each link is an
HMAC-SHA256 instead (``"alg": "hmac-sha256"`` in the record), so records cannot be
forged or re-chained without the key. Once a log is signed, every later record
must be signed too; a verifier holding the key rejects unsigned records after
that point and an unsigned final record, which blocks a downgrade rewrite.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from collections.abc import Iterator
from pathlib import Path

from . import fileio

log = logging.getLogger("mcpguard")
GENESIS = "0" * 64
HMAC_ALG = "hmac-sha256"
KEY_ENV = "MCPGUARD_AUDIT_KEY"


def _digest(prev: str, body: dict, key: bytes | None = None) -> str:
    payload = (prev + json.dumps(body, sort_keys=True, separators=(",", ":"))).encode()
    if body.get("alg") == HMAC_ALG:
        if key is None:
            raise ValueError("signed record needs a key")
        return hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hashlib.sha256(payload).hexdigest()


def _same(expected: str, given: object) -> bool:
    """Constant-time comparison that tolerates any value (tampered records may hold anything)."""
    return hmac.compare_digest(expected.encode(), str(given).encode("utf-8", "surrogatepass"))


def load_key(path: str | Path | None, create: bool = False) -> bytes | None:
    """Audit signing key from MCPGUARD_AUDIT_KEY or the key file (hex).

    With create=True a missing key file is generated with owner-only permissions.
    """
    env = os.environ.get(KEY_ENV)
    if env:
        return _parse_key(env, KEY_ENV)
    if not path:
        return None
    p = Path(path)
    if not p.exists() and not create:
        return None
    # Two gateways starting at once on a fresh install both create the key; one used to crash.
    return _parse_key(fileio.create_once(p, lambda: secrets.token_hex(32)), str(p))


def has_signed_records(path: str | Path) -> bool:
    """True if the log (or its oldest segment) holds records signed with a key."""
    segs = segments(path)
    if not segs:
        return False
    try:
        with segs[0].open("rb") as f:
            first = json.loads(f.readline().decode("utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(first, dict) and first.get("alg") == HMAC_ALG


def _parse_key(text: str, source: str) -> bytes:
    try:
        key = bytes.fromhex(text.strip())
    except ValueError:
        raise ValueError(f"audit key in {source} is not valid hex") from None
    if len(key) < 16:
        raise ValueError(f"audit key in {source} is too short (need at least 16 bytes)")
    return key


_ROTATED = re.compile(r"\d{8}T\d{12}Z")


def _is_rotated_name(candidate: Path, active: Path) -> bool:
    """Only names mcpguard itself gives a rotated segment (<stem>.<UTC stamp><suffix>) count as part of the
    log. A file somebody drops beside it, such as <stem>.backup<suffix>, is not a segment."""
    middle = candidate.name[len(active.stem) + 1: len(candidate.name) - len(active.suffix)]
    return candidate.suffix == active.suffix and bool(_ROTATED.fullmatch(middle))


def segments(path: str | Path) -> list[Path]:
    """All files of a log in chain order: rotated segments, then the active file."""
    p = Path(path)
    rotated = sorted(p.parent.glob(f"{p.stem}.*{p.suffix}"))
    rotated = [r for r in rotated if r != p and _is_rotated_name(r, p)]
    return [*rotated, p] if p.exists() else rotated


class LogDamaged(ValueError):
    """A line of the audit log is not a record (not JSON, not UTF-8, or not an object)."""


def _iter_file(path: Path, strict: bool = False) -> Iterator[dict]:
    with path.open("rb") as f:
        for n, raw in enumerate(f, 1):
            if not raw.endswith(b"\n"):
                return  # incomplete final line from an interrupted write
            line = raw.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if not isinstance(rec, dict):
                    raise ValueError("not an object")
            except (ValueError, RecursionError):  # JSON errors, bad UTF-8 and over-deep nesting
                if strict:
                    raise LogDamaged(f"{path.name} line {n} is not a valid record") from None
                continue
            yield rec


def read_log(path: str | Path, include_rotated: bool = True, strict: bool = False) -> list[dict]:
    """Return records in order. A trailing partial line is ignored. A damaged line is skipped,
    or with strict=True raises LogDamaged (verify uses that: damage is something to report)."""
    files = segments(path) if include_rotated else [Path(path)]
    out: list[dict] = []
    for f in files:
        if f.exists():
            out.extend(_iter_file(f, strict))
    return out


_file_lock = fileio.locked  # kept for readability below


class AuditLog:
    def __init__(self, path: str | Path, max_bytes: int = 0, key: bytes | None = None):
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.max_bytes = max_bytes
        self.key = key
        self.listeners: list = []  # callables receiving each written record
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seen: tuple | None = None  # (identity, size) of the file after our last read or write
        # What this process last wrote, and where it ended: (seq, hash, end offset, identity, line bytes).
        # If those bytes are not there later, someone changed the file behind our back.
        self._anchor: tuple[int, str, int, tuple, bytes] | None = None
        self._rotate_warned = False
        with self._lock, _file_lock(self.lock_path):
            try:
                recovered = self._recover_partial_line()
            except PermissionError:
                # An append-only file (audit-protect) cannot be truncated. Close the broken line
                # instead, so the next record starts cleanly; `verify` will report the broken one.
                with self.path.open("ab") as f:
                    f.write(b"\n")
                recovered = 0
            self._sync()
        if recovered:
            self.write("audit.recovered", partial_bytes=recovered,
                       note="incomplete record from an interrupted write moved to .partial")

    def _stamp(self) -> tuple | None:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return None
        return st.st_dev, st.st_ino, st.st_size

    def _sync(self) -> None:
        """Take the chain head from disk unless the file is exactly as we left it."""
        stamp = self._stamp()
        if stamp is not None and stamp == self._seen:
            return
        self._prev, self._seq = self._tail_state()
        self._seen = stamp

    def _recover_partial_line(self) -> int:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0
        with self.path.open("rb+") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 1))
            if f.read(1) == b"\n":
                return 0
            data = self._read_tail(f, size)
            cut = data.rfind(b"\n") + 1  # 0 when the whole file is one partial line
            keep = size - (len(data) - cut)
            f.seek(keep)
            partial = f.read()
            with open(str(self.path) + ".partial", "ab") as side:
                side.write(partial + b"\n")
            f.truncate(keep)
            return len(partial)

    @staticmethod
    def _read_tail(f, size: int, chunk: int = 1 << 16) -> bytes:
        start = max(0, size - chunk)
        while True:
            f.seek(start)
            data = f.read(size - start)
            if b"\n" in data or start == 0:
                return data
            start = max(0, start - chunk)

    def _tail_state(self) -> tuple[str, int]:
        """Hash and next sequence number, taken from the newest segment's last record."""
        for seg in reversed(segments(self.path)):
            try:
                rec = _last_record(seg)
            except LogDamaged:  # a broken line at the end (an interrupted write we could not move aside)
                rec = None
                for rec in _iter_file(seg):  # noqa: B007 - the loop keeps the last good record
                    pass
            if rec is not None:
                return rec["hash"], rec["seq"] + 1
        return GENESIS, 0

    def _rotate_if_needed(self) -> None:
        if not self.max_bytes or not self.path.exists() or self.path.stat().st_size < self.max_bytes:
            return
        stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S%fZ")
        try:
            fileio.replace(self.path, self.path.with_name(f"{self.path.stem}.{stamp}{self.path.suffix}"), attempts=10)
        except PermissionError:
            # Windows: something has the file open. Never lose the record over it; keep
            # writing to the current file and rotate on a later write.
            if not self._rotate_warned:
                self._rotate_warned = True
                log.warning("could not rotate %s (in use or append-only); will retry", self.path.name)

    def write(self, event: str, **fields) -> dict:
        with self._lock, _file_lock(self.lock_path):
            self._rotate_if_needed()
            self._sync()  # another process may have appended since our last write
            body = {"seq": self._seq, "ts": round(time.time(), 3), "event": event, **fields}
            if self.key:
                body["alg"] = HMAC_ALG
            h = _digest(self._prev, body, self.key)
            record = {**body, "prev": self._prev, "hash": h}
            line = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
            fresh = not self.path.exists()
            with self.path.open("ab") as f:
                f.write(line)
                end = f.tell()
            if fresh and os.name == "posix":
                with contextlib.suppress(OSError):
                    os.chmod(self.path, 0o600)  # the log can hold tool names and masked arguments
            self._prev = h
            self._seq += 1
            self._seen = self._stamp()
            self._anchor = (record["seq"], h, end, self._seen[:2] if self._seen else (), line)
        for listener in list(self.listeners):
            with contextlib.suppress(Exception):  # a broken listener must never stop auditing
                listener(record)
        return record

    def check_intact(self) -> str | None:
        """None if everything this process wrote is still in the log exactly as written; otherwise
        what is wrong. Cheap enough to run before every tool call. It catches deleting the file,
        cutting it short, replacing it, and editing records already written, which a hash chain
        alone cannot show to the process that keeps appending to it."""
        with self._lock:
            anchor = self._anchor
            if anchor is None:
                return None
            seq, h, end, ident, line = anchor
            try:
                st = self.path.stat()
            except FileNotFoundError:
                return None if self._still_exists_elsewhere(seq, h, line) else "the audit log file was deleted"
            if (st.st_dev, st.st_ino) == ident and st.st_size >= end:
                try:
                    with self.path.open("rb") as f:
                        f.seek(end - len(line))
                        if f.read(len(line)) == line:
                            return None
                except OSError:
                    pass
            if self._still_exists_elsewhere(seq, h, line):
                return None
            return (f"record {seq}, written by this gateway, is missing or was changed: the audit log was "
                    "edited, cut short or replaced outside mcpguard")

    def _still_exists_elsewhere(self, seq: int, h: str, line: bytes) -> bool:
        """The file is not as we left it. That is fine if the log was rotated or archived on purpose
        (our record is still in an older segment or the archive); otherwise it is tampering."""
        candidates = [seg for seg in segments(self.path) if seg != self.path]  # real rotated segments
        if candidates and self._still_holds_record(seq):
            candidates = []  # rotation moves our record out of this file; it is still here, so nothing rotated
        if self._starts_with_archive_record():
            candidates += [f for folder in sorted((self.path.parent / "audit-archive").glob("*"))
                           for f in [folder / self.path.name] if f.is_file()]
        for seg in candidates:
            try:
                for rec in _iter_file(seg):
                    if (rec.get("seq") == seq and rec.get("hash") == h
                            and (json.dumps(rec, sort_keys=True) + "\n").encode("utf-8") == line):
                        self._anchor = None  # re-anchor at the next write
                        return True
            except OSError:
                continue
        return False

    def _still_holds_record(self, seq: int) -> bool:
        """True if the active file begins at or before our record: a real rotation would have moved
        everything up to it into a segment, so a copy planted under a segment's name is no excuse."""
        try:
            with self.path.open("rb") as f:
                first = json.loads(f.readline().decode("utf-8"))
        except (OSError, ValueError):
            return False
        return (isinstance(first, dict) and isinstance(first.get("seq"), int) and first["seq"] <= seq
                and first.get("event") != "audit.new")

    def _starts_with_archive_record(self) -> bool:
        """`audit-new` archives the log and begins a new one whose first record says so. Without that
        record, a file in audit-archive/ is not evidence of a legitimate archive."""
        try:
            with self.path.open("rb") as f:
                first = json.loads(f.readline().decode("utf-8"))
        except (OSError, ValueError):
            return False
        return isinstance(first, dict) and first.get("event") == "audit.new" and bool(first.get("archived"))

    def _current(self) -> tuple[str, int]:
        with self._lock, _file_lock(self.lock_path):
            self._sync()
            return self._prev, self._seq

    @property
    def count(self) -> int:
        """Number of records in the log so far, across all segments and all writers."""
        return self._current()[1]

    @property
    def head(self) -> str:
        """Hash of the latest record. Copy it somewhere external to anchor the log."""
        return self._current()[0]


def _last_record(path: Path, chunk: int = 1 << 16) -> dict | None:
    with path.open("rb") as f:
        size = f.seek(0, os.SEEK_END)
        if size == 0:
            return None
        start = max(0, size - chunk)
        while True:
            f.seek(start)
            body = f.read(size - start).rstrip(b"\n")
            if b"\n" in body or start == 0:
                last = body.rsplit(b"\n", 1)[-1]
                if not last.strip():
                    return None
                try:
                    rec = json.loads(last)
                except (ValueError, RecursionError):
                    raise LogDamaged(f"the last line of {path.name} is not a valid record") from None
                return rec if isinstance(rec, dict) else _bad_last(path)
            start = max(0, start - chunk)


def _bad_last(path: Path):
    raise LogDamaged(f"the last line of {path.name} is not a valid record")


def _identity(path: Path) -> tuple[int, int]:
    st = path.stat()
    return st.st_dev, st.st_ino


class ChainVerifier:
    """Incremental verification for long-running readers such as the dashboard.

    Between full passes only appended bytes are read. Truncation, rotation or a
    replaced file triggers a full pass at once; an in-place edit of older bytes is
    caught by the periodic full pass every ``full_interval`` seconds.
    """

    def __init__(self, path: str | Path, full_interval: float = 30.0, key: bytes | None = None):
        self.path = Path(path)
        self.full_interval = full_interval
        self.key = key
        self._last_full = 0.0
        self._reset()

    def _reset(self) -> None:
        self._last_full = time.monotonic()
        self._seen: list[tuple[tuple[int, int], int]] = []  # (file identity, bytes verified)
        self._state = _ChainState(self.key)
        self._failure: str | None = None

    def check(self) -> tuple[bool, str]:
        segs = [s for s in segments(self.path) if s.exists()]
        ids = [_identity(s) for s in segs]
        sizes = [s.stat().st_size for s in segs]
        unchanged_prefix = all(
            i < len(ids) and ids[i] == ident and sizes[i] >= done
            for i, (ident, done) in enumerate(self._seen))
        if not unchanged_prefix or self._failure or time.monotonic() - self._last_full >= self.full_interval:
            self._reset()
        for i, seg in enumerate(segs):
            done = self._seen[i][1] if i < len(self._seen) else 0
            if i >= len(self._seen):
                self._seen.append((ids[i], 0))
            if sizes[i] == done:
                continue
            with seg.open("rb") as f:
                f.seek(done)
                for raw in f:
                    if not raw.endswith(b"\n"):
                        break
                    done += len(raw)
                    if not raw.strip():
                        continue
                    try:
                        rec = json.loads(raw)
                        if not isinstance(rec, dict):
                            raise ValueError("not an object")
                    except (ValueError, RecursionError):
                        self._failure = f"{seg.name} contains a line that is not a valid record"
                        return False, self._failure
                    ok, msg = self._state.feed(rec)
                    if not ok:
                        self._failure = msg
                        return False, msg
            self._seen[i] = (ids[i], done)
        return self._state.result()

    @property
    def records(self) -> int:
        return self._state.seq


class _ChainState:
    """Walks records in order and applies every link and signature rule."""

    def __init__(self, key: bytes | None):
        self.key = key
        self.prev, self.seq = GENESIS, 0
        self.signed_seen = False
        self.last_signed = True
        self.unchecked_signatures = 0
        self.seen: dict[str, int] = {GENESIS: -1}  # hash -> seq, to recognise a fork

    def _fork_of(self, rec: dict, body: dict) -> int | None:
        """The earlier record this one validly continues from, if any (two writers, not an edit)."""
        parent = self.seen.get(str(rec.get("prev")))
        if parent is None or rec.get("seq") != parent + 1:
            return None
        key = self.key if rec.get("alg") == HMAC_ALG else None
        if rec.get("alg") == HMAC_ALG and key is None:
            return None
        return parent if _same(_digest(str(rec.get("prev")), body, key), rec.get("hash")) else None

    def feed(self, rec: dict) -> tuple[bool, str]:
        seq = self.seq
        claimed = rec.get("hash")
        body = {k: v for k, v in rec.items() if k not in ("prev", "hash")}
        if rec.get("prev") != self.prev:
            parent = self._fork_of(rec, body)
            if parent is not None:
                start = "the start of the log" if parent < 0 else f"record {parent}"
                return False, (f"record {seq}: chain forked - this record validly continues from {start}, not "
                               f"record {seq - 1}. Two gateway processes wrote at once (mcpguard before 0.8.0) "
                               "or records were removed; records after this point cannot be trusted. "
                               "Start a new log with `mcpguard audit-new`")
            return False, f"record {seq}: chain broken (previous-hash mismatch)"
        if rec.get("seq") != seq:
            return False, f"record {seq}: sequence gap or reordering"
        signed = rec.get("alg") == HMAC_ALG
        if signed:
            self.signed_seen = True
            if self.key is None:
                self.unchecked_signatures += 1
            elif not _same(_digest(self.prev, body, self.key), claimed):
                return False, f"record {seq}: signature invalid (forged, edited, or a different key)"
        else:
            if self.key is not None and self.signed_seen:
                return False, f"record {seq}: unsigned record in a signed log"
            if _digest(self.prev, body) != claimed:
                return False, f"record {seq}: contents modified (hash mismatch)"
        self.last_signed = signed
        self.prev, self.seq = str(claimed), seq + 1
        self.seen[self.prev] = seq
        return True, ""

    def result(self) -> tuple[bool, str]:
        if self.key is not None and self.seq and not self.last_signed:
            return False, "log ends with an unsigned record although a signing key is configured"
        note = ""
        if self.unchecked_signatures:
            note = f"; {self.unchecked_signatures} signatures not checked (no key available)"
        elif self.key is not None and self.signed_seen:
            note = ", signatures valid"
        return True, f"audit log intact ({self.seq} records{note})"


def archive(path: str | Path, key: bytes | None = None, reason: str = "") -> Path:
    """Move the log (every segment and any .partial) into audit-archive/<time>/ and start a
    new log whose first record names the archive and its verification result."""
    path = Path(path)
    ok, msg = verify(path, key) if path.exists() else (True, "no previous log")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = path.parent / "audit-archive" / stamp
    n = 1
    while dest.exists():  # two archives in the same second must not collide
        n += 1
        dest = path.parent / "audit-archive" / f"{stamp}-{n}"
    lock = path.with_name(path.name + ".lock")
    with _file_lock(lock):
        files = [*segments(path), *path.parent.glob(path.name + ".partial*")]
        if files:
            dest.mkdir(parents=True, exist_ok=False)
            for f in files:
                fileio.replace(f, dest / f.name)
    log = AuditLog(path, key=key)
    log.write("audit.new", reason=reason or "started a new log", archived=str(dest) if files else "",
              previous_verified=ok, previous_result=msg)
    return dest


def verify(path: str | Path, key: bytes | None = None) -> tuple[bool, str]:
    """Check every segment of the log. Returns (ok, message)."""
    state = _ChainState(key)
    try:
        records = read_log(path, strict=True)
    except LogDamaged as e:
        return False, f"{e}: the log was edited or damaged"
    except OSError as e:
        return False, f"cannot read the log: {e.strerror or e}"
    for rec in records:
        ok, msg = state.feed(rec)
        if not ok:
            return False, msg
    return state.result()


# ---------------------------------------------------------------- checkpoints
#
# A hash chain cannot show that its newest records were deleted: the shorter log is
# still a valid chain. A checkpoint records "record N had hash H" somewhere else
# (another disk, a ticket, a chat message). Verifying against checkpoints catches
# truncation and any rewrite of the covered history.


def _checkpoint_sig(key: bytes, cp: dict) -> str:
    msg = f"{cp['seq']}:{cp['hash']}:{cp['ts']}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def default_checkpoint_path(audit_path: str | Path) -> Path:
    """Where checkpoints go when the config names no place: the mcpguard home folder, away from
    the project folder, so wiping or rolling back the project does not also wipe the proof."""
    import hashlib
    home = Path(os.environ.get("MCPGUARD_HOME") or Path.home() / ".mcpguard")
    ap = Path(audit_path).resolve()
    tag = hashlib.sha256(str(ap).encode("utf-8", "replace")).hexdigest()[:10]
    return home / "checkpoints" / f"{ap.stem}-{tag}.jsonl"


def default_key_path(audit_path: str | Path) -> Path:
    """Where the signing key goes when the config names none: the mcpguard home folder, away from the
    project folder that a tool server's files tool or a copied project can reach."""
    import hashlib
    home = Path(os.environ.get("MCPGUARD_HOME") or Path.home() / ".mcpguard")
    ap = Path(audit_path).resolve()
    tag = hashlib.sha256(str(ap).encode("utf-8", "replace")).hexdigest()[:10]
    return home / "keys" / f"{ap.stem}-{tag}.key"


def make_checkpoint(path: str | Path, key: bytes | None = None) -> dict | None:
    """Describe the latest record; signed when a key is available. None for an empty log."""
    for seg in reversed(segments(path)):
        rec = _last_record(seg)
        if rec is not None:
            cp = {"seq": rec["seq"], "hash": rec["hash"], "ts": round(time.time(), 3), "log": Path(path).name}
            if key:
                cp["sig"] = _checkpoint_sig(key, cp)
            return cp
    return None


def append_checkpoint(path: str | Path, checkpoint: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(checkpoint, sort_keys=True) + "\n")


def read_checkpoints(path: str | Path) -> list[dict]:
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            cp = json.loads(line)
            if not isinstance(cp, dict) or not isinstance(cp.get("seq"), int) or not isinstance(cp.get("hash"), str):
                raise ValueError("checkpoint lines must be objects with integer 'seq' and string 'hash'")
            out.append(cp)
    return out


def check_checkpoints(path: str | Path, checkpoints: list[dict], key: bytes | None = None) -> tuple[bool, str]:
    """Confirm every checkpointed record is still present and unchanged."""
    wanted = {cp["seq"]: cp for cp in checkpoints}
    for cp in checkpoints:
        if key and "sig" in cp and not _same(_checkpoint_sig(key, cp), cp["sig"]):
            return False, f"checkpoint for record {cp['seq']} has an invalid signature"
    last = -1
    for rec in read_log(path):
        last = rec["seq"]
        expected = wanted.get(last)
        if expected and expected["hash"] != rec["hash"]:
            return False, (f"record {last} differs from the checkpoint taken at {expected.get('ts')} "
                           "(history rewritten)")
    beyond = [s for s in wanted if s > last]
    if beyond:
        return False, (f"log truncated: a checkpoint covers record {max(beyond)} but the log ends at record {last}")
    return True, f"{len(checkpoints)} checkpoint{'s' * (len(checkpoints) != 1)} confirmed"
