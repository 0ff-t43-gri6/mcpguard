"""Small state files shared by every gateway process (pins, baselines).

Saves are atomic: the new content goes to a temporary file that then replaces the old
one, so a reader never sees half a file even when several processes save at once.
A file that is unreadable anyway (for example after a disk error) is moved aside to
``<name>.corrupt`` and the gateway starts with empty state instead of refusing to run.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

log = logging.getLogger("mcpguard")


def replace(src: Path, dst: Path, attempts: int = 50, delay: float = 0.02) -> None:
    """os.replace that waits out the short PermissionError Windows raises while another
    process has either file open."""
    for attempt in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay)


def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    try:
        replace(tmp, path)
    except PermissionError:
        tmp.unlink(missing_ok=True)
        raise


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):  # not JSON, or nested too deeply to parse
        aside = path.with_name(path.name + ".corrupt")
        os.replace(path, aside)
        log.warning("%s was unreadable; moved it to %s and started fresh", path, aside.name)
        return default
    if not isinstance(data, type(default)):
        log.warning("%s has unexpected content; ignoring it", path)
        return default
    return data


def _try_lock(f) -> bool:
    if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI
        import msvcrt
        f.seek(0)
        try:
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True
    else:  # an explicit branch, so mypy on Windows does not call this unreachable
        import fcntl
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True


def _unlock(f) -> None:
    if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI
        import msvcrt
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)


@contextlib.contextmanager
def locked(path: Path, timeout: float = 30.0) -> Iterator[None]:
    """Exclusive lock on ``path`` shared by every process (Windows and POSIX)."""
    with path.open("a+b") as f:
        deadline = time.monotonic() + timeout
        while not _try_lock(f):
            if time.monotonic() > deadline:
                raise TimeoutError(f"could not lock {path}")
            time.sleep(0.01)
        try:
            yield
        finally:
            _unlock(f)


def create_once(path: Path, make_text, timeout: float = 5.0) -> str:
    """Return the file's content, creating it with ``make_text()`` if it does not exist.

    Safe when several processes start at once (Claude Desktop can start the gateway twice):
    the content is written to a private temporary file and hard-linked into place, which
    fails if another process got there first; the loser then reads the winner's complete
    file instead of crashing or reading it half-written. The file is owner-only from the start.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)  # a folder made for a key is private too
    if not path.exists():
        tmp = path.with_name(f".{path.name}.{os.getpid()}.new")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(make_text())
        try:
            os.link(tmp, path)
        except FileExistsError:
            pass  # another process won; use its file
        except OSError:  # no hard links on this file system: exclusive create instead
            with contextlib.suppress(FileExistsError):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(tmp.read_text(encoding="utf-8"))
        finally:
            with contextlib.suppress(OSError):
                tmp.unlink()
    deadline = time.monotonic() + timeout
    while True:  # only the no-hard-link fallback can leave a moment where the file is empty
        text = path.read_text(encoding="utf-8").strip()
        if text or time.monotonic() > deadline:
            return text
        time.sleep(0.01)
