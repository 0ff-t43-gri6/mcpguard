"""Ask the operating system to make the audit log append-only.

An append-only file can have records added to it but cannot be edited, truncated, renamed or
deleted, so a program running as you (a compromised tool server, a confused agent) cannot
rewrite history by touching the file.

* Linux: ``chattr +a`` (needs administrator rights, and a file system that supports it).
* macOS: ``chflags uappnd`` (you can set it yourself; the same user can clear it again, so it stops
  accidents and careless attacks, not a determined one running as you).
* Windows: not done here. Run mcpguard as a separate, restricted account and give the project's
  account only append rights to the log folder (see docs/deployment.md).

Rotation and ``audit-new`` need to move the file, so run ``mcpguard audit-unprotect`` first.
Nothing here is required: mcpguard works the same without it.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


class ProtectError(Exception):
    pass


def _command(enable: bool, flavour: str | None = None) -> list[str]:
    flavour = flavour or ("linux" if sys.platform.startswith("linux") else "mac" if sys.platform == "darwin" else "")
    if flavour == "linux":
        tool = shutil.which("chattr")
        if not tool:
            raise ProtectError("chattr is not installed (it is part of e2fsprogs)")
        return [tool, "+a" if enable else "-a"]
    if flavour == "mac":
        tool = shutil.which("chflags")
        if not tool:
            raise ProtectError("chflags was not found")
        return [tool, "uappnd" if enable else "nouappnd"]
    raise ProtectError("this operating system has no append-only flag mcpguard can set; "
                       "see docs/deployment.md for running the gateway as a separate account instead")


def set_append_only(paths: list[Path], enable: bool = True, flavour: str | None = None) -> list[str]:
    """Apply (or remove) the flag on each existing file. Returns one line per file."""
    base = _command(enable, flavour)
    out: list[str] = []
    for p in paths:
        if not p.exists():
            out.append(f"skipped {p} (does not exist yet)")
            continue
        # '--': a file called -R is a file, not an option
        r = subprocess.run([*base, "--", str(p)], capture_output=True, encoding="utf-8", errors="replace", check=False)
        if r.returncode != 0:
            why = (r.stderr or r.stdout).strip() or f"exit code {r.returncode}"
            hint = " Run it as administrator (sudo)." if sys.platform.startswith("linux") else ""
            raise ProtectError(f"could not change {p}: {why}.{hint}")
        out.append(f"{'protected' if enable else 'unprotected'} {p}")
    return out
