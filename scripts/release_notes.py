"""Print the CHANGELOG section for the current version (used by the release workflow)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcpguard import __version__  # noqa: E402


def notes(changelog: str, version: str) -> str:
    m = re.search(rf"^## {re.escape(version)}\s*\n(.*?)(?=^## |\Z)", changelog, re.S | re.M)
    return m.group(1).strip() if m else ""


if __name__ == "__main__":
    text = notes((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), __version__)
    if not text:
        sys.exit(f"CHANGELOG.md has no section for {__version__}")
    print(text)
