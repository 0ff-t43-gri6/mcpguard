"""Lets `python -m mcpguard ...` work the same as the `mcpguard` command."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
