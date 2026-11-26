"""mcpguard: governance, behavioral detection and audit for MCP."""

__version__ = "1.0.0rc1"

import logging as _logging

_logging.getLogger("mcpguard").addHandler(_logging.NullHandler())
