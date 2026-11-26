"""Outbound HTTP for upstream servers and webhooks.

A dedicated opener rather than ``urllib.request.urlopen``:
- only http and https (no file://, ftp:// or data: handlers), checked again here
  even though the config already validates URLs
- redirects are not followed, so a server cannot bounce a request (with its bearer
  token) to another host or an internal address
- proxies from the environment are still honoured
"""

from __future__ import annotations

import re
import urllib.request
from urllib.parse import urlsplit

LOOPBACK_NAMES = ("127.0.0.1", "localhost", "::1")


def local_or_https(url: str) -> bool:
    """https anywhere; plain http only when the host (not just the start of the text) is this machine."""
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        parts.port  # noqa: B018 - raises ValueError for a bad port
    except ValueError:
        return False
    # Older Python 3.11 releases accept "http://[::1].evil.com/" and report the host as "::1". Brackets are
    # only valid around the whole host, so refuse any other placement here instead of relying on the parser.
    netloc = parts.netloc
    if ("[" in netloc or "]" in netloc) and not re.fullmatch(r"\[[0-9A-Fa-f:.%\w]+\](:\d*)?", netloc):
        return False
    if not host or parts.username is not None:
        return False
    return parts.scheme == "https" or (parts.scheme == "http" and host in LOOPBACK_NAMES)

_HANDLERS = (urllib.request.ProxyHandler, urllib.request.HTTPHandler, urllib.request.HTTPSHandler,
             urllib.request.HTTPDefaultErrorHandler, urllib.request.HTTPErrorProcessor)


def _build_opener() -> urllib.request.OpenerDirector:
    opener = urllib.request.OpenerDirector()
    for handler in _HANDLERS:
        opener.add_handler(handler())
    return opener


_OPENER = _build_opener()


class UnsafeURL(ValueError):
    """The URL does not use http or https."""


def open_url(req: urllib.request.Request | str, timeout: float):
    url = req.full_url if isinstance(req, urllib.request.Request) else req
    if urlsplit(url).scheme not in ("http", "https"):
        raise UnsafeURL(f"refusing to open non-HTTP URL: {url[:60]}")
    return _OPENER.open(req, timeout=timeout)
