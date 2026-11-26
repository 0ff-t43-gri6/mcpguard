"""Shared helpers. Fake servers live in fake_server.py (stdio) and http_fake.py."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).parent
sys.path.insert(0, str(TESTS))  # for sample_plugin and http_fake

FAKE = str(TESTS / "fake_server.py").replace("\\", "/")
PY = sys.executable.replace("\\", "/")


def server_block(name: str = "srv", mode: str = "benign", extra: str = "") -> str:
    return (f'[servers.{name}]\ncommand = "{PY}"\nargs = ["{FAKE}"]\n'
            f'env = {{ FAKE_MODE = "{mode}" }}\n{extra}')


def bump(path: Path, text: str) -> None:
    """Rewrite a config and move its mtime forward so the change is always noticed."""
    path.write_text(text, encoding="utf-8")
    st = os.stat(path)
    os.utime(path, (st.st_atime, st.st_mtime + 5))


def run(coro):
    return asyncio.run(coro)


async def call(gw, name, args=None, rid=1):
    return await gw.handle({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                            "params": {"name": name, "arguments": args or {}}})


async def rpc(gw, method, params=None, rid=1):
    return await gw.handle({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})


def text(resp) -> str:
    r = resp["result"]
    if "content" in r:
        return r["content"][0]["text"]
    if "contents" in r:
        return r["contents"][0]["text"]
    return r["messages"][0]["content"]["text"]


def is_err(resp) -> bool:
    return bool(resp.get("result", {}).get("isError"))


@pytest.fixture
def make_config(tmp_path):
    """Write a config file; returns its path. Anomaly detection is off unless asked for."""
    def _make(body: str = "", servers: str | None = None, anomaly: bool = False) -> Path:
        p = tmp_path / "mcpguard.toml"
        # Top-level keys such as `mode` must come before any table, so the body goes first.
        tail = "" if anomaly or "[anomaly]" in body else "\n[anomaly]\nenabled = false\n"
        p.write_text(body + tail + "\n" + (server_block() if servers is None else servers), encoding="utf-8")
        return p
    return _make


@pytest.fixture
def gateway(make_config):
    """Async context helper: `async with gateway(body) as gw:` starts and stops a gateway."""
    from contextlib import asynccontextmanager

    from mcpguard.config import load_config
    from mcpguard.gateway import Gateway

    @asynccontextmanager
    async def _gw(body: str = "", servers: str | None = None, **kw):
        gw = Gateway(load_config(make_config(body, servers, kw.pop("anomaly", False))), **kw)
        await gw.start()
        try:
            yield gw
        finally:
            await gw.stop()
    return _gw


@pytest.fixture(autouse=True)
def _own_trust_store(tmp_path_factory, monkeypatch):
    """Keep `mcpguard trust` records out of the real home folder."""
    monkeypatch.setenv("MCPGUARD_HOME", str(tmp_path_factory.mktemp("mcpguard-home")))
    monkeypatch.delenv("MCPGUARD_CONFIG", raising=False)


@pytest.fixture(autouse=True)
def _empty_working_folder(tmp_path_factory, monkeypatch):
    """Run every test from an empty folder, so a mcpguard.toml in the repo (made by `mcpguard init`) is never found."""
    monkeypatch.chdir(tmp_path_factory.mktemp("cwd"))



def pytest_report_header(config):
    from timing import SPEED
    return f"timing limits scaled x{SPEED:.1f} for this machine (1.0 = as fast as the reference machine)"
