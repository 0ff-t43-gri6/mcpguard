"""Live behaviour: config reload, server supervision, client notifications."""

import asyncio

from conftest import bump, call, is_err, run, server_block, text

from mcpguard.state import read_merged
from mcpguard.audit import read_log
from mcpguard.config import load_config
from mcpguard.gateway import Gateway


def _events(tmp_path):
    return [r["event"] for r in read_log(tmp_path / "mcpguard-audit.jsonl")]


def test_policy_reload_applies_without_restart(make_config, tmp_path):
    p = make_config()
    sent = []

    async def notify(m):
        sent.append(m)

    async def go():
        gw = Gateway(load_config(p), notify_client=notify)
        await gw.start()
        try:
            assert text(await call(gw, "srv__echo", {"text": "a"})) == "a"
            bump(p, '[[policy.rules]]\nmatch = "srv/echo"\naction = "deny"\n' + server_block())
            assert is_err(await call(gw, "srv__echo", {"text": "b"}))
            assert "srv__echo" not in {t["name"] for t in gw._visible_tools()}
        finally:
            await gw.stop()
    run(go())
    assert {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"} in sent
    assert "config.reloaded" in _events(tmp_path)


def test_servers_can_be_added_removed_and_disabled(make_config):
    p = make_config()

    async def go():
        gw = Gateway(load_config(p))
        await gw.start()
        try:
            bump(p, server_block("srv") + server_block("extra"))
            await gw.tick()
            assert "extra__echo" in gw.tools
            bump(p, server_block("srv", extra="enabled = false\n") + server_block("extra"))
            await gw.tick()
            assert gw.servers["srv"].status == "disabled"
            assert "srv__echo" not in gw.tools
            bump(p, server_block("extra"))
            await gw.tick()
            assert "srv" not in gw.servers
            assert "extra__echo" in gw.tools
        finally:
            await gw.stop()
    run(go())


def test_invalid_reload_keeps_the_running_config(make_config, tmp_path):
    p = make_config()

    async def go():
        gw = Gateway(load_config(p))
        await gw.start()
        try:
            bump(p, "this is = = not toml")
            assert text(await call(gw, "srv__echo", {"text": "still"})) == "still"
        finally:
            await gw.stop()
    run(go())
    assert "config.reload_failed" in _events(tmp_path)


def test_reload_with_broken_plugin_does_not_break_requests(make_config, tmp_path):
    """Previously the gateway half-applied the new config and every request then failed."""
    p = make_config()

    async def go():
        gw = Gateway(load_config(p))
        await gw.start()
        try:
            bump(p, '[detectors]\nplugins = ["no.such.module:x"]\n' + server_block())
            r1 = await call(gw, "srv__echo", {"text": "a"})
            r2 = await call(gw, "srv__echo", {"text": "b"})
            assert text(r1) == "a"
            assert text(r2) == "b"
        finally:
            await gw.stop()
    run(go())
    assert "config.reload_failed" in _events(tmp_path)


def test_rate_limit_counters_survive_reload(make_config):
    p = make_config("[policy]\nrate_limit_per_minute = 2\n")

    async def go():
        gw = Gateway(load_config(p))
        await gw.start()
        try:
            await call(gw, "srv__echo", {"text": "1"})
            await call(gw, "srv__echo", {"text": "2"})
            bump(p, "[policy]\nrate_limit_per_minute = 2\nredact_secrets = false\n" + server_block())
            assert is_err(await call(gw, "srv__echo", {"text": "3"}))
        finally:
            await gw.stop()
    run(go())


def test_crashed_server_is_restarted(make_config, tmp_path):
    p = make_config()

    async def go():
        gw = Gateway(load_config(p))
        await gw.start()
        try:
            gw.upstreams["srv"].proc.kill()
            await asyncio.sleep(0.2)
            down = await call(gw, "srv__echo", {"text": "a"})
            assert is_err(down)
            assert "unavailable" in text(down)
            for _ in range(30):
                await asyncio.sleep(0.1)
                await gw.tick()
                if gw.servers["srv"].status == "up":
                    break
            assert gw.servers["srv"].restarts == 1
            assert text(await call(gw, "srv__echo", {"text": "b"})) == "b"
        finally:
            await gw.stop()
    run(go())
    assert {"server.exited", "server.start"} <= set(_events(tmp_path))


def test_server_that_fails_to_start_is_retried_with_backoff(make_config, tmp_path):
    p = make_config(servers='[servers.broken]\ncommand = "definitely-not-a-real-command"\n' + server_block())

    async def go():
        gw = Gateway(load_config(p))
        await gw.start()
        try:
            state = gw.servers["broken"]
            assert state.status == "down"
            assert "not found" in state.last_error
            assert "srv__echo" in gw.tools  # the healthy server is unaffected
            first_retry = state.next_retry
            state.next_retry = 0
            await gw.tick()
            assert state.failures == 2
            assert state.next_retry > first_retry
        finally:
            await gw.stop()
    run(go())
    assert _events(tmp_path).count("server.failed") == 1  # repeated failures are not re-logged


def test_state_snapshot_is_written(make_config, tmp_path):
    p = make_config()

    async def go():
        gw = Gateway(load_config(p))
        await gw.start()
        await gw.stop()
    run(go())
    snap = read_merged(tmp_path / "mcpguard-state.json")
    assert snap["servers"][0]["name"] == "srv"
    assert snap["running"] is False
    assert any(r["qualified"] == "srv__echo" for r in snap["inventory"])
