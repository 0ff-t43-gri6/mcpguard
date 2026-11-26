from pathlib import Path

from conftest import call, is_err, rpc, run, server_block, text

from mcpguard.audit import read_log, verify
from mcpguard.report import build_report


def test_tools_are_namespaced_and_proxied(gateway):
    async def go():
        async with gateway() as gw:
            names = {t["name"] for t in (await rpc(gw, "tools/list"))["result"]["tools"]}
            assert {"srv__echo", "srv__read_notes"} <= names
            assert text(await call(gw, "srv__echo", {"text": "hello"})) == "hello"
    run(go())


def test_protocol_version_negotiation(gateway):
    async def go():
        async with gateway() as gw:
            ok = await rpc(gw, "initialize", {"protocolVersion": "2025-03-26"})
            assert ok["result"]["protocolVersion"] == "2025-03-26"
            other = await rpc(gw, "initialize", {"protocolVersion": "1999-01-01"})
            assert other["result"]["protocolVersion"] == "2025-06-18"
    run(go())


def test_malformed_requests_get_errors_not_crashes(gateway):
    async def go():
        async with gateway() as gw:
            assert (await gw.handle({"jsonrpc": "2.0", "id": 1, "method": 5}))["error"]["code"] == -32600
            assert (await gw.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": []}))["error"]
            bad_args = await call(gw, "srv__echo", args=None)
            assert not bad_args.get("error")
            r = await gw.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                 "params": {"name": "srv__echo", "arguments": "nope"}})
            assert r["error"]["code"] == -32602
            assert (await call(gw, "srv__missing"))["error"]["code"] == -32602
    run(go())


def test_poisoned_tool_is_quarantined(gateway):
    async def go():
        async with gateway(servers=server_block(mode="poisoned")) as gw:
            names = {t["name"] for t in gw._visible_tools()}
            assert "srv__add" not in names
            assert "srv__echo" in names
            r = await call(gw, "srv__add")
            assert is_err(r)
            assert "quarantined" in text(r)
            inv = {row["qualified"]: row["status"] for row in gw.inventory()}
            assert inv["srv__add"] == "quarantined"
            assert inv["srv__echo"] == "allowed"
    run(go())


def test_hidden_unicode_is_quarantined(gateway):
    async def go():
        async with gateway(servers=server_block(mode="hidden_unicode")) as gw:
            assert "srv__calc" in gw.quarantined
    run(go())


def test_rug_pull_is_caught_on_relisting(gateway):
    async def go():
        async with gateway(servers=server_block(mode="rugpull")) as gw:
            assert "srv__echo" in gw.tools
            await gw.refresh()
            assert "srv__echo" in gw.quarantined
    run(go())


def test_definition_findings_are_audited_once(gateway, tmp_path):
    async def go():
        async with gateway(servers=server_block(mode="poisoned")) as gw:
            for _ in range(3):
                await gw.refresh()
    run(go())
    events = [r["event"] for r in read_log(tmp_path / "mcpguard-audit.jsonl")]
    assert events.count("tool.quarantined") == 1


def test_secrets_are_redacted_from_results(gateway):
    async def go():
        async with gateway() as gw:
            r = await call(gw, "srv__read_notes")
            assert "AKIA" not in text(r)
            assert "REDACTED" in text(r)
    run(go())


def test_secret_in_arguments_is_blocked(gateway):
    async def go():
        async with gateway() as gw:
            assert is_err(await call(gw, "srv__echo", {"text": "AKIAABCDEFGHIJKLMNOP"}))
    run(go())


def test_data_read_by_one_tool_cannot_leave_through_another(gateway):
    async def go():
        async with gateway("[policy]\nredact_secrets = false\n") as gw:
            await call(gw, "srv__read_notes")
            r = await call(gw, "srv__send_email", {"body": "here: AKIAABCDEFGHIJKLMNOP"})
            assert is_err(r)
            assert "mcpguard blocked" in text(r)
    run(go())


def test_injected_result_is_withheld(gateway):
    async def go():
        async with gateway() as gw:
            r = await call(gw, "srv__web_page")
            assert is_err(r)
            assert "withheld" in text(r)
    run(go())


def test_deny_hides_and_blocks(gateway):
    async def go():
        async with gateway('[[policy.rules]]\nmatch = "*/delete_*"\naction = "deny"\n') as gw:
            assert "srv__delete_item" not in {t["name"] for t in gw._visible_tools()}
            assert is_err(await call(gw, "srv__delete_item"))
    run(go())


def test_argument_conditions(gateway):
    rule = '[[policy.rules]]\nmatch = "srv/write_file"\nargs = { path = "/etc/*" }\naction = "deny"\n'

    async def go():
        async with gateway(rule) as gw:
            assert "srv__write_file" in {t["name"] for t in gw._visible_tools()}
            assert is_err(await call(gw, "srv__write_file", {"path": "/etc/passwd"}))
            assert text(await call(gw, "srv__write_file", {"path": "/tmp/x"})) == "written /tmp/x"
    run(go())


def test_ask_rule_uses_the_approver(gateway):
    rule = '[[policy.rules]]\nmatch = "*/delete_*"\naction = "ask"\n'

    async def go(answer):
        async def approver(name, args, reason=""):
            return answer
        async with gateway(rule, approver=approver) as gw:
            return await call(gw, "srv__delete_item")
    assert is_err(run(go(False)))
    assert text(run(go(True))) == "deleted"


def test_session_budget(gateway):
    async def go():
        async with gateway("[policy]\nmax_calls_per_session = 2\n") as gw:
            assert not is_err(await call(gw, "srv__echo", {"text": "a"}))
            assert not is_err(await call(gw, "srv__echo", {"text": "b"}))
            assert is_err(await call(gw, "srv__echo", {"text": "c"}))
    run(go())


def test_multiple_servers(gateway):
    async def go():
        async with gateway(servers=server_block("a") + server_block("b")) as gw:
            assert {"a__echo", "b__echo"} <= {t["name"] for t in gw._visible_tools()}
            assert text(await call(gw, "b__echo", {"text": "hi"})) == "hi"
    run(go())


def test_prompts_and_resources(gateway):
    async def go():
        async with gateway() as gw:
            prompts = (await rpc(gw, "prompts/list"))["result"]["prompts"]
            assert [p["name"] for p in prompts] == ["srv__summarize"]
            r = await rpc(gw, "prompts/get", {"name": "srv__summarize", "arguments": {"text": "hi"}})
            assert text(r) == "Summarize: hi"
            uris = {x["uri"] for x in (await rpc(gw, "resources/list"))["result"]["resources"]}
            assert uris == {"notes://clean", "notes://evil"}
            assert text(await rpc(gw, "resources/read", {"uri": "notes://clean"})) == "meeting at 3pm"
            assert is_err(await rpc(gw, "resources/read", {"uri": "notes://evil"}))
            assert (await rpc(gw, "resources/read", {"uri": "notes://nope"}))["error"]["code"] == -32002
    run(go())


def test_policy_can_hide_resources(gateway):
    async def go():
        async with gateway('[[policy.rules]]\nmatch = "srv/resource:notes://evil"\naction = "deny"\n') as gw:
            uris = {x["uri"] for x in (await rpc(gw, "resources/list"))["result"]["resources"]}
            assert uris == {"notes://clean"}
    run(go())


def test_monitor_mode_records_but_never_blocks(gateway, tmp_path):
    body = 'mode = "monitor"\n[[policy.rules]]\nmatch = "*/delete_*"\naction = "deny"\n'

    async def go():
        async with gateway(body, servers=server_block(mode="poisoned")) as gw:
            assert "srv__add" in gw.tools
            assert text(await call(gw, "srv__delete_item")) == "deleted"
            assert not is_err(await call(gw, "srv__web_page"))
    run(go())
    events = [r["event"] for r in read_log(tmp_path / "mcpguard-audit.jsonl")]
    assert events.count("call.would_block") >= 2
    assert "call.blocked" not in events
    assert "Would have blocked" in build_report(str(tmp_path / "mcpguard-audit.jsonl"))


def test_anomalies_are_logged(gateway, tmp_path):
    async def go():
        async with gateway("[anomaly]\nmin_samples = 10\n[policy]\nmax_result_chars = 0\n") as gw:
            for _ in range(15):
                await call(gw, "srv__sized", {"n": 100})
            assert not is_err(await call(gw, "srv__sized", {"n": 200_000}))
    run(go())
    rules = [f["rule"] for r in read_log(tmp_path / "mcpguard-audit.jsonl") for f in r.get("findings", [])]
    assert "anomaly.result_chars" in rules


def test_secrets_in_upstream_errors_are_not_logged(gateway, tmp_path):
    async def go():
        async with gateway(servers=server_block(mode="leaky_errors")) as gw:
            await call(gw, "srv__echo", {"text": "x"})
    run(go())
    log_text = (tmp_path / "mcpguard-audit.jsonl").read_text(encoding="utf-8")
    assert "upstream_error" in log_text
    assert "AKIAABCDEFGHIJKLMNOP" not in log_text


def test_full_session_leaves_an_intact_log(gateway, tmp_path):
    body = '[[policy.rules]]\nmatch = "*/delete_*"\naction = "ask"\n[approvals]\nmode = "deny"\n'

    async def go():
        async with gateway(body) as gw:
            await call(gw, "srv__echo", {"text": "x"})
            assert is_err(await call(gw, "srv__delete_item"))
            await call(gw, "srv__read_notes")
    run(go())
    assert verify(tmp_path / "mcpguard-audit.jsonl")[0]


def test_pins_forget_while_the_gateway_runs_is_not_undone(gateway, tmp_path):
    """The documented way out of a quarantine (`mcpguard pins forget`) must work while Claude
    Desktop keeps the gateway running. It used to be overwritten by the gateway's next save."""
    import json

    from mcpguard.detect import PinStore

    async def go():
        async with gateway(servers=server_block(mode="harmless_change")) as gw:
            old_fp = gw.pins.pins["srv/echo"]
            await gw.refresh()
            assert "srv__echo" in gw.quarantined        # changed since it was pinned
            assert PinStore(gw.cfg.pins_path).forget("srv/echo")  # what `mcpguard pins forget srv/echo` does
            await gw.refresh()
            assert "srv__echo" in gw.tools               # trusted again, no restart needed
            return gw.cfg.pins_path, old_fp
    pins_path, old_fp = run(go())
    saved = json.loads(Path(pins_path).read_text(encoding="utf-8"))
    assert saved["srv/echo"] != old_fp                   # the gateway's shutdown did not restore the old pin


def test_pin_saves_from_two_processes_keep_both(tmp_path):
    from mcpguard.detect import PinStore
    p = tmp_path / "pins.json"
    a, b = PinStore(p), PinStore(p)
    a.check("one", {"name": "t", "description": "x"})
    b.check("two", {"name": "t", "description": "y"})
    a.save()
    b.save()
    assert set(PinStore(p).pins) == {"one/t", "two/t"}
