"""Signed audit log, alerts, client identities, timed approvals, cancellation, policy tests."""

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from conftest import call, is_err, rpc, run, server_block, text

from mcpguard.alerts import Alerter
from mcpguard.approvals import Verdict
from mcpguard.audit import AuditLog, load_key, read_log, verify
from mcpguard.cli import main

# ------------------------------------------------------------------ signed audit log


def test_signed_log_rejects_recomputed_hashes(tmp_path):
    """The weakness of a plain chain: an editor can recompute every hash. With a key they can't."""
    import hashlib
    key = load_key(tmp_path / "k", create=True)
    p = tmp_path / "a.jsonl"
    log = AuditLog(p, key=key)
    for i in range(4):
        log.write("call.blocked", n=i)
    assert verify(p, key) == (True, "audit log intact (4 records, signatures valid)")

    # Forge: change a record, drop the signature marker and rebuild the plain chain.
    recs = read_log(p)
    recs[1]["event"] = "call.allowed"
    prev = "0" * 64
    for r in recs:
        r.pop("alg", None)
        body = {k: v for k, v in r.items() if k not in ("prev", "hash")}
        r["prev"] = prev
        payload = prev + json.dumps(body, sort_keys=True, separators=(",", ":"))
        r["hash"] = hashlib.sha256(payload.encode()).hexdigest()
        prev = r["hash"]
    p.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in recs), encoding="utf-8")
    assert verify(p)[0]                       # without the key it looks fine...
    ok, msg = verify(p, key)                  # ...with the key the downgrade is caught
    assert not ok
    assert "unsigned" in msg


def test_signature_with_wrong_key_fails(tmp_path):
    p = tmp_path / "a.jsonl"
    AuditLog(p, key=b"k" * 32).write("e")
    ok, msg = verify(p, b"x" * 32)
    assert not ok
    assert "signature invalid" in msg
    ok, msg = verify(p)
    assert ok
    assert "not checked" in msg


def test_unsigned_history_can_continue_signed(tmp_path):
    p = tmp_path / "a.jsonl"
    AuditLog(p).write("old")
    AuditLog(p, key=b"k" * 32).write("new")
    assert verify(p, b"k" * 32)[0]


def test_key_file_is_created_private(tmp_path):
    import os
    key = load_key(tmp_path / "k", create=True)
    assert len(key) == 32
    assert load_key(tmp_path / "k") == key
    if os.name != "nt":
        assert (tmp_path / "k").stat().st_mode & 0o077 == 0


def test_gateway_signs_by_default(gateway, tmp_path):
    async def go():
        async with gateway() as gw:
            await call(gw, "srv__echo", {"text": "x"})
    run(go())
    from mcpguard.audit import default_key_path
    key_file = default_key_path(tmp_path / "mcpguard-audit.jsonl")  # outside the project folder by default
    assert key_file.exists()
    assert not (tmp_path / "mcpguard-audit.key").exists()
    ok, msg = verify(tmp_path / "mcpguard-audit.jsonl", load_key(key_file))
    assert ok
    assert "signatures valid" in msg


# ------------------------------------------------------------------ alerts


class _Sink:
    def __init__(self):
        self.bodies = []
        sink = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                sink.bodies.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.end_headers()

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/hook"


def test_alerts_batch_matching_events():
    sink = _Sink()
    a = Alerter(sink.url, ["call.blocked", "*.quarantined"], min_interval=0.2)
    for i in range(3):
        a({"event": "call.blocked", "tool": f"t{i}", "reason": "denied"})
    a({"event": "call.allowed", "tool": "fine"})
    a.close()
    sink.srv.shutdown()
    assert len(sink.bodies) == 1
    body = sink.bodies[0]
    assert len(body["records"]) == 3
    assert "3 security events" in body["text"]
    assert "t0" in body["text"]
    assert "fine" not in body["text"]


def test_gateway_sends_alerts_for_blocks(gateway):
    sink = _Sink()
    body = f'[alerts]\nwebhook_url = "{sink.url}"\nmin_interval_seconds = 0.1\n' \
           '[[policy.rules]]\nmatch = "*/delete_*"\naction = "deny"\n'

    async def go():
        async with gateway(body) as gw:
            await call(gw, "srv__delete_item")
    run(go())
    sink.srv.shutdown()
    events = [r["event"] for b in sink.bodies for r in b["records"]]
    assert "call.blocked" in events


def test_alert_delivery_failure_does_not_break_the_gateway(gateway):
    body = '[alerts]\nwebhook_url = "http://127.0.0.1:9/nothing"\nmin_interval_seconds = 0.05\n' \
           '[[policy.rules]]\nmatch = "*/delete_*"\naction = "deny"\n'

    async def go():
        async with gateway(body) as gw:
            assert is_err(await call(gw, "srv__delete_item"))
            assert text(await call(gw, "srv__echo", {"text": "ok"})) == "ok"
    run(go())


# ------------------------------------------------------------------ clients, grants, cancellation


def test_client_specific_rules(gateway):
    from mcpguard.gateway import Caller
    rules = '[[policy.rules]]\nmatch = "srv/send_email"\nclients = ["ci-*"]\naction = "deny"\n'

    async def go():
        async with gateway(rules) as gw:
            ci = Caller("ci-bot", "s1")
            names_ci = {t["name"] for t in (await rpc(gw, "tools/list"))["result"]["tools"]}
            assert "srv__send_email" in names_ci  # stdio is not ci-*
            listed = await gw.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, ci)
            assert "srv__send_email" not in {t["name"] for t in listed["result"]["tools"]}
            r = await gw.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                 "params": {"name": "srv__send_email", "arguments": {"body": "hi"}}}, ci)
            assert is_err(r)
            assert text(await call(gw, "srv__send_email", {"body": "hi"})) == "sent"
    run(go())


def test_budgets_are_per_client(gateway):
    from mcpguard.gateway import Caller

    async def go():
        async with gateway("[policy]\nmax_calls_per_session = 1\n") as gw:
            msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "srv__echo", "arguments": {"text": "x"}}}
            assert not is_err(await gw.handle(msg, Caller("a", "1")))
            assert is_err(await gw.handle(msg, Caller("a", "1")))
            assert not is_err(await gw.handle(msg, Caller("b", "2")))
    run(go())


def test_timed_approval_skips_later_prompts(gateway, tmp_path):
    asked = []

    async def approver(name, args, reason=""):
        asked.append(name)
        return Verdict(True, 600)

    async def go():
        async with gateway('[[policy.rules]]\nmatch = "*/delete_*"\naction = "ask"\n', approver=approver) as gw:
            for _ in range(3):
                assert text(await call(gw, "srv__delete_item")) == "deleted"
            assert len(asked) == 1
            gw.grants[("stdio", "srv/delete_item")] = 0  # expire it
            await call(gw, "srv__delete_item")
            assert len(asked) == 2
    run(go())
    approvals = [r for r in read_log(tmp_path / "mcpguard-audit.jsonl") if r["event"] == "call.approval"]
    assert approvals[0]["remember_until"] > 0


def test_tuple_and_bool_approvers_still_work():
    assert Verdict.of(True) == Verdict(True)
    assert Verdict.of((True, 5)) == Verdict(True, 300)
    assert Verdict.of((False, 5)) == Verdict(False, 0)


def test_cancellation_is_forwarded(gateway, tmp_path, monkeypatch):
    log = tmp_path / "cancels.txt"
    servers = server_block(extra=f'env = {{ FAKE_CANCEL_LOG = "{str(log).replace(chr(92), "/")}" }}\n')
    servers = servers.replace('env = { FAKE_MODE = "benign" }\n', "")

    async def go():
        async with gateway(servers=servers) as gw:
            task = asyncio.create_task(gw.handle({"jsonrpc": "2.0", "id": 77, "method": "tools/call",
                                                  "params": {"name": "srv__slow", "arguments": {"seconds": 5}}}))
            await asyncio.sleep(0.3)
            await gw.handle({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 77}})
            result = await asyncio.wait_for(task, 2)
            assert result is None  # no response for a cancelled request
            assert text(await call(gw, "srv__echo", {"text": "still fine"})) == "still fine"
    run(go())
    assert log.read_text(encoding="utf-8").strip()  # the server received notifications/cancelled
    assert "call.cancelled" in [r["event"] for r in read_log(tmp_path / "mcpguard-audit.jsonl")]


# ------------------------------------------------------------------ policy tests


def test_policy_test_command(make_config, tmp_path, capsys):
    p = make_config('[[policy.rules]]\nmatch = "srv/write_file"\nargs = { path = "/etc/*" }\naction = "deny"\n'
                    '[[policy.rules]]\nmatch = "srv/send_email"\nclients = ["ci"]\naction = "deny"\n')
    cases = tmp_path / "cases.toml"
    cases.write_text('''
[[case]]
call = "srv/write_file"
args = { path = "/etc/hosts" }
expect = "deny"

[[case]]
call = "srv/send_email"
client = "ci"
expect = "deny"
visible = false

[[case]]
call = "srv/echo"
args = { text = "AKIAABCDEFGHIJKLMNOP" }
expect = "allow"
expect_findings = ["secret.aws_access_key"]
''', encoding="utf-8")
    assert main(["-c", str(p), "policy-test", str(cases)]) == 0
    assert "3 passed, 0 failed" in capsys.readouterr().out
    cases.write_text('[[case]]\ncall = "srv/echo"\nexpect = "deny"\n', encoding="utf-8")
    assert main(["-c", str(p), "policy-test", str(cases)]) == 1
    assert "expected deny, got allow" in capsys.readouterr().out


def test_malformed_upstream_errors_are_contained(gateway):
    from mcpguard.upstream import UpstreamError
    assert UpstreamError("plain string").error == {"code": -32603, "message": "plain string"}
    assert UpstreamError({"code": "x", "message": 5}).error == {"code": -32603, "message": "5"}


def test_invalid_audit_key_is_a_config_error(make_config, monkeypatch):
    import pytest

    from mcpguard.config import ConfigError, load_config
    monkeypatch.setenv("MCPGUARD_AUDIT_KEY", "not-hex")
    with pytest.raises(ConfigError, match="not valid hex"):
        load_config(make_config())
    monkeypatch.setenv("MCPGUARD_AUDIT_KEY", "abcd")
    with pytest.raises(ConfigError, match="too short"):
        load_config(make_config())


def test_timed_approval_covers_every_gateway_process(gateway, tmp_path):
    """Claude Desktop may run two gateways: 'Allow for 15 minutes' in one must cover the other."""
    from mcpguard.approvals import load_grants
    asked = []

    async def approver(name, args, reason=""):
        asked.append(name)
        return Verdict(True, 600)

    rule = '[[policy.rules]]\nmatch = "*/delete_*"\naction = "ask"\n'

    async def go():
        async with gateway(rule, approver=approver) as first:
            assert text(await call(first, "srv__delete_item")) == "deleted"
            approvals_dir = first.cfg.approvals_dir
        async with gateway(rule, approver=approver) as second:  # a separate gateway, same config
            assert second.grants == {}
            assert text(await call(second, "srv__delete_item")) == "deleted"
        return approvals_dir
    approvals_dir = run(go())
    assert len(asked) == 1
    assert ("stdio", "srv/delete_item") in load_grants(approvals_dir)


def test_shared_grants_expire_and_survive_a_corrupt_file(tmp_path):
    import time as _time

    from mcpguard.approvals import GRANTS_FILE, load_grants, save_grant
    save_grant(tmp_path, "stdio", "a/x", _time.time() + 60)
    save_grant(tmp_path, "stdio", "a/old", _time.time() - 1)
    assert set(load_grants(tmp_path)) == {("stdio", "a/x")}
    save_grant(tmp_path, "ci", "a/y", _time.time() + 60)  # writing drops the expired one
    assert "a/old" not in (tmp_path / GRANTS_FILE).read_text(encoding="utf-8")
    (tmp_path / GRANTS_FILE).write_text("{not json", encoding="utf-8")
    assert load_grants(tmp_path) == {}
