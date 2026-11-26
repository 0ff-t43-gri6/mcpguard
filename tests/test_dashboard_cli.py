import asyncio
import json
from pathlib import Path
import threading
import urllib.error
import urllib.request

import pytest
from conftest import call, run

from mcpguard.approvals import Approvals, Verdict, decide, list_pending
from mcpguard.cli import main
from mcpguard.config import load_config
from mcpguard.dashboard import make_server


def test_dashboard_approval_queue(tmp_path):
    appr = Approvals("dashboard", tmp_path / "ap", timeout=5)

    async def go():
        task = asyncio.create_task(appr("srv__delete_item", {"key": "AKIAABCDEFGHIJKLMNOP"}, "rule"))
        for _ in range(40):
            await asyncio.sleep(0.05)
            if list_pending(tmp_path / "ap"):
                break
        pending = list_pending(tmp_path / "ap")
        assert pending[0]["tool"] == "srv__delete_item"
        assert "AKIA" not in json.dumps(pending[0]["args"])  # secrets are not shown to the approver
        assert decide(tmp_path / "ap", pending[0]["id"], True)
        return await task
    assert run(go()).approved is True
    assert list_pending(tmp_path / "ap") == []
    assert not list((tmp_path / "ap" / "decided").glob("*.json"))


def test_unanswered_approval_is_denied(tmp_path):
    assert run(Approvals("dashboard", tmp_path / "ap", timeout=0.3)("x", {}, "")).approved is False


@pytest.fixture
def dashboard(gateway, tmp_path):
    async def populate():
        async with gateway('[[policy.rules]]\nmatch = "*/delete_*"\naction = "deny"\n') as gw:
            await call(gw, "srv__echo", {"text": "x"})
            await call(gw, "srv__delete_item")
            return gw.cfg
    cfg = run(populate())
    srv = make_server(cfg, 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_dashboard_page_and_state(dashboard):
    html = urllib.request.urlopen(dashboard + "/").read().decode()
    assert "Audit ledger" in html
    assert "__MCPGUARD_TOKEN__" not in html
    assert "mcpguard audit-new" in html  # the integrity banner says what to do next
    assert "gateway processes share this config" in html
    s = json.loads(urllib.request.urlopen(dashboard + "/api/state").read())
    assert s["integrity"]["ok"]
    assert s["counts"]["allowed"] == 1
    assert s["counts"]["blocked"] == 1
    assert s["gateway"]["running"] is False                    # gateway stopped after the fixture
    assert s["gateway"]["processes"] == 0
    assert len(s["timeline"]) == 60
    assert sum(m["allowed"] for m in s["timeline"]) == 1
    assert s["servers"][0]["name"] == "srv"
    assert s["inventory"]
    assert s["events"][0]["event"] == "server.start" or s["events"]


def test_dashboard_rejects_bad_token_and_foreign_host(dashboard):
    req = urllib.request.Request(dashboard + "/api/decide", data=b'{"id":"abc","approved":true}',
                                 headers={"X-Token": "wrong"}, method="POST")
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 403
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(urllib.request.Request(dashboard + "/api/state", headers={"Host": "evil.example"}))
    assert e.value.code == 403


def test_cli_check_explain_and_errors(make_config, capsys):
    p = make_config('[[policy.rules]]\nmatch = "srv/write_file"\nargs = { path = "/etc/*" }\naction = "deny"\n')
    assert main(["-c", str(p), "check"]) == 0
    assert "valid" in capsys.readouterr().out
    assert main(["-c", str(p), "explain", "srv/write_file", "--args", '{"path": "/etc/hosts"}']) == 0
    assert "deny" in capsys.readouterr().out
    assert main(["-c", str(p), "explain", "srv__echo"]) == 0
    assert "allow" in capsys.readouterr().out
    assert main(["-c", str(p.parent / "missing.toml"), "check"]) == 1
    assert "mcpguard init" in capsys.readouterr().err


def test_cli_scan_reports_findings(tmp_path, capsys, monkeypatch):
    from conftest import FAKE, PY
    monkeypatch.setenv("FAKE_MODE", "poisoned")
    monkeypatch.chdir(tmp_path)
    assert main(["scan", "--", PY, FAKE]) == 2
    out = capsys.readouterr().out
    assert "critical" in out
    assert "injection.pattern" in out


def test_cli_verify_and_report(gateway, tmp_path, capsys):
    async def go():
        async with gateway() as gw:
            await call(gw, "srv__echo", {"text": "x"})
            return gw.cfg.source
    cfg = run(go())
    assert main(["-c", cfg, "verify"]) == 0
    assert "OK" in capsys.readouterr().out
    assert main(["-c", cfg, "report"]) == 0
    assert "Log integrity: **PASS**." in capsys.readouterr().out
    assert load_config(cfg).mode == "enforce"


def test_dashboard_metrics_endpoint(dashboard):
    with urllib.request.urlopen(dashboard + "/metrics") as r:
        body = r.read().decode()
        assert r.headers["Content-Type"].startswith("text/plain")
    assert 'mcpguard_calls_total{outcome="allowed",server="srv"} 1' in body
    assert 'mcpguard_calls_total{outcome="blocked",server="srv"} 1' in body
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(dashboard + "/nope")
    assert e.value.code == 404


def test_tty_approvals(monkeypatch, tmp_path):
    import builtins
    import io

    real_open = builtins.open
    answers = iter(["y\n", "a\n", "n\n"])

    class FakeTTY(io.StringIO):
        def readline(self, *a):
            return next(answers)

    def fake_open(path, *a, **k):
        if path in ("/dev/tty", "CONIN$", "CONOUT$"):
            return FakeTTY()
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", fake_open)
    appr = Approvals("tty", tmp_path, remember_minutes=15)
    assert appr._tty("t", {}) == Verdict(True)
    assert appr._tty("t", {}) == Verdict(True, 900)
    assert appr._tty("t", {}) == Verdict(False)

    def no_console(path, *a, **k):
        if path in ("/dev/tty", "CONIN$", "CONOUT$"):
            raise OSError("no console")
        return real_open(path, *a, **k)
    monkeypatch.setattr(builtins, "open", no_console)
    assert appr._tty("t", {}) is None  # no console: the caller falls back to the dashboard, or denies
    assert asyncio.run(appr("t", {})) == Verdict(False)  # with no dashboard to fall back to, fail closed


def test_fixed_approval_modes(tmp_path):
    assert run(Approvals("allow", tmp_path)("t", {})).approved is True
    assert run(Approvals("deny", tmp_path)("t", {})).approved is False
    with pytest.raises(ValueError):
        Approvals("maybe", tmp_path)


def test_dashboard_reports_a_forked_log(gateway, tmp_path):
    from test_audit import _forked_log
    async def populate():
        async with gateway() as gw:
            return gw.cfg
    cfg = run(populate())
    log_path = Path(cfg.audit_path)
    for f in log_path.parent.glob(log_path.name + "*"):
        f.unlink()
    from mcpguard.audit import load_key
    _forked_log(log_path, load_key(cfg.audit_key_file))
    srv = make_server(cfg, 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        s = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{srv.server_address[1]}/api/state").read())
    finally:
        srv.shutdown()
    assert not s["integrity"]["ok"]
    assert "chain forked" in s["integrity"]["message"]


def test_one_dashboard_answers_requests_from_two_gateway_processes(tmp_path):
    """Two gateways (as Claude Desktop may start) share the approvals folder: both requests are
    listed in one dashboard, and each answer reaches the gateway that asked."""
    import asyncio

    from mcpguard.approvals import decide, list_pending

    async def go():
        first = Approvals("dashboard", tmp_path / "ap", timeout=10)
        second = Approvals("dashboard", tmp_path / "ap", timeout=10)
        a = asyncio.create_task(first("files__move_file", {"source": "a"}, "policy: ask"))
        b = asyncio.create_task(second("files__delete_file", {"path": "b"}, "policy: ask"))
        for _ in range(100):
            pending = list_pending(tmp_path / "ap")
            if len(pending) == 2:
                break
            await asyncio.sleep(0.05)
        by_tool = {p["tool"]: p["id"] for p in pending}
        assert set(by_tool) == {"files__move_file", "files__delete_file"}
        assert decide(tmp_path / "ap", by_tool["files__move_file"], True)
        assert decide(tmp_path / "ap", by_tool["files__delete_file"], False)
        return (await a).approved, (await b).approved

    assert run(go()) == (True, False)
    assert list_pending(tmp_path / "ap") == []
