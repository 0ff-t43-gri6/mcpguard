"""First-sight pinning (hold new definitions for review) and tamper-evidence of the audit log."""

import json
import threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from conftest import call, is_err, rpc, run
from mcpguard.audit import default_checkpoint_path, read_log
from mcpguard.cli import main
from mcpguard.config import ConfigError, load_config
from mcpguard.detect import PinStore


def _tool(desc="Echo text back"):
    return {"name": "echo", "description": desc, "inputSchema": {"type": "object"}}


# ------------------------------------------------------------------ pins

def test_a_new_definition_is_trusted_on_sight_by_default_and_logged(tmp_path):
    store = PinStore(tmp_path / "pins.json")
    assert store.check("s", _tool()) is None
    assert store.take_first_seen() == ["s/echo"]
    assert store.check("s", _tool("changed")).rule == "rug_pull.changed"


def test_with_hold_new_nothing_is_trusted_until_approved(tmp_path):
    store = PinStore(tmp_path / "pins.json")
    f = store.check("s", _tool(), hold_new=True)
    assert f is not None
    assert f.rule == "pin.unreviewed"
    assert f.severity == "critical"
    store.save()
    assert store.pins == {}
    assert "s/echo" in PinStore(tmp_path / "pins.json").pending
    assert store.check("s", _tool(), hold_new=True) is not None  # asking again does not trust it

    assert store.approve("s") == ["s/echo"]
    fresh = PinStore(tmp_path / "pins.json")
    assert fresh.check("s", _tool(), hold_new=True) is None
    assert fresh.pending == {}


def test_approving_only_trusts_the_definition_you_were_shown(tmp_path):
    store = PinStore(tmp_path / "pins.json")
    store.check("s", _tool("what you read"), hold_new=True)
    store.save()
    store.approve("s")
    # The server now lists a different definition: that is a change, not a first sight.
    assert PinStore(tmp_path / "pins.json").check("s", _tool("swapped"), hold_new=True).rule == "rug_pull.changed"


def test_gateway_holds_new_tools_until_approved(gateway, tmp_path):
    async def go():
        async with gateway('[pins]\nfirst_seen = "approve"\n') as gw:
            names = {t["name"] for t in (await rpc(gw, "tools/list"))["result"]["tools"]}
            assert not any(n.endswith("echo") for n in names)
            res = await call(gw, "srv__echo", {"text": "hi"})
            assert is_err(res) or "error" in res
            pins_file = gw.cfg.pins_path
        return pins_file
    pins_file = run(go())
    assert PinStore(pins_file).pending  # waiting for review
    assert main(["-c", str(tmp_path / "mcpguard.toml"), "pins", "approve", "srv"]) == 0

    async def after():
        async with gateway('[pins]\nfirst_seen = "approve"\n') as gw:
            return {t["name"] for t in (await rpc(gw, "tools/list"))["result"]["tools"]}
    assert any(n.endswith("echo") for n in run(after()))


def test_default_mode_logs_what_it_trusted_on_sight(gateway):
    async def go():
        async with gateway() as gw:
            return gw.cfg.audit_path
    events = [r["event"] for r in read_log(run(go()))]
    assert "pins.first_seen" in events


def test_pins_commands_and_config_validation(make_config, capsys):
    cfg = make_config('[pins]\nfirst_seen = "approve"\n')
    assert main(["-c", str(cfg), "trust"]) == 0
    assert main(["-c", str(cfg), "pins", "pending"]) == 0
    assert "Nothing is waiting" in capsys.readouterr().out
    assert main(["-c", str(cfg), "pins", "approve"]) == 1  # names nothing
    assert main(["-c", str(cfg), "pins", "approve", "nothing-here"]) == 1
    bad = make_config('[pins]\nfirst_seen = "sometimes"\n')
    with pytest.raises(ConfigError):
        load_config(bad)


def test_strict_profile_holds_new_definitions(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["init", "--profile", "strict"]) == 0
    assert load_config("mcpguard.toml").pins_first_seen == "approve"


# ------------------------------------------------------------------ audit log witness

def test_checkpoints_are_on_by_default_in_the_home_folder(make_config):
    cfg = load_config(make_config())
    assert cfg.checkpoint_path == str(default_checkpoint_path(cfg.audit_path))
    off = load_config(make_config('[audit]\ncheckpoint_path = "off"\n'))
    assert off.checkpoint_path == ""


def test_deleting_the_newest_records_is_caught(gateway, tmp_path, capsys):
    async def go():
        async with gateway() as gw:
            await call(gw, "srv__echo", {"text": "one"})
            await call(gw, "srv__echo", {"text": "two"}, rid=2)
            gw.checkpoint()
            return gw.cfg.audit_path
    audit = run(go())
    cfg = str(tmp_path / "mcpguard.toml")
    assert main(["-c", cfg, "verify"]) == 0
    lines = Path(audit).read_text(encoding="utf-8").splitlines(keepends=True)
    with open(audit, "w", encoding="utf-8") as f:  # an attacker removes the last records; the chain stays valid
        f.writelines(lines[: len(lines) // 2])
    capsys.readouterr()
    assert main(["-c", cfg, "verify"]) == 3
    assert "truncated" in capsys.readouterr().out


def test_audit_new_moves_checkpoints_so_the_new_log_is_not_flagged(gateway, tmp_path):
    async def go():
        async with gateway() as gw:
            await call(gw, "srv__echo", {"text": "x"})
            gw.checkpoint()
    run(go())
    cfg = str(tmp_path / "mcpguard.toml")
    assert main(["-c", cfg, "audit-new"]) == 0
    assert main(["-c", cfg, "verify"]) == 0
    assert list((tmp_path / "audit-archive").glob("*/checkpoints.jsonl"))


def test_checkpoints_go_to_a_witness_server(gateway):
    got: list[dict] = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        async def go():
            async with gateway(f'[audit]\nwitness_url = "http://127.0.0.1:{srv.server_address[1]}/w"\n') as gw:
                await call(gw, "srv__echo", {"text": "x"})
                return gw.checkpoint()
        cp = run(go())
        for _ in range(50):
            if any(g.get("seq") == cp["seq"] for g in got):
                break
            threading.Event().wait(0.1)
        assert any(g.get("seq") == cp["seq"] and g.get("hash") == cp["hash"] for g in got)
    finally:
        srv.shutdown()


def test_witness_url_must_be_https(make_config):
    with pytest.raises(ConfigError):
        load_config(make_config('[audit]\nwitness_url = "http://example.com/w"\n'))


def test_doctor_warns_when_no_outside_copy_is_kept(make_config):
    from mcpguard import doctor
    on = doctor.check_witness(load_config(make_config()))
    off = doctor.check_witness(load_config(make_config('[audit]\ncheckpoint_path = "off"\n')))
    assert on.status == "ok"
    assert off.status == "warn"
