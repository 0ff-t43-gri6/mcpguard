"""Stopping audit-log tampering where software can: noticing while running, a copy off the
machine, and an operating-system append-only lock."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from conftest import call, is_err, rpc, run
from mcpguard import protect
from mcpguard.audit import AuditLog, read_log
from mcpguard.cli import main
from mcpguard.config import ConfigError, load_config
from mcpguard.forward import Forwarder


def _log(tmp_path, n=4, **kw):
    log = AuditLog(tmp_path / "a.jsonl", **kw)
    for i in range(n):
        log.write("e", n=i)
    return log


# ------------------------------------------------------------------ AuditLog.check_intact

def test_an_untouched_log_is_intact_even_when_another_process_appends(tmp_path):
    log = _log(tmp_path)
    assert log.check_intact() is None
    AuditLog(tmp_path / "a.jsonl").write("other-process")  # a second gateway on the same log
    assert log.check_intact() is None


def test_deleting_the_log_is_noticed(tmp_path):
    log = _log(tmp_path)
    (tmp_path / "a.jsonl").unlink()
    assert "deleted" in log.check_intact()


def test_cutting_the_log_short_is_noticed(tmp_path):
    log = _log(tmp_path)
    p = tmp_path / "a.jsonl"
    lines = p.read_bytes().splitlines(keepends=True)
    p.write_bytes(b"".join(lines[:2]))
    assert "missing or was changed" in log.check_intact()
    # the chain is still valid, and the next write quietly continues it: that is exactly the hole
    log.write("after")
    assert read_log(p)[-1]["event"] == "after"


def test_editing_the_newest_record_is_noticed(tmp_path):
    log = _log(tmp_path)
    p = tmp_path / "a.jsonl"
    p.write_bytes(p.read_bytes().replace(b'"n": 3', b'"n": 9').replace(b'"n":3', b'"n":9'))
    assert log.check_intact() is not None


def test_replacing_the_file_with_a_copy_is_noticed(tmp_path):
    log = _log(tmp_path)
    p = tmp_path / "a.jsonl"
    p.write_bytes(p.read_bytes()[:50])  # same inode, shorter
    assert log.check_intact() is not None


def test_rotation_and_archiving_on_purpose_are_not_tampering(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl", max_bytes=400)
    for i in range(12):
        log.write("e", n=i, pad="x" * 40)
        assert log.check_intact() is None
    from mcpguard.audit import archive
    archive(tmp_path / "a.jsonl")
    assert log.check_intact() is None  # our record is in the archive


# ------------------------------------------------------------------ gateway reaction

def _cut(path: Path):
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:2]))


def test_a_tampered_log_stops_tool_calls_and_raises_an_alarm(gateway):
    async def go():
        async with gateway() as gw:
            assert not is_err(await call(gw, "srv__echo", {"text": "before"}))
            _cut(Path(gw.cfg.audit_path))
            res = await call(gw, "srv__echo", {"text": "after"}, rid=2)
            assert is_err(res)
            assert "audit log was changed" in res["result"]["content"][0]["text"]
            assert "tools" in (await rpc(gw, "tools/list", rid=3))["result"]  # listing still works
            res = await call(gw, "srv__echo", {"text": "again"}, rid=4)  # and it stays blocked
            assert is_err(res)
            return gw.cfg.audit_path
    events = [r["event"] for r in read_log(run(go()))]
    assert "audit.tampered" in events


def test_warn_mode_alerts_but_carries_on(gateway):
    async def go():
        async with gateway('[audit]\non_tamper = "warn"\n') as gw:
            await call(gw, "srv__echo", {"text": "x"})
            _cut(Path(gw.cfg.audit_path))
            assert not is_err(await call(gw, "srv__echo", {"text": "y"}, rid=2))
            return gw.cfg.audit_path
    assert "audit.tampered" in [r["event"] for r in read_log(run(go()))]


def test_audit_new_clears_the_block(gateway, tmp_path):
    async def go():
        async with gateway() as gw:
            await call(gw, "srv__echo", {"text": "x"})
            _cut(Path(gw.cfg.audit_path))
            assert is_err(await call(gw, "srv__echo", {"text": "y"}, rid=2))
            assert main(["-c", str(tmp_path / "mcpguard.toml"), "audit-new"]) == 0  # the operator looked into it
            assert not is_err(await call(gw, "srv__echo", {"text": "z"}, rid=3))
    run(go())


def test_the_periodic_check_catches_an_edit_in_the_middle(gateway):
    async def go():
        async with gateway('[audit]\nverify_minutes = 1\n') as gw:
            for i in range(3):
                await call(gw, "srv__echo", {"text": str(i)}, rid=i + 1)
            p = Path(gw.cfg.audit_path)
            data = p.read_bytes()
            first = data.split(b"\n", 1)
            p.write_bytes(first[0].replace(b'"event": "', b'"event":"x', 1) + b"\n" + first[1])
            assert not is_err(await call(gw, "srv__echo", {"text": "quick check passes"}, rid=10))
            gw._last_verify -= 120  # a minute has passed
            assert is_err(await call(gw, "srv__echo", {"text": "full check fails"}, rid=11))
    run(go())


def test_config_validation(make_config):
    with pytest.raises(ConfigError):
        load_config(make_config('[audit]\non_tamper = "ignore"\n'))
    with pytest.raises(ConfigError):
        load_config(make_config('[audit]\nforward_url = "http://logs.example.com/x"\n'))
    with pytest.raises(ConfigError):
        load_config(make_config('[audit]\nverify_minutes = -1\n'))
    assert load_config(make_config()).audit_on_tamper == "block"


# ------------------------------------------------------------------ forwarding off the machine

class Sink:
    """A tiny log server: records what it is sent, and can pretend to be down."""

    def __init__(self):
        self.batches: list[list[dict]] = []
        self.up = True
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                if not outer.up:
                    self.send_response(503)
                    self.end_headers()
                    return
                outer.batches.append([json.loads(x) for x in body.decode().splitlines()])
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/log"

    @property
    def seqs(self):
        return [r["seq"] for b in self.batches for r in b]

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def sink():
    s = Sink()
    yield s
    s.close()


def test_every_record_is_sent_and_a_restart_does_not_repeat_or_skip(tmp_path, sink):
    log = _log(tmp_path, 5)
    f = Forwarder(sink.url, tmp_path / "a.jsonl", interval=3600)
    while f.flush_once():
        pass
    f.close(flush=False)
    assert sink.seqs == [0, 1, 2, 3, 4]
    log.write("more")
    log.write("and more")
    f2 = Forwarder(sink.url, tmp_path / "a.jsonl", interval=3600)  # a new process, same cursor file
    while f2.flush_once():
        pass
    f2.close(flush=False)
    assert sink.seqs == [0, 1, 2, 3, 4, 5, 6]


def test_an_outage_loses_nothing(tmp_path, sink):
    log = _log(tmp_path, 3)
    f = Forwarder(sink.url, tmp_path / "a.jsonl", interval=3600)
    sink.up = False
    assert not f.flush_once()
    assert f.failed == 1
    log.write("during the outage")
    sink.up = True
    while f.flush_once():
        pass
    f.close(flush=False)
    assert sink.seqs == [0, 1, 2, 3]


def test_a_deleted_log_cannot_take_back_what_was_already_sent(tmp_path, sink):
    log = _log(tmp_path, 4)
    f = Forwarder(sink.url, tmp_path / "a.jsonl", interval=3600)
    while f.flush_once():
        pass
    f.close(flush=False)
    (tmp_path / "a.jsonl").unlink()
    assert log.check_intact() is not None  # noticed locally...
    assert sink.seqs == [0, 1, 2, 3]  # ...and the copy is still there


def test_a_new_log_after_audit_new_is_forwarded_from_its_start(tmp_path, sink):
    from mcpguard.audit import archive
    _log(tmp_path, 3)
    f = Forwarder(sink.url, tmp_path / "a.jsonl", interval=3600)
    while f.flush_once():
        pass
    archive(tmp_path / "a.jsonl")
    AuditLog(tmp_path / "a.jsonl").write("fresh")
    while f.flush_once():
        pass
    f.close(flush=False)
    assert sink.seqs[:3] == [0, 1, 2]
    assert sink.seqs[3:]
    assert sink.seqs[-1] == read_log(tmp_path / "a.jsonl")[-1]["seq"]


def test_the_gateway_forwards_as_it_runs(gateway, sink):
    async def go():
        async with gateway(f'[audit]\nforward_url = "{sink.url}"\n') as gw:
            await call(gw, "srv__echo", {"text": "x"})
    run(go())
    for _ in range(50):
        if sink.batches:
            break
        time.sleep(0.1)
    events = [r["event"] for b in sink.batches for r in b]
    assert "call.allowed" in events or any(e.startswith("call") for e in events)


# ------------------------------------------------------------------ operating-system lock

def test_protect_runs_the_right_command(tmp_path, monkeypatch):
    p = tmp_path / "a.jsonl"
    p.write_text("x", encoding="utf-8")
    ran = []
    monkeypatch.setattr(protect.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(protect.subprocess, "run", lambda cmd, **k: ran.append(cmd) or type(
        "R", (), {"returncode": 0, "stderr": "", "stdout": ""})())
    assert protect.set_append_only([p, tmp_path / "missing"], True, "linux")[1].startswith("skipped")
    assert ran == [["/usr/bin/chattr", "+a", "--", str(p)]]
    ran.clear()
    protect.set_append_only([p], False, "mac")
    assert ran == [["/usr/bin/chflags", "nouappnd", "--", str(p)]]


def test_protect_explains_failures(tmp_path, monkeypatch):
    p = tmp_path / "a.jsonl"
    p.write_text("x", encoding="utf-8")
    monkeypatch.setattr(protect.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(protect.subprocess, "run", lambda cmd, **k: type(
        "R", (), {"returncode": 1, "stderr": "Operation not permitted", "stdout": ""})())
    with pytest.raises(protect.ProtectError, match="Operation not permitted"):
        protect.set_append_only([p], True, "linux")
    with pytest.raises(protect.ProtectError, match="no append-only flag"):
        protect.set_append_only([p], True, "windows")


def test_the_cli_commands(make_config, monkeypatch, capsys):
    cfg = make_config()
    assert main(["-c", str(cfg), "trust"]) == 0
    seen = []
    monkeypatch.setattr("mcpguard.protect.set_append_only",
                        lambda paths, enable, flavour=None: seen.append(enable) or ["protected x"])
    assert main(["-c", str(cfg), "audit-protect"]) == 0
    assert main(["-c", str(cfg), "audit-unprotect"]) == 0
    assert seen == [True, False]
    capsys.readouterr()
    monkeypatch.setattr("mcpguard.protect.set_append_only",
                        lambda *a, **k: (_ for _ in ()).throw(protect.ProtectError("nope")))
    assert main(["-c", str(cfg), "audit-protect"]) == 1
    assert "nope" in capsys.readouterr().err


def test_a_protected_log_with_a_broken_last_line_still_starts(tmp_path, monkeypatch):
    p = tmp_path / "a.jsonl"
    _log(tmp_path, 2)
    with p.open("ab") as f:
        f.write(b'{"seq": 2, "ev')  # an interrupted write
    monkeypatch.setattr(AuditLog, "_recover_partial_line", lambda self: (_ for _ in ()).throw(PermissionError()))
    log = AuditLog(p)  # cannot truncate an append-only file; must not crash
    log.write("after")
    assert read_log(p)[-1]["event"] == "after"
