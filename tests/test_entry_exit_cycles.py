"""Regression tests for bugs found by scripts/cycles.py (entry and exit points)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcpguard.audit import AuditLog, LogDamaged, read_log, verify
from mcpguard.cli import main

ROOT = Path(__file__).resolve().parent.parent


def _log(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(3):
        log.write("tool.call", n=i)
    return tmp_path / "a.jsonl"


@pytest.mark.parametrize("junk", [b"not json\n", b"\xff\xfe\n", b"[1,2]\n", b"42\n", b"[" * 5000 + b"\n"])
def test_a_damaged_line_is_reported_by_verify_and_skipped_elsewhere(tmp_path, junk):
    p = _log(tmp_path)
    p.write_bytes(p.read_bytes() + junk)
    ok, msg = verify(p)
    assert not ok
    assert "damaged" in msg
    assert len(read_log(p)) >= 3  # readers skip the line instead of crashing
    with pytest.raises(LogDamaged):
        read_log(p, strict=True)


def test_a_log_that_is_a_folder_is_an_error_not_a_traceback(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    (tmp_path / "mcpguard-audit.jsonl").mkdir()
    assert main(["check"]) == 1
    assert "is a folder" in capsys.readouterr().err
    ok, msg = verify(tmp_path / "mcpguard-audit.jsonl")
    assert not ok
    assert "cannot read" in msg


def test_audit_new_twice_in_one_second_does_not_collide(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    assert main(["audit-new"]) == 0
    assert main(["audit-new"]) == 0
    assert main(["verify"]) == 0


def test_trust_follows_the_content_of_the_config(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    assert main(["check"]) == 0
    cfg = tmp_path / "mcpguard.toml"
    cfg.write_text(cfg.read_text(encoding="utf-8") + f'\n[servers.extra]\ncommand = {json.dumps(sys.executable)}\n',
                   encoding="utf-8")
    capsys.readouterr()
    assert main(["check"]) == 1
    assert "has changed since you trusted it" in capsys.readouterr().err
    assert main(["trust"]) == 0
    assert main(["check"]) == 0


def test_an_unexpected_error_is_one_line_not_a_traceback(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    from mcpguard import cli
    parser_fn = cli.build_parser
    monkeypatch.setattr(cli, "build_parser", lambda: _with_fn(parser_fn(), lambda a: 1 / 0))
    assert main(["checks"]) == 1
    err = capsys.readouterr().err
    assert "unexpected ZeroDivisionError" in err
    assert "Traceback" not in err


def _with_fn(parser, fn):
    class P:
        def parse_args(self, argv):
            a = parser.parse_args(argv)
            a.fn = fn
            return a
    return P()


def _cycles(pattern):
    p = subprocess.run([sys.executable, str(ROOT / "scripts" / "cycles.py"), "-k", pattern],
                       capture_output=True, text=True, encoding="utf-8", timeout=120)
    return p.returncode, p.stdout


@pytest.mark.parametrize("pattern", ["stdio: non-UTF-8 bytes", "SIGTERM while idle", "closed reader",
                                     "closes stdout early"])
def test_gateway_exit_cycles(pattern):
    if sys.platform == "win32" and pattern != "stdio: non-UTF-8 bytes":
        pytest.skip("these cycles send POSIX signals or use shell pipes; Windows has neither")
    rc, out = _cycles(pattern)
    assert rc == 0, out


@pytest.mark.skipif(sys.platform == "win32", reason="uses a POSIX pipe handed to a child process")
def test_a_gateway_whose_app_has_gone_exits_even_if_its_stdin_stays_open(tmp_path, monkeypatch):
    """The app starts the gateway and then disappears, but the stdin pipe stays open because
    something else still holds it. The gateway used to live on forever."""
    import os
    import time

    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    r, w = os.pipe()  # we keep the write end, so the gateway's stdin never reaches EOF
    launcher = (
        "import subprocess, sys\n"
        f"p = subprocess.Popen([sys.executable, '-m', 'mcpguard', 'run'], stdin={r}, stdout=subprocess.DEVNULL,\n"
        f"                     stderr=subprocess.DEVNULL, pass_fds=({r},))\n"
        "print(p.pid, flush=True)\n"
    )
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "MCPGUARD_HOME": str(tmp_path / "home")}
    out = subprocess.run([sys.executable, "-c", launcher], capture_output=True, text=True, encoding="utf-8",
                         env=env, cwd=tmp_path, pass_fds=(r,), timeout=60, check=True).stdout
    pid = int(out.split()[0])
    os.close(r)

    def alive() -> bool:
        try:
            status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
        except OSError:
            return False
        return "State:\tZ" not in status

    try:
        deadline = time.time() + 20
        while alive() and time.time() < deadline:
            time.sleep(0.5)
        assert not alive(), "the gateway kept running after its parent exited"
    finally:
        os.close(w)
        if alive():
            os.kill(pid, 9)
