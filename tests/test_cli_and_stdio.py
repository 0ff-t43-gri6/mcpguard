"""CLI commands end to end, and the stdio gateway as a real subprocess."""

import json
import os
import subprocess
import sys
import time

import pytest
from conftest import FAKE, PY, call, run

from mcpguard.state import read_merged
from mcpguard.cli import main


@pytest.fixture
def cfg(make_config):
    return str(make_config())


def test_init_refuses_to_overwrite_without_force(tmp_path, capsys):
    p = tmp_path / "new.toml"
    assert main(["-c", str(p), "init"]) == 0
    assert main(["-c", str(p), "init"]) == 1
    assert "already exists" in capsys.readouterr().err
    assert main(["-c", str(p), "init", "--force"]) == 0
    assert main(["-c", str(p), "check"]) == 0


def test_test_command_shows_findings_and_redaction(cfg, capsys):
    assert main(["-c", cfg, "test", "key AKIAABCDEFGHIJKLMNOP", "--scope", "args"]) == 0
    out = capsys.readouterr().out
    assert "secret.aws_access_key" in out
    assert "[REDACTED:aws_access_key]" in out
    assert main(["-c", cfg, "test", "hello there", "--scope", "definition"]) == 0
    out = capsys.readouterr().out
    assert "No findings." in out
    assert "redacted" not in out  # nothing was removed, so the text is not repeated


def test_pins_baseline_report_and_checkpoint_commands(gateway, tmp_path, capsys):
    async def go():
        async with gateway("[anomaly]\nenabled = true\nmin_samples = 2\n") as gw:
            for _ in range(3):
                await call(gw, "srv__echo", {"text": "x"})
            return gw.cfg.source
    cfg = run(go())
    assert main(["-c", cfg, "pins", "list"]) == 0
    assert "srv/echo" in capsys.readouterr().out
    assert main(["-c", cfg, "pins", "forget", "srv/echo"]) == 0
    assert main(["-c", cfg, "pins", "forget", "srv/nope"]) == 1
    assert main(["-c", cfg, "pins", "reset"]) == 0
    capsys.readouterr()
    assert main(["-c", cfg, "baseline", "show"]) == 0
    assert "result_chars" in capsys.readouterr().out
    assert main(["-c", cfg, "baseline", "reset"]) == 0
    out = tmp_path / "report.md"
    assert main(["-c", cfg, "report", "-o", str(out)]) == 0
    assert "Control evidence" in out.read_text(encoding="utf-8")
    page = tmp_path / "report.html"
    assert main(["-c", cfg, "report", "-o", str(page)]) == 0  # the .html name picks the format
    text = page.read_text(encoding="utf-8")
    assert text.startswith("<!doctype html>")
    assert "Control evidence" in text
    assert 'class="badge' in text
    assert "http://" not in text
    assert "https://" not in text  # one file, no outside requests
    assert main(["-c", cfg, "checkpoint"]) == 0  # no -o: goes to the default checkpoint file in the home folder
    assert "appended to" in capsys.readouterr().out
    assert main(["-c", cfg, "checkpoint", "-o", str(tmp_path / "cp.jsonl")]) == 0
    assert main(["-c", cfg, "verify", "--checkpoints", str(tmp_path / "cp.jsonl")]) == 0


def test_scan_json_output(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["scan", "--json", "--", PY, FAKE]) == 0
    data = json.loads(capsys.readouterr().out)
    assert any(t["name"] == "echo" for t in data["tools"])
    assert data["prompts"] == 1


def test_scan_needs_a_target(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["scan"]) == 1
    assert "give a server command" in capsys.readouterr().err


def test_policy_test_file_errors(cfg, tmp_path, capsys):
    assert main(["-c", cfg, "policy-test", str(tmp_path / "missing.toml")]) == 1
    empty = tmp_path / "empty.toml"
    empty.write_text("", encoding="utf-8")
    assert main(["-c", cfg, "policy-test", str(empty)]) == 1
    assert "no [[case]]" in capsys.readouterr().err


def test_explain_rejects_bad_json(cfg, capsys):
    assert main(["-c", cfg, "explain", "srv/echo", "--args", "{nope"]) == 1
    assert main(["-c", cfg, "explain", "srv/echo", "--args", "[1]"]) == 1


def test_dashboard_command_reports_busy_port(cfg, capsys):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    try:
        assert main(["-c", cfg, "dashboard", "--port", str(s.getsockname()[1])]) == 1
        assert "cannot listen" in capsys.readouterr().err
    finally:
        s.close()


def test_stdio_gateway_as_a_subprocess(make_config, tmp_path):
    """The real `mcpguard run` loop: handshake, calls, parse errors, clean exit on EOF."""
    cfg = make_config()
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    p = subprocess.Popen([sys.executable, "-m", "mcpguard.cli", "-c", str(cfg), "run"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", env=env)

    def send(obj):
        p.stdin.write((obj if isinstance(obj, str) else json.dumps(obj)) + "\n")
        p.stdin.flush()

    def recv():
        return json.loads(p.stdout.readline())

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
        assert recv()["result"]["serverInfo"]["name"] == "mcpguard"
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": "srv__echo", "arguments": {"text": "through stdio"}}})
        assert recv()["result"]["content"][0]["text"] == "through stdio"
        send("this is not json")
        assert recv()["error"]["code"] == -32700
        send("[1, 2]")
        assert recv()["error"]["code"] == -32600
    finally:
        p.stdin.close()
        p.wait(timeout=15)
    assert p.returncode == 0
    state = read_merged(tmp_path / "mcpguard-state.json")
    assert state["running"] is False


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_stdio_gateway_stops_cleanly_on_sigterm(make_config, tmp_path):
    import signal
    cfg = make_config()
    p = subprocess.Popen([sys.executable, "-m", "mcpguard.cli", "-c", str(cfg), "run"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
    p.stdin.flush()
    p.stdout.readline()
    time.sleep(0.2)
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=15)
    assert read_merged(tmp_path / "mcpguard-state.json")["running"] is False


def test_scan_all_servers_with_cross_server_checks(tmp_path, capsys, monkeypatch):
    from conftest import server_block
    monkeypatch.chdir(tmp_path)
    (tmp_path / "mcpguard.toml").write_text(
        server_block("mail") + server_block("weather", "shadow")
        + '\n[servers.broken]\ncommand = "no-such-command-xyz"\n', encoding="utf-8")
    assert main(["scan", "--all", "--json"]) == 1  # a config merely found in this folder starts nothing
    assert "has not been trusted" in capsys.readouterr().err
    assert main(["trust"]) == 0
    capsys.readouterr()
    code = main(["scan", "--all", "--json"])
    data = json.loads(capsys.readouterr().out)
    by_name = {r["server"]: r for r in data["servers"]}
    assert by_name["mail"]["tools"] > 0
    assert "error" in by_name["broken"]           # one bad server does not hide the others
    rules = {f["rule"] for f in data["findings"]}
    assert "shadowing.cross_reference" in rules   # weather/forecast talks about mail/send_email
    assert "shadowing.duplicate_name" in rules    # both fake servers offer send_email
    assert code == 1  # a server failed and nothing reached high


def test_scan_all_rejects_a_command_too(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "mcpguard.toml").write_text("", encoding="utf-8")
    assert main(["scan", "--all", "--", PY, FAKE]) == 1
    assert "--all" in capsys.readouterr().err
