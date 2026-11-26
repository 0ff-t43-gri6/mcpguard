"""mcpguard doctor."""

import json
import socket
import sys

from mcpguard import desktop, doctor
from mcpguard.audit import AuditLog
from mcpguard.cli import main


def write_cfg(tmp_path, servers, extra=""):
    p = tmp_path / "mcpguard.toml"
    p.write_text(f'mode = "enforce"\n{extra}\n{servers}', encoding="utf-8")
    return p


def by_name(checks):
    return {c.name: c for c in checks}


def test_missing_config(tmp_path):
    checks = doctor.run(tmp_path / "nope.toml", tmp_path / "none.json")
    assert checks[-1].status == doctor.FAIL
    assert "mcpguard init" in checks[-1].detail or "not found" in checks[-1].detail


def test_servers_found_missing_and_node_hint(tmp_path):
    cfg = write_cfg(tmp_path, f'''
[servers.py]
command = {json.dumps(sys.executable)}
args = ["-c", "pass"]
[servers.node]
command = "npx-not-installed-xyz"
[servers.nodejs]
command = "npx"
args = ["-y", "pkg", "/definitely/not/here"]
[servers.remote]
url = "https://mcp.example/mcp"
bearer_env = "MCPGUARD_TEST_UNSET_TOKEN"
''')
    checks = by_name(doctor.run(cfg, tmp_path / "none.json"))
    assert checks["server py"].status == doctor.OK
    assert checks["server node"].status == doctor.FAIL
    assert checks["server remote"].status == doctor.WARN
    nodejs = checks["server nodejs"]
    assert nodejs.status in (doctor.FAIL, doctor.WARN)  # FAIL without Node, WARN for the missing path
    assert ("nodejs.org" in nodejs.detail) or ("/definitely/not/here" in nodejs.detail)


def test_no_servers_is_a_problem(tmp_path):
    cfg = write_cfg(tmp_path, "")
    assert by_name(doctor.run(cfg, tmp_path / "none.json"))["servers"].status == doctor.FAIL


def test_dashboard_port_in_use(tmp_path):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        cfg = write_cfg(tmp_path, f'[servers.a]\ncommand = {json.dumps(sys.executable)}\n',
                        f"[dashboard]\nenabled = true\nport = {port}\n")
        assert by_name(doctor.run(cfg, tmp_path / "none.json"))["dashboard"].status == doctor.WARN


def test_audit_log_broken_and_key_missing(tmp_path):
    cfg = write_cfg(tmp_path, f'[servers.a]\ncommand = {json.dumps(sys.executable)}\n')
    log_path = tmp_path / "mcpguard-audit.jsonl"
    key = bytes(range(32))
    (tmp_path / "mcpguard-audit.key").write_text(key.hex(), encoding="utf-8")
    log = AuditLog(log_path, key=key)
    log.write("a")
    log.write("b")
    assert by_name(doctor.run(cfg, tmp_path / "none.json"))["audit log"].status == doctor.OK
    lines = log_path.read_text(encoding="utf-8").splitlines()
    log_path.write_text(lines[1] + "\n", encoding="utf-8")  # drop the first record
    audit = by_name(doctor.run(cfg, tmp_path / "none.json"))["audit log"]
    assert audit.status == doctor.FAIL
    assert "audit-new" in audit.detail
    (tmp_path / "mcpguard-audit.key").unlink()
    assert "signing key" in by_name(doctor.run(cfg, tmp_path / "none.json"))["audit log"].detail


def test_claude_desktop_check_and_cli(tmp_path, capsys):
    cfg = write_cfg(tmp_path, f'[servers.a]\ncommand = {json.dumps(sys.executable)}\n')
    dfile = tmp_path / "claude_desktop_config.json"
    dfile.write_text("{}", encoding="utf-8")
    assert by_name(doctor.run(cfg, dfile))["Claude Desktop"].status == doctor.WARN
    desktop.install(dfile, cfg)
    assert by_name(doctor.run(cfg, dfile))["Claude Desktop"].status == doctor.OK
    assert main(["-c", str(cfg), "doctor", "--desktop-file", str(dfile)]) == 0
    assert "Everything looks right." in capsys.readouterr().out
    assert main(["-c", str(tmp_path / "missing.toml"), "doctor"]) == 2


def test_ask_rules_that_nobody_can_answer(tmp_path):
    srv = f'[servers.a]\ncommand = {json.dumps(sys.executable)}\n'
    ask = '[[policy.rules]]\nmatch = "*/move_*"\naction = "ask"\n'
    cases = {
        '[approvals]\nmode = "tty"\n': doctor.WARN,
        '[approvals]\nmode = "dashboard"\n[dashboard]\nenabled = false\n': doctor.FAIL,
        '[approvals]\nmode = "deny"\n': doctor.WARN,
        '[approvals]\nmode = "dashboard"\n[dashboard]\nenabled = true\nport = 1\n': doctor.OK,
    }
    for extra, want in cases.items():
        cfg = write_cfg(tmp_path, srv, extra + ask)
        got = by_name(doctor.run(cfg, tmp_path / "none.json"))["approvals"].status
        assert got == want, extra
    cfg = write_cfg(tmp_path, srv)
    assert "approvals" not in by_name(doctor.run(cfg, tmp_path / "none.json"))  # no ask rules, nothing to say


def test_monitor_mode_is_a_warning(tmp_path):
    p = tmp_path / "mcpguard.toml"
    p.write_text(f'mode = "monitor"\n[servers.a]\ncommand = {json.dumps(sys.executable)}\n',
                 encoding="utf-8")
    assert by_name(doctor.run(p, tmp_path / "none.json"))["mode"].status == doctor.WARN
