"""Features added for production use: self-test, export, readiness, profiles, split personal data."""

import csv
import io
import json

import pytest

from mcpguard import selftest
from mcpguard.cli import main
from mcpguard.config import DetectorConfig, load_config
from mcpguard.detect import Engine
from mcpguard.dlp import DlpConfig, PieceTracker
from mcpguard.export import cef_line, export, flatten

CARD = "4111111111111111"


def test_selftest_passes_with_defaults():
    results = selftest.run(Engine(DetectorConfig()), DlpConfig())
    assert [c.name for c, passed, _ in results if not passed] == []
    assert "All 12 checks passed" in selftest.render(results, "enforce")


def test_selftest_fails_when_protection_is_switched_off():
    weak = DlpConfig(enabled=False)
    results = selftest.run(Engine(DetectorConfig()), weak)
    failed = [c.kind for c, passed, _ in results if not passed]
    assert failed == ["dlp_result", "dlp_outbound"]
    assert "NOT STOPPED" in selftest.render(results, "enforce")


def test_selftest_command_exit_codes(tmp_path, capsys):
    cfg = tmp_path / "c.toml"
    assert main(["-c", str(cfg), "init", "--profile", "monitor"]) == 0
    assert main(["-c", str(cfg), "selftest"]) == 0
    assert "monitor" in capsys.readouterr().out
    cfg.write_text(cfg.read_text(encoding="utf-8").replace("[dlp]\nenabled = true", "[dlp]\nenabled = false"),
                   encoding="utf-8")
    assert main(["-c", str(cfg), "selftest"]) == 2


@pytest.mark.parametrize(("profile", "mode", "default", "block"), [
    ("balanced", "enforce", "allow", "high"), ("strict", "enforce", "ask", "medium"),
    ("monitor", "monitor", "allow", "high")])
def test_init_profiles(tmp_path, profile, mode, default, block):
    cfg = tmp_path / "c.toml"
    assert main(["-c", str(cfg), "init", "--profile", profile]) == 0
    loaded = load_config(cfg)
    assert (loaded.mode, loaded.policy.default, loaded.policy.block_severity) == (mode, default, block)


RECORD = {"ts": 1_700_000_000.0, "seq": 7, "event": "call.blocked", "client": "stdio", "tool": "mail__send",
          "reason": "secret | leaving\nvia =cmd", "hash": "h", "prev": "p", "sig": "s", "alg": "hmac-sha256",
          "findings": [{"rule": "taint.exfiltration", "severity": "critical", "message": "m", "where": "w"}]}


def test_export_formats():
    row = flatten(RECORD)
    assert (row["server"], row["severity"], row["rules"]) == ("mail", "critical", "taint.exfiltration")
    assert row["time"] == "2023-11-14T22:13:20Z"
    plain = json.loads(next(export([RECORD], "jsonl")))
    assert "hash" not in plain
    assert "hash" in json.loads(next(export([RECORD], "jsonl", raw=True)))
    header, line = list(export([RECORD], "csv"))
    assert header.split(",")[:3] == ["time", "seq", "event"]
    assert next(csv.reader(io.StringIO(line)))[5] == "mail__send"


def test_cef_is_well_formed_and_escaped():
    line = cef_line(RECORD)
    assert line.startswith("CEF:0|mcpguard|mcpguard|")
    assert line.split("|", 7)[7].startswith("rt=1700000000000 ")  # seven header fields, then the extension
    assert "|10|" in line
    assert "msg=secret | leaving via \\=cmd" in line
    assert "\n" not in line


def test_csv_export_defuses_spreadsheet_formulas():
    rec = dict(RECORD, reason="=HYPERLINK(\"http://evil\")")
    _, line = list(export([rec], "csv"))
    assert next(csv.reader(io.StringIO(line)))[-1].startswith("'=")


def test_export_command(tmp_path, capsys):
    from mcpguard.audit import AuditLog
    cfg = tmp_path / "c.toml"
    main(["-c", str(cfg), "init"])
    loaded = load_config(cfg)
    AuditLog(loaded.audit_path).write("call.blocked", tool="mail__send", reason="test")
    capsys.readouterr()
    assert main(["-c", str(cfg), "export", "--format", "cef"]) == 0
    assert "CEF:0|mcpguard" in capsys.readouterr().out
    out = tmp_path / "audit.csv"
    assert main(["-c", str(cfg), "export", "--format", "csv", "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8").splitlines()[1].count("mail__send") == 1


def test_t26_a_card_number_sent_in_pieces_is_caught():
    t = PieceTracker()
    values = {CARD: "crm__lookup"}
    flags = [t.check(text, values) for text in ("first part 4111", "then 1111", "and 1111", "last 1111")]
    assert flags[:3] == [None, None, None]
    assert flags[3] == (CARD, "crm__lookup")


def test_t26_one_call_with_separated_pieces_is_caught():
    assert PieceTracker().check("a: 41111111, b: 11111111", {CARD: "crm"})


def test_t26_last_four_digits_and_unrelated_numbers_stay_quiet():
    t = PieceTracker()
    values = {CARD: "crm", "123456789": "hr"}
    assert t.check("card ending 1111 was charged in 2024, order 88231", values) is None
    assert t.check("ssn pieces 1234 and 5678", values) is None  # short values must leave completely


def test_t26_gateway_blocks_split_card(make_config):
    import asyncio

    from mcpguard.gateway import Gateway
    gw = Gateway(load_config(make_config()))
    gw.pii_seen[CARD] = "crm__lookup"

    async def go():
        return [gw._dlp_outbound("mail__send", {"body": part}, egress=True)
                for part in ("4111 and", "1111 and", "1111 and", "1111")]
    found = asyncio.run(go())
    assert not any(found[:3])
    assert [f.rule for f in found[3]] == ["dlp.tracked_pii"]
    assert CARD not in found[3][0].message


def test_readyz_reports_servers_that_are_down(make_config):
    import asyncio
    from types import SimpleNamespace

    from mcpguard.gateway import Gateway
    from mcpguard.httpserve import HttpFrontend, Request
    gw = Gateway(load_config(make_config()))
    front = HttpFrontend(gw, "127.0.0.1", 0, "/mcp")

    def ready():
        return asyncio.run(front._route(Request("GET", "/readyz", {}, b"")))[:2]
    gw.servers = {"srv": SimpleNamespace(status="up"), "mail": SimpleNamespace(status="failed")}
    assert ready() == (503, {"ready": False, "servers_down": ["mail"]})
    gw.servers["mail"].status = "up"
    assert ready() == (200, {"ready": True, "servers_down": []})


def test_harmless_session_variables_reach_servers():
    from mcpguard.upstream import looks_like_secret_env as secret
    assert not secret("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
    assert not secret("XDG_SESSION_TYPE", "wayland")
    assert secret("SESSION_TOKEN", "x")


# ---------------------------------------------------------------- sandbox, least privilege, approvals

SANDBOXED = """
[servers.files]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
env = { API_KEY = "abc" }
allowed_paths = ["C:/Users/me/project"]
allowed_hosts = ["api.github.com", "*.example.com"]

[servers.files.sandbox]
image = "node:22-slim"
mounts = [{ host = "C:/Users/me/project", container = "/data" },
          { host = "/tmp/out", container = "/out", write = true }]
"""


def _cfg(tmp_path, text):
    p = tmp_path / "c.toml"
    p.write_text(text, encoding="utf-8")
    return load_config(p)


def test_sandbox_wraps_the_server_in_a_locked_down_container(tmp_path):
    cfg = _cfg(tmp_path, SANDBOXED)
    assert cfg.warnings == []
    spec = cfg.servers[0]
    runtime, args = spec.sandbox.wrap(spec.command, spec.args, list(spec.env))
    assert runtime == "docker"
    line = " ".join(args)
    for needed in ("--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "--pids-limit 256",
                   "type=bind,source=C:/Users/me/project,target=/data,readonly",
                   "type=bind,source=/tmp/out,target=/out -e API_KEY"):
        assert needed in line, needed
    assert "abc" not in line  # the value travels in the environment, not on the command line
    assert args[-5:] == ["node:22-slim", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]


def test_sandbox_network_is_opt_in_and_changes_restart_the_server(tmp_path):
    a = _cfg(tmp_path, SANDBOXED).servers[0]
    b = _cfg(tmp_path, SANDBOXED.replace('image = "node:22-slim"', 'image = "node:22-slim"\nnetwork = true')).servers[0]
    assert "--network" not in b.sandbox.wrap("x", [], [])[1]
    assert a.key() != b.key()


@pytest.mark.parametrize(("bad", "message"), [
    ('image = "--privileged"', "image"), ('image = "x"\nruntime = "sudo"', "runtime"),
    ('image = "x"\nmounts = [{ host = "/a,b", container = "/d" }]', "commas"),
    ('image = "x"\nmounts = [{ host = "/a", container = "d" }]', "start with /"),
    ('image = "x"\nprivileged = true', "unknown key"), ('image = "x"\nmemory = "1g --privileged"', "memory")])
def test_sandbox_settings_are_validated(tmp_path, bad, message):
    from mcpguard.config import ConfigError
    with pytest.raises(ConfigError, match=message):
        _cfg(tmp_path, f'[servers.s]\ncommand = "python"\n[servers.s.sandbox]\n{bad}\n')


def test_sandboxed_server_starts_through_the_runtime(tmp_path, monkeypatch):
    import asyncio

    from mcpguard.upstream import make_upstream
    spec = _cfg(tmp_path, SANDBOXED).servers[0]
    up = make_upstream(spec)
    seen = {}

    async def fake_exec(command, *args, **kw):
        seen.update(command=command, args=args, env=kw["env"])
        raise FileNotFoundError("stop here")
    monkeypatch.setattr("mcpguard.upstream.shutil.which", lambda name, path=None: f"/usr/bin/{name}")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    with pytest.raises(FileNotFoundError):
        asyncio.run(up.start())
    assert seen["command"] == "/usr/bin/docker"
    assert seen["args"][0] == "run"
    assert seen["env"]["API_KEY"] == "abc"


PATHS, HOSTS = ["C:/Users/me/project", "/srv/data"], ["api.github.com", "*.example.com"]


@pytest.mark.parametrize("args", [
    {"path": "C:/Users/me/project/notes.txt"}, {"path": "c:\\users\\ME\\project\\sub\\a.txt"},
    {"path": "/srv/data"}, {"path": "notes/today.md"}, {"url": "https://api.github.com/repos"},
    {"url": "https://docs.example.com/x"}, {"text": "see ../README for details, or /etc is where configs live"},
    {"n": 5, "flags": ["a", "b"]}])
def test_least_privilege_allows_what_is_in_scope(args):
    from mcpguard.policy import scope_violation
    assert scope_violation(args, PATHS, HOSTS) == ""


@pytest.mark.parametrize(("args", "why"), [
    ({"path": "C:/Users/me/.ssh/id_rsa"}, "allowed_paths"), ({"path": "/etc/passwd"}, "allowed_paths"),
    ({"path": "C:/Users/me/project/../.aws/credentials"}, "allowed_paths"),
    ({"path": "C:/Users/me/project-secrets/x"}, "allowed_paths"), ({"path": "~/.ssh/id_rsa"}, "allowed_paths"),
    ({"path": "file:///etc/shadow"}, "allowed_paths"), ({"files": [{"p": "\\\\server\\share\\x"}]}, "allowed_paths"),
    ({"path": "../../etc/passwd"}, "climbs"), ({"url": "https://evil.test/upload"}, "allowed_hosts"),
    ({"url": "https://api.github.com.evil.test/"}, "allowed_hosts"),
    ({"url": "https://example.com@evil.test/"}, "read differently")])
def test_least_privilege_refuses_what_is_out_of_scope(args, why):
    from mcpguard.policy import scope_violation
    assert why in scope_violation(args, PATHS, HOSTS)


def test_ask_sensitive_asks_for_tools_that_write_run_or_send():
    from mcpguard.policy import Policy, sensitive_name
    assert all(sensitive_name(n) for n in ("write_file", "sendEmail", "run-command", "delete_repo", "git_push"))
    assert not any(sensitive_name(n) for n in ("read_file", "list_directory", "get_weather", "search", "prune_cache"))
    on = Policy.from_dict({"ask_sensitive": True, "rules": [{"match": "files/write_log", "action": "allow"}]})
    assert on.evaluate("files/write_file").action == "ask"
    assert on.evaluate("files/read_file").action == "allow"
    assert on.evaluate("files/write_log").action == "allow"  # an explicit rule is the owner's decision
    assert Policy.from_dict({}).evaluate("files/write_file").action == "allow"  # off unless asked for


def test_gateway_enforces_scope_and_asks_for_sensitive_tools(make_config):
    import asyncio

    from mcpguard.gateway import Gateway
    cfg = load_config(make_config())
    cfg.servers[0].allowed_paths = ["/srv/data"]
    cfg.policy.ask_sensitive = True
    asked = []

    async def approver(tool, args, reason):
        asked.append((tool, reason))
        return False

    async def go():
        gw = Gateway(cfg, approver=approver)
        await gw.start()
        try:
            call = lambda rid, name, a: gw.handle({"jsonrpc": "2.0", "id": rid, "method": "tools/call",  # noqa: E731
                                                  "params": {"name": name, "arguments": a}})
            outside = await call(1, "srv__echo", {"text": "/etc/passwd"})
            inside = await call(2, "srv__echo", {"text": "/srv/data/a.txt"})
            sensitive = await call(3, "srv__send_email", {"body": "hi"})
            return outside, inside, sensitive
        finally:
            await gw.stop()
    outside, inside, sensitive = asyncio.run(go())
    assert "allowed_paths" in outside["result"]["content"][0]["text"]
    assert inside["result"]["content"][0]["text"] == "/srv/data/a.txt"
    assert "approval was denied" in sensitive["result"]["content"][0]["text"]
    assert asked
    assert asked[0][0] == "srv__send_email"
    assert "ask_sensitive" in asked[0][1]


def test_check_points_out_wide_open_settings(tmp_path, capsys):
    cfg = tmp_path / "c.toml"
    main(["-c", str(cfg), "init"])
    cfg.write_text(cfg.read_text(encoding="utf-8").replace('mode = "dashboard"', 'mode = "allow"'), encoding="utf-8")
    capsys.readouterr()
    assert main(["-c", str(cfg), "check"]) == 0
    out = capsys.readouterr().out
    assert "grants every approval request automatically" in out
    assert "runs unsandboxed" in out
    main(["-c", str(cfg), "init", "--force", "--profile", "strict"])
    assert load_config(cfg).policy.ask_sensitive is True
