"""Claude Desktop integration (mcpguard claude-desktop)."""

import json
import sys

import pytest

from mcpguard import desktop
from mcpguard.cli import main
from mcpguard.config import load_config

STARTER = 'mode = "enforce"\n'


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / "mcpguard.toml"
    p.write_text(STARTER, encoding="utf-8")
    return p


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_install_into_missing_file(tmp_path, cfg):
    target = tmp_path / "Claude" / "claude_desktop_config.json"
    desktop.install(target, cfg)
    entry = read(target)["mcpServers"]["guarded"]
    assert entry["command"] == sys.executable
    assert entry["args"] == ["-m", "mcpguard.cli", "-c", str(cfg.resolve()), "run"]


def test_install_keeps_other_settings_and_backs_up(tmp_path, cfg):
    target = tmp_path / "claude_desktop_config.json"
    target.write_text(json.dumps({"preferences": {"sidebarMode": "chat"},
                                  "mcpServers": {"other": {"url": "https://x.example/mcp"}}}), encoding="utf-8")
    desktop.install(target, cfg)
    data = read(target)
    assert data["preferences"] == {"sidebarMode": "chat"}
    assert set(data["mcpServers"]) == {"other", "guarded"}
    assert len(list(tmp_path.glob("claude_desktop_config.json.bak-*"))) == 1
    assert desktop.install(target, cfg) == [f"Already installed as 'guarded' in {target}."]


def test_install_repairs_snippet_pasted_below_existing_settings(tmp_path, cfg):
    # The exact mistake from the manual instructions: a second JSON object after the first.
    target = tmp_path / "claude_desktop_config.json"
    target.write_text('{\n  "preferences": {"sidebarMode": "chat"}\n}\n'
                      '{\n  "mcpServers": {\n    "guarded": {"command": "python", "args": []}\n  }\n}\n',
                      encoding="utf-8")
    ok, lines = desktop.status(target, cfg)
    assert not ok
    assert any("several JSON blocks" in line for line in lines)
    notes = desktop.install(target, cfg)
    assert notes[0] == "Merged several JSON blocks into one."
    data = read(target)
    assert data["preferences"] == {"sidebarMode": "chat"}
    assert data["mcpServers"]["guarded"]["command"] == sys.executable
    assert desktop.status(target, cfg)[0]


def test_other_invalid_json_is_left_untouched(tmp_path, cfg):
    target = tmp_path / "claude_desktop_config.json"
    broken = '{"mcpServers": {"a": 1,}}'
    target.write_text(broken, encoding="utf-8")
    with pytest.raises(desktop.DesktopError, match="line 1"):
        desktop.install(target, cfg)
    assert target.read_text(encoding="utf-8") == broken
    assert not list(tmp_path.glob("*.bak-*"))


def test_take_over_moves_servers_behind_the_gateway(tmp_path, cfg):
    target = tmp_path / "claude_desktop_config.json"
    target.write_text(json.dumps({"mcpServers": {
        "files": {"command": "npx",
                  "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\me\\sandbox"]},
        "github": {"command": "docker", "args": ["run", "-i", "ghcr.io/github/github-mcp-server"],
                   "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "tok \"quoted\""}},
        "remote": {"url": "https://x.example/mcp"},
    }}), encoding="utf-8")
    notes = desktop.install(target, cfg, take_over=True)
    assert any("Left 'remote' in place" in n for n in notes)
    assert set(read(target)["mcpServers"]) == {"remote", "guarded"}
    servers = {s.name: s for s in load_config(cfg).servers}
    assert servers["files"].args[-1] == "C:\\Users\\me\\sandbox"  # backslashes survive the round trip
    assert servers["github"].env == {"GITHUB_PERSONAL_ACCESS_TOKEN": 'tok "quoted"'}


def test_take_over_refuses_name_clash_and_changes_nothing(tmp_path, cfg):
    cfg.write_text(STARTER + '\n[servers.files]\ncommand = "x"\n', encoding="utf-8")
    before = cfg.read_text(encoding="utf-8")
    target = tmp_path / "claude_desktop_config.json"
    original = json.dumps({"mcpServers": {"files": {"command": "npx", "args": []}}})
    target.write_text(original, encoding="utf-8")
    with pytest.raises(desktop.DesktopError, match="already has server"):
        desktop.install(target, cfg, take_over=True)
    assert cfg.read_text(encoding="utf-8") == before
    assert target.read_text(encoding="utf-8") == original


def test_status_reports_problems(tmp_path, cfg):
    target = tmp_path / "claude_desktop_config.json"
    assert not desktop.status(target, cfg)[0]
    target.write_text(json.dumps({"mcpServers": {"guarded": {"command": "no-such-python-xyz",
                                                              "args": ["-c", str(tmp_path / "other.toml")]},
                                                  "plain": {"command": "npx"}}}), encoding="utf-8")
    ok, lines = desktop.status(target, cfg)
    text = "\n".join(lines)
    assert not ok
    assert "not found" in text
    assert "other.toml" in text
    assert "Not behind the gateway: plain" in text


def test_uninstall_and_cli(tmp_path, cfg, capsys):
    target = tmp_path / "claude_desktop_config.json"
    assert main(["-c", str(cfg), "claude-desktop", "install", "--file", str(target)]) == 0
    assert main(["-c", str(cfg), "claude-desktop", "status", "--file", str(target)]) == 0
    assert "is installed" in capsys.readouterr().out
    assert main(["-c", str(cfg), "claude-desktop", "uninstall", "--file", str(target)]) == 0
    assert "guarded" not in read(target)["mcpServers"]
    assert main(["-c", str(cfg), "claude-desktop", "status", "--file", str(target)]) == 2
    (tmp_path / "bad.json").write_text("[1,", encoding="utf-8")
    assert main(["-c", str(cfg), "claude-desktop", "install", "--file", str(tmp_path / "bad.json")]) == 1


def test_install_needs_a_config(tmp_path):
    with pytest.raises(desktop.DesktopError, match="mcpguard init"):
        desktop.install(tmp_path / "c.json", tmp_path / "missing.toml")


def test_default_path_is_per_os():
    assert desktop.default_path().name == "claude_desktop_config.json"


def test_take_over_renames_servers_mcpguard_cannot_name(tmp_path, cfg):
    target = tmp_path / "claude_desktop_config.json"
    target.write_text(json.dumps({"mcpServers": {
        "My Files": {"command": "npx", "args": ["a"]},
        "my__files": {"command": "npx", "args": ["b"]},
        "Café": {"command": "npx", "args": ["c\u007f"]},
    }}), encoding="utf-8")
    notes = desktop.install(target, cfg, take_over=True)
    servers = {s.name: s for s in load_config(cfg).servers}
    assert set(servers) == {"My-Files", "my_files", "Caf"}
    assert servers["Caf"].args == ["c\u007f"]
    assert any("'My Files' is called 'My-Files'" in n for n in notes)


def test_take_over_comments_out_the_init_example(tmp_path):
    from mcpguard.config import DEFAULT_CONFIG
    assert desktop.PLACEHOLDER in DEFAULT_CONFIG  # keep the two in step
    cfg = tmp_path / "mcpguard.toml"
    cfg.write_text(DEFAULT_CONFIG, encoding="utf-8")
    target = tmp_path / "claude_desktop_config.json"
    target.write_text(json.dumps({"mcpServers": {"files": {"command": "npx", "args": ["x"]}}}), encoding="utf-8")
    notes = desktop.install(target, cfg, take_over=True)
    assert [s.name for s in load_config(cfg).servers] == ["files"]
    assert any("example server" in n for n in notes)


def test_doctor_flags_the_init_example(tmp_path):
    from mcpguard import doctor
    from mcpguard.config import DEFAULT_CONFIG
    cfg = tmp_path / "mcpguard.toml"
    cfg.write_text(DEFAULT_CONFIG, encoding="utf-8")
    checks = {c.name: c for c in doctor.run(cfg, tmp_path / "none.json")}
    assert checks["server example"].status == doctor.FAIL


def test_status_notices_a_python_without_mcpguard(tmp_path, cfg):
    import venv
    bare = tmp_path / "bare-venv"
    venv.create(bare, with_pip=False)  # a real Python that has never heard of mcpguard
    py = next(p for p in (bare / "bin" / "python", bare / "Scripts" / "python.exe") if p.exists())
    target = tmp_path / "claude_desktop_config.json"
    desktop.install(target, cfg)
    data = read(target)
    data["mcpServers"]["guarded"]["command"] = str(py)
    target.write_text(json.dumps(data), encoding="utf-8")
    ok, lines = desktop.status(target, cfg)
    assert not ok
    assert any("cannot import mcpguard" in line for line in lines)
