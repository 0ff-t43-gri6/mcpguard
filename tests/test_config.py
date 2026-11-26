import pytest

from mcpguard.config import DEFAULT_CONFIG, ConfigError, load_config
from mcpguard.policy import Policy


def _load(tmp_path, text):
    p = tmp_path / "c.toml"
    p.write_text(text, encoding="utf-8")
    return load_config(p)


def test_default_config_is_valid(tmp_path):
    cfg = _load(tmp_path, DEFAULT_CONFIG)
    assert cfg.detectors.rules[0]["pattern"] == r"\bcorp\.internal\b"
    assert cfg.approval_mode == "dashboard"


@pytest.mark.parametrize(("text", "message"), [
    ('mode = "loud"', "mode must be one of"),
    ('[policy]\nblock_severity = "hgih"', "policy.block_severity"),
    ('[[policy.rules]]\nmatch = "*"\naction = "maybe"', "policy.rules[0].action"),
    ('[[detectors.rules]]\npattern = "("', "not a valid regular expression"),
    ('[detectors]\nplugins = ["no.such.module:x"]', "detectors:"),
    ('[servers.a]\nurl = "http://example.com/mcp"', "must use https://"),
    ('[servers.a]\ncommand = "x"\nurl = "https://x"', "exactly one of"),
    ('[servers."a b"]\ncommand = "x"', "letters, digits"),
    ('[servers.a__b]\ncommand = "x"', "cannot contain '__'"),
    ('[dashboard]\nport = 99999', "dashboard.port"),
    ('[policy]\nrate_limit_per_minute = "lots"', "must be int"),
    ("this is = = not toml", "c.toml"),
])
def test_invalid_configs_are_rejected_with_a_clear_message(tmp_path, text, message):
    with pytest.raises(ConfigError, match=None) as e:
        _load(tmp_path, text)
    assert message in str(e.value)


def test_policy_first_match_args_and_budget():
    p = Policy.from_dict({"rules": [
        {"match": "fs/write_file", "args": {"path": "/etc/*"}, "action": "deny"},
        {"match": "*/rm*", "action": "deny"},
    ], "rate_limit_per_minute": 2})
    assert not p.visible("a/rm_all")
    assert p.visible("fs/write_file")                      # conditional rules don't hide
    assert p.evaluate("fs/write_file", {"path": "/etc/hosts"}).action == "deny"
    assert p.evaluate("fs/write_file", {"path": "/tmp/x"}).action == "allow"
    p.record_call("a/ls", 0)
    p.record_call("a/ls", 1)
    assert p.check_budget("a/ls", 2) is not None
    assert p.check_budget("a/ls", 100) is None


def test_non_utf8_config_is_a_config_error(tmp_path):
    # A file saved in a Windows code page (0xa0 is a cp1252 non-breaking space).
    p = tmp_path / "mcpguard.toml"
    p.write_bytes(b"[servers]\xa0\n")
    with pytest.raises(ConfigError, match="not valid UTF-8"):
        load_config(p)


def test_directory_as_config_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="directory"):
        load_config(tmp_path)


def test_config_with_non_ascii_text_loads(tmp_path):
    p = tmp_path / "mcpguard.toml"
    p.write_text('# café — 日本語\n[servers.a]\ncommand = "x"\n', encoding="utf-8")
    load_config(p)


def test_starter_policy_decisions(tmp_path):
    policy = _load(tmp_path, DEFAULT_CONFIG).policy
    cases = {
        ("files/move_file", None): "ask",
        ("files/delete_file", None): "ask",
        ("db/drop_table", None): "ask",
        ("shell/exec_command", None): "deny",
        ("files/read_text_file", None): "allow",
        ("files/write_file", "/etc/passwd"): "deny",
        ("files/write_file", "C:\\Windows\\System32\\drivers\\etc\\hosts"): "deny",
        ("files/write_file", "c:/windows/win.ini"): "deny",
        ("files/write_file", "C:\\Users\\me\\sandbox\\note.txt"): "allow",
    }
    for (tool, path), want in cases.items():
        got = policy.evaluate(tool, {"path": path} if path else {}).action
        assert got == want, (tool, path, got)


def test_unknown_sections_and_keys_are_errors_with_suggestions(tmp_path):
    text = ('mode = "enforce"\n[dashbaord]\nenabled = true\n[audit]\nrotate_byts = 5\n'
            '[servers.a]\ncommand = "x"\ntimout_seconds = 3\nenv = { ANY_NAME = "ok" }\n'
            '[clients.bot]\ntoken_env = "T"\n[[policy.rules]]\nmatch = "a/*"\naction = "deny"\nclients = ["bot"]\n'
            '[detectors.severity_overrides]\n"secret.jwt" = "medium"\n')
    with pytest.raises(ConfigError) as e:
        _load(tmp_path, text)
    msg = str(e.value)
    assert "unknown section [dashbaord] (did you mean 'dashboard'?)" in msg
    assert "unknown key 'rotate_byts' in [audit] (did you mean 'rotate_bytes'?)" in msg
    assert "unknown key 'timout_seconds' in [servers.*] (did you mean 'timeout_seconds'?)" in msg


@pytest.mark.parametrize("typo", ['[policy]\ndefualt = "deny"\n', '[pins]\nfirst_see = "approve"\n',
                                  '[audit]\non_tamper_mode = "block"\n', 'mod = "enforce"\n'])
def test_a_typo_in_a_security_setting_stops_the_config_loading(tmp_path, typo):
    with pytest.raises(ConfigError, match="unknown"):
        _load(tmp_path, typo)


def test_starter_config_and_every_key_the_loader_reads_are_known(tmp_path):
    import re
    from pathlib import Path

    import mcpguard.config as config_module
    from mcpguard.config import _known_keys
    assert _load(tmp_path, DEFAULT_CONFIG).warnings == []
    sections = _known_keys()
    known = set().union(*sections.values()) | {part for k in sections for part in k.split(".")}
    src = Path(config_module.__file__).read_text(encoding="utf-8")
    read = set(re.findall(r'_get\([^,]+,\s*"(\w+)"', src)) | set(re.findall(r'\.get\("(\w+)"', src))
    missing = read - known - {"rules", "iocs", "suppress", "severity_overrides"}
    assert not missing, f"document these in DEFAULT_CONFIG: {sorted(missing)}"
