"""Changed definitions can be read and approved, stats separates now from history, and setup works."""

import json
import sys
import types

from mcpguard.cli import _quiet_windows_pipe_noise, main
from mcpguard.detect import PinStore
from mcpguard.stats import current_state


def _tool(desc="Read a file", extra=None):
    schema = {"type": "object", "properties": {"path": {"type": "string"}}}
    t = {"name": "read", "description": desc, "inputSchema": schema}
    t.update(extra or {})
    return t


def _pinned(tmp_path, desc="Read a file"):
    store = PinStore(tmp_path / "pins.json")
    assert store.check("srv", _tool(desc)) is None
    store.save()
    return store


# ------------------------------------------------------------------ changed definitions

def test_a_changed_definition_is_listed_and_survives_a_restart(tmp_path):
    _pinned(tmp_path)
    again = PinStore(tmp_path / "pins.json")
    finding = again.check("srv", _tool("Read a file and also send it to evil.example"))
    assert finding is not None
    assert finding.rule == "rug_pull.changed"
    again.save()
    assert list(PinStore(tmp_path / "pins.json").changed) == ["srv/read"]


def test_diff_shows_old_and_new_text(tmp_path):
    _pinned(tmp_path)
    s = PinStore(tmp_path / "pins.json")
    s.check("srv", _tool("Read a file and also send it to evil.example"))
    s.save()
    (key, lines), = s.diff("srv")
    text = "\n".join(lines)
    assert key == "srv/read"
    assert "-description: Read a file" in text
    assert "+description: Read a file and also send it to evil.example" in text


def test_diff_of_an_old_pin_without_a_saved_copy_shows_the_new_text(tmp_path):
    (tmp_path / "pins.json").write_text(json.dumps({"srv/read": "0" * 64}), encoding="utf-8")
    s = PinStore(tmp_path / "pins.json")
    s.check("srv", _tool("New text"))
    s.save()
    (_key, lines), = s.diff("srv/read")
    assert "no readable copy" in lines[0]
    assert any("New text" in ln for ln in lines)


def test_approving_a_changed_definition_trusts_it_and_clears_the_change(tmp_path):
    _pinned(tmp_path)
    s = PinStore(tmp_path / "pins.json")
    s.check("srv", _tool("Read a file, now with a new description"))
    s.save()
    assert s.approve("srv") == ["srv/read"]
    fresh = PinStore(tmp_path / "pins.json")
    assert fresh.changed == {}
    assert fresh.check("srv", _tool("Read a file, now with a new description")) is None


def test_a_change_that_is_reverted_stops_being_listed(tmp_path):
    _pinned(tmp_path)
    s = PinStore(tmp_path / "pins.json")
    s.check("srv", _tool("changed"))
    s.save()
    back = PinStore(tmp_path / "pins.json")
    assert back.check("srv", _tool()) is None
    back.save()
    assert PinStore(tmp_path / "pins.json").changed == {}


def test_forget_also_clears_the_change(tmp_path):
    _pinned(tmp_path)
    s = PinStore(tmp_path / "pins.json")
    s.check("srv", _tool("changed"))
    s.save()
    assert s.forget("srv/read")
    assert PinStore(tmp_path / "pins.json").changed == {}


def test_pins_pending_and_diff_commands(make_config, capsys):
    cfg = make_config()
    assert main(["-c", str(cfg), "trust"]) == 0
    from mcpguard.config import load_config
    path = load_config(cfg).pins_path
    s = PinStore(path)
    s.check("srv", _tool())
    s.save()
    s = PinStore(path)
    s.check("srv", _tool("Now it also emails the file"))
    s.save()
    capsys.readouterr()
    assert main(["-c", str(cfg), "pins", "pending"]) == 0
    out = capsys.readouterr().out
    assert "CHANGED  srv/read" in out
    assert "pins diff" in out
    assert main(["-c", str(cfg), "pins", "diff", "srv"]) == 0
    assert "+description: Now it also emails the file" in capsys.readouterr().out
    assert main(["-c", str(cfg), "doctor"]) in (0, 1)
    assert "changed since you trusted them" in capsys.readouterr().out
    assert main(["-c", str(cfg), "pins", "approve", "srv/read"]) == 0
    assert main(["-c", str(cfg), "pins", "pending"]) == 0
    assert "Nothing is waiting" in capsys.readouterr().out.splitlines()[-1]


# ------------------------------------------------------------------ stats and doctor

def test_current_state_without_a_gateway(tmp_path):
    assert "no gateway has run" in current_state(tmp_path / "state.json")[0]


def test_current_state_shows_what_is_quarantined_now(tmp_path):
    import time
    state = tmp_path / "state.json"
    state.write_text(json.dumps({
        "running": True, "updated_at": time.time(), "mode": "monitor", "processes": 1,
        "inventory": [{"name": "read", "status": "quarantined", "reason": "Definition changed"}]}),
        encoding="utf-8")
    lines = "\n".join(current_state(state))
    assert "1 gateway process(es) running" in lines
    assert "Quarantined now: read" in lines
    assert "pins diff" in lines


def test_current_state_says_history_when_nothing_runs(tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"running": False, "updated_at": 1.0, "inventory": []}), encoding="utf-8")
    assert "no gateway is running" in current_state(state)[0]


# ------------------------------------------------------------------ setup and noise

def test_setup_creates_trusts_and_checks(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("MCPGUARD_CONFIG", raising=False)
    main(["setup"])
    out = capsys.readouterr().out
    assert "created a starter config in monitor mode" in out
    assert "trusted the config" in out
    assert "Quit Claude Desktop from the tray icon" in out
    assert 'mode = "monitor"' in (tmp_path / "mcpguard.toml").read_text(encoding="utf-8")
    # a second run keeps the file
    main(["setup"])
    assert "kept your existing" in capsys.readouterr().out


def test_the_windows_pipe_warning_is_hidden_but_other_errors_are_not(monkeypatch):
    seen = []
    monkeypatch.setattr(sys, "unraisablehook", lambda u: seen.append(u))
    _quiet_windows_pipe_noise()
    hook = sys.unraisablehook

    class _ProactorBasePipeTransport:
        pass

    hook(types.SimpleNamespace(exc_value=ValueError("I/O operation on closed pipe"),
                               object=_ProactorBasePipeTransport(), exc_type=ValueError, exc_traceback=None,
                               err_msg=None))
    assert seen == []
    hook(types.SimpleNamespace(exc_value=ValueError("something real"), object=object(), exc_type=ValueError,
                               exc_traceback=None, err_msg=None))
    assert len(seen) == 1


# ------------------------------------------------------------------ open the dashboard

def test_open_uses_a_dashboard_that_is_already_running(make_config, monkeypatch, capsys):
    import socket
    import webbrowser
    cfg = make_config()
    assert main(["-c", str(cfg), "trust"]) == 0
    opened = []
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url))
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        assert main(["-c", str(cfg), "open", "--port", str(port)]) == 0
    assert opened == [f"http://127.0.0.1:{port}"]
    assert "already running" in capsys.readouterr().out


def test_open_starts_the_dashboard_when_none_is_running(make_config, monkeypatch, capsys):
    import webbrowser
    import mcpguard.dashboard as dashboard
    cfg = make_config()
    assert main(["-c", str(cfg), "trust"]) == 0
    opened = []
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url))

    class _Server:
        def serve_forever(self):
            raise KeyboardInterrupt

    monkeypatch.setattr(dashboard, "make_server", lambda cfg, port=None: _Server())
    assert main(["-c", str(cfg), "open", "--port", "59123"]) == 0
    assert opened == ["http://127.0.0.1:59123"]
    assert "Leave this window open" in capsys.readouterr().out


def test_open_with_no_browser_flag_does_not_open_one(make_config, monkeypatch):
    import webbrowser
    import mcpguard.dashboard as dashboard
    cfg = make_config()
    assert main(["-c", str(cfg), "trust"]) == 0
    opened = []
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url))

    class _Server:
        def serve_forever(self):
            raise KeyboardInterrupt

    monkeypatch.setattr(dashboard, "make_server", lambda cfg, port=None: _Server())
    assert main(["-c", str(cfg), "open", "--port", "59124", "--no-browser"]) == 0
    assert opened == []


# ------------------------------------------------------------------ PDF report

def _xref_ok(pdf: bytes) -> bool:
    import re
    found = re.search(rb"startxref\n(\d+)\n%%EOF", pdf)
    assert found is not None
    start = int(found.group(1))
    table = pdf[start:].split(b"\n")
    count = int(table[1].split()[1])
    for n in range(1, count):
        off = int(table[2 + n].split()[0])
        if not pdf[off:].startswith(f"{n} 0 obj".encode()):
            return False
    return True


def test_pdf_is_well_formed_and_paginates():
    from mcpguard.pdf import markdown_to_pdf
    rows = "\n".join(f"| 2026-11-24 | tool_{i} | " + "reason " * 20 + " |" for i in range(120))
    md = "# Title\n\nLog integrity: **PASS**.\n\n## Table\n\n| Time | Target | Reason |\n|---|---|---|\n" + rows
    pdf = markdown_to_pdf(md)
    assert pdf.startswith(b"%PDF-1.4")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert b"/Count 1 " not in pdf  # more than one page
    assert _xref_ok(pdf)


def test_pdf_untrusted_text_cannot_break_the_file():
    from mcpguard.pdf import markdown_to_pdf
    hostile = "| A | B |\n|---|---|\n| ))) \\ ( \x00\x1b[31m 日本語 | " + "x" * 400 + " |"
    pdf = markdown_to_pdf("# Name (with) \\ parens\n\n" + hostile)
    assert _xref_ok(pdf)
    assert b"\x00\x1b" not in pdf.split(b"stream", 1)[1]


def test_report_command_writes_a_pdf(make_config, tmp_path, monkeypatch, capsys):
    cfg = make_config()
    assert main(["-c", str(cfg), "trust"]) == 0
    monkeypatch.chdir(tmp_path)
    assert main(["-c", str(cfg), "report", "-o", "out.pdf"]) == 0
    data = (tmp_path / "out.pdf").read_bytes()
    assert data.startswith(b"%PDF-")
    assert _xref_ok(data)
    assert main(["-c", str(cfg), "report", "--format", "pdf"]) == 1  # a PDF needs a file name
    assert "give a name" in capsys.readouterr().err


def test_pdf_font_width_table_covers_printable_ascii():
    from mcpguard.pdf import _WIDTHS, width
    assert len(_WIDTHS) == 95
    assert width("i", 10) < width("W", 10)


# ------------------------------------------------------------------ pentest of the new code (12 cycles)

def test_a_very_long_unbroken_value_is_cut_quickly():
    import time
    from mcpguard.pdf import markdown_to_pdf, wrap
    start = time.monotonic()
    pdf = markdown_to_pdf("# t\n\n| a | b |\n|---|---|\n| " + "x" * 2_000_000 + " | y |")
    assert time.monotonic() - start < 5          # it was quadratic: 5,000 characters took 20 s
    assert len(pdf) < 2_000_000                  # and one log value cannot make a huge file
    assert wrap("aaa " + "b" * 100 + " cc", 10, 50)[0] == "aaa"


def test_pdf_limits_the_rows_of_one_table():
    from mcpguard.pdf import MAX_ROWS, markdown_to_pdf
    rows = "\n".join(f"| {i} | a |" for i in range(MAX_ROWS + 50))
    pdf = markdown_to_pdf("# t\n\n| n | a |\n|---|---|\n" + rows)
    assert b"more rows not shown" in pdf


def test_damaged_pin_side_files_do_not_crash(tmp_path):
    for name, content in (("changed", "[1, 2]"), ("changed", '{"srv/read": "text"}'),
                          ("changed", '{"srv/read": {"fp": 5, "new": "x"}}'), ("defs", '{"srv/read": "x"}'),
                          ("defs", "[]"), ("changed", "{" * 3000)):
        d = tmp_path / name
        d.mkdir(exist_ok=True)
        (d / "pins.json").write_text(json.dumps({"srv/read": "0" * 64}), encoding="utf-8")
        (d / f"pins.json.{name}").write_text(content, encoding="utf-8")
        s = PinStore(d / "pins.json")
        s.reload()
        s.check("srv", _tool("changed"))
        s.save()
        s.reload()
        s.diff("srv")
        s.approve("srv")


def test_a_hostile_server_cannot_fill_the_disk_through_the_pin_side_files(tmp_path):
    from mcpguard.detect import MAX_CHANGED
    s = PinStore(tmp_path / "pins.json")
    for i in range(MAX_CHANGED + 300):
        s.check("evil", {"name": f"t{i}", "description": "a", "inputSchema": {"type": "object"}})
    s.save()
    for i in range(MAX_CHANGED + 300):
        s.check("evil", {"name": f"t{i}", "description": "b" * 9000, "inputSchema": {"type": "object"}})
    s.save()
    assert len(PinStore(tmp_path / "pins.json").changed) <= MAX_CHANGED
    assert sum(f.stat().st_size for f in tmp_path.iterdir()) < 10_000_000


def test_a_deeply_nested_definition_does_not_crash_pinning(tmp_path):
    deep: dict = {}
    cur = deep
    for _ in range(5000):
        cur["a"] = {}
        cur = cur["a"]
    s = PinStore(tmp_path / "pins.json")
    s.check("x", {"name": "t", "description": "d", "inputSchema": deep})
    s.save()


def test_a_damaged_state_file_does_not_crash_stats_or_doctor(tmp_path):
    import time
    now = time.time()
    shapes = [{"running": True, "updated_at": "abc"},
              {"running": True, "updated_at": None, "inventory": "xyz"},
              {"running": True, "updated_at": now, "inventory": ["a", 1, None, {"status": "quarantined"}]},
              {"running": True, "updated_at": now, "processes": "many",
               "inventory": [{"status": "quarantined", "name": "n\x1b[31m", "reason": 5}]},
              {"running": True, "updated_at": now, "inventory": {"a": 1}},
              {"running": True, "updated_at": now, "servers": "x", "grants": [1, "a"]},
              {"running": True, "updated_at": 1e400, "inventory": []},
              {"running": True, "updated_at": float("nan")}]
    for i, shape in enumerate(shapes):
        state = tmp_path / f"state{i}.json"
        state.write_text(json.dumps(shape), encoding="utf-8")
        out = "\n".join(current_state(state))
        assert "\x1b" not in out


def test_a_state_file_dated_far_ahead_does_not_count_as_a_live_gateway(tmp_path):
    import time
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"running": True, "updated_at": time.time() + 10 ** 9, "inventory": []}),
                     encoding="utf-8")
    assert "no gateway is running" in current_state(state)[0]


def test_setup_does_not_trust_an_existing_config_that_starts_programs(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("MCPGUARD_CONFIG", raising=False)
    (tmp_path / "mcpguard.toml").write_text('[servers.x]\ncommand = "calc.exe"\nargs = []\n', encoding="utf-8")
    assert main(["setup"]) != 0
    out = capsys.readouterr().out
    assert "not trusted yet" in out
    assert "starts 1 server (x)" in out or "calc" in out or "x" in out
    from mcpguard.cli import _digest_of, _trusted
    assert _trusted().get(str((tmp_path / "mcpguard.toml").resolve())) != _digest_of(str(tmp_path / "mcpguard.toml"))


def test_setup_keeps_a_config_you_already_trusted(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("MCPGUARD_CONFIG", raising=False)
    (tmp_path / "mcpguard.toml").write_text('[servers.x]\ncommand = "node"\nargs = []\n', encoding="utf-8")
    assert main(["trust"]) == 0
    capsys.readouterr()
    main(["setup"])
    assert "kept your existing" in capsys.readouterr().out


def test_pins_commands_print_no_raw_control_characters(make_config, capsys):
    from mcpguard.config import load_config
    cfg = make_config()
    assert main(["-c", str(cfg), "trust"]) == 0
    path = load_config(cfg).pins_path
    s = PinStore(path)
    s.check("s\x1b[2J", {"name": "t‮\x07", "description": "d"})
    s.save()
    s = PinStore(path)
    s.check("s\x1b[2J", {"name": "t‮\x07", "description": "evil \x1b]0;pwn\x07 text\r\nfake"})
    s.save()
    capsys.readouterr()
    main(["-c", str(cfg), "pins", "pending"])
    main(["-c", str(cfg), "pins", "diff"])
    out = capsys.readouterr().out
    assert not any(c in out for c in "\x1b\x07‮\r")


def test_a_changed_tool_end_to_end_through_the_gateway(gateway, tmp_path):
    from conftest import run, server_block

    async def go():
        async with gateway(servers=server_block(mode="rugpull")) as gw:
            await gw.refresh()
            assert "srv__echo" in gw.quarantined
            changed = PinStore(gw.cfg.pins_path).changed
            assert "srv/echo" in changed
            return gw.cfg.pins_path
    path = run(go())
    assert PinStore(path).diff("srv")
    assert PinStore(path).approve("srv/echo") == ["srv/echo"]
    assert PinStore(path).changed == {}


def test_approving_a_change_clears_the_rug_pull_finding_but_not_the_detectors(gateway):
    """Approval says "I read this change". It does not switch off the injection checks: the rug-pull
    fake server's new text really does contain an injected instruction, so it stays quarantined."""
    from conftest import run, server_block

    async def go():
        async with gateway(servers=server_block(mode="rugpull")) as gw:
            await gw.refresh()
            assert {f.rule for f in gw.quarantined["srv__echo"][1]} >= {"rug_pull.changed"}
            assert PinStore(gw.cfg.pins_path).approve("srv/echo") == ["srv/echo"]
            await gw.refresh()
            rules = {f.rule for f in gw.quarantined["srv__echo"][1]}
            assert "rug_pull.changed" not in rules
            assert any(r.startswith("injection") for r in rules)
    run(go())


# ------------------------------------------------------------------ PDF styling

def test_pdf_report_has_the_dashboard_look_and_repeats_table_headers():
    from mcpguard.pdf import markdown_to_pdf
    rows = "\n".join(f"| 2026-11-24 | tool_{i} | reason |" for i in range(150))
    md = ("# mcpguard report\n\nCovers 2026-11-24 to 2026-11-24, 10 audit records.\n\n"
          "Log integrity: **PASS**. Audit log intact (10 records).\n\n## Summary\n\n"
          "| Measure | Count |\n|---|---|\n| Tool calls allowed | 7 |\n| Tool calls blocked | 0 |\n"
          "| Would have blocked (monitor mode) | 3 |\n| Definitions quarantined | 1 |\n\n"
          "Findings by severity: critical 1, high 2.\n\n## Blocked\n\n"
          "| Time | Target | Reason |\n|---|---|---|\n" + rows)
    pdf = markdown_to_pdf(md)
    assert _xref_ok(pdf)
    assert b"0.855 0.980 0.612 rg" in pdf          # the dashboard's lime accent (#dafa9c)
    assert b"LOG INTACT" in pdf                      # integrity badge in the header
    assert pdf.count(b"(Target) Tj") >= 2            # table header repeated on the next page


def test_pdf_shows_a_failed_integrity_check_in_red():
    from mcpguard.pdf import markdown_to_pdf
    pdf = markdown_to_pdf("# mcpguard report\n\nLog integrity: **FAIL**. Chain broken.\n")
    assert b"LOG CHECK FAILED" in pdf
    assert b"1.000 0.541 0.502 rg" in pdf            # #ff8a80


def test_server_supplied_names_cannot_inject_terminal_escapes_into_stats_or_the_report(tmp_path):
    from mcpguard.audit import AuditLog
    from mcpguard.report import build_report
    from mcpguard.stats import collect, render
    log = tmp_path / "a.jsonl"
    AuditLog(log, key=None).write(
        "call.blocked", tool="srv/\x1b]0;x\x07t", client="c", reason="r \x1b[1m",
        findings=[{"rule": "x\x1b[0m", "severity": "high", "message": "m"}])
    for text in (build_report(str(log)), render(collect(log, hours=24), 24)):
        assert not any(c in text for c in "\x1b\x07\x9b")


def test_a_config_nested_thousands_deep_is_a_config_error_not_a_crash(tmp_path):
    import pytest

    from mcpguard.config import ConfigError, load_config
    f = tmp_path / "deep.toml"
    f.write_bytes(b"a=" + b"[" * 100000 + b"]" * 100000)
    with pytest.raises(ConfigError, match="nested too deeply"):
        load_config(f)


def test_sandbox_mount_paths_refuse_control_characters():
    import pytest

    from mcpguard.sandbox import parse
    with pytest.raises(ValueError, match="control characters"):
        parse({"image": "x", "mounts": [{"host": "a\nb", "container": "/d"}]}, "t")


def test_full_width_look_alikes_do_not_slip_past_the_folder_check():
    from mcpguard.policy import scope_violation
    assert scope_violation({"path": "ｆｉｌｅ:///etc/passwd"}, ["/data"], [])
    assert scope_violation({"path": "／etc／passwd"}, ["/data"], [])
    assert not scope_violation({"path": "/data/notes.txt"}, ["/data"], [])
