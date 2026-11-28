"""The HTML report: same facts as the Markdown one, escaped, and with nothing loaded from outside."""

from __future__ import annotations

from mcpguard.report import build_report, build_report_html


def _log(tmp_path, reason):
    from mcpguard.audit import AuditLog

    path = str(tmp_path / "audit.jsonl")
    AuditLog(path).write("call.blocked", tool="web/fetch", reason=reason, findings=[])
    return path


def test_html_report_escapes_audit_text(tmp_path):
    path = _log(tmp_path, '<script>alert(1)</script> | "x"')
    page = build_report_html(path)
    assert "<script>" not in page.replace("<style>", "")
    assert "&lt;script&gt;" in page
    assert "web/fetch" in page


def test_html_report_matches_markdown_facts(tmp_path):
    path = _log(tmp_path, "host not allowed")
    md = build_report(path)
    page = build_report_html(path)
    for needle in ("Tool calls blocked", "Control evidence", "Blocked calls", "host not allowed"):
        assert needle in md
        assert needle in page
    assert 'class="badge' in page
    assert "<h1>mcpguard report</h1>" in page


def test_html_report_of_an_empty_log(tmp_path):
    from mcpguard.audit import AuditLog

    path = str(tmp_path / "empty.jsonl")
    AuditLog(path)
    assert "The audit log is empty." in build_report_html(path)


def test_python_dash_m_runs_the_cli():
    import subprocess
    import sys

    cmd = [sys.executable, "-m", "mcpguard", "--version"]
    done = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=False)
    assert done.returncode == 0
    assert "mcpguard" in (done.stdout + done.stderr)


def test_selftest_runs_with_an_untrusted_config_in_the_folder(tmp_path, monkeypatch, capsys):
    from mcpguard.cli import main

    body = '[servers.files]\ncommand = "python"\nargs = ["-c", "pass"]\n'
    (tmp_path / "mcpguard.toml").write_text(body, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert main(["selftest"]) == 0
    assert "not trusted yet" in capsys.readouterr().out


def test_report_checks_signatures_when_it_has_the_key(tmp_path):
    from mcpguard.audit import AuditLog

    key = b"k" * 32
    path = str(tmp_path / "audit.jsonl")
    AuditLog(path, key=key).write("call.blocked", tool="web/fetch", reason="host not allowed", findings=[])
    with_key = build_report(path, key=key)
    without_key = build_report(path)
    assert "signatures valid" in with_key
    assert "not checked" in without_key
    assert "signatures valid" in build_report_html(path, key=key)
