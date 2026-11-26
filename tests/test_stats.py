"""mcpguard stats."""

import time

from conftest import call, run

from mcpguard.audit import AuditLog
from mcpguard.cli import main
from mcpguard.stats import collect, render


def test_stats_from_a_real_gateway_run(gateway, tmp_path, capsys, monkeypatch):
    async def go():
        async with gateway('[[policy.rules]]\nmatch = "*/delete_*"\naction = "deny"\n') as gw:
            await call(gw, "srv__echo", {"text": "x"})
            await call(gw, "srv__echo", {"text": "y"})
            await call(gw, "srv__delete_item")
            return gw.cfg
    cfg = run(go())
    st = collect(cfg.audit_path)
    assert st.calls["srv__echo"] == 2
    assert st.blocked["srv__delete_item"] == 1
    text = render(st, 24)
    assert "2 call(s) allowed, 1 blocked" in text
    assert "srv__delete_item" in text
    monkeypatch.chdir(tmp_path)
    assert main(["-c", cfg.source, "stats", "--hours", "1"]) == 0
    assert "Last 1 hours" in capsys.readouterr().out


def test_stats_window_monitor_mode_and_approvals(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    log.write("call.allowed", tool="s__old", latency_ms=5)
    now = time.time() + 3 * 3600  # three hours later
    log.write("call.would_block", tool="s__x", reason="policy", findings=[{"rule": "secret.jwt"}])
    log.write("call.approval", tool="s__m", approved=True)
    log.write("call.approval", tool="s__m", approved=False)
    log.write("tool.quarantined", tool="evil")
    log.write("server.failed", server="s")
    st = collect(p, hours=24, now=now)
    text = render(st, 24)
    assert "would have been blocked (monitor mode)" in text
    assert "1 approved, 1 denied" in text
    assert "secret.jwt" in text
    assert "Quarantined at some point in this period: evil" in text
    assert "server.failed x1" in text
    assert collect(p, hours=1, now=now + 3600 * 5).calls == {}  # outside the window


def test_stats_without_a_log(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "mcpguard.toml").write_text("", encoding="utf-8")
    assert main(["stats"]) == 0
    assert "No audit log yet" in capsys.readouterr().out
