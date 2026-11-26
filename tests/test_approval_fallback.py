"""With no console, a terminal approval falls back to the dashboard (or denies)."""

import asyncio
import json

from mcpguard.approvals import Approvals


def no_console(monkeypatch):
    monkeypatch.setattr(Approvals, "_tty", lambda self, name, args: None)


def test_no_console_and_no_dashboard_denies(tmp_path, monkeypatch):
    no_console(monkeypatch)
    ap = Approvals("tty", tmp_path / "ap", timeout=1)
    assert asyncio.run(ap("srv/tool", {}, "")).approved is False


def test_no_console_with_dashboard_waits_for_an_answer(tmp_path, monkeypatch):
    no_console(monkeypatch)
    folder = tmp_path / "ap"
    ap = Approvals("tty", folder, timeout=5, dashboard_fallback=True)

    async def go():
        task = asyncio.create_task(ap("srv/tool", {"a": 1}, "why"))
        for _ in range(40):
            await asyncio.sleep(0.05)
            files = list((folder / "pending").glob("*.json"))
            if files:
                break
        assert files, "the request never reached the dashboard queue"
        rid = json.loads(files[0].read_text(encoding="utf-8"))["id"]
        (folder / "decided" / f"{rid}.json").write_text(json.dumps({"approved": True}), encoding="utf-8")
        return await task
    assert asyncio.run(go()).approved is True


def test_no_console_with_dashboard_times_out_closed(tmp_path, monkeypatch):
    no_console(monkeypatch)
    ap = Approvals("tty", tmp_path / "ap", timeout=0.5, dashboard_fallback=True)
    assert asyncio.run(ap("srv/tool", {}, "")).approved is False


def test_a_console_answer_still_wins(tmp_path, monkeypatch):
    from mcpguard.approvals import Verdict
    monkeypatch.setattr(Approvals, "_tty", lambda self, name, args: Verdict(True))
    ap = Approvals("tty", tmp_path / "ap", dashboard_fallback=True)
    assert asyncio.run(ap("srv/tool", {}, "")).approved is True
    assert not list((tmp_path / "ap" / "pending").glob("*.json"))
