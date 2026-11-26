"""Switching between monitor and enforce from the dashboard or the command line."""

import json
import threading
import urllib.error
import urllib.request

import pytest
from conftest import call, is_err, run

from mcpguard.audit import read_log
from mcpguard.cli import main
from mcpguard.config import load_config
from mcpguard.dashboard import make_server
from mcpguard.modeswitch import MAX_BYTES, clear_override, mode_path, read_override, set_override
from mcpguard.policy import own_files_problem

DENY = '[[policy.rules]]\nmatch = "*/delete_*"\naction = "deny"\n'


def test_the_choice_is_saved_read_and_cleared(tmp_path):
    assert read_override(tmp_path) is None
    set_override(tmp_path, "enforce", "dashboard")
    saved = read_override(tmp_path)
    assert saved is not None
    assert saved["mode"] == "enforce"
    assert saved["by"] == "dashboard"
    assert clear_override(tmp_path) is True
    assert clear_override(tmp_path) is False
    with pytest.raises(ValueError):
        set_override(tmp_path, "off", "x")


@pytest.mark.parametrize("content", [
    "not json", "[]", '{"mode": "off"}', '{"mode": 5}', '{"mode":"enforce"' + " " * MAX_BYTES + "}", "{" * 3000,
    '{"mode": "enforce", "by": 7, "ts": true}'])
def test_a_damaged_mode_file_is_ignored_or_cleaned(tmp_path, content):
    mode_path(tmp_path).write_text(content, encoding="utf-8")
    saved = read_override(tmp_path)
    if saved is not None:  # only the last case is valid, with its odd fields replaced
        assert saved == {"mode": "enforce", "by": "unknown", "ts": 0.0}


def test_switching_to_enforce_makes_the_gateway_block_and_back_unblocks(gateway, tmp_path):
    async def go():
        async with gateway('mode = "monitor"\n' + DENY) as gw:
            assert not is_err(await call(gw, "srv__delete_item"))        # monitor: let through
            set_override(gw.cfg.approvals_dir, "enforce", "dashboard")
            assert gw._apply_mode() is True
            assert gw.cfg.mode == "enforce"
            assert is_err(await call(gw, "srv__delete_item", rid=2))     # enforce: blocked
            set_override(gw.cfg.approvals_dir, "monitor", "dashboard")
            gw._apply_mode()
            assert not is_err(await call(gw, "srv__delete_item", rid=3))
            clear_override(gw.cfg.approvals_dir)
            gw._apply_mode()
            assert gw.cfg.mode == "monitor"
            return gw.cfg.audit_path
    audit = run(go())
    changes = [r for r in read_log(audit) if r["event"] == "mode.changed"]
    assert [(r["before"], r["after"]) for r in changes] == [("monitor", "enforce"), ("enforce", "monitor")]
    assert changes[0]["source"] == "switch (dashboard)"


def test_the_switch_survives_a_config_reload_and_applies_at_start(make_config):
    from conftest import bump

    async def go():
        from mcpguard.gateway import Gateway
        cfgfile = make_config('mode = "monitor"\n' + DENY)
        set_override(load_config(cfgfile).approvals_dir, "enforce", "cli")
        gw = Gateway(load_config(cfgfile))
        await gw.start()
        try:
            assert gw.cfg.mode == "enforce"                  # applied at start, with no change record
            bump(cfgfile, 'mode = "monitor"\n' + DENY + "\n[anomaly]\nenabled = false\n")
            await gw.maybe_reload()
            assert gw.cfg.mode == "enforce"                  # still on top of the file
            assert gw._file_mode == "monitor"
        finally:
            await gw.stop()
    run(go())


def test_tools_cannot_reach_the_mode_file(tmp_path):
    approvals = str(tmp_path / "mcpguard-approvals")
    for path in (approvals + "/mode.json", approvals + "/../mcpguard-approvals/mode.json"):
        assert own_files_problem({"path": path}, [approvals], "write_file")
        assert own_files_problem({"path": path}, [approvals], "read_file")


@pytest.fixture
def dash(make_config):
    cfg = load_config(make_config('mode = "monitor"\n'))
    srv = make_server(cfg, 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield cfg, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _post(url, body, token):
    req = urllib.request.Request(url + "/api/mode", data=json.dumps(body).encode(),
                                 headers={"X-Token": token, "Content-Type": "application/json"}, method="POST")
    return urllib.request.urlopen(req)


def test_dashboard_switch_needs_the_token_and_a_valid_mode(dash):
    from mcpguard.approvals import token_for
    cfg, url = dash
    for token in ("", "wrong"):
        with pytest.raises(urllib.error.HTTPError) as e:
            _post(url, {"mode": "enforce"}, token)
        assert e.value.code == 403
    assert read_override(cfg.approvals_dir) is None
    token = token_for(cfg.approvals_dir)
    for bad in ({"mode": "off"}, {"mode": True}, {}, {"mode": ["enforce"]}):
        with pytest.raises(urllib.error.HTTPError) as e:
            _post(url, bad, token)
        assert e.value.code == 400
    assert json.loads(_post(url, {"mode": "enforce"}, token).read()) == {"ok": True, "mode": "enforce"}
    saved = read_override(cfg.approvals_dir)
    assert saved is not None
    assert saved["by"] == "dashboard"


def test_dashboard_refuses_a_foreign_host_for_the_switch(dash):
    from mcpguard.approvals import token_for
    cfg, url = dash
    req = urllib.request.Request(url + "/api/mode", data=b'{"mode":"monitor"}',
                                 headers={"X-Token": token_for(cfg.approvals_dir), "Host": "evil.example"},
                                 method="POST")
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 403


def test_dashboard_page_has_the_switch_and_state_reports_the_source(dash):
    cfg, url = dash
    page = urllib.request.urlopen(url + "/").read().decode()
    assert 'id="modeswitch"' in page
    assert "/api/mode" in page
    state = json.loads(urllib.request.urlopen(url + "/api/state").read())
    assert state["gateway"]["config_mode"] == "monitor"
    set_override(cfg.approvals_dir, "enforce", "cli")
    state = json.loads(urllib.request.urlopen(url + "/api/state").read())
    assert state["gateway"]["wanted_mode"] == "enforce"


def test_mode_command(make_config, capsys):
    cfg = make_config('mode = "monitor"\n')
    assert main(["-c", str(cfg), "trust"]) == 0
    capsys.readouterr()
    assert main(["-c", str(cfg), "mode"]) == 0
    assert "Mode: monitor (from the config file)" in capsys.readouterr().out
    assert main(["-c", str(cfg), "mode", "enforce"]) == 0
    assert "no restart" in capsys.readouterr().out
    assert main(["-c", str(cfg), "mode"]) == 0
    assert "Mode: enforce (set by cli; the config file says monitor)" in capsys.readouterr().out
    assert main(["-c", str(cfg), "doctor"]) in (0, 1)
    assert "mcpguard mode config" in capsys.readouterr().out
    assert main(["-c", str(cfg), "mode", "config"]) == 0
    assert "Back to the config file" in capsys.readouterr().out
    assert read_override(load_config(cfg).approvals_dir) is None


def test_the_switch_code_is_in_the_page_script_and_not_in_the_stylesheet():
    """The first version put the code inside <style>: the page then crashed while drawing the top bar."""
    import re
    from importlib import resources
    page = resources.files("mcpguard").joinpath("dashboard.html").read_text(encoding="utf-8")
    style = re.search(r"<style>(.*?)</style>", page, re.S)
    script = re.search(r"<script>(.*?)</script>", page, re.S)
    assert style is not None
    assert script is not None
    assert "function " not in style.group(1)
    assert "addEventListener" not in style.group(1)
    assert "function renderModeSwitch" in script.group(1)
    assert 'getElementById("modeswitch")' in script.group(1) or '$("modeswitch")' in script.group(1)
    assert "hidden>" not in page.split('id="modeswitch"', 1)[1].split("</div>", 1)[0].split(">", 1)[0] + ">"


def test_every_function_the_page_calls_is_defined():
    """A cheap guard against a missing function (a ReferenceError stops the whole page from updating)."""
    import re
    from importlib import resources
    page = resources.files("mcpguard").joinpath("dashboard.html").read_text(encoding="utf-8")
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)  # type: ignore[union-attr]
    defined = set(re.findall(r"function\s+([A-Za-z_$][\w$]*)", script)) | set(
        re.findall(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=", script))
    called = set(re.findall(r"\b(render[A-Z]\w*)\(", script))
    assert called <= defined, called - defined


def test_two_quick_clicks_at_once_do_not_collide(dash):
    from mcpguard.approvals import token_for
    cfg, url = dash
    token = token_for(cfg.approvals_dir)
    codes = []

    def click(mode):
        try:
            codes.append(_post(url, {"mode": mode}, token).status)
        except urllib.error.HTTPError as e:
            codes.append(e.code)

    threads = [threading.Thread(target=click, args=(m,)) for m in ["enforce", "monitor"] * 40]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(set(map(str, codes))) == ["200"], codes
    assert read_override(cfg.approvals_dir) is not None


def test_a_request_without_a_host_is_refused(dash):
    import socket
    _cfg, url = dash
    port = int(url.rsplit(":", 1)[1])
    s = socket.create_connection(("127.0.0.1", port))
    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
    assert s.recv(64).split()[1] == b"403"
    s.close()
