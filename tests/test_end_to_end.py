"""The whole Claude Desktop path: init -> install --take-over -> start the gateway exactly as
Claude Desktop would (the command and args written into its config) -> MCP handshake."""

import contextlib
import json
import subprocess

from conftest import FAKE, PY

from mcpguard.cli import main


def _died(proc) -> str:
    proc.kill()
    return f"gateway exited (code {proc.wait()}); its stderr:\n{proc.stderr.read()[-3000:]}"


def rpc(proc, msg):
    try:
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()
    except (BrokenPipeError, OSError):
        raise AssertionError(_died(proc)) from None
    if "id" not in msg:
        return None
    while True:
        line = proc.stdout.readline()
        assert line, _died(proc)
        reply = json.loads(line)
        if reply.get("id") == msg["id"]:
            return reply


def test_claude_desktop_path_end_to_end(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    desk = tmp_path / "claude_desktop_config.json"
    desk.write_text(json.dumps({"preferences": {"x": 1},
                                "mcpServers": {"My Files": {"command": PY, "args": [FAKE]}}}), encoding="utf-8")
    assert main(["claude-desktop", "install", "--take-over", "--file", str(desk)]) == 0
    entry = json.loads(desk.read_text(encoding="utf-8"))["mcpServers"]["guarded"]
    # Start it the way Claude Desktop does: the command and args from its config, from another folder.
    proc = subprocess.Popen([entry["command"], *entry["args"]], cwd=tmp_path.parent, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        init = rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                          "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                     "clientInfo": {"name": "claude-ai", "version": "0"}}})
        assert init["result"]["serverInfo"]["name"] == "mcpguard"
        rpc(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools = rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
        names = {t["name"] for t in tools}
        assert "My-Files__echo" in names  # the renamed, moved server answers through the gateway
        reply = rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                           "params": {"name": "My-Files__echo", "arguments": {"text": "hi"}}})
        assert "hi" in json.dumps(reply["result"])
    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
    assert main(["verify"]) == 0  # the audit log of that session is intact


def _start(entry, cwd):
    return subprocess.Popen([entry["command"], *entry["args"]], cwd=cwd, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")


def _handshake(proc):
    rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "t", "version": "0"}}})
    rpc(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})


def _stop(proc):
    with contextlib.suppress(OSError):  # already gone; the assertion that noticed has the details
        proc.stdin.close()
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_two_gateways_on_one_config_like_claude_desktop(tmp_path, monkeypatch):
    """Claude Desktop can start the gateway twice. Both must extend one audit chain, and the
    dashboard must see one running gateway with both processes, even after one stops."""
    import time

    from mcpguard.config import load_config
    from mcpguard.state import is_live, read_merged
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    desk = tmp_path / "claude_desktop_config.json"
    desk.write_text(json.dumps({"mcpServers": {"files": {"command": PY, "args": [FAKE]}}}), encoding="utf-8")
    assert main(["claude-desktop", "install", "--take-over", "--file", str(desk)]) == 0
    entry = json.loads(desk.read_text(encoding="utf-8"))["mcpServers"]["guarded"]
    a, b = _start(entry, tmp_path), _start(entry, tmp_path)
    try:
        _handshake(a)
        _handshake(b)
        for i in range(15):  # interleaved calls through both processes
            for proc, n in ((a, 100 + i), (b, 200 + i)):
                reply = rpc(proc, {"jsonrpc": "2.0", "id": n, "method": "tools/call",
                                   "params": {"name": "files__echo", "arguments": {"text": f"{n}"}}})
                assert str(n) in json.dumps(reply["result"])
        state_path = load_config(tmp_path / "mcpguard.toml").state_path
        deadline = time.time() + 10
        while time.time() < deadline and read_merged(state_path).get("processes") != 2:
            time.sleep(0.2)
        merged = read_merged(state_path)
        assert merged["processes"] == 2
        assert [s["name"] for s in merged["servers"]] == ["files"]
        _stop(a)
        merged = read_merged(state_path)
        assert is_live(merged)            # the other gateway still runs
        assert merged["processes"] == 1
    finally:
        _stop(a)
        _stop(b)
    assert main(["verify"]) == 0          # one unbroken chain from both processes
