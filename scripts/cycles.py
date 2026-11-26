# ruff: noqa: E501
"""Run 100 entry/exit cycles against the real CLI and gateway, each in a fresh folder.

Every cycle starts mcpguard as a subprocess the way a user or an MCP client would, feeds it
something awkward, and checks the way it exits:

  * no Python traceback reaches the user,
  * the exit code is one the CLI documents (0 ok, 1 error, 2 findings, 3 tampered),
  * nothing hangs,
  * a gateway told to stop (EOF, SIGTERM) stops cleanly and leaves an intact audit log.

Usage:  python scripts/cycles.py [-v] [-k substring]
Exit status is the number of failing cycles (capped at 100).
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAKE = ROOT / "tests" / "fake_server.py"
TIMEOUT = 25
OK_CODES = {0, 1, 2, 3}

CONFIG = f"""
mode = "enforce"
[servers.fake]
command = "{Path(sys.executable).as_posix()}"
args = ["{FAKE.as_posix()}"]
[audit]
path = "audit.jsonl"
[dashboard]
enabled = false
"""


class Cycle:
    def __init__(self, name: str, fn):
        self.name, self.fn = name, fn


CYCLES: list[Cycle] = []


def cycle(name: str):
    def deco(fn):
        CYCLES.append(Cycle(name, fn))
        return fn
    return deco


def env_for(home: Path) -> dict:
    e = dict(os.environ)
    e["MCPGUARD_HOME"] = str(home / "home")
    e["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + e.get("PYTHONPATH", "")
    e["PYTHONIOENCODING"] = "utf-8"
    e.pop("MCPGUARD_CONFIG", None)
    return e


def run(cwd: Path, args: list[str], stdin: bytes | str | None = b"", timeout: int = TIMEOUT,
        extra_env: dict | None = None):
    e = env_for(cwd)
    e.update(extra_env or {})
    data = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
    try:
        p = subprocess.run([sys.executable, "-m", "mcpguard", *args], cwd=cwd, env=e, input=data,
                           capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "", "TIMEOUT"
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def judge(res, allowed=OK_CODES, want_out: str | None = None, want_err: str | None = None):
    """Return an error string, or None when the cycle's exit was clean."""
    rc, out, err = res
    if rc is None:
        return "hung (timeout)"
    if "Traceback (most recent call last)" in err or "Traceback (most recent call last)" in out:
        return "traceback shown to the user: " + err.strip().splitlines()[-1][:160]
    if rc not in allowed:
        return f"exit code {rc} not in {sorted(allowed)}: {err.strip()[-160:]}"
    if want_out and want_out not in out:
        return f"stdout lacks {want_out!r}"
    if want_err and want_err not in err:
        return f"stderr lacks {want_err!r}: {err.strip()[-120:]}"
    return None


def trusted_dir(d: Path, config: str = CONFIG) -> None:
    (d / "mcpguard.toml").write_text(config, encoding="utf-8")
    run(d, ["trust"])


# ------------------------------------------------------------ A. every command, no config

COMMANDS = [
    ["check"], ["doctor"], ["verify"], ["stats"], ["report"], ["export"], ["checks"], ["pins"],
    ["baseline"], ["iocs"], ["advisories"], ["selftest"], ["audit-configs", "."], ["scan"],
    ["checkpoint"], ["explain", "echo"], ["policy-test", "missing.json"], ["test", "hello"],
    ["claude-desktop", "status"], ["dashboard", "--help"], ["run", "--help"], ["serve", "--help"],
    ["trust"], ["audit-new"], ["init", "--profile", "strict"],
]
for _cmd in COMMANDS:
    def _mk(cmd):
        @cycle("no config: " + " ".join(cmd))
        def _(d):
            return judge(run(d, cmd, stdin=b""))
    _mk(_cmd)


# ------------------------------------------------------------ B. awkward config files

BAD_CONFIGS = {
    "empty file": "",
    "binary garbage": "\x00\x01\x02\xff\xfe",
    "invalid toml": "mode = = enforce",
    "mode wrong type": "mode = 7",
    "unknown mode": 'mode = "yolo"',
    "servers not a table": "servers = 3",
    "server without command": "[servers.x]\nenv = {}\n",
    "command is a string": '[servers.x]\ncommand = "python"\n',
    "command empty list": "[servers.x]\ncommand = []\n",
    "negative limits": "[limits]\nmax_calls_per_minute = -5\n",
    "huge number": "[limits]\nmax_calls_per_minute = 99999999999999999999999\n",
    "bom + crlf": "﻿mode = \"enforce\"\r\n",
    "unicode server name": '[servers."сервер"]\ncommand = ["python"]\n',
    "port out of range": "[dashboard]\nenabled = true\nport = 99999\n",
    "audit path is a folder": '[audit]\npath = "."\n',
}
for _n, _t in BAD_CONFIGS.items():
    def _mk(n, t):
        @cycle("bad config: " + n)
        def _(d):
            (d / "mcpguard.toml").write_text(t, encoding="utf-8", errors="surrogateescape") \
                if "\x00" not in t else (d / "mcpguard.toml").write_bytes(t.encode("latin-1"))
            run(d, ["trust"])
            for cmd in (["check"], ["doctor"], ["selftest"]):
                err = judge(run(d, cmd))
                if err:
                    return f"{' '.join(cmd)}: {err}"
    _mk(_n, _t)


# ------------------------------------------------------------ C. awkward arguments

BAD_ARGS = [
    [], ["nonsense"], ["--version", "x"], ["-c"], ["-c", "nope.toml", "check"], ["check", "--bogus"],
    ["test"], ["explain"], ["export", "--format", "xml"], ["report", "--format", "pdf"],
    ["iocs", "frobnicate"], ["claude-desktop", "explode"], ["serve", "--port", "notanumber"],
    ["serve", "--port", "70000"], ["stats", "--limit", "-3"], ["report", "--limit", "abc"],
]
for _a in BAD_ARGS:
    def _mk(args):
        @cycle("bad args: " + (" ".join(args) or "(none)"))
        def _(d):
            return judge(run(d, args))
    _mk(_a)


# ------------------------------------------------------------ D. damaged audit logs

def make_log(d: Path) -> Path:
    trusted_dir(d)
    run(d, ["selftest"])
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "1"}}}
    msgs = [init, {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "fake__echo", "arguments": {"text": "hi"}}}]
    run(d, ["run"], stdin="".join(json.dumps(m) + "\n" for m in msgs))
    return d / "audit.jsonl"


LOG_DAMAGE = {
    "truncated mid-line": lambda b: b[: max(1, len(b) // 2)],
    "garbage appended": lambda b: b + b"\x00\xffnot json\n",
    "empty": lambda b: b"",
    "only newlines": lambda b: b"\n\n\n",
    "huge line": lambda b: b + b"x" * 3_000_000 + b"\n",
    "non-utf8": lambda b: b + b"\xff\xfe\xfa\n",
    "json but wrong shape": lambda b: b + b'[1,2,3]\n"str"\n42\nnull\n{"a":1}\n',
    "first record deleted": lambda b: b.split(b"\n", 1)[-1],
    "records reordered": lambda b: b"\n".join(reversed(b.split(b"\n"))),
}
for _n, _f in LOG_DAMAGE.items():
    def _mk(n, f):
        @cycle("damaged log: " + n)
        def _(d):
            log = make_log(d)
            if not log.exists():
                return "the gateway wrote no audit log"
            log.write_bytes(f(log.read_bytes()))
            for cmd in (["verify"], ["stats"], ["report"], ["report", "--format", "html"],
                        ["export"], ["doctor"], ["checkpoint"]):
                err = judge(run(d, cmd))
                if err:
                    return f"{' '.join(cmd)}: {err}"
    _mk(_n, _f)


@cycle("audit log: key file deleted after use")
def _(d):
    make_log(d)
    for k in list(d.glob("*.key")) + list((d / "home").glob("*.key")):
        k.unlink()
    return judge(run(d, ["verify"]))


@cycle("audit log: is a directory")
def _(d):
    trusted_dir(d)
    (d / "audit.jsonl").mkdir()
    return judge(run(d, ["verify"])) or judge(run(d, ["run"], stdin=b""))


@cycle("audit log: read-only file, gateway starts")
def _(d):
    log = make_log(d)
    log.chmod(0o444)
    return judge(run(d, ["run"], stdin=b""))


@cycle("audit-new twice in a row")
def _(d):
    make_log(d)
    return judge(run(d, ["audit-new"])) or judge(run(d, ["audit-new"])) or judge(run(d, ["verify"]))


# ------------------------------------------------------------ E. gateway over stdio

INIT = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                              "clientInfo": {"name": "t", "version": "1"}}}) + "\n"
INITED = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"

STDIO_INPUTS = {
    "immediate EOF": b"",
    "EOF in the middle of a message": b'{"jsonrpc":"2.0","id":1,"meth',
    "blank lines only": b"\n\n\r\n",
    "malformed JSON": b"{not json}\n",
    "json array batch": b'[{"jsonrpc":"2.0","id":1,"method":"ping"}]\n',
    "empty array": b"[]\n",
    "bare scalar": b"42\nnull\ntrue\n",
    "missing method": b'{"jsonrpc":"2.0","id":1}\n',
    "method not a string": b'{"jsonrpc":"2.0","id":1,"method":["x"]}\n',
    "unknown method": b'{"jsonrpc":"2.0","id":1,"method":"nope/nope"}\n',
    "id is an object": b'{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}\n',
    "huge line (5 MB)": b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"' + b"a" * 5_000_000 + b'"}}\n',
    "non-UTF-8 bytes": b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"\xff\xfe"}}\n',
    "NUL bytes": b'\x00\x00\x00\n',
    "deeply nested JSON": b'{"jsonrpc":"2.0","id":1,"method":"ping","params":' + b"[" * 5000 + b"]" * 5000 + b"}\n",
    "tool call before initialize": b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fake__echo","arguments":{}}}\n',
    "tool call with no params": (INIT + INITED + '{"jsonrpc":"2.0","id":2,"method":"tools/call"}\n').encode(),
    "tool call, params a list": (INIT + INITED + '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":[1]}\n').encode(),
    "tool call, unknown tool": (INIT + INITED + '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"zzz","arguments":{}}}\n').encode(),
    "tool call, arguments not an object": (INIT + INITED + '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fake__echo","arguments":"x"}}\n').encode(),
    "tool call with a secret": (INIT + INITED + '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fake__echo","arguments":{"text":"AKIAABCDEFGHIJKLMNOP"}}}\n').encode(),
    "1000 pings": (INIT + INITED + '{"jsonrpc":"2.0","id":2,"method":"ping"}\n' * 1000).encode(),
    "duplicate ids": (INIT + INITED + '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n' * 3).encode(),
    "CRLF line endings": (INIT + INITED).replace("\n", "\r\n").encode(),
    "cancel for an unknown request": (INIT + INITED + '{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":99}}\n').encode(),
}
for _n, _b in STDIO_INPUTS.items():
    def _mk(n, b):
        @cycle("stdio: " + n)
        def _(d):
            trusted_dir(d)
            err = judge(run(d, ["run"], stdin=b, timeout=40), allowed={0, 1})
            if err:
                return err
            res = run(d, ["verify"])
            return judge(res, allowed={0}) and "audit log not intact after: " + judge(res, allowed={0})
    _mk(_n, _b)


@cycle("stdio: server command does not exist")
def _(d):
    trusted_dir(d, CONFIG.replace(Path(sys.executable).as_posix(), "/no/such/binary"))
    return judge(run(d, ["run"], stdin=(INIT + INITED + '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n').encode()),
                 allowed={0, 1})


@cycle("stdio: server exits immediately")
def _(d):
    trusted_dir(d, CONFIG.replace(f'args = ["{FAKE.as_posix()}"]', 'args = ["-c", "import sys; sys.exit(3)"]'))
    return judge(run(d, ["run"], stdin=(INIT + INITED + '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n').encode()),
                 allowed={0, 1})


@cycle("stdio: SIGTERM while idle")
def _(d):
    if sys.platform == "win32":
        return None  # Windows has no SIGTERM/SIGINT/EPIPE to send: send_signal would just kill the process
    trusted_dir(d)
    p = subprocess.Popen([sys.executable, "-m", "mcpguard", "run"], cwd=d, env=env_for(d),
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.stdin.write((INIT + INITED).encode())
    p.stdin.flush()
    time.sleep(2.5)
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=15)
    except subprocess.TimeoutExpired:
        p.kill()
        return "did not stop within 15 s of SIGTERM"
    err = p.stderr.read().decode("utf-8", "replace")
    if "Traceback" in err:
        return "traceback on SIGTERM: " + err.strip().splitlines()[-1]
    if p.returncode not in (0, -15, 143):
        return f"exit code {p.returncode} after SIGTERM"
    return judge(run(d, ["verify"]), allowed={0})


@cycle("stdio: SIGINT while idle")
def _(d):
    if sys.platform == "win32":
        return None  # Windows has no SIGTERM/SIGINT/EPIPE to send: send_signal would just kill the process
    trusted_dir(d)
    p = subprocess.Popen([sys.executable, "-m", "mcpguard", "run"], cwd=d, env=env_for(d),
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.stdin.write((INIT + INITED).encode())
    p.stdin.flush()
    time.sleep(2.5)
    p.send_signal(signal.SIGINT)
    try:
        p.wait(timeout=15)
    except subprocess.TimeoutExpired:
        p.kill()
        return "did not stop within 15 s of SIGINT"
    if "Traceback" in p.stderr.read().decode("utf-8", "replace"):
        return "traceback on SIGINT"


@cycle("stdio: client closes stdout early (broken pipe)")
def _(d):
    if sys.platform == "win32":
        return None  # Windows has no SIGTERM/SIGINT/EPIPE to send: send_signal would just kill the process
    trusted_dir(d)
    p = subprocess.Popen([sys.executable, "-m", "mcpguard", "run"], cwd=d, env=env_for(d),
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.stdout.close()
    try:
        p.stdin.write((INIT + INITED + '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n' * 50).encode())
        p.stdin.close()
    except OSError:
        pass
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        p.kill()
        return "hung after the client closed its read end"
    err = p.stderr.read().decode("utf-8", "replace")
    if "Traceback" in err:
        return "traceback after broken pipe: " + err.strip().splitlines()[-1][:150]


# ------------------------------------------------------------ F. gateway over HTTP

def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def http_raw(port: int, payload: bytes, wait: float = 1.5) -> bytes:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(payload)
    s.settimeout(wait)
    out = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            out += c
    except OSError:
        pass
    s.close()
    return out


def with_http(d: Path, payloads: list[bytes]):
    trusted_dir(d)
    port = free_port()
    p = subprocess.Popen([sys.executable, "-m", "mcpguard", "serve", "--port", str(port)], cwd=d,
                         env=env_for(d), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    problem = _probe_http(p, port, payloads)
    return stop_http(p) or problem


def _probe_http(p, port: int, payloads: list[bytes]):
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            break
        except OSError:
            time.sleep(0.2)
    else:
        return "the HTTP server never started: " + (p.stderr.read(400).decode("utf-8", "replace") if p.poll() is not None else "")
    for pl in payloads:
        http_raw(port, pl)
    if p.poll() is not None:
        return "the HTTP server died on a hostile request"
    try:
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
    except OSError:
        return "the HTTP server stopped answering after a hostile request"
    return None


def stop_http(p):
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=15)
    except subprocess.TimeoutExpired:
        p.kill()
        return "did not stop on SIGTERM"
    err = p.stderr.read().decode("utf-8", "replace")
    if "Traceback" in err:
        return "traceback in the server's stderr: " + err.strip().splitlines()[-1][:150]
    return None


HTTP_REQS = {
    "garbage bytes": b"\x00\xff\xfegarbage\r\n\r\n",
    "no request line": b"\r\n\r\n",
    "GET /": b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
    "POST wrong path": b"POST /nope HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}",
    "POST no token": b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}",
    "negative Content-Length": b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n",
    "huge Content-Length": b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999\r\n\r\n{}",
    "non-numeric Content-Length": b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n{}",
    "truncated body": b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 500\r\n\r\n{}",
    "duplicate headers": b"POST /mcp HTTP/1.1\r\nHost: x\r\nHost: y\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}",
    "10 000 headers": b"GET /mcp HTTP/1.1\r\n" + b"X-A: b\r\n" * 10000 + b"\r\n",
    "chunked body": b"POST /mcp HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
    "method FOO": b"FOO /mcp HTTP/1.1\r\nHost: x\r\n\r\n",
    "OPTIONS": b"OPTIONS /mcp HTTP/1.1\r\nHost: x\r\nOrigin: http://evil.example\r\n\r\n",
    "foreign Origin": b"POST /mcp HTTP/1.1\r\nHost: x\r\nOrigin: http://evil.example\r\nContent-Length: 2\r\n\r\n{}",
    "client connects then hangs up": b"",
    "slow header, never finished": b"POST /mcp HTTP/1.1\r\nHost: x\r\nCont",
}
for _n, _b in HTTP_REQS.items():
    def _mk(n, b):
        @cycle("http: " + n)
        def _(d):
            return with_http(d, [b])
    _mk(_n, _b)


@cycle("http: port already in use")
def _(d):
    trusted_dir(d)
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        return judge(run(d, ["serve", "--port", str(port)]), allowed={1}, want_err="mcpguard:")
    finally:
        s.close()


@cycle("http: bind to a bad host")
def _(d):
    trusted_dir(d)
    return judge(run(d, ["serve", "--host", "999.999.1.1", "--port", "0"]), allowed={1}, want_err="mcpguard:")


# ------------------------------------------------------------ G. awkward surroundings

@cycle("output piped into a closed reader (EPIPE)")
def _(d):
    if sys.platform == "win32":
        return None  # Windows has no SIGTERM/SIGINT/EPIPE to send: send_signal would just kill the process
    trusted_dir(d)
    p = subprocess.Popen(f"{sys.executable} -m mcpguard checks | head -c 10", shell=True, cwd=d,
                         env=env_for(d), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, err = p.communicate(timeout=30)
    if b"Traceback" in err or b"BrokenPipe" in err:
        return "traceback or BrokenPipeError after the reader closed: " + err.decode()[-150:]


@cycle("stdout closed")
def _(d):
    if sys.platform == "win32":
        return None  # Windows has no SIGTERM/SIGINT/EPIPE to send: send_signal would just kill the process
    p = subprocess.run(f"{sys.executable} -m mcpguard checks >&-", shell=True, cwd=d, env=env_for(d),
                       capture_output=True, timeout=30)
    if b"Traceback" in p.stderr:
        return "traceback with stdout closed: " + p.stderr.decode()[-150:]


@cycle("home folder is read-only")
def _(d):
    (d / "mcpguard.toml").write_text(CONFIG, encoding="utf-8")
    ro = d / "ro"
    ro.mkdir()
    ro.chmod(0o555)
    try:
        return judge(run(d, ["trust"], extra_env={"MCPGUARD_HOME": str(ro / "home")}), allowed={0, 1})
    finally:
        ro.chmod(0o755)


@cycle("working folder has unicode and spaces")
def _(d):
    w = d / "проект with spaces ✓"
    w.mkdir()
    trusted_dir(w)
    return judge(run(w, ["check"]), allowed={0}) or judge(run(w, ["selftest"]), allowed={0})


@cycle("config named with -c in another folder")
def _(d):
    other = d / "elsewhere"
    other.mkdir()
    (other / "c.toml").write_text(CONFIG, encoding="utf-8")
    return judge(run(d, ["-c", str(other / "c.toml"), "check"]), allowed={0})


@cycle("MCPGUARD_CONFIG points at a missing file")
def _(d):
    return judge(run(d, ["check"], extra_env={"MCPGUARD_CONFIG": str(d / "gone.toml")}), allowed={1},
                 want_err="mcpguard:")


@cycle("init over an existing config")
def _(d):
    (d / "mcpguard.toml").write_text("x = 1\n", encoding="utf-8")
    r = run(d, ["init"])
    if (d / "mcpguard.toml").read_text(encoding="utf-8") != "x = 1\n":
        return "init overwrote an existing config without --force"
    return judge(r, allowed={1})


@cycle("init then immediately selftest, check, doctor")
def _(d):
    for cmd in (["init"], ["check"], ["selftest"], ["doctor"], ["verify"]):
        err = judge(run(d, cmd))
        if err:
            return f"{' '.join(cmd)}: {err}"


@cycle("config edited after trust")
def _(d):
    trusted_dir(d)
    (d / "mcpguard.toml").write_text(CONFIG + '\n[servers.evil]\ncommand = "calc"\n', encoding="utf-8")
    r = run(d, ["check"])
    # Editing a trusted file must not silently start running new programs.
    if r[0] == 0:
        return "a config edited after trust loaded a new server without asking again"
    run(d, ["trust"])
    return judge(run(d, ["check"]), allowed={0})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-k", default="")
    a = ap.parse_args()
    todo = [c for c in CYCLES if a.k in c.name]
    failed = []
    for i, c in enumerate(todo, 1):
        # Windows cannot delete a folder while a process (a tool server still shutting down after its
        # parent was stopped) has it as its working directory. That is not a result of the cycle.
        with tempfile.TemporaryDirectory(prefix="mcpguard-cycle-", ignore_cleanup_errors=True) as t:
            d = Path(t)
            (d / "home").mkdir()
            started = time.time()
            try:
                problem = c.fn(d)
            except Exception as e:  # noqa: BLE001 - a harness bug must not hide a result
                problem = f"harness error: {type(e).__name__}: {e}"
            took = time.time() - started
            time.sleep(0.2)  # let processes started by the cycle finish exiting before the folder is removed
        mark = "ok  " if not problem else "FAIL"
        if problem or a.verbose:
            print(f"{i:3d} {mark} {c.name}  ({took:.1f}s)" + (f"\n      {problem}" if problem else ""))
        if problem:
            failed.append((c.name, problem))
    print(f"\n{len(todo)} cycles, {len(failed)} failed")
    return min(len(failed), 100)


if __name__ == "__main__":
    sys.exit(main())
