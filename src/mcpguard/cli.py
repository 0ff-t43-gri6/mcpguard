"""Command line interface."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import json
import os
import logging
import signal
import shutil
import sys
from collections.abc import Callable
import time
from pathlib import Path

from . import __version__
from .stats import printable
from .audit import (
    AuditLog,
    LogDamaged,
    append_checkpoint,
    check_checkpoints,
    load_key,
    make_checkpoint,
    read_checkpoints,
    read_log,
    verify,
)
from . import trust
from .config import DEFAULT_CONFIG, Config, ConfigError, DetectorConfig, ServerSpec, load_config
from .detect import SEVERITIES, Engine, PinStore, fingerprint_tool, max_severity
from .report import build_report, build_report_html
from .upstream import make_upstream

EXIT_OK, EXIT_ERROR, EXIT_FINDINGS, EXIT_TAMPERED = 0, 1, 2, 3


class CliError(Exception):
    """An error to show the user without a traceback."""


def setup_logging(level: str, file: str = "") -> None:
    handler: logging.Handler = (logging.FileHandler(file, encoding="utf-8") if file
                                else logging.StreamHandler(sys.stderr))
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S"))
    root = logging.getLogger("mcpguard")
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    root.propagate = False


def install_stop_handlers(stop: asyncio.Event) -> None:
    """Shut down cleanly on SIGTERM/SIGINT (state saved, servers stopped)."""
    loop = asyncio.get_running_loop()
    for name in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):  # Windows event loops
            signal.signal(sig, lambda *_: loop.call_soon_threadsafe(stop.set))


def watch_parent(stop: asyncio.Event) -> None:
    """Stop when the program that started us (the AI app) is gone.

    A stdio gateway normally ends when its stdin closes. That does not happen if another process
    still holds the other end of the pipe, which on Windows is easy to arrange: a gateway then lives
    on for days after its app was closed. So also watch the parent process itself.
    Set MCPGUARD_NO_PARENT_WATCH=1 if something launches the gateway through a short-lived helper."""
    if os.environ.get("MCPGUARD_NO_PARENT_WATCH"):
        return
    import threading
    parent = os.getppid()
    if parent <= 1:
        return  # started by init or a service manager: nothing to watch
    loop = asyncio.get_running_loop()

    def parent_gone() -> bool:
        return os.getppid() != parent

    def poll() -> bool:
        time.sleep(1)
        return parent_gone()

    waiter: Callable[[], bool] = poll
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.WinDLL("kernel32")
            kernel32.OpenProcess.restype = ctypes.c_void_p
            kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
            kernel32.WaitForSingleObject.restype = ctypes.c_ulong
            kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
            handle = kernel32.OpenProcess(0x00100000, False, parent)  # SYNCHRONIZE
        except (OSError, AttributeError, ImportError):
            return
        if not handle:
            return  # cannot watch it (no permission, or it is already gone): leave things as they are

        def wait_win() -> bool:
            return kernel32.WaitForSingleObject(handle, 1000) == 0  # 0 = the parent has exited

        waiter = wait_win

    def run() -> None:
        while True:
            if waiter():
                loop.call_soon_threadsafe(stop.set)
                return

    threading.Thread(target=run, name="mcpguard-parent", daemon=True).start()


def _digest_of(config: str) -> str:
    return trust.digest_of(config)


def _trusted() -> dict[str, str]:
    return trust.trusted()


def _set_trust(config: str, is_trusted: bool) -> None:
    trust.set_trust(config, is_trusted)


def _runs_code(config: str) -> list[str]:
    """What in a config file makes mcpguard execute something: servers it starts, plugins it imports."""
    import tomllib
    try:
        data = tomllib.loads(Path(config).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return []
    out = []
    servers = data.get("servers")
    if isinstance(servers, dict) and servers:
        names = ", ".join(sorted(map(str, servers))[:5])
        out.append(f"starts {len(servers)} server{'s' * (len(servers) != 1)} ({names})")
    detectors = data.get("detectors")
    if isinstance(detectors, dict) and detectors.get("plugins"):
        out.append("loads Python plugins")
    return out


def _require_trust(a) -> None:
    """A config named with -c (or MCPGUARD_CONFIG) is the user's choice. One merely found in the
    current folder may have arrived with a cloned project, and a config can start programs and
    import code, so it must be trusted once on this machine before any command loads it.
    The file is read once: what was checked is exactly what gets loaded."""
    try:
        a._config_bytes = Path(a.config).read_bytes()
    except OSError:
        a._config_bytes = None
        return
    if getattr(a, "config_explicit", True):
        return
    digest = trust.digest_bytes(a._config_bytes)
    known = _trusted().get(str(Path(a.config).resolve()))
    if known is not None and known == digest:
        return
    risky = _runs_code(a.config)
    if risky:
        what = "has changed since you trusted it" if known is not None else "has not been trusted on this machine"
        raise CliError(
            f"{a.config} in this folder {what}, and it {' and '.join(risky)}.\n"
            "If it is yours, run: mcpguard trust\n"
            "If it came with a project you downloaded, inspect it first: mcpguard audit-configs .")


def _cfg(a) -> Config:
    try:
        return load_config(a.config, source_bytes=getattr(a, "_config_bytes", None))
    except ConfigError as e:
        if "not found" in str(e):
            raise CliError(f"{e}\nCreate one with: mcpguard init") from e
        raise CliError(f"invalid config: {e}") from e


def _engine(a) -> Engine:
    """Detectors from the config when there is one, built-in defaults otherwise."""
    return Engine(_cfg(a).detectors) if Path(a.config).exists() else Engine(DetectorConfig())


# ---------------------------------------------------------------- commands

def cmd_init(a) -> int:
    p = Path(a.config)
    if p.exists() and not a.force:
        raise CliError(f"{p} already exists (use --force to overwrite)")
    text = DEFAULT_CONFIG
    if a.profile == "monitor":  # observe first: record what would be blocked, block nothing
        text = text.replace('mode = "enforce"', 'mode = "monitor"', 1)
    elif a.profile == "strict":  # unknown tools need approval; medium findings block too
        text = text.replace('default = "allow" ', 'default = "ask"   ', 1)
        text = text.replace('block_severity = "high"   ', 'block_severity = "medium" ', 1)
        text = text.replace("ask_sensitive = false", "ask_sensitive = true", 1)
        text = text.replace('first_seen = "allow"', 'first_seen = "approve"', 1)
    p.write_text(text, encoding="utf-8")
    _set_trust(str(p), True)  # you created it here, so it is yours
    print(f"Created {p} ({a.profile} profile).")
    print("Next: replace [servers.example] with your servers, then check the file with 'mcpguard check'.")
    return EXIT_OK


def cmd_trust(a) -> int:
    """Mark the config as yours, so commands run in its folder will load it."""
    if not Path(a.config).exists():
        raise CliError(f"config file not found: {a.config}")
    _set_trust(a.config, not a.forget)
    if a.forget:
        print(f"{Path(a.config).resolve()} is no longer trusted.")
        return EXIT_OK
    risky = _runs_code(a.config)
    print(f"Trusted {Path(a.config).resolve()}" + (f" (it {' and '.join(risky)})." if risky else "."))
    return EXIT_OK


def cmd_selftest(a) -> int:
    from . import selftest
    from .dlp import DlpConfig
    cfg = None
    note = "built-in defaults: no config file"
    if Path(a.config).exists():
        try:
            _require_trust(a)
            cfg = _cfg(a)
        except CliError:
            note = "built-in defaults: the config here is not trusted yet (run mcpguard trust)"
    engine = Engine(cfg.detectors) if cfg else Engine(DetectorConfig())
    results = selftest.run(engine, cfg.dlp if cfg else DlpConfig(),
                           cfg.policy.block_severity if cfg else "high",
                           cfg.static_block_severity if cfg else "high")
    print(f"mcpguard {__version__} self-test ({a.config if cfg else note})\n")
    print(selftest.render(results, cfg.mode if cfg else "enforce"))
    return EXIT_OK if all(passed for _, passed, _ in results) else EXIT_FINDINGS


_STATUS_WORDS = {"blocks": "stops it", "limits": "limits it", "detects": "warns", "gaps": "needs setup",
                 "affected": "AFFECTED", "outside": "outside"}


def cmd_advisories(a) -> int:
    """Known MCP incidents and CVEs, and whether this setup would stop each one."""
    from . import advisories
    cfg = _cfg(a)
    report = advisories.coverage(cfg)
    if a.json:
        print(json.dumps(report, indent=1))
        return EXIT_FINDINGS if report["counts"]["affected"] else EXIT_OK
    c = report["counts"]
    print(f"{report['total']} recorded incidents and CVEs. With this config mcpguard stops {c['blocks']}, limits "
          f"{c['limits']}, warns about {c['detects']}; {c['gaps']} need a setting turned on, {c['affected']} match a "
          f"configured server, {c['outside']} are outside what a gateway can do.\n")
    for r in report["advisories"]:
        print(f"  {_STATUS_WORDS[r['status']]:<11} {r['date']:<8} {printable(r['title'])}")
        if a.verbose or r["status"] in ("gaps", "affected"):
            for m in r["matches"]:
                print(f"              {m['server']}: {printable(m['message'])}")
            for ctl in r["controls"]:
                if ctl["state"] in ("off", "partial"):
                    print(f"              turn on: {ctl['label']} ({ctl['detail']}): {ctl['how']}")
        if a.verbose:
            print(f"              {r['response']}")
    if report["mode"] == "monitor":
        print("\nNote: mode is 'monitor', so matches are recorded but nothing is refused or blocked.")
    return EXIT_FINDINGS if c["affected"] else EXIT_OK


def cmd_audit_configs(a) -> int:
    """Read the MCP and AI-tool config files in a project folder before opening it in an IDE."""
    from . import advisories
    worst = 0
    found = 0
    for root in a.paths or ["."]:
        if not Path(root).is_dir():
            raise CliError(f"not a folder: {root}")
        for report in advisories.audit_config_files(root):
            found += 1
            print(printable(report["file"]))
            for sv in report["servers"]:
                print(f"  server  {printable(sv['name'])}: {printable(sv['runs'])[:160]}")
            for hook in report["hooks"]:
                print(f"  hook    {printable(hook['runs'])[:160]}")
            for f in sorted(report["findings"], key=lambda f: -SEVERITIES[f["severity"]]):
                worst = max(worst, SEVERITIES[f["severity"]])
                print(f"  {f['severity']:<8} {f['rule']}  {printable(f['message'])}")
            print()
    if not found:
        print("No MCP or AI-tool config files found.")
    elif worst >= SEVERITIES["high"]:
        print("Do not open this project in an AI-enabled editor until the commands above are understood.")
    return EXIT_FINDINGS if worst >= SEVERITIES["high"] else EXIT_OK


def cmd_export(a) -> int:
    from .audit import read_log
    from .export import export
    cfg = _cfg(a)
    if not Path(cfg.audit_path).exists():
        raise CliError(f"no audit log at {cfg.audit_path}")
    since = time.time() - a.hours * 3600 if a.hours else 0
    records = [r for r in read_log(cfg.audit_path) if r.get("ts", 0) >= since]
    lines = export(records, a.format, a.raw)
    if a.output:
        with open(a.output, "w", encoding="utf-8", newline="\n") as fh:
            for line in lines:
                fh.write(line + "\n")
        print(f"Wrote {len(records)} records to {a.output}.")
    else:
        for line in lines:
            print(line)
    return EXIT_OK


def cmd_run(a) -> int:
    from .gateway import Gateway, serve_stdio
    cfg = _cfg(a)
    setup_logging(a.log_level or cfg.log_level, cfg.log_file)
    log = logging.getLogger("mcpguard")
    if cfg.dashboard_enabled:
        from .dashboard import start_background
        if start_background(cfg):
            log.warning("dashboard at http://127.0.0.1:%d", cfg.dashboard_port)
        else:
            log.warning("dashboard port %d is in use; continuing without it", cfg.dashboard_port)
    async def main() -> None:
        stop = asyncio.Event()
        install_stop_handlers(stop)
        watch_parent(stop)
        await serve_stdio(Gateway(cfg, require_trusted_reload=True), stop=stop)

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
    _leave_stdin_thread()
    return EXIT_OK


def _leave_stdin_thread() -> None:
    """The stdin reader is a daemon thread blocked in a read. If we were stopped by a signal (not
    by stdin closing) it is still blocked, and Python aborts at exit trying to lock stdin. Flush
    and leave without finalizing, which is safe here: state is saved and servers are stopped."""
    import threading
    if any(t.name == "mcpguard-stdin" and t.is_alive() for t in threading.enumerate()):
        for stream in (sys.stdout, sys.stderr):
            with contextlib.suppress(Exception):
                stream.flush()
        logging.shutdown()
        os._exit(EXIT_OK)


def cmd_serve(a) -> int:
    from .gateway import Gateway
    from .httpserve import ServeError, serve_http
    cfg = _cfg(a)
    setup_logging(a.log_level or cfg.log_level, cfg.log_file)
    if cfg.dashboard_enabled:
        from .dashboard import start_background
        start_background(cfg)
    host, port = a.host or cfg.http_host, a.port if a.port is not None else cfg.http_port

    async def main() -> None:
        stop = asyncio.Event()
        install_stop_handlers(stop)
        await serve_http(Gateway(cfg, require_trusted_reload=True), host, port, cfg.http_path, stop=stop)

    try:
        with contextlib.suppress(KeyboardInterrupt):
            asyncio.run(main())
    except ServeError as e:
        raise CliError(str(e)) from e
    except OSError as e:
        raise CliError(f"cannot listen on {host}:{port}: {e.strerror or e}") from e
    return EXIT_OK


def cmd_policy_test(a) -> int:
    """Check policy decisions (and optionally detector findings) against expectations."""
    import tomllib
    cfg = _cfg(a)
    try:
        cases = tomllib.loads(Path(a.file).read_text(encoding="utf-8")).get("case", [])
    except FileNotFoundError as e:
        raise CliError(f"test file not found: {a.file}") from e
    except (tomllib.TOMLDecodeError, RecursionError) as e:
        raise CliError(f"{a.file}: {e}") from e
    if not cases:
        raise CliError(f"{a.file} has no [[case]] entries")
    engine = Engine(cfg.detectors)
    failures = 0
    for i, case in enumerate(cases, 1):
        target = str(case.get("call", ""))
        args = case.get("args")
        client = case.get("client", "stdio")
        label = case.get("name") or f"{target}{' as ' + client if client != 'stdio' else ''}"
        problems = []
        if not target:
            problems.append("missing 'call'")
        else:
            got = cfg.policy.evaluate(target, args, client)
            if "expect" in case and got.action != case["expect"]:
                problems.append(f"expected {case['expect']}, got {got.action} ({got.reason})")
            if "visible" in case and cfg.policy.visible(target, client) != case["visible"]:
                problems.append(f"expected visible={case['visible']}")
            if "expect_findings" in case:
                rules = {f.rule for f in engine.scan_args(target, args or {})}
                missing = set(case["expect_findings"]) - rules
                if missing:
                    problems.append(f"missing findings: {', '.join(sorted(missing))}")
        failures += bool(problems)
        status = "FAIL" if problems else "ok  "
        print(f"{status} {i:>3}. {label}" + ("".join(f"\n          {p}" for p in problems)))
    print(f"\n{len(cases) - failures} passed, {failures} failed")
    return EXIT_ERROR if failures else EXIT_OK


def cmd_dashboard(a) -> int:
    from .dashboard import make_server
    cfg = _cfg(a)
    try:
        srv = make_server(cfg, a.port)
    except OSError as e:
        raise CliError(f"cannot listen on port {a.port or cfg.dashboard_port}: {e.strerror}") from e
    print(f"Dashboard at http://127.0.0.1:{srv.server_address[1]}  (Ctrl+C to stop)")
    with contextlib.suppress(KeyboardInterrupt):
        srv.serve_forever()
    return EXIT_OK


def cmd_open(a) -> int:
    """Open the dashboard in the browser: use the running one, or start it (the double-click path)."""
    import socket
    import webbrowser
    from .dashboard import make_server
    cfg = _cfg(a)
    port = a.port or cfg.dashboard_port
    url = f"http://127.0.0.1:{port}"
    with socket.socket() as probe:
        probe.settimeout(0.5)
        running = probe.connect_ex(("127.0.0.1", port)) == 0
    if running:
        print(f"The dashboard is already running. Opening {url}")
        if not a.no_browser:
            webbrowser.open(url)
        return EXIT_OK
    try:
        srv = make_server(cfg, port)
    except OSError as e:
        raise CliError(f"cannot listen on port {port}: {e.strerror}") from e
    print(f"Dashboard at {url}. Leave this window open; close it or press Ctrl+C to stop.")
    if not a.no_browser:
        webbrowser.open(url)
    with contextlib.suppress(KeyboardInterrupt):
        srv.serve_forever()
    return EXIT_OK


def cmd_check(a) -> int:
    cfg = _cfg(a)
    print(f"{cfg.source}: valid")
    for w in cfg.warnings:
        print(f"  warning: {w} - mcpguard ignores it")
    print(f"  mode          {cfg.mode}")
    print(f"  approvals     {cfg.approval_mode} (timeout {cfg.approval_timeout:.0f}s)")
    print(f"  dashboard     {f'http://127.0.0.1:{cfg.dashboard_port}' if cfg.dashboard_enabled else 'off'}")
    print(f"  audit log     {cfg.audit_path} ({'signed' if cfg.audit_sign else 'unsigned'})")
    print(f"  alerts        {'webhook configured' if cfg.alert_url else 'off'}")
    print(f"  http serve    http://{cfg.http_host}:{cfg.http_port}{cfg.http_path}")
    if cfg.clients:
        print(f"\nClients ({len(cfg.clients)})")
        for c in cfg.clients:
            state = "token set" if c.token else f"{c.token_env} NOT SET"
            print(f"  {c.name:<16} {state}")
    print(f"\nServers ({len(cfg.servers)})")
    for s in cfg.servers:
        target = s.url if s.kind == "http" else " ".join([s.command, *s.args])
        flag = "" if s.enabled else "  [disabled]"
        print(f"  {s.name:<16} {s.kind:<5} {target}{flag}")
    if not cfg.servers:
        print("  none: add a [servers.<name>] section")
    from . import advisories
    for sv in cfg.servers:
        for f in advisories.check_launch(sv.name, sv.command, sv.args, sv.url) if sv.enabled else []:
            print(f"  {f.severity}: server '{sv.name}': {printable(f.message)}")
    for note in _exposure_notes(cfg):
        print(f"  note: {note}")
    print(f"\nPolicy rules ({len(cfg.policy.rules)}, first match wins; default {cfg.policy.default})")
    for i, r in enumerate(cfg.policy.rules, 1):
        cond = f"  when {r['args']}" if "args" in r else ""
        if "clients" in r:
            cond += f"  for {', '.join(r['clients'])}"
        print(f"  {i:>2}. {r['action']:<5} {r['match']}{cond}")
    if cfg.detectors.rules or cfg.detectors.plugins:
        nr, np_ = len(cfg.detectors.rules), len(cfg.detectors.plugins)
        print(f"\nCustom detectors: {nr} rule{'s' * (nr != 1)}, {np_} plugin{'s' * (np_ != 1)}")
    return EXIT_OK


def _exposure_notes(cfg: Config) -> list[str]:
    """Settings that leave more open than most people intend."""
    notes = []
    if cfg.approval_mode == "allow":
        notes.append("approvals.mode = \"allow\" grants every approval request automatically; "
                     "no person is asked")
    if cfg.policy.default == "allow" and not cfg.policy.ask_sensitive and not cfg.policy.rules:
        notes.append("every tool is allowed without approval (default allow, no rules); set "
                     "[policy] ask_sensitive = true to be asked before tools that write, run or send")
    notes.extend(f"server '{sv.name}' runs unsandboxed with no allowed_paths: it can read whatever "
                 "your account can"
                 for sv in cfg.servers if sv.enabled and sv.kind == "stdio" and not sv.sandbox and not sv.allowed_paths)
    return notes


def cmd_explain(a) -> int:
    """Show which rule decides a call, and what the detectors make of the arguments."""
    cfg = _cfg(a)
    try:
        args = json.loads(a.args) if a.args else None
    except json.JSONDecodeError as e:
        raise CliError(f"--args is not valid JSON: {e.msg}") from e
    if args is not None and not isinstance(args, dict):
        raise CliError("--args must be a JSON object")
    target = a.target.replace("__", "/", 1) if "/" not in a.target else a.target
    d = cfg.policy.evaluate(target, args, a.client)
    who = f" for client {a.client}" if a.client != "stdio" else ""
    print(f"{target}{who}: {d.action}  ({d.reason})")
    if args is None and any("args" in r for r in cfg.policy.rules):
        print("  Some rules depend on arguments; pass --args '{...}' to evaluate them.")
    if not cfg.policy.visible(target, a.client):
        print("  This tool is hidden from the model.")
    if args:
        findings = Engine(cfg.detectors).scan_args(target, args)
        for f in findings:
            blocks = SEVERITIES[f.severity] >= SEVERITIES[cfg.policy.block_severity]
            print(f"  {f.severity:<8} {f.rule}: {f.message}{'  (blocks)' if blocks else ''}")
    return EXIT_OK


async def _inspect(spec: ServerSpec) -> tuple[dict, list, list, list]:
    up = make_upstream(spec)
    try:
        await up.start()
        tools = await up.list_tools()
        prompts = await up.list_all("prompts/list", "prompts") if up.supports("prompts") else []
        resources = await up.list_all("resources/list", "resources") if up.supports("resources") else []
    except (OSError, ConnectionError, TimeoutError) as e:
        raise CliError(f"could not inspect {spec.name}: {e}") from e
    finally:
        await up.stop()
    return up.server_info, tools, prompts, resources


def _definition_findings(engine: Engine, server: str, tools: list, prompts: list, resources: list) -> list:
    findings = [f for t in tools for f in engine.scan_definition(t, server)]
    findings += [f for p in prompts for f in engine.scan_definition(p, server, "prompt")]
    findings += [f for r in resources for f in engine.scan_definition(r, server, "resource")]
    return findings


async def _scan_all(cfg, engine: Engine, as_json: bool) -> int:
    """Every enabled server from the config, plus the checks that need them side by side."""
    from .checks import cross_server_names
    from .detect import cross_tool_references
    servers = [s for s in cfg.servers if s.enabled]
    if not servers:
        raise CliError("no enabled servers in the config")
    results = await asyncio.gather(*(_inspect(s) for s in servers), return_exceptions=True)
    report, findings, by_server = [], [], {}
    for spec, res in zip(servers, results, strict=True):
        if isinstance(res, BaseException):
            report.append({"server": spec.name, "error": str(res)})
            continue
        _info, tools, prompts, resources = res
        by_server[spec.name] = tools
        findings += _definition_findings(engine, spec.name, tools, prompts, resources)
        report.append({"server": spec.name, "tools": len(tools), "prompts": len(prompts),
                       "resources": len(resources)})
    findings += engine.finalize(cross_server_names({k: [t["name"] for t in v] for k, v in by_server.items()})
                                + cross_tool_references(by_server))
    findings.sort(key=lambda f: -SEVERITIES[f.severity])
    worst = max_severity(findings)
    failed = [r for r in report if "error" in r]
    if as_json:
        print(json.dumps({"servers": report, "findings": [f.to_dict() for f in findings],
                          "max_severity": worst}, indent=2))
    else:
        for r in report:
            print(f"  {r['server']}: " + (f"FAILED ({r['error']})" if "error" in r else
                                          f"{r['tools']} tools, {r['prompts']} prompts, {r['resources']} resources"))
        if not findings:
            print("\nNo findings.")
        else:
            print(f"\n{len(findings)} finding{'s' if len(findings) != 1 else ''}")
            for f in findings:
                print(f"  {f.severity:<8} {f.rule}  {printable(f.message)}\n           at {printable(f.where)}")
    if worst in ("high", "critical"):
        return EXIT_FINDINGS
    return EXIT_ERROR if failed else EXIT_OK


async def _scan(spec: ServerSpec, engine: Engine, as_json: bool) -> int:
    info, tools, prompts, resources = await _inspect(spec)
    findings = _definition_findings(engine, "target", tools, prompts, resources)
    findings.sort(key=lambda f: -SEVERITIES[f.severity])
    worst = max_severity(findings)
    if as_json:
        print(json.dumps({"server": info,
                          "tools": [{"name": t["name"], "fingerprint": fingerprint_tool(t)} for t in tools],
                          "prompts": len(prompts), "resources": len(resources),
                          "findings": [f.to_dict() for f in findings], "max_severity": worst}, indent=2))
    else:
        name = info.get("name", "server")
        print(f"{name}: {len(tools)} tools, {len(prompts)} prompts, {len(resources)} resources")
        width = max((len(t["name"]) for t in tools), default=10)
        for t in tools:
            print(f"  {printable(t['name']):<{width}}  {fingerprint_tool(t)[:12]}")
        if not findings:
            print("\nNo findings.")
        else:
            print(f"\n{len(findings)} finding{'s' if len(findings) != 1 else ''}")
            for f in findings:
                print(f"  {f.severity:<8} {f.rule}  {printable(f.message)}\n           at {printable(f.where)}")
    return EXIT_FINDINGS if worst in ("high", "critical") else EXIT_OK


def cmd_scan(a) -> int:
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if a.all:
        if cmd or a.url:
            raise CliError("--all scans the servers in the config; do not also give a command or --url")
        return asyncio.run(_scan_all(_cfg(a), _engine(a), a.json))
    if a.url:
        spec = ServerSpec("target", url=a.url, bearer_env=a.bearer_env or "", timeout=a.timeout)
    elif cmd:
        spec = ServerSpec("target", cmd[0], cmd[1:], timeout=a.timeout)
    else:
        raise CliError("give a server command after '--', --url, or --all")
    return asyncio.run(_scan(spec, _engine(a), a.json))


def cmd_test(a) -> int:
    text = sys.stdin.buffer.read().decode("utf-8", "replace") if a.text == "-" else a.text
    engine = _engine(a)
    scans = {
        "definition": lambda: engine.scan_definition({"name": "sample", "description": text}),
        "args": lambda: engine.scan_args("sample", {"value": text}),
        "result": lambda: engine.scan_texts("sample", [text]),
    }
    scopes = list(scans) if a.scope == "all" else [a.scope]
    seen: dict[tuple[str, str], tuple] = {}
    for scope in scopes:
        for f in scans[scope]():
            key = (f.rule, f.message)
            seen.setdefault(key, (f, []))[1].append(scope)
    findings = sorted((f for f, _ in seen.values()), key=lambda f: -SEVERITIES[f.severity])
    for f in findings:
        where = f"  [{', '.join(seen[(f.rule, f.message)][1])}]" if a.scope == "all" else ""
        print(f"{f.severity:<8} {f.rule}  {f.message}{where}")
    cfg = load_config(a.config) if Path(a.config).exists() else None
    dlp_cfg = cfg.dlp if cfg else None
    from . import dlp as _dlp
    data_found = False
    for m in _dlp.find(text):
        if dlp_cfg is None or dlp_cfg.enabled:
            res = (dlp_cfg.results if dlp_cfg else _dlp.DEFAULT_RESULTS)[m.cls.name]
            out = (dlp_cfg.outbound if dlp_cfg else _dlp.DEFAULT_OUTBOUND)[m.cls.name]
            ending = f" ending {_dlp.normalise(m.value)[-4:]}" if m.cls.name not in ("email", "phone") else ""
            print(f"{'data':<8} dlp.{m.cls.name}  {m.cls.label}{ending}: "
                  f"in a result -> {res}; sent to an email/HTTP tool -> {out}")
            data_found = True
    if engine.model is not None:
        p = engine.model.score(text)
        print(f"\nClassifier: {p:.0%} likely to contain injected instructions "
              f"(warns at {engine.cfg.model_medium or engine.model.medium:.0%}, "
              f"blocks results at {engine.cfg.model_high or engine.model.high:.0%}).")
    if not findings and not data_found:
        print("No findings.")
    redacted = engine.redact(text)
    if redacted != text:
        print(f"\nWith secrets redacted: {redacted}")
    return EXIT_OK


def cmd_checks(a) -> int:
    """List every detection rule with its scope and default severity."""
    from .checks import CATALOG
    cfg = load_config(a.config) if Path(a.config).exists() else None
    overrides = cfg.detectors.severity_overrides if cfg else {}
    suppressed = {s.get("rule") for s in cfg.detectors.suppress} if cfg else set()
    width = max(len(c.rule) for c in CATALOG)
    print(f"{'Rule':<{width}}  {'Checks':<19} {'Severity':<16} What it catches")
    for c in CATALOG:
        sev = overrides.get(c.rule, c.severity)
        note = "  (suppressed)" if c.rule in suppressed else ""
        print(f"{c.rule:<{width}}  {c.scope:<19} {sev:<16} {c.summary}{note}")
    if cfg and cfg.detectors.rules:
        print(f"\nPlus {len(cfg.detectors.rules)} custom rule(s) from {Path(cfg.source).name}.")
    print("\nChange a severity with [detectors.severity_overrides]; silence a rule with [[detectors.suppress]].")
    return EXIT_OK


def cmd_iocs(a) -> int:
    from .iocs import BUNDLED_FEED, IocFeed, build, evaluate, load_feeds, make_scorer, read_corpus
    if a.action == "show":
        cfg = load_config(a.config) if Path(a.config).exists() else None
        extra = cfg.detectors.ioc_feeds if cfg else []
        feed = load_feeds(extra)
        bundled = IocFeed.load(BUNDLED_FEED)
        print(f"Bundled feed: {len(bundled)} indicators from {len(bundled.sources)} sources "
              f"({bundled.stats.get('malicious', '?')} malicious, {bundled.stats.get('benign', '?')} benign records)")
        for p in extra:
            print(f"Extra feed:   {p}")
        print(f"\n  {'fingerprints':<14}{len(feed.fingerprints):>6}  exact known-malicious texts")
        print(f"  {'shingles':<14}{len(feed.shingles):>6}  hashed 5-word fragments of attack payloads")
        print(f"  {'phrases':<14}{len(feed.phrases):>6}  wording seen only in attacks")
        print(f"  {'domains':<14}{len(feed.domains):>6}  {', '.join(sorted(feed.domains)[:5])}"
              + (" ..." if len(feed.domains) > 5 else ""))
        print(f"  {'tool names':<14}{len(feed.tool_names):>6}  names used only by malicious tools")
        print(f"  {'parameters':<14}{len(feed.param_names):>6}  {', '.join(sorted(feed.param_names))}")
        if a.verbose:
            print("\nTop phrases (number of distinct attack tools using them):")
            for p, n in sorted(feed.phrases.items(), key=lambda x: -x[1])[:25]:
                print(f"  {n:>3}  {p}")
        print(f"\nSources: {', '.join(feed.sources)}")
        return EXIT_OK
    if not a.corpus:
        raise CliError(f"'iocs {a.action}' needs a corpus file (JSONL); see scripts/ioc/build_corpus.py")
    try:
        records = read_corpus(a.corpus)
    except (OSError, ValueError) as e:
        raise CliError(str(e)) from e
    if a.action == "build":
        if not a.out:
            raise CliError("give an output file with -o")
        feed = build(records)
        feed.save(a.out)
        print(f"Wrote {a.out}: {len(feed)} indicators from {feed.stats['malicious']} malicious and "
              f"{feed.stats['benign']} benign records ({feed.stats['malicious_without_payload']} malicious records "
              "had no text payload, e.g. renamed copies of genuine tools).")
        print(f"Use it with:  [detectors.iocs] feeds = [\"{a.out}\"]")
        return EXIT_OK
    print(f"Building from part of the corpus and testing on unseen tools ({a.level} findings and above).\n")
    print(f"{'split':<8}{'detectors only':>22}{'detectors + IOCs':>22}{'false alarms':>16}")
    for seed in (7, 11, 23):
        detectors_only = make_scorer(a.level)
        base = evaluate(records, lambda feed, r, score=detectors_only: score(IocFeed(), r), seed=seed)
        full = evaluate(records, make_scorer(a.level), seed=seed)
        print(f"{seed:<8}{base.detected:>8}/{base.malicious:<4}{base.recall:>8.1%}  "
              f"{full.detected:>8}/{full.malicious:<4}{full.recall:>8.1%}  "
              f"{full.false_positives:>6}/{full.benign:<4}{full.fp_rate:>5.1%}")
    full = evaluate(records, make_scorer(a.level), seed=7)
    print("\nBy attack category (split 7):")
    for cat, (hit, n) in sorted(full.by_category.items(), key=lambda x: (-x[1][1], x[0])):
        print(f"  {cat:<48}{hit:>4}/{n}")
    return EXIT_OK


def cmd_verify(a) -> int:
    cfg = _cfg(a)
    key = load_key(cfg.audit_key_file) if cfg.audit_sign else None
    ok, msg = verify(cfg.audit_path, key)
    print(("OK  " if ok else "TAMPERED  ") + msg)
    cp_file = a.checkpoints or cfg.checkpoint_path
    if ok and not cp_file:
        print("note: no outside copy of the log head is kept, so deleting the newest records would not be "
              "noticed. Remove checkpoint_path = \"off\" from the [audit] table to turn it on.")
    if ok and cp_file:
        try:
            cps = read_checkpoints(cp_file)
        except FileNotFoundError:
            cps = []
            print(f"no checkpoints yet ({cp_file} does not exist)")
        except ValueError as e:
            raise CliError(f"{cp_file}: {e}") from e
        if cps:
            ok, msg = check_checkpoints(cfg.audit_path, cps, key)
            print(("OK  " if ok else "TAMPERED  ") + msg)
    if ok and Path(cfg.audit_path).exists():
        print(f"head {AuditLog(cfg.audit_path, key=key).head}")
    return EXIT_OK if ok else EXIT_TAMPERED


def cmd_checkpoint(a) -> int:
    cfg = _cfg(a)
    key = load_key(cfg.audit_key_file) if cfg.audit_sign else None
    cp = make_checkpoint(cfg.audit_path, key)
    if cp is None:
        raise CliError("the audit log is empty; nothing to checkpoint")
    target = a.out or cfg.checkpoint_path
    if target:
        append_checkpoint(target, cp)
        print(f"Checkpoint for record {cp['seq']} appended to {target}")
    else:
        print(json.dumps(cp))
    return EXIT_OK


def cmd_stats(a) -> int:
    from .stats import collect, current_state, render
    cfg = _cfg(a)
    print("\n".join(current_state(cfg.state_path)))
    print()
    if not Path(cfg.audit_path).exists():
        print("No audit log yet: nothing has gone through the gateway.")
        return EXIT_OK
    print(render(collect(cfg.audit_path, a.hours), a.hours, a.top))
    return EXIT_OK


def cmd_report(a) -> int:
    cfg = _cfg(a)
    key = load_key(cfg.audit_key_file) if cfg.audit_sign else None
    name = str(a.out).lower() if a.out else ""
    fmt = a.format or ("html" if name.endswith((".html", ".htm")) else "pdf" if name.endswith(".pdf") else "md")
    if fmt == "pdf":
        if not a.out:
            raise CliError("a PDF is a binary file: give a name, for example  -o report.pdf")
        from .pdf import markdown_to_pdf
        Path(a.out).write_bytes(markdown_to_pdf(build_report(cfg.audit_path, key=key)))
        print(f"Wrote {a.out}")
        return EXIT_OK
    text = build_report_html(cfg.audit_path, key=key) if fmt == "html" else build_report(cfg.audit_path, key=key)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"Wrote {a.out}")
    else:
        print(text)
    return EXIT_OK


def cmd_pins(a) -> int:
    cfg = _cfg(a)
    store = PinStore(cfg.pins_path)
    if a.action == "list":
        if not store.pins:
            print("No pins yet. Definitions are pinned the first time the gateway sees them.")
        for k, v in sorted(store.pins.items()):
            print(f"{v[:12]}  {printable(k)}")
    elif a.action == "pending":
        if not store.pending and not store.changed:
            print("Nothing is waiting for review.")
        for key, entry in sorted(store.pending.items()):
            print(f"NEW      {printable(key)}  [{entry.get('fp', '')[:12]}]\n"
                  f"    {printable(entry.get('preview') or '(no description)')}")
        for key in sorted(store.changed):
            print(f"CHANGED  {printable(key)}  (the server now sends a different definition)")
        if store.changed:
            print("\nSee exactly what changed: mcpguard pins diff <server>[/tool]")
        if store.pending or store.changed:
            print("Read them (or run 'mcpguard scan --all'), then: mcpguard pins approve <server>[/tool]")
            print("If you did not expect a change, do NOT approve it: it may be a rug pull.")
    elif a.action == "diff":
        shown = store.diff(a.key or "")
        if not shown:
            print("No changed definitions." if not store.changed else f"No changed definition matches {a.key!r}.")
        for key, lines in shown:
            print(f"== {printable(key)}")
            for ln in lines:
                print("  " + printable(ln))
    elif a.action == "approve":
        if not a.key:
            raise CliError("give a server or a key from 'mcpguard pins pending', for example 'github'")
        keys = store.approve(a.key)
        if not keys:
            raise CliError(f"nothing pending or changed matches {a.key!r}")
        print(f"Approved {len(keys)} definition(s). The gateway picks them up at its next listing.")
    elif a.action == "forget":
        if not a.key or not store.forget(a.key):
            raise CliError("give a key from 'mcpguard pins list', for example 'github/create_issue'")
        print(f"Forgot {a.key}. Its current definition will be trusted the next time it is listed.")
    elif a.action == "reset":
        Path(cfg.pins_path).unlink(missing_ok=True)
        print("All pins cleared. Review your servers: every definition will be trusted on next listing.")
    return EXIT_OK


def cmd_baseline(a) -> int:
    from .anomaly import Baselines
    cfg = _cfg(a)
    if a.action == "reset":
        Path(cfg.baseline_path).unlink(missing_ok=True)
        print("Baselines cleared.")
        return EXIT_OK
    data = Baselines(cfg.baseline_path).summary()
    if not data:
        print("Nothing learned yet.")
    for tool, metrics in sorted(data.items()):
        print(tool)
        for m, v in metrics.items():
            print(f"  {m:<13} n={v['n']:<6} mean={v['mean']:<10} std={v['std']}")
    return EXIT_OK


# ---------------------------------------------------------------- parser

def cmd_claude_desktop(a) -> int:
    from . import desktop
    path = Path(a.file) if a.file else desktop.default_path()
    config = Path(a.config)
    try:
        if a.action == "install":
            was_trusted = _trusted().get(str(config.resolve())) == _digest_of(str(config))
            lines = desktop.install(path, config, a.name, a.take_over)
            if was_trusted:  # --take-over edits the config; keep trusting a file you already trusted
                _set_trust(str(config), True)
            ok = True
        elif a.action == "uninstall":
            lines, ok = desktop.uninstall(path, a.name), True
        else:
            ok, lines = desktop.status(path, config, a.name)
    except desktop.DesktopError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    print("\n".join(lines))
    return EXIT_OK if ok else EXIT_FINDINGS


def cmd_doctor(a) -> int:
    from . import doctor
    checks = doctor.run(Path(a.config), Path(a.desktop_file) if a.desktop_file else None)
    width = max(len(c.name) for c in checks)
    for c in checks:
        print(f"{c.status.upper():5} {c.name:<{width}}  {c.detail}")
    fails = sum(c.status == doctor.FAIL for c in checks)
    warns = sum(c.status == doctor.WARN for c in checks)
    print(f"\n{fails} problem(s), {warns} warning(s)." if fails or warns else "\nEverything looks right.")
    return EXIT_FINDINGS if fails else EXIT_OK


def cmd_mode(a) -> int:
    """Show or switch monitor/enforce without editing the config. Running gateways pick it up in seconds."""
    from .modeswitch import clear_override, read_override, set_override
    cfg = _cfg(a)
    saved = read_override(cfg.approvals_dir)
    if a.choice is None:
        if saved:
            print(f"Mode: {saved['mode']} (set by {printable(saved['by'])}; the config file says {cfg.mode}).")
        else:
            print(f"Mode: {cfg.mode} (from the config file).")
        print("Change it: mcpguard mode monitor | enforce | config   (config = go back to the file's setting)")
        return EXIT_OK
    if a.choice == "config":
        print("Back to the config file's setting." if clear_override(cfg.approvals_dir)
              else "No switch was set; the config file's setting is in use.")
        print(f"Mode now: {cfg.mode}.")
        return EXIT_OK
    set_override(cfg.approvals_dir, a.choice, "cli")
    print(f"Mode set to {a.choice}. Running gateways apply it within a few seconds; no restart or 'trust' needed.")
    if a.choice == "monitor":
        print("Monitor records what would be blocked and lets every call through.")
    return EXIT_OK


def cmd_setup(a) -> int:
    """First-time setup in one command: config (monitor mode), trust, then a health check."""
    import types
    steps = []
    if not Path(a.config).exists():
        cmd_init(types.SimpleNamespace(config=a.config, force=False, profile="monitor"))
        steps.append("created a starter config in monitor mode (nothing is blocked while you learn)")
    else:
        steps.append(f"kept your existing {a.config}")
    risky = _runs_code(a.config)
    already = _trusted().get(str(Path(a.config).resolve())) == _digest_of(str(a.config))
    if risky and not already and "created a starter config" not in steps[0]:
        # A config you did not just make here can start programs. Reading it comes before trusting it.
        print(f"{Path(a.config).resolve()} is not trusted yet and it {' and '.join(risky)}.\n"
              "Read it first. If it is yours, run:  mcpguard trust   then run setup again.")
        return EXIT_ERROR
    if not already:
        cmd_trust(types.SimpleNamespace(config=a.config, forget=False))
    steps.append("trusted the config")
    if a.claude_desktop:
        from . import desktop
        lines = desktop.install(desktop.default_path(), Path(a.config), "guarded", True)
        print("\n".join(lines))
        steps.append("connected Claude Desktop (its old servers moved into the config; a backup was kept)")
    print("\nDone: " + "; ".join(steps) + ".\n\nHealth check:")
    code = cmd_doctor(types.SimpleNamespace(config=a.config, desktop_file=None))
    print("\nNext:\n  1. Edit mcpguard.toml if needed, then run: mcpguard check && mcpguard trust"
          "\n  2. Quit Claude Desktop from the tray icon (not just the window) and open it again"
          "\n  3. Use it normally; look at: mcpguard stats   and   mcpguard dashboard"
          "\n  4. After a few days with no surprises, set mode = \"enforce\" (see docs/USER-GUIDE.md)")
    return code


def cmd_audit_new(a) -> int:
    from .audit import archive
    cfg = _cfg(a)
    key = load_key(cfg.audit_key_file) if cfg.audit_sign else None
    try:
        dest = archive(cfg.audit_path, key, a.reason)
    except PermissionError as e:
        raise CliError("the audit log is append-only and cannot be moved. Run 'mcpguard audit-unprotect' "
                       "first (administrator rights may be needed)") from e
    if cfg.checkpoint_path and Path(cfg.checkpoint_path).exists() and Path(dest).is_dir():
        # Checkpoints describe the old log; against the new one they would read as truncation.
        with contextlib.suppress(OSError):
            shutil.move(cfg.checkpoint_path, Path(dest) / "checkpoints.jsonl")
    first = read_log(cfg.audit_path)[-1]
    if first.get("archived"):
        print(f"Moved the old log to {dest}")
        print(("Old log: " if first["previous_verified"] else "Old log FAILED verification: ")
              + first["previous_result"])
    print(f"New log started at {cfg.audit_path}. A running gateway continues in the new log.")
    return EXIT_OK


def _log_files(cfg: Config) -> list[Path]:
    from .audit import segments
    files = [*segments(cfg.audit_path)]
    if cfg.checkpoint_path:
        files.append(Path(cfg.checkpoint_path))
    return files


def cmd_audit_protect(a) -> int:
    from . import protect
    cfg = _cfg(a)
    enable = a.command == "audit-protect"
    try:
        lines = protect.set_append_only(_log_files(cfg), enable)
    except protect.ProtectError as e:
        raise CliError(str(e)) from e
    print("\n".join(lines))
    if enable:
        print("The log can now only be added to. Before 'mcpguard audit-new' or log rotation, run "
              "'mcpguard audit-unprotect'.")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="mcpguard", description="Security gateway for MCP servers.")
    ap.add_argument("-c", "--config", default=None,
                    help="config file (default: $MCPGUARD_CONFIG, else mcpguard.toml in the current folder)")
    ap.add_argument("--version", action="version", version=f"mcpguard {__version__}")
    sub = ap.add_subparsers(dest="command", required=True, metavar="command")

    p = sub.add_parser("init", help="create a starter config")
    p.add_argument("--force", action="store_true", help="overwrite an existing file")
    p.add_argument("--profile", choices=["balanced", "strict", "monitor"], default="balanced",
                   help="balanced: block high findings (default); strict: unknown tools need approval and "
                        "medium findings block; monitor: record only, block nothing")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("trust", help="trust the config in this folder (needed once for a config that starts "
                                     "servers or loads plugins and is not named with -c)")
    p.add_argument("--forget", action="store_true", help="stop trusting it")
    p.set_defaults(fn=cmd_trust)

    sub.add_parser("selftest", help="check that this install and config stop known attacks "
                                     "(no servers started)").set_defaults(fn=cmd_selftest)

    p = sub.add_parser("advisories", help="known MCP incidents and CVEs, and whether this setup stops each one")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("-v", "--verbose", action="store_true", help="show how mcpguard responds to each")
    p.set_defaults(fn=cmd_advisories)

    p = sub.add_parser("audit-configs", help="check the MCP and AI-tool config files in a project folder "
                                             "before opening it (exits 2 on risky commands)")
    p.add_argument("paths", nargs="*", help="folders to check (default: the current folder)")
    p.set_defaults(fn=cmd_audit_configs)

    p = sub.add_parser("export", help="export the audit log as JSON lines, CSV or CEF (for a SIEM)")
    p.add_argument("--format", choices=["jsonl", "csv", "cef"], default="jsonl")
    p.add_argument("--hours", type=float, default=0, help="only the last N hours (default: everything)")
    p.add_argument("-o", "--output", help="write to this file instead of the terminal")
    p.add_argument("--raw", action="store_true", help="jsonl only: keep the hash-chain and signature fields")
    p.set_defaults(fn=cmd_export)

    p = sub.add_parser("run", help="run the gateway (point your MCP client at this)")
    p.add_argument("--log-level", choices=["debug", "info", "warning", "error"])
    p.set_defaults(fn=cmd_run)

    sub.add_parser("check", help="validate the config and summarise it").set_defaults(fn=cmd_check)

    p = sub.add_parser("serve", help="serve MCP clients over HTTP instead of stdio")
    p.add_argument("--host", help="address to bind (default from [http], usually 127.0.0.1)")
    p.add_argument("--port", type=int, help="port (default from [http], usually 8766)")
    p.add_argument("--log-level", choices=["debug", "info", "warning", "error"])
    p.set_defaults(fn=cmd_serve)

    p = sub.add_parser("policy-test", help="check policy decisions against a test file")
    p.add_argument("file", help="TOML file of [[case]] entries")
    p.set_defaults(fn=cmd_policy_test)

    p = sub.add_parser("explain", help="show how policy treats a tool call")
    p.add_argument("target", help="server/tool, server/prompt:<name> or server/resource:<uri>")
    p.add_argument("--args", help="call arguments as a JSON object")
    p.add_argument("--client", default="stdio", help="client name for client-specific rules")
    p.set_defaults(fn=cmd_explain)

    p = sub.add_parser("dashboard", help="run the dashboard on its own")
    p.add_argument("--port", type=int)
    p.set_defaults(fn=cmd_dashboard)

    p = sub.add_parser("scan", help="inspect a server's (or every configured server's) definitions without running it")
    p.add_argument("--all", action="store_true",
                   help="scan every server in the config together, including cross-server checks")
    p.add_argument("--url", help="Streamable HTTP endpoint instead of a command")
    p.add_argument("--bearer-env", help="environment variable holding a bearer token for --url")
    p.add_argument("--timeout", type=float, default=30.0, help="seconds to wait for the server (default 30)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("cmd", nargs=argparse.REMAINDER, help="-- <command> [args...]")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("test", help="run the detectors on a piece of text")
    p.add_argument("text", help="text to check, or - to read stdin")
    p.add_argument("--scope", choices=["all", "definition", "args", "result"], default="all",
                   help="check the text as a tool description, call arguments, a tool result, or all three")
    p.set_defaults(fn=cmd_test)

    sub.add_parser("checks", help="list every detection rule").set_defaults(fn=cmd_checks)

    p = sub.add_parser("iocs", help="show, build or evaluate indicator-of-compromise feeds")
    p.add_argument("action", choices=["show", "build", "eval"], nargs="?", default="show")
    p.add_argument("corpus", nargs="?", help="labelled JSONL corpus (for build and eval)")
    p.add_argument("-o", "--out", help="output feed file (for build)")
    p.add_argument("--level", choices=["medium", "high"], default="high", help="severity that counts as detected")
    p.add_argument("-v", "--verbose", action="store_true", help="also list the top phrases")
    p.set_defaults(fn=cmd_iocs)

    p = sub.add_parser("open", help="open the dashboard in your browser (starts it if it is not running)")
    p.add_argument("--port", type=int, default=None, help="dashboard port (default: from the config)")
    p.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    p.set_defaults(fn=cmd_open)

    p = sub.add_parser("mode", help="show or switch monitor/enforce (also a switch in the dashboard)")
    p.add_argument("choice", nargs="?", choices=["monitor", "enforce", "config"],
                   help="monitor or enforce; config goes back to the config file's mode")
    p.set_defaults(fn=cmd_mode)

    p = sub.add_parser("setup", help="first-time setup in one step: config, trust and a health check")
    p.add_argument("--claude-desktop", action="store_true",
                   help="also connect Claude Desktop (moves its existing servers into the config)")
    p.set_defaults(fn=cmd_setup)

    p = sub.add_parser("doctor", help="check the config, servers, dashboard port, audit log and Claude Desktop")
    p.add_argument("--desktop-file", help="claude_desktop_config.json to check (default: the usual place)")
    p.set_defaults(fn=cmd_doctor)

    p = sub.add_parser("claude-desktop", help="connect the gateway to Claude Desktop (install, status, uninstall)")
    p.add_argument("action", choices=["install", "status", "uninstall"], nargs="?", default="status")
    p.add_argument("--file", help="claude_desktop_config.json (default: the usual place for this OS)")
    p.add_argument("--name", default="guarded", help="name of the entry (default: guarded)")
    p.add_argument("--take-over", action="store_true",
                   help="also move the servers Claude Desktop runs directly behind the gateway")
    p.set_defaults(fn=cmd_claude_desktop)

    p = sub.add_parser("stats", help="summarise recent calls, blocks, approvals and findings from the audit log")
    p.add_argument("--hours", type=float, default=24.0, help="how far back (default 24)")
    p.add_argument("--top", type=int, default=10, help="rows per table (default 10)")
    p.set_defaults(fn=cmd_stats)

    p = sub.add_parser("verify", help="check the audit log for tampering")
    p.add_argument("--checkpoints", help="checkpoint file to confirm (default: [audit] checkpoint_path)")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("audit-new", help="archive the audit log (for example after a failed verify) and start fresh")
    p.add_argument("--reason", default="", help="recorded in the first record of the new log")
    p.set_defaults(fn=cmd_audit_new)

    p = sub.add_parser("audit-protect", help="make the audit log append-only (needs administrator rights on Linux)")
    p.set_defaults(fn=cmd_audit_protect)
    p = sub.add_parser("audit-unprotect", help="remove the append-only flag (before audit-new or rotation)")
    p.set_defaults(fn=cmd_audit_protect)

    p = sub.add_parser("checkpoint", help="record the current audit head outside the log")
    p.add_argument("-o", "--out", help="append to this file (default: [audit] checkpoint_path, else print)")
    p.set_defaults(fn=cmd_checkpoint)

    p = sub.add_parser("report", help="write a compliance report (Markdown or HTML)")
    p.add_argument("-o", "--out", help="output file (default: print); .html writes HTML, .pdf writes a PDF")
    p.add_argument("--format", choices=["md", "html", "pdf"],
                   help="report format (default: from the file name, else md)")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("pins", help="list, review, approve or clear trusted definitions")
    p.add_argument("action", choices=["list", "pending", "diff", "approve", "forget", "reset"])
    p.add_argument("key", nargs="?", help="for diff, approve and forget: a server or server/tool")
    p.set_defaults(fn=cmd_pins)

    p = sub.add_parser("baseline", help="show or clear learned per-tool baselines")
    p.add_argument("action", choices=["show", "reset"])
    p.set_defaults(fn=cmd_baseline)
    return ap


def _quiet_windows_pipe_noise() -> None:
    """On Windows, Python's asyncio prints a scary traceback when a finished child process's pipe is
    cleaned up ('I/O operation on closed pipe'). It is harmless and means nothing; hide only that."""
    previous = sys.unraisablehook

    def hook(unraisable) -> None:
        text = f"{unraisable.exc_value}"
        if "closed pipe" in text and "Proactor" in repr(unraisable.object):
            return
        previous(unraisable)

    sys.unraisablehook = hook


def main(argv: list[str] | None = None) -> int:
    # On Windows, output redirected to a file or pipe uses the ANSI code page; never crash
    # printing a tool name or description that it cannot represent.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="backslashreplace")
    _quiet_windows_pipe_noise()
    a = build_parser().parse_args(argv)
    a.config_explicit = bool(a.config or os.environ.get("MCPGUARD_CONFIG"))
    a.config = a.config or os.environ.get("MCPGUARD_CONFIG") or "mcpguard.toml"
    try:
        if a.fn not in (cmd_init, cmd_trust, cmd_audit_configs, cmd_selftest, cmd_setup):
            _require_trust(a)
        return a.fn(a)
    except CliError as e:
        print(f"mcpguard: {e}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        # The reader of our output (| head, a closed terminal) went away. That is not an error.
        with contextlib.suppress(OSError):
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_OK
    except KeyboardInterrupt:
        print("mcpguard: interrupted", file=sys.stderr)
        return 130
    except LogDamaged as e:
        print(f"mcpguard: the audit log is damaged ({e}). Run: mcpguard verify", file=sys.stderr)
        return EXIT_ERROR
    except OSError as e:
        print(f"mcpguard: {e.strerror or e}" + (f": {e.filename}" if e.filename else ""), file=sys.stderr)
        return EXIT_ERROR
    except Exception as e:  # last resort: a one-line message, the traceback only on request
        if os.environ.get("MCPGUARD_DEBUG"):
            raise
        print(f"mcpguard: unexpected {type(e).__name__}: {e} (set MCPGUARD_DEBUG=1 for the traceback)",
              file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
