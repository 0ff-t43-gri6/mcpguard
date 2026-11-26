"""Known MCP incidents and CVEs, and what this installation does about each.

``data/advisories.json`` records real campaigns and vulnerabilities (each with its sources).
This module uses it three ways:

* ``check_launch`` / ``check_server_info`` look at how a server is started and what it says it
  is: a package or host named in a campaign is refused, a version with a known CVE is flagged,
  and launch commands that are shells, downloaders or unpinned packages are pointed out.
* ``audit_config_files`` reads the MCP and agent config files inside a project folder, the
  files the Miasma worm and the Cursor "MCPoison" flaw abused, before you open it in an IDE.
* ``coverage`` answers, for every recorded incident, "would this setup stop it?", from the
  controls that are switched on in the config. The dashboard's Threat coverage view shows it.
"""

from __future__ import annotations

import contextlib
import functools
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from .detect import Finding

FEED = Path(__file__).with_name("data") / "advisories.json"

_RUNNERS = {"npx": "npm", "bunx": "npm", "pnpm": "npm", "yarn": "npm", "npm": "npm",
            "uvx": "pypi", "uv": "pypi", "pipx": "pypi", "pip": "pypi", "docker": "image", "podman": "image"}
_SHELLS = {"sh", "bash", "zsh", "dash", "fish", "cmd", "powershell", "pwsh"}
_INLINE = {"node": {"-e", "--eval", "-p", "--print"}, "python": {"-c"}, "python3": {"-c"}, "bun": {"-e", "--eval"},
           "deno": {"eval"}, "ruby": {"-e"}, "perl": {"-e"}}
_DOWNLOADER = re.compile(
    r"(?i)\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|certutil|bitsadmin)\b[^|;&]{0,300}[|;&]"
    r"|\|\s*(?:sh|bash|zsh|iex|python3?|node)\b|-enc(?:odedcommand)?\b|\bfrombase64string\b|\bbase64\s+(?:-d|--decode)\b"
    r"|\biex\s*\(|\bdownloadstring\b")
_VERSION = re.compile(r"\d+(?:\.\d+)*")


@functools.lru_cache(maxsize=1)
def load() -> list[dict]:
    return json.loads(FEED.read_text(encoding="utf-8"))["advisories"]


# ---------------------------------------------------------------- versions and packages

def _vtuple(version: str) -> tuple[int, ...]:
    m = _VERSION.match(version.lstrip("vV="))
    return tuple(int(p) for p in m.group(0).split(".")) if m else ()


def version_in(version: str, spec: str) -> bool:
    """True when ``version`` satisfies every comma-separated clause of ``spec`` (">=1.2,<1.5")."""
    v = _vtuple(version)
    if not v:
        return False
    for clause in spec.split(","):
        m = re.match(r"\s*(>=|<=|<|>|==)\s*(\S+)", clause)
        if not m:
            return False
        op, bound = m.group(1), _vtuple(m.group(2))
        width = max(len(v), len(bound))
        a, b = v + (0,) * (width - len(v)), bound + (0,) * (width - len(bound))
        if not {">=": a >= b, "<=": a <= b, "<": a < b, ">": a > b, "==": a == b}[op]:
            return False
    return True


def _base(command: str) -> str:
    name = PurePosixPath(command.replace("\\", "/")).name.lower()
    return re.sub(r"\.(?:exe|cmd|bat|ps1)$", "", name)


def _split_ref(ref: str, ecosystem: str) -> tuple[str, str]:
    """('name', 'version or ""') from 'name@1.2', '@scope/name@1.2', 'name==1.2' or 'repo/name:1.2'."""
    if ecosystem == "image":
        tail = ref.rsplit("/", 1)[-1]
        name, _, tag = tail.partition(":")
        full = ref.rsplit(":", 1)[0] if ":" in tail else ref
        return full if "/" in ref else name, tag.split("@")[0]
    ref = re.sub(r"^npm:", "", ref)
    m = re.match(r"^(@?[^@=<>~!\s]+?)(?:@|==|>=|~=)([^@=\s]+)$", ref)
    if not m:
        return ref.lower() if eco_lower(ecosystem) else ref, ""
    name, version = m.group(1), m.group(2)
    # "latest", "^0.1.0", "~1.2" and ">=1" are not pins: what runs is decided at start time.
    if not re.match(r"^v?\d", version):
        version = ""
    return (name.lower() if eco_lower(ecosystem) else name), version


def eco_lower(ecosystem: str) -> bool:
    return ecosystem in ("npm", "pypi")  # names there are case-insensitive


_WRAPPERS = {"cmd", "sh", "bash", "zsh", "powershell", "pwsh", "env", "wsl", "sudo", "nohup", "time", "exec",
             "doas", "nice", "stdbuf", "winpty"}


def _unwrap(command: str, args: list[str]) -> tuple[str, list[str]]:
    """The runner hidden behind a wrapper: `cmd /c npx pkg`, `env A=1 npx pkg`, `sh -c "npx pkg"`,
    `docker run image npx pkg`."""
    for _ in range(4):
        base = _base(command)
        words = [w for a in args for w in (a.split() if " " in a and base in _SHELLS else [a])]
        idx = next((i for i, w in enumerate(words) if _base(w) in _RUNNERS and _base(w) not in ("docker", "podman")),
                   None)
        if base in _RUNNERS and base not in ("docker", "podman"):
            return command, args
        if idx is None or (base not in _WRAPPERS and base not in ("docker", "podman")):
            return command, args
        command, args = words[idx], words[idx + 1:]
    return command, args


def packages_in(command: str, args: list[str]) -> list[tuple[str, str, str]]:
    """(ecosystem, name, version) for each package a launch command fetches and runs."""
    if _base(command) in ("docker", "podman"):
        inner_cmd, inner_args = _unwrap(command, args)
        inner = packages_in(inner_cmd, inner_args) if inner_cmd != command else []
        return [*_direct_packages(command, args), *inner]
    command, args = _unwrap(command, args)
    return _direct_packages(command, args)


def _direct_packages(command: str, args: list[str]) -> list[tuple[str, str, str]]:
    eco = _RUNNERS.get(_base(command))
    if not eco:
        return []
    rest = list(args)
    base = _base(command)
    if (base in ("pnpm", "yarn") and rest[:1] == ["dlx"]) or (base == "npm" and rest[:1] == ["exec"]) \
            or (base == "pipx" and rest[:1] == ["run"]):
        rest = rest[1:]
    elif base == "uv" and rest[:2] == ["tool", "run"]:
        rest = rest[2:]
    elif base in ("docker", "podman"):
        if rest[:1] != ["run"]:
            return []
        rest = rest[1:]
    elif base in ("pnpm", "yarn", "npm", "pip", "uv"):
        return []
    out = []
    takes_value = {"-p", "--package", "--from", "--with", "-e", "--env", "-v", "--volume", "--mount", "--name",
                   "--network", "-w", "--workdir", "--python", "--index-url", "--memory", "-u", "--user"}
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--":
            i += 1
            continue
        if a in ("-p", "--package", "--from"):
            if i + 1 < len(rest):
                out.append((eco, *_split_ref(rest[i + 1], eco)))
            i += 2
            continue
        if a.startswith(("--package=", "--from=")):
            out.append((eco, *_split_ref(a.split("=", 1)[1], eco)))
            i += 1
            continue
        if a.startswith("-"):
            i += 2 if a in takes_value else 1
            continue
        if not any(e == eco and n == _split_ref(a, eco)[0] for e, n, _ in out):
            out.append((eco, *_split_ref(a, eco)))
        break  # the first bare word is the thing that runs; what follows are its own arguments
    return out


# ---------------------------------------------------------------- checks on one server

def _finding(rule: str, severity: str, message: str, where: str) -> Finding:
    return Finding(rule, severity, message, where)


def check_launch(name: str, command: str = "", args: list[str] | None = None, url: str = "") -> list[Finding]:
    """What a server's launch command or URL reveals before anything is started."""
    args = args or []
    where = f"servers.{name}"
    out: list[Finding] = []
    line = " ".join([command, *args])
    host = (urlsplit(url).hostname or "").lower() if url else ""
    for adv in load():
        ind = adv.get("indicators", {})
        if host and any(host == h or host.endswith("." + h) for h in ind.get("hosts", [])):
            out.append(_finding("advisory.malicious", "critical",
                                f"this address belongs to a known campaign: {adv['title']}", where))
        if any(s.lower() in line.lower() for s in ind.get("strings", [])) or \
                any(h in line.lower() for h in ind.get("hosts", [])):
            out.append(_finding("advisory.malicious", "critical",
                                f"the launch command matches a known campaign: {adv['title']}", where))
    lowered = line.lower().replace("\\", "/")
    for adv in load():
        for p in adv.get("packages", []):
            named = rf"(?:^|[\s/\"'=:])(?:npm:)?{re.escape(p['name'])}(?:[@/\s\"']|$)"
            if p.get("malicious") and re.search(named, lowered):
                out.append(_finding("advisory.malicious", "critical",
                                    f"package '{p['name']}' is named in a known campaign: {adv['title']}", where))
    base = _base(command) if command else ""
    for eco, pkg, version in packages_in(command, args) if command else []:
        short = pkg.rsplit("/", 1)[-1]
        for adv in load():
            for p in adv.get("packages", []):
                if p.get("library") or p["name"] not in (pkg, short):
                    continue
                if p["ecosystem"] not in (eco, "any"):
                    continue
                if p.get("malicious"):
                    out.append(_finding("advisory.malicious", "critical",
                                        f"package '{pkg}' is named in a known campaign: {adv['title']}", where))
                elif version and p.get("affected") and version_in(version, p["affected"]):
                    out.append(_finding("advisory.vulnerable", "high",
                                        f"{pkg} {version} is affected by {adv['id']} ({adv['title']}); "
                                        f"fixed in {p.get('fixed', 'a later release')}", where))
                elif not version and p.get("affected"):
                    out.append(_finding("advisory.unknown_version", "medium",
                                        f"{pkg} has a known flaw ({adv['id']}) in versions {p['affected']}; pin a "
                                        f"version at or above {p.get('fixed', 'the fix')}", where))
        if not version and eco != "image":
            out.append(_finding("supply_chain.unpinned", "low",
                                f"'{pkg}' is fetched without a version, so every start runs whatever was published "
                                f"last; pin it (for example {pkg}{'==' if eco == 'pypi' else '@'}1.2.3)", where))
        elif eco == "image" and version in ("", "latest"):
            out.append(_finding("supply_chain.unpinned", "low",
                                f"image '{pkg}' has no fixed tag; pin a version or digest", where))
    if command:
        if base in _SHELLS and any(a.lower() in ("-c", "/c", "-command", "-enc", "-encodedcommand") for a in args):
            out.append(_finding("launch.shell", "high",
                                "the server is started through a shell with an inline command; name the program "
                                "and its arguments directly", where))
        if any(a in _INLINE.get(base, ()) for a in args):
            out.append(_finding("launch.inline_code", "high",
                                "the launch command runs code written inline in the config, not an installed "
                                "server", where))
        if _DOWNLOADER.search(line):
            out.append(_finding("launch.downloader", "critical",
                                "the launch command downloads or decodes something and runs it", where))
    seen, unique = set(), []
    for f in out:
        if (f.rule, f.message) not in seen:
            seen.add((f.rule, f.message))
            unique.append(f)
    return unique


def check_server_info(name: str, info: dict | None) -> list[Finding]:
    """What a running server says it is (``serverInfo`` from the initialize reply)."""
    if not isinstance(info, dict):
        return []
    reported, version = str(info.get("name", "")).lower(), str(info.get("version", ""))
    where = f"servers.{name}"
    out = []
    for adv in load():
        if reported and reported in (s.lower() for s in adv.get("indicators", {}).get("server_names", [])):
            out.append(_finding("advisory.malicious", "critical",
                                f"the server identifies itself as '{reported}', the name used in: {adv['title']}",
                                where))
        out.extend(_finding("advisory.vulnerable", "high",
                            f"{reported} {version} is affected by {adv['id']} ({adv['title']}); fixed in "
                            f"{p.get('fixed', 'a later release')}", where)
                   for p in adv.get("packages", [])
                   if not p.get("library") and not p.get("malicious") and p["name"].lower() == reported
                   and p.get("affected") and version_in(version, p["affected"]))
    return out


# ---------------------------------------------------------------- project config files

CONFIG_FILES = (".mcp.json", "mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".vscode/settings.json",
                ".claude/settings.json", ".claude/settings.local.json", ".claude.json", ".gemini/settings.json",
                ".windsurf/mcp_config.json", ".zed/settings.json", ".roo/mcp.json", ".kiro/settings/mcp.json",
                ".amazonq/mcp.json", "claude_desktop_config.json", ".codex/config.toml", "mcpguard.toml",
                ".continue/config.json", ".continue/config.yaml", ".aider.conf.yml")
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox"}
_MAX_CONFIG_BYTES = 2_000_000
_SERVER_KEYS = ("mcpServers", "servers", "mcp_servers", "context_servers", "amp.mcpServers", "mcp.servers")


def _config_files(root: Path, max_depth: int = 4):
    stack = [(root, 0)]
    while stack:
        folder, depth = stack.pop()
        for rel in CONFIG_FILES:
            f = folder / rel
            if f.is_file():
                yield f
        extra = folder / ".continue" / "mcpServers"
        if extra.is_dir():
            with contextlib.suppress(OSError):
                yield from (f for f in extra.iterdir() if f.is_file())
        if depth >= max_depth:
            continue
        try:
            children = [c for c in folder.iterdir() if c.is_dir() and not c.is_symlink()]
        except OSError:
            continue
        stack.extend((c, depth + 1) for c in children if c.name not in _SKIP_DIRS and not c.name.startswith("."))


def _strip_jsonc(text: str) -> str:
    """JSON as editors accept it: // and /* */ comments and trailing commas removed. A poisoned
    config with one comment in it must not become unreadable to the audit while the editor
    that runs it reads it fine."""
    out, i, n, in_string = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_string = False
        elif c == '"':
            in_string = True
            out.append(c)
        elif text.startswith("//", i):
            i = text.find("\n", i)
            if i == -1:
                break
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _read_config(f: Path):
    """(data, raw text) for a config file in JSON, JSON-with-comments or TOML; data is None when
    it cannot be parsed (YAML, or broken)."""
    with f.open("rb") as fh:
        raw = fh.read(_MAX_CONFIG_BYTES)
    for encoding in ("utf-8-sig", "utf-16"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("utf-8", errors="replace")
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16", errors="replace")
    if f.suffix == ".toml":
        import tomllib
        try:
            return tomllib.loads(text), text
        except (tomllib.TOMLDecodeError, RecursionError):
            return None, text
    for candidate in (text, _strip_jsonc(text)):
        try:
            return json.loads(candidate), text
        except (ValueError, RecursionError):
            continue
    return None, text


def _server_entries(data, depth: int = 0):
    """(name, entry) for every MCP server definition, wherever the file keeps them."""
    if not isinstance(data, dict) or depth > 3:
        return
    for key, value in data.items():
        if key in _SERVER_KEYS:
            if isinstance(value, dict):
                yield from ((str(n), e) for n, e in value.items() if isinstance(e, dict))
            elif isinstance(value, list):
                yield from ((str(e.get("name", i)), e) for i, e in enumerate(value) if isinstance(e, dict))
        elif isinstance(value, dict):
            yield from _server_entries(value, depth + 1)


def _launch_of(entry: dict) -> tuple[str, list[str], str]:
    command = entry.get("command", "")
    args = entry.get("args", [])
    if isinstance(command, dict):  # Zed: {"command": {"path": ..., "args": [...]}}
        command, args = command.get("path", ""), command.get("args", args)
    if isinstance(command, list):  # some tools take the whole command line as a list
        command, args = (command[0], command[1:]) if command else ("", [])
    args = [str(a) for a in args] if isinstance(args, list) else []
    url = entry.get("url") or entry.get("serverUrl") or entry.get("httpUrl") or ""
    return str(command), args, str(url)


def _hook_commands(node, path="", depth=0):
    """Every "command" string under a "hooks" key (Claude Code / Gemini CLI settings)."""
    if depth > 40:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "command" and isinstance(v, str) and "hooks" in path:
                yield path, v
            else:
                yield from _hook_commands(v, f"{path}.{k}" if path else k, depth + 1)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _hook_commands(v, f"{path}[{i}]", depth + 1)


def audit_config_files(root: str | Path) -> list[dict]:
    """One entry per MCP/agent config file under ``root``: its servers, hooks and findings."""
    reports = []
    seen: set[Path] = set()
    for f in _config_files(Path(root)):
        if f in seen:
            continue
        seen.add(f)
        report: dict[str, Any] = {"file": str(f), "servers": [], "hooks": [], "findings": []}

        def note(rule: str, severity: str, message: str, where: str, report=report) -> None:
            report["findings"].append(Finding(rule, severity, message, where).to_dict())

        try:
            data, text = _read_config(f)
        except OSError as e:
            note("config.unreadable", "high", f"could not be read ({e}); it cannot be vouched for", str(f))
            reports.append(report)
            continue
        if data is None and f.suffix in (".yaml", ".yml"):
            note("config.unparsed", "medium", "YAML is not parsed here; read this file yourself", str(f))
        elif data is None:
            note("config.unreadable", "high",
                 "could not be parsed, so its commands cannot be checked; an editor may still run them", str(f))
        for name, entry in _server_entries(data):
            command, args, url = _launch_of(entry)
            report["servers"].append({"name": name, "runs": " ".join([command, *args]).strip() or url})
            for fd in check_launch(name, command, args, url):
                fd.where = f"{f}: {name}"
                report["findings"].append(fd.to_dict())
        for where, command in _hook_commands(data):
            report["hooks"].append({"where": where, "runs": command})
            severity = "critical" if _DOWNLOADER.search(command) else "medium"
            note("config.hook", severity,
                 "a hook here runs a command automatically when the project is opened or used"
                 + (", and it downloads or decodes something" if severity == "critical" else ""), f"{f}: {where}")
        if isinstance(data, dict) and f.name == "mcpguard.toml" and (data.get("detectors") or {}).get("plugins"):
            note("config.plugin", "high", "this mcpguard config loads Python plugins: code that runs inside the "
                                          "gateway", f"{f}: detectors.plugins")
        # Safety net for shapes this audit does not know: a download-and-run command anywhere.
        if not any(x["severity"] == "critical" for x in report["findings"]) and _DOWNLOADER.search(text):
            note("launch.downloader", "critical",
                 "the file contains a command that downloads or decodes something and runs it", str(f))
        if report["servers"] or report["hooks"] or report["findings"]:
            reports.append(report)
    return reports


# ---------------------------------------------------------------- coverage

CONTROL_LABELS = {
    "definition_scan": "Tool definitions scanned before the model sees them",
    "pinning": "Definitions pinned; a later change is quarantined",
    "result_scan": "Tool results scanned for injected instructions",
    "dlp_taint": "Secrets and personal data tracked across calls",
    "sandbox": "Local servers run in a container",
    "allowed_paths": "Servers limited to named folders",
    "allowed_hosts": "Servers limited to named hosts",
    "ask_sensitive": "A person approves tools that write, run or send",
    "launch_pinning": "Server packages pinned to a version",
    "launch_audit": "Launch commands checked for shells and downloaders",
    "advisory_match": "Servers checked against known campaigns and CVEs",
    "config_audit": "Project config files audited before opening",
    "config_trusted": "Only servers in mcpguard's own config are started",
    "http_auth": "HTTP clients authenticated; sessions bound to their client",
    "no_oauth_client": "No OAuth discovery towards servers",
    "dashboard_auth": "Dashboard protected by token and Host check",
    "direct_http": "Remote servers reached directly, no helper process",
    "rate_limit": "Per-tool rate limits",
    "redos_guard": "mcpguard's own patterns tested to stay linear",
}
_BUILT_IN = {"launch_audit", "advisory_match", "config_trusted", "http_auth", "no_oauth_client", "dashboard_auth",
             "direct_http", "redos_guard", "pinning"}


def _share(done: int, total: int, what: str) -> tuple[str, str]:
    if total == 0:
        return "na", f"no {what} configured"
    state = "on" if done == total else "partial" if done else "off"
    return state, f"{done} of {total} {what}"


def controls(cfg) -> dict[str, dict]:
    """State of every control for this config: on | partial | off | manual | na."""
    servers = [s for s in cfg.servers if s.enabled]
    local = [s for s in servers if s.kind == "stdio"]
    out: dict[str, dict] = {}

    def put(cid: str, state: str, detail: str, how: str = "") -> None:
        out[cid] = {"id": cid, "label": CONTROL_LABELS[cid], "state": state, "detail": detail, "how": how}

    for cid in _BUILT_IN:
        put(cid, "on", "always on")
    put("definition_scan", "on", f"quarantines at '{cfg.static_block_severity}' and above")
    put("result_scan", "on", f"blocks at '{cfg.policy.block_severity}' and above"
        + ("" if cfg.detectors.model else "; classifier off"))
    put("dlp_taint", "on" if cfg.dlp.enabled else "off",
        "on" if cfg.dlp.enabled else "data leakage prevention is off", "[dlp] enabled = true")
    put("sandbox", *_share(sum(1 for s in local if s.sandbox), len(local), "local servers"),
        "add [servers.<name>.sandbox] with an image and mounts")
    put("allowed_paths", *_share(sum(1 for s in local if s.allowed_paths or s.sandbox), len(local), "local servers"),
        'allowed_paths = ["C:/path/to/project"] under the server')
    put("allowed_hosts", *_share(sum(1 for s in servers if s.allowed_hosts or (s.sandbox and not s.sandbox.network)),
                                 len(servers), "servers"),
        'allowed_hosts = ["api.example.com"] under the server')
    asks = cfg.policy.ask_sensitive or cfg.policy.default in ("ask", "deny")
    if cfg.approval_mode == "allow":
        put("ask_sensitive", "off", 'approvals.mode = "allow" grants every request automatically',
            '[approvals] mode = "dashboard"')
    else:
        put("ask_sensitive", "on" if asks else "partial",
            "on" if asks else "only for tools with an explicit ask rule", "[policy] ask_sensitive = true")
    unpinned = [s.name for s in local
                if any(f.rule == "supply_chain.unpinned" for f in check_launch(s.name, s.command, s.args))]
    fetched = [s for s in local if packages_in(s.command, s.args)]
    put("launch_pinning", *_share(len(fetched) - len(unpinned), len(fetched), "fetched packages pinned"),
        "write the version in the launch command, for example name@1.2.3")
    put("rate_limit", "on" if cfg.policy.rate_limit_per_minute else "off",
        f"{cfg.policy.rate_limit_per_minute} per minute per tool" if cfg.policy.rate_limit_per_minute else "unlimited",
        "[policy] rate_limit_per_minute = 60")
    put("config_audit", "manual", "run before opening a cloned project", "mcpguard audit-configs <folder>")
    return out


def coverage(cfg) -> dict:
    """Every recorded incident with a status for this installation, plus matches on its servers."""
    ctl = controls(cfg)
    matches = []
    for s in cfg.servers:
        if s.enabled:
            matches += [dict(f.to_dict(), server=s.name)
                        for f in check_launch(s.name, s.command, s.args, s.url) if f.rule.startswith("advisory.")]
    rows = []
    for adv in load():
        needed = [ctl[c] for c in adv["controls"] if c in ctl]
        gaps = [c for c in needed if c["state"] in ("off", "partial")]
        hit = [m for m in matches if adv["id"] in m["message"] or adv["title"] in m["message"]]
        # affected: one of your servers matches it. gaps: a control it needs is off here.
        # Otherwise the status is what mcpguard does about it: blocks, limits, detects or outside.
        if hit:
            status = "affected"
        elif adv["verdict"] == "outside":
            status = "outside"
        elif gaps:
            status = "gaps"
        else:
            status = adv["verdict"]
        rows.append({
            "id": adv["id"], "title": adv["title"], "date": adv["date"], "kind": adv["kind"],
            "component": adv["component"], "summary": adv["summary"], "response": adv["note"],
            "verdict": adv["verdict"], "status": status, "caveat": adv.get("caveat", ""),
            "sources": adv.get("sources", []),
            "controls": [{"label": c["label"], "state": c["state"], "detail": c["detail"], "how": c["how"]}
                         for c in needed],
            "matches": hit,
        })
    counts = {k: sum(1 for r in rows if r["status"] == k)
              for k in ("blocks", "limits", "detects", "gaps", "affected", "outside")}
    return {"counts": counts, "advisories": rows, "controls": list(ctl.values()), "matches": matches,
            "mode": cfg.mode, "total": len(rows)}
