"""Configuration: TOML loading and validation.

``load_config`` either returns a fully validated ``Config`` or raises
``ConfigError`` with a message that names the offending key. Detector plugins
are imported during validation, so a broken plugin is caught at load time
rather than on the first request.
"""

from __future__ import annotations

import os
import difflib
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .dlp import DlpConfig
from .net import local_or_https
from .policy import ACTIONS, Policy
from .sandbox import Sandbox
from .sandbox import parse as parse_sandbox

SEVERITIES = ("low", "medium", "high", "critical")
MODES = ("enforce", "monitor")
APPROVAL_MODES = ("tty", "dashboard", "allow", "deny")
SERVER_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
DEFAULT_ALERT_EVENTS = ("call.blocked", "audit.tampered", "*.quarantined", "server.exited", "server.failed",
                        "config.reload_failed", "audit.recovered", "gateway.error")

DEFAULT_CONFIG = """\
# mcpguard configuration. The gateway reloads this file automatically
# when it changes; invalid edits are rejected and the previous version stays active.

# enforce: block according to policy.
# monitor: record what would have been blocked, but let everything through.
mode = "enforce"

[audit]
path = "mcpguard-audit.jsonl"
rotate_bytes = 10_000_000          # start a new segment after ~10 MB (0 = never)
sign = true                        # HMAC-sign records so they cannot be forged without the key
# key_file = "D:/keys/mcpguard-audit.key"   # default: ~/.mcpguard/keys/, away from this folder
# Or set MCPGUARD_AUDIT_KEY (hex) instead of a key file.
# Write the latest record's hash somewhere else on a schedule, so deleting the newest
# records (which a hash chain alone cannot reveal) is caught by 'mcpguard verify'.
# The newest record's hash is copied to an outside file every checkpoint_minutes, so deleting the
# newest records is caught by 'mcpguard verify'. Default: a file in your mcpguard home folder
# (~/.mcpguard/checkpoints). Point it at another disk or a share for more; "off" disables it.
# checkpoint_path = "D:/mcpguard-checkpoints.jsonl"
checkpoint_minutes = 5
# Also send each checkpoint to a server you control (a witness). It holds a copy someone with
# access to this machine cannot reach back and edit.
# witness_url = "https://example.com/mcpguard-witness"
# Send every audit record to a server you control as it is written. A log kept only on this machine
# can be deleted by whoever controls the machine; a copy that already left cannot be.
# forward_url = "https://logs.example.com/mcpguard"
# What to do if the log is edited, cut short or deleted while the gateway runs:
# block = alert and refuse tool calls until you review it (run 'mcpguard verify', then 'mcpguard audit-new');
# warn = alert and carry on.
on_tamper = "block"
verify_minutes = 30                # re-check the whole log this often while running (0 = never)

[pins]
path = "mcpguard-pins.json"
# allow: trust a tool definition the first time it is seen (it is logged as pins.first_seen).
# approve: hold every new definition until you read it with 'mcpguard pins pending' and run
# 'mcpguard pins approve <server>'. Changed definitions are always blocked.
first_seen = "allow"

# [state]
# path = "mcpguard-state.json"     # what the dashboard shows about the running gateway

[approvals]
mode = "dashboard"                 # tty | dashboard | allow | deny
dir = "mcpguard-approvals"
timeout_seconds = 120              # unanswered requests are denied
remember_minutes = 15              # "Allow for 15 minutes" in the dashboard (0 hides it)

[dashboard]
enabled = true
port = 8765                        # http://127.0.0.1:8765

# Data leakage prevention: personal and financial data in tool traffic. Recognisers check
# what they find (Luhn for cards, Verhoeff for Aadhaar, mod-97 for IBAN), so random numbers
# are not reported. Values are never written to the audit log.
#   results:  what tools return to the model                 allow | log | redact
#   outbound: what the model sends to tools that send data out  allow | log | block
[dlp]
enabled = true
track_pii = true                   # block personal data read by one tool and sent out by another

[dlp.results]
credit_card = "redact"             # masked, keeping the last 4 characters
aadhaar = "redact"
us_ssn = "redact"
iban = "log"
india_pan = "log"
email = "allow"
phone = "allow"

[dlp.outbound]
credit_card = "block"
aadhaar = "block"
us_ssn = "block"
iban = "log"
india_pan = "log"
email = "allow"
phone = "allow"

[anomaly]
enabled = true
path = "mcpguard-baseline.json"
min_samples = 20                   # observations before a tool's baseline is used
z_threshold = 4.0

[logging]
level = "warning"                  # debug | info | warning | error  (written to stderr)
# file = "mcpguard.log"

# Send blocks, quarantines and outages to a chat or incident webhook.
# [alerts]
# webhook_url_env = "MCPGUARD_WEBHOOK"
# webhook_url = "https://hooks.slack.com/..."   # or the URL itself
# events = ["call.blocked", "*.quarantined", "server.exited", "server.failed",
#           "config.reload_failed", "audit.recovered", "gateway.error"]
# min_interval_seconds = 10              # events in this window are sent as one message

# Accept MCP clients over HTTP as well (start with: mcpguard serve).
[http]
host = "127.0.0.1"
port = 8766
path = "/mcp"

# Named clients for HTTP mode. Each sends "Authorization: Bearer <token>".
# Rules can then target a client: clients = ["ci-agent"].
# [clients.ci-agent]
# token_env = "MCPGUARD_TOKEN_CI"

[policy]
default = "allow"                  # allow | deny | ask
block_severity = "high"            # runtime findings at or above this block the call
static_block_severity = "high"     # definitions at or above this are quarantined
rate_limit_per_minute = 60         # per tool; 0 = unlimited
max_calls_per_session = 500        # 0 = unlimited
max_result_chars = 50_000          # longer text results are truncated; 0 = unlimited
redact_secrets = true
validate_arguments = true          # check calls against each tool's declared input schema
egress_tools = []                  # extra tool names that send data out
# Tools may not read or change mcpguard's own files (this config, the audit log and its key, pins,
# approvals, the trust record), whatever the rules say. Turn off only for a project that stores such
# files on purpose.
protect_own_files = true
# Human in the loop: a tool that no rule below names, and whose name says it writes, deletes,
# runs or sends (write_file, run_command, send_email), needs approval instead of the default.
ask_sensitive = false

# Rules are checked in order and the first match wins.
#   match   "<server>/<tool>", "<server>/prompt:<name>" or "<server>/resource:<uri>" (glob)
#   args    optional; the rule applies only when every listed argument matches its glob
#   clients optional; the rule applies only to these client names (globs). stdio is "stdio".
#   action  allow | deny | ask

[[policy.rules]]
match = "*/exec*"
action = "deny"
# clients = ["*"]

# Ask before anything that deletes or moves data (approve in the dashboard).
[[policy.rules]]
match = "*/delete_*"
action = "ask"

[[policy.rules]]
match = "*/remove_*"
action = "ask"

[[policy.rules]]
match = "*/move_*"
action = "ask"

[[policy.rules]]
match = "*/drop_*"
action = "ask"

[[policy.rules]]
match = "*/purge_*"
action = "ask"

# Never write into system folders.
[[policy.rules]]
match = "*/write_file"
args = { path = "/etc/*" }
action = "deny"

[[policy.rules]]
match = "*/write_file"
args = { path = "?:[/\\\\][Ww]indows[/\\\\]*" }
action = "deny"

# Flow rules: a risky sequence of tools needs a decision, even when each tool is fine alone.
# If a tool matching "after" was used earlier in the same session, a call to a tool matching
# "then" is asked about (action = "ask") or refused (action = "deny"). It matches tool names, so
# it shows the sequence happened, not that data flowed between the two.
# [[flows]]
# name = "private-data-then-email"
# after = ["crm/*", "files/read_*"]
# then = ["email/send_*", "*/post_*"]
# within_minutes = 30            # how far back to look (default 30)
# action = "ask"                 # ask | deny
# clients = ["ci-*"]             # optional: only these clients

[detectors]
entropy = true                     # flag random-looking tokens as possible credentials
entropy_threshold = 4.3
plugins = []                       # "package.module:function"

# Custom rules. scope: definition | args | result | any
[[detectors.rules]]
id = "custom.internal_hostname"
pattern = "\\\\bcorp\\\\.internal\\\\b"
severity = "medium"
scope = "result"
message = "Internal hostname in tool output"

# Indicators of compromise from public MCP attack datasets (see `mcpguard iocs`).
# [detectors.iocs]
# enabled = true
# feeds = ["my-iocs.json"]       # extra feeds built with `mcpguard iocs build`
# shingle_hits = 4               # shared word sequences needed for ioc.similar_text

# Learned injection classifier (see docs/model.md). On tool results it warns at "medium" and
# blocks at "high"; on tool definitions it only warns.
# [detectors.model]
# enabled = true
# file = "my-model.json"         # one trained with scripts/train_model.py
# medium = 0.3                   # thresholds; default: the ones stored with the model
# high = 0.93

# Silence known false positives (rule and location are globs):
# [[detectors.suppress]]
# rule = "shadowing.cross_reference"
# where = "github.*"

# Change the severity of any rule:
# [detectors.severity_overrides]
# "secret.jwt" = "medium"

# Local server (stdio):
[servers.example]
command = "python"
args = ["-m", "my_mcp_server"]
# env = { API_KEY = "..." }
# Inherited variables that look like secrets (names with TOKEN, KEY, SECRET, PASSWORD ..., or
# values shaped like known keys) are withheld from servers. Let named ones through:
# pass_env = ["GITHUB_TOKEN", "AWS_*"]
# Least privilege: refuse calls whose path arguments are outside these folders, or whose URL
# arguments name other hosts (globs).
# allowed_paths = ["C:/Users/me/Documents/project"]
# allowed_hosts = ["api.github.com", "*.example.com"]
# timeout_seconds = 60
# enabled = true

# Run an untrusted local server in a container: no network, read-only, and only these folders.
# [servers.example.sandbox]
# image = "python:3.13-slim"       # must contain the server's runtime
# network = false
# mounts = [{ host = "C:/Users/me/Documents/project", container = "/data", write = false }]
# memory = "1g"
# runtime = "docker"               # or "podman"

# Remote server (Streamable HTTP):
# [servers.remote]
# url = "https://mcp.example.com/mcp"
# bearer_env = "REMOTE_MCP_TOKEN"  # token is read from this environment variable
# headers = { "X-Team" = "infra" }
"""


class ConfigError(ValueError):
    """The configuration file is missing, unreadable or invalid."""


@dataclass
class ServerSpec:
    name: str
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    bearer_env: str = ""
    timeout: float = 60.0
    enabled: bool = True
    # Inherited variables that look like secrets are withheld unless named here (globs allowed).
    pass_env: list[str] = field(default_factory=list)
    # Least privilege: path arguments must lie inside these folders, URL arguments name these hosts.
    allowed_paths: list[str] = field(default_factory=list)
    allowed_hosts: list[str] = field(default_factory=list)
    sandbox: Sandbox | None = None  # run the server in a container (see sandbox.py)

    @property
    def kind(self) -> str:
        return "http" if self.url else "stdio"

    def key(self) -> tuple:
        """Identity used to decide whether a reload must restart this server."""
        return (self.command, tuple(self.args), tuple(sorted(self.env.items())), self.url,
                tuple(sorted(self.headers.items())), self.bearer_env, self.timeout, tuple(self.pass_env),
                self.sandbox.key() if self.sandbox else None)


@dataclass
class DetectorConfig:
    entropy: bool = True
    entropy_threshold: float = 4.3
    rules: list[dict] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)
    suppress: list[dict] = field(default_factory=list)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    iocs: bool = True
    ioc_feeds: list[str] = field(default_factory=list)
    ioc_shingle_hits: int = 4
    model: bool = True
    model_file: str = ""                 # empty: the bundled classifier
    model_medium: float | None = None    # None: the thresholds stored with the model
    model_high: float | None = None


@dataclass
class ClientSpec:
    name: str
    token_env: str = ""
    token: str = ""  # resolved at load time; never logged

    def __repr__(self) -> str:
        return f"ClientSpec(name={self.name!r}, token_env={self.token_env!r})"


@dataclass
class Config:
    servers: list[ServerSpec]
    policy: Policy
    audit_path: str
    pins_path: str
    pins_first_seen: str = "allow"
    static_block_severity: str = "high"
    mode: str = "enforce"
    detectors: DetectorConfig = field(default_factory=DetectorConfig)
    approval_mode: str = "tty"
    approvals_dir: str = "mcpguard-approvals"
    approval_timeout: float = 120.0
    dashboard_enabled: bool = False
    dashboard_port: int = 8765
    anomaly_enabled: bool = True
    dlp: DlpConfig = field(default_factory=DlpConfig)
    baseline_path: str = "mcpguard-baseline.json"
    anomaly_min_samples: int = 20
    anomaly_z: float = 4.0
    audit_rotate_bytes: int = 0
    checkpoint_path: str = ""
    witness_url: str = ""
    forward_url: str = ""
    audit_on_tamper: str = "block"
    audit_verify_minutes: float = 30.0
    checkpoint_minutes: float = 5.0
    state_path: str = "mcpguard-state.json"
    log_level: str = "warning"
    log_file: str = ""
    audit_sign: bool = True
    audit_key_file: str = "mcpguard-audit.key"
    approval_remember_minutes: int = 15
    alert_url: str = ""
    # Environment variables holding mcpguard's own secrets (audit key, client and server tokens,
    # webhook): withheld from every server process, so one server cannot read another's token.
    secret_env: frozenset = frozenset()
    alert_events: list[str] = field(default_factory=list)
    alert_interval: float = 10.0
    http_host: str = "127.0.0.1"
    http_port: int = 8766
    http_path: str = "/mcp"
    clients: list[ClientSpec] = field(default_factory=list)
    source: str = ""
    flows: tuple = ()  # FlowRule, see flows.py
    warnings: list[str] = field(default_factory=list)  # unknown sections and keys (probably typos)


# ---------------------------------------------------------------- validation helpers

def _get(table: dict, key: str, kind, default, where: str):
    value = table.get(key, default)
    if kind is float and isinstance(value, int) and not isinstance(value, bool):
        value = float(value)
    if not isinstance(value, kind) or (kind in (int, float) and isinstance(value, bool)):
        names = kind.__name__ if isinstance(kind, type) else " or ".join(k.__name__ for k in kind)
        raise ConfigError(f"{where}.{key} must be {names}, got {type(value).__name__}")
    return value


def _table(data: dict, key: str) -> dict:
    """A [section] that must be a table if present."""
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{key}] must be a table, got {type(value).__name__}")
    return value


def _list_of(value, kind, where: str) -> list:
    if not isinstance(value, list) or not all(isinstance(v, kind) for v in value):
        raise ConfigError(f"{where} must be a list of {kind.__name__ if isinstance(kind, type) else 'tables'}")
    return value


def _choice(value, options, where: str):
    if value not in options:
        raise ConfigError(f"{where} must be one of {', '.join(options)}; got '{value}'")
    return value


def _check_policy(pol: dict) -> None:
    _list_of(pol.get("rules", []), dict, "policy.rules")
    _list_of(pol.get("egress_tools", []), str, "policy.egress_tools")
    _get(pol, "redact_secrets", bool, True, "policy")
    _choice(pol.get("default", "allow"), ACTIONS, "policy.default")
    for key in ("block_severity", "static_block_severity"):
        _choice(pol.get(key, "high"), SEVERITIES, f"policy.{key}")
    _get(pol, "validate_arguments", bool, True, "policy")
    _get(pol, "protect_own_files", bool, True, "policy")
    for key in ("rate_limit_per_minute", "max_calls_per_session", "max_result_chars"):
        if _get(pol, key, int, 0, "policy") < 0:
            raise ConfigError(f"policy.{key} cannot be negative")
    for i, rule in enumerate(pol.get("rules", [])):
        where = f"policy.rules[{i}]"
        if not isinstance(rule.get("match"), str):
            raise ConfigError(f"{where} needs a 'match' string")
        _choice(rule.get("action"), ACTIONS, f"{where}.action")
        if "args" in rule and not isinstance(rule["args"], dict):
            raise ConfigError(f"{where}.args must be a table of argument globs")
        if "clients" in rule and (not isinstance(rule["clients"], list)
                                  or not all(isinstance(c, str) for c in rule["clients"])):
            raise ConfigError(f"{where}.clients must be a list of client names")


def _check_dlp(d: dict) -> DlpConfig:
    from .dlp import BY_NAME, DEFAULT_OUTBOUND, DEFAULT_RESULTS, OUTBOUND_ACTIONS, RESULT_ACTIONS
    cfg = DlpConfig(enabled=_get(d, "enabled", bool, True, "dlp"), track_pii=_get(d, "track_pii", bool, True, "dlp"))
    for direction, defaults, allowed in (("results", DEFAULT_RESULTS, RESULT_ACTIONS),
                                         ("outbound", DEFAULT_OUTBOUND, OUTBOUND_ACTIONS)):
        table = _table(d, direction) if direction in d else {}
        actions = dict(defaults)
        for name, action in table.items():
            if name not in BY_NAME:
                raise ConfigError(f"dlp.{direction}: unknown data class '{name}' "
                                  f"(known: {', '.join(BY_NAME)})")
            if action not in allowed:
                raise ConfigError(f"dlp.{direction}.{name} must be one of {', '.join(allowed)}")
            actions[name] = action
        setattr(cfg, direction, actions)
    return cfg


def _check_detectors(det: dict, base: Path | None = None) -> DetectorConfig:
    _list_of(det.get("rules", []), dict, "detectors.rules")
    _list_of(det.get("plugins", []), str, "detectors.plugins")
    _list_of(det.get("suppress", []), dict, "detectors.suppress")
    if not isinstance(det.get("severity_overrides", {}), dict):
        raise ConfigError("detectors.severity_overrides must be a table of rule = severity")
    cfg = DetectorConfig(
        entropy=_get(det, "entropy", bool, True, "detectors"),
        entropy_threshold=_get(det, "entropy_threshold", float, 4.3, "detectors"),
        rules=det.get("rules", []),
        plugins=det.get("plugins", []),
        suppress=det.get("suppress", []),
        severity_overrides=det.get("severity_overrides", {}),
    )
    for i, r in enumerate(cfg.rules):
        where = f"detectors.rules[{i}]"
        if not isinstance(r.get("pattern"), str):
            raise ConfigError(f"{where} needs a 'pattern' string")
        for k in ("id", "message"):
            if k in r and not isinstance(r[k], str):
                raise ConfigError(f"{where}.{k} must be a string")
        try:
            re.compile(r["pattern"])
        except re.error as e:
            raise ConfigError(f"{where}.pattern is not a valid regular expression: {e}") from e
        _choice(r.get("severity", "medium"), SEVERITIES, f"{where}.severity")
        _choice(r.get("scope", "any"), ("definition", "args", "result", "any"), f"{where}.scope")
    for rule, sev in cfg.severity_overrides.items():
        _choice(sev, SEVERITIES, f"detectors.severity_overrides['{rule}']")
    iocs = det.get("iocs", {})
    if not isinstance(iocs, dict):
        raise ConfigError("[detectors.iocs] must be a table")
    cfg.iocs = _get(iocs, "enabled", bool, True, "detectors.iocs")
    feeds = _list_of(iocs.get("feeds", []), str, "detectors.iocs.feeds")
    cfg.ioc_feeds = [str(Path(p) if Path(p).is_absolute() or base is None else base / p) for p in feeds]
    missing = [p for p in cfg.ioc_feeds if not Path(p).exists()]
    if missing:
        raise ConfigError(f"detectors.iocs.feeds: file not found: {missing[0]}")
    cfg.ioc_shingle_hits = _get(iocs, "shingle_hits", int, 4, "detectors.iocs")
    if cfg.ioc_shingle_hits < 1:
        raise ConfigError("detectors.iocs.shingle_hits must be at least 1")
    # Import plugins now so a broken one fails the load, not the first request.
    from .detect import Engine
    try:
        Engine(cfg)
    except Exception as e:
        raise ConfigError(f"detectors: {e}") from e
    model = det.get("model", {})
    if not isinstance(model, dict):
        raise ConfigError("[detectors.model] must be a table")
    cfg.model = _get(model, "enabled", bool, True, "detectors.model")
    model_file = _get(model, "file", str, "", "detectors.model")
    if model_file:
        resolved = Path(model_file) if Path(model_file).is_absolute() or base is None else base / model_file
        if not resolved.exists():
            raise ConfigError(f"detectors.model.file: {resolved} does not exist")
        cfg.model_file = str(resolved)
    for key in ("medium", "high"):
        value = model.get(key)
        if value is not None:
            if not isinstance(value, int | float) or not 0 < value < 1:
                raise ConfigError(f"detectors.model.{key} must be a number between 0 and 1")
            setattr(cfg, f"model_{key}", float(value))
    if cfg.model_medium is not None and cfg.model_high is not None and cfg.model_medium >= cfg.model_high:
        raise ConfigError("detectors.model.medium must be below detectors.model.high")
    return cfg


def _check_server(name: str, s) -> ServerSpec:
    where = f"servers.{name}"
    if not isinstance(s, dict):
        raise ConfigError(f"{where} must be a table")
    for key in ("command", "url", "bearer_env"):
        if key in s and not isinstance(s[key], str):
            raise ConfigError(f"{where}.{key} must be a string")
    _list_of(s.get("args", []), str, f"{where}.args")
    _list_of(s.get("pass_env", []), str, f"{where}.pass_env")
    _list_of(s.get("allowed_paths", []), str, f"{where}.allowed_paths")
    _list_of(s.get("allowed_hosts", []), str, f"{where}.allowed_hosts")
    box = None
    if "sandbox" in s:
        if s.get("url"):
            raise ConfigError(f"{where}.sandbox applies to local servers (command), not remote ones (url)")
        try:
            box = parse_sandbox(s["sandbox"], f"{where}.sandbox")
        except ValueError as e:
            raise ConfigError(str(e)) from e
    for key in ("env", "headers"):
        table = s.get(key, {})
        if not isinstance(table, dict) or not all(isinstance(v, str) for v in table.values()):
            raise ConfigError(f"{where}.{key} must be a table of strings")
    if not SERVER_NAME.match(name):
        raise ConfigError(f"{where}: server names may contain only letters, digits, '-' and '_'")
    if "__" in name:
        raise ConfigError(f"{where}: server names cannot contain '__' (used as the namespace separator)")
    if bool(s.get("url")) == bool(s.get("command")):
        raise ConfigError(f"{where} needs exactly one of 'command' (local) or 'url' (remote)")
    url = s.get("url", "")
    if url and not local_or_https(url):
        raise ConfigError(f"{where}.url must use https:// (plain http is only allowed for localhost)")
    timeout = _get(s, "timeout_seconds", float, 60.0, where)
    if timeout <= 0:
        raise ConfigError(f"{where}.timeout_seconds must be positive")
    return ServerSpec(
        name, s.get("command", ""), list(s.get("args", [])), dict(s.get("env", {})), url,
        dict(s.get("headers", {})), s.get("bearer_env", ""), timeout,
        _get(s, "enabled", bool, True, where), list(s.get("pass_env", [])),
        list(s.get("allowed_paths", [])), list(s.get("allowed_hosts", [])), box,
    )


# ---------------------------------------------------------------- loader

# Tables whose keys are the user's own (environment variables, argument globs, rule names).
_FREEFORM = {"env", "headers", "args", "severity_overrides", "pass_env", "mounts"}


def _known_keys() -> dict[str, set[str]]:
    """Sections and keys of the starter config, including the commented-out examples, so the
    template is the single list of what exists."""
    known: dict[str, set[str]] = {"": set()}
    section = ""
    for line in DEFAULT_CONFIG.splitlines():
        m = re.match(r"\s*#?\s*\[\[?\s*([\w.-]+)\s*\]\]?\s*(?:#.*)?$", line)
        if m:
            section = re.sub(r"^(servers|clients)\.[\w-]+(\.[\w.-]+)?$", r"\1.*\2", m.group(1))
            known.setdefault(section, set())
            continue
        m = re.match(r"\s*#?\s*([A-Za-z_][\w-]*)\s*=", line)
        if m:
            known[section].add(m.group(1))
    return known


def unknown_keys(data: dict) -> list[str]:
    """Readable warnings for sections and keys mcpguard does not use (usually typos)."""
    known = _known_keys()
    out: list[str] = []

    def hint(word: str, options) -> str:
        close = difflib.get_close_matches(word, sorted(options), n=1, cutoff=0.7)
        return f" (did you mean '{close[0]}'?)" if close else ""

    def walk(table: dict, section: str) -> None:
        for key, value in table.items():
            if section in ("servers", "clients"):  # names chosen by the user
                if isinstance(value, dict):
                    walk(value, f"{section}.*")
                continue
            if key in _FREEFORM:
                continue
            child = f"{section}.{key}" if section else key
            tables = [value] if isinstance(value, dict) else (
                value if isinstance(value, list) and value and all(isinstance(v, dict) for v in value) else None)
            if tables is not None and (child in known or child in ("servers", "clients")):
                for t in tables:
                    walk(t, child)
            elif tables is not None and key not in known.get(section, set()):
                sections = [k.rsplit(".", 1)[-1] for k in known if k.startswith(section + ".") or "." not in k]
                out.append(f"unknown section [{child}]{hint(key, sections)}")
            elif key not in known.get(section, set()):
                where = f"[{section}]" if section else "the top level"
                out.append(f"unknown key '{key}' in {where}{hint(key, known.get(section, set()))}")

    walk(data, "")
    return out


def load_config(path: str | Path, source_bytes: bytes | None = None) -> Config:
    """Read a config. Pass `source_bytes` (the bytes already checked for trust) to load exactly those bytes
    rather than reading the file a second time."""
    path = Path(path).resolve()
    if path.is_dir():
        raise ConfigError(f"config path is a directory: {path}")
    try:
        raw = source_bytes if source_bytes is not None else path.read_bytes()
        data = tomllib.loads(raw.decode("utf-8"))
    except FileNotFoundError as e:
        raise ConfigError(f"config file not found: {path}") from e
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path.name}: {e}") from e
    except RecursionError as e:  # a file nested thousands of levels deep
        raise ConfigError(f"{path.name}: nested too deeply to read") from e
    except UnicodeDecodeError as e:
        raise ConfigError(f"{path.name}: not valid UTF-8 at byte {e.start}; save the file as UTF-8") from e
    except OSError as e:
        raise ConfigError(f"{path.name}: cannot read the file: {e.strerror or e}") from e
    base = path.parent
    unknown = unknown_keys(data)

    def rel(p: str) -> str:
        return str(Path(p) if Path(p).is_absolute() else base / p)

    servers = [_check_server(n, s) for n, s in _table(data, "servers").items()]

    pol = _table(data, "policy")
    _check_policy(pol)
    det = _check_detectors(_table(data, "detectors"), base)
    appr = _table(data, "approvals")
    dash = _table(data, "dashboard")
    anom = _table(data, "anomaly")
    audit = _table(data, "audit")
    logging_ = _table(data, "logging")
    audit_keys = ("path", "key_file", "checkpoint_path", "witness_url", "forward_url", "on_tamper")
    for table, name, keys in ((audit, "audit", audit_keys),
                              (appr, "approvals", ("dir",)), (anom, "anomaly", ("path",)),
                              (logging_, "logging", ("file",)), (_table(data, "pins"), "pins", ("path", "first_seen")),
                              (_table(data, "state"), "state", ("path",))):
        for key in keys:
            if key in table and not isinstance(table[key], str):
                raise ConfigError(f"{name}.{key} must be a string")

    port = _get(dash, "port", int, 8765, "dashboard")
    if not 0 <= port <= 65535:
        raise ConfigError("dashboard.port must be between 0 and 65535")
    timeout = _get(appr, "timeout_seconds", float, 120.0, "approvals")
    if timeout <= 0:
        raise ConfigError("approvals.timeout_seconds must be positive")
    min_samples = _get(anom, "min_samples", int, 20, "anomaly")
    if min_samples < 2:
        raise ConfigError("anomaly.min_samples must be at least 2")

    alerts = _table(data, "alerts")
    for key in ("webhook_url", "webhook_url_env"):
        if key in alerts and not isinstance(alerts[key], str):
            raise ConfigError(f"alerts.{key} must be a string")
    alert_url = alerts.get("webhook_url", "")
    if alerts.get("webhook_url_env"):
        alert_url = os.environ.get(alerts["webhook_url_env"], "")
        if not alert_url:
            raise ConfigError(f"alerts.webhook_url_env: environment variable {alerts['webhook_url_env']} is not set")
    if alert_url and not local_or_https(alert_url):
        raise ConfigError("alerts.webhook_url must use https:// (plain http is only allowed for localhost)")
    alert_events = alerts.get("events", list(DEFAULT_ALERT_EVENTS))
    if not isinstance(alert_events, list) or not all(isinstance(e, str) for e in alert_events):
        raise ConfigError("alerts.events must be a list of event names (globs allowed)")

    http = _table(data, "http")
    http_port = _get(http, "port", int, 8766, "http")
    if not 0 <= http_port <= 65535:
        raise ConfigError("http.port must be between 0 and 65535")
    http_path = _get(http, "path", str, "/mcp", "http")
    if not http_path.startswith("/"):
        raise ConfigError("http.path must start with '/'")

    clients = []
    for name, c in _table(data, "clients").items():
        if not isinstance(c, dict):
            raise ConfigError(f"clients.{name} must be a table")
        if not SERVER_NAME.match(name) or name == "stdio":
            raise ConfigError(f"clients.{name}: names may contain only letters, digits, '-' and '_' "
                              "and 'stdio' is reserved")
        env = _get(c, "token_env", str, "", f"clients.{name}")
        if not env:
            raise ConfigError(f"clients.{name} needs token_env (the environment variable holding its token)")
        token = os.environ.get(env, "")
        clients.append(ClientSpec(name, env, token))

    remember = _get(appr, "remember_minutes", int, 15, "approvals")
    if not 0 <= remember <= 24 * 60:
        raise ConfigError("approvals.remember_minutes must be between 0 and 1440")

    audit_sign = _get(audit, "sign", bool, True, "audit")
    if "key_file" in audit:
        key_file = rel(audit["key_file"])
    else:
        legacy = Path(rel("mcpguard-audit.key"))  # a key an older version put beside the log stays in use
        from .audit import default_key_path
        key_file = str(legacy) if legacy.exists() else str(
            default_key_path(rel(audit.get("path", "mcpguard-audit.jsonl"))))
    if audit_sign:
        from .audit import load_key
        try:
            load_key(key_file)  # validates an existing key; a missing one is created at startup
        except (ValueError, OSError) as e:
            raise ConfigError(f"audit: {e}") from e

    for what, p in (("audit.path", audit.get("path", "mcpguard-audit.jsonl")),
                    ("pins.path", data.get("pins", {}).get("path", "mcpguard-pins.json"))):
        if isinstance(p, str) and p and Path(rel(p)).is_dir():
            raise ConfigError(f"{what} is a folder ({rel(p)}); name a file")

    cp_raw = audit.get("checkpoint_path")
    if cp_raw == "off":
        checkpoint_path = ""
    elif cp_raw:
        checkpoint_path = rel(cp_raw)
    elif _get(audit, "sign", bool, True, "audit"):
        from .audit import default_checkpoint_path
        checkpoint_path = str(default_checkpoint_path(rel(audit.get("path", "mcpguard-audit.jsonl"))))
    else:
        checkpoint_path = ""
    witness_url = audit.get("witness_url", "")
    if not isinstance(witness_url, str) or (witness_url and not local_or_https(witness_url)):
        raise ConfigError("audit.witness_url must be an https:// URL (plain http only for localhost)")

    forward_url = audit.get("forward_url", "")
    if not isinstance(forward_url, str) or (forward_url and not local_or_https(forward_url)):
        raise ConfigError("audit.forward_url must be an https:// URL (plain http only for localhost)")
    on_tamper = audit.get("on_tamper", "block")
    if on_tamper not in ("block", "warn"):
        raise ConfigError('audit.on_tamper must be "block" or "warn"')
    for numeric in ("rotate_bytes", "checkpoint_minutes"):
        if isinstance(audit.get(numeric), (int, float)) and audit[numeric] < 0:
            raise ConfigError(f"audit.{numeric} cannot be negative (0 turns it off)")
    verify_minutes = _get(audit, "verify_minutes", float, 30.0, "audit")
    if verify_minutes < 0:
        raise ConfigError("audit.verify_minutes cannot be negative")

    first_seen = data.get("pins", {}).get("first_seen", "allow")
    if first_seen not in ("allow", "approve"):
        raise ConfigError('pins.first_seen must be "allow" or "approve"')

    from .flows import parse_flows
    try:
        flows = parse_flows(data.get("flows"))
    except ValueError as e:
        raise ConfigError(str(e)) from e

    if unknown:  # a typo in a security setting must not leave it quietly at its default
        raise ConfigError(f"{path.name}: " + "; ".join(unknown) + " - fix or remove it")
    return Config(
        servers=servers,
        policy=Policy.from_dict(pol),
        flows=flows,
        audit_path=rel(audit.get("path", "mcpguard-audit.jsonl")),
        pins_path=rel(data.get("pins", {}).get("path", "mcpguard-pins.json")),
        pins_first_seen=first_seen,
        static_block_severity=pol.get("static_block_severity", "high"),
        mode=_choice(data.get("mode", "enforce") if isinstance(data.get("mode", "enforce"), str) else None,
                     MODES, "mode"),
        detectors=det,
        approval_mode=_choice(appr.get("mode", "tty") if isinstance(appr.get("mode", "tty"), str) else None,
                              APPROVAL_MODES, "approvals.mode"),
        approvals_dir=rel(appr.get("dir", "mcpguard-approvals")),
        approval_timeout=timeout,
        dashboard_enabled=_get(dash, "enabled", bool, False, "dashboard"),
        dashboard_port=port,
        anomaly_enabled=_get(anom, "enabled", bool, True, "anomaly"),
        dlp=_check_dlp(_table(data, "dlp")),
        baseline_path=rel(anom.get("path", "mcpguard-baseline.json")),
        anomaly_min_samples=min_samples,
        anomaly_z=_get(anom, "z_threshold", float, 4.0, "anomaly"),
        audit_rotate_bytes=_get(audit, "rotate_bytes", int, 0, "audit"),
        checkpoint_path=checkpoint_path,
        witness_url=witness_url,
        forward_url=forward_url,
        audit_on_tamper=on_tamper,
        audit_verify_minutes=verify_minutes,
        checkpoint_minutes=_get(audit, "checkpoint_minutes", float, 5.0, "audit"),
        state_path=rel(data.get("state", {}).get("path", "mcpguard-state.json")),
        log_level=_choice(logging_.get("level", "warning"), ("debug", "info", "warning", "error"),
                          "logging.level"),
        log_file=rel(logging_["file"]) if logging_.get("file") else "",
        audit_sign=audit_sign,
        audit_key_file=key_file,
        approval_remember_minutes=remember,
        alert_url=alert_url,
        secret_env=frozenset({"MCPGUARD_AUDIT_KEY", *(c.token_env for c in clients if c.token_env),
                              *([alerts["webhook_url_env"]] if alerts.get("webhook_url_env") else []),
                              *(sp.bearer_env for sp in servers if sp.bearer_env)}),
        alert_events=alert_events,
        alert_interval=_get(alerts, "min_interval_seconds", float, 10.0, "alerts"),
        http_host=_get(http, "host", str, "127.0.0.1", "http"),
        http_port=http_port,
        http_path=http_path,
        clients=clients,
        source=str(path),
        warnings=[],
    )
