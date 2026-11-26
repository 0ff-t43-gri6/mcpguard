"""Per-tool policy: allow/deny/ask globs with argument conditions, rate limits,
budgets and size caps."""

from __future__ import annotations

import fnmatch
import json
import posixpath
import re
import time
import unicodedata
from collections import defaultdict, deque
from dataclasses import dataclass, field

ALLOW, DENY, ASK = "allow", "deny", "ask"
ACTIONS = (ALLOW, DENY, ASK)



def _name_matches(qualified: str, pattern: str) -> bool:
    """Tool names match case-insensitively: a server must not dodge "*/delete_*" with DELETE_FILE."""
    return fnmatch.fnmatchcase(qualified.lower(), pattern.lower())


def normalise_path(value: str) -> str:
    r"""What a path argument points at, lexically: backslashes as '/', no \?\ prefix, repeated
    slashes collapsed and '..' resolved, so /tmp/../etc/passwd and //etc/passwd are /etc/passwd."""
    v = value.replace("\\", "/")
    v = re.sub(r"^//[?.]/", "", v)
    lead = "//" if re.match(r"^//[^/]", v) and not re.match(r"^//[?.]/", v) else ""  # keep UNC hosts
    v = lead + re.sub(r"/{2,}", "/", v[len(lead):])
    norm = posixpath.normpath(v)
    return norm if norm != "." else v


def _arg_matches(text: str, pattern: str) -> bool:
    """Argument globs match the raw value or its normalised path form, ignoring case: a deny on
    C:/Windows/* must also cover c:/WINDOWS/x and C:/Users/../Windows/x."""
    pat = pattern.lower()
    forms = {text}
    if "/" in text or "\\" in text:
        norm = normalise_path(text)
        # A leading // is a network share on Windows but the root on POSIX: test both readings.
        forms |= {norm, posixpath.normpath(re.sub(r"/{2,}", "/", norm))}
    return any(fnmatch.fnmatchcase(f.lower(), pat) for f in forms)

@dataclass
class Decision:
    action: str
    reason: str = ""


# Words in a tool's name that mean it changes, runs or sends something.
SENSITIVE_WORDS = frozenset({
    "write", "delete", "remove", "rm", "drop", "exec", "execute", "run", "shell", "bash", "command", "cmd", "kill",
    "move", "rename", "create", "update", "edit", "patch", "put", "push", "commit", "merge", "deploy", "install",
    "pay", "transfer", "purchase", "buy", "send", "email", "post", "publish", "upload", "set", "insert", "modify",
    "overwrite", "truncate", "terminate", "stop", "start", "restart", "grant", "revoke", "apply", "wire", "format",
    "reboot", "shutdown", "fork", "close", "reply", "forward", "schedule", "invite", "add", "share", "import",
    "replace", "append", "save", "submit", "click", "type", "navigate", "fill", "eval", "sudo", "chmod", "chown",
    "mkdir", "rmdir", "unlink", "sendmail", "runcmd", "sql",
})
# A name that starts with one of these only reads: get_commit, list_posts, show_command_help.
READ_WORDS = frozenset({"get", "list", "show", "read", "describe", "search", "find", "view", "preview", "status",
                        "count", "check", "fetch", "lookup", "query", "info", "help", "is", "has"})
_NAME_PARTS = re.compile(r"[A-Za-z][a-z]*|[A-Z]+(?![a-z])")
_LONG_WORDS = tuple(sorted((w for w in SENSITIVE_WORDS if len(w) >= 4), key=len, reverse=True))


def sensitive_name(tool: str) -> bool:
    """True when a tool's name says it writes, deletes, runs or sends: write_file, sendEmail,
    filewrite, deletefile. Names that begin with a reading verb (get_, list_, show_) are not."""
    parts = [p.lower() for p in _NAME_PARTS.findall(tool)]
    if not parts or parts[0] in READ_WORDS:
        return False
    if any(p in SENSITIVE_WORDS for p in parts):
        return True
    # Words run together without a separator: "filewrite", "sendmessage", "uploadfile".
    return any(len(p) > len(w) and (p.startswith(w) or p.endswith(w)) for p in parts for w in _LONG_WORDS)


_PATH_START = re.compile(r"^(?:[A-Za-z]:|[\\/]|~|\.{1,2}[\\/])")
_SCHEME = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{1,15}):(/{0,2})")
_URL_ANYWHERE = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{1,15})://([^\s\"'<>]*)")
_NETWORK_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp", "ftps", "sftp", "ssh", "git", "smb", "gopher",
                              "ldap", "ldaps", "telnet", "rtsp", "nfs", "tftp", "dict", "redis", "postgres",
                              "postgresql", "mysql", "mongodb", "mongodb+srv", "amqp", "amqps", "s3", "gs"})
_SCP_STYLE = re.compile(r"^[\w.\-]+@([\w.\-]+):[^\s/\\]")
_BARE_HOST = re.compile(r"^((?:[a-z0-9\-]+\.)+[a-z]{2,})(?::\d+)?/", re.I)
_ENV_REF = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\$\(")
_ENCODED_SEP = re.compile(r"(?i)%(?:2e|2f|5c|00|25)")


def _strings(value, keys: bool = False):
    """Every string in an argument; with keys=True the dict keys too (batch tools take {path: content})."""
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            yield v
        elif isinstance(v, dict):
            stack.extend(v.values())
            if keys:
                stack.extend(k for k in v if isinstance(k, str))
        elif isinstance(v, list):
            stack.extend(v)


def _inside(path: str, root: str) -> bool:
    p, r = normalise_path(path).lower().rstrip("/"), normalise_path(root).lower().rstrip("/")
    return p == r or p.startswith(r + "/")


def _host_of(authority: str) -> str:
    """The host of a URL authority, or "" when parsers could disagree about it: a backslash,
    user-info ('@'), control characters, or anything else a strict reader would not accept."""
    if re.search(r"[\\@]", authority.split("/", 1)[0]):  # also after '?' or '#': older parsers stop later
        return ""
    authority = re.split(r"[/?#]", authority, maxsplit=1)[0]
    if not authority or re.search(r"[\s\x00-\x1f%]", authority):
        return ""
    host = authority.rsplit(":", 1)[0] if re.search(r":\d*$", authority) and not authority.endswith("]") \
        else authority
    host = unicodedata.normalize("NFKC", host).lower().rstrip(".")
    return host if re.fullmatch(r"[a-z0-9.\-]+|\[[0-9a-f:.]+\]", host) else ""


def _short_host(host: str) -> str:
    """The last two labels only: enough to recognise the destination without copying data that
    was smuggled into a subdomain into the audit log."""
    return ".".join(host.strip("[]").split(".")[-2:])[:60]


def _host_problem(text: str, allowed_hosts: list[str]) -> str:
    def allowed(host: str) -> bool:
        return any(fnmatch.fnmatchcase(host, h.lower()) for h in allowed_hosts)

    stripped = text.strip()
    for m in _URL_ANYWHERE.finditer(text):
        scheme, rest = m.group(1).lower(), m.group(2)
        if scheme == "file":
            continue
        host = _host_of(rest)
        if not host:
            return "a URL argument is written in a way different programs read differently (user-info, " \
                   "backslash or encoded characters in the host)"
        if not allowed(host):
            return f"host '{_short_host(host)}' is not in this server's allowed_hosts"
    lead = _SCHEME.match(stripped)
    if lead and lead.group(1).lower() in _NETWORK_SCHEMES and lead.group(2) != "//":
        return "a URL argument is malformed (scheme without '//')"
    if stripped.startswith("//") and not stripped.startswith("///"):
        host = _host_of(stripped[2:])
        if not host or not allowed(host):
            return "a scheme-relative URL argument names a host that is not in allowed_hosts"
    named = _SCP_STYLE.match(stripped) or (_BARE_HOST.match(stripped) if " " not in stripped else None)
    if named and not allowed(named.group(1).lower()):
        return f"host '{_short_host(named.group(1).lower())}' is not in this server's allowed_hosts"
    return ""


def _path_problem(text: str, allowed_paths: list[str]) -> str:
    stripped = text.strip()
    m = _SCHEME.match(stripped)
    scheme = m.group(1).lower() if m and len(m.group(1)) > 1 else ""
    if scheme == "file":
        stripped = re.sub(r"(?i)^file:(?://(?:localhost)?)?", "", stripped) or "/"
    elif scheme in ("smb", "nfs"):
        return "a network share argument is outside this server's allowed_paths"
    elif scheme:
        return ""  # some other URL: the host check's business
    if re.match(r"^(?:%[A-Za-z_]\w*%|\$\{?[A-Za-z_]\w*\}?)(?:[\\/]|$)", stripped):
        return "a path argument contains an environment variable, which is expanded only after this check"
    looks_like_path = bool(_PATH_START.match(stripped)) or scheme == "file"
    if re.search(r"(?i)%2e\.|\.%2e|%2e%2e", stripped):
        return "a path argument contains encoded separators or a NUL byte"  # %2e%2e/ even without a leading slash
    traversal = re.search(r"(?:^|[\\/])\.{2,}(?:[\\/]|$)", stripped) is not None
    if not (looks_like_path or (traversal and " " not in stripped)):
        return ""
    if "\x00" in stripped or _ENCODED_SEP.search(stripped):
        return "a path argument contains encoded separators or a NUL byte"
    if _ENV_REF.search(stripped):
        return "a path argument contains an environment variable, which is expanded only after this check"
    windows = re.sub(r"^[\\/]{2}[?.][\\/]", "", stripped)
    if re.match(r"^[A-Za-z]:", windows) and ":" in windows[2:]:
        return "a Windows path argument names an alternate data stream"
    if not looks_like_path:
        return "a relative path argument climbs out of its folder with '..'"
    if re.match(r"^\.{1,2}[\\/]", stripped):
        return "a relative path argument climbs out of its folder with '..'" if traversal else ""
    if not any(_inside(stripped, root) for root in allowed_paths):
        return "a path argument is outside this server's allowed_paths"
    if _DEVICE_NAME.search(stripped):
        return "a path argument names a Windows device (CON, NUL, COM1 ...), not a file"
    real = _resolved_outside(stripped, allowed_paths)
    if real:
        return real
    return ""


_DEVICE_NAME = re.compile(r"(?i)(?:^|[\\/])(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.[^\\/]*)?(?:[\\/]|$)")


def _resolved_outside(path: str, allowed_paths: list[str]) -> str:
    """A path that exists and, once symlinks and junctions are followed, lies outside every allowed folder."""
    import os
    try:
        if not os.path.lexists(path):
            return ""
        real = os.path.realpath(path)
        roots = [os.path.realpath(r) for r in allowed_paths]
    except (OSError, ValueError):
        return ""
    if not any(_inside(real, r) for r in roots):
        return "a path argument leads outside this server's allowed_paths through a link"
    return ""


_OWN_FILE_NAMES = re.compile(
    r"(?i)(?:mcpguard[\w.\-]*\.(?:key|toml|jsonl|pending|forward|lock|partial|json)|trusted-configs\.json"
    r"|mcpguard-approvals|audit-archive|[\\/]\.mcpguard(?:[\\/]|$)|^\.mcpguard(?:[\\/]|$)"
    r"|\bmcp\w{0,6}~\d)")  # the last one: a Windows 8.3 short name such as MCPGUA~1.TOM
_DESTRUCTIVE_TOOL = re.compile(r"(?i)(delet|remov|(?:^|[_/\-])rm(?:dir)?(?:$|[_\-])|unlink|move|rename"
                               r"|(?:^|[_/\-])mv(?:$|[_\-])"
                               r"|trash|wipe|purge|truncat|overwrit|writ|chmod|chown|replace|copy|(?:^|[_/\-])cp(?:$|[_\-])|archive|zip)")
_LOOKALIKES = str.maketrans({"\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0443": "y",
                             "\u0445": "x", "\u0456": "i", "\u0455": "s", "\u0501": "d", "\u0261": "g", "\u043c": "m",
                             "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03c1": "p", "\u03ba": "k", "\u03c4": "t"})
_HIDDEN = re.compile("[\u00ad\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]")


def _fold_name(text: str) -> str:
    """The text as a file system would read it: percent-decoded (up to three times), compatibility
    forms folded (full-width letters), invisible characters dropped, look-alike letters mapped."""
    from urllib.parse import unquote
    for _ in range(3):
        again = unquote(text)
        if again == text:
            break
        text = again
    return _HIDDEN.sub("", unicodedata.normalize("NFKC", text)).translate(_LOOKALIKES)


def own_files_problem(args: dict, own_paths: list[str], tool: str = "") -> str:
    """Why these arguments name one of mcpguard's own files ("" when they do not). Matches the files
    this gateway uses (paths given) and the names mcpguard gives its files anywhere, in the spellings
    a file system would accept: percent-encoded, full-width, with invisible characters, as an 8.3 short
    name, as a wildcard, or as a dict key. Naming the folder that holds them counts when the tool
    changes things (delete, move, rename, write...)."""
    roots = [normalise_path(p).lower().rstrip("/") for p in own_paths if p]
    dirs = {posixpath.dirname(r) for r in roots if "." in posixpath.basename(r)} | set(roots)
    destructive = bool(tool and _DESTRUCTIVE_TOOL.search(tool))
    for original in _strings(args, keys=True):
        text = _fold_name(original[:8192])
        low = normalise_path(text).lower() if ("/" in text or "\\" in text) else text.lower()
        hit = _OWN_FILE_NAMES.search(text) or any(
            r and (low == r or low.startswith(r + "/") or r in low) for r in roots)
        if not hit and any(c in low for c in "*?["):
            whole = low if "/" in low else ""
            hit = any(fnmatch.fnmatchcase(r, whole) for r in roots) if whole else (
                len(re.split(r"[*?\[]", low)[0]) >= 4
                and any(fnmatch.fnmatchcase(posixpath.basename(r), low) for r in roots))
        if not hit and destructive and low.rstrip("/") in dirs:
            hit = True
        if hit:
            return ("the arguments name one of mcpguard's own files "
                    "(config, audit log or key, pins, approvals or trust record)")
    return ""


def scope_violation(args: dict, allowed_paths: list[str], allowed_hosts: list[str]) -> str:
    """Why these arguments are outside a server's allowed folders or hosts ("" when they are not).

    Hosts: every URL found anywhere in an argument must name an allowed host (globs); so must
    scheme-relative (//host), scp-style (user@host:path) and bare host/path arguments. A URL
    whose host different programs would read differently is refused outright.
    Paths: an argument that is an absolute path (or ~, a drive, file:, a share) must lie inside
    an allowed folder after normalisation; '..' may not climb out; encoded separators,
    environment variables and alternate data streams are refused because they change meaning
    after this check. Names are compared without regard to case.
    """
    for raw in _strings(args, keys=True):
        # full-width look-alikes of "file:" must not slip past either check
        folded = unicodedata.normalize("NFKC", raw[:8192])
        for text in ((raw[:8192], folded) if folded != raw[:8192] else (folded,)):
            problem = _scope_problem(text, allowed_paths, allowed_hosts)
            if problem:
                return problem
    return ""


def _scope_problem(text: str, allowed_paths: list[str], allowed_hosts: list[str]) -> str:
    if allowed_hosts:
        problem = _host_problem(text, allowed_hosts)
        if problem:
            return problem
    if allowed_paths and "\n" not in text.strip():
        return _path_problem(text, allowed_paths)
    return ""


def _arg_text(value) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)


@dataclass
class Policy:
    default: str = ALLOW
    rules: list[dict] = field(default_factory=list)
    rate_limit_per_minute: int = 0
    max_calls_per_session: int = 0
    max_result_chars: int = 0
    block_severity: str = "high"
    redact_secrets: bool = True
    egress_tools: set[str] = field(default_factory=set)
    validate_arguments: bool = True
    protect_own_files: bool = True  # tools may not touch mcpguard's own config, log, key, pins or trust record
    ask_sensitive: bool = False  # tools no rule names, whose name says they write/run/send, need approval

    _calls: dict = field(default_factory=lambda: defaultdict(deque), repr=False)
    _totals: dict = field(default_factory=lambda: defaultdict(int), repr=False)

    @classmethod
    def from_dict(cls, d: dict) -> Policy:
        for r in d.get("rules", []):
            if r.get("action") not in ACTIONS or "match" not in r:
                raise ValueError(f"invalid policy rule: {r}")
        if d.get("default", ALLOW) not in ACTIONS:
            raise ValueError("policy.default must be allow, deny or ask")
        return cls(
            default=d.get("default", ALLOW),
            rules=d.get("rules", []),
            rate_limit_per_minute=d.get("rate_limit_per_minute", 0),
            max_calls_per_session=d.get("max_calls_per_session", 0),
            max_result_chars=d.get("max_result_chars", 0),
            block_severity=d.get("block_severity", "high"),
            redact_secrets=d.get("redact_secrets", True),
            egress_tools=set(d.get("egress_tools", [])),
            validate_arguments=d.get("validate_arguments", True),
            ask_sensitive=d.get("ask_sensitive", False),
            protect_own_files=d.get("protect_own_files", True),
        )

    def inherit_counters(self, old: Policy) -> None:
        """Keep rate-limit and budget state across a live config reload."""
        self._calls, self._totals = old._calls, old._totals

    @staticmethod
    def _args_match(cond: dict, args: dict) -> bool:
        return all(name in args and _arg_matches(_arg_text(args[name]), str(pattern))
                   for name, pattern in cond.items())

    @staticmethod
    def _client_match(patterns: list[str], client: str | None) -> bool:
        return client is not None and any(fnmatch.fnmatch(client, p) for p in patterns)

    def evaluate(self, qualified: str, args: dict | None = None, client: str | None = None) -> Decision:
        """First matching rule wins.

        Rules with ``args`` apply only at call time (when args are given); rules with
        ``clients`` apply only when the caller's name matches one of the globs.
        """
        for rule in self.rules:
            if not _name_matches(qualified, rule["match"]):
                continue
            if "clients" in rule and not self._client_match(rule["clients"], client):
                continue
            if "args" in rule and (args is None or not self._args_match(rule["args"], args)):
                continue
            detail = [f"rule '{rule['match']}'"]
            if "clients" in rule:
                detail.append(f"for {', '.join(rule['clients'])}")
            if "args" in rule:
                detail.append(f"with args {rule['args']}")
            return Decision(rule["action"], " ".join(detail))
        if self.default == ALLOW and self.ask_sensitive:
            tool = qualified.partition("/")[2]
            if not tool.startswith(("prompt:", "resource:")) and sensitive_name(tool):
                return Decision(ASK, "ask_sensitive: no rule names this tool and its name says it "
                                     "writes, runs or sends")
        return Decision(self.default, "default policy")

    def visible(self, qualified: str, client: str | None = None) -> bool:
        """Unconditionally denied tools are hidden so the model never sees them."""
        return self.evaluate(qualified, None, client).action != DENY

    def conditional(self, qualified: str) -> bool:
        """True when some rule for this target depends on arguments."""
        return any("args" in r and _name_matches(qualified, r["match"]) for r in self.rules)

    def check_budget(self, qualified: str, now: float | None = None, client: str = "") -> Decision | None:
        """Budgets and rate limits are counted per client."""
        now = time.time() if now is None else now
        if self.max_calls_per_session and self._totals[client] >= self.max_calls_per_session:
            return Decision(DENY, "session call budget exhausted")
        if self.rate_limit_per_minute:
            q = self._calls[(client, qualified)]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= self.rate_limit_per_minute:
                return Decision(DENY, f"rate limit {self.rate_limit_per_minute}/min exceeded")
        return None

    def record_call(self, qualified: str, now: float | None = None, client: str = "") -> None:
        now = time.time() if now is None else now
        self._calls[(client, qualified)].append(now)
        self._totals[client] += 1
