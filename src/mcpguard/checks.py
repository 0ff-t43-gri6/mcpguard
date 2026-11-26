"""Attack-specific checks.

Each check is a small function from text to findings, run by ``detect.Engine`` for
the scopes it applies to:

  args        path traversal, sensitive files, shell and SQL injection, SSRF
  result      data exfiltration through markdown, encoded instructions, terminal escapes
  definition  look-alike tool names, terminal escapes, shell-execution capability

plus ``cross_server_names`` for the whole catalog (duplicate and typosquatted names).

The checks favour precision: ordinary prose, file paths and URLs must not trigger
them. Every check can be silenced or re-graded with ``[detectors.suppress]`` and
``[detectors.severity_overrides]`` using the rule ids below.
"""

from __future__ import annotations

import base64
import codecs
import binascii
import html
import ipaddress
import re
import socket
import unicodedata
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

from .detect import Finding, find_injection


@dataclass(frozen=True)
class CheckInfo:
    rule: str
    scope: str
    severity: str
    summary: str


# Rule catalog, shown by `mcpguard checks`. Severities are defaults.
CATALOG: list[CheckInfo] = [
    CheckInfo("injection.pattern", "definition, result", "medium-critical",
              "Instructions aimed at the model (ignore previous instructions, hide this from the user, ...)"),
    CheckInfo("injection.addresses_model", "result", "high",
              "Data that speaks to the assistant (\"to you, the assistant\", \"the task I gave you\")"),
    CheckInfo("injection.role_marker", "result", "high",
              "Fake chat or system markers inside data (###(system_message), [SYSTEM], <|im_start|>)"),
    CheckInfo("injection.exfil_request", "result", "medium-high",
              "A request inside data to send information to a given address (get X, then email it to ...)"),
    CheckInfo("injection.tool_directive", "result", "medium",
              "Data that tells the assistant to use a named tool"),
    CheckInfo("injection.risky_request", "result", "medium",
              "Data asking for a high-risk action: move money, grant access, unlock or disarm, wipe data, "
              "change credentials"),
    CheckInfo("ml.injection", "definition, result", "medium-high",
              "Learned classifier: wording typical of injected instructions (on definitions: warning only)"),
    CheckInfo("dlp.<class>", "args, result", "low-critical",
              "Personal or financial data (card, Aadhaar, SSN, IBAN, PAN, email, phone) per the [dlp] policy"),
    CheckInfo("dlp.tracked_pii", "args", "high",
              "Personal data returned by one tool being sent out through another"),
    CheckInfo("injection.obfuscated", "definition, result", "high-critical",
              "An injection written with look-alike letters, full-width forms or s p a c e d letters"),
    CheckInfo("name.control_chars", "definition", "critical",
              "Control or invisible characters in a tool name (terminal escape sequences)"),
    CheckInfo("name.unusual", "definition", "medium", "Tool name with unusual characters or over 128 characters"),
    CheckInfo("injection.encoded", "result", "same as decoded",
              "Base64 text that decodes to instructions aimed at the model"),
    CheckInfo("hidden.unicode", "all", "high", "Invisible or format characters that can hide text"),
    CheckInfo("hidden.ansi_escape", "definition, result", "medium",
              "Terminal escape sequences that can rewrite what a person sees"),
    CheckInfo("secret.*", "all", "high-critical", "Known credential formats (cloud keys, tokens, private keys, ...)"),
    CheckInfo("secret.high_entropy", "all", "medium", "Random-looking tokens that may be credentials"),
    CheckInfo("path.traversal", "args", "medium", "'../' sequences that climb out of a directory"),
    CheckInfo("path.sensitive", "args", "high", "Paths to credentials and system secrets (.ssh, .aws, .env, ...)"),
    CheckInfo("path.unc", "args", "medium", "Windows network paths (\\\\host\\share) that can leak credentials"),
    CheckInfo("injection.command", "args", "high-critical", "Shell command chaining and pipe-to-shell"),
    CheckInfo("injection.sql", "args", "medium",
              "SQL injection shapes (tautologies, UNION SELECT, stacked statements)"),
    CheckInfo("ssrf.metadata", "args", "critical", "Requests to cloud metadata endpoints"),
    CheckInfo("ssrf.internal", "args", "high", "Requests to loopback, private or link-local addresses"),
    CheckInfo("ssrf.scheme", "args", "high", "file://, gopher:// and dict:// URLs"),
    CheckInfo("exfil.markdown_image", "result", "high",
              "Markdown or HTML images whose URL carries data (rendered automatically by many clients)"),
    CheckInfo("exfil.markdown_link", "result", "medium", "Links whose URL carries a long data payload"),
    CheckInfo("name.confusable", "definition", "high", "Tool names using look-alike letters from other alphabets"),
    CheckInfo("capability.shell", "definition", "low", "Tools that advertise arbitrary command execution"),
    CheckInfo("shadowing.cross_reference", "catalog", "medium",
              "A tool description that talks about a tool on another server"),
    CheckInfo("shadowing.duplicate_name", "catalog", "medium", "The same tool name offered by two servers"),
    CheckInfo("shadowing.similar_name", "catalog", "medium", "Near-identical tool names on different servers"),
    CheckInfo("rug_pull.changed", "definition", "critical", "A definition changed after it was first trusted"),
    CheckInfo("advisory.malicious", "server", "critical",
              "A server whose package, address or name appears in a known malicious campaign (not started)"),
    CheckInfo("advisory.vulnerable", "server", "high", "A server version with a published CVE"),
    CheckInfo("advisory.unknown_version", "server", "medium",
              "A server with a published CVE, started without a pinned version"),
    CheckInfo("supply_chain.unpinned", "server", "low",
              "A package fetched without a version: every start runs the latest release"),
    CheckInfo("launch.shell", "server", "high", "A server started through a shell with an inline command"),
    CheckInfo("launch.inline_code", "server", "high", "A launch command that runs code written in the config"),
    CheckInfo("launch.downloader", "server", "critical",
              "A launch command that downloads or decodes something and runs it"),
    CheckInfo("config.hook", "project config", "medium",
              "A hook in a project's AI-tool config that runs a command automatically (audit-configs)"),
    CheckInfo("schema.invalid_arguments", "args", "high", "Arguments that break the tool's own input schema"),
    CheckInfo("flow.chained", "call", "high",
              "A tool used after another that a [[flows]] rule links it to (e.g. reading customer data, then email)"),
    CheckInfo("exfiltration.tainted_data", "args", "critical",
              "Sensitive data returned by one tool being sent out through another"),
    CheckInfo("anomaly.*", "result", "medium", "Result size, latency or argument size far outside a tool's norm"),
    CheckInfo("ioc.known_text", "definition, result", "critical", "Exact match with a known malicious MCP tool text"),
    CheckInfo("ioc.similar_text", "definition, result", "high",
              "Shares several word sequences with known malicious MCP payloads"),
    CheckInfo("ioc.phrase", "definition, result", "medium-high", "Wording that appears only in known MCP attacks"),
    CheckInfo("ioc.domain", "all", "high", "Hosts used by known MCP attacks"),
    CheckInfo("ioc.param_name", "definition", "high", "Parameters that known attacks inject to extract information"),
    CheckInfo("ioc.tool_name", "definition", "medium", "Tool names used only by known malicious tools"),
]


# ---------------------------------------------------------------- paths

_TRAVERSAL = re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)")
_SENSITIVE_PATHS = re.compile(
    r"(?:^|[\\/\s'\"=])(?:"
    r"etc[\\/](?:shadow|sudoers|gshadow)"
    r"|\.ssh[\\/]|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?\b"
    r"|\.aws[\\/](?:credentials|config)\b|\.azure[\\/]|\.config[\\/]gcloud[\\/]"
    r"|\.kube[\\/]config\b|\.docker[\\/]config\.json\b"
    r"|\.netrc\b|\.npmrc\b|\.pypirc\b|\.git-credentials\b|\.git[\\/]config\b"
    r"|proc[\\/]self[\\/](?:environ|mem)\b"
    r"|windows[\\/]system32[\\/]config[\\/](?:sam|system|security)\b"
    r"|appdata[\\/]roaming[\\/]microsoft[\\/]credentials"
    r")",
    re.IGNORECASE,
)
_ENV_FILE = re.compile(r"(?:^|[\\/])\.env(?:\.[\w-]+)?$", re.IGNORECASE)  # a path, not prose
_UNC = re.compile(r"^\\\\[^\\/\s]+\\[^\\/\s]+")


def check_paths(text: str, where: str) -> list[Finding]:
    out = []
    if _SENSITIVE_PATHS.search(text) or _ENV_FILE.search(text.strip()):
        out.append(Finding("path.sensitive", "high", f"Points at a sensitive file: '{text[:80]}'", where))
    if _TRAVERSAL.search(text):
        out.append(Finding("path.traversal", "medium", "Contains '../' directory traversal", where))
    if _UNC.match(text.strip()):
        out.append(Finding("path.unc", "medium", "Windows network path; connecting can leak credentials", where))
    return out


# ---------------------------------------------------------------- command and SQL injection

_SHELL_CMDS = (r"(?:rm|curl|wget|nc|ncat|netcat|bash|sh|zsh|dash|powershell|pwsh|cmd(?:\.exe)?|python[23]?"
               r"|perl|ruby|php|chmod|chown|scp|ssh|base64|eval|iex|certutil|mkfifo|telnet|socat|bitsadmin)")
# [ \t]{0,16}, not \s*: \s* runs across every following line break, which made this quadratic
# on a result made of newlines.
_CMD_CHAIN = re.compile(r"(?:;|&&|\|\||\$\(|\n)[ \t]{0,16}" + _SHELL_CMDS + r"\b", re.IGNORECASE)
_CMD_BACKTICK = re.compile(r"`\s*" + _SHELL_CMDS + r"\b[^`]*`", re.IGNORECASE)
_PIPE_TO_SHELL = re.compile(r"\|\s*(?:ba|z|da)?sh\b|\|\s*(?:iex|invoke-expression)\b", re.IGNORECASE)
_DEV_TCP = re.compile(r"/dev/(?:tcp|udp)/", re.IGNORECASE)

_SQL = [
    re.compile(r"'\s*(?:or|and)\s+'?\w+'?\s*(?:=|like)\s*'?\w+", re.IGNORECASE),
    re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE),
    re.compile(r";\s*(?:drop|truncate|alter|create)\s+(?:table|database|user)\b", re.IGNORECASE),
    re.compile(r"'\s*;\s*(?:--|#|/\*)", re.IGNORECASE),
    re.compile(r"'\s*(?:--|#)\s*$", re.IGNORECASE),
]


def check_injection(text: str, where: str) -> list[Finding]:
    out = []
    if _DEV_TCP.search(text):
        out.append(Finding("injection.command", "critical", "Reverse-shell pattern (/dev/tcp)", where))
    elif _PIPE_TO_SHELL.search(text):
        out.append(Finding("injection.command", "critical", "Output piped into a shell", where))
    elif m := _CMD_CHAIN.search(text):
        out.append(Finding("injection.command", "high", f"Chained shell command: '{m.group(0).strip()[:40]}'", where))
    elif m := _CMD_BACKTICK.search(text):
        out.append(Finding("injection.command", "high", f"Command substitution: '{m.group(0)[:40]}'", where))
    for pat in _SQL:
        m = pat.search(text)
        if m:
            out.append(Finding("injection.sql", "medium", f"SQL injection shape: '{m.group(0)[:40]}'", where))
            break
    return out


# ---------------------------------------------------------------- SSRF

_URL = re.compile(r"\b(?:https?|ftp|file|gopher|dict|ldap|tftp)://[^\s'\"<>`]+", re.IGNORECASE)
_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata", "100.100.100.200",
                   "fd00:ec2::254", "169.254.170.2", "metadata.azure.com"}


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    host = host.strip("[]")
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    # Decimal, hex and octal spellings such as 2130706433, 0x7f000001, 0177.0.0.1, 127.1.
    if re.fullmatch(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}", host, re.IGNORECASE):
        try:
            return ipaddress.ip_address(socket.inet_aton(host))
        except OSError:
            return None
    return None


def check_ssrf(text: str, where: str) -> list[Finding]:
    out: list[Finding] = []
    for m in _URL.finditer(text):
        url = m.group(0)
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        scheme = parts.scheme.lower()
        if scheme in ("file", "gopher", "dict", "ldap", "tftp"):
            out.append(Finding("ssrf.scheme", "high", f"{scheme}:// URL in arguments", where))
            continue
        if host in _METADATA_HOSTS:
            out.append(Finding("ssrf.metadata", "critical", f"Cloud metadata endpoint: {host}", where))
            continue
        ip = _parse_ip(host)
        if ip is not None:
            if str(ip) in _METADATA_HOSTS:
                out.append(Finding("ssrf.metadata", "critical", f"Cloud metadata endpoint: {host}", where))
            elif ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
                out.append(Finding("ssrf.internal", "high", f"Internal address: {host}", where))
        elif host == "localhost" or host.endswith(".localhost"):
            out.append(Finding("ssrf.internal", "high", f"Internal address: {host}", where))
        if len(out) >= 3:
            break
    return out


# ---------------------------------------------------------------- result-side exfiltration

_MD_IMAGE = re.compile(r"!\[[^\]\n]{0,200}\]\(\s*<?(https?://[^)\s>]+)", re.IGNORECASE)
_HTML_IMAGE = re.compile(r"<img\b[^>]{0,200}?\bsrc\s*=\s*['\"]?(https?://[^'\"\s>]+)", re.IGNORECASE)
_MD_LINK = re.compile(r"(?<!!)\[[^\]\n]{0,200}\]\(\s*<?(https?://[^)\s>]+)", re.IGNORECASE)
_DATA_CHUNK = re.compile(r"[A-Za-z0-9+/_=%-]{24,}")


_PLAIN_VALUE = re.compile(r"[a-z]+(?:[-_][a-z]+)*|(?i:[0-9a-f]{40}|[0-9a-f]{64})|[\w.-]+\.(?i:png|jpe?g|gif|svg|"
                          r"webp|ico|md|html?|json|ya?ml|txt|pdf|zip|tar|gz)|v?\d+(?:\.\d+)*")


# Badge and slug style: words, numbers or a colour code joined by - or _ (Visual_Studio-Install-C16FDE).
_WORD = r"(?:[A-Za-z][a-z]*|[A-Z]+|\d+|[0-9A-Fa-f]{6})"
_SLUG = re.compile(rf"{_WORD}(?:[-_]{_WORD})+")


def _looks_like_data(value: str, length: int) -> bool:
    """A URL part that could carry stolen text: long, and not a word, slug, file name, version or digest."""
    value = unquote(value)
    if len(value) < length:
        return False
    if len(value) > 512:  # no ordinary path segment or parameter is this long; also bounds the regexes below
        return True
    if re.search(r"\s", value):  # sentence-like text in a URL is never a normal parameter
        return True
    return not (_PLAIN_VALUE.fullmatch(value) or _SLUG.fullmatch(value)
                or re.fullmatch(r"[A-Za-z][a-z]+(?:[A-Z][a-z]+)+", value))


def _carries_data(url: str, threshold: int) -> bool:
    try:
        parts = urlsplit(url)
        query = parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        return False
    if any(_looks_like_data(v, threshold) or _looks_like_data(k, threshold * 2) for k, v in query):
        return True
    if parts.query and not query and _looks_like_data(parts.query, threshold):  # ?<payload> with no key
        return True
    return any(_looks_like_data(seg, threshold * 2) for seg in parts.path.split("/"))


def check_exfil(text: str, where: str) -> list[Finding]:
    out = []
    for pat in (_MD_IMAGE, _HTML_IMAGE):
        for m in pat.finditer(text):
            if _carries_data(m.group(1), 16):
                host = urlsplit(m.group(1)).hostname or "?"
                out.append(Finding("exfil.markdown_image", "high",
                                   f"Image URL to {host} carries data; clients load it without a click", where))
                return out
    for m in _MD_LINK.finditer(text):
        if _carries_data(m.group(1), 64):
            host = urlsplit(m.group(1)).hostname or "?"
            out.append(Finding("exfil.markdown_link", "medium", f"Link to {host} carries a long data payload", where))
            break
    return out


_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def check_encoded(text: str, where: str) -> list[Finding]:
    """Decode base64 blobs and look for instructions hidden inside."""
    for n, m in enumerate(_B64.finditer(text)):
        if n >= 20:
            break
        blob = m.group(0)
        if len(blob) > 65536:
            continue
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        printable = sum(c.isprintable() or c.isspace() for c in decoded)
        if not decoded or printable / len(decoded) < 0.9:
            continue
        hits = find_injection(decoded, where)
        if hits:
            worst = hits[0]
            return [Finding("injection.encoded", worst.severity,
                            f"Base64 text decodes to an instruction: {worst.message}", where)]
    return []


_ANSI = re.compile(r"\x1b(?:\[[0-9;?]*[A-Za-z]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[PX^_][^\x1b]*\x1b\\)")


def check_ansi(text: str, where: str) -> list[Finding]:
    if "\x1b" in text and _ANSI.search(text):
        return [Finding("hidden.ansi_escape", "medium",
                        "Terminal escape sequences can rewrite or hide what a person sees", where)]
    return []


# ---------------------------------------------------------------- definitions

_SHELL_CAPABILITY = re.compile(
    r"\b(?:execut\w*|run\w*|evaluat\w*)\s+(?:arbitrary|any|raw)?\s*(?:shell|system|bash|terminal|os)?\s*"
    r"(?:commands?|code|scripts?)\b(?:\s+on\s+the\s+(?:host|system|machine|server))?",
    re.IGNORECASE)
_SHELL_NAME = re.compile(r"(?:^|_)(?:exec|shell|bash|run_command|execute_command|run_shell|eval|terminal)(?:_|$)",
                         re.IGNORECASE)


def check_name(name: str, where: str) -> list[Finding]:
    out = []
    controls = [c for c in name if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp")]
    if controls:
        # Terminal escape sequences or invisible characters in a name a client may print or display.
        out.append(Finding("name.control_chars", "critical",
                           f"Tool name contains {len(controls)} control or invisible character(s) "
                           f"({', '.join(sorted({f'U+{ord(c):04X}' for c in controls})[:4])})", where))
    elif len(name) > 128 or re.search(r"[^\w.\-/:]", name):
        out.append(Finding("name.unusual", "medium", "Tool name has characters outside letters, digits, _ - . / :"
                                                     " or is longer than 128 characters", where))
    foreign = sorted({unicodedata.name(c, "?").split(" ")[0] for c in name if ord(c) > 127 and c.isalpha()})
    if foreign:
        out.append(Finding("name.confusable", "high",
                           f"Tool name uses non-Latin letters ({', '.join(foreign)}) that can imitate another tool",
                           where))
    if _SHELL_NAME.search(name):
        out.append(Finding("capability.shell", "low", "Tool name suggests shell command execution", where))
    return out


def check_capability(text: str, where: str) -> list[Finding]:
    m = _SHELL_CAPABILITY.search(text)
    if m and re.search(r"arbitrary|any|shell|system|bash|terminal|raw|os\b", m.group(0), re.IGNORECASE):
        return [Finding("capability.shell", "low", f"Advertises command execution: '{m.group(0)[:50]}'", where)]
    return []


def _distance_le1(a: str, b: str) -> bool:
    """True when a and b differ by at most one edit (insert, delete or substitute)."""
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = j = edits = 0
    while i < len(a) and j < len(b):
        if a[i] != b[j]:
            edits += 1
            if edits > 1:
                return False
            if len(a) == len(b):
                i += 1
            j += 1
        else:
            i += 1
            j += 1
    return edits + (len(b) - j) <= 1


def cross_server_names(catalog: dict[str, list[str]]) -> list[Finding]:
    """Duplicate or near-identical tool names across servers (shadowing, typosquatting)."""
    owners: dict[str, list[str]] = {}
    for server, names in catalog.items():
        for name in names:
            owners.setdefault(name, []).append(server)
    out = []
    for name, servers in sorted(owners.items()):
        if len(servers) > 1:
            out.append(Finding("shadowing.duplicate_name", "medium",
                               f"'{name}' is offered by {', '.join(sorted(servers))}", f"*.{name}", subject=name))
    flat = [(s, n) for s, names in catalog.items() for n in names]
    seen = set()
    for i, (s1, n1) in enumerate(flat):
        for s2, n2 in flat[i + 1:]:
            if s1 == s2 or n1 == n2 or len(n1) < 5 or len(n2) < 5:
                continue
            key = tuple(sorted((f"{s1}/{n1}", f"{s2}/{n2}")))
            if key not in seen and _distance_le1(n1.lower(), n2.lower()):
                seen.add(key)
                out.append(Finding("shadowing.similar_name", "medium",
                                   f"'{s1}/{n1}' and '{s2}/{n2}' differ by one character", f"{s2}.{n2}",
                                   subject=n2))
    return out


# ---------------------------------------------------------------- entry points used by Engine


def args_checks(text: str, where: str) -> list[Finding]:
    return check_paths(text, where) + check_injection(text, where) + check_ssrf(text, where)


# ---------------------------------------------------------------- injections inside tool results
#
# A tool result is data: an email, a web page, a review. Text in it that talks to the
# assistant, fakes a chat role, or asks for information to be sent somewhere is an
# indirect prompt injection whatever its wording. These checks run on results only;
# a tool's own description legitimately says "use this tool".

_AI = r"(?:ai|a\.i\.|assistant|ai assistant|model|language model|llm|agent|ai agent|chatbot|copilot|claude|chatgpt|gpt)"
_ADDRESSES_MODEL = re.compile("|".join([
    rf"\bto you,?\s+(?:the\s+|my\s+)?{_AI}\b",
    r"\b(?:the\s+)?(?:task|request|instructions?|question)s?\s+(?:that\s+)?(?:i|the user)\s+"
    r"(?:gave|asked|assigned|sent|give|ask)\s+you\b",
    rf"(?:^|[\n.!?][ \t]{{0,4}})(?:dear|attention|note to|hey|hello|hi)\s+(?:the\s+)?{_AI}[ \t]{{0,4}}[,:!]",
    rf"\bif you are an? {_AI}\b",
    rf"\b(?:as|you are) an? {_AI},? you (?:must|should|need to|have to)\b",
]), re.I)
_ROLE_MARKER = re.compile("|".join([
    # ###(system_message) or ##system_prompt, not a markdown heading such as "### System prompt"
    r"(?<!#)#{2,}+[ \t]{0,4}\([ \t]{0,4}system(?:[ _-]?(?:message|prompt|note|instruction)s?)?[ \t]{0,4}\)"
    r"|(?<!#)#{2,}+[ \t]{0,4}system[_-](?:message|prompt)",
    r"\[[ \t]{0,4}(?:system|admin|administrator|developer)(?:[ _-](?:message|prompt|note|override))?[ \t]{0,4}\]",
    r"<\|[ \t]{0,4}(?:im_start|im_end|system|endoftext|eot_id|start_header_id)[ \t]{0,4}\|>",
    r"(?:^|\n)[ \t]{0,8}(?:system|developer) (?:message|prompt|override|instruction)s?[ \t]{0,4}:",
]), re.I)
_EMAIL = r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"
_DEST = rf"(?:{_EMAIL}|https?://\S+)"
_SEND = r"(?:send|email|e-mail|mail|forward|share|upload|post|transmit|deliver)"
_FETCH = (r"(?:retrieve|retrive|get|fetch|find|list|download|collect|gather|extract|access|search|read|look up|"
          r"check|pull|export|copy|grab|obtain)")
# Gather-then-send may span sentences ("Fetch X. Once you have it, email it to ..."), but
# stays inside one paragraph; addresses and file names contain dots, so [^\n] not [^.].
_EXFIL_CHAIN = re.compile(rf"\b{_FETCH}\b[^\n]{{0,240}}?\b{_SEND}\s+(?:it|them|this|that|these|those|all|the|"
                          rf"my|our|your|a|an|those|its|their)\b[^\n]{{0,120}}?\b(?:to|at|with)\b[^\n]{{0,40}}?{_DEST}",
                          re.I)
_EXFIL_SEND = re.compile(rf"\b{_SEND}\s+(?:it|them|this|that|these|those|all|the|my|our|your)\b[^\n]{{0,80}}?"
                         rf"\b(?:to|with)\b[^\n]{{0,30}}?{_DEST}", re.I)
# A named tool: quoted, or written as code (GmailSendEmail, send_email), then "tool"/"function".
_TOOL_DIRECTIVE = re.compile(r"\b(?:use|using|call|calling|invoke|invoking)\s+(?:the\s+)?"
                             r"(?:[`'\"][\w.-]+[`'\"]|(?:[A-Z][a-z0-9]+){2,}|[a-z0-9]+(?:_[a-z0-9]+)+)"
                             r"\s+(?:tool|function|api)\b")


# Requests for actions with real-world consequences. Written from the action categories, not
# from benchmark samples. Medium: a genuine email can ask for a payment too, so this warns.
_REQ = r"(?:^|[.!?\n:\"'][ \t]{0,4}|\bplease\s+|\bkindly\s+|\bcan you\s+|\bcould you\s+|\bi need you to\s+)"
_RISKY_REQUEST = re.compile(_REQ + r"(?:" + "|".join([
    r"(?:transfer|wire|send|pay|deposit|move)\s+(?:\$|usd|eur|£|€)?\s?\d[\d,.]*\s*(?:k|usd|dollars|eur|euros|"
    r"pounds|btc|eth)?|(?:transfer|wire|send|pay|move)\s+(?:(?:the\s+|all\s+(?:the\s+|my\s+)?|my\s+)?(?:funds|"
    r"money|savings|balance|crypto|bitcoin)|(?:the|a|my)\s+payment)",
    r"(?:grant|give|share|provide)\s+(?:\w+\s+){0,4}?(?:permanent\s+|full\s+|admin(?:istrator)?\s+|root\s+|"
    r"owner\s+)?access\b",
    r"(?:unlock|open)\s+(?:the\s+|my\s+|our\s+)?(?:front\s+|back\s+|garage\s+|main\s+|smart\s+)?"
    r"(?:door|lock|gate|garage|safe)\b",
    r"(?:disable|deactivate|turn\s+off|switch\s+off|disarm)\s+(?:the\s+|my\s+|all\s+)?(?:\w+\s+)?"
    r"(?:alarm|security|cameras?|firewall|antivirus|2fa|two[- ]factor|mfa|monitoring)",
    r"(?:delete|erase|wipe|destroy|remove)\s+(?:all|every|the\s+entire|everything)\b",
    r"(?:change|reset|update)\s+(?:the\s+|my\s+)?(?:account\s+)?(?:password|passcode|recovery\s+email|"
    r"2fa|two[- ]factor)",
]) + r")", re.I)


# Things worth stealing. A request to send one of these to an address is not a normal message.
_SENSITIVE_OBJECT = re.compile(
    r"\b(?:private|secret|ssh|api|access|auth(?:entication)?|signing)\s+(?:keys?|tokens?)\b|\bcredentials?\b"
    r"|\bpass(?:words?|codes?|phrases?)\b|\bsecrets?\b|\bsession\s+cookies?\b|\brecovery\s+(?:codes?|phrases?)\b"
    r"|\bseed\s+phrases?\b|\.env\b", re.I)


_NEGATION = re.compile(r"\b(?:never|not|don'?t|do\s+not|avoid|nobody|no\s+one|should\s+not|shouldn'?t)\b", re.I)


def check_result_injection(text: str, where: str) -> list[Finding]:
    out = []
    m = _RISKY_REQUEST.search(text)
    if m:
        out.append(Finding("injection.risky_request", "medium",
                           f"Data asks for a high-risk action: '{m.group(0).strip()[:70]}'", where))
    m = _ADDRESSES_MODEL.search(text)
    if m:
        out.append(Finding("injection.addresses_model", "high", f"Data speaks to the assistant: '{m.group(0)[:60]}'",
                           where))
    m = _ROLE_MARKER.search(text)
    if m:
        out.append(Finding("injection.role_marker", "high", f"Fake chat marker in data: '{m.group(0)[:60]}'",
                           where))
    m = _EXFIL_CHAIN.search(text)
    if m:
        out.append(Finding("injection.exfil_request", "high",
                           f"Request to gather information and send it out: '{m.group(0)[:80]}'", where))
    else:
        m = _EXFIL_SEND.search(text)
        if m:
            warned = _NEGATION.search(text[max(0, m.start() - 30):m.start()])  # "never send your password to ..."
            level = "high" if _SENSITIVE_OBJECT.search(m.group(0)) and not warned else "medium"
            out.append(Finding("injection.exfil_request", level,
                               f"Request to send {'credentials or keys' if level == 'high' else 'information'}"
                               f" to an address: '{m.group(0)[:80]}'", where))
    m = _TOOL_DIRECTIVE.search(text)
    if m:
        out.append(Finding("injection.tool_directive", "medium", f"Data names a tool to use: '{m.group(0)[:60]}'",
                           where))
    return out


_TOOL_CALL_SHAPE = re.compile(
    r'"name"\s*:\s*"[\w./-]{2,64}"\s*,\s*"(?:arguments|input|parameters)"\s*:\s*\{|<\s*(?:tool_call|function_call|tool_use)\b',
    re.I)
_PLACEHOLDER_IMAGE = re.compile(
    r"!\[[^\]]*\]\(\s*(?:https?:)?//[^)]*?(?:\{\{|%7B%7B|\$\{|<[a-z]|%3C[a-z])", re.I)
_SQUEEZED = ("ignorepreviousinstructions", "ignoreallpreviousinstructions", "disregardpreviousinstructions",
             "ignorepriorinstructions", "forgetpreviousinstructions", "ignoretheaboveinstructions",
             "ignoreallpriorinstructions", "disregardallpreviousinstructions")


_ENTITIES = re.compile(r"(?:&#x?[0-9a-fA-F]{2,6};){6,}")
_QP_RUN = re.compile(r"(?:=[0-9A-F]{2}){8,}")
_BLOCK_CODECS = (
    ("base32", re.compile(r"\b[A-Z2-7]{32,}={0,6}"), lambda t: base64.b32decode(t + "=" * (-len(t) % 8))),
    ("base85", re.compile(r"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]{25,}"), lambda t: base64.b85decode(t)),
    ("ascii85", re.compile(r"<~[!-u\s]{10,2000}~>|[!-u]{25,}"),
     lambda t: base64.a85decode(t, adobe=t.startswith("<~"))),
)
# Anchored at line starts and capped per line, so a long run of one character cannot make it quadratic.
_WRAPPED_B64 = re.compile(r"(?m)^(?:[A-Za-z0-9+/_-]{16,200}[ \t]*\r?\n){1,40}[A-Za-z0-9+/_-]{4,200}={0,2}[ \t]*$")


def _unquote_qp(m: re.Match[str]) -> str:
    return bytes(int(h, 16) for h in re.findall(r"[0-9A-Fa-f]{2}", m.group(0))).decode("latin-1")


def _hidden_views(text: str) -> list[tuple[str, str]]:
    """(how it was hidden, the text read back): ROT13, reversed, hex bytes, and the letters with the
    spaces and punctuation taken out (an instruction split into pieces)."""
    views = [("ROT13", codecs.encode(text[:100_000], "rot13")), ("reversed", text[:100_000][::-1])]
    for m in list(re.finditer(r"\b(?:[0-9a-fA-F]{2}){12,}\b", text))[:10]:
        try:
            views.append(("hex", bytes.fromhex(m.group(0)).decode("utf-8")))
        except ValueError:
            continue
    if _ENTITIES.search(text[:100_000]):
        views.append(("HTML-entity", html.unescape(text[:100_000])))
    if _QP_RUN.search(text):
        views.append(("quoted-printable", _QP_RUN.sub(_unquote_qp, text[:100_000])))
    for label, rx, decode in _BLOCK_CODECS:
        for m in list(rx.finditer(text[:100_000]))[:10]:
            try:
                views.append((label, decode(m.group(0)).decode("utf-8")))
            except (ValueError, binascii.Error, UnicodeDecodeError):
                continue
    for m in list(_WRAPPED_B64.finditer(text[:100_000]))[:5]:  # base64 wrapped over lines, or the URL-safe alphabet
        joined = re.sub(r"\s+", "", m.group(0)).replace("-", "+").replace("_", "/")
        try:
            views.append(("wrapped base64", base64.b64decode(joined + "=" * (-len(joined) % 4)).decode("utf-8")))
        except (ValueError, binascii.Error, UnicodeDecodeError):
            continue
    return views


def check_hidden_forms(text: str, where: str) -> list[Finding]:
    """Instructions and exfiltration dressed up so a plain pattern does not see them."""
    out: list[Finding] = []
    for how, view in _hidden_views(text):
        hits = find_injection(view, where) + check_result_injection(view, where)
        if hits:
            worst = max(hits, key=lambda f: ("info", "low", "medium", "high", "critical").index(f.severity))
            out.append(Finding("injection.encoded", worst.severity,
                               f"Text {how}-encoded reads as an instruction: {worst.message}", where))
            break
    squeezed = re.sub(r"[^a-z]", "", text[:100_000].lower())
    if any(p in squeezed for p in _SQUEEZED) and not find_injection(text, where):
        out.append(Finding("injection.obfuscated", "high",
                           "Letters split by spaces or punctuation spell out an instruction to ignore earlier ones",
                           where))
    if _PLACEHOLDER_IMAGE.search(text):
        out.append(Finding("exfil.markdown_image", "high",
                           "Image URL contains a placeholder for data; clients load it without a click", where))
    if _TOOL_CALL_SHAPE.search(text):
        out.append(Finding("injection.tool_directive", "medium",
                           "Data contains text shaped like a tool call, which a model may act on", where))
    return out


def result_checks(text: str, where: str) -> list[Finding]:
    return (check_exfil(text, where) + check_encoded(text, where) + check_ansi(text, where)
            + check_result_injection(text, where) + check_hidden_forms(text, where))


def definition_checks(text: str, where: str) -> list[Finding]:
    return check_ansi(text, where) + check_capability(text, where)
