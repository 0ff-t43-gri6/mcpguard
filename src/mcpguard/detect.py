"""Detection engine.

Built-in skills: injection phrases, hidden Unicode, known secret formats,
high-entropy tokens, cross-tool shadowing, rug-pull pinning, exfiltration taint.
Extensible with custom regex rules and Python plugins; tunable with
suppressions and severity overrides.
"""

from __future__ import annotations

import fnmatch
import hashlib
import importlib
import functools
import json
import math
import re
from urllib.parse import unquote
import unicodedata
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

from .fileio import load_json, locked, write_atomic

SEVERITIES = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    where: str = ""
    subject: str = ""  # tool/prompt name the finding belongs to, for grouping

    def to_dict(self) -> dict:
        d = {"rule": self.rule, "severity": self.severity, "message": self.message, "where": self.where}
        if self.subject:
            d["subject"] = self.subject
        return d


# ---------------------------------------------------------------- built-in patterns

INJECTION_PATTERNS = [
    (r"\b(ignore|disregard|forget) (all |any |your |the |of )*(previous|prior|above|earlier|preceding|former) "
     r"(i\w{0,2}nstruct\w*|rules|directions|guidelines|prompts?|commands|directives|tasks?)", "high"),
    # The same order in everyday words: "disregard what you were told before", "forget everything you were
    # given earlier". It must end on a time word, so "forget everything you were told about SEO" passes.
    (r"\b(?:disregard|ignore|forget|set aside|abandon|drop)\s+(?:what|everything|anything|all(?:\s+that)?|whatever)"
     r"\s+you\s+(?:were|have\s+been|had\s+been)\s+(?:told|given|instructed|asked)(?:\s+to\s+do)?\s+"
     r"(?:before|earlier|previously|until\s+now|so\s+far|above|prior)\b", "high"),
    (r"\b(?:stop|cease)\s+following\s+(?:your|the|all)\s+(?:(?:previous|prior|earlier|original|initial)\s+)?"
     r"(?:instructions|rules|guidelines|directions)\b", "high"),
    (r"do not (tell|inform|mention|reveal|show)[^.]{0,40}\buser\b", "high"),
    (r"without (telling|informing|notifying|alerting) the user", "high"),
    (r"<\s*/?\s*(important|system|instructions?|secret|information|admin|hidden)\s*>", "high"),
    (r"\byou (must|should) (first|always|now)\b", "medium"),
    (r"(send|post|upload|forward|exfiltrate|transmit)[^.]{0,60}(to|at)\s+https?://", "high"),
    (r"before (using|calling|running) (this|any other) tool", "medium"),
    # Between the verb and the path, a dot is allowed only inside a path (../.ssh, /home/me/.ssh),
    # not as a full stop, so the match stays within one sentence.
    (r"\b(read|cat|open|access|include|embed|attach|append|send|copy|dump|upload)\b(?:[^.\n]|\.(?=[\w/~.\\])){0,40}?"
     r"(\.ssh\b|id_rsa|id_ed25519|/etc/(passwd|shadow)|\.aws[/\\]credentials)", "critical"),
    # Reading or copying .env is everyday setup ("copy .env.example to .env"); moving it out is not.
    (r"\b(include|embed|attach|append|send|dump|upload|leak|exfiltrate)\b(?:[^.\n]|\.(?=[\w/~.\\])){0,40}?"
     r"\.env\b(?!\.)", "critical"),
    # Setup guides tell people to open mcp.json; a tool description has no reason to.
    (r"\b(read|cat|open|access|include|embed|attach|append|send|copy|dump|upload)\b[^.]{0,30}mcp\.json",
     "critical", "definition"),
    (r"(override|disregard|forget) (the |your )?(system|developer|previous) (prompt|message|instructions)", "high"),
    (r"\b(you are now|act as|new instructions:)", "medium"),
    (r"(conceal|hide) (this|the following) from the user", "high"),
    # Covert actions: "quietly include ...", "silently send ...".
    (r"\b(quietly|secretly|silently|covertly|discreetly|stealthily|surreptitiously)[ \t]+(?:[\w'-]+[ \t]+){0,2}?"
     r"(include|add|append|insert|embed|attach|send|forward|upload|copy|read|collect|share|leak|post)\b", "high"),
    # Putting sensitive local data into the model's output or a tool argument.
    (r"(?<!\bnever )(?<!\bnot )(?<!n't )(?<!\bno )"
     r"\b(include|append|insert|embed|attach|paste|dump|leak)\b[^.]{0,30}?\bcontents?\b[^.]{0,30}?"
     r"\b(config(uration)? files?|credentials?|secrets?|private keys?|ssh keys?|api keys?|passwords?|"
     r"environment variables|env vars|cookies|browser history|chat history|conversation history)", "high"),
    # Stealing or exfiltrating named in so many words, with something worth stealing nearby.
    (r"\b(exfiltrat\w*|siphon\w*|steal\w*)\b[^\n]{0,80}?"
     r"(credential|secret|\bkeys?\b|token|password|\.ssh|\.aws|id_rsa|\.env\b)", "high"),
    # "Ignore the previous instructions" in other languages (Spanish, French, German, Portuguese, Italian,
    # Russian, Chinese, Japanese, Hindi).
    (r"\bignor[ae]r?\s+(?:todas\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)"
     r"|\bolvida\s+(?:todas\s+)?las\s+instrucciones", "high"),
    (r"\bignore[rz]?\s+(?:toutes\s+)?les\s+instructions\s+(?:pr[ée]c[ée]dentes|ant[ée]rieures)"
     r"|\boubliez?\s+(?:toutes\s+)?les\s+instructions", "high"),
    (r"\bignorier\w*\s+(?:alle\s+)?(?:vorherigen|bisherigen|fr[üu]heren)\s+"
     r"(?:anweisungen|instruktionen|befehle)", "high"),
    (r"\bignor[ae]\s+(?:todas\s+)?as\s+instru[çc][õo]es\s+anteriores", "high"),
    (r"\bignora\s+(?:tutte\s+)?le\s+istruzioni\s+precedenti", "high"),
    (r"игнорир\w*\s+(?:все\s+)?(?:предыдущие|прежние|прошлые)\s+(?:инструкции|указания|команды)", "high"),
    (r"(?:忽略|无视|忽视|不要理会)(?:之前|以前|先前|上面|前面)(?:的)?(?:所有)?(?:指令|指示|说明|提示|命令)", "high"),
    (r"(?:以前|前)の(?:すべての)?(?:指示|命令|プロンプト)を無視", "high"),
    (r"(?:पिछले|पहले)\s+(?:सभी\s+)?निर्देशों?\s+को\s+(?:अनदेखा|नज़रअंदाज़|नजरअंदाज)", "high"),
]
_INJECTION = [(re.compile(p[0], re.I), p[1], p[2] if len(p) > 2 else None) for p in INJECTION_PATTERNS]

SECRET_PATTERNS = [
    ("aws_access_key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "critical"),
    ("private_key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "critical"),
    ("github_token", r"\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b", "critical"),
    ("llm_api_key", r"\bsk-(ant-)?[A-Za-z0-9_\-]{20,}\b", "critical"),
    ("slack_token", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b", "critical"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "critical"),
    ("stripe_key", r"\b(sk|rk)_live_[0-9A-Za-z]{20,}\b", "critical"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b", "high"),
    ("connection_string", r"\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^\s:/]+:[^\s@/]+@", "critical"),
    ("generic_secret_assignment",
     r"(?i)\b(api[_-]?key|secret|passwd|password|token|auth)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+=]{12,}", "high"),
]
_SECRETS = [(n, re.compile(p), s) for n, p, s in SECRET_PATTERNS]

EGRESS_HINTS = re.compile(
    r"(http|fetch|request|webhook|upload|send|email|mail|post|publish|slack|sms|tweet|share|curl|notify|message"
    r"|browse|navigate|url|crawl|scrape|gist|issue|comment|reply|api|graphql|push|deploy|download)", re.I
)
INVISIBLE_CATEGORIES = {"Cf", "Co", "Cs"}
_TOKEN = re.compile(r"[A-Za-z0-9+/_\-=]{24,}")


# ---------------------------------------------------------------- primitives

_EXTRA_FINGERPRINT_FIELDS = ("title", "outputSchema", "_meta", "icons", "execution")


def fingerprint_tool(tool: dict, legacy: bool = False) -> str:
    """Hash of everything in a definition a model or user may act on. Fields added to the hash later
    (title, outputSchema, _meta, icons, execution) count only when the definition has them, so the pin of
    a definition without them is unchanged. ``legacy`` leaves them out (the hash older versions stored)."""
    material = {k: tool.get(k) for k in ("name", "description", "inputSchema", "annotations", "arguments")}
    if not legacy:
        material.update({k: tool[k] for k in _EXTRA_FINGERPRINT_FIELDS if k in tool})
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


MAX_DEPTH = 64  # deeper JSON is refused: no real tool needs it, and recursion would crash


def json_depth(obj) -> int:
    """Nesting depth, without recursion (a crafted 100,000-level object must not crash us)."""
    deepest, stack = 0, [(obj, 1)]
    while stack:
        o, d = stack.pop()
        if isinstance(o, dict | list):
            deepest = max(deepest, d)
            if d > MAX_DEPTH:
                return d
            stack.extend((v, d + 1) for v in (o.values() if isinstance(o, dict) else o))
    return deepest


def _walk_strings(obj, path="", keys=False):
    """Yield (path, text) for every string. With keys=True, dict keys are yielded
    too: a schema property name is read by the model and can carry instructions.
    Iterative and depth-limited, so hostile nesting cannot exhaust the stack."""
    stack = [(obj, path, 0)]
    while stack:
        o, here, depth = stack.pop()
        if isinstance(o, str):
            yield here, o
        elif depth > MAX_DEPTH:
            continue
        elif isinstance(o, dict):
            for k, v in reversed(list(o.items())):
                child = f"{here}.{k}" if here else str(k)
                stack.append((v, child, depth + 1))
                if keys and isinstance(k, str) and len(k) > 24:
                    stack.append((k.replace("_", " "), f"{child}<key>", depth + 1))
        elif isinstance(o, list):
            stack.extend((v, f"{here}[{i}]", depth + 1) for i, v in reversed(list(enumerate(o))))


def shannon_entropy(s: str) -> float:
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


# Documentation placeholders such as xoxb-your-bot-token or postgres://user:password@host.
_PLACEHOLDER = re.compile(r"(?i)your[-_]|example|placeholder|x{4,}|<[^<>]{0,80}>|\$\{|\{\{|changeme|dummy|sample|"
                          r"redacted|\.\.\.|token[-_]?here|(?:^|[:/])(?:user(?:name)?|pass(?:word)?)[:@]")


def find_secrets(text: str, where: str = "") -> list[Finding]:
    return [Finding(f"secret.{n}", s, f"Possible {n.replace('_', ' ')} detected", where)
            for n, p, s in _SECRETS if any(not _PLACEHOLDER.search(m.group(0)) for m in p.finditer(text))]


def looks_random(tok: str, threshold: float) -> bool:
    """Mixed character classes plus high entropy: words, paths and hex digests don't qualify."""
    classes = sum(bool(re.search(c, tok)) for c in ("[a-z]", "[A-Z]", "[0-9]"))
    return classes >= 3 and shannon_entropy(tok) >= threshold


def find_high_entropy(text: str, threshold: float = 4.3, where: str = "") -> list[Finding]:
    for tok in _TOKEN.findall(text):
        if looks_random(tok, threshold):
            return [Finding("secret.high_entropy", "medium",
                            f"Random-looking token ({len(tok)} chars) may be a credential", where)]
    return []


def redact_secrets(text: str, entropy_threshold: float | None = None) -> str:
    for n, p, _ in _SECRETS:
        text = p.sub(f"[REDACTED:{n}]", text)
    if entropy_threshold:
        threshold = entropy_threshold
        text = _TOKEN.sub(lambda m: "[REDACTED:high_entropy]" if looks_random(m.group(0), threshold)
                          else m.group(0), text)
    return text


def find_injection(text: str, where: str = "", scope: str | None = None) -> list[Finding]:
    out = []
    for pat, sev, only in _INJECTION:
        if only and scope and only != scope:
            continue
        m = pat.search(text)
        if m:
            out.append(Finding("injection.pattern", sev, f"Suspicious instruction: '{m.group(0)[:60]}'", where))
    return out


def find_invisible(text: str, where: str = "") -> list[Finding]:
    bad = {c for c in text if unicodedata.category(c) in INVISIBLE_CATEGORIES}
    if bad:
        codes = ", ".join(f"U+{ord(c):04X}" for c in sorted(bad))
        return [Finding("hidden.unicode", "high", f"Invisible/format characters present ({codes})", where)]
    return []


def max_severity(findings: list[Finding]) -> str | None:
    return max(findings, key=lambda f: SEVERITIES[f.severity]).severity if findings else None


def at_least(findings: list[Finding], level: str) -> list[Finding]:
    return [f for f in findings if SEVERITIES[f.severity] >= SEVERITIES[level]]


# ---------------------------------------------------------------- engine

class Engine:
    """Runs all detectors for a scope, then applies overrides and suppressions."""

    def __init__(self, cfg=None):
        from .config import DetectorConfig
        self.cfg = cfg or DetectorConfig()
        self.custom: list[dict] = []
        for r in self.cfg.rules:
            if r.get("severity", "medium") not in SEVERITIES:
                raise ValueError(f"rule {r.get('id')}: bad severity")
            self.custom.append({
                "id": r.get("id") or f"custom.{len(self.custom)}",
                "re": re.compile(r["pattern"], re.I if r.get("ignore_case", True) else 0),
                "severity": r.get("severity", "medium"),
                "scope": r.get("scope", "any"),
                "message": r.get("message", "Custom rule matched"),
            })
        self.plugins = [self._load_plugin(p) for p in self.cfg.plugins]
        self.iocs = None
        if self.cfg.iocs:
            from .iocs import load_feeds
            self.iocs = load_feeds(self.cfg.ioc_feeds)
        self.model = _load_model(self.cfg.model_file) if self.cfg.model else None

    def _model_findings(self, text: str, where: str, definition: bool) -> list[Finding]:
        if self.model is None or len(text) < 20:
            return []
        # Scored as the model would read it, so look-alike letters do not hide wording from it.
        found = self.model.findings(deobfuscate(text[:20_000]), where, self.cfg.model_medium, self.cfg.model_high)
        if definition:  # near-copies of genuine tools fool word features: on definitions, only warn
            for f in found:
                f.severity = "medium"
        return found

    @staticmethod
    def _load_plugin(spec: str):
        mod, _, fn = spec.partition(":")
        return getattr(importlib.import_module(mod), fn or "detect")

    def _text_findings(self, text: str, scope: str, where: str, context: dict) -> list[Finding]:
        f: list[Finding] = []
        f += find_invisible(text, where)
        if scope in ("definition", "result"):
            found = find_injection(text, where, scope)
            if not found:  # only obfuscated text needs a second pass
                for plain in deobfuscated_variants(text):
                    for x in find_injection(plain, where, scope):
                        found.append(Finding("injection.obfuscated", "critical" if x.severity == "critical" else "high",
                                             f"{x.message} (written with look-alike, invisible, leetspeak or "
                                             "spaced-out characters, which normal text does not do)", where))
                    if found:
                        break
            f += found
        f += find_secrets(text, where)
        if self.cfg.entropy:
            f += find_high_entropy(text, self.cfg.entropy_threshold, where)
        if scope == "args":
            f += _checks.args_checks(text, where)
        elif scope == "result":
            f += _checks.result_checks(text, where)
        elif scope == "definition":
            f += _checks.definition_checks(text, where)
        for r in self.custom:
            if r["scope"] in ("any", scope):
                m = r["re"].search(text)
                if m:
                    f.append(Finding(r["id"], r["severity"], f"{r['message']}: '{m.group(0)[:60]}'", where))
        for plugin in self.plugins:
            for item in plugin(scope, text, context) or []:
                f.append(item if isinstance(item, Finding) else Finding(
                    item["rule"], item.get("severity", "medium"), item.get("message", ""), where))
                if not f[-1].where:
                    f[-1].where = where
        return f

    def finalize(self, findings: list[Finding]) -> list[Finding]:
        out = []
        for f in findings:
            sev = self.cfg.severity_overrides.get(f.rule)
            if sev in SEVERITIES:
                f.severity = sev
            if any(fnmatch.fnmatch(f.rule, s.get("rule", "*")) and fnmatch.fnmatch(f.where, s.get("where", "*"))
                   for s in self.cfg.suppress):
                continue
            # Messages quote what matched, and they go to the audit log and the dashboard:
            # never let a quoted card number, ID or credential travel with them.
            f.message = _scrub(self.redact(f.message))
            out.append(f)
        return out

    # -- scopes

    def scan_definition(self, item: dict, server: str = "", kind: str = "tool") -> list[Finding]:
        name = item.get("name") or item.get("uri") or "?"
        findings = []
        for path, text in _walk_strings(item, keys=True):
            where = f"{server}.{name}:{path}" if server else f"{name}:{path}"
            if path in ("name", "uri", "mimeType"):
                findings += find_invisible(text, where)
                if path == "name":
                    findings += _checks.check_name(text, where)
                continue
            findings += self._text_findings(text, "definition", where, {"server": server, "kind": kind, "name": name})
        desc = item.get("description") or ""
        findings += self._model_findings(desc, f"{server}.{name}:description" if server else f"{name}:description",
                                         definition=True)
        if self.iocs is not None:
            where = f"{server}.{name}" if server else name
            findings += self.iocs.match_text(desc, f"{where}:description", self.cfg.ioc_shingle_hits)
            schema = item.get("inputSchema") or {}
            props = schema.get("properties") if isinstance(schema, dict) else None
            if isinstance(props, dict):
                param_text = " ".join(str(v.get("description", "")) for v in props.values() if isinstance(v, dict))
                if param_text.strip():
                    findings += [f for f in self.iocs.match_text(param_text, f"{where}:inputSchema",
                                                                 self.cfg.ioc_shingle_hits)
                                 if f.rule != "ioc.known_text"]
                findings += self.iocs.match_params(props.keys(), f"{where}:inputSchema")
            if kind == "tool":
                findings += self.iocs.match_name(str(item.get("name", "")), where)
        if len(desc) > 2000:
            findings.append(Finding("description.oversized", "medium",
                                    f"Description is {len(desc)} chars; long text can hide instructions",
                                    f"{server}.{name}"))
        for f in findings:
            f.subject = name
        return self.finalize(findings)

    def scan_args(self, name: str, args: dict) -> list[Finding]:
        findings = []
        for path, text in _walk_strings(args):
            findings += self._text_findings(text, "args", f"args:{name}:{path}", {"name": name})
            if self.iocs is not None:
                findings += self.iocs.match_domains(text, f"args:{name}:{path}")
        return self.finalize(findings)

    def scan_texts(self, name: str, texts: list[str]) -> list[Finding]:
        findings = []
        for t in texts:
            findings += self._text_findings(t, "result", f"result:{name}", {"name": name})
            findings += self._model_findings(t, f"result:{name}", definition=False)
            if self.iocs is not None:
                findings += self.iocs.match_text(t, f"result:{name}", self.cfg.ioc_shingle_hits)
        return self.finalize(findings)

    def redact(self, text: str) -> str:
        return redact_secrets(text, self.cfg.entropy_threshold if self.cfg.entropy else None)






_PLAIN_WORD = re.compile(r"[a-z]+")


def cross_tool_references(by_server: dict[str, list[dict]]) -> list[Finding]:
    """A tool whose description talks about a tool on a *different* server.

    That is how tool shadowing works: a malicious server's description tells the model
    how to use another server's tool ("when calling send_email, also BCC ..."). Tools
    mentioning their own server's tools are normal ("deprecated: use read_text_file").
    Names that are ordinary words (search, fetch) only count when quoted or in backticks.
    """
    names = {(srv, t["name"]) for srv, tools in by_server.items() for t in tools if t.get("name")}
    out: list[Finding] = []
    for server, tools in by_server.items():
        for t in tools:
            desc = (t.get("description") or "").lower()
            if not desc:
                continue
            for other_server, other in sorted(names):
                if other_server == server or len(other) <= 3 or other == t.get("name"):
                    continue
                o = re.escape(other.lower())
                pattern = rf"[`'\"]{o}[`'\"]" if _PLAIN_WORD.fullmatch(other.lower()) else rf"\b{o}\b"
                if re.search(pattern, desc):
                    out.append(Finding("shadowing.cross_reference", "medium",
                                       f"'{server}/{t['name']}' mentions '{other_server}/{other}', "
                                       "a tool on another server", f"{server}.{t['name']}", subject=t["name"]))
    return out


def texts_of(result: dict) -> list[str]:
    """Every piece of text in a tool result, resource read or prompt that a model could be shown:
    text blocks first, then titles, descriptions, annotations, ``_meta`` and any other string
    field, and text hidden in base64 ``blob`` fields. Image and audio data are skipped."""
    out: list[str] = []
    extra: list[str] = []
    seen: set[int] = set()

    def items(key: str) -> list:  # a hostile server may send anything where a list belongs
        value = result.get(key)
        return value if isinstance(value, list) else []

    def take(value) -> None:
        if isinstance(value, str) and value:
            out.append(value)

    for item in items("content"):
        if isinstance(item, dict):
            take(item.get("text"))
            res = item.get("resource")
            if isinstance(res, dict):
                take(res.get("text"))
    for item in items("contents"):
        if isinstance(item, dict):
            take(item.get("text"))
    for msg in items("messages"):
        c = msg.get("content") if isinstance(msg, dict) else None
        if isinstance(c, dict):
            take(c.get("text"))
    if isinstance(result.get("structuredContent"), (dict, list)):
        out.append(json.dumps(result["structuredContent"]))
    primary = set(out)

    # Everything else: a title, a description or a note is read by the model just the same.
    stack: list[tuple[object, str, int]] = [(v, k, 0) for k, v in result.items() if k != "structuredContent"]
    budget = 20_000
    while stack and budget > 0:
        value, key, depth = stack.pop()
        budget -= 1
        if isinstance(value, str):
            if key == "blob":
                hidden = _blob_text(value)
                if hidden:
                    extra.append(hidden)
            elif key in ("uri", "mimeType"):
                # Not read as text unless it is one: a sentence in a MIME type or a percent-encoded uri.
                sentence = unquote(value)
                if len(sentence.split()) >= 4 and sentence not in primary:
                    extra.append(sentence)
            elif key not in ("data", "type", "role") and len(value) >= 12 \
                    and value not in primary and id(value) not in seen:
                seen.add(id(value))
                extra.append(value)
        elif depth < MAX_DEPTH:
            if isinstance(value, dict):
                stack.extend((v, k, depth + 1) for k, v in value.items())
            elif isinstance(value, list):
                stack.extend((v, key, depth + 1) for v in value)
    if extra:
        out.append("\n".join(extra))
    return out


def _blob_text(blob: str) -> str:
    """The text inside a base64 blob, if it decodes to text ("" for images and other binary)."""
    import base64
    import binascii
    try:
        raw = base64.b64decode(blob[:1_400_000], validate=False)
    except (binascii.Error, ValueError):
        return ""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    return text if text.isprintable() or "\n" in text or "\t" in text else ""


# ---------------------------------------------------------------- pinning

_SNAPSHOT_LIMIT = 3000
MAX_CHANGED = 500    # changed definitions kept for `pins diff`; a hostile server cannot fill the disk
MAX_DEFS = 5000      # readable copies of pinned definitions


def _entries(data, need: tuple[str, ...] = ()) -> dict[str, dict]:
    """A sidecar file's contents, keeping only well-formed entries (the file may be damaged or planted)."""
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items()
            if isinstance(k, str) and isinstance(v, dict) and all(isinstance(v.get(n), str) for n in need)}


def _snapshot(item: dict) -> dict:
    """A short readable copy of a definition (what a model reads), for `pins diff`."""
    snap = {k: item[k] for k in ("title", "description", "inputSchema", "annotations") if k in item}
    if len(json.dumps(snap, default=str)) > _SNAPSHOT_LIMIT:
        snap = {"description": str(item.get("description", ""))[:_SNAPSHOT_LIMIT], "truncated": True}
    return snap


def _readable(snap: dict) -> list[str]:
    lines: list[str] = []
    try:
        for k in ("title", "description"):
            if k in snap:
                lines += [f"{k}: {ln}" for ln in str(snap[k]).splitlines() or [""]]
        for k in ("inputSchema", "annotations"):
            if k in snap:
                lines += [f"{k}: {ln}"
                          for ln in json.dumps(snap[k], indent=1, sort_keys=True, default=str).splitlines()]
    except (RecursionError, ValueError, TypeError):  # a damaged or planted copy
        return ["(this copy of the definition is unreadable)"]
    return lines[:400]


class PinStore:
    """Trust-on-first-use pins of definitions; detects rug pulls.

    With ``hold_new`` a definition seen for the first time is *not* trusted: it is parked in a
    pending file with a short preview until ``mcpguard pins approve`` says you have read it."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.pending_path = self.path.with_name(self.path.name + ".pending")
        self.changed_path = self.path.with_name(self.path.name + ".changed")
        self.defs_path = self.path.with_name(self.path.name + ".defs")
        self.pins: dict[str, str] = load_json(self.path, {})
        self.pending: dict[str, dict] = load_json(self.pending_path, {})
        self.changed: dict[str, dict] = _entries(load_json(self.changed_path, {}), ("fp",))
        self._added: dict[str, str] = {}  # pinned by this process and not yet saved
        self._added_defs: dict[str, dict] = {}  # readable copies of what was pinned, for `pins diff`
        self._changed_now: dict[str, dict] = {}  # changes seen by this process and not yet saved
        self._reverted: set[str] = set()  # changed once, now back to what was trusted
        self._held: dict[str, dict] = {}  # parked by this process and not yet saved
        self.first_seen: list[str] = []  # keys pinned without review since the last take_first_seen()

    def reload(self) -> None:
        """Pick up `mcpguard pins forget/approve` and pins made by other gateway processes."""
        self.pins = {**load_json(self.path, {}), **self._added}
        self.pending = {**load_json(self.pending_path, {}), **self._held}
        for k in list(self.pending):
            if k in self.pins:
                del self.pending[k]
        self.changed = {**_entries(load_json(self.changed_path, {}), ("fp",)), **self._changed_now}
        for k in list(self.changed):  # approved, forgotten or reverted since: no longer a change
            if k not in self.pins or self.pins[k] == self.changed[k].get("fp"):
                del self.changed[k]

    def save(self):
        """Add this process's new pins to what is on disk. Writing the whole in-memory copy
        would undo a `pins forget` run while the gateway was up, and drop other processes' pins."""
        lock = self.path.with_name(self.path.name + ".lock")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with locked(lock):
            on_disk = load_json(self.path, {})
            merged = {**self._added, **on_disk}  # a pin already on disk wins: first seen is trusted
            if merged != on_disk:
                write_atomic(self.path, json.dumps(merged, indent=2, sort_keys=True))
            if self._held or self.pending_path.exists():
                waiting = {**load_json(self.pending_path, {}), **self._held}
                waiting = {k: v for k, v in waiting.items() if k not in merged}
                if waiting != load_json(self.pending_path, {}):
                    write_atomic(self.pending_path, json.dumps(waiting, indent=2, sort_keys=True))
                self.pending = waiting
            self._save_changes(merged)
        self.pins, self._added, self._held = merged, {}, {}

    def _save_changes(self, pins: dict[str, str]) -> None:
        """Keep the readable copies and the list of changed definitions (call with the lock held)."""
        if self._added_defs:
            defs = _entries(load_json(self.defs_path, {}))
            defs = {**self._added_defs, **defs}  # the first copy stays: it is what was trusted
            if len(defs) > MAX_DEFS:
                defs = dict(list(defs.items())[:MAX_DEFS])
            write_atomic(self.defs_path, json.dumps(defs, indent=2, sort_keys=True))
            self._added_defs = {}
        if self._changed_now or self._reverted or self.changed_path.exists():
            current = {**_entries(load_json(self.changed_path, {}), ("fp",)), **self._changed_now}
            current = {k: v for k, v in current.items()
                       if k in pins and pins[k] != v.get("fp") and k not in self._reverted}
            if len(current) > MAX_CHANGED:
                current = dict(list(current.items())[:MAX_CHANGED])
            self._reverted = set()
            if current != _entries(load_json(self.changed_path, {}), ("fp",)):
                write_atomic(self.changed_path, json.dumps(current, indent=2, sort_keys=True))
            self.changed, self._changed_now = current, {}

    def forget(self, key: str) -> bool:
        """Remove one pin from disk (and here). Returns False if it was not pinned."""
        lock = self.path.with_name(self.path.name + ".lock")
        with locked(lock):
            on_disk = load_json(self.path, {})
            found = on_disk.pop(key, None) is not None
            if found:
                write_atomic(self.path, json.dumps(on_disk, indent=2, sort_keys=True))
        self._added.pop(key, None)
        self.pins = {**on_disk, **self._added}
        if found:
            with locked(lock):
                for path in (self.changed_path, self.defs_path):
                    data = _entries(load_json(path, {}))
                    if data.pop(key, None) is not None:
                        write_atomic(path, json.dumps(data, indent=2, sort_keys=True))
            self.changed.pop(key, None)
        return found

    def approve(self, what: str) -> list[str]:
        """Trust pending definitions: one key ('files/read_file') or every pending one of a server
        ('files'). Returns the keys approved."""
        lock = self.path.with_name(self.path.name + ".lock")
        with locked(lock):
            on_disk = load_json(self.path, {})
            waiting = load_json(self.pending_path, {})
            keys = [k for k in waiting if k == what or k.startswith(what + "/")]
            for k in keys:
                on_disk[k] = waiting.pop(k)["fp"]
            changed = _entries(load_json(self.changed_path, {}), ("fp",))
            defs = _entries(load_json(self.defs_path, {}))
            moved = [k for k in changed if k == what or k.startswith(what + "/")]
            for k in moved:  # the reviewed new definition becomes the trusted one
                entry = changed.pop(k)
                on_disk[k] = entry["fp"]
                if isinstance(entry.get("new"), dict):
                    defs[k] = entry["new"]
            if keys or moved:
                write_atomic(self.path, json.dumps(on_disk, indent=2, sort_keys=True))
                write_atomic(self.pending_path, json.dumps(waiting, indent=2, sort_keys=True))
                write_atomic(self.changed_path, json.dumps(changed, indent=2, sort_keys=True))
                write_atomic(self.defs_path, json.dumps(defs, indent=2, sort_keys=True))
        self.pins, self.pending, self.changed = on_disk, waiting, changed
        return keys + moved

    def diff(self, what: str) -> list[tuple[str, list[str]]]:
        """For each changed definition matching ``what``: its key and the lines that differ."""
        import difflib
        defs = _entries(load_json(self.defs_path, {}))
        out = []
        for key in sorted(k for k in self.changed if k == what or k.startswith(what + "/")):
            entry = self.changed[key]
            fresh = entry.get("new")
            new = _readable(fresh) if isinstance(fresh, dict) else []
            saved = defs.get(key)
            old = _readable(saved) if isinstance(saved, dict) else []
            if not old:
                lines = ["(no readable copy of the old definition was saved: it was pinned by an older "
                         "version. The new definition is:)"] + [f"+ {x}" for x in new]
            else:
                lines = list(difflib.unified_diff(old, new, "pinned", "now", lineterm="", n=2))
                lines = lines or ["(only fields outside description and schema differ)"]
            out.append((key, lines))
        return out

    def take_first_seen(self) -> list[str]:
        keys, self.first_seen = self.first_seen, []
        return keys

    def check(self, server: str, item: dict, kind: str = "tool", hold_new: bool = False) -> Finding | None:
        key = f"{server}/{item['name']}" if kind == "tool" else f"{server}/{kind}:{item['name']}"
        fp = fingerprint_tool(item)
        old = self.pins.get(key)
        if old is None:
            if hold_new:
                preview = " ".join(str(item.get("description") or item.get("title") or "").split())[:240]
                entry = {"fp": fp, "preview": preview, "kind": kind}
                if self.pending.get(key, {}).get("fp") != fp:
                    self.pending[key] = self._held[key] = entry
                return Finding("pin.unreviewed", "critical",
                               "New definition waiting for your review: run 'mcpguard pins pending', then "
                               f"'mcpguard pins approve {server}'", key, subject=item["name"])
            self.pins[key] = fp
            self._added[key] = fp
            self._added_defs[key] = _snapshot(item)
            self.first_seen.append(key)
            return None
        if old != fp and old == fingerprint_tool(item, legacy=True) and fp != old:
            # Pinned by an older version that did not hash the extra fields, and nothing else changed:
            # re-pin quietly (this happens once per tool, on upgrade).
            self.pins[key] = fp
            self._added[key] = fp
            return None
        if old == fp and (key in self.changed or key in self._changed_now):
            self._changed_now.pop(key, None)
            self._reverted.add(key)
        if old != fp:
            self._reverted.discard(key)
            self._changed_now[key] = {"fp": fp, "old_fp": old, "new": _snapshot(item)}
            return Finding("rug_pull.changed", "critical", "Definition changed since it was first approved "
                           f"(see: mcpguard pins diff {server})", key, subject=item["name"])
        return None

    def removed(self, server: str, current: set[str]) -> list[Finding]:
        prefix = f"{server}/"
        gone = [k for k in self.pins if k.startswith(prefix) and ":" not in k and k[len(prefix):] not in current]
        return [Finding("rug_pull.removed", "low", "Previously pinned tool disappeared", k) for k in gone]


def _scrub(text: str) -> str:
    from . import dlp
    if not any(ch.isdigit() for ch in text):
        return text
    return dlp.redact(text, dict.fromkeys(("credit_card", "aadhaar", "us_ssn", "iban", "india_pan"), "redact"))[0]


@functools.lru_cache(maxsize=4)
def _load_model(path: str = ""):
    from .model import BUNDLED_MODEL, Model
    return Model.load(path or BUNDLED_MODEL)


@functools.lru_cache(maxsize=4096)
def _base64_forms(value: str) -> tuple[str, ...]:
    """Base64 (standard and URL-safe) of a value at each of the three byte alignments it can have
    inside a longer encoded blob, without the edge characters that depend on its neighbours."""
    import base64
    forms = []
    for pad in range(3):
        raw = b"\0" * pad + value.encode()
        for enc in (base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode()):
            core = enc.rstrip("=")[(pad * 4 + 2) // 3:][: -2 or None]
            if len(core) >= 8:
                forms.append(core)
    return tuple(dict.fromkeys(forms))


@functools.lru_cache(maxsize=4096)
def _encoded_forms(value: str) -> tuple[str, ...]:
    """Other spellings of a value that carry the same bytes: base32, ROT13, base64 of base64."""
    import base64
    import codecs
    raw = value.encode()
    forms = [codecs.encode(value, "rot13"), base64.b64encode(base64.b64encode(raw)).decode().rstrip("=")[:-3]]
    for pad in range(5):  # base32 works in 5-byte groups, so five alignments inside a longer blob
        enc = base64.b32encode(b"\0" * pad + raw).decode().rstrip("=")
        core = enc[(pad * 8 + 4) // 5:][:-2]
        if len(core) >= 12:
            forms.append(core)
    return tuple(dict.fromkeys(f for f in forms if len(f) >= 12 and f != value))


_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_U_ESCAPE = re.compile(r"(?:\\\\?u[0-9a-fA-F]{4}){4,}")
_HEX_SEPARATED = re.compile(r"(?:[0-9a-fA-F]{2}[:\- ,]){7,}[0-9a-fA-F]{2}")
_CODE_RUN = re.compile(r"(?:\b(?:[01]{8}|\d{2,3})\b[ ,;]+){7,}\b(?:[01]{8}|\d{2,3})\b")


_ENTITY = re.compile(r"&#(?:[xX][0-9a-fA-F]{1,6}|\d{1,7});")
_OCTAL_RUN = re.compile(r"(?:\b[0-7]{2,3}\b[ ,;]+){7,}\b[0-7]{2,3}\b")
_B64_BLOB = re.compile(r"[A-Za-z0-9+/_-]{20,}={0,2}")
_HEX_BLOB = re.compile(r"\b(?:[0-9a-fA-F]{2}){10,}\b")


def _inflate(data: bytes) -> str | None:
    """The text inside a gzip or zlib stream (at most 1 MB of it), or None when this is not one."""
    import zlib
    if data[:2] == b"\x1f\x8b":
        wbits = 31
    elif data[:1] == b"x" and data[1:2] in (b"\x01", b"\x5e", b"\x9c", b"\xda"):
        wbits = 15
    else:
        return None
    try:
        out = zlib.decompressobj(wbits).decompress(data, 1 << 20)
    except zlib.error:
        return None
    return out.decode("utf-8", "replace")


def decoded_views(blob: str) -> list[str]:
    """The outgoing text as its receiver could trivially decode it: percent-decoded (twice),
    ``\\uXXXX`` escapes resolved, full-width folded, separators removed from hex dumps, and runs
    of decimal or binary character codes turned back into characters. Only views that differ
    from ``blob`` are returned."""
    views: list[str] = []

    def add(text: str) -> None:
        if text != blob and text not in views:
            views.append(text)

    if _PERCENT.search(blob):
        once = unquote(blob)
        add(once)
        if _PERCENT.search(once):
            add(unquote(once))
    if _U_ESCAPE.search(blob):
        add(_U_ESCAPE.sub(lambda m: "".join(chr(int(h, 16)) for h in re.findall(r"u([0-9a-fA-F]{4})", m.group(0))),
                          blob))
    if not blob.isascii():
        add(unicodedata.normalize("NFKC", blob))
    if _HEX_SEPARATED.search(blob):
        add(_HEX_SEPARATED.sub(lambda m: re.sub(r"[:\- ,]", "", m.group(0)), blob))
    if _CODE_RUN.search(blob):
        def chars(m: re.Match[str]) -> str:
            out = []
            for tok in re.findall(r"[01]{8}|\d{2,3}", m.group(0)):
                n = int(tok, 2) if len(tok) == 8 else int(tok)
                out.append(chr(n) if 32 <= n < 127 else " ")
            return "".join(out)
        add(_CODE_RUN.sub(chars, blob))
    if _ENTITY.search(blob):
        import html
        add(html.unescape(blob))
    if _OCTAL_RUN.search(blob):
        add(_OCTAL_RUN.sub(lambda m: "".join(chr(int(t, 8)) if 32 <= int(t, 8) < 127 else " "
                                             for t in re.findall(r"[0-7]{2,3}", m.group(0))), blob))
    if len(blob) < 400_000:  # base64 or hex that wraps a compressed stream
        import base64
        import binascii
        for m in [*_B64_BLOB.finditer(blob), *_HEX_BLOB.finditer(blob)][:20]:
            tok = m.group(0)
            try:
                data = bytes.fromhex(tok) if _HEX_BLOB.fullmatch(tok) else base64.b64decode(
                    tok.replace("-", "+").replace("_", "/") + "=" * (-len(tok) % 4))
            except (ValueError, binascii.Error):
                continue
            text = _inflate(data)
            if text:
                add(blob.replace(tok, text))
    return views


# Letters that look like Latin ones (Cyrillic, Greek), as the model reads them.
_SPACED = re.compile(r"(?<![\w])(?:[A-Za-z][ .\-_]){3,}[A-Za-z](?![\w])")
_LATIN_NAME = re.compile(r"^LATIN (?:SMALL |CAPITAL )?LETTER (?:SMALL CAPITAL |SMALL |CAPITAL )?([A-Z])(?: WITH .*)?$")
# Leetspeak inside a word that also has letters: 1gn0re, a11, pr3v10us. "11" reads as "ll"; a lone
# 1 is read as i in one variant and l in the other.
_LEET_WORD = re.compile(r"\b(?=[A-Za-z0-9@$]*[A-Za-z])(?=[A-Za-z0-9@$]*[0-9@$])[A-Za-z0-9@$]{3,}\b")
_LEET = (str.maketrans("0134578@$", "oieastbas"), str.maketrans("0134578@$", "oleastbas"))


@functools.lru_cache(maxsize=1)
def _latin_confusables() -> dict[str, str]:
    """Unicode's confusables (UTS #39) that look like a Latin letter and that NFKC leaves alone.
    Generated from the confusable_homoglyphs package data (MIT)."""
    return load_json(Path(__file__).with_name("data") / "confusables.json", {})


class _Fold(dict):
    """A str.translate table that works each character out once: invisible format characters
    dropped, Unicode tag characters (hidden ASCII) decoded, accents stripped, compatibility
    forms folded, and anything that looks like a Latin letter mapped to it."""

    def __missing__(self, cp: int) -> str:
        ch = chr(cp)
        out = ch
        if cp < 128:
            pass
        elif 0xE0020 <= cp <= 0xE007E:
            out = chr(cp - 0xE0000)
        elif unicodedata.category(ch) in ("Cf", "Mn", "Me"):
            out = ""
        else:
            base = "".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c))
            base = unicodedata.normalize("NFKC", base)
            if base and base.isascii():
                out = base
            elif ch in _latin_confusables():
                out = _latin_confusables()[ch]
            else:
                m = _LATIN_NAME.match(unicodedata.name(ch, ""))
                if m:
                    out = m.group(1).lower() if "SMALL" in unicodedata.name(ch) else m.group(1)
        if len(self) < 20_000:
            self[cp] = out
        return out


_FOLD = _Fold()


def deobfuscate(text: str) -> str:
    """The text as the model would read it: invisible characters dropped, hidden tag text
    decoded, accents stripped, full-width, small-capital and other look-alike letters mapped to
    Latin, and s p a c e d - o u t words joined. Cheap when there is nothing to undo."""
    if text.isascii() and not _SPACED.search(text):
        return text
    plain = text if text.isascii() else text.translate(_FOLD)
    return _SPACED.sub(lambda m: re.sub(r"[ .\-_]", "", m.group(0)), plain)


def deobfuscated_variants(text: str) -> list[str]:
    """Readings of ``text`` that differ from it: de-obfuscated, then leetspeak read two ways."""
    plain = deobfuscate(text)
    out = [plain] if plain != text else []
    if _LEET_WORD.search(plain):
        for table in _LEET:
            def read(m: re.Match[str], t: dict[int, int] = table) -> str:
                return m.group(0).replace("11", "ll").translate(t)
            v = _LEET_WORD.sub(read, plain)
            if v != plain and v not in out:
                out.append(v)
    return out


# ---------------------------------------------------------------- taint

@dataclass
class SessionTaint:
    """Remembers sensitive values seen in results so they can be spotted leaving.

    Bounded: the oldest values are forgotten once ``max_values`` is reached.
    """

    min_len: int = 12
    entropy_threshold: float = 4.3
    max_values: int = 2000
    values: OrderedDict[str, str] = field(default_factory=OrderedDict)
    # Fragment tracking: every 8-character piece of each tracked value (letters and digits only),
    # and which positions of each value have already left in some earlier call.
    secrets: set[str] = field(default_factory=set)  # tracked values that matched a credential format
    _grams: dict[str, set[str]] = field(default_factory=dict)
    _covered: dict[str, set[int]] = field(default_factory=dict)

    GRAM = 8
    SHARE = 0.5  # flag once this much of a value has left in pieces
    FRAGMENT_SCAN = 262_144

    def _add(self, value: str, source: str) -> None:
        if value not in self.values:
            for g in self._value_grams(value):
                self._grams.setdefault(g, set()).add(value)
        self.values[value] = source
        self.values.move_to_end(value)
        while len(self.values) > self.max_values:
            old, _ = self.values.popitem(last=False)
            for g in self._value_grams(old):
                owners = self._grams.get(g)
                if owners:
                    owners.discard(old)
                    if not owners:
                        del self._grams[g]
            self._covered.pop(old, None)

    @staticmethod
    def _compact(text: str) -> str:
        return re.sub(r"[^A-Za-z0-9]", "", text).upper()

    def _value_grams(self, value: str) -> set[str]:
        c = self._compact(value)
        return {c[i:i + self.GRAM] for i in range(len(c) - self.GRAM + 1)} if len(c) >= self.min_len else set()

    def record_result(self, source: str, text: str):
        for _, p, _ in _SECRETS:
            for m in p.finditer(text):
                if len(m.group(0)) >= self.min_len:
                    self._add(m.group(0), source)
                    self.secrets.add(m.group(0))
                    if len(self.secrets) > 4 * self.max_values:
                        self.secrets &= set(self.values)
        for tok in _TOKEN.findall(text):
            if looks_random(tok, self.entropy_threshold):
                self._add(tok, source)

    def leaks_in(self, args: dict, secrets_only: bool = False) -> list[tuple[str, str]]:
        """Tracked values leaving in these arguments: whole (as-is, reversed, base64, base32, hex,
        ROT13, percent- or escape-encoded, as character codes), or in pieces - reversed, broken up
        with separators, or spread over several calls - once ``SHARE`` of a value has left.
        ``secrets_only`` limits the check to values that matched a credential format."""
        blob = json.dumps(args, ensure_ascii=False)
        texts = [blob, *decoded_views(blob)]
        lowered = [t.lower() for t in texts]
        out = []
        for v, origin in self.values.items():
            if secrets_only and v not in self.secrets:
                continue
            spellings = (v, v[::-1], *_base64_forms(v), *_encoded_forms(v))
            if any(sp in t for t in texts for sp in spellings) or any(v.encode().hex() in t for t in lowered):
                out.append((v, origin))
        if not secrets_only:
            whole = {v for v, _ in out}
            out.extend((v, self.values[v]) for v in self._fragments(args) if v not in whole and v in self.values)
        return out

    def _fragments(self, args: dict) -> list[str]:
        """Values whose pieces, counted over every call so far, now pass ``SHARE``."""
        if not self._grams:
            return []
        # Pieces are looked for in the first FRAGMENT_SCAN characters; whole values everywhere.
        compact = self._compact("".join(t for _, t in _walk_strings(args)))[:self.FRAGMENT_SCAN]
        hits: dict[str, set[int]] = {}
        n = self.GRAM
        for text in (compact, compact[::-1]):
            for i in range(len(text) - n + 1):
                for v in self._grams.get(text[i:i + n], ()):
                    cv = self._compact(v)
                    start = cv.find(text[i:i + n])
                    while start != -1:
                        hits.setdefault(v, set()).update(range(start, start + n))
                        start = cv.find(text[i:i + n], start + 1)
        flagged = []
        for v, pos in hits.items():
            need = self.SHARE * len(self._compact(v))
            before = self._covered.setdefault(v, set())
            after = before | pos
            self._covered[v] = after
            # This call alone carries enough (however often the value was seen before), or its pieces
            # added to earlier calls' now pass the share.
            if len(pos) >= need or (after != before and len(after) >= need):
                flagged.append(v)
        return flagged


def is_egress_tool(tool: dict, extra_names: set[str] | None = None) -> bool:
    if extra_names and tool.get("name") in extra_names:
        return True
    ann = tool.get("annotations") or {}
    if ann.get("openWorldHint") is True:
        return True
    return bool(EGRESS_HINTS.search(tool.get("name", "")))






# Attack-specific checks live in their own module; imported last because they use Finding.
from . import checks as _checks  # noqa: E402
