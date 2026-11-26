"""Indicators of compromise (IOCs) derived from known-malicious MCP tools.

A feed is built from a labelled corpus (JSONL records with ``kind`` = definition |
result, ``label`` = malicious | benign, ``text``, ``name``, and optionally ``params``
and ``added_params``: parameters an attack added to an existing tool) and contains:

  fingerprints  SHA-256 of normalised known-malicious texts            -> ioc.known_text (critical)
  shingles      hashed 5-word fragments seen only in malicious texts   -> ioc.similar_text (medium / high,
                high with 2+ fragments seen across unrelated tools, or 6+ in all)
  phrases       short word sequences seen only in malicious texts,
                across several different tools                         -> ioc.phrase (medium / high)
  domains       hosts referenced by malicious texts, never by benign   -> ioc.domain (high)
  tool_names    names used only by malicious tools                     -> ioc.tool_name (medium)
  param_names   parameters used only by malicious tools                -> ioc.param_name (high)

Indicators come only from each malicious text's payload: the part left after removing
wording that also appears in benign tools, or that every variant of the same tool shares
(a poisoned description is usually a genuine one with an instruction added). Without
this, the genuine, unpoisoned tool would match its own poisoned copies.

Raw attack texts are never stored: fingerprints and
shingles are one-way hashes, and phrases are at most six words.

``evaluate`` measures a feed honestly: it builds from one part of the corpus and tests
on the rest, reporting detection on unseen malicious items and false positives on
unseen benign ones.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .detect import Finding

FEED_VERSION = 1
SHINGLE = 5
PHRASE_MIN, PHRASE_MAX = 3, 6
_WORD = re.compile(r"[a-z0-9]+")
_URL = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>`)\]}]+", re.IGNORECASE)
# The lookbehind starts a match only at the beginning of a name, which keeps this linear.
_BARE_DOMAIN = re.compile(r"(?<![a-z0-9.-])(?:[a-z0-9-]++\.)+"
                          r"(?:com|net|org|io|xyz|ru|cn|top|site|info|biz|co|me|app|dev)\b", re.IGNORECASE)
_STOP = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "have", "in", "is", "it", "its", "of",
    "on", "or", "that", "the", "this", "to", "was", "were", "will", "with", "you", "your", "we", "our", "they",
    "their", "can", "may", "must", "should", "all", "any",
}
# Hosts that show up in attack examples but also everywhere in normal use.
_NEVER_DOMAINS = {"localhost", "example.com", "github.com", "google.com", "www.google.com", "python.org"}


def normalise(text: str) -> list[str]:
    return _WORD.findall(text.lower())


def _h(s: str, size: int = 8) -> str:
    return hashlib.blake2b(s.encode(), digest_size=size).hexdigest()


def fingerprint(text: str) -> str:
    return hashlib.sha256(" ".join(normalise(text)).encode()).hexdigest()


def shingles(tokens: list[str], n: int = SHINGLE) -> set[str]:
    return {_h(" ".join(tokens[i:i + n]), 6) for i in range(len(tokens) - n + 1)}


def ngrams(tokens: list[str], lo: int = PHRASE_MIN, hi: int = PHRASE_MAX) -> set[str]:
    return {" ".join(tokens[i:i + n]) for n in range(lo, hi + 1) for i in range(len(tokens) - n + 1)}


def hosts_in(text: str) -> set[str]:
    out = set()
    for m in _URL.finditer(text):
        try:
            host = (urlsplit(m.group(0)).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if host:
            out.add(host)
    out.update(d.lower() for d in _BARE_DOMAIN.findall(text))
    return out


# ---------------------------------------------------------------- feed


@dataclass
class IocFeed:
    fingerprints: set[str] = field(default_factory=set)
    shingles: set[str] = field(default_factory=set)
    phrases: dict[str, int] = field(default_factory=dict)  # phrase -> number of distinct malicious tools using it
    domains: set[str] = field(default_factory=set)
    tool_names: set[str] = field(default_factory=set)
    param_names: set[str] = field(default_factory=set)
    sources: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    # Shingles seen in poisoned copies of at least two unrelated tools. The rest may be one
    # genuine tool's own wording copied into its poisoned version, so alone they only warn.
    cross_tool: set[str] = field(default_factory=set)

    # -- persistence

    def to_json(self) -> dict:
        return {"version": FEED_VERSION, "sources": self.sources, "stats": self.stats,
                "fingerprints": sorted(self.fingerprints), "shingles": sorted(self.shingles),
                "phrases": dict(sorted(self.phrases.items())), "domains": sorted(self.domains),
                "tool_names": sorted(self.tool_names), "param_names": sorted(self.param_names),
                "cross_tool_shingles": sorted(self.cross_tool)}

    @classmethod
    def from_json(cls, d: dict) -> IocFeed:
        if d.get("version") != FEED_VERSION:
            raise ValueError(f"unsupported IOC feed version {d.get('version')}")
        shingle_set = set(d.get("shingles", []))
        cross = set(d["cross_tool_shingles"]) if "cross_tool_shingles" in d else set(shingle_set)  # older feeds
        return cls(set(d.get("fingerprints", [])), shingle_set, dict(d.get("phrases", {})),
                   set(d.get("domains", [])), set(d.get("tool_names", [])), set(d.get("param_names", [])),
                   list(d.get("sources", [])), dict(d.get("stats", {})), cross)

    @classmethod
    def load(cls, path: str | Path) -> IocFeed:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except RecursionError:
            raise ValueError("the IOC feed is nested too deeply to read") from None
        if not isinstance(data, dict):
            raise ValueError("the IOC feed must be a JSON object")
        return cls.from_json(data)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_json(), indent=1), encoding="utf-8")

    def merge(self, other: IocFeed) -> IocFeed:
        phrases = dict(self.phrases)
        for p, n in other.phrases.items():
            phrases[p] = max(n, phrases.get(p, 0))
        return IocFeed(self.fingerprints | other.fingerprints, self.shingles | other.shingles, phrases,
                       self.domains | other.domains, self.tool_names | other.tool_names,
                       self.param_names | other.param_names, sorted(set(self.sources) | set(other.sources)), {},
                       self.cross_tool | other.cross_tool)

    def __len__(self) -> int:
        return (len(self.fingerprints) + len(self.shingles) + len(self.phrases) + len(self.domains)
                + len(self.tool_names) + len(self.param_names))

    # -- matching

    def match_text(self, text: str, where: str, shingle_hits: int = 4) -> list[Finding]:
        tokens = normalise(text)
        if not tokens:
            return []
        out: list[Finding] = []
        if fingerprint(text) in self.fingerprints:
            out.append(Finding("ioc.known_text", "critical", "Matches a known malicious MCP tool text", where))
            return out
        found_shingles = shingles(normalise(strip_param_docs(text))) & self.shingles
        hits = len(found_shingles)
        if hits >= shingle_hits:
            # High needs evidence beyond one tool's own wording: two sequences seen across
            # unrelated tools, or a long overlap. Otherwise it is a warning.
            confident = len(found_shingles & self.cross_tool) >= 2 or hits >= shingle_hits + 2
            out.append(Finding("ioc.similar_text", "high" if confident else "medium",
                               f"Shares {hits} word sequences with known malicious MCP tools"
                               + ("" if confident else " (wording of a single tool, so only a warning)"), where))
        joined = f" {' '.join(normalise(strip_param_docs(text)))} "
        found = [p for p in self.phrases if f" {p} " in joined]
        if found:
            well_supported = [p for p in found if self.phrases[p] >= 3]
            strong = len(well_supported) >= 2 or (well_supported and len(found) >= 3)
            out.append(Finding("ioc.phrase", "high" if strong else "medium",
                               f"Wording seen in known attacks: '{found[0]}'"
                               + (f" (+{len(found) - 1} more)" if len(found) > 1 else ""), where))
        out += self.match_domains(text, where)
        return out

    def match_name(self, name: str, where: str) -> list[Finding]:
        if name in self.tool_names:
            return [Finding("ioc.tool_name", "medium", f"Tool name '{name}' is used by known malicious tools",
                            where)]
        return []

    def match_domains(self, text: str, where: str) -> list[Finding]:
        bad_hosts = hosts_in(text) & self.domains
        if bad_hosts:
            return [Finding("ioc.domain", "high", f"Known attack host: {sorted(bad_hosts)[0]}", where)]
        return []

    def match_params(self, params: Iterable[str], where: str) -> list[Finding]:
        bad = sorted(set(params) & self.param_names)
        if bad:
            return [Finding("ioc.param_name", "high",
                            f"Parameter '{bad[0]}' is used by known malicious tools to extract information", where)]
        return []


BUNDLED_FEED = Path(__file__).parent / "data" / "iocs.json"
_cache: dict[tuple, IocFeed] = {}


def load_feeds(extra: Iterable[str] = (), bundled: bool = True) -> IocFeed:
    """The bundled feed merged with any extra feed files. Cached by file name and mtime."""
    paths = ([BUNDLED_FEED] if bundled else []) + [Path(p) for p in extra]
    missing = [p for p in paths if not p.exists()]
    if missing:
        raise FileNotFoundError(f"IOC feed not found: {missing[0]}")  # never skip a feed silently
    key = tuple((str(p), p.stat().st_mtime) for p in paths)
    if key not in _cache:
        feed = IocFeed()
        for p in paths:
            feed = feed.merge(IocFeed.load(p))
        _cache.clear()
        _cache[key] = feed
    return _cache[key]


# ---------------------------------------------------------------- building


def read_corpus(path: str | Path) -> list[dict]:
    out = []
    for i, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("label") not in ("malicious", "benign") or not isinstance(rec.get("text"), str):
            raise ValueError(f"{path}:{i}: each record needs label (malicious|benign) and text")
        out.append(rec)
    return out


def _grams(tokens: list[str], n: int) -> set[str]:
    return {" ".join(tokens[i:i + n]) for i in range(len(tokens) - n + 1)}


def _common_prefix(token_lists: list[list[str]]) -> list[str]:
    if len(token_lists) < 2:
        return []
    out = []
    for column in zip(*token_lists, strict=False):
        if len(set(column)) != 1:
            break
        out.append(column[0])
    return out


_PARAM_LINE = re.compile(r"^\s*[A-Za-z_][\w.]*\s*(?:\([^)]*\))?\s*:\s+\S")  # "query (str): The search query"
_SECTION = re.compile(r"^\s*(?:args|arguments|parameters|params|returns?|raises|example[s]?)\s*:\s*$", re.I)


def strip_param_docs(text: str) -> str:
    """Drop docstring parameter lines and section headers: boilerplate, not instructions."""
    return "\n".join(line for line in text.splitlines() if not (_PARAM_LINE.match(line) or _SECTION.match(line)))


_STRONG_CUES = {"must", "ignore", "important", "mandatory", "required", "requires", "never", "always", "instead",
                "immediately", "critical", "override", "secretly", "silently", "regardless", "mandate", "strictly"}
_CUES = _STRONG_CUES | {"should", "before", "after", "first", "also", "do", "not", "don", "call", "send", "use",
                        "only", "prioritize", "best", "include", "add", "modify", "replace", "forward", "upload",
                        "read", "write", "execute", "run", "need", "please", "ensure", "every", "any"}


def looks_like_instruction(tokens: list[str]) -> bool:
    """Payload text that tells the model to do something, rather than describing the tool."""
    strong = sum(t in _STRONG_CUES for t in tokens)
    cues = sum(t in _CUES for t in tokens)
    return (strong >= 1 and cues >= 3) or strong >= 2


def isolate_payload(tokens: list[str], benign_grams: set[str], known_prefix: list[str], n: int = SHINGLE,
                    min_run: int = 4) -> list[list[str]]:
    """Runs of tokens not explained by benign wording.

    A poisoned description is usually a genuine description with an instruction added.
    Tokens covered by any benign n-gram, or by the prefix every variant of the same tool
    shares, are treated as the genuine part; what remains is the payload.
    """
    covered = [False] * len(tokens)
    for i in range(min(len(known_prefix), len(tokens))):
        covered[i] = tokens[i] == known_prefix[i]
    for i in range(len(tokens) - n + 1):
        if " ".join(tokens[i:i + n]) in benign_grams:
            for j in range(i, i + n):
                covered[j] = True
    runs: list[list[str]] = []
    current: list[str] = []
    for tok, cov in zip(tokens, covered, strict=True):
        if cov:
            if len(current) >= min_run:
                runs.append(current)
            current = []
        else:
            current.append(tok)
    if len(current) >= min_run:
        runs.append(current)
    return runs


def build(records: Iterable[dict], min_phrase_tools: int = 2, max_phrases: int = 400,
          min_shingle_tools: int = 1) -> IocFeed:
    """Build a feed. Only payload text (the part not explained by benign wording) yields indicators."""
    records = list(records)
    bad = [r for r in records if r["label"] == "malicious"]
    good = [r for r in records if r["label"] == "benign"]

    good_grams5: set[str] = set()
    good_ngrams: set[str] = set()
    good_hosts: set[str] = set()
    good_names = {r.get("name") for r in good}
    good_params = {p for r in good for p in r.get("params", [])}
    for r in good:
        toks = normalise(r["text"])
        good_grams5 |= _grams(toks, SHINGLE)
        good_ngrams |= ngrams(toks)
        good_hosts |= hosts_in(r["text"])

    variants: dict[tuple, list[list[str]]] = defaultdict(list)
    for r in bad:
        variants[(r.get("source"), r.get("name"), r.get("kind"))].append(normalise(strip_param_docs(r["text"])))
    prefixes = {k: _common_prefix(v) for k, v in variants.items()}

    feed = IocFeed(sources=sorted({r.get("source", "?") for r in records}))
    phrase_tools: dict[str, set] = defaultdict(set)
    shingle_tools: dict[str, set] = defaultdict(set)
    param_tools: dict[str, set] = defaultdict(set)
    no_payload = 0
    for r in bad:
        toks = normalise(strip_param_docs(r["text"]))
        runs = [run for run in isolate_payload(toks, good_grams5,
                                               prefixes[(r.get("source"), r.get("name"), r.get("kind"))])
                if looks_like_instruction(run)]
        if not runs:
            no_payload += 1  # identical to genuine wording: not detectable from text
        else:
            feed.fingerprints.add(fingerprint(r["text"]))
            for run in runs:
                for sh in shingles(run):
                    shingle_tools[sh].add(_family(r))
                for g in ngrams(run):
                    phrase_tools[g].add((r.get("source"), r.get("name")))
        feed.domains |= hosts_in(r["text"]) - good_hosts - _NEVER_DOMAINS
        name = r.get("name")
        if r.get("kind") == "definition" and name and name not in good_names and len(name) > 3:
            feed.tool_names.add(name)
        # Only parameters an attack added to an existing tool are evidence; a malicious tool's
        # ordinary parameters (query, name, location) are not.
        for p in r.get("added_params", []):
            if p not in good_params:
                param_tools[p].add((r.get("source"), name))

    def informative(p: str) -> bool:
        # Two real words of three letters or more, so "of the user s" (from "of the user's") does not count.
        return sum(w not in _STOP and len(w) >= 3 for w in p.split()) >= 2 and len(p) >= 12

    # An injected parameter is added to many unrelated tools; a tool's own parameters are not.
    feed.param_names = {p for p, tools in param_tools.items() if len(tools) >= 2}
    support = {p: len(t) for p, t in phrase_tools.items()}
    candidates = sorted((p for p, n in support.items()
                         if n >= min_phrase_tools and p not in good_ngrams and informative(p)),
                        key=lambda p: (-support[p], len(p)))
    chosen: list[str] = []
    for p in candidates:
        if any(c in p for c in chosen):  # a shorter selected phrase already covers this one
            continue
        chosen.append(p)
        if len(chosen) >= max_phrases:
            break
    feed.phrases = {p: support[p] for p in chosen}
    # A word sequence seen in poisoned copies of a single tool may just be that tool's own
    # wording ("the name of the repository"); attack text recurs across unrelated tools.
    feed.shingles = {sh for sh, fams in shingle_tools.items() if len(fams) >= min_shingle_tools}
    feed.cross_tool = {sh for sh, fams in shingle_tools.items() if len(fams) >= 2}
    feed.stats = {"malicious": len(bad), "benign": len(good), "malicious_without_payload": no_payload}
    return feed


# ---------------------------------------------------------------- evaluation


@dataclass
class EvalResult:
    detected: int = 0
    malicious: int = 0
    false_positives: int = 0
    benign: int = 0
    by_category: dict = field(default_factory=lambda: defaultdict(lambda: [0, 0]))
    misses: list = field(default_factory=list)

    @property
    def recall(self) -> float:
        return self.detected / self.malicious if self.malicious else 0.0

    @property
    def fp_rate(self) -> float:
        return self.false_positives / self.benign if self.benign else 0.0


def _family(r: dict) -> str:
    """Records about the same tool (its genuine and poisoned versions) form one family."""
    return re.sub(r"[^a-z0-9]", "", str(r.get("name", "")).lower())[:12] or str(r.get("id"))


def _split(records: list[dict], test_share: float, seed: int) -> tuple[list[dict], list[dict]]:
    """Split by tool family, so test tools were never seen during building (realistic for new attacks)."""
    # Seeded RNG for a reproducible data split; not used for anything security-related.
    rng = random.Random(seed)  # noqa: S311  # nosec B311
    families = sorted({_family(r) for r in records})
    rng.shuffle(families)
    test_families = set(families[: round(len(families) * test_share)])
    train = [r for r in records if _family(r) not in test_families]
    test = [r for r in records if _family(r) in test_families]
    return train, test


def make_scorer(level: str = "high", with_detectors: bool = True):
    """Score a record with the feed (and, optionally, mcpguard's other detectors) at a severity level."""
    from .config import DetectorConfig
    from .detect import SEVERITIES, Engine
    engine = Engine(DetectorConfig(iocs=False, model=False)) if with_detectors else None
    threshold = SEVERITIES[level]

    def score(feed: IocFeed, r: dict) -> bool:
        findings = feed.match_text(r["text"], "x")
        if r.get("kind") == "definition":
            findings += feed.match_name(r.get("name", ""), "x") + feed.match_params(r.get("params", []), "x")
        if engine is not None:
            if r.get("kind") == "definition":
                props = {p: {"type": "string"} for p in r.get("params", [])}
                findings += engine.scan_definition({"name": r.get("name", "t"), "description": r["text"],
                                                    "inputSchema": {"type": "object", "properties": props}}, "s")
            else:
                findings += engine.scan_texts(r.get("name", "t"), [r["text"]])
        return any(SEVERITIES[f.severity] >= threshold for f in findings)
    return score


def evaluate(records: list[dict], scorer, test_share: float = 0.5, seed: int = 7,
             holdout_source: str | None = None) -> EvalResult:
    """Build on the training part, score the test part with ``scorer(feed, record) -> bool``.

    With ``holdout_source`` the whole source is held out instead (cross-dataset test).
    """
    if holdout_source:
        def benign_half(r: dict) -> bool:  # stable across runs, unlike hash()
            return hashlib.sha256(f"{seed}:{r['text']}".encode()).digest()[0] % 2 == 1
        in_test = [r.get("source") == holdout_source or (r["label"] == "benign" and benign_half(r))
                   for r in records]
        test = [r for r, t in zip(records, in_test, strict=True) if t]
        train = [r for r, t in zip(records, in_test, strict=True) if not t]
    else:
        train, test = _split(records, test_share, seed)
    feed = build(train)
    res = EvalResult()
    for r in test:
        hit = scorer(feed, r)
        if r["label"] == "malicious":
            res.malicious += 1
            res.detected += hit
            cat = res.by_category[r.get("category", "?")]
            cat[0] += hit
            cat[1] += 1
            if not hit:
                res.misses.append(r)
        else:
            res.benign += 1
            res.false_positives += hit
    return res
