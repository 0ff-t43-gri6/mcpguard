"""Build a labelled corpus (JSONL) of MCP tool definitions and tool responses.

    python scripts/ioc/build_corpus.py DATASET_DIR -o corpus.jsonl

DATASET_DIR holds clones of:
  MCPSafety (MCP-SafetyBench), MSB, MCPSecBench, mcp-injection-experiments,
  damn-vulnerable-MCP-server, servers, servers-archived, github-mcp-server

Each line: {"id", "source", "kind": "definition"|"result", "label": "malicious"|"benign",
            "category", "name", "text", "params"}
Labels come from each benchmark's own ground truth, plus a short hand-labelled list for
the small repositories (see HAND_LABELS). The corpus itself is not shipped: some sources
carry no license, so only derived indicators go into mcpguard's feed.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pyextract import tools_in

HAND_LABELS = {  # (file name, tool name) -> category, for repositories without ground-truth files
    ("direct-poisoning.py", "add"): "tool_poisoning",
    ("shadowing.py", "add"): "tool_shadowing",
    ("maliciousadd.py", "add"): "preference_manipulation",
    ("maliciousadd.py", "modify"): "tool_redirection",
    ("maliciousadd.py", "m_check"): "preference_manipulation",
    ("maliciousadd.py", "aft_check"): "tool_redirection",
    ("server.py@challenge2", "enhanced_search"): "tool_poisoning",
}
BENIGN_FILES = {"addserver.py", "download.py", "sse.py"}  # MCPSecBench baselines


def rec(out, source, kind, label, category, name, text, params=None, added_params=None):
    if not isinstance(text, str):
        text = json.dumps(text, ensure_ascii=False)  # structured responses are scanned as JSON text
    text = text.strip()
    if len(text) < 8:
        return
    out.append({"source": source, "kind": kind, "label": label, "category": category,
                "name": name, "text": text, "params": params or [], "added_params": added_params or []})


def safetybench(root: Path, out: list) -> None:
    for f in sorted((root / "MCPSafety/mcpuniverse/benchmark/configs/test").glob("*/*.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        cat = d.get("attack_category", "unknown")
        for key in ("mcp_server_modifications", "mcp_server_additions", "mcp_server_update"):
            items = d.get(key)
            for it in items if isinstance(items, list) else [items] if items else []:
                if not isinstance(it, dict):
                    continue
                name = it.get("tool_name", "?")
                if it.get("modification_description"):
                    rec(out, "mcp-safetybench", "definition", "malicious", cat, name, it["modification_description"])
                if it.get("description"):
                    params = list(it.get("input_parameters", {}) or {}) if isinstance(it.get("input_parameters"),
                                                                                      dict) else []
                    rec(out, "mcp-safetybench", "definition", "malicious", cat, name, it["description"], params)
                if it.get("modification_return"):
                    rec(out, "mcp-safetybench", "result", "malicious", cat, name, it["modification_return"])
    for f in sorted((root / "MCPSafety/mcpuniverse/mcp/servers").rglob("*.py")):
        for t in tools_in(f):
            rec(out, "mcp-universe-servers", "definition", "benign", "benign", t["name"], t["description"],
                t["params"])


def msb(root: Path, out: list, rng: random.Random) -> None:
    base = root / "MSB"
    tmpl = (base / "data/prompt_template.py").read_text(encoding="utf-8")

    def const(name):
        m = re.search(name + r"\s*=\s*(\"\"\"|''')(.*?)\1", tmpl, re.S) or re.search(name + r"\s*=\s*(['\"])(.*?)\1",
                                                                                     tmpl, re.S)
        return m.group(2)
    injection, false_error, simulated = (const("PROMPT_INJECTION_TEMPLATE"), const("TOOL_RESPONSE_ATTACK_TEMPLATE"),
                                         const("SIMULATED_USER_TEMPLATE"))
    task_lines = (base / "data/attack_task.jsonl").read_text(encoding="utf-8").splitlines()
    goals = [json.loads(line) for line in task_lines if line.strip()]
    goals = [(g["attack_task"], g["implementation"].replace("{pid}", "4242")) for g in goals]

    benign_tools = []
    for f in sorted((base / "data/tools/attack_tools").rglob("*.py")):
        stem = f.stem
        variant = stem.split("-", 1)[1] if "-" in stem else None
        tools = tools_in(f)
        if variant is None:
            for t in tools:
                benign_tools.append(t)
                rec(out, "msb-servers", "definition", "benign", "benign", t["name"], t["description"], t["params"])
            continue
        base_file = f.with_name(stem.split("-", 1)[0] + f.suffix)
        originals = tools_in(base_file) if base_file.exists() else []
        base_tools = {(t["name"], t["description"], tuple(t["params"])) for t in originals}
        base_params = {p for t in originals for p in t["params"]}
        for t in tools:
            if (t["name"], t["description"], tuple(t["params"])) not in base_tools:
                added = [p for p in t["params"] if p not in base_params]
                rec(out, "msb", "definition", "malicious", variant, t["name"], t["description"], t["params"], added)
    for task, goal in goals:  # templated attacks, a few tool contexts each (avoid near-duplicate flooding)
        for t in rng.sample(benign_tools, k=min(3, len(benign_tools))):
            rec(out, "msb", "definition", "malicious", "prompt_injection", t["name"],
                t["description"] + "\n" + injection.replace("{goal}", goal), t["params"])
        rec(out, "msb", "result", "malicious", "false_error", task, false_error + goal)
        rec(out, "msb", "result", "malicious", "simulated_user", task, simulated + goal)
        rec(out, "msb", "result", "malicious", "search_term_deception", task, goal)


def small_repos(root: Path, out: list) -> None:
    files = list((root / "mcp-injection-experiments").glob("*.py")) + list((root / "MCPSecBench/code").glob("*.py")) \
        + list((root / "damn-vulnerable-MCP-server/challenges").rglob("server.py"))
    for f in sorted(files):
        key_file = f.name if "challenge" not in str(f) else f"{f.name}@{f.parent.name}"
        for t in tools_in(f):
            cat = HAND_LABELS.get((key_file, t["name"]))
            if cat:
                src = "invariant" if "injection-experiments" in str(f) else "mcpsecbench" \
                    if "MCPSecBench" in str(f) else "dvmcp"
                rec(out, src, "definition", "malicious", cat, t["name"], t["description"], t["params"])
            elif f.name in BENIGN_FILES:
                rec(out, "mcpsecbench", "definition", "benign", "benign", t["name"], t["description"], t["params"])
    rug = (root / "mcp-injection-experiments/whatsapp-takeover.py").read_text(encoding="utf-8")
    m = re.search(r'__doc__\s*=\s*"""(.*?)"""', rug, re.S)
    if m:
        rec(out, "invariant", "definition", "malicious", "rug_pull", "get_fact_of_the_day", m.group(1))


_TS_STR = r'(?:"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|`(?:[^`\\]|\\.)*`)'


def _ts_join(chunk: str) -> str:
    parts = re.findall(_TS_STR, chunk)
    return "".join(p[1:-1].encode().decode("unicode_escape", errors="ignore") for p in parts)


def benign_sources(root: Path, out: list) -> None:
    pat = re.compile(r"description\s*:\s*((?:" + _TS_STR + r"\s*\+?\s*)+)", re.S)
    for repo in ("servers/src", "servers-archived/src"):
        for f in sorted((root / repo).rglob("*.ts")):
            if "test" in f.name.lower() or "node_modules" in str(f):
                continue
            for m in pat.finditer(f.read_text(errors="replace", encoding="utf-8")):
                text = _ts_join(m.group(1))
                rec(out, "mcp-reference-servers", "definition", "benign", "benign", f.parent.name, text)
        for f in sorted((root / repo).rglob("*.py")):
            for t in tools_in(f):
                rec(out, "mcp-reference-servers", "definition", "benign", "benign", t["name"], t["description"])
    describe = re.compile(r"\.describe\(\s*((?:" + _TS_STR + r"\s*\+?\s*)+)\)", re.S)
    field_desc = re.compile(r"Field\([^)]*description\s*=\s*(\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*')")
    for repo in ("servers/src", "servers-archived/src"):
        for f in sorted((root / repo).rglob("*.ts")):
            if "test" in f.name.lower():
                continue
            for m in describe.finditer(f.read_text(errors="replace", encoding="utf-8")):
                rec(out, "mcp-reference-servers", "definition", "benign", "benign", f.parent.name + ".param",
                    _ts_join(m.group(1)))
    for f in sorted(root.glob("*/**/*.py")):
        if "MCPSafety/mcpuniverse/mcp/servers" in str(f) or "MSB/data/tools" in str(f):
            for m in field_desc.finditer(f.read_text(errors="replace", encoding="utf-8")):
                rec(out, "param-descriptions", "definition", "benign", "benign", f.stem + ".param", m.group(1)[1:-1])
    go = re.compile(r'(?:Description:\s*t\("[A-Z0-9_]+",\s*|mcp\.Description\()("(?:[^"\\]|\\.)*")')
    for f in sorted((root / "github-mcp-server").rglob("*.go")):
        if f.name.endswith("_test.go"):
            continue
        for m in go.finditer(f.read_text(errors="replace", encoding="utf-8")):
            rec(out, "github-mcp-server", "definition", "benign", "benign", f.stem, json.loads(m.group(1)))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", type=Path)
    ap.add_argument("-o", "--out", type=Path, required=True)
    a = ap.parse_args()
    rng = random.Random(1234)
    out: list[dict] = []
    safetybench(a.root, out)
    msb(a.root, out, rng)
    small_repos(a.root, out)
    benign_sources(a.root, out)
    seen, unique = set(), []
    for r in out:  # identical texts appear in several places; keep one of each per label
        key = (r["kind"], r["label"], r["text"])
        if key not in seen:
            seen.add(key)
            unique.append(r)
    for i, r in enumerate(unique):
        r["id"] = i
    a.out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in unique), encoding="utf-8")
    from collections import Counter
    print(Counter((r["kind"], r["label"]) for r in unique))
    print(Counter(r["source"] for r in unique))
    return 0


if __name__ == "__main__":
    sys.exit(main())
