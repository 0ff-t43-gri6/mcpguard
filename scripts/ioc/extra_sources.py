"""Held-out evaluation corpus from public prompt-injection benchmarks.

    python scripts/ioc/extra_sources.py DATASET_DIR -o eval_extra.jsonl

These sources are never used to build mcpguard's IOC feed. They test how the rules and
the feed generalise to attacks written by other people, for other purposes:

  InjecAgent  (uiuc-kang-lab/InjecAgent)   tool results with injected instructions, base
                                            and "enhanced" (hacking prompt) settings
  AgentDojo   (ethz-spylab/agentdojo)      the benchmark's attack templates around its
                                            injection goals; the clean environment data
                                            (emails, calendar, files, ...) as benign results
  BIPIA       (microsoft/BIPIA)            text and code attacks inside emails and tables;
                                            the clean emails, tables and code as benign results
  ToolEmu     (ryoungj/ToolEmu)            300+ ordinary tool definitions as benign definitions
  MCP docs    (modelcontextprotocol/servers, github/github-mcp-server)
                                            README and documentation pages as benign results

Records have the same shape as build_corpus.py output.
"""

from __future__ import annotations

import argparse
import ast
import json
import random
import re
import sys
from collections import Counter
from pathlib import Path


def rec(out, source, kind, label, category, name, text, params=None):
    text = text if isinstance(text, str) else json.dumps(text, ensure_ascii=False)
    text = text.strip()
    if len(text) >= 8:
        out.append({"source": source, "kind": kind, "label": label, "category": category,
                    "name": name, "text": text, "params": params or [], "added_params": []})


# ------------------------------------------------------------------ InjecAgent

def injecagent(root: Path, out: list) -> None:
    base = root / "InjecAgent/data"
    if not base.exists():
        return
    for f in sorted(base.glob("test_cases_*_*.json")):
        setting = "enhanced" if "enhanced" in f.name else "base"
        kind = "data_stealing" if "_ds_" in f.name else "direct_harm"
        for case in json.loads(f.read_text(encoding="utf-8")):
            rec(out, "injecagent", "result", "malicious", f"{kind}/{setting}",
                case["Attacker Instruction"], case["Tool Response"])


# ------------------------------------------------------------------ AgentDojo

def _class_strings(cls: ast.ClassDef) -> dict[str, str]:
    env: dict[str, str] = {}
    for node in cls.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            value = _eval_str(node.value, env)
            if value is not None:
                env[node.targets[0].id] = value
    return env


def _eval_str(node: ast.AST, env: dict[str, str]) -> str | None:
    """Evaluate a string constant or an f-string over earlier class constants."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else str(node.value)
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(str(v.value))
            elif isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name) and v.value.id in env:
                parts.append(env[v.value.id])
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = _eval_str(node.left, env), _eval_str(node.right, env)
        return a + b if a is not None and b is not None else None
    return None


def _agentdojo_goals(suites: Path) -> list[tuple[str, str]]:
    goals = []
    for f in sorted(suites.glob("*/injection_tasks.py")):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ClassDef):
                goal = _class_strings(node).get("GOAL")
                if goal:
                    goals.append((f.parent.name, goal))
    return goals


def _agentdojo_templates(attacks: Path) -> dict[str, str]:
    templates = {}
    for f in ("baseline_attacks.py", "important_instructions_attacks.py"):
        for node in ast.walk(ast.parse((attacks / f).read_text(encoding="utf-8"))):
            if isinstance(node, ast.ClassDef):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and "{goal}" in sub.value \
                            and "{tools}" not in sub.value:
                        templates[node.name] = sub.value
    return templates


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def agentdojo(root: Path, out: list, rng: random.Random) -> None:
    import yaml
    pkg = root / "agentdojo/src/agentdojo"
    if not pkg.exists():
        return
    data = pkg / "data/suites"
    defaults: dict[str, str] = {}
    for f in sorted(data.glob("*/injection_vectors.yaml")):
        for name, spec in (yaml.safe_load(f.read_text(encoding="utf-8")) or {}).items():
            defaults[name] = str(spec.get("default", ""))
    # Benign results: the environment's own content with every injection slot at its default.
    for suite in sorted(p for p in data.iterdir() if p.is_dir()):
        for f in sorted([suite / "environment.yaml", *(suite / "include").glob("*.yaml")]):
            if not f.exists():
                continue
            text = f.read_text(encoding="utf-8")
            text = re.sub(r"\{(\w+)\}", lambda m: defaults.get(m.group(1), m.group(0)), text)
            try:
                doc = yaml.safe_load(text)
            except yaml.YAMLError:
                continue
            for s in _strings(doc):
                if len(s) >= 40:
                    rec(out, "agentdojo", "result", "benign", f"benign/{suite.name}", f.stem, s)
    # Malicious results: each attack template around each goal, placed in a benign slot.
    templates = _agentdojo_templates(pkg / "attacks")
    contexts = [d for d in defaults.values() if len(d) >= 20]
    for suite, goal in _agentdojo_goals(pkg / "default_suites/v1"):
        for attack, tmpl in sorted(templates.items()):
            payload = tmpl.replace("{goal}", goal).replace("{user}", "Emma Johnson").replace("{model}", "the assistant")
            rec(out, "agentdojo", "result", "malicious", f"{attack}", suite,
                f"{rng.choice(contexts)} {payload}" if contexts else payload)


# ------------------------------------------------------------------ BIPIA

def bipia(root: Path, out: list, rng: random.Random) -> None:
    base = root / "BIPIA/benchmark"
    if not base.exists():
        return
    contexts: dict[str, list[str]] = {}
    for task in ("email", "table", "code"):
        for split in ("train", "test"):
            f = base / task / f"{split}.jsonl"
            if f.exists():
                for line in f.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        ctx = json.loads(line).get("context")
                        if isinstance(ctx, list):
                            ctx = "\n".join(map(str, ctx))
                        if isinstance(ctx, str):
                            contexts.setdefault(task, []).append(ctx)
    for task, items in contexts.items():
        sample = items if task != "table" else rng.sample(items, k=min(150, len(items)))
        for ctx in sample:
            rec(out, "bipia", "result", "benign", f"benign/{task}", task, ctx)
    for attack_file, host in (("text_attack_test.json", "email"), ("code_attack_test.json", "code")):
        f = base / attack_file
        if not f.exists():
            continue
        for category, attacks in json.loads(f.read_text(encoding="utf-8")).items():
            for attack in attacks:
                ctx = rng.choice(contexts.get(host) or [""])
                where = rng.choice(("start", "middle", "end"))
                if where == "start":
                    text = f"{attack}\n{ctx}"
                elif where == "end":
                    text = f"{ctx}\n{attack}"
                else:
                    cut = len(ctx) // 2
                    text = f"{ctx[:cut]}\n{attack}\n{ctx[cut:]}"
                rec(out, "bipia", "result", "malicious", category, host, text)


# ------------------------------------------------------------------ ToolEmu

def toolemu(root: Path, out: list) -> None:
    f = root / "ToolEmu/assets/all_toolkits.json"
    if not f.exists():
        return
    for kit in json.loads(f.read_text(encoding="utf-8")):
        for t in kit.get("tools", []):
            params = [p["name"] for p in t.get("parameters", []) if isinstance(p, dict) and "name" in p]
            rec(out, "toolemu", "definition", "benign", "benign", kit["toolkit"] + t["name"], t.get("summary", ""),
                params)
            for p in t.get("parameters", []):
                if isinstance(p, dict) and p.get("description"):
                    rec(out, "toolemu", "definition", "benign", "benign", f"{kit['toolkit']}{t['name']}.param",
                        p["description"])


# ------------------------------------------------------------------ documentation pages

def docs(root: Path, out: list) -> None:
    """Markdown documentation, as a fetch tool would return it: benign results full of
    "use the X tool" and "send feedback to ..."."""
    for repo in ("servers", "servers-archived", "github-mcp-server"):
        for f in sorted((root / repo).rglob("*.md")):
            if "node_modules" in f.parts or f.stat().st_size > 200_000:
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
            chunk = ""
            for para in re.split(r"\n\s*\n", text):
                if len(chunk) + len(para) > 1500 and chunk:
                    rec(out, "mcp-docs", "result", "benign", "benign/docs", f.name, chunk)
                    chunk = ""
                chunk += para + "\n\n"
            rec(out, "mcp-docs", "result", "benign", "benign/docs", f.name, chunk)


def injecagent_controls(root: Path, out: list, rng: random.Random, per_template: int = 30) -> None:
    """Benign twins of InjecAgent's results: the same 17 response templates with the attack
    slot filled by real benign sentences (from AgentDojo and BIPIA). Without them every
    InjecAgent-shaped result is an attack, and a classifier can learn the template instead
    of the injection."""
    f = root / "InjecAgent/data/user_cases.jsonl"
    if not f.exists():
        return
    pool = []
    for r in out:
        if r["label"] == "benign" and r["kind"] == "result" and r["source"] in ("agentdojo", "bipia"):
            pool.extend(sentence.replace('"', "'") for sentence in re.split(r"(?<=[.!?])\s+", r["text"])
                        if 30 <= len(sentence) <= 220 and "{" not in sentence)
    if not pool:
        return
    for line in f.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        case = json.loads(line)
        template = case["Tool Response Template"]
        for i in range(per_template):
            rec(out, "injecagent", "result", "benign", "benign/template", f"{case['User Tool']}#{i}",
                template.replace("<Attacker Instruction>", rng.choice(pool)))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", type=Path)
    ap.add_argument("-o", "--out", type=Path, required=True)
    a = ap.parse_args()
    rng = random.Random(4321)
    out: list[dict] = []
    injecagent(a.root, out)
    agentdojo(a.root, out, rng)
    bipia(a.root, out, rng)
    toolemu(a.root, out)
    docs(a.root, out)
    injecagent_controls(a.root, out, rng)
    seen, unique = set(), []
    for r in out:
        key = (r["kind"], r["label"], r["text"])
        if key not in seen:
            seen.add(key)
            unique.append(r)
    for i, r in enumerate(unique):
        r["id"] = i
    a.out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in unique), encoding="utf-8")
    print(Counter((r["source"], r["kind"], r["label"]) for r in unique))
    return 0


if __name__ == "__main__":
    sys.exit(main())
