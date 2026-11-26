"""Measure mcpguard's detection against public attack datasets and write a report.

    python scripts/benchmark.py --corpus corpus.jsonl --extra eval_extra.jsonl -o docs/benchmark.md

Three views, from easiest to hardest:

1. Unseen tool families: the IOC feed is rebuilt on half the tool families of the
   training corpus (scripts/ioc/build_corpus.py) and scored on the other half.
2. Unseen dataset: each attack dataset of the training corpus is held out in turn and
   the feed is rebuilt from the others.
3. Held-out benchmarks: datasets the bundled feed never saw (scripts/ioc/extra_sources.py),
   scored with the shipped rules and the shipped feed.

"Detected" means at least one finding at or above the level. A false alarm is a benign
definition or result with such a finding. Rules-only columns show what the built-in rules
catch without any indicators.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import defaultdict
from pathlib import Path

from mcpguard.config import DetectorConfig
from mcpguard.detect import SEVERITIES, Engine
from mcpguard.iocs import BUNDLED_FEED, IocFeed, evaluate, make_scorer, read_corpus

LEVELS = ("medium", "high")


def development_case(r: dict) -> bool:
    """Cases looked at while writing the result-injection rules (mcpguard 0.8.0). The
    other cases of the same benchmarks were only scored, which keeps a clean test set."""
    return (r["source"] == "injecagent" and r["category"].startswith("data_stealing")) or \
        (r["source"] == "agentdojo" and r["label"] == "malicious" and r.get("name") == "workspace")


def worst(engine: Engine, feed: IocFeed | None, r: dict) -> int:
    findings = []
    if r["kind"] == "definition":
        props = {p: {"type": "string"} for p in r.get("params", [])}
        findings += engine.scan_definition({"name": r.get("name") or "t", "description": r["text"],
                                            "inputSchema": {"type": "object", "properties": props}}, "s")
        if feed is not None:
            findings += feed.match_text(r["text"], "x") + feed.match_name(r.get("name", ""), "x") \
                + feed.match_params(r.get("params", []), "x")
    else:
        findings += engine.scan_texts(r.get("name") or "t", [r["text"]])
        if feed is not None:
            findings += feed.match_text(r["text"], "x")
    return max((SEVERITIES[f.severity] for f in findings), default=-1)


def pct(n: int, d: int) -> str:
    return f"{n / d:.1%}" if d else "–"


def held_out(records: list[dict]) -> tuple[list[str], dict]:
    engine = Engine(DetectorConfig(iocs=False, model=False))  # the classifier is scored in docs/model.md
    feed = IocFeed.load(BUNDLED_FEED)
    rows: dict = defaultdict(lambda: {"n": 0, **{f"{m}/{lv}": 0 for m in ("rules", "all") for lv in LEVELS}})
    for r in records:
        sev_rules, sev_all = worst(engine, None, r), worst(engine, feed, r)
        keys = [(r["source"], r["kind"], r["label"], "*")]
        if r["label"] == "malicious":
            keys.append((r["source"], r["kind"], r["label"], r["category"]))
            if r["source"] in ("injecagent", "agentdojo"):
                keys.append((r["source"], r["kind"], "dev" if development_case(r) else "test", "*"))
        for k in keys:
            row = rows[k]
            row["n"] += 1
            for lv in LEVELS:
                row[f"rules/{lv}"] += sev_rules >= SEVERITIES[lv]
                row[f"all/{lv}"] += sev_all >= SEVERITIES[lv]
    out = ["| Dataset | Kind | Texts | Rules only (high) | Rules + IOCs (high) | Rules + IOCs (medium) |",
           "|---|---|---:|---:|---:|---:|"]
    for (src, kind, label, cat), row in sorted(rows.items()):
        if label == "malicious" and cat == "*":
            out.append(f"| {src} | {kind} attacks | {row['n']} | {pct(row['rules/high'], row['n'])} | "
                       f"{pct(row['all/high'], row['n'])} | {pct(row['all/medium'], row['n'])} |")
    out += ["", "The result-injection rules were written while looking at InjecAgent's data-stealing cases",
            "and AgentDojo's workspace suite. Scored separately:", "",
            "| Dataset | Part | Texts | Rules + IOCs (high) |", "|---|---|---:|---:|"]
    for (src, _kind, part, cat), row in sorted(rows.items()):
        if part in ("dev", "test") and cat == "*":
            label = "looked at (development)" if part == "dev" else "never looked at (test)"
            out.append(f"| {src} | {label} | {row['n']} | {pct(row['all/high'], row['n'])} |")
    out += ["", "False alarms on benign texts from the same benchmarks:", "",
            "| Dataset | Kind | Texts | Flagged (high) | Flagged (medium) |", "|---|---|---:|---:|---:|"]
    for (src, kind, label, cat), row in sorted(rows.items()):
        if label == "benign" and cat == "*":
            out.append(f"| {src} | {kind} | {row['n']} | {row['all/high']} ({pct(row['all/high'], row['n'])}) | "
                       f"{row['all/medium']} ({pct(row['all/medium'], row['n'])}) |")
    out += ["", "By attack category (rules + IOCs, high):", "", "| Dataset | Category | Texts | Detected |",
            "|---|---|---:|---:|"]
    for (src, _kind, label, cat), row in sorted(rows.items()):
        if label == "malicious" and cat != "*":
            out.append(f"| {src} | {cat} | {row['n']} | {pct(row['all/high'], row['n'])} |")
    return out, rows


def families(records: list[dict], seeds: tuple[int, ...]) -> list[str]:
    out = ["| Level | Detectors | " + " | ".join(f"Split {s}" for s in seeds) + " |",
           "|---|---|" + "---:|" * len(seeds)]
    for lv in ("high", "medium"):
        for with_rules in (False, True):
            cells = []
            for s in seeds:
                r = evaluate(records, make_scorer(lv, with_detectors=with_rules), seed=s)
                cells.append(f"{r.recall:.1%} (false alarms {r.false_positives}/{r.benign})")
            out.append(f"| {lv} | {'rules + IOCs' if with_rules else 'IOCs only'} | " + " | ".join(cells) + " |")
    return out


def by_source(records: list[dict]) -> list[str]:
    sources = sorted({r["source"] for r in records if r["label"] == "malicious"})
    out = ["| Held-out dataset | Attacks | IOCs only (high) | Rules + IOCs (high) | False alarms |",
           "|---|---:|---:|---:|---:|"]
    for src in sources:
        ioc = evaluate(records, make_scorer("high", with_detectors=False), holdout_source=src)
        both = evaluate(records, make_scorer("high", with_detectors=True), holdout_source=src)
        out.append(f"| {src} | {both.malicious} | {ioc.recall:.1%} | {both.recall:.1%} | "
                   f"{both.false_positives}/{both.benign} |")
    return out


NOTES = """## Reading these numbers

- **High** is what blocks a call or quarantines a tool by default; **medium** is logged and
  shown in the dashboard.
- The IOC feed helps on attacks that reuse known wording (view 1). On a dataset it has never
  seen (views 2 and 3) it adds nothing measurable; detection there comes from the rules.
- Not caught, by design or for now:
  - requests that read like ordinary user requests inside data, with nothing to send
    anywhere ("Please unlock my front door", InjecAgent direct-harm base: 0%);
  - AgentDojo's bare `TODO: <goal>` style;
  - BIPIA's off-task requests ("write a script that renames files"), which are only
    attacks relative to what the user asked;
  - attacks with no text to inspect (a renamed copy of a genuine tool, preference
    manipulation).
- Medium flags on documentation are mostly `secret.high_entropy` on hashes and IDs.

## The learned classifier

Not included above: part of these benchmarks is its training data. It is trained and scored on
its own split (never-seen test texts only) in [model.md](model.md).

## Reproducing

Clone the datasets into one folder (see scripts/ioc/build_corpus.py and
scripts/ioc/extra_sources.py for the list), then:

    python scripts/ioc/build_corpus.py DATASETS -o corpus.jsonl
    python scripts/ioc/extra_sources.py DATASETS -o eval_extra.jsonl
    python scripts/benchmark.py --corpus corpus.jsonl --extra eval_extra.jsonl -o docs/benchmark.md
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=Path, help="training corpus from scripts/ioc/build_corpus.py")
    ap.add_argument("--extra", type=Path, help="held-out corpus from scripts/ioc/extra_sources.py")
    ap.add_argument("-o", "--out", type=Path, help="write the report here (Markdown)")
    a = ap.parse_args()
    if not a.corpus and not a.extra:
        ap.error("give --corpus, --extra or both")
    started = time.perf_counter()
    lines = ["# mcpguard detection benchmark", ""]
    if a.corpus:
        corpus = read_corpus(a.corpus)
        lines += ["## 1. Unseen tool families", "",
                  "IOC feed rebuilt on half the tool families of the training corpus, scored on the rest.", "",
                  *families(corpus, (7, 11, 23)), "",
                  "## 2. Unseen dataset", "",
                  "Each dataset is held out in turn; the feed is rebuilt from the others.", "",
                  *by_source(corpus), ""]
    if a.extra:
        table, _ = held_out(read_corpus(a.extra))
        lines += ["## 3. Held-out benchmarks", "",
                  "Datasets never used to build the bundled feed, scored with the shipped rules and feed.", "",
                  *table, ""]
    lines += NOTES.splitlines()
    lines.append(f"_Generated by scripts/benchmark.py in {time.perf_counter() - started:.0f}s._")
    report = "\n".join(lines) + "\n"
    if a.out:
        a.out.write_text(report, encoding="utf-8")
    sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
