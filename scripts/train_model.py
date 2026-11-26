"""Train and evaluate mcpguard's injection classifier.

    python scripts/train_model.py --corpus corpus.jsonl --extra eval_extra.jsonl eval_more.jsonl \
        -o src/mcpguard/data/injection_model.json --report docs/model.md

Data, and what is never trained on:

  train   the training corpus (build_corpus.py) except the held-out tool families, the
          development parts of the held-out benchmarks (InjecAgent data-stealing, AgentDojo
          workspace; already used to write the result rules) and half of the benign texts of
          each benchmark source (split by source document)
  valid   a slice of the training data, used only to choose the two thresholds
  test    held-out tool families of the corpus, InjecAgent direct-harm, every other AgentDojo
          suite, all of BIPIA's attacks, and the other half of the benign texts

Thresholds: "high" is set above every benign validation text (so it blocks nothing benign we
know of); "medium" at the 99th percentile of benign validation scores.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcpguard.iocs import _family, read_corpus
from mcpguard.model import Model, features, train


HASH_SPLIT = {"asb", "purplellama", "tensortrust", "jailbreak-llms"}  # scripts/ioc/more_sources.py


TEST_ONLY = {"asb"}
HIGH_FLOOR = 0.97


def _half(key: str, salt: str = "split") -> bool:
    return hashlib.sha256(f"{salt}:{key}".encode()).digest()[0] % 2 == 0


def development_case(r: dict) -> bool:
    return (r["source"] == "injecagent" and r["category"].startswith("data_stealing")) or \
        (r["source"] == "agentdojo" and r["label"] == "malicious" and r.get("name") == "workspace")


def split(corpus: list[dict], extra: list[dict]) -> tuple[list[dict], list[dict]]:
    train_set, test_set = [], []
    held_families = {f for f in {_family(r) for r in corpus} if _half(f, "family")}
    for r in corpus:
        (test_set if _family(r) in held_families else train_set).append(r)
    for r in extra:
        if r["source"] in HASH_SPLIT or (r["source"] == "bipia" and r["label"] != "malicious"):
            # newer sources, and BIPIA's clean emails, tables and code: half of the texts each way
            (train_set if _half(r["text"][:200], r["source"]) else test_set).append(r)
        elif r["label"] == "malicious":
            (train_set if development_case(r) else test_set).append(r)
        else:  # benign: split by source document so near-duplicate chunks stay together
            (train_set if _half(f"{r['source']}:{r.get('name')}") else test_set).append(r)
    return train_set, test_set


def evaluate(model: Model, rows: list[dict]) -> dict:
    groups: dict[str, list[float]] = defaultdict(list)
    for r in rows:
        key = f"{r['source']}|{r['kind']}|{r['label']}"
        groups[key].append(model.score(r["text"]))
    out = {}
    for key, scores in sorted(groups.items()):
        out[key] = {"n": len(scores), "medium": sum(s >= model.medium for s in scores),
                    "high": sum(s >= model.high for s in scores)}
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--extra", type=Path, required=True, nargs="+", help="one or more extra corpora")
    ap.add_argument("-o", "--out", type=Path, required=True)
    ap.add_argument("--report", type=Path)
    ap.add_argument("--max-weights", type=int, default=30000, help="keep the largest weights (file size)")
    a = ap.parse_args()

    train_rows, test_rows = split(read_corpus(a.corpus), [r for f in a.extra for r in read_corpus(f)])
    valid_rows = [r for r in train_rows if _half(str(r.get("id")) + r["text"][:50], "valid") and
                  _half(r["text"][:80], "valid2")]  # about a quarter of training data
    # ASB's attacker tools and requests ("please allocate more CPU to process X") are attacks only
    # by intent; trained on, they make ordinary emails and tools look malicious. Test only.
    fit_rows = [r for r in train_rows if r not in valid_rows and r["source"] not in TEST_ONLY]
    docs = [(features(r["text"]), int(r["label"] == "malicious")) for r in fit_rows]
    model = train(docs)
    keep = sorted(model.weights.items(), key=lambda kv: -abs(kv[1]))[: a.max_weights]
    model.weights = dict(keep)

    benign_valid = sorted(model.score(r["text"]) for r in valid_rows if r["label"] != "malicious")
    # "high" blocks a result, so it gets a floor as well as the margin over benign validation
    # text (see docs/model.md for why 0.97).
    model.high = round(min(0.99, max(HIGH_FLOOR, benign_valid[-1] + 0.02)), 3) if benign_valid else HIGH_FLOOR
    model.medium = round(max(0.5, benign_valid[int(0.99 * (len(benign_valid) - 1))]), 3) if benign_valid else 0.5
    model.medium = min(model.medium, model.high - 0.05)

    result = {"train": len(fit_rows), "valid": len(valid_rows), "test": len(test_rows),
              "train_malicious": sum(y for _, y in docs), "test_results": evaluate(model, test_rows)}
    model.info = {"trained_on": sorted({r["source"] for r in fit_rows}), "rows": result["train"],
                  "medium": model.medium, "high": model.high}
    model.save(a.out)
    lines = [f"Trained on {result['train']} texts ({result['train_malicious']} malicious), thresholds chosen on "
             f"{result['valid']}, tested on {result['test']} never used for either.",
             f"Thresholds: medium {model.medium}, high {model.high}.", "",
             "| Test set | Texts | Medium or above | High |", "|---|---:|---:|---:|"]
    for key, v in result["test_results"].items():
        src, kind, label = key.split("|")
        name = f"{src} {kind}s ({'attacks' if label == 'malicious' else 'benign'})"
        lines.append(f"| {name} | {v['n']} | {v['medium']} ({v['medium'] / v['n']:.1%}) | "
                     f"{v['high']} ({v['high'] / v['n']:.1%}) |")
    report = "\n".join(lines)
    print(report)
    if a.report:
        a.report.write_text(report + "\n", encoding="utf-8")
    print(json.dumps({"weights": len(model.weights), "file_kb": a.out.stat().st_size // 1024}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
