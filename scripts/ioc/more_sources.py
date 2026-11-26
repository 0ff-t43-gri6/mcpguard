"""More public attack data for training and testing the classifier.

    python scripts/ioc/more_sources.py DATASET_DIR -o eval_more.jsonl

DATASET_DIR holds shallow clones (all on GitHub):

  ASB                 agiresearch/ASB (MIT): 400 attacker tool definitions and the normal tools
  purple/             meta-llama/PurpleLlama CybersecurityBenchmarks prompt_injection.json (MIT):
                      direct and indirect injections in several languages
  tensor-trust-data   HumanCompatibleAI/tensor-trust-data: human-written hijacking and
                      prompt-extraction attacks from the Tensor Trust game
  jailbreak_llms      verazuo/jailbreak_llms (MIT): in-the-wild jailbreak prompts. Its "regular
                      prompts" are NOT used as benign text: they are role-play instructions, and
                      instructions inside a tool result are exactly what mcpguard flags.

scripts/train_model.py puts half of each source's texts in train and half in test, by hash.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

from extra_sources import rec


def asb(root: Path, out: list) -> None:
    base = root / "ASB/data"
    if not base.exists():
        return
    for line in (base / "all_attack_tools.jsonl").read_text(encoding="utf-8").splitlines():
        t = json.loads(line)
        rec(out, "asb", "definition", "malicious", t.get("Attack Type", ""), t["Attacker Tool"], t["Description"])
        rec(out, "asb", "result", "malicious", t.get("Attack Type", ""), t["Attacker Tool"],
            t["Attacker Instruction"])
    for line in (base / "all_normal_tools.jsonl").read_text(encoding="utf-8").splitlines():
        t = json.loads(line)
        rec(out, "asb", "definition", "benign", "", t["Tool Name"], t["Description"])


def purple(root: Path, out: list) -> None:
    f = root / "purple/prompt_injection.json"
    if not f.exists():
        return
    for case in json.loads(f.read_text(encoding="utf-8")):
        rec(out, "purplellama", "result", "malicious",
            f"{case.get('injection_type')}/{case.get('injection_variant')}", case["prompt_id"], case["user_input"])


def tensor_trust(root: Path, out: list) -> None:
    base = root / "tensor-trust-data/benchmarks"
    seen: set[str] = set()
    for sub in ("hijacking-robustness", "extraction-robustness"):
        f = base / sub / "v1" / f"{sub.replace('-', '_')}_dataset.jsonl"
        if not f.exists():
            continue
        for line in f.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            text = r["attack"].strip()
            # Skip attacks that are only a repeated filler token: nothing to learn from wording.
            if text in seen or len(set(text.split())) < 4:
                continue
            seen.add(text)
            rec(out, "tensortrust", "result", "malicious", sub, r["sample_id"], text)


def jailbreaks(root: Path, out: list) -> None:
    f = root / "jailbreak_llms/data/prompts/jailbreak_prompts_2023_12_25.csv"
    if not f.exists():
        return
    csv.field_size_limit(10 ** 9)
    seen: set[str] = set()
    with f.open(encoding="utf-8", newline="") as fh:
        for i, row in enumerate(csv.DictReader(fh)):
            text = row["prompt"].strip()
            if text[:200] in seen:
                continue
            seen.add(text[:200])
            rec(out, "jailbreak-llms", "result", "malicious", row.get("platform", ""), str(i), text)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", type=Path)
    ap.add_argument("-o", "--out", type=Path, required=True)
    a = ap.parse_args()
    out: list = []
    for load in (asb, purple, tensor_trust, jailbreaks):
        load(a.root, out)
    with a.out.open("w", encoding="utf-8") as fh:
        for i, r in enumerate(out):
            r["id"] = f"more-{i}"
            fh.write(json.dumps(r) + "\n")  # ASCII-only: some texts contain Unicode line separators
    for key, n in sorted(Counter((r["source"], r["kind"], r["label"]) for r in out).items()):
        print(*key, n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
