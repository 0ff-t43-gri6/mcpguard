"""A small learned classifier for prompt injection, used next to the rules.

Logistic regression on hashed word unigrams and bigrams, in plain Python (no numpy, no
model server). Trained by scripts/train_model.py on public datasets; the weights ship in
data/injection_model.json together with the thresholds and the evaluation they came from.

It gives a probability that a text (a tool description or a tool result) carries injected
instructions. Rules explain *why* something is suspicious; the model catches wording no rule
names. Its findings say "classifier", so they are easy to tell apart and to tune with
[detectors.severity_overrides] "ml.injection".
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

from .detect import Finding

BUNDLED_MODEL = Path(__file__).with_name("data") / "injection_model.json"
DIM = 1 << 18
_WORD = re.compile(r"[a-z]+|\d+|[^\sa-z\d]")


def tokens(text: str) -> list[str]:
    words = _WORD.findall(text.lower()[:20_000])  # long results: the start carries the signal; bounded cost
    return ["0" if w.isdigit() else w for w in words]


def _h(s: str) -> int:
    return int.from_bytes(hashlib.blake2b(s.encode(), digest_size=8).digest(), "little") % DIM


def features(text: str) -> dict[int, float]:
    """Hashed unigrams and bigrams, L2-normalised (binary presence)."""
    toks = tokens(text)
    keys = {_h("u:" + t) for t in toks} | {_h("b:" + a + " " + b) for a, b in itertools.pairwise(toks)}
    if not keys:
        return {}
    v = 1.0 / math.sqrt(len(keys))
    return dict.fromkeys(keys, v)


@dataclass
class Model:
    weights: dict[int, float] = field(default_factory=dict)
    bias: float = 0.0
    medium: float = 0.5
    high: float = 0.9
    info: dict = field(default_factory=dict)

    def score(self, text: str) -> float:
        z = self.bias + sum(self.weights.get(k, 0.0) * v for k, v in features(text).items())
        return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))

    def findings(self, text: str, where: str, medium: float | None = None, high: float | None = None) -> list[Finding]:
        p = self.score(text)
        hi = self.high if high is None else high
        med = self.medium if medium is None else medium
        if p >= hi:
            return [Finding("ml.injection", "high", f"classifier: {p:.0%} likely to contain injected instructions",
                            where)]
        if p >= med:
            return [Finding("ml.injection", "medium", f"classifier: {p:.0%} likely to contain injected instructions",
                            where)]
        return []

    def to_json(self) -> dict:
        return {"version": 1, "dim": DIM, "bias": round(self.bias, 6), "medium": self.medium, "high": self.high,
                "info": self.info, "weights": {str(k): round(w, 5) for k, w in sorted(self.weights.items())}}

    @classmethod
    def from_json(cls, d: dict) -> Model:
        if d.get("version") != 1 or d.get("dim") != DIM:
            raise ValueError("unsupported model file")
        return cls({int(k): float(w) for k, w in d["weights"].items()}, float(d["bias"]), float(d["medium"]),
                   float(d["high"]), dict(d.get("info", {})))

    @classmethod
    def load(cls, path: str | Path = BUNDLED_MODEL) -> Model:
        return cls.from_json(json.loads(Path(path).read_text(encoding="utf-8")))

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_json(), separators=(",", ":")), encoding="utf-8")


def train(docs: list[tuple[dict[int, float], int]], epochs: int = 12, lr: float = 0.5, l2: float = 1e-6,
          seed: int = 0) -> Model:
    """Logistic regression by AdaGrad SGD with balanced class weights."""
    import random
    # Seeded shuffling for reproducible training; nothing security-related.
    rng = random.Random(seed)  # noqa: S311  # nosec B311
    pos = sum(y for _, y in docs) or 1
    neg = (len(docs) - pos) or 1
    cw = {1: len(docs) / (2 * pos), 0: len(docs) / (2 * neg)}
    w: dict[int, float] = {}
    g2: dict[int, float] = {}
    b, gb = 0.0, 0.0
    order = list(range(len(docs)))
    for _ in range(epochs):
        rng.shuffle(order)
        for i in order:
            x, y = docs[i]
            z = b + sum(w.get(k, 0.0) * v for k, v in x.items())
            p = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
            err = (p - y) * cw[y]
            for k, v in x.items():
                g = err * v + l2 * w.get(k, 0.0)
                g2[k] = g2.get(k, 0.0) + g * g
                w[k] = w.get(k, 0.0) - lr * g / (math.sqrt(g2[k]) + 1e-8)
            gb += err * err
            b -= lr * err / (math.sqrt(gb) + 1e-8)
    return Model(w, b)
