"""Adaptive per-tool baselines.

Learns what "normal" looks like for each tool (result size, latency, argument
size) with running mean/variance (Welford). Once a tool has enough samples, a
value more than `z` standard deviations out is reported as an anomaly.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from .detect import Finding
from .fileio import load_json, locked, write_atomic


def _valid(stat) -> bool:
    return isinstance(stat, list) and len(stat) == 3 and all(isinstance(x, int | float) for x in stat)


def combine(a: list[float], b: list[float]) -> list[float]:
    """Merge two (n, mean, M2) running statistics into the statistics of all their samples."""
    na, nb = a[0], b[0]
    if not na:
        return list(b)
    if not nb:
        return list(a)
    n = na + nb
    delta = b[1] - a[1]
    return [n, a[1] + delta * nb / n, a[2] + b[2] + delta * delta * na * nb / n]


class Baselines:
    def __init__(self, path: str | Path, min_samples: int = 20, z: float = 4.0):
        self.path = Path(path)
        self.min_samples = min_samples
        self.z = z
        self.data: dict[str, dict[str, list[float]]] = load_json(self.path, {})
        self._new: dict[str, dict[str, list[float]]] = {}  # observed here since the last save
        self._dirty = 0

    def _stats(self, tool: str, metric: str) -> list[float]:
        return self.data.setdefault(tool, {}).setdefault(metric, [0, 0.0, 0.0])  # n, mean, M2

    def check(self, tool: str, metric: str, value: float) -> Finding | None:
        n, mean, m2 = self._stats(tool, metric)
        if n < self.min_samples:
            return None
        std = math.sqrt(m2 / (n - 1)) if n > 1 else 0.0
        std = max(std, abs(mean) * 0.05, 1.0)  # floor so near-constant tools don't flag tiny changes
        score = (value - mean) / std
        if score > self.z:
            return Finding(f"anomaly.{metric}", "medium",
                           f"{metric}={value:.0f} is {score:.1f}σ above this tool's norm ({mean:.0f})", tool)
        return None

    def observe(self, tool: str, metric: str, value: float):
        for s in (self._stats(tool, metric), self._new.setdefault(tool, {}).setdefault(metric, [0, 0.0, 0.0])):
            s[0] += 1
            delta = value - s[1]
            s[1] += delta / s[0]
            s[2] += delta * (value - s[1])
        self._dirty += 1
        if self._dirty >= 20:
            self.save()

    def update(self, tool: str, **metrics: float) -> list[Finding]:
        """Check then learn. Anomalous values are not learned, so attacks can't shift the norm."""
        out = []
        for metric, value in metrics.items():
            f = self.check(tool, metric, value)
            if f:
                out.append(f)
            else:
                self.observe(tool, metric, value)
        return out

    def save(self):
        """Merge what this process learned into the file. Running statistics combine exactly
        (Chan et al.), so several gateway processes learn together, and a `mcpguard baseline
        reset` made while a gateway runs is not undone by its next save."""
        lock = self.path.with_name(self.path.name + ".lock")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with locked(lock):
            disk: dict = load_json(self.path, {})
            for tool, metrics in self._new.items():
                for metric, new in metrics.items():
                    old = disk.setdefault(tool, {}).get(metric)
                    disk[tool][metric] = combine(old, new) if _valid(old) else list(new)
            if self._new:
                write_atomic(self.path, json.dumps(disk, indent=1, sort_keys=True))
        self.data, self._new, self._dirty = disk, {}, 0

    def summary(self) -> dict:
        out = {}
        for tool, metrics in self.data.items():
            out[tool] = {m: {"n": v[0], "mean": round(v[1], 1),
                             "std": round(math.sqrt(v[2] / (v[0] - 1)), 1) if v[0] > 1 else 0}
                         for m, v in metrics.items()}
        return out
