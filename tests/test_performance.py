"""No detector may be slowed down by crafted input (regex backtracking, ReDoS).

A malicious server controls its results completely. Each input here once made a pattern
quadratic: a run of '#', newlines, brackets, ... Every scan must finish quickly.

Each scan runs in a child process: Python's regex engine holds the GIL, so a stuck pattern
would also freeze a watchdog thread, and the test would hang instead of failing.
"""

import json
import subprocess
import sys

import pytest
from timing import scaled

N = 60_000
UNITS = ["#", "[", "<|", "![", "a/", "a@", ".", "\n", "please ", "to you, the ", "quietly word ", "retrieve and ",
         "send it to ", "1", "Ab",
         "4 ", "1-", "+9 ", "(1", "GB82 ", "A1", "a@b.", "a.", "1.",
         "the ", "x-", "_", "%20", "a_", "`", "<", "data and ", "​", "QUJD"]

SCAN = """
import json, sys, time
from mcpguard.config import DetectorConfig
from mcpguard.detect import Engine
from mcpguard import dlp
engine = Engine(DetectorConfig())
times = []
for text in json.loads(sys.stdin.read()):
    t = time.perf_counter()
    engine.scan_texts("t", [text])
    engine.scan_args("t", {"value": text})
    engine.scan_definition({"name": "t", "description": text}, "s")
    dlp.redact(text, {c.name: "redact" for c in dlp.CLASSES})
    dlp.scan(text, {c.name: "block" for c in dlp.CLASSES}, "outbound", "t")
    times.append(time.perf_counter() - t)
print(json.dumps(times))
"""


def scan_times(texts: list[str], seconds: float) -> list[float]:
    try:
        out = subprocess.run([sys.executable, "-c", SCAN], input=json.dumps(texts), capture_output=True, text=True,
                             encoding="utf-8", timeout=seconds, check=True).stdout
    except subprocess.TimeoutExpired:
        pytest.fail(f"scanning crafted input did not finish within {seconds}s")
    return json.loads(out)


def test_crafted_input_cannot_stall_the_detectors():
    texts = [u * (N // len(u)) for u in UNITS]
    times = scan_times(texts, seconds=scaled(60))
    slow = [(repr(u), round(t, 2)) for u, t in zip(UNITS, times, strict=True) if t > scaled(5)]
    assert not slow, slow


def test_scan_time_grows_linearly():
    small, large = scan_times(["#" * 20_000 + "\n" * 20_000, "#" * 80_000 + "\n" * 80_000], seconds=scaled(60))
    assert large < max(small, 0.02) * 12  # 4x the input; quadratic would be ~16x
