# Contributing

```sh
pip install -e ".[dev]"
python scripts/check.py          # lint, types (all three platforms), security lint, dead code, tests
python scripts/check.py --full   # plus a clean-install package check, property campaign, dependency audit
```

Everything must pass before a change is merged; CI runs the same script on Linux, Windows
and macOS.

- **No runtime dependencies.** mcpguard installs with nothing else; keep it that way.
- **A detector change needs both sides:** a test that the attack is caught and a test that
  similar ordinary text is not. Then run `scripts/benchmark.py` and check the false-alarm
  counts did not move.
- **A security fix needs a row** in `docs/threat-model.md` and a test in `tests/test_threats.py`.
- **Regexes on text a server controls must stay linear;** `tests/test_performance.py` enforces it.
- **Text I/O names its encoding.** The tests fail on any that relies on the platform default.
- **The classifier is never tuned on its test split.** See `docs/model.md`.

`docs/architecture.md` has the map of the code.
