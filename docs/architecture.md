# mcpguard: architecture notes

A Python 3.11+ MCP security gateway with no runtime dependencies. It sits between an MCP
client and many upstream servers (stdio or Streamable HTTP) and adds policy, detection,
supervision and a tamper-evident audit log. See README.md for behaviour and CHANGELOG.md
for history.

## Layout
- `gateway.py`: the core. Dispatch, `_guarded` (the request path), discovery and
  quarantine, server supervision (`_start_one`, `_check_health`), live reload
  (`maybe_reload`, `_swap_config`, `_sync_servers`), state snapshot, `serve_stdio`.
- `httpserve.py`: Streamable HTTP front end (`HttpFrontend`, `serve_http`), client auth, sessions.
- `checks.py`: attack-specific checks (paths, injection, SSRF, exfiltration, names) and the
  rule `CATALOG` behind `mcpguard checks`. New checks need tests for both attacks and
  ordinary input that must stay quiet.
- `iocs.py`: IOC feeds (build with payload isolation, match, evaluate); bundled feed in
  `data/iocs.json`, rebuilt with `scripts/ioc/build_corpus.py` + `mcpguard iocs build`.
  Re-run `mcpguard iocs eval` before shipping a new feed: zero false alarms on benign tools is
  the bar.
- `scripts/benchmark.py`: detection report over the training corpus and the held-out
  benchmarks (`scripts/ioc/extra_sources.py`). Regenerate `docs/benchmark.md` after changing
  rules or the feed; never tune rules on the "test" parts it lists.
- `fileio.py`: atomic saves, corrupt-tolerant loads, the cross-process `locked()` and
  `create_once()` (race-free creation of the audit key and dashboard token).
- Several gateway processes may share one config (Claude Desktop starts two). Anything written to
  disk must merge, not overwrite: audit log (lock + re-read head), pins and baselines (merge only
  this process's new data), grants (`grants.json`), state (`mcpguard-state.<pid>.json`, merged
  by `state.read_merged`). `tests/test_end_to_end.py` runs two real gateways.
- `desktop.py` (Claude Desktop config), `doctor.py`, `stats.py`, `state.py`: see their docstrings.
- Regexes on text a server controls must stay linear: bounded gaps, no `\s*` after a line
  break, run anchors. `tests/test_performance.py` times every detector on crafted input.
- `data/confusables.json`: Latin look-alike letters from Unicode's confusables list (UTS #39), taken from the
  MIT-licensed confusable_homoglyphs package data; only entries NFKC does not already fold.
- `docs/threat-model.md` records attacks on mcpguard itself; every fixed one has a test in
  `tests/test_threats.py`. Add a row and a test for each new one.
- `dlp.py`: validated personal-data recognisers and the per-direction policy; gateway hooks are
  `_dlp_outbound`, `_dlp_result` and `_clean`. Finding messages are scrubbed in `Engine.finalize`.
- `selftest.py` (acceptance check; keep every case passing under the default config), `export.py`
  (audit log to JSONL/CSV/CEF), `deploy/` + `Dockerfile` (see docs/deployment.md, docs/operations.md).
- `sandbox.py` (container wrapper for local servers), `policy.scope_violation` (allowed_paths /
  allowed_hosts), `policy.sensitive_name` + `ask_sensitive` (approval for tools no rule names).
- `advisories.py` + `data/advisories.json`: real incidents and CVEs. Every entry needs a source (or a
  caveat saying it has none) and an honest verdict: blocks, limits, detects or outside.
- Entry points are tested in `tests/test_entry_points.py` against `tests/hostile_server.py`. Messages
  shown to the model must never quote text a server supplied (`Gateway._for_model`).
- `model.py` + `scripts/train_model.py`: the classifier. Never tune thresholds or features on the
  test split; keep benign twins of any templated attack data, or the model learns the template.
- `net.py`: the only way to make outbound HTTP (http/https only, no redirects).
- `schema.py`: minimal JSON Schema validator for tool arguments (never raises).
- `metrics.py`: Prometheus counters derived from audit records.
- `alerts.py`: batched webhook delivery on a background thread, fed by `AuditLog.listeners`.
- `upstream.py`: `Upstream` (stdio, with stderr capture) and `HttpUpstream` (JSON or SSE,
  session renewal, bearer token).
- `detect.py`: `Engine` (built-in detectors, custom rules, plugins, suppressions,
  severity overrides), `PinStore`, `SessionTaint`.
- `policy.py`: rules (first match wins, optional `args` globs), rate limits, budgets.
- `config.py`: TOML loading and validation (raises `ConfigError`); holds `DEFAULT_CONFIG`.
- `audit.py`: hash-chained log with rotation, crash recovery and `ChainVerifier`. Writes hold
  a cross-process lock (`<log>.lock`) and re-read the chain head, so several gateways can share
  one log.
- `dashboard.py` + `dashboard.html`: the local UI. It reads only files the gateway writes.
- `approvals.py` (`Verdict` with optional remember window), `anomaly.py`, `report.py`, `cli.py`.
- Requests carry a `Caller(client, session)`; stdio is `Caller("stdio", "stdio")`.

## Rules for changes
- Never write to stdout from the gateway process: stdout carries the MCP protocol.
  Diagnostics go through `logging` (stderr or a file).
- Fail closed: unanswered approvals are denied, and invalid reloads keep the old config.
- Every security decision is written to the audit log. Never log argument or result
  contents (hashes only), and pass upstream text through `Gateway._safe` first.
- In monitor mode, log `call.would_block` and never block.
- Keep it working on Windows: no POSIX-only APIs without a fallback.
- Add a regression test with every fix. Shared fixtures are in `tests/conftest.py`.

## Checks
`pip install -e ".[dev]"`, then `python scripts/check.py`. It must report "All checks passed." Before a release, also run `HYPOTHESIS_PROFILE=campaign pytest tests/test_properties.py`.
When a property test finds a bug, keep the falsifying input as a regular regression test.

## Possible next steps
- OAuth discovery and sign-in for remote upstream servers.
- Anchor the audit head hash externally, for example on a schedule to a remote store.
- Grants scoped to argument patterns rather than the whole tool.
