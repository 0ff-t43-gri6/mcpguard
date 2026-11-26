# Operating mcpguard

For whoever is on call for a running gateway.

## Daily and weekly

| When | Do | Why |
|---|---|---|
| Daily | Look at alerts (webhook) or `mcpguard stats --hours 24` | Blocks and quarantines are either attacks or false alarms; both need an answer |
| Weekly | `mcpguard verify --checkpoints <file>` | Detects edits, deletions and truncation of the audit log |
| Weekly | `mcpguard export --format cef --hours 168 -o week.cef` (or ship continuously) | Gets the record into your SIEM, off the machine |
| Monthly | `mcpguard report -o report.md` | Compliance evidence |
| Weekly | `mcpguard advisories` (or the dashboard's Threat coverage view) | Shows servers matching known campaigns or CVEs, and protections that are off |
| Before opening a cloned project | `mcpguard audit-configs <folder>` | Poisoned AI-tool config files run commands when an editor opens them |
| On every config change | `mcpguard check && mcpguard selftest` | An edit must not quietly switch protection off |

Set `[audit] checkpoint_path` to a different disk or share. A hash chain alone cannot show
that the newest records were deleted; checkpoints can.

## What the events mean and what to do

| Event | Meaning | Action |
|---|---|---|
| `call.blocked` | A call or its result was stopped | Read `reason` and `findings`. `mcpguard explain <server>/<tool>` shows the rule. If it is a false alarm, add a policy rule or a severity override rather than switching the detector off |
| `tool.quarantined` (also `prompt.`, `resource.`) | A definition failed the checks when the server was listed | Do not un-quarantine by habit. `mcpguard scan --all`, read the definition, ask where the server came from |
| `tools.findings` with `rug_pull.changed` | A trusted definition changed (possible rug pull) | Compare with the vendor's release notes; `mcpguard pins forget <server>/<tool>` only after review |
| `server.start` with `env_withheld` | Credential-looking variables were not passed to that server | If the server needs one, add it to that server's `pass_env` |
| `server.refused` | A server matched a known malicious campaign and was not started | Remove it from the config; rotate anything it had access to if it ran before |
| `server.advisory` | A server has a published CVE, or its launch command is risky or unpinned | `mcpguard advisories -v` shows the fix version |
| `server.exited` / `server.failed` | A tool server stopped; it is restarted with backoff | Check the server's own logs; `/readyz` shows which are down |
| `call.failed` / `call.upstream_error` | The server returned an error or did not answer | Usually the server's problem, not a security event |
| `http.unauthorized` | A request with a missing or wrong token | Repeated from one source: someone is guessing; check the proxy's logs |
| `config.reload_failed` | An edit was invalid; the previous config is still active | `mcpguard check` names the key |
| `audit.recovered` | A torn or damaged log tail was set aside at start | Run `mcpguard verify`; if it fails, treat as an incident (below) |
| `call.approval` | A person allowed or denied a call | Review who approves what; at most 20 requests wait at once |

Finding rules are listed, with scope and severity, by `mcpguard checks`.

## Sending the audit log to a SIEM

```sh
mcpguard export --format cef --hours 1      # ArcSight CEF: Splunk, QRadar, Sentinel
mcpguard export --format jsonl --hours 1    # one JSON object per line
mcpguard export --format csv -o audit.csv   # for a spreadsheet; formula characters are defused
```

Run it from cron or a timer, or tail `mcpguard-audit.jsonl` directly with your log shipper:
it is append-only JSON lines and rotates by size. The log never contains arguments, results,
secrets or personal data, only hashes, tool names, findings and reasons.

## Incident: suspected compromise or failed verify

1. **Preserve.** Copy the audit files and the checkpoint file before anything else.
2. **Contain.** Disable the server in the config (`enabled = false`); the gateway reloads and
   stops it. To stop everything, set `[policy] default = "deny"`.
3. **Establish what happened.** `mcpguard verify` says where the chain breaks.
   `mcpguard export --format jsonl` around that time shows calls, blocks and approvals.
   `env_withheld` on `server.start` shows which credentials that server could not have read.
4. **Rotate** any credential in the affected server's `env` or `pass_env`, and client tokens
   if the HTTP endpoint was involved.
5. **Restart clean.** `mcpguard audit-new --reason "..."` archives the log and starts a new
   chain. `mcpguard pins reset` only if you have re-reviewed every server.

## Tuning false alarms

- Start in monitor mode; it shows what enforce would do.
- Lower one rule, not the whole detector: `[detectors.severity_overrides] "rule.name" = "low"`.
- The classifier warns at "medium" and blocks at "high". Adjust with `[detectors.model]
  medium` / `high`, or `enabled = false`.
- Allow a specific tool past policy with an `allow` rule placed before the general ones.
- `mcpguard test "text"` shows what each detector makes of a sample.

## Capacity

One gateway process serves one stdio client, or many HTTP clients. Scanning costs a few
milliseconds per call for ordinary results and up to about two seconds for a 1 MB result
(the size cap). The audit log grows by roughly 300-500 bytes per call and rotates at
`rotate_bytes`. Rate limits (`rate_limit_per_minute`, `max_calls_per_session`) are per tool
and per session.
