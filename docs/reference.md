# mcpguard: full reference

Every feature, setting and command in detail. The short version is in the [README](../README.md).

A security gateway for the Model Context Protocol (MCP): it pins tool definitions, scans for prompt
injection, stops secrets leaving through tools, flags risky tool sequences and keeps a tamper-evident
audit log.

> **Status: release candidate (1.0.0rc1).** It has not had an independent security review.
> Treat it as one layer of defence, not a guarantee. Detection is weakest on attacks it has never
> seen; the measured numbers are under [Limits](#limits).

mcpguard is a local gateway that sits between an MCP client (Claude Desktop, Cursor,
an agent framework) and the MCP servers it uses. Every tool call, prompt and resource
read passes through it. It decides what is allowed, inspects traffic in both
directions, and keeps a tamper-evident record of what happened.

It is a single Python package with no runtime dependencies.

```
MCP client ──stdio or HTTP──▶ mcpguard ──┬──▶ local server (stdio)
                                │        ├──▶ local server (stdio)
                           dashboard     └──▶ remote server (Streamable HTTP)
                           signed audit log, alerts
```

Deploying for a team: [deployment.md](deployment.md). Running it day to day:
[docs/operations.md](operations.md). Reporting a vulnerability: [SECURITY.md](../SECURITY.md).

## Quick start

```sh
pip install -e .
mcpguard init                              # writes mcpguard.toml with comments for every setting
mcpguard claude-desktop install --take-over  # Claude Desktop now reaches its servers through the gateway
mcpguard doctor                            # checks the whole setup and says what to fix
```

`--take-over` moves the servers Claude Desktop already runs into `mcpguard.toml`
(a backup of Claude Desktop's config is kept). Without it, edit the `[servers]` section
yourself. Then fully quit Claude Desktop and open it again.

For any other MCP client, point it at the gateway in place of the servers it wraps:

```json
{
  "mcpServers": {
    "guarded": {
      "command": "mcpguard",
      "args": ["-c", "C:/path/to/mcpguard.toml", "run"]
    }
  }
}
```

Tools appear to the model as `<server>__<tool>`. The dashboard is at
<http://127.0.0.1:8765> while the gateway runs.

### Serving clients over HTTP

`mcpguard serve` accepts MCP clients over Streamable HTTP at
`http://127.0.0.1:8766/mcp`. To let several agents share one gateway, give each its
own token, then write rules for particular clients:

```toml
[clients.ci-agent]
token_env = "MCPGUARD_TOKEN_CI"      # the client sends: Authorization: Bearer <token>

[[policy.rules]]
match = "github/merge_*"
clients = ["ci-*"]
action = "deny"
```

Without any `[clients]` entries, `serve` only listens on a loopback address. It does
not terminate TLS, so put a reverse proxy in front of any other bind address.

A client can open an event stream (`GET /mcp` with `Accept: text/event-stream`) to
receive `list_changed` notifications. `/healthz` reports liveness, `/readyz` whether every server is up, and `/metrics`
serves Prometheus metrics (the dashboard serves `/metrics` too).

## What it does

### Policy

- Rules for `allow`, `deny` or `ask` per tool, prompt or resource, matched by glob.
  The first match wins.
- Rules can test argument values, for example: deny `write_file` when `path` matches `/etc/*`.
- Tools that are always denied are removed from the list the model sees.
- Rules can be limited to particular clients (`clients = ["ci-*"]`).
- Rate limits and call budgets are counted separately for each client.
- A cap on result size.
- `ask` rules pause the call until someone allows or denies it in the dashboard
  (or the terminal). A call that nobody answers is denied when the timeout ends.
- "Allow for 15 minutes" stops prompts for that client and tool until the time is up.
  It covers every argument, so use it for tools where that is acceptable.

### Risky sequences (flow rules)

Each tool can be harmless alone. Reading customer records and then sending an email is how
data leaves, and the data itself need not look sensitive. A flow rule names the two steps:

```toml
[[flows]]
name = "private-data-then-email"
after = ["crm/*", "files/read_*"]   # if one of these was used earlier in this session...
then = ["email/send_*"]             # ...a call to one of these needs a decision
within_minutes = 30                 # how far back to look (default 30)
action = "ask"                      # ask | deny
# clients = ["ci-*"]                # optional: only these clients
```

In monitor mode the sequence is recorded as "would block" and nobody is interrupted. In enforce
mode `ask` pauses the call for approval (an unanswered request is denied) and `deny` refuses it.
A stricter rule, such as a deny rule for the same tool, still wins.

What it does not do: it matches tool names, so it shows that a risky sequence happened, not that
data flowed from one step to the other (the secret and personal-data tracking in `[dlp]` covers
values it recognises). Calls that were blocked do not count as the first step. Memory is per
client session and is lost on restart. Broad patterns such as `*/*` will ask too often.

### Known incidents and CVEs

mcpguard ships a record of real MCP campaigns and vulnerabilities (20 as of November 2026, each
with sources) and checks your setup against it:

- A server named in a malicious campaign is not started; one with a published CVE is flagged.
- `mcpguard advisories` and the dashboard's **Threat coverage** view show, for every incident,
  what mcpguard does about it with your current settings and which setting would close a gap.
- `mcpguard audit-configs <folder>` reads a cloned project's MCP and AI-tool config files and
  flags commands that download or run scripts, before an editor runs them for you.

The record is a snapshot, not a live feed. See `threat-model.md` for attacks on mcpguard itself.

### Containing servers

Three settings limit what a server can do even if it turns hostile:

```toml
[policy]
ask_sensitive = true          # approval before tools that write, delete, run or send

[servers.files]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
allowed_paths = ["C:/Users/me/project"]     # path arguments must be inside
allowed_hosts = ["api.github.com"]          # URL arguments must name these hosts

[servers.files.sandbox]                     # run it in a container
image = "node:22-slim"
network = false
mounts = [{ host = "C:/Users/me/project", container = "/data", write = false }]
```

- `ask_sensitive` applies to tools that no rule names. An explicit `allow` rule is your
  decision and is not second-guessed. "Allow for 15 minutes" in the dashboard keeps it usable.
- `allowed_paths` and `allowed_hosts` check arguments; they cannot see what the server does
  on its own. The sandbox is what stops that: the container has no network unless you set
  `network = true`, a read-only filesystem, and only the mounted folders. It needs Docker or
  Podman, and an image that contains the server's runtime.
- `mcpguard check` notes servers that run unsandboxed with no `allowed_paths`.

### Detection

- **Definitions:** every tool, prompt and resource description, schema string and
  long property name is checked for hidden instructions and invisible Unicode.
  Definitions at or above `static_block_severity` are quarantined.
- **Rug pulls:** each definition is pinned by hash the first time it is seen.
  A later change quarantines it until you clear the pin.
- **Arguments:** each call is checked against the tool's own `inputSchema` (types,
  required fields, lengths, patterns, enums), and known credential formats and
  random-looking tokens are blocked before they leave.
- **Attacks in arguments:** path traversal and paths to credentials (`.ssh`, `.aws`,
  `.env`, ...), Windows network paths, shell command chaining and pipe-to-shell, SQL
  injection shapes, and SSRF (cloud metadata endpoints, loopback, private and link-local
  addresses, including decimal and hex spellings such as `http://2130706433/`, and
  `file://` or `gopher://` URLs).
- **Results:** injected instructions are withheld, including instructions hidden in
  base64, and credentials are redacted. Data that speaks to the assistant ("to you, the
  assistant", "the task I gave you"), fake chat markers (`###(system_message)`,
  `<|im_start|>`), and requests to gather information and send it to an address are
  flagged too, whatever their wording. Markdown or HTML images whose URLs carry data
  are blocked, because many clients load them without a click. Terminal escape
  sequences are flagged.
- **Catalog:** look-alike tool names (Cyrillic letters standing in for Latin), the same
  tool name offered by two servers, names one character apart (typosquatting), tools
  whose description talks about another server's tool (shadowing), and tools that
  advertise arbitrary command execution.
- **Indicators of compromise:** a bundled feed derived from public MCP attack benchmarks
  (MCP-SafetyBench, MSB, MCPSecBench and others): hashed fingerprints and fragments of known
  attack payloads, attack-only phrases, attacker hosts and injected parameters. On tools it
  has never seen, it raises detection of benchmark attacks from about 14% to 63–71%, with no
  false alarms on 967 benign tools. Brand-new attack wording is not caught. Method, results
  and sources are in [docs/iocs.md](iocs.md).
- **Measured, not claimed:** [benchmark.md](benchmark.md) scores the rules and the
  feed on five more public benchmarks they were not built from (InjecAgent, AgentDojo,
  BIPIA, ToolEmu, MCP documentation), including what is still missed. The honest result-injection
  numbers are the unseen ones: about 50% on the InjecAgent cases the rules were not written from, and
  0% on BIPIA (see Limits).
- `mcpguard checks` lists every rule with its scope and default severity.
- **Exfiltration:** a credential read by one tool is blocked if a later call tries
  to send it out through an email, HTTP or messaging tool.
- **Data leakage prevention:** payment cards, Aadhaar, IBAN, US SSN, Indian PAN, email and
  phone numbers, validated by checksum or structure. By default cards, Aadhaar and SSNs are
  masked in what tools return to the model and blocked from leaving through email/HTTP/messaging
  tools; personal data read from one tool and sent out through another is blocked. Each class and
  direction is configurable in `[dlp]`. Values are never written to the audit log.
- **Learned classifier:** a small logistic-regression model scores descriptions and results for
  injected instructions, catching plain-language requests no rule names. It warns on
  definitions and can block results; how it was trained and tested is in
  [docs/model.md](model.md).
- **Baselines:** mcpguard learns each tool's usual result size, latency and argument
  size, and records outliers. Outliers are not learned.
- **Your own rules:** add regex rules in the config, or Python plugins
  (`fn(scope, text, context) -> [{"rule", "severity", "message"}]`).
- **Tuning:** suppress a rule by name and location, change the severity of any rule,
  and try rules on sample text with `mcpguard test`.

### Operation

- **Monitor mode** records what would have been blocked without blocking anything.
  Run it for a while before you enforce. Switch with the dashboard's top-bar switch or
  `mcpguard mode enforce` (no restart, no config edit; each change is audited).
- **Live config:** changes to the config file apply while the gateway runs, including
  adding, removing or disabling servers. An invalid edit is rejected and logged, and
  the previous config stays in force.
- **Supervision:** a server that crashes or fails to start is restarted with backoff
  (1 s up to 60 s). While it is down, calls to it return a clear error rather than hanging.
- **Remote servers:** Streamable HTTP with JSON or SSE responses and bearer tokens.
  An expired session is renewed automatically. Remote URLs must use HTTPS.
- **Concurrency:** requests are handled concurrently, so a call waiting for approval
  doesn't hold up the others.
- **Cancellation:** a `notifications/cancelled` from the client is forwarded to the
  server handling the request.
- **Alerts:** blocks, quarantines, outages and log problems are posted to a webhook
  (Slack-compatible `text`, plus the raw records). Events in a short window are sent
  as one message.
- **Shutdown:** SIGTERM or Ctrl+C saves state and stops servers cleanly.
- **Server isolation:** upstream servers cannot call back into the model. Sampling and
  similar requests are refused.

### Audit

- Every decision is written to a hash-chained JSON Lines log. `mcpguard verify` detects
  edited, deleted or reordered records.
- Records are signed with HMAC-SHA256 using a key in `mcpguard-audit.key`, which is
  created on first run (or set `MCPGUARD_AUDIT_KEY`). Without the key, someone who can
  edit the file could rebuild the whole hash chain. With it, forged records and
  downgrades to unsigned records are detected. Keep the key away from the log if you
  can, for example only in the environment.
- The log rotates by size, and the chain continues across segments.
- **Checkpoints** catch deleted records at the end of the log, which a chain alone can't
  reveal. Set `[audit] checkpoint_path` to a file on another disk, and the gateway records
  the head there hourly and on shutdown. `mcpguard verify` then confirms every checkpointed
  record is still present and unchanged. `mcpguard checkpoint` takes one by hand.
- If the process dies mid-write, the incomplete record is set aside on the next
  start and the recovery is itself logged.
- Several gateway processes can share one log (Claude Desktop may start the gateway more
  than once). Writes take a file lock and continue the chain from its real end, so the
  processes never fork it.
- Arguments and results are recorded as hashes, never as contents. Error messages
  from servers are redacted before they are written.
- `mcpguard report` writes a summary with evidence for each control, as Markdown, as a PDF (`-o report.pdf`) or, with a `.html` name or `--format html`, as one self-contained web page.

## Policy tests

Keep expected decisions next to your config and check them in CI:

```toml
[[case]]
name = "CI agent cannot merge"
call = "github/merge_pull_request"
client = "ci-agent"
expect = "deny"
visible = false                       # optional: hidden from that client's tool list

[[case]]
call = "files/write_file"
args = { path = "/etc/hosts" }
expect = "deny"
expect_findings = []                  # optional: detector rules that must fire
```

## Commands

| Command | Purpose |
|---|---|
| `mcpguard init [--profile balanced\|strict\|monitor]` | Write a starter config |
| `mcpguard advisories [-v] [--json]` | Known MCP incidents and CVEs, and whether this setup stops each one; exits 2 if a configured server matches one |
| `mcpguard audit-configs [folder]` | Check a project's MCP and AI-tool config files before opening it in an editor |
| `mcpguard trust [--forget]` | Trust the config in the current folder. Needed once for a config that starts servers or loads plugins, unless you name it with `-c` or created it with `init` |
| `mcpguard selftest` | Run known attacks and ordinary text through this install and config; exits 2 if protection is not working |
| `mcpguard export --format jsonl\|csv\|cef [--hours N] [-o file]` | Export the audit log for a SIEM or spreadsheet |
| `mcpguard check` | Validate the config and summarise servers and rules; warns about unknown keys (typos) |
| `mcpguard doctor` | Check Python, the config, each server's command, approvals, the dashboard port, the audit log and Claude Desktop |
| `mcpguard claude-desktop install [--take-over] \| status \| uninstall` | Connect the gateway to Claude Desktop, with a backup; `--take-over` moves existing servers behind it |
| `mcpguard stats [--hours N]` | Calls, blocks, approvals and findings from the audit log, in the terminal |
| `mcpguard run` | Run the gateway on stdio (this is what your MCP client starts) |
| `mcpguard serve` | Run the gateway for MCP clients over HTTP |
| `mcpguard policy-test cases.toml` | Check rules against expected decisions; exits 1 on any failure |
| `mcpguard explain srv/tool --args '{...}' --client ci` | Show which rule decides a call and what the detectors make of it |
| `mcpguard scan -- <command>` / `--url URL` / `--all` | Inspect one server's definitions, or every configured server together with the cross-server checks; exits 2 on high or critical findings |
| `mcpguard test "text"` | Run the detectors on sample text |
| `mcpguard checks` | List every detection rule, its scope and severity |
| `mcpguard iocs [show \| build \| eval]` | Show the IOC feed, build one from a labelled corpus, or measure it |
| `mcpguard dashboard` | Run the dashboard without the gateway |
| `mcpguard verify [--checkpoints file]` | Check the audit log (and checkpoints); exits 3 if it has been tampered with |
| `mcpguard checkpoint [-o file]` | Record the current audit head outside the log |
| `mcpguard audit-new [--reason text]` | Move the log to `audit-archive/<time>/` and start a fresh one (after a failed verify) |
| `mcpguard report -o report.md` | Write the compliance report (`report.html` for a web page) |
| `mcpguard pins list \| forget srv/tool \| reset` | Manage trusted definitions |
| `mcpguard baseline show \| reset` | Inspect or clear learned baselines |

## Files

All paths are relative to the config file and can be changed in it.

| File | Contents |
|---|---|
| `mcpguard-audit.jsonl` | Audit log (plus rotated segments) |
| `mcpguard-audit.key` | Audit signing key (owner-only permissions) |
| `mcpguard-pins.json` | Trusted definition hashes |
| `mcpguard-baseline.json` | Learned per-tool baselines |
| `mcpguard-state.json` | Server health and tool inventory for the dashboard |
| `mcpguard-approvals/` | Pending approval requests and the dashboard token |

## Limits

**Detection**

- Detection is pattern matching and statistics. It makes common attacks harder and will miss
  others, so use it as one layer of protection. A request that reads like something a user would
  ask ("please unlock my front door") looks harmless inside data and is not caught. The measured
  gaps are in [benchmark.md](benchmark.md).
- The rules for injected instructions in results may be overfitted. On InjecAgent they catch 96.9%
  of the cases that were looked at while writing the rules, and 51.7% of the 1,020 that were not.
  On AgentDojo the two parts are about even (80% and 82%). On BIPIA they catch none. For attacks
  you have not seen before, 50% is the figure to expect, not the higher headline numbers.
- Schema checking follows `$ref` that points inside the same schema (`#/$defs/name`). It does not
  fetch other documents, and it ignores any keyword it does not know instead of guessing.

**Rules and trust**

- Flow rules match tool names. They show that a risky sequence happened, not that data moved from
  one step to the next. Their memory is per client session. It is saved to `mcpguard-flows.json`
  next to the state file, so a restart does not clear it, but a new client session starts empty.
- By default, pinning trusts a definition the first time it sees it and logs that it did. To hold
  new definitions until you approve them, set `[pins] first_seen = "approve"` (the strict profile
  does this), then use `mcpguard pins pending` and `mcpguard pins approve <server>`. Run
  `mcpguard scan` on a new server before you add it.
- A config found in the current folder is not loaded until you run `mcpguard trust` there, because
  a config can start programs. Read a downloaded project's config with `mcpguard audit-configs .`
  first.

**Servers**

- Without a sandbox, a local server runs as you and can read anything your account can.
  `allowed_paths` only checks the arguments of calls. When it is set, any text argument that
  starts like an absolute path is treated as a path.
- Servers do not inherit mcpguard's own secrets, or any variable that looks like a credential. If
  a server needs one from the environment, list it in that server's `pass_env` (for example
  `pass_env = ["GITHUB_TOKEN"]`) or set it in its `env`.
- Remote servers that need an interactive OAuth sign-in are not supported. Use a bearer token.

**Audit log**

- Nothing can stop someone with full control of a machine from deleting files on it, so the log
  is protected in layers:
  - While running, the gateway notices if records it wrote are deleted, cut short or changed. It
    raises an alert and, by default, refuses tool calls until you have looked into it.
  - The newest hash is copied to a signed checkpoint file outside the project folder, so
    `mcpguard verify` also catches deleted records at the end of the log.
  - For a copy an attacker on your machine cannot reach, set `[audit] forward_url` (each record is
    sent as it is written) or `witness_url`.
  - `mcpguard audit-protect` adds the operating system's append-only flag where there is one.
  See [deployment.md](deployment.md).

**Windows**

- Terminal approvals need a console window. When the client starts the gateway in the background
  there is none, so the request goes to the dashboard if it is enabled, and is denied if not.

Attacks on mcpguard itself that were tried, and what happened, are in
[threat-model.md](threat-model.md).

## Development

```sh
pip install -e ".[dev]"
python scripts/check.py          # everything below, with a summary
python scripts/check.py --full   # plus a clean-install package check, the property campaign and a dependency audit
pre-commit install               # optional: run the fast checks on every commit
```

`scripts/check.py` runs:

| Check | Tool | Gate |
|---|---|---|
| Lint, including security and pytest rules | ruff | no findings |
| Types (`check_untyped_defs`, unreachable code) | mypy | no errors |
| Security lint | bandit | no findings |
| Dead code | vulture | nothing unused outside `scripts/vulture_whitelist.py` |
| Tests, with branch coverage | pytest, pytest-cov | all pass, coverage at least 88% |
| Property campaign (`--full`) | Hypothesis | 1,500 generated cases per property |
| Known vulnerabilities in dev dependencies (`--full`) | pip-audit | none |

CI (`.github/workflows/ci.yml`) runs the checks on Linux, Windows and macOS with
Python 3.11 and 3.13, plus a `--full` job.
