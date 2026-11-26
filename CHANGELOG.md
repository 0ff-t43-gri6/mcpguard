# Changelog

## 1.0.0rc1

First public release candidate. Earlier entries below (0.1.0 to 1.0.0rc4) are internal builds that were
never published; the numbers are kept as history.

- Detection: injections written as polite requests ("could you please disregard what you were told before ...")
  and requests to send keys, passwords or credentials to an address are now rated high (unless negated, as in
  "never send your password to ..."). Benchmark: no new false alarms; InjecAgent unseen part 50.0% to 51.7%.
- Pentest of the whole folder (100 cycles, docs/pentest-2026-11-25-repo-audit.md). Fixed: terminal escape
  sequences from a server could reach the terminal through `stats` and the Markdown report; a config nested
  thousands of levels deep crashed instead of giving a config error; sandbox mount paths accepted control
  characters; full-width look-alikes of `file:` and `/` slipped past the folder guard. CI now has explicit
  read-only permissions, `build/` and `dist/` are ignored, and Dependabot is set up for the workflows.
- New flow rules (`[[flows]]`): name a risky sequence of tools, for example reading customer records and
  then sending email, and the second step is asked about or denied when the first was used earlier in the
  same session. Monitor mode only records it (`flow.chained`). Matching is by tool name, memory is bounded
  and per client session. Without `[[flows]]` nothing changes.
- Fixes found by a round of tests on the dashboard: two simultaneous mode clicks could collide on the same
  temporary file, a request with no Host header is refused, and the dashboard queues up to 128 connections.
- `pins pending` now lists definitions that changed, not only new ones. New `pins diff <server>` shows
  the old and new text, and `pins approve` accepts a changed definition you have read. Before this the
  only way out of a quarantine was `pins reset`. A readable copy of each definition is kept beside the pins.
- `stats` starts with what is true right now (gateway running, tools quarantined now, what to do) and
  labels the quarantine list from the log as history.
- `doctor` checks for a running gateway and for pin changes waiting for review.
- New `mcpguard setup [--claude-desktop]`: config in monitor mode, trust, health check, next steps.
- New `mcpguard open` and a double-click `mcpguard-dashboard.bat`: open the dashboard in the browser, starting it if it is not running.
- Monitor and enforce can be switched while the gateway runs: a switch in the dashboard's top bar (confirms before going down to monitor) and `mcpguard mode [monitor|enforce|config]`. The choice is a small file in the approvals folder, so the config is not edited and needs no `trust`; gateways apply it within 2 seconds, and each change is audited as `mode.changed`.
- `mcpguard report -o report.pdf` writes a PDF styled like the dashboard (dark header with the arch mark and a log-integrity badge, summary cards, severity chips, tables with repeating headers, page numbers; no new dependency).
- Pentest of the new code (`docs/pentest-2026-11-24-new-features.md`): a long unbroken value made the PDF quadratic; damaged pin side files and state files crashed `pins`, `stats` and `doctor`; the side files were unbounded; `setup` trusted an existing config that starts programs. All fixed.
- The harmless Windows "I/O operation on closed pipe" traceback is no longer printed after commands.

### Fixed (pentest rounds 3 to 7: `docs/pentest-2026-11-20-rounds-3-7.md`, threat model T87 to T97)
- **A hostile tool schema could freeze the whole gateway.** A `pattern` such as `^(a+)+$` took 10 s on 28
  characters, and Python cannot interrupt a regex. Patterns that can backtrack badly are no longer evaluated.
- A renamed approvals folder (`[approvals] dir`) was not protected, so a tool could read the dashboard token
  and approve its own `ask` calls. It is now one of the gateway's own paths.
- The remote-server client (`url = ...`) had its own copy of the `http://localhost.evil.com` prefix bug, no limit
  on how much a server may send, no overall deadline on an event stream, and failed on bytes that are not UTF-8.
- Dashboard: a string such as `"false"` counted as approval; idle clients held threads for ever.
- Alerts escape chat markup (`<!channel>`, `<url|label>`); the console prompt cannot be spoofed by a tool name.
- A deeply nested pins, baseline, grants, state or IOC-feed file no longer stops start-up.
- Injection written in the `uri` or `mimeType` of a result is read; `audit-protect` ends options with `--`.

### Fixed (second self-penetration test, 52 cycles: `docs/pentest-2026-11-20-round2.md`, threat model T72 to T86)
- **Own-file protection could be walked around.** Percent-encoded, full-width, zero-width, look-alike-letter,
  8.3 short-name and wildcard spellings of `mcpguard.toml` and friends are now recognised; so is the name as a dict
  key (batch-write tools); and deleting, moving or overwriting the folder that holds them is refused.
- **`http://localhost.evil.com` passed as "localhost".** `forward_url`, `witness_url`, `alert_url` and a server
  `url` now check the host, not the start of the text.
- **Moving or copying a project folder no longer makes a second audit key silently.** The default key path comes
  from the log's path, so a moved project got a new key and every old record then failed `verify`. The gateway now
  refuses to start (with the fix) when the log holds signed records and the key is missing.
- Instructions in tool results hidden as HTML entities, base32, base85, ascii85, quoted-printable or line-wrapped
  or URL-safe base64 are found.
- A tool server that wrote one line over 16 MB used to leave every request waiting; it is now stopped and the
  requests fail at once.
- Columns of numbers and CSV were read as card numbers (false blocks and corrupted redactions); card numbers must
  now be in even groups or the American Express / Diners layout.
- Smaller: a planted segment-named copy no longer excuses cut records; negative `checkpoint_minutes` or
  `rotate_bytes` is an error; the keys folder is created 0700; a deeply nested trust file no longer crashes the
  start and is written atomically; bidi controls are escaped in exports; two `Host` or `Content-Length` headers
  are refused; `*_SK` environment variables are withheld.

### Fixed (self-penetration test, 37 cycles: `docs/pentest-2026-11-20.md`, threat model T58 to T71)
- **A running gateway no longer reloads a config you have not trusted.** Editing `mcpguard.toml` while the
  gateway runs (by a files tool, an injected agent or any program) used to change its mode, rules and servers,
  and a new `[servers.x]` block was started. A changed config is now reloaded only after `mcpguard trust`
  records its exact contents; until then the old settings stay and `config.reload_refused` is logged. The file
  is read once, so what is checked is what is loaded.
- Tools can no longer read or change mcpguard's own files (config, audit log and key, pins, approvals, trust
  record): `[policy] protect_own_files`, on by default.
- Unknown keys and sections in the config are an error that names the typo, not a warning.
- The runtime log guard no longer accepts a planted `*.backup.jsonl` (or a file in `audit-archive/` without a
  real `audit-new`) as proof that records moved. New audit logs are owner-only on POSIX.
- The audit key defaults to `~/.mcpguard/keys/` instead of the project folder (an existing key beside the log
  keeps being used; `doctor` warns about it). Checkpoints default to every 5 minutes. The forwarding cursor
  is signed.
- Secrets and card numbers leaving in disguise are caught more often: spaced, hyphenated, lower-cased,
  HTML-entity, octal and gzip+base64 forms, card numbers among invisible characters or markup, and a secret seen
  again after it was first blocked (coverage used to saturate). Half a value in one call is flagged.
- Instructions in results are caught in ROT13, hex, reversed text, nine more languages, split letters, JSON
  tasks, mimicked tool calls and image URLs with a data placeholder.
- Smaller: `%2e%2e/` paths, Windows device names and symlinks leaving an allowed folder are refused; more
  credential variable names are withheld from servers; pins cover `title`, `outputSchema`, `_meta`, `icons`
  and `execution`; the HTTP endpoint refuses a non-loopback `Host` on loopback and warns when no tokens are
  set; exports show control characters as `\xNN`.

### Added (audit log protection)
- The running gateway checks that the records it wrote are still in the log exactly as written (deleted,
  truncated, replaced or edited files are caught), alerts, and by default refuses tool calls until
  `mcpguard audit-new` (`[audit] on_tamper = "block" | "warn"`). It also re-verifies the whole chain and the
  checkpoints every `verify_minutes` (default 30).
- `[audit] forward_url` sends every record to a server you control as it is written, with retry, a saved
  cursor and catch-up after outages and restarts.
- `mcpguard audit-protect` / `audit-unprotect` set the operating-system append-only flag (Linux `chattr +a`,
  macOS `chflags uappnd`). The gateway and `audit-new` cope with a protected log.
- Fixed: a truncated log used to be silently continued by the running gateway (threat model T57).

### Added (security)
- `[pins] first_seen = "approve"` holds every new tool definition until you read it
  (`mcpguard pins pending`) and run `mcpguard pins approve <server>`. The strict profile turns it on.
  In the default `allow` mode, what was trusted on sight is written to the audit log (`pins.first_seen`).
- Audit log head checkpoints are now on by default, signed, in the mcpguard home folder (outside the project
  folder). `[audit] witness_url` also sends each checkpoint to a server you control. `mcpguard doctor` warns
  when no outside copy is kept, `verify` says so, and `audit-new` moves the old checkpoints with the old log.

### Fixed (found by `scripts/cycles.py`, 127 entry/exit cycles)
- A damaged, non-UTF-8 or non-JSON line in the audit log no longer crashes `verify`, `stats`, `report`, `export`
  or `doctor`: `verify` reports it as damage, the others skip the line.
- `audit-new` run twice in one second no longer fails; an audit or pins path that is a folder is a config error.
- `mcpguard serve` on a port that is already in use now stops the tool servers it had started, instead of
  leaving them running as orphaned processes (on Windows this also printed a closed-pipe traceback).
- A non-UTF-8 message on stdin gets a JSON-RPC parse error instead of a traceback.
- The gateway shuts down cleanly when the client closes its output, and exits 0 (not an abort) on SIGTERM.
- `| head` and other closed pipes no longer print `BrokenPipeError`; any other unexpected error is one line
  (`MCPGUARD_DEBUG=1` shows the traceback).

### Changed (security)
- Trust for a `mcpguard.toml` found in the current folder is now tied to the file's contents. A trusted config
  that changes (for example after `git pull`) must be trusted again. Existing trust entries must be renewed once.

### Changed
- The dashboard uses the same dark design as the project site and report (lime accent, softer corners). It always
  uses the dark theme now, and still makes no outside requests: fonts come from the system.
- `mcpguard selftest` no longer refuses to run when the config in the folder is untrusted. It runs on
  built-in defaults, loads nothing from that config, and says so. Other commands still require `mcpguard trust`.
- Tests now run from an empty folder, so a `mcpguard.toml` made by `mcpguard init` in the repo no longer breaks them.

### Added
- `python -m mcpguard ...` now works (a `__main__.py` was missing), as an alternative to the `mcpguard` command.
- `mcpguard report` can write one self-contained HTML page (`-o report.html`, or `--format html`),
  styled to match the project site and print-friendly. It makes no outside requests. The
  Markdown report is unchanged and stays the default.
- `site/`: a one-page project website (static HTML). Open `site/index.html` through any local web
  server; it loads Google Fonts when online and falls back to system fonts when not.

## Internal build 1.0.0rc4 (not published)
27 more threat-modelling cycles (T28-T54), aimed at the entry points: what servers send in,
what leaves in arguments, client requests, config files and exports. 21 attacks worked and are
fixed, 6 held. See [docs/threat-model.md](docs/threat-model.md).

### Security
- **A config found in the current folder is not loaded until trusted** when it starts servers
  or loads plugins. Before this, running `mcpguard check` or `doctor` inside a cloned project
  ran whatever its `mcpguard.toml` named. **Behaviour change:** run `mcpguard trust` once in
  the folder of an existing config; `-c`, `MCPGUARD_CONFIG` and `mcpguard init` need nothing.
- Results are scanned in every text field (titles, descriptions, annotations, `_meta`, text
  inside base64 blobs), and so are error messages and resource-template descriptions.
- mcpguard's own "withheld" notice no longer quotes the offending text to the model.
- Leak tracking recognises eight more encodings, covers resource URIs the model builds, and
  checks every call for credentials going to a different server than they came from.
- `allowed_hosts` and `allowed_paths` were rewritten against 54 bypass forms.
- Known-bad packages are recognised behind wrappers; `audit-configs` reads JSON with comments,
  UTF-16, TOML and more editors' layouts, and treats what it cannot parse as high.
- At most 2,000 catalog entries per server; arguments over 4,000,000 characters are refused;
  malformed client messages and tool names get errors instead of raising.
- Connection URLs with passwords are withheld from servers' environments.

### Fixed
- CSV export wrote `'` into every empty cell.
- `ask_sensitive` asked for tools such as `get_commit` and `show_command_help`.

## Internal build 1.0.0rc3 (not published)
Real incidents and CVEs, built in. Twenty MCP campaigns and vulnerabilities from 2025-2026,
each checked against its sources, are recorded in `data/advisories.json` and used three ways.

### Added
- **Servers are checked against known campaigns and CVEs.** A server whose package, address or
  self-reported name appears in a malicious campaign (postmark-mcp, the fake Oura repositories,
  Deadbugz's "productivity-suite") is not started. A version with a published CVE (mcp-remote,
  MCP Inspector, Terraform MCP, Dolt MCP, ContextForge) is flagged at start and in `mcpguard check`.
- **Launch commands are audited:** shells with inline commands, downloaders, inline code, and
  packages fetched without a pinned version.
- **`mcpguard audit-configs <folder>`** reads the MCP and AI-tool config files in a project
  (`.mcp.json`, `.cursor/`, `.vscode/`, `.claude/settings.json` hooks, ...) before you open it,
  the files the Miasma worm and Cursor's MCPoison flaw abused. Exits 2 on risky commands.
- **`mcpguard advisories`** and a **Threat coverage view in the dashboard**: every recorded
  incident with what mcpguard does about it under the current config (stops it, limits the
  damage, warns, needs a setting, affects one of your servers, or outside a gateway's reach),
  which protections are on, and the sources.
- Regression tests that replay Deadbugz (descriptions that turn after three calls) and the Dolt
  MCP bypass (a rejected request must run nothing) against the gateway.

### Fixed
- A server result with the wrong shape (a number where a list belongs) raised an error in the
  scanner (T27, found by the property-test campaign).

### Honest limits
- The feed is a snapshot dated 2026-11-16; it does not update itself.
- "Stops it" describes the attack technique. A vulnerable product you run elsewhere (Langflow,
  nginx-ui, an IDE) still needs its own patch.
- A package that turns malicious in an update (postmark-mcp) is only caught by name after it is
  known. Before that, pinned versions and a sandbox are what limit it.

## Internal build 1.0.0rc2 (not published)
Three standard MCP hardening measures, built in.

### Added
- **Sandboxing:** `[servers.<name>.sandbox]` runs a local server inside a Docker or Podman
  container: no network unless asked, read-only filesystem, no capabilities, and only the
  folders listed in `mounts`. The command line is built and tested; it has not been run
  against a container runtime in this project's checks.
- **Least privilege:** per-server `allowed_paths` and `allowed_hosts`. A call whose path
  argument lies outside the folders (including via `..`, `~`, `file://` or a look-alike sibling
  folder), or whose URL argument names another host, is refused.
- **Human in the loop:** `[policy] ask_sensitive = true` asks for approval before any tool that
  no rule names and whose name says it writes, deletes, runs or sends, or that the server marks
  destructive. On in the `strict` profile.
- `mcpguard check` points out wide-open settings: approvals granted automatically, every tool
  allowed without approval, and local servers running unsandboxed with no `allowed_paths`.

## Internal build 1.0.0rc1 (not published)
Release candidate: everything needed to deploy and operate mcpguard for a team. It is a
candidate, not 1.0, until it has run in monitor mode on real traffic and a licence is chosen.

### Added
- `mcpguard selftest`: runs known attacks and ordinary text through the installed config and
  exits non-zero if an attack gets through or ordinary text is stopped. For acceptance checks
  and deployment pipelines; the systemd unit runs it before every start.
- `mcpguard export --format jsonl|csv|cef`: the audit log for SIEMs and spreadsheets.
- `/readyz` on the HTTP endpoint: 200 when every configured server is up, else 503.
- `mcpguard init --profile balanced|strict|monitor`.
- Deployment: `Dockerfile`, `deploy/docker-compose.yml`, `deploy/mcpguard.service`,
  [docs/deployment.md](docs/deployment.md), [docs/operations.md](docs/operations.md),
  `SECURITY.md`, `CONTRIBUTING.md`, a tag-driven release workflow, and a clean-install package
  check in `scripts/check.py --full`.

### Detection
- **Classifier retrained** on three more public attack sets (in-the-wild jailbreaks, Tensor
  Trust, PurpleLlama), half of each held out. On the held-out half it blocks 83% of jailbreak
  prompts (rules alone: 10%), 88% of Tensor Trust attacks (22%) and 53% of PurpleLlama
  injections (6%), with no benign test text blocked. See [docs/model.md](docs/model.md).
  Text is de-obfuscated before the classifier scores it.
- Card and ID numbers sent out in pieces, in one call or across several, are caught (T26).

### Fixed
- Servers lost harmless variables whose names contain SESSION (for example
  `DBUS_SESSION_BUS_ADDRESS`); only `SESSION_ID`, `_KEY`, `_TOKEN` and `_SECRET` are withheld now.

## 0.12.0

Closes the three limits left open in 0.11.0 (cycles 59-61, threats T23-T25 in
[docs/threat-model.md](docs/threat-model.md)).

### Security
- **Servers no longer inherit credentials from the environment.** Variables whose name
  (TOKEN, SECRET, PASSWORD, API_KEY, ...) or value (a recognised key format) looks like a
  credential are withheld. **Behaviour change:** a server that relied on inheriting one needs
  `pass_env = ["NAME"]` (globs allowed) or the value in its own `env`. Withheld names are listed
  in the `server.start` audit record and in the gateway log.
- Taint tracking catches secrets sent reversed, broken up with separators, or split across
  several calls in any order (flagged once 60% has left).
- De-obfuscation also handles zero-width and other invisible characters, hidden Unicode tag
  text, accents, small capitals, 500+ Unicode lookalike letters (UTS #39 confusables, from the
  MIT-licensed confusable_homoglyphs data) and leetspeak.

## 0.11.0

22 threat-modelling cycles against mcpguard itself (cycles 37-58); see
[docs/threat-model.md](docs/threat-model.md). 15 attacks worked and are fixed, 7 held.

### Security
- Servers no longer inherit mcpguard's own secrets: the audit key, HTTP client tokens, the
  alert webhook and other servers' bearer tokens are withheld from every server process.
- A request nested too deeply to parse no longer stops the gateway.
- Tool and argument rules ignore letter case; paths are normalised before matching.
- Deeply nested arguments are refused and over-deep results withheld; a hostile response fails
  only its own call.
- Scanning and delivery stop at 1,000,000 characters per result.
- Control characters in tool names quarantine the tool; mcpguard prints names escaped.
- Taint tracking recognises base64 and hex forms of secrets; card numbers with dots,
  underscores or slashes are recognised.
- Injections hidden with lookalike letters, full-width or spaced-out text are caught
  (`injection.obfuscated`).
- At most 20 approval requests wait at once; approval files and logged server errors are
  masked for personal data; notification floods write one audit record per refresh.

## 0.10.0

Cycles 29-35 in [docs/devlog.md](docs/devlog.md).

### Added
- **Data leakage prevention** (`[dlp]`): payment cards (Luhn), Aadhaar (Verhoeff), IBAN
  (mod-97), US SSN, Indian PAN, email and phone, validated so random numbers do not count.
  Per class and direction: results to the model `allow / log / redact` (masked, last 4 kept),
  arguments to email/HTTP/messaging tools `allow / log / block`. Defaults redact cards, Aadhaar
  and SSN in results and block them going out. Personal data read from one tool and sent out
  through another is blocked. Values never reach the audit log.
- **Learned injection classifier** (`[detectors.model]`, `ml.injection`): logistic regression in
  plain Python, trained by `scripts/train_model.py` with a train / threshold / test split. On the
  test split it adds 35.7% warnings and 5.5% blocks on plain-request injections the rules miss,
  with no alarms on 1,065 benign results. On tool definitions it only warns. See
  [docs/model.md](docs/model.md).
- `mcpguard test` shows personal data with the action per direction, and the classifier score.

### Fixed
- Rule messages quoted matched text, so a card number or ID in a tool call could be copied
  into the audit log. All finding messages are scrubbed.

## 0.9.0

28 development cycles; each one is listed with what its testing found in
[docs/devlog.md](docs/devlog.md).

### Added
- `mcpguard claude-desktop install [--take-over] | status | uninstall`: connects the gateway to
  Claude Desktop with a backup and an atomic write; repairs a snippet pasted below the existing
  JSON; `--take-over` moves existing servers behind the gateway (renaming names mcpguard cannot
  use, commenting out the `init` example) and rolls back if the config would break.
- `mcpguard doctor`: Python, config (including unknown keys), each server's command, approvals that
  could never be answered, monitor mode, the dashboard port, the audit log and key, and whether
  Claude Desktop's entry points at a Python that can import mcpguard.
- `mcpguard audit-new` archives the log into `audit-archive/<time>/` and starts a new one;
  `mcpguard verify` recognises a forked chain and says so.
- `mcpguard scan --all`: every configured server together, with the cross-server checks.
- `mcpguard stats`: calls, blocks, approvals and findings from the log, in the terminal.
- `mcpguard test` checks definition, argument and result scope at once and labels each finding.
- `injection.risky_request` (results, medium): requests to move money, grant access, unlock or
  disarm, wipe data or change credentials.
- Unknown config sections and keys are reported with a "did you mean" suggestion.
- Starter policy asks before move/remove/drop/purge tools and denies writes into `C:\Windows`.

### Fixed
- **ReDoS:** 10 of 58 detection regexes were quadratic on crafted input, so one malicious result
  of a few tens of KB could freeze the gateway. All are linear now and a test guards it.
- **Several gateways on one config** (Claude Desktop can start two):
  - on a fresh install the second crashed creating the audit key (or read it, or the dashboard
    token, half-written);
  - the dashboard showed whichever process wrote last and "stopped" when one exited;
  - "Allow for 15 minutes" covered only one process;
  - pins and baselines overwrote each other.
- `mcpguard pins forget` and `baseline reset` were undone by a running gateway's next save, so a
  quarantined tool could not be released without stopping Claude Desktop.
- Log rotation blocked by Windows file locking lost that call's audit record.
- `read ../../.ssh/id_rsa` was not critical (paths with dots were missed); "copy .env.example to
  .env" in setup guides was.

## 0.8.0

### Fixed
- The audit log forked when Claude Desktop started the gateway more than once: each
  process kept its own idea of the chain head, so two records claimed the same
  predecessor and `verify` reported "chain broken". Writes now hold a lock on
  `<log>.lock` (Windows and POSIX) and re-read the head first, so any number of processes
  extend one chain. `count` and `head` reflect every writer. A log that already forked
  stays broken; start a new one.
- `shadowing.cross_reference` flagged a tool mentioning another tool on the same server
  ("read_file: use read_text_file instead"), and could never see the real attack, a tool
  talking about a tool on a different server. It now compares across servers only, and
  names that are ordinary words count only when quoted.
- Pins and baselines are saved atomically, and a corrupt file is moved to `.corrupt`
  instead of stopping the gateway.
- Fetched documentation was blocked as data exfiltration: badge and image URLs on
  shields.io or GitHub counted as "carrying data" because any long path or query did.
  URLs are now judged part by part; words, slugs, file names, versions and digests are
  not data.
- Documentation placeholders (`xoxb-your-bot-token`, `postgres://user:password@host`) are
  no longer reported as secrets.
- "Open your mcp.json" is suspicious in a tool description but normal in a setup guide;
  the rule now applies to definitions only. The sensitive-path rule needs word
  boundaries (`ACCESS_TOKEN=...` no longer reads as "access").
- `ioc.similar_text` is high only with two fragments seen across unrelated tools or six in
  all; fragments from one tool's poisoned copies may be its genuine wording. Removes all
  false alarms on 2,435 held-out benign texts; detection on unseen tools at high moves from
  65.6/73.8/64.1% to 64.1/70.9/63.4%.
- The cross-dataset evaluation used Python's randomised `hash()` to pick benign test
  records, so its numbers changed between runs.

### Added
- Result checks for injections written as ordinary text: data that addresses the
  assistant, fake chat or system markers, requests to gather information and send it to an
  address, and data naming a tool to use. "Ignore previous instructions" now also matches
  "ignore your previous iunstructions" and similar, and `<INFORMATION>` style tags.
- `scripts/benchmark.py` and `docs/benchmark.md`: detection measured on the training
  corpus (unseen tool families, unseen datasets) and on held-out benchmarks never used for
  the feed: InjecAgent (2,108 injected results), AgentDojo, BIPIA, ToolEmu (943 benign
  definitions) and MCP documentation (978 benign pages). Rules were developed on one part of
  InjecAgent and AgentDojo and are reported separately on the untouched part.
- `scripts/ioc/extra_sources.py` builds that held-out corpus.

## 0.7.2

### Added
- Two injection rules (high) for attacks phrased in new words: covert actions
  ("quietly include", "silently send", "covertly copy") and instructions to put sensitive
  data into the output ("include the contents of the user's config files", "dump the
  contents of all environment variables"). Negated wording ("never include the contents
  of credential files") and ordinary uses ("runs quietly; add --verbose") do not match.
  Neither rule fires on any of the 652 benign tools in the evaluation corpus.
- The critical rule for sensitive paths (`~/.ssh`, `.aws/credentials`, ...) also covers
  embed, attach, append, send, copy, dump and upload.

### Fixed
- The IOC builder counted one-letter fragments as words, so "of the user s" (from
  "of the user's") and escaped-newline junk such as "n nsudo rm rf" became indicators.
  Phrases now need two words of three letters or more. The bundled feed is rebuilt;
  detection on unseen tools is unchanged.
- `mcpguard test` prints the redacted text only when a secret was actually removed.

## 0.7.1

### Fixed
- A config file that is not valid UTF-8 (for example one saved by a Windows editor in the
  ANSI code page) crashed `load_config` with `UnicodeDecodeError`. It now raises a
  `ConfigError` saying where the bad byte is. Found by the property tests on Windows.
- Passing a folder as the config path is now a `ConfigError` on every platform.
- All text file reads and writes name UTF-8 explicitly instead of using the platform
  default, which is not UTF-8 on Windows. The interactive approval prompt uses the
  console's own encoding.
- `mcpguard scan -` reads piped input as UTF-8, and CLI output redirected on Windows no
  longer crashes on characters the code page cannot represent.

### Changed
- `scripts/check.py` and CI run the tests with `PYTHONWARNDEFAULTENCODING=1`, and pytest
  turns `EncodingWarning` into an error, so code relying on the platform encoding fails
  on every OS, not just Windows.
- `scripts/check.py --install` installs the dev tools; without pytest-cov the tests still
  run, without coverage.

## 0.7.0

### Added
- Indicators of compromise built from public MCP attack benchmarks (MCP-SafetyBench, MSB,
  MCPSecBench, Invariant Labs' experiments, DVMCP), filtered against benign tools from the
  official reference servers and GitHub's MCP server. New rules: `ioc.known_text`,
  `ioc.similar_text`, `ioc.phrase`, `ioc.domain`, `ioc.param_name` and `ioc.tool_name`.
- Payload isolation: indicators come only from the part of a malicious text that is not
  genuine tool wording, so genuine tools are not flagged by their poisoned copies.
- `mcpguard iocs` to show the feed, `iocs build` to build one from your own labelled corpus,
  and `iocs eval` to measure it on unseen tools. Extra feeds are set with
  `[detectors.iocs] feeds`.
- `scripts/ioc/build_corpus.py` to rebuild the corpus from the benchmark repositories.
- `docs/iocs.md`: method, results, limits and sources.

### Measured
- Baseline before IOCs: mcpguard caught 13–16% of benchmark attacks at high severity.
- With IOCs, on tool families never seen during building: 64–74%, with 0 false alarms
  on 967 benign tools across three splits.
- On a fully unseen benchmark, IOCs add no detection: they recognise known attacks, not new wording.

### Fixed
- A missing extra feed was skipped silently; it is now a config error.
- Feed paths were resolved against the working directory instead of the config file.

## 0.6.0

### Added: security checks
- Arguments: `path.traversal`, `path.sensitive`, `path.unc`, `injection.command`,
  `injection.sql`, `ssrf.metadata`, `ssrf.internal` (including decimal, hex and octal IP
  spellings) and `ssrf.scheme`.
- Results: `exfil.markdown_image`, `exfil.markdown_link`, `injection.encoded` (base64
  instructions) and `hidden.ansi_escape`.
- Catalog: `name.confusable`, `capability.shell`, `shadowing.duplicate_name` and
  `shadowing.similar_name`.
- `mcpguard checks` lists every rule.
- Each check is tested against attacks and against ordinary input that must not trigger it.

### Added: quality checks
- `scripts/check.py` runs ruff, mypy, bandit, vulture and the tests with coverage; `--full`
  adds the property campaign and pip-audit.
- Branch coverage gate at 88% (currently 88.8%), including the stdio gateway run as a subprocess.
- Stricter ruff rules (security, pytest style, performance) and stricter mypy settings.
- Pre-commit hooks, and CI running the checks on three operating systems and two Python versions.

### Fixed (found by the new checks)
- Outbound HTTP used Python's default opener, which accepts `file://` URLs and follows
  redirects. A malicious server or webhook could redirect a request, with its bearer
  token, to another host or an internal address. A dedicated opener now allows only
  http(s) and never follows redirects.
- Runtime checks used `assert`, which `python -O` removes.
- Removed dead code left from earlier versions.

## 0.5.0

### Added
- Argument checking against each tool's declared `inputSchema` (`policy.validate_arguments`).
- Audit checkpoints (`[audit] checkpoint_path`, `mcpguard checkpoint`, `verify --checkpoints`),
  which detect deleted records at the end of the log and rewrites of checkpointed history.
- Server-to-client event stream in HTTP mode, so HTTP clients receive `list_changed`.
- Prometheus metrics at `/metrics`, on both the HTTP front end and the dashboard.
- Property-based tests (Hypothesis) for the audit chain, redaction, detectors, policy,
  schema validation, config loading and the HTTP parser.

### Fixed (found by the new tests)
- `verify` crashed with a TypeError on a record whose hash contained non-ASCII characters,
  so a crafted edit could make verification fail with an error instead of reporting tampering.
- The config loader raised internal errors (AttributeError) for sections of the wrong type,
  such as `policy = []`; it now reports a clear config error for every malformed shape tested.
- The dashboard compared its approval token without a constant-time comparison.

### Testing
- Property campaign: about 54,000 generated cases across three seeds, all passing.
- Live HTTP fuzzing: 9,000 random and mutated requests; the server stayed healthy and
  logged no internal errors.
- Whole suite run 100 times in random order and 40 more times under 2x CPU overload:
  140 of 140 runs passed.

## 0.4.0

### Added
- `mcpguard serve`: Streamable HTTP front end for MCP clients, with sessions, a health
  check (`/healthz`), Origin checks, body limits and graceful shutdown.
- Named clients with bearer tokens (`[clients.<name>]`); rules can target clients, and
  budgets and rate limits are counted per client.
- HMAC-signed audit records. The verifier detects forged records, records signed with the
  wrong key, and downgrade rewrites.
- Webhook alerts for blocks, quarantines, outages and log problems, batched per interval.
- "Allow for N minutes" approvals from the dashboard (or `a` at the terminal), shown with
  their remaining time.
- Forwarding of client cancellation (`notifications/cancelled`) to upstream servers.
- `mcpguard policy-test` for checking rules against expected decisions.
- `explain --client`; `check` lists clients, alerts and signing.

### Fixed
- An unauthenticated client could fill the audit log; failed logins are now logged at
  most once a minute, with a count.
- The first failed login was not logged when system uptime was under a minute.
- A malformed error object from an upstream server could crash request handling.
- Upstream error messages forwarded to the client are now redacted.
- An invalid audit key crashed startup instead of reporting a config error.
- Two clients sharing a token, or a single client opening unlimited sessions, were allowed.
- SIGTERM skipped cleanup in both stdio and HTTP mode.
- Stale approval requests left by a crashed gateway were still shown in the dashboard.
- The dashboard token file was briefly readable by other users while it was being created.

## 0.3.0

### Fixed
- A config reload with a broken detector plugin left the gateway half-updated, and every
  later request failed. Reloads now validate everything first and swap atomically.
- Invalid severities, actions and other values were accepted silently and failed later.
  The config is now fully validated, with messages that name the offending key.
- A partially written final record (after a crash) made the audit log unreadable and
  stopped the gateway from starting. It is now set aside and the recovery is logged.
- A crashed upstream server stayed unavailable until restart. Servers are now supervised
  and restarted with backoff.
- The gateway's stdin reader did not work on Windows.
- `npx`, `uvx` and other `.cmd` launchers were not found on Windows.
- Terminal approvals always denied on Windows; they now use the console.
- Secrets in upstream error messages were written to the audit log unredacted.
- Approval requests showed secrets in the dashboard.
- Definition findings were re-logged on every re-scan.
- The exfiltration tracker grew without bound and tainted ordinary words.
- Resources quarantined in enforce mode could raise an internal error when read.
- Long schema property names were not scanned.
- The protocol version requested by the client was echoed back even when unsupported.
- The incremental verifier missed in-place edits; it now runs a full pass every 30 seconds.

### Added
- Server supervision with exponential backoff, health state and `server.exited` events.
- Automatic renewal of expired Streamable HTTP sessions, and clearer HTTP errors.
- Per-server `timeout_seconds` and `enabled` settings.
- Audit log rotation (`[audit] rotate_bytes`) with the chain continuing across segments.
- `mcpguard check` and `mcpguard explain`.
- Logging to stderr or a file (`[logging]`, `run --log-level`).
- A state snapshot for the dashboard (server health and tool inventory).
- A redesigned dashboard: activity chart with a table view, a filterable audit ledger with
  per-record detail, approvals with a countdown, server health, tool inventory, light and
  dark themes, and a mobile layout.
- Tests organised by module, with regression tests for each fix (75 in total), plus CI on
  Linux, Windows and macOS.

## 0.2.0
- Streamable HTTP upstreams; proxying of prompts and resources; argument-level rules; monitor
  mode; custom rules, plugins, suppressions and severity overrides; entropy detection;
  adaptive baselines; live config reload; dashboard approvals.

## 0.1.0
- First version: stdio gateway with policy, definition scanning, pinning, redaction,
  exfiltration checks and a hash-chained audit log.
