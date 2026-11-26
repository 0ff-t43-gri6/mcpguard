# Threat model: attacks on mcpguard itself

mcpguard sits between an AI client and its tool servers, so a weakness in mcpguard is a weakness
in everything behind it. This page records 54 rounds of attacking mcpguard directly: what was
tried, what happened, the fix, and the test that keeps the fix in place
(`tests/test_threats.py`).

## Who is attacking

- **A hostile or compromised tool server**: it controls tool names, descriptions, results,
  notifications, error text, and what it does with the environment it is started with.
- **Text that reaches the model** (a web page, an email, a file) and tries to make the model call
  tools in harmful ways: prompt injection.
- **A local web page or process** that tries to use the dashboard or the HTTP endpoint.

Out of scope: someone who can already edit mcpguard's config, key or code, and the AI client.

## Results

| # | Attack | Before | Fix | Test |
|---|---|---|---|---|
| T1 | Call `files__Write_File` to skip an `ask` rule written for `files__write_file` | **worked**: rules matched case-sensitively | Tool names match rules without regard to case | `test_t1_*` |
| T2 | Reach a denied path with `..`, `//`, backslashes or `\\?\` prefixes | **worked** | Paths are normalised before argument rules match; ordinary paths are unaffected | `test_t2_*` |
| T3 | Send arguments nested 50,000 deep | **worked**: the scanner crashed | Nesting is measured without recursion; calls deeper than 64 levels are refused | `test_t3_*` |
| T4 | A server returns a 10 MB result to stall the scanner | **worked**: scans took minutes | Results are scanned and passed on up to 1,000,000 characters (or `max_result_chars`), the rest truncated | `test_t4_*` |
| T5 | A server answers with JSON too deep to parse | **worked**: the reader stopped and every later call to that server hung | That one call fails with a clear error; the server keeps working | `test_t5_*` |
| T6 | A tool name with terminal escape codes, to rewrite what `mcpguard scan` shows | **worked** | Control characters in names quarantine the tool (critical); names are printed escaped | `test_t6_*` |
| T7 | Script in a tool name or reason, shown on the dashboard | held: every field is escaped | The one unescaped field (latency) is now shown only when it is a number | — |
| T8 | Send a secret read earlier in base64, URL-safe base64 or hex | **worked**: taint tracking only matched the plain value | Encoded forms of tracked values are matched too | `test_t8_*` |
| T9 | Write a card number with dots, underscores or slashes between digits | **worked** | Those separators count like spaces and dashes | `test_t9_*` |
| T10 | A server floods "tool list changed" notifications to fill the audit log | **worked**: one record per notification | One record per refresh | `test_t10_*` |
| T11 | Edit, delete or forge audit records | held: with the key, an edit fails the signature, a deleted record breaks the chain, and a rewritten unsigned log is refused | — | existing audit tests |
| T12 | Read personal data from a pending approval file | **worked**: approval files held the raw arguments | Shown arguments are masked like log messages | `test_t12_*` |
| T13 | A server returns a result nested too deeply to scan | held after T3, plus an explicit guard | Results deeper than 64 levels are withheld | `test_t3_*` |
| T14 | A web page posts to the dashboard (CSRF) or reaches it by DNS rebinding | held: foreign Host and missing token refused | POST is refused if no token exists at all | existing dashboard test |
| T15 | Oversized headers, bodies or chunked uploads to the HTTP endpoint | held: 4 MB body cap, header limit, timeouts | — | existing HTTP tests |
| T16 | Hide an injection with lookalike Cyrillic or Greek letters, full-width text or s p a c e d letters | **worked** | Text is also checked after undoing those tricks (`injection.obfuscated`); real Russian, Greek and accented text stays quiet | `test_t16_*` |
| T17 | Make thousands of calls that need approval to flood the user | **worked** | At most 20 requests wait at once; more are refused | `test_t17_*` |
| T18 | Guess an HTTP client token by timing, or use another client's session | held: tokens compared in constant time; sessions bound to their client | — | existing HTTP tests |
| T19 | A server reads mcpguard's audit key, the HTTP client tokens, the alert webhook, or **another server's** bearer token from its environment | **worked**: every server inherited the gateway's full environment | Those variables are withheld from every server process; a server's own `env` still applies | `test_t19_*` |
| T20 | A server puts personal data in its error output, which mcpguard logs | **worked**: secrets were masked there but personal data was not | Error and stderr text is masked like everything else in the log | `test_t20_*` |
| T21 | Send a request too deep to parse (200,000 brackets) to the gateway itself | **worked**: the gateway process exited, cutting off every tool | Answered as a parse error; the gateway keeps running. Same for the HTTP endpoint and the dashboard | `test_t21_*` |
| T22 | Replace an audit record and recompute the chain without the key | held: records are HMAC-signed | — | existing audit tests |
| T23 | Send a secret read earlier reversed, broken up with separators, or split over several calls in any order | **worked**: only whole values (and base64/hex) were matched | Whole values are also matched reversed; pieces of 8+ letters and digits are counted across calls, and a value is flagged once 60% of it has left. Short references (a key's last 8 characters) stay quiet | `test_t23_*` |
| T24 | Hide an injection with zero-width characters, accents, small capitals, rarer lookalikes (Armenian, Cherokee, Latin-like symbols), hidden Unicode tag text, or leetspeak (`1gn0re a11`) | **worked** for accents, small capitals, rarer lookalikes and leetspeak (invisible characters were flagged, but not read as an injection) | De-obfuscation drops invisible characters, decodes tag text, strips accents, maps 500+ Unicode lookalikes (UTS #39 confusables) and reads leetspeak two ways; Hindi, accented Latin and version strings like `v1.2.3` or `k8s` stay quiet | `test_t24_*` |
| T25 | A server reads a credential the user keeps in the environment (`GITHUB_TOKEN`, `OPENAI_API_KEY`, a key under an innocent name) | **worked**: servers inherited every variable except mcpguard's own | Variables whose name or value looks like a credential are withheld unless the server's `pass_env` names them; withheld names are written to the audit log at server start | `test_t25_*` |
| T26 | Send a card or ID number read earlier in pieces (four digits at a time, in one call or over several) | **worked**: personal data was matched whole, per call | Whole runs of 4+ characters that occur inside a tracked value are counted across calls; reported once 80% has left (all of it for short values such as SSNs). "Card ending 1111" stays quiet | `test_t26_*` in `tests/test_production.py` |
| T27 | A server returns a result with the wrong shape (`{"messages": 1}`, a number where a list belongs) | **worked**: the scanner raised an error on that result; found by the large property-test campaign | Result fields are read only when they have the expected type | `test_t27_*` |
| T28 | Hide instructions in a resource template's description | **worked**: templates were passed on unscanned | Templates are scanned like every other definition | `test_t28_t50_*` |
| T29 | A tool whose name is a number | **worked**: the gateway failed to start | Entries without a string name are dropped | `test_t29_*` |
| T30 | Put instructions in a JSON-RPC error message | **worked**: error text went to the model as written | Error text is scanned; a hostile one is replaced | `test_t30_t31_*` |
| T31 | Put instructions in a result's title, description, annotations, `_meta`, or a base64 `blob` | **worked**: only `text` fields were scanned | Every string field is scanned, and text inside blobs is decoded first; image and audio data are skipped | `test_t30_t31_*`, `test_t31_*` |
| T32 | Offer 50,000 tools | **worked**: the refresh never finished | At most 2,000 tools, prompts or resources are taken from one server | `test_t32_*` |
| T33 | Carry a secret out in the URI of a templated resource read | **worked**: resource URIs were not checked | A URI the model builds is checked like outgoing arguments | `test_t33_t48_*` |
| T34 | Send a secret as base32, ROT13, percent-encoding, `\u` escapes, hex with separators, character codes, full-width letters or base64 twice | **worked** for all of these | The outgoing text is also checked in each decoded form | `test_t34_*` |
| T35 | Get past `allowed_hosts` with URL tricks: a backslash or `@` in the host, `//host`, `https:host`, other schemes, a URL inside a sentence, `git@host:path` | **worked** for 13 of 24 forms tried | Every URL anywhere in an argument is checked, for any network scheme; a URL that programs read differently is refused outright | `test_t35_*` |
| T36 | Smuggle data into the audit log as a subdomain of a refused URL | **worked**: the whole host name was written to the log | Only the last two labels are recorded | `test_t36_*` |
| T37 | Get past `allowed_paths` with `%VAR%` / `$VAR`, `file:` spellings, percent-encoded `..`, alternate data streams, network shares | **worked** for 9 of 30 forms tried | Each is refused: they change meaning after the check | `test_t37_*` |
| T38 | A tool named `filewrite`, `sendmail` or `terraform_apply` avoids the approval prompt | **worked**: only separated words were recognised | Words run together and 30 more verbs count; names starting with a reading verb (`get_`, `list_`) no longer do | `test_t38_*` |
| T39 | Start a known-bad package behind a wrapper (`cmd /c npx ...`, `env`, `sh -c`, `docker run`), in capitals, as `npm:name`, or by path | **worked** for 9 of 18 forms tried | Wrappers are unwrapped, names compared without case, and the name is looked for anywhere in the command; a version range counts as unpinned | `test_t39_*` |
| T40 | Hide a poisoned project config from `audit-configs` with a comment, a trailing comma, a byte-order mark, UTF-16, another file or key name, or TOML/YAML | **worked** for every form tried: the file was reported as merely unreadable or not found | JSON-with-comments, BOM, UTF-16 and TOML are parsed; more files and layouts are known; unparseable files are high; any download-and-run command in the raw text is critical | `test_t40_*` |
| T41 | A server reads a password from an inherited connection URL (`redis://:pass@host`, a proxy URL) | **worked** | Variables whose value is a URL with a password are withheld | `test_t41_*` |
| T42 | A formula hidden behind a tab or line break in the CSV export | **worked**; also every empty cell was written as `'` | Leading whitespace is ignored when checking; empty cells stay empty | `test_t42_*` |
| T43 | Slow every outgoing call by filling the tracker with numbers | **worked**: about a second per call at worst | Fewer, de-duplicated pieces are compared; bounded and tested | `test_t43_*` |
| T44 | Get a phrase to the model inside mcpguard's own "withheld" notice | **worked**: the notice quoted up to 60 characters of the offending text | The notice names the rule only; details stay in the audit log | `test_t30_t31_*` |
| T45 | Malformed client messages (a list, a number, an object as `id`, a non-string tool name) | **worked**: unhandled errors inside the gateway | Each gets a JSON-RPC error | `test_t45_*` |
| T46 | A 40 MB argument over stdio | **worked**: forwarded to the server whole | Arguments over 4,000,000 characters are refused | `test_t46_*` |
| T47 | Clone a project containing `mcpguard.toml`; the victim runs `mcpguard check` or `doctor` in it | **worked**: its plugins were imported and its servers started | A config merely found in the current folder that starts servers or loads plugins is refused until `mcpguard trust`; `-c` and `mcpguard init` count as trust | `test_t47_*` |
| T48 | Send an encoded credential through a tool that does not look like sending (`search`, `create_issue`) on another server | **worked**: only tools named like "send" were checked | More names count as sending, and every call is checked for credentials going to a different server than they came from | `test_t33_t48_*`, `test_t48_*` |
| T49 | A server calls back into the client (`roots/list`, `sampling/createMessage`) | held: the gateway offers neither | — | `test_t49_*` |
| T50 | Instructions in a schema property description, enum, default, title or output schema | held: every string in a definition is scanned | — | `test_t28_t50_*` |
| T51 | Frame the dashboard in a web page to steal an approval click | held: `X-Frame-Options: DENY` and a content security policy | — | existing dashboard tests |
| T52 | Open sessions without limit on the HTTP endpoint | held: 64 per client, oldest dropped | — | existing HTTP tests |
| T53 | Smuggle container options through sandbox settings | held: image, memory, runtime and mounts are validated | — | `test_t53_*` |
| T54 | Return the injection in a result marked `isError` | held: error results are scanned like any other | — | `test_t30_t31_*` |
| T55 | A malicious server is trusted the moment it is first connected (trust on first use) | **worked**: its definitions were pinned without review | `first_seen = "approve"` holds new definitions until reviewed; the default mode logs what it trusted on sight | `test_first_seen_*` |
| T56 | Delete the newest audit records (the chain alone cannot show this) | **worked** unless a checkpoint path was set by hand | Signed checkpoints are on by default outside the project folder; optional witness server; `doctor` warns | `test_deleting_the_newest_records_is_caught` |
| T57 | Truncate, delete or edit the audit log while the gateway runs | **worked**: the next write continued the shortened chain without a word | The gateway remembers the bytes it wrote and checks them before every call, alerts, and refuses tool calls by default; full re-verification on a timer; `forward_url` keeps a copy off the machine; optional append-only flag | `test_log_prevention.py` |

| T58 | Edit `mcpguard.toml` while the gateway runs (a files tool, an injected agent or any program): switch to monitor mode, drop rules, add a `[servers.x]` block | **worked**: the running gateway reloaded it with no trust check and started the new program | A changed config is reloaded only if its exact contents were trusted with `mcpguard trust`; otherwise `config.reload_refused` is logged and the old config stays | `test_h1_*` in `tests/test_pentest_fixes.py` |
| T59 | Drop a copy of the log beside it (`mcpguard-audit.backup.jsonl`) and delete the newest records | **worked**: the runtime guard took the copy as proof the records had moved | Only real rotated segments, or the archive after a genuine `audit-new`, excuse a changed log; a stray file is not read as a segment either | `test_m1_*` |
| T60 | A tool reads the audit key, or writes the config, log, pins or trust record | **worked**: no rule covered mcpguard's own files | Calls whose arguments name them are refused (`[policy] protect_own_files`, on by default) | `test_m2_*` |
| T61 | Leak a read secret spaced, hyphenated, lower-cased, gzip+base64, as HTML entities, as octal codes, or again after the first block | **worked**: coverage counted once, so later sightings of the same pieces passed; several encodings were not decoded | A call that carries half a value alone is flagged however often it was seen; case is ignored; HTML entities, octal codes and compressed base64 or hex are decoded | `test_m3_*` |
| T62 | Hide a card number among invisible characters, markup, newlines or odd separators | **worked**: not recognised | Data classes are also looked for in a cleaned view of the text (invisible characters and markup removed, digits joined) | `test_m4_*` |
| T63 | Instructions in ROT13, hex, reversed, in Spanish, French, German, Portuguese, Italian, Russian, Chinese, Japanese or Hindi, split into pieces, as a JSON task, as a mimicked tool call, or as an image URL with a data placeholder | **worked**: 10 of 16 forms gave no finding | Decoded views are re-scanned; multilingual patterns, a "letters spell it out" check, the tool-call shape and placeholder images added | `test_m5_*` |
| T64 | Misspell a security setting (`defualt`, `first_see`, `alowed_paths`) | **worked**: ignored with a warning only Claude Desktop hides | Unknown sections and keys are a config error that names the typo | `test_m6_*` |
| T65 | `%2e%2e/` without a leading slash, a Windows device name (`CON`), or a symlink inside an allowed folder pointing outside | **worked**: the path check was textual | Encoded climbs and device names are refused; existing paths are resolved through links | `test_l4_*`, `test_l5_*` |
| T66 | Change a tool's `title`, `outputSchema`, `_meta`, `icons` or `execution` after approval | **worked**: the pin ignored those fields | They are part of the pin when present; a pin made by an older version is renewed once | `test_l7_*` |
| T67 | A web page rebound to 127.0.0.1 calls the HTTP endpoint with its own `Host` | **worked**: only `Origin` was checked | On loopback, a `Host` that is not loopback gets 403 | `test_l8_*` |
| T68 | Terminal escape sequences in audit data reach a terminal through CSV or CEF export | **worked**: written raw | Control characters are written as `\xNN` | `test_l10_*` |
| T69 | Edit the forwarding cursor so records are skipped | **worked**: the cursor was trusted | The cursor is signed with the audit key; an unsigned or altered one is ignored and the log is sent again | `test_l3_*` |
| T70 | Swap the config file between the trust check and the load | **worked** in principle: it was read twice | The bytes that were checked are the bytes that are loaded | `test_l11_*` |
| T71 | Database, Kubernetes, Vault and similar credentials in the gateway's environment (`DB_PASS`, `MYSQL_PWD`, `KUBECONFIG`, `NETRC`, `BEARER` ...) | **worked**: passed to every tool server | Those names are withheld unless `pass_env` names them | `test_l6_*` |
| T72 | Name the config in another spelling a file system accepts: `%6dcpguard.toml`, `%256d...`, full-width `ｍ`, a zero-width character inside, a look-alike letter, `MCPGUA~1.TOM`, a wildcard (`mcpg*`, `/proj/*.toml`) | **worked** for 12 of 19 spellings | Names are percent-decoded (3 times), folded (full-width), stripped of invisible characters and look-alike letters, 8.3 short names are recognised, and wildcards are matched against the real paths | `test_own_files_are_recognised_in_every_spelling` in `tests/test_pentest_round2.py` |
| T73 | Put the config path in a dict key (`{"files": {"<path>": "..."}}`, as batch-write tools take) | **worked**: only values were read | Keys are checked, for own files and for `allowed_paths` | `test_own_file_named_by_a_dict_key` in `tests/test_pentest_round2.py` |
| T74 | Delete, move or overwrite the folder that holds the config, log and key | **worked**: a folder is not a file name | A destructive tool (delete, remove, move, rename, write, copy ...) naming that folder is refused; listing it is still fine | `test_folder_holding_own_files_*` in `tests/test_pentest_round2.py` |
| T75 | `forward_url`, `witness_url`, `alert_url` or a server `url` of `http://localhost.evil.com/` (or `127.0.0.1.evil.com`, `localhost@evil.com`) | **worked**: only the start of the text was checked, so cleartext went to a remote host | The host is parsed; plain http only to `127.0.0.1`, `localhost` or `::1` | `test_url_check_*` in `tests/test_pentest_round2.py` |
| T76 | Copy or move the project folder: the default key path (from the log's path) changes | **worked**: a new key was made silently; the old records no longer verified | The gateway refuses to start when the log holds signed records and the key is missing, and says what to do | `test_a_moved_project_*` in `tests/test_pentest_round2.py` |
| T77 | Plant a copy of the log named like a rotated segment, then cut the newest records | **worked**: the runtime guard took the copy as proof of rotation | A rotation moves our record out of the active file; if the file still starts at or before it, nothing was rotated | `test_a_copy_planted_*` in `tests/test_pentest_round2.py` |
| T78 | Instructions in a tool result as HTML entities, base32, base85, ascii85, quoted-printable, or base64 wrapped over lines / URL-safe | **worked**: only base64, hex, ROT13 and reversed text were read | All of these are decoded and checked | `test_instruction_hidden_in_a_further_encoding_is_found` in `tests/test_pentest_round2.py` |
| T79 | A tool server writes one line longer than 16 MB | **worked**: an unhandled error ended the read loop; every request waited (start-up timed out after 60 s) | The server is stopped and waiting requests fail at once with a clear message | `test_an_oversized_server_message_*` in `tests/test_pentest_round2.py` |
| T80 | Numeric tables, CSV or columns of numbers read as card numbers (redacted or blocked: data corrupted, a block with no cause) | **worked** (a false alarm, 22 to 37 per 300 rows) | A card number has even groups (4-4-4-4, one digit per line) or 4-6-5 / 4-6-4; columns do not | `test_numeric_tables_*`, `test_space_separated_columns_*` in `tests/test_pentest_round2.py` |
| T81 | `checkpoint_minutes = -1` or `rotate_bytes = -5` | **worked**: accepted | Negative values are a config error | `test_negative_audit_numbers_are_refused` in `tests/test_pentest_round2.py` |
| T82 | Read the key through a group- or world-readable `~/.mcpguard/keys/` folder | **worked** (0755 folder; the file was 0600) | The folder made for a key is 0700 | `test_the_folder_made_for_a_key_is_private` in `tests/test_pentest_round2.py` |
| T83 | A deeply nested `trusted-configs.json` (or one half-written) | **worked**: `RecursionError` stopped every start | Unreadable or too-deep files count as no trust; the file is written atomically | `test_a_deeply_nested_trust_file_*` in `tests/test_pentest_round2.py` |
| T84 | Bidi override (`U+202E`, `U+2066` ...) in a tool name or reason shown in an export | **worked**: not escaped in CSV, CEF or JSON | Shown as `\uXXXX` | `test_export_escapes_bidi_*` in `tests/test_pentest_round2.py` |
| T85 | Two `Host:` or two `Content-Length:` headers (a parser differential) | **worked**: the last one won | Refused with 400 | `test_two_host_headers_*` in `tests/test_pentest_round2.py` |
| T86 | `STRIPE_SK`-style environment variable names (`*_SK`) | **worked**: passed to every tool server | Withheld unless `pass_env` names them | `test_secret_key_suffix_*` in `tests/test_pentest_round2.py` |
| T87 | Rename the approvals folder (`[approvals] dir`): its `.token` and `decided/` are not under a name mcpguard recognises | **worked**: a tool could read the dashboard token and approve its own `ask` calls | The approvals folder is one of the gateway's own paths, whatever it is called | `test_a_renamed_approvals_folder_*` in `tests/test_pentest_rounds_3_to_7.py` |
| T88 | Dashboard decision with `"approved": "false"` (a non-empty string) | **worked**: stored as approved | Only a real `true` or `false` is accepted | `test_dashboard_decision_needs_a_real_boolean` in `tests/test_pentest_rounds_3_to_7.py` |
| T89 | Dashboard: a client that stops sending, or a negative `Content-Length`, holds a thread for ever | **worked** | 30-second socket timeout; lengths below 0 are 0 | `test_dashboard_negative_length_*` in `tests/test_pentest_rounds_3_to_7.py` |
| T90 | A tool name or reason with `<!channel>`, `<@U1>` or `<url|label>` reaches a chat webhook | **worked**: pinged people or showed a fake link | `&`, `<`, `>` are escaped | `test_alert_text_*` in `tests/test_pentest_rounds_3_to_7.py` |
| T91 | A tool name with ESC codes or newlines in the console approval prompt | **worked**: could redraw or fake the question | Control characters become `?`, the name is cut at 120 | `test_tty_prompt_*` in `tests/test_pentest_rounds_3_to_7.py` |
| T92 | A deeply nested pins, baseline, grants, state or IOC feed file | **worked**: `RecursionError` stopped start-up | Treated as corrupt (moved aside); a feed must be a JSON object and not too deep | `test_deeply_nested_state_*` in `tests/test_pentest_rounds_3_to_7.py` |
| T93 | Injection written in a `uri` (percent-encoded) or `mimeType` field of a result | **worked**: those fields were skipped | A sentence in either field is read like any other text | `test_sentences_in_uri_*` in `tests/test_pentest_rounds_3_to_7.py` |
| T94 | Remote tool server `url` of `http://localhost.evil.com/` given straight to the HTTP client | **worked**: its own prefix check | Same host check as the config | `test_remote_server_client_*` in `tests/test_pentest_rounds_3_to_7.py` |
| T95 | Remote server answers with an endless body, an endless slow event stream, or bytes that are not UTF-8 | **worked**: unbounded memory and time; a bad byte raised an error | 64 MB cap, an overall deadline of ten times the timeout, bad bytes replaced | `test_a_remote_server_cannot_*` in `tests/test_pentest_rounds_3_to_7.py` |
| T96 | A tool schema with `pattern: "^(a+)+$"` (or any nested-quantifier pattern) checked against a crafted argument | **worked**: 10 s on 28 characters, the gateway's event loop stalled for every server | Patterns with repeated groups, back-references, more than 3 unbounded quantifiers or over 300 characters are not evaluated; values over 2,000 characters skip the pattern | `test_a_hostile_schema_pattern_*` in `tests/test_pentest_rounds_3_to_7.py` |
| T97 | `audit-protect` on a file whose name starts with `-` | **worked** in principle: read as an option by `chattr`/`chflags` | `--` ends the options | `test_append_only_command_*` in `tests/test_pentest_rounds_3_to_7.py` |

**84 attacks worked and are fixed; 13 held** (rows T1 to T97; rounds 2 to 7 added 52 + 5 x about 10 attack cycles).

## Known limits

- **Encoded or split secrets.** Recognised whole, reversed, in the encodings listed under T8, T34 and
  T61, or once 50% has left in pieces of 8+ characters. Encrypted data, home-made ciphers (a byte XOR, a
  Caesar shift) and a secret leaked one or two characters at a time are not. No list of encodings can be complete.
- **Which calls are checked for what.** Tools that look like sending are checked against
  everything read in the session. Other tools are checked only for credentials going to a
  different server; an unrecognised random token sent through a tool named `search` is missed.
- **Instructions that read like ordinary requests** are missed by rules and classifier alike.
- **Images and audio** in results are not inspected.
- **`allowed_hosts` and `allowed_paths` check arguments.** A bare `name.tld/path` argument is
  treated as a host, so `README.md/section` is refused on a server with `allowed_hosts`. A
  server can still connect anywhere on its own; only a sandbox prevents that.
- **`ask_sensitive` reads tool names.** A hostile server can name a destructive tool `helper`.
- **The audit key and the log are the same account's files.** Anyone who can read the key can forge the log and
  its checkpoints. The key now defaults to `~/.mcpguard/keys/`, away from the project folder, and `doctor` warns
  when it sits beside the log; only `forward_url`, a witness, the append-only flag or a separate account stop a
  forger who has the key.
- **Newest records between checkpoints.** While the gateway is stopped, records written since the last
  checkpoint (at most `checkpoint_minutes`, default 5) can be deleted without `verify` noticing.
- **The HTTP endpoint without `[clients]` tokens** is open to any program on the machine (loopback only);
  the gateway warns at start-up.
- **`mcpguard verify` without the key** checks the chain but not the signatures, and says so.
- mcpguard trusts its own key files, the configs you trust, and the AI client.
