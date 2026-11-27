# mcpguard

A gateway that sits between an MCP client (Claude Desktop, Cursor, an agent framework) and the MCP
servers it talks to. Every tool call, prompt and resource read goes through it, so it can check
them, block some, ask you about others, and write down what happened. It is one Python package
and needs nothing else at runtime.

> **Status: release candidate (1.0.0rc1).** Nobody outside the project has reviewed it for
> security. Use it as one layer of protection, not the only one. It is weakest on attacks it has
> not seen before. The measured numbers are in [docs/benchmark.md](docs/benchmark.md) and under
> [Limits](#limits).

```
MCP client ──stdio or HTTP──▶ mcpguard ──┬──▶ local server (stdio)
                                │        ├──▶ local server (stdio)
                           dashboard     └──▶ remote server (Streamable HTTP)
                           signed audit log, alerts
```

## What it does

- **Rules.** Each tool, prompt or resource can be allowed, denied or put behind an approval,
  matched by glob. Rules can look at argument values and can apply to particular clients.
- **Pinning.** A tool definition is hashed the first time mcpguard sees it. If it changes later,
  the tool is quarantined until you clear it. This is the defence against a server that turns
  hostile after you trusted it.
- **Injection scanning.** Tool descriptions and tool results are checked for hidden or planted
  instructions. Matches are withheld instead of being passed to the model.
- **Secrets and personal data.** Credentials are redacted from results and blocked from leaving
  through email, HTTP or messaging tools. Card numbers, Aadhaar, US SSN, PAN and IBAN are masked
  and blocked in the same way.
- **Flow rules.** You can say that after one tool runs, a second one needs approval. Reading
  customer records and then sending email is the usual example.
- **Containment.** Servers can be limited to certain folders and hosts, and run in a container
  with no network.
- **Audit log.** Every decision is written to a hash-chained, signed log. `mcpguard verify`
  tells you if records were edited, removed or reordered.
- **Dashboard.** A local page at `127.0.0.1:8765` shows what is happening, takes approvals, and
  has a switch between monitor and enforce mode.
- **Known incidents.** A bundled list of 20 real MCP attacks and CVEs is checked against your
  setup.

New installs should start in monitor mode. It records what would have been blocked and blocks
nothing, so you can see how noisy the rules are before turning enforcement on.

## What it catches

| Attack | What happens |
|---|---|
| Hidden instructions in a tool description | The definition is quarantined |
| A trusted tool changes its definition | Quarantined until you clear the pin |
| A web page or file tells the agent what to do | The instructions are withheld |
| A credential read by one tool is sent out by another | Blocked |
| Private data is read, then email is sent | A flow rule asks or denies |
| Path traversal, SSRF, shell chaining or SQL in arguments | The call is blocked |
| Look-alike tool names, or two servers offering one name | Flagged |
| Edited or deleted audit records | `mcpguard verify` reports it |

## Quick start

```sh
pip install -e .
mcpguard init                                # writes mcpguard.toml, with comments on every setting
mcpguard claude-desktop install --take-over  # Claude Desktop now reaches its servers through the gateway
mcpguard doctor                              # checks the setup and says what to fix
```

Quit Claude Desktop completely and open it again. The dashboard is at <http://127.0.0.1:8765>.

For another MCP client, point it at the gateway instead of at the servers:

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

`mcpguard serve` lets several agents share one gateway over HTTP. Every command and setting is
described in [docs/reference.md](docs/reference.md).

## Layout

```
src/mcpguard/    the package (gateway.py is the request path, policy.py the rules,
                 detect.py and checks.py the detection, audit.py the log)
tests/           test suite
scripts/         check.py, benchmark.py and maintenance scripts
deploy/          Docker Compose and systemd examples
docs/            guides, threat model, benchmarks
```

## Documentation

- [docs/USER-GUIDE.md](docs/USER-GUIDE.md): a first install, step by step
- [docs/reference.md](docs/reference.md): all features, settings and commands
- [docs/deployment.md](docs/deployment.md): running it for a team
- [docs/operations.md](docs/operations.md): day-to-day use
- [docs/threat-model.md](docs/threat-model.md): what it stops, and attacks on mcpguard itself
- [docs/benchmark.md](docs/benchmark.md): detection results, including what it misses

## Limits

- Detection is pattern matching and statistics. It makes common attacks harder and will miss
  others. A request that reads like something a user would ask ("please unlock my front door")
  looks harmless inside data, and it is not caught.
- On attack wording it was not written from, roughly half are caught: about 50% of unseen
  InjecAgent cases and none of BIPIA. See [docs/benchmark.md](docs/benchmark.md).
- Flow rules match tool names. They show that a risky sequence happened, not that data moved from
  one step to the next. Their memory is kept per client session.
- Remote servers that need an interactive OAuth sign-in are not supported. Use a bearer token.
- Without a sandbox, a local server runs as you and can read anything your account can.
- Nothing can stop someone with full control of a machine from deleting files on it. The audit log
  has several protections (see [docs/deployment.md](docs/deployment.md)), but they have limits too.

## Development

```sh
pip install -e ".[dev]"
python scripts/check.py          # lint, types, security lint, dead code, tests with coverage
python scripts/check.py --full   # also a package check, property tests and a dependency audit
```

## Reporting a problem

For a security issue, follow [SECURITY.md](SECURITY.md) and do not open a public issue.

## License

MIT License. See [LICENSE](LICENSE).
