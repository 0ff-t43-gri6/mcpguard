# Deploying mcpguard

Three ways to run it, from one person to a team. All of them end with the same acceptance
checks.

| Setup | Who it is for | How clients connect |
|---|---|---|
| Desktop | One person, Claude Desktop or an IDE on their own machine | The client starts `mcpguard run` (stdio) |
| Service | A team or CI sharing one gateway on a Linux host | HTTP with a bearer token per client |
| Container | The same, in Docker or Kubernetes | HTTP with a bearer token per client |

## Roll out in two stages

1. **Monitor.** `mcpguard init --profile monitor`. Nothing is blocked; the audit log records
   what would have been. Run real work through it for a week, then read `mcpguard stats
   --hours 168` and the dashboard's "would block" entries.
2. **Enforce.** Fix or allow what monitor mode showed (policy rules, `pass_env`, severity
   overrides), then set `mode = "enforce"`. The config reloads while the gateway runs.

`--profile strict` starts stricter: tools without a rule need approval, and medium findings
block too. Use it where the tools can move money, send mail or change production systems.

## Desktop

```sh
pip install mcpguard-<version>-py3-none-any.whl
mcpguard init
mcpguard claude-desktop install --take-over   # moves existing servers behind the gateway
mcpguard doctor
mcpguard selftest
```

Restart Claude Desktop. The dashboard is at http://127.0.0.1:8765.

## Service (systemd)

[`deploy/mcpguard.service`](../deploy/mcpguard.service) has the commands in its header. In
short: a dedicated `mcpguard` user, a virtual environment in `/var/lib/mcpguard`, tokens in
`/etc/mcpguard/env`, and a unit that runs `mcpguard selftest` before every start, so a config
that no longer stops the known attacks does not come up.

Give each client a name and a token:

```toml
[http]
host = "127.0.0.1"      # keep it on loopback and put a TLS proxy (nginx, Caddy) in front
port = 8766

[clients.ci-agent]
token_env = "MCPGUARD_TOKEN_CI"
```

mcpguard does not terminate TLS. Anything beyond loopback must go through a proxy that does,
and the gateway refuses to listen beyond loopback without client tokens.

## Container

```sh
mkdir data && mcpguard -c data/mcpguard.toml init     # then add [clients.<name>] and servers
docker build -t mcpguard .
docker run -d --name mcpguard -v "$PWD/data:/data" -p 127.0.0.1:8766:8766 \
    -e MCPGUARD_TOKEN_CI=... mcpguard
```

or `docker compose -f deploy/docker-compose.yml up -d`. The container runs as a non-root user
with a read-only root filesystem; everything it writes is in `/data`.

Tool servers that the gateway starts run inside the container, so their runtimes must be in
the image (build one `FROM mcpguard` and add Node, uv, ...), or use remote HTTP servers. The
dashboard listens on the container's loopback only; use `mcpguard stats`, `/metrics` and
`mcpguard export` from outside, or run with `approvals.mode = "deny"`/`"allow"` where no one
can answer approval prompts.

The Dockerfile and compose file have been reviewed but not built in this project's CI.
Build and smoke-test them in your environment before relying on them.

## Containing each server

Before enforcing, give every server the narrowest setup that still works (details in the
README under "Containing servers"):

1. `allowed_paths` / `allowed_hosts` for what its calls may touch.
2. `[servers.<name>.sandbox]` for third-party or untrusted servers, so the process itself is
   confined to a container. Build and try the container once by hand; mcpguard's own checks
   test the command line it generates, not your Docker installation.
3. `[policy] ask_sensitive = true`, or explicit `ask` rules, for tools that write, run or send.

`mcpguard check` lists servers that have neither a sandbox nor `allowed_paths`.

## Acceptance checks

Run these after installing, after every config change, and in the deployment pipeline. Each
exits non-zero on failure.

| Command | Proves |
|---|---|
| `mcpguard check` | The config is valid; lists servers and rules |
| `mcpguard selftest` | This install and config stop the known attacks and let ordinary text through |
| `mcpguard doctor` | Servers start, ports are free, the audit log verifies |
| `mcpguard scan --all` | No configured server has a poisoned or shadowing definition |
| `mcpguard policy-test cases.toml` | Your rules decide your own cases as expected |
| `curl http://127.0.0.1:8766/readyz` | Every configured server is up (HTTP mode) |

## Probes and metrics (HTTP mode)

| Path | Auth | Use |
|---|---|---|
| `/healthz` | none | Liveness: the process answers |
| `/readyz` | none | Readiness: 200 when every configured server is up, 503 with the list of those that are not |
| `/metrics` | bearer token | Prometheus counters: calls, blocks, findings, latency |

## Upgrading

1. Read the CHANGELOG entry; "Behaviour change" marks anything that can stop a working setup.
2. Install the new wheel, run `mcpguard check` and `mcpguard selftest`.
3. Restart the gateway (or the client, on a desktop). State, pins, baselines and the audit
   chain carry over.

## Changing the config of a running gateway

A running gateway reloads `mcpguard.toml` when it changes, but only a version you have trusted. After editing it
(or after `git pull` changes it), run `mcpguard trust` in that folder; the gateway picks the change up within a few
seconds. Until then it keeps the old settings and writes `config.reload_refused` to the audit log. This stops a
tool, or anything else that can write the file, from switching the mode or adding a server to a live gateway.
Keep the config, the audit log and the key out of any folder a files tool server may reach, and see
`[policy] protect_own_files`.

## Making the audit log hard to tamper with

No program can stop someone with full control of a machine from deleting a file on it. These steps
stop the realistic cases (a compromised tool server or agent running as you) and keep a copy where a
local attacker cannot reach:

1. **Send every record off the machine:** `[audit] forward_url = "https://..."`. Records are
   sent as they are written, retried after outages, and resumed after restarts. This is the strongest
   step: a deleted local log cannot take back what already left.
2. **Let the gateway notice:** the default `on_tamper = "block"` makes it alert and refuse tool calls
   if records it wrote are deleted, cut short or changed; `verify_minutes` re-checks the whole chain.
3. **Lock the file (optional):** `mcpguard audit-protect` sets the operating system's append-only flag
   (Linux: `chattr +a`, needs `sudo`; macOS: `chflags uappnd`). Run `mcpguard audit-unprotect` before
   `audit-new` or rotation. On Linux a locked file defeats a program running as an ordinary user.
4. **Separate accounts (strongest local option):** run the gateway as its own account that owns the
   log folder (see the systemd service above), and run the AI client and its tool servers as another
   account that can read but not write it. On Windows, do the same with a second user and folder
   permissions that give your everyday account read-only access.

## Backup

Back up the config, `mcpguard-audit*.jsonl`, the checkpoint file and `mcpguard-pins.json`.
Keep `mcpguard-audit.key` somewhere separate and access-controlled: with the key and the
log, records can be forged. Without the key, signatures on old records cannot be checked.
