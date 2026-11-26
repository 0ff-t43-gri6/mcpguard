# mcpguard user guide (Windows, Claude Desktop)

This guide is for someone who wants to run mcpguard on their own PC and use it day to day.
It uses plain commands and no jargon. Run every command in PowerShell, inside the mcpguard
folder:

```powershell
cd C:\Users\<you>\Desktop\mcpguard
```

## 1. What it does

mcpguard sits between Claude Desktop and your MCP servers (for example the file tools).
Every tool call goes through it. It can block dangerous calls, flag suspicious text,
and keep a signed log of everything that happened.

It has two modes, set at the top of `mcpguard.toml`:

| Mode | What happens |
|------|--------------|
| `monitor` | Calls are logged and findings are recorded, but nothing is blocked. Use this first. |
| `enforce` | Calls that break a rule are blocked. Switch to this once the findings look right. |

## 2. First-time setup

```powershell
py -m pip install -e .
py -m mcpguard setup --claude-desktop
```

`setup` writes a starter config in monitor mode (or keeps yours), trusts it, optionally connects
Claude Desktop, runs the health check and prints what to do next. Without `--claude-desktop` it
leaves Claude Desktop alone. The same steps by hand: `init`, `claude-desktop install --take-over`,
`trust`, `doctor`.

Then quit Claude Desktop fully (section 6) and open it again. Tools now reach Claude through
the gateway and appear as `<server>__<tool>`.

## 3. Every time you edit mcpguard.toml

1. Save the file.
2. Run `py -m mcpguard check`. It says whether the file is valid.
3. Run `py -m mcpguard trust`. mcpguard refuses to start a config you have not trusted,
   so a change made by something else cannot run silently.
4. Quit and reopen Claude Desktop.

## 4. Pin the server version

If a server is started with `npx`, name its version, otherwise the package can change under
you:

```toml
args = ["-y", "@modelcontextprotocol/server-filesystem@2.4.0", "C:/Users/<you>/Desktop/mcp-sandbox"]
```

Find the latest version with `npm view @modelcontextprotocol/server-filesystem version`.

## 5. Daily commands

| Command | Use it to |
|---------|-----------|
| `py -m mcpguard doctor` | check the whole setup and see what to fix |
| `py -m mcpguard stats` | see what is true right now (running, quarantined), then calls, blocks and findings for the last 24 hours (`--hours 0.5` for less) |
| `py -m mcpguard mode` | show the mode; `mode enforce` or `mode monitor` switches it (also a switch in the dashboard) |
| `py -m mcpguard open` | open the dashboard in your browser (starts it if needed). Or double-click `mcpguard-dashboard.bat` in the mcpguard folder |
| `py -m mcpguard dashboard` | run the dashboard on its own, without opening a browser |
| `py -m mcpguard report -o report.pdf` | write a PDF report you can open, print or share (`.html` and `.md` also work) |
| `py -m mcpguard verify` | check the audit log for tampering |
| `py -m mcpguard scan --all` | read every server's tool definitions without running a call |

`stats` reads the log, so old findings stay in it for 24 hours. Use a short `--hours` value
to see only what happened just now.

## 6. Quitting Claude Desktop properly

Closing the window leaves the gateway running in the background. To stop it:

1. Click the small up arrow (^) next to the clock.
2. Right-click the Claude icon and choose **Quit**.

To check nothing is left:

```powershell
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match "mcpguard" -and $_.Name -ne "Code.exe" } | Select-Object ProcessId, Name
```

An empty result means no gateway is running. To stop one by hand:
`Stop-Process -Id <ProcessId> -Force`.

## 7. Pins: what they are and how to read the output

The first time mcpguard sees a tool, it records a fingerprint (a pin) of its definition.
If the definition later changes, that is called a rug pull: a tool that behaved one way
when you approved it now behaves another way.

- `py -m mcpguard pins list` shows the recorded pins.
- `py -m mcpguard pins pending` shows tools waiting for review: `NEW` ones, and `CHANGED` ones
  whose definition differs from what you trusted.
- `py -m mcpguard pins diff <server>` shows exactly what changed (old text with `-`, new with `+`).
- `py -m mcpguard pins approve <server>[/tool]` trusts the new or changed definition you have read.
- `py -m mcpguard pins forget <server>/<tool>` makes mcpguard trust one tool's current
  definition again.
- `py -m mcpguard pins reset` clears every pin. Everything is trusted again on next start.

**If you see `rug_pull.changed` or tools listed as quarantined:**

1. Run `py -m mcpguard pins diff <server>` and read what changed.
2. Ask whether you changed the server version. Upgrading a server changes its definitions.
3. Run `py -m mcpguard scan --all`. If it reports findings, or the diff shows new instructions or
   mentions sending data somewhere, stop and do not approve.
4. If the change is harmless and expected, run `py -m mcpguard pins approve <server>`, then quit
   and reopen Claude Desktop.

Never re-trust a definition just to make the alert go away.

## 8. Reading the doctor output

- `OK` means fine.
- `WARN mode monitor` is expected while you are testing.
- `WARN dashboard port in use` is expected while the gateway is running.
- Any line starting `FAIL` or counted under "problems" needs fixing. Follow the text on the line.

## 9. Moving to enforce mode

After a few days in monitor mode:

1. Run `py -m mcpguard stats` and `py -m mcpguard report -o report.pdf`.
2. Read the findings. For each one, decide if it was a real problem or a false alarm.
3. If a rule was a false alarm, adjust the policy in `mcpguard.toml`.
4. Switch to enforce. Either click **Enforce** in the dashboard (top right), or run
   `py -m mcpguard mode enforce`. It applies within a couple of seconds, with no restart and no
   `trust`. Switch back the same way (`py -m mcpguard mode monitor`, or the **Monitor** button, which
   asks you to confirm).

The switch does not change `mcpguard.toml`. `py -m mcpguard mode` shows what is in force and what the
file says; `py -m mcpguard mode config` drops the switch and goes back to the file's setting. Every
change is written to the audit log as `mode.changed`.

## 10. If something goes wrong

| Symptom | What to do |
|---------|------------|
| Claude has no file tools | Quit Claude Desktop from the tray and reopen it. Run `doctor`. |
| "config is not trusted" | Run `py -m mcpguard trust`. |
| A tool call was blocked | Run `py -m mcpguard stats`; the rule that blocked it is listed. |
| `verify` reports tampering | Do not delete anything. Keep the log and the `~\.mcpguard` folder and ask for help. |
| `Exception ignored ... _ProactorBasePipeTransport` | Harmless Windows noise when a command exits. |

## 11. Where things live

| Item | Location |
|------|----------|
| Config | `mcpguard\mcpguard.toml` |
| Audit log | `mcpguard\mcpguard-audit.jsonl` |
| Signing keys, trust list, checkpoints | `C:\Users\<you>\.mcpguard\` |
| Pins | stored by mcpguard; use the `pins` commands rather than editing them |

Keep the key folder. A log without its key cannot be verified, and mcpguard will refuse to
start on a log it can no longer verify.
