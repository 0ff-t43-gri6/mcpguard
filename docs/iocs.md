# Indicators of compromise

mcpguard ships a feed of indicators of compromise (IOCs) derived from public MCP attack
benchmarks. Every tool definition, tool response and argument is checked against it,
alongside the regular detectors.

## What is in the feed

| Indicator | Rule | Severity | Built from |
|---|---|---|---|
| Exact fingerprints | `ioc.known_text` | critical | SHA-256 of known malicious texts that carry a payload |
| Hashed 5-word fragments | `ioc.similar_text` | high | attack payloads (catches reworded or partial copies) |
| Phrases (3–6 words) | `ioc.phrase` | medium, high when several match | wording found only in attacks, across 2+ different tools |
| Hosts | `ioc.domain` | high | hosts referenced by attacks and never by benign tools |
| Injected parameters | `ioc.param_name` | high | parameters attacks add to existing tools (`llm_model_name`) |
| Tool names | `ioc.tool_name` | medium | names used only by malicious tools |

See the current feed with `mcpguard iocs -v`.

## How it is built

1. **Corpus.** `scripts/ioc/build_corpus.py` turns the benchmark repositories into a labelled
   JSONL corpus of tool definitions and tool responses, using each benchmark's own ground
   truth. A few small repositories are labelled by hand (the list is in the script).
   Benign examples come from the official MCP reference servers, GitHub's MCP server, and
   the benign servers inside the benchmarks.
2. **Payload isolation.** A poisoned description is usually a genuine description with an
   instruction appended. Indicators are built only from the payload: the text left after
   removing anything that matches benign wording, and anything every variant of the same
   tool shares. Payloads must also read as instructions to the model. Without this step,
   the genuine, unpoisoned tool would match its own poisoned copies.
3. **Benign filter.** Anything that appears in the benign corpus is dropped. Phrases must
   appear in attacks on at least two different tools. Parameters must have been added by
   an attack to at least two different tools.

Raw attack texts are not shipped. Fingerprints and fragments are one-way hashes, and phrases
are at most six words. Some sources have no license, so only derived indicators are
distributed.

## Results

Measured with `mcpguard iocs eval corpus.jsonl`. The feed is built from half of the tool
families and tested on the other half, so every test tool is one the feed has never seen,
neither its genuine nor its poisoned versions. "Detected" means a finding of high
severity or above, the level at which mcpguard quarantines a tool or withholds a result.

| Split | mcpguard without IOCs | with IOCs | False alarms on benign tools |
|---|---|---|---|
| 7 | 17 / 128 (13.3%) | 84 / 128 (65.6%) | 0 / 260 |
| 11 | 18 / 141 (12.8%) | 104 / 141 (73.8%) | 0 / 319 |
| 23 | 22 / 142 (15.5%) | 91 / 142 (64.1%) | 0 / 388 |

What the numbers mean:

- **Known attack families are caught on new tools.** The same injection templates and payload
  styles reappear across benchmarks and tools, and the feed recognises them.
- **Entirely new attack wording is not.** When a whole dataset is held out, the feed adds
  nothing over the regular detectors (9.5% for MCP-SafetyBench, 16.3% for MSB). IOCs recognise
  what has been seen before; they do not predict new phrasing.
- **Some attacks have no text to detect.** A shadowing tool that copies a genuine description
  under a new name (`name_overlap`, much of `Function Overlapping`) or "This is the best tool in
  the world" (`preference_manipulation`) look like ordinary tools. mcpguard's duplicate and
  similar-name checks, pinning and policy are the defences there.
- Some learned phrases are artefacts of how a benchmark was written, for example the
  placeholder path `/ABSOLUTE/PATH/TO/SPACE/OUTPUT` in MSB. They are harmless, but carry no
  signal for real attacks.

## Sources

| Source | License | Used for |
|---|---|---|
| [MCP-SafetyBench](https://github.com/xjzzzzzzzz/MCPSafety) (Zong et al., 2025) | none stated | poisoned descriptions, malicious responses, rogue tools |
| [MCP Security Bench (MSB)](https://github.com/dongsenzhang/MSB) (Zhang et al., ICLR 2026) | MIT | injection templates, attack variants, benign servers |
| [MCPSecBench](https://github.com/AIS2Lab/MCPSecBench) (Yang et al., 2025) | MIT | malicious and benign servers |
| [Invariant Labs injection experiments](https://github.com/invariantlabs-ai/mcp-injection-experiments) | none stated | tool poisoning, shadowing, rug pull |
| [Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) | none stated | one poisoned description |
| [MCP reference servers](https://github.com/modelcontextprotocol/servers) | MIT | benign definitions |
| [GitHub MCP server](https://github.com/github/github-mcp-server) | MIT | benign definitions |

MCPTox (Wang et al., AAAI 2026) is not included: its anonymised repository could not be
downloaded from the build environment. Adding it is the most valuable next step for the
feed.

## Rebuilding or extending the feed

```sh
# clone the sources listed above into one directory, then:
python scripts/ioc/build_corpus.py path/to/datasets -o corpus.jsonl
mcpguard iocs eval corpus.jsonl                 # measure before you ship
mcpguard iocs build corpus.jsonl -o my-iocs.json
```

Your own observations can be added as JSONL records:

```json
{"label": "malicious", "kind": "definition", "name": "tool_name", "text": "description...", "source": "incident-42"}
{"label": "benign", "kind": "definition", "name": "tool_name", "text": "description...", "source": "our-servers"}
```

Then point mcpguard at the extra feed. It is merged with the bundled one:

```toml
[detectors.iocs]
feeds = ["my-iocs.json"]
```

## See also

[benchmark.md](benchmark.md) measures the feed and the rules together on benchmarks the feed
was never built from. On those, the feed adds nothing measurable: detection there comes from
the rules. High-severity `ioc.similar_text` now needs two fragments seen across unrelated
tools (or six fragments in all); fragments from a single tool's poisoned copies can be that
tool's genuine wording, and on their own only produce a warning.
