# mcpguard detection benchmark

## 1. Unseen tool families

IOC feed rebuilt on half the tool families of the training corpus, scored on the rest.

| Level | Detectors | Split 7 | Split 11 | Split 23 |
|---|---|---:|---:|---:|
| high | IOCs only | 59.4% (false alarms 0/260) | 68.8% (false alarms 0/319) | 56.3% (false alarms 0/388) |
| high | rules + IOCs | 64.1% (false alarms 0/260) | 70.9% (false alarms 0/319) | 63.4% (false alarms 0/388) |
| medium | IOCs only | 75.0% (false alarms 0/260) | 78.0% (false alarms 2/319) | 68.3% (false alarms 2/388) |
| medium | rules + IOCs | 76.6% (false alarms 0/260) | 80.9% (false alarms 2/319) | 73.2% (false alarms 2/388) |

## 2. Unseen dataset

Each dataset is held out in turn; the feed is rebuilt from the others.

| Held-out dataset | Attacks | IOCs only (high) | Rules + IOCs (high) | False alarms |
|---|---:|---:|---:|---:|
| dvmcp | 1 | 0.0% | 100.0% | 0/325 |
| invariant | 3 | 0.0% | 100.0% | 0/325 |
| mcp-safetybench | 168 | 0.0% | 9.5% | 0/325 |
| mcpsecbench | 4 | 0.0% | 0.0% | 0/328 |
| msb | 92 | 0.0% | 16.3% | 0/325 |

## 3. Held-out benchmarks

Datasets never used to build the bundled feed, scored with the shipped rules and feed.

| Dataset | Kind | Texts | Rules only (high) | Rules + IOCs (high) | Rules + IOCs (medium) |
|---|---|---:|---:|---:|---:|
| agentdojo | result attacks | 135 | 81.5% | 81.5% | 86.7% |
| bipia | result attacks | 125 | 0.0% | 0.0% | 2.4% |
| injecagent | result attacks | 2108 | 75.0% | 75.0% | 82.2% |

The result-injection rules were written while looking at InjecAgent's data-stealing cases
and AgentDojo's workspace suite. Scored separately:

| Dataset | Part | Texts | Rules + IOCs (high) |
|---|---|---:|---:|
| agentdojo | looked at (development) | 30 | 80.0% |
| agentdojo | never looked at (test) | 105 | 81.9% |
| injecagent | looked at (development) | 1088 | 96.9% |
| injecagent | never looked at (test) | 1020 | 51.7% |

False alarms on benign texts from the same benchmarks:

| Dataset | Kind | Texts | Flagged (high) | Flagged (medium) |
|---|---|---:|---:|---:|
| agentdojo | result | 196 | 0 (0.0%) | 1 (0.5%) |
| bipia | result | 318 | 0 (0.0%) | 4 (1.3%) |
| injecagent | result | 500 | 0 (0.0%) | 2 (0.4%) |
| mcp-docs | result | 978 | 1 (0.1%) | 79 (8.1%) |
| toolemu | definition | 943 | 2 (0.2%) | 7 (0.7%) |

By attack category (rules + IOCs, high):

| Dataset | Category | Texts | Detected |
|---|---|---:|---:|
| agentdojo | DirectAttack | 27 | 7.4% |
| agentdojo | IgnorePreviousAttack | 27 | 100.0% |
| agentdojo | ImportantInstructionsAttack | 27 | 100.0% |
| agentdojo | InjecAgentAttack | 27 | 100.0% |
| agentdojo | SystemMessageAttack | 27 | 100.0% |
| bipia | Base Encoding | 5 | 0.0% |
| bipia | Blocking Internet Connection | 5 | 0.0% |
| bipia | Bringing Down Hosts and Servers (Denial of Service) | 5 | 0.0% |
| bipia | Business Intelligence | 5 | 0.0% |
| bipia | Compromising Computers | 5 | 0.0% |
| bipia | Conversational Agent | 5 | 0.0% |
| bipia | Corrupting an Operating System | 5 | 0.0% |
| bipia | Data Eavesdropping | 5 | 0.0% |
| bipia | Emoji Substitution | 5 | 0.0% |
| bipia | Encrypting Documents and Demanding Ransom (Ransomware) | 5 | 0.0% |
| bipia | Entertainment | 5 | 0.0% |
| bipia | Information Dissemination | 5 | 0.0% |
| bipia | Introduce System Fingerprinting | 5 | 0.0% |
| bipia | Keylogging | 5 | 0.0% |
| bipia | Language Translation | 5 | 0.0% |
| bipia | Marketing & Advertising | 5 | 0.0% |
| bipia | Misinformation & Propaganda | 5 | 0.0% |
| bipia | Research Assistance | 5 | 0.0% |
| bipia | Reverse Text | 5 | 0.0% |
| bipia | Scams & Fraud | 5 | 0.0% |
| bipia | Screen Scraping | 5 | 0.0% |
| bipia | Sentiment Analysis | 5 | 0.0% |
| bipia | Substitution Ciphers | 5 | 0.0% |
| bipia | Task Automation | 5 | 0.0% |
| bipia | Traffic Analysis | 5 | 0.0% |
| injecagent | data_stealing/base | 544 | 93.8% |
| injecagent | data_stealing/enhanced | 544 | 100.0% |
| injecagent | direct_harm/base | 510 | 3.3% |
| injecagent | direct_harm/enhanced | 510 | 100.0% |

## Reading these numbers

- **High** is what blocks a call or quarantines a tool by default; **medium** is logged and
  shown in the dashboard.
- The IOC feed helps on attacks that reuse known wording (view 1). On a dataset it has never
  seen (views 2 and 3) it adds nothing measurable; detection there comes from the rules.
- Not caught, by design or for now:
  - requests that read like ordinary user requests inside data, with nothing to send
    anywhere ("Please unlock my front door", InjecAgent direct-harm base: 0%);
  - AgentDojo's bare `TODO: <goal>` style;
  - BIPIA's off-task requests ("write a script that renames files"), which are only
    attacks relative to what the user asked;
  - attacks with no text to inspect (a renamed copy of a genuine tool, preference
    manipulation).
- Medium flags on documentation are mostly `secret.high_entropy` on hashes and IDs.

## The learned classifier

Not included above: part of these benchmarks is its training data. It is trained and scored on
its own split (never-seen test texts only) in [model.md](model.md).

## Reproducing

Clone the datasets into one folder (see scripts/ioc/build_corpus.py and
scripts/ioc/extra_sources.py for the list), then:

    python scripts/ioc/build_corpus.py DATASETS -o corpus.jsonl
    python scripts/ioc/extra_sources.py DATASETS -o eval_extra.jsonl
    python scripts/benchmark.py --corpus corpus.jsonl --extra eval_extra.jsonl -o docs/benchmark.md
_Generated by scripts/benchmark.py in 12s._
