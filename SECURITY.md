# Security policy

mcpguard is a security control, so weaknesses in it matter more than ordinary bugs.

## Reporting a vulnerability

Report privately through the repository's **Security → Report a vulnerability** form (GitHub
private vulnerability reporting). Please do not open a public issue for anything that lets
an attacker bypass a policy rule, evade a detector in a way the documented limits do not
already describe, read mcpguard's secrets, forge or hide audit records, or stop the gateway.

Include the version (`mcpguard --version`), the config sections involved, and the smallest
input that shows the problem. `mcpguard test "text"` output is useful for detector bypasses.

## What to expect

Every confirmed report gets a row in [docs/threat-model.md](docs/threat-model.md), a fix, and
a regression test in `tests/test_threats.py`. Fixes are released in the next version and
described in the CHANGELOG under "Security".

## Scope

In scope: the gateway, CLI, dashboard, HTTP endpoint, detectors, audit log.
Out of scope: someone who can already edit the config, key files or code; the AI client;
attacks listed under "Known limits" in the threat model (they are known, not unimportant:
improvements are welcome as ordinary issues).

## Supported versions

The latest release receives security fixes.
