# Security Policy

## Scope of this project

`mcp-purple-lab` is a **defensive** purple-team range. It emulates attacks against fake, local MCP servers so that detection rules can be proven to fire.

**This repo does not contain exploits against real products.** The scenarios under `lab/scenarios/` and `HACK/attack_scenarios/` are detection test vectors. The "malicious" servers under `lab/servers/` run entirely on your machine:

- `evil_server.py`'s "exfiltration" appends to an in-process list and replies `"sent"`.
- No scenario opens a socket to anything outside `localhost`.
- Canary domains are `*.example` (reserved by RFC 2606) and never resolve.

## If you find a bug in the lab

Open a normal issue (label: `bug`) — for example a rule that fires without citing real trace lines, a scenario that touches the network, or a non-deterministic test.

## If you find a vulnerability in a real MCP server or in something this lab uses

Do **not** open a public issue here. Report it to the affected vendor directly, per their security policy, and follow coordinated disclosure.

## Trust model

- **No telemetry, no analytics, no outbound calls** in the lab code paths.
- The only dependency is `PyYAML`.
- The CI workflow (`.github/workflows/ci.yml`) runs on `push` and `pull_request` with read-only repository permissions by default; it executes the repo's own Python against its own fake servers.

## Intended use

Defensive security research, detection-rule validation, and CI gating of MCP telemetry pipelines. Use it only against systems you own or are authorized to test.
