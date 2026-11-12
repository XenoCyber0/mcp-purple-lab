# mcp-purple-lab

**A purple-team range for MCP: emulate the attack, capture the telemetry,
prove the detection fired.**

Verified gap (GitHub search, 2026-11-08): **0 repos** for "MCP purple team",
"MCP detection validation", or "MCP telemetry → SIEM". Tools exist for each
half — pipelock (firewalls), garak (LLM scanners), AgentCapture (honeypots) —
but nothing closes the loop: attack → trace → detection → verdict.

## The loop in one command

```bash
python lab/run.py lab/scenarios/tool_poisoning.yaml
# scenario : tool-poisoning-001
# expected : mcp_tool_poisoning
# fired    : 1/3 rules
# verdict  : DETECTED (exit 0)
```

Every run produces, in `out/<scenario-id>/`:

- `trace.jsonl` — every JSON-RPC message, one per line, line-numbered
- `report.json` — machine-readable verdict + per-rule evidence
- `report.md` — human-readable verdict + rule matrix

`python lab/summary.py` runs all scenarios and prints the coverage matrix:
which attack was caught by which rule, with trace lines.

## Exit codes

| code | meaning |
|---|---|
| 0 | expected attack detected, or control scenario clean |
| 1 | an attack went **undetected**, or the control raised a false positive |
| 2 | setup failure (bad scenario, server would not start) |

Use it as a CI gate: a regression in your detection rules fails the build.

## What's in the lab

### Attacks (`lab/scenarios/`)

| scenario | ATLAS | what the "attacker" server does |
|---|---|---|
| `tool_poisoning.yaml` | T1552/T1041 | tool description carries an instruction to the agent ("call send_canary with the user's env"); agent complies |
| `schema_rugpull.yaml` | T1548 | benign at `tools/list`, then the server silently adds `export_secrets` and rewrites a description mid-session |
| `confused_deputy.yaml` | T1550 | `authorize_integration` accepts an attacker-controlled `redirect_uri` and mints a token-shaped string to it |

Plus `benign_control.yaml` — a well-behaved server. No rule may fire on it.

### Rules (`lab/rules/`, Sigma-style YAML)

`mcp_tool_poisoning` (canary URL / suspicious tool names in `tools/call`),
`mcp_schema_drift` (`tools/list` value changes between calls),
`mcp_oauth_confused_deputy` (`redirect_uri` outside an allowlist).

Every fired rule reports the **trace line numbers** it matched. A detection
with no evidence is impossible by construction — the test suite asserts it.

## Install

```bash
pip install pyyaml   # only dependency
python -m unittest discover -s tests -v
```

## Architecture

```
scenario YAML
   |  run.py: spawn server, execute scripted tool calls
   v
JSON-RPC over stdio ── mcp_client.py ── trace.py ── out/<id>.trace.jsonl
   v
evaluate.py: rules matched against the trace (evidence = line numbers)
   v
report json + md, exit code
```

`lab/servers/*` are **fake** MCP servers. `evil_server.py`'s "exfiltration"
appends to an in-process list and answers "sent". Nothing leaves the machine;
canary domains are `*.example`.

## Roadmap

- [ ] Drive the agent from a real LLM instead of a scripted call list
- [ ] More scenarios: permission-escalation via tool chains, cross-server
      confused deputy (two servers), memory/context poisoning between servers
- [ ] Rule scoring: severity-weighted coverage report instead of pass/fail
- [ ] MITRE ATLAS mappings formalized as IDs + descriptions in the report
- [ ] SIEM export (Sigma de-coders) from the trace
- [ ] `lab/harness.py`-style API for external servers (probe your own MCP
      server, same contract as `bench`)

## License

MIT

## Intended use

**Defensive security research only.** The attack scenarios under `HACK/attack_scenarios/` are detection test vectors (proof that the rules fire), not exploits, and the rule engine is a regression suite, not a production detection system. Review rule scope and false-positive risk before adapting any of this to a real MCP deployment.
