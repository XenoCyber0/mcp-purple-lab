# Contributing to mcp-purple-lab

Thanks for wanting to close the purple-team loop for MCP. This project is small on purpose: **stdlib + PyYAML, no framework, no network I/O at runtime.**

## The contract

A contribution is complete when **all three** exist and agree:

| Piece | Where | Rule |
|---|---|---|
| Scenario | `lab/scenarios/<name>.yaml` | describes the fake server + the scripted agent calls |
| Rule | `lab/rules/<id>.yaml` | a Sigma-style matcher that cites trace lines |
| Test | `tests/` | asserts the rule fires **and** that the cited lines exist in the trace |

If the rule fires but the evidence lines don't exist in the trace, the test suite fails — that check is the whole point of this repo. **A detection without evidence is impossible by construction.**

## Quickstart

```bash
pip install pyyaml
python lab/summary.py                     # all scenarios + coverage matrix
python -m unittest discover -s tests -v   # 7/7 green
```

## Writing a rule

```yaml
id: mcp_example_attack
title: Human-readable title
severity: high            # low | medium | high | critical
confidence: high          # low | medium | high
atlas_technique: T1550    # optional MITRE ATLAS id
match:
  message_type: tools/call
  arguments_keys: ["some_arg"]
  arguments_value_regex: ['^https?://[^/]*\\.example']
```

Available matchers (see `lab/matching.py`):

- `message_type`
- `arguments_keys` / `arguments_value_regex` / `arguments_value_regex_not_in`
- `text_regex` (matches the raw message text)
- `tool_name_regex`
- `track_field` + `on_change` (stateful correlation — used by the schema-drift rule)

**Prefer host-anchored regexes.** A naive `example.com` pattern matches `app.example.evil.com`. Anchor with `(^|\.)` and a boundary class `([:/?#]|$)`.

## Writing a scenario

```yaml
id: example-attack-001
expected_rule: mcp_example_attack
server: lab/servers/evil_server.py        # a fake, local-only server
steps:
  - call: list_tools
  - call: attack_tool
    arguments: {"some_arg": "https://canary.example"}
```

The servers under `lab/servers/` are **fake**. Nothing leaves the machine; canary domains are `*.example`. Your scenario must keep it that way — a contribution that touches the network is out of scope.

## Ground rules

- **Stdlib only** outside `lab/rules/*.yaml` (PyYAML is the single dependency).
- Every file under `lab/*.py` stays under ~200 lines — CI enforces this.
- Tests must be deterministic: no network, no clocks, no randomness without a fixed seed.
- Rule IDs are `<snake_case>` and stable — they end up in reports and SIEM exports.
- Prefer a new scenario over a more permissive rule. **A rule that never false-positives on the benign control matters more than one that catches more attacks.**

## Style

- Python: 4-space indent, stdlib `typing` annotations on public functions, no `print()` outside `lab/report.py`, `lab/summary.py` and `lab/export_sigma.py` (those are the CLI surfaces).
- YAML: 2-space indent, comments explaining *why* a matcher is host-anchored.
- Commit messages: conventional commits (`feat(rules):`, `test(scenarios):`, `docs:`, `fix:`).

## Run the full gate before you open a PR

```bash
python lab/summary.py && python -m unittest discover -s tests -v
```

CI runs the same commands on Ubuntu and Windows with Python 3.11.

## Code of conduct

Be rigorous, be kind, and argue about the rules, not the person. This is a security research project — every claim should be backed by a trace line.

## Reporting a security issue in *this* repo

See [SECURITY.md](SECURITY.md). (Note: the "security issues" here are usually bugs in the *lab*, not vulnerabilities in real MCP servers.)
