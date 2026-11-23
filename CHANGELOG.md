# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Community health files: `CONTRIBUTING.md`, `SECURITY.md`, issue and PR templates.
- Discussions enabled for rule-format and scenario design threads.
- Severity-weighted coverage score: `lab/summary.py --threshold` gates on a weighted
  score, with `--severity-weights` overrides (`low=1,medium=3,high=5,critical=10` by default).

## [0.1.0] — 2026-11-16

The first public release: a working purple-team loop for MCP.

### Added
- **Lab core** — JSON-RPC/stdio MCP client with id-routed transport, line-numbered trace writer
  (`trace.jsonl`), rule matcher, evaluator, and report writers (`report.json` / `report.md`).
- **4 detection rules** (Sigma-style YAML, `lab/rules/`):
  - `mcp_tool_poisoning` — suspicious tool names / canary URLs in `tools/call`
  - `mcp_schema_drift` — `tools/list` digest changes between calls (schema rug-pull)
  - `mcp_oauth_confused_deputy` — `redirect_uri` outside a host-anchored allowlist
  - `mcp_tool_shadowing` — a later `tools/list` shadows the original definitions
- **4 scenarios** (`lab/scenarios/`): tool poisoning, schema rug-pull, OAuth confused deputy,
  and a benign control that asserts **no** rule fires.
- **Coverage matrix** (`lab/summary.py`) — prints which attack was caught by which rule, with the
  cited trace line numbers.
- **CI gate** (`.github/workflows/ci.yml`) — runs the coverage matrix, the test suite, and the
  file-size contract on Ubuntu and Windows with Python 3.11. Exit codes 0/1/2 make the lab usable
  as a pipeline stage.
- **Evidence assertion** — the test suite fails if a fired rule cites trace lines that don't exist.

### Notes
- One dependency: `PyYAML`. Everything else is stdlib.
- Zero network I/O at runtime; the fake servers stay on `localhost`.
- Defensive research use only.

[Unreleased]: https://github.com/XenoCyber0/mcp-purple-lab/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/XenoCyber0/mcp-purple-lab/releases/tag/v0.1.0
