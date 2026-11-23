# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] — 2026-11-23

The interoperability release: the lab accepts the framing real MCP harnesses
emit, fails a silent server instead of a CI runner, and compiles each rule once.

### Added
- `lab/run.py --format json` — one machine-readable report per scenario, with
  `exit_code`, `detected`, `duration_ms`, `results`, and the evidence line numbers.
- Per-request deadlines. `READ_TIMEOUT` is 10s by default and a scenario may set
  `timeout:`. A silent server is killed and reported as exit 2.
- Argv-form `server:` in a scenario (a YAML list), alongside the string form.
- `docs/HARNESSES.md` and `examples/harnesses/` — the stdio compatibility matrix
  and copy-paste configs for Claude Desktop, Claude Code, Cursor, VS Code,
  Windsurf, Cline, Continue, Zed, Goose, Roo Code, MCP Inspector, and CI.
- `HACK/bench/v2.0.0.json` — repeated-median timings against the v0.1.0 tag.
- Sigma export (`lab/export_sigma.py`, `sigma/*.yml`) from #5.
- Severity-weighted coverage score (`summary.py --threshold`) from #6.

### Fixed
- An invalid regex in a rule exited 1 ("attack missed") because `re.error` is not
  a `ValueError`. Patterns compile at load now and raise `RuleError` -> exit 2.
- String JSON-RPC ids were rejected. Ids accept `String|Number`; `true` is still
  refused so it cannot alias id 1.
- An out-of-order pipelined response aborted the session. It is buffered by id and
  returned when its request is read.
- A server-initiated request (`method` + `id`) was treated as a response. It is
  answered `-32601`, recorded as `server.request`, and the run continues.
- Server commands were split on spaces, so a checkout under "Program Files" died
  as a missing file. Parsing uses `shlex`; a quoted path works on both OSes.
- The evidence test depended on `out/` from a previous summary run. It now
  regenerates its own traces under `tempfile`.
- Duplicate rule ids silently overwrote one matrix column; loading rejects them.

### Performance
| path | v0.1.0 | v2.0.0 | delta |
|---|---|---|---|
| `evaluate_all`, one trace | 91.9 us | 75.4 us | -18% |
| engine, per trace line | 4.84 us | 3.77 us | -22% |
| coverage matrix | 0.644 s | 0.568 s | -11.8% |
| one scenario (median) | 284.5 ms | 274.0 ms | -3.7% |

Regexes compile once at rule load instead of once per line per rule, arguments
are serialized once per line, and the rules directory is re-parsed only when a
file's `(name, mtime_ns, size)` signature changes. Scenario wall time remains dominated
by interpreter startup; the per-line figure is the part rules control.

### Compatibility
- Exit codes are unchanged: 0 detected/clean, 1 missed or false positive, 2 setup failure.
- stdio framing: integer or string ids, interleaved notifications, out-of-order
  pipelined replies, `-32601` for server-initiated requests.
- All four lab servers pass a pipelined `initialize` + `tools/list` handshake
  under the framing the harnesses use (`tests/test_v2.py`).
- Lab servers run under `-I`, so an inherited `PYTHONPATH` cannot change the run.
- Runtime dependencies remain `PyYAML` only; no network I/O.

### Notes
- 36 tests, up from 21 (7 at v0.1.0).
- The three attack scenarios and the benign control are unchanged; v2 is a
  compatibility and speed release, not a new attack.

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

[2.0.0]: https://github.com/XenoCyber0/mcp-purple-lab/compare/v0.1.0...v2.0.0
[0.1.0]: https://github.com/XenoCyber0/mcp-purple-lab/releases/tag/v0.1.0
