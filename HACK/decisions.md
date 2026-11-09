# Aggregator coordination log — mcp-purple-lab review

## Baseline (pinned before any edit)
- `HACK/baseline_summary.txt` — 3 attacks DETECTED by their expected rule, benign control raises zero rules, `SUMMARY_EXIT=0`.
- `HACK/baseline_tests.txt` — 7/7 OK, `TEST_EXIT=0`, but 4 × `ResourceWarning: unclosed file` at `tests/test_end_to_end.py:28` and `:65`.
- Repo is **not** a git repository. `init` + baseline commit happens before the first patch so every change is diffable.

## Invariants (gate on every batch)
1. 3 attacks still DETECTED by their expected rule.
2. Benign control raises zero rules.
3. stdlib + PyYAML only. No new runtime deps. No network at runtime.
4. Canary hosts `*.example` / `*.invalid` only.
5. `lab/*.py` under ~200 lines — split rather than bloat.
6. Every fix ships with a test; every detection cites trace lines.

## Ownership (proposers write only under HACK/)
- Red → `lab/servers/`, `lab/scenarios/`
- Blue → `lab/rules/`, `lab/evaluate.py`
- Harness → `lab/run.py`, `lab/mcp_client.py`, `lab/trace.py`, `tests/`
- Aggregator → everything applied, plus `LICENSE`, `.gitignore`, `pyproject.toml`, CI, README.

## Apply order (minimizes collision)
1. **Harness** — stabilize the machine (handles, exit codes, guard breakages) before anything changes what it measures.
2. **Engine** — new match keys, additive only; re-verify baseline.
3. **Scenarios + rules together** — never land a scenario without its rule and its positive+negative tests in the same commit.
4. **Reporting/hygiene** — `summary.py` dynamic columns, severity/MITRE fields, LICENSE/CI/pyproject/README.

## Conflict rule
Where a tighter rule (Blue) makes a realistic attack (Red) undetectable: prefer adding the minimum engine primitive that satisfies both. If that is impossible, the **rule yields** — precision beats recall on a demo whose value is non-false-positive detection. Rationale recorded here and in the commit message.

## Decision record
_(empty — filled as proposals are adjudicated)_
