# HERMES HANDOFF — 4 agents (3 reference, 1 aggregator)

Project: **mcp-purple-lab** at `C:\Users\PC\Desktop\PC2.0\mcp-purple-lab`
Goal: **find, fix, and improve** an already-working MVP. It runs green today —
your job is to make it hold up to real reviewers.

---

## 0. Current state (read before touching anything)

Working, verified on Windows, Python 3.11:

```
lab/
  run.py            # scenario -> trace -> rules -> report, exit 0/1/2
  summary.py        # coverage matrix over all scenarios
  mcp_client.py     # min stdio MCP client (initialize, tools/list, tools/call)
  trace.py          # JSONL trace, line-numbered (rules cite line numbers)
  evaluate.py       # Sigma-style rule engine (OR, *_contains, allowlists,
                    # cross-line track_field for schema drift)
  servers/          # evil, rugpull, confused_deputy, benign (fake MCP servers)
  scenarios/        # tool_poisoning, schema_rugpull, confused_deputy,
                    # benign_control
  rules/            # mcp_tool_poisoning, mcp_schema_drift,
                    # mcp_oauth_confused_deputy
tests/test_end_to_end.py  # 7 tests, incl. anti-fabrication guards
BUILD_GUIDE.md            # original build brief
AGENTS.md                 # contracts: evidence, control must stay clean, stdlib+pyyaml
README.md, out/           # docs + generated traces/reports
```

Verified behavior: `python lab/summary.py` → 3 attacks DETECTED by their
expected rule with real trace-line evidence, benign control clean, exit 0.
`python -m unittest discover -s tests -v` → 7/7 OK.

---

## 1. Known weak spots — every one of you should try to prove me wrong here

1. **Agent is a script, not a model.** `agent_script` is a static call list.
   Nothing tests whether an agent would actually *follow* the poisoned tool
   description. The strongest fix would be a `lab/llm_agent.py` driver
   (BYOK, e.g. OpenRouter/Groq) OR a documented limitation in the README.
2. **Rule engine is only ~10 match keys.** No regex on args, no negation, no
   frequency/time-window rules, no "call sequence" patterns. See
   `evaluate.py` docstring for the current key list.
3. **No granularity in reports.** Pure pass/fail; no severity-weighted
   coverage score, no per-scenario confidence, no MITRE ATLAS linkage
   beyond a free-text field.
4. **Windows-only validation.** Servers spawn via `sys.executable` with
   `PATHEXT`-style shim handling in `mcp_client.resolve_command`; CI
   (.github workflows) was never written for this repo.
5. **No negative-detection tests.** Nothing asserts the rules *fail* to fire
   on a novel benign-but-suspicious trace (e.g. a legit `https://app.example/upload`).
   Only the one benign control exists — rule over-fitting is unproven.
6. **Trace has no tamper-evidence** (no hashes), despite the repo's own
   philosophy of "evidence beats claims" (see sibling project call-anything).
7. **No CI**, no LICENSE file on disk, no `pyproject.toml`.
8. `lab/summary.py` columns are hardcoded-width and degrade on long rule ids.

---

## 2. Roles — 3 reference agents (proposers), each a different lens

Each of you: **find issues, produce a concrete diff or patch proposal, and
report findings ranked worst-first with evidence.** Do not rewrite files
owned by another agent — propose, don't collide.

### Reference Agent 1 — "Red: attack realism" (owns lens: lab/servers, lab/scenarios)
Review the attacks like a real adversary would:

- Are the scenarios realistic for how MCP attacks actually happen in the
  wild now (tool poisoning via descriptions, rug-pull after session start,
  OAuth confused deputy)? Anything staged that a reviewer would call theater?
- Are tool descriptions/schemas convincing to an actual agent? Would a model
  actually make the `send_canary` call, or is the "injection text" implausible?
- Missing attacks worth adding (candidates: cross-server confused deputy via
  two servers, tool-chain permission escalation, memory/context poisoning,
  `tools/list` shadowing / impersonation of a popular server name,
  MCP resource-subscription abuse)?
- Do the fake servers leak reality anywhere? Confirm all canary domains are
  `*.example` and nothing contacts the network.

### Reference Agent 2 — "Blue: detection quality" (owns lens: lab/rules, lab/evaluate.py)
Review the defense like a detection engineer:

- Find every over-broad rule: craft benign-but-suspicious trace lines that
  fire the rules (e.g. `tool_name_contains: ["send_"]` will hit any tool
  named `send_report`). Argue which matches are too loose and specify tighter
  conditions using existing engine keys.
- Find every under-broad rule: an evasion of the current attacks. E.g. could
  the poisoned exfil be re-pointed to bypass `arguments_contains_url`? Would
  a single drift between two `tools/list` calls that the rule's `track_field`
  misses (result ordering?) slip through?
- Propose the minimum engine additions with the highest payoff (regex match
  key? negation? sequence rules?) with a concrete rule example for each.

### Reference Agent 3 — "Harness: robustness & proof" (owns lens: run.py, mcp_client.py, trace.py, tests/)
Review the machinery:

- Re-run the full suite and SB-verify: `python lab/summary.py`,
  `python -m unittest discover -s tests -v`. Report anything flaky or
  Windows-dependent.
- Read the anti-fabrication guards
  (`tests/test_end_to_end.py::test_every_fired_rule_has_evidence`,
  `TestRuleEngine::test_evidence_lines_exist`). Can you break them? If yes,
  that's a critical finding — write the failing case as a test.
- Check report correctness: do `report.json` fields match the markdown
  render? Does exit code 1 actually mean "missed attack" in every path?
- Check for real defects: file handle leaks (`lab/trace.py` `Trace` has no
  context manager), spawn failure handling, servers that hang on stderr
  filling, PATH shim resolution for non-`python` commands.

### Aggregator — "Merge, decide, ship"
Owns: final diff, conflict resolution, `HACK/` decisions, release hygiene.

- Collect all three reports. Dedupe overlapping findings, rank by
  (exploitability x likelihood x effort).
- **Resolve disagreements**: where a "tighter rule" from agent 2 makes agent
  1's attack undetectable, decide which side yields and write the rationale
  into the commit message. Same principle as BUILD_GUIDE: best-of-N, not
  first-come.
- Enforce invariants after every change: the 3 attacks must still be
  DETECTED, the control must still raise zero rules, 7+ tests green. Add
  regression tests for every fix.
- Missing-hygiene pass: `LICENSE` (MIT), `.gitignore` (`out/`, `__pycache__`),
  CI workflow (GitHub Actions: `pip install pyyaml`, run summary + unittest),
  README updates (limitations section, roadmap checkboxes).
- Do NOT merge anything that breaks the evidence contract in `AGENTS.md`.

---

## 3. Rules of engagement

1. Run `python lab/summary.py` + `python -m unittest discover -s tests -v`
   before and after your change. Paste both outputs in your report.
2. No new dependencies without the aggregator's sign-off. PyYAML is the
   cap; stdlib beyond that. No network at runtime, ever.
3. No real URLs in scenarios or canaries — `*.example` only.
4. A fix without a test is not a fix. A detection without trace-line
   evidence is not a detection.
5. Keep `lab/*.py` under ~200 lines; split if bigger (harness rule).
6. Small commits. Message format: `fix|feat|docs(area): what + why`.

## 4. Report format (every agent)

```
## Findings (ranked worst-first)
### N. <severity> <title>
- where:   file:line
- symptom: what breaks / what a reviewer will say
- repro:   exact commands + output
- fix:     concrete patch, or "proposal" + diff
- test:    the test that would catch a regression
## Invariants check
(paste summary.py + unittest output)
## Deliberately out of scope
(anything you found but intentionally did not touch)
```
