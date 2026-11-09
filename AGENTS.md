# Agent contract for mcp-purple-lab

You are contributing to a lab that CLOSES THE PURPLE-TEAM LOOP for MCP:
an attack is emulated, telemetry is captured, detection rules are evaluated,
and the report proves whether the defense actually fired.

## Ground rules

1. **Attacks are simulated against lab targets only.** Every `lab/servers/`
   file is a fake server that runs on localhost over stdio. No real system is
   ever touched. All canary/attacker URLs must use reserved example domains
   (`*.example`) so the lab cannot be aimed at anything real.

2. **Evidence or it did not happen.** A detection that cannot cite the exact
   trace line numbers it matched is not a detection. The test suite enforces
   this: `test_every_fired_rule_has_evidence` fails any rule that fires on
   nothing.

3. **Never fabricate a detection.** Do not mark a scenario "detected"
   manually. The engine decides from the trace. Reports are generated output,
   never hand-written.

4. **Respect the formats.** Scenarios match `lab/scenarios/*.yaml`; rules
   match `lab/rules/*.yaml`; the engine keys are documented in
   `lab/evaluate.py`'s docstring. If you need a new match key, add it to the
   engine and document it there in the same commit.

5. **Exit codes are the API.**
   0 = expected attack detected (or control clean), 1 = attack missed or
   false positive on the control, 2 = setup failure. CI depends on these.

6. **Keep the control honest.** `benign_control.yaml` must raise zero rules.
   If yours fires on it, your rule is too broad -- fix it there, not by
   loosening the scenario.

7. **stdlib + PyYAML only.** No MCP SDK, no LLM, no network at runtime. Same
   constraint as call-anything: the whole lab runs offline in CI.

8. **Small files, focused commits.** Servers under ~120 lines, run.py under
   ~200. If it grows, split it.

## The contract in one table

| you want to | you run |
|---|---|
| run one attack and see the verdict | `python lab/run.py lab/scenarios/<id>.yaml` |
| run everything as a coverage matrix | `python lab/summary.py` |
| validate the lab | `python -m unittest discover -s tests -v` |
| add an attack | new server in `lab/servers/` + scenario YAML + expected rule |
| add a detection | new rule YAML in `lab/rules/` (match keys: see engine docstring) |

## Roles (for multi-agent work)

- **Attacker** — owns `lab/servers/`, `lab/scenarios/`: plays the red side,
  realistic MCP attack, correct ATLAS technique id.
- **Detection engineer** — owns `lab/rules/`, `lab/evaluate.py`: plays the
  blue side, precise rules with evidence.
- **Harness engineer** — owns `lab/run.py`, `lab/mcp_client.py`, `lab/trace.py`:
  the plumbing that makes both sides comparable.
- **Aggregator** — reads all proposals, resolves disagreements (a rule that
  fires everything is as useless as one that fires nothing), merges, and
  records the rationale in the commit message.
