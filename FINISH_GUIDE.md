# FINISH GUIDE — mcp-purple-lab (final round: merge, extend, ship v0.2)

Hand this file to 4 agents. 3 are the **same reference agents** as HERMES_GUIDE
(Red / Blue / Harness), 1 is a **fresh aggregator**. The aggregator role is
reassigned for this round; the three reference lenses and their ownership stay
exactly as in HERMES_GUIDE §2.

Work happens in `.`.
Predecessors: `BUILD_GUIDE.md` (built the MVP) -> `HERMES_GUIDE.md` (hardened it).

---

## 0. Current state (verified on the tree as pinned, do not re-litigate)

Green and reviewer-ready at the base commit:

```
python lab/summary.py                      -> 3 attacks DETECTED, control clean, exit 0
python -m unittest discover -s tests -v    -> 7/7 OK
```

Already fixed since HERMES (confirmed in code — do NOT redo):

| HERMES weak spot | Where it landed |
|---|---|
| exit-code conflation (setup vs miss) | `lab/run.py` — setup failures raise, `main()` maps to 2 |
| OR discarding sibling keys | `lab/matching.py::line_matches` — siblings always AND |
| typo'd match key = silent false negative | `matching.py::validate_match` -> `RuleError` at load |
| 200-char excerpt hiding tail drift | `track_field` on full field/digest (`tools_digest`) |
| no tamper-evidence on traces | `lab/trace.py` — SHA-256 hash chain + `verify_trace` |
| `Trace` handle leak | context manager in `trace.py` |
| hardcoded summary columns | `lab/summary.py::_widths` |
| no CI / LICENSE / pyproject | `.github/workflows/ci.yml` (2-OS), MIT, `pyproject.toml` |
| lab only ran from repo root | `run.py` passes `cwd=REPO` to spawn |

CI additionally enforces two contracts no one may weaken: file size
(`lab/*.py` <= 220 lines) and canary hygiene (`*.example` / `*.invalid` only).

---

## 1. What is actually left (this is the whole job)

### 1a. Unmerged Red proposals — adjudicate, don't rebuild

`HACK/attack_scenarios/scratch/lab/` holds proposals the last aggregator never merged. They
target the lab from the AFTER-hermes state, so re-verify before applying:

| proposal | what it proves |
|---|---|
| `servers/evil_server_v2.py` + `scenarios/tool_poisoning_v2.yaml` | vendor-style plausible description; exfil destination arrives via a `get_settings` **tool result**, not the tool description — defeats description-only rules |
| `servers/rugpull_late_server.py` + `scenarios/rugpull_late.yaml` | append-only rug-pull; mutation lands past old 200-char window |
| `servers/listchanged_server.py` + `scenarios/rugpull_notify.yaml` | spec-compliant rug-pull via `notifications/tools/list_changed` — legitimate traffic hiding the same attack |
| `scenarios/*` + `rules/` + engine edits | the v2 rule/engine changes Red proposed to catch them |

Blue's probe artifacts live in `HACK/blue/` (`mk_traces.py`, `run_probe.py`) —
reuse them as the negative-detection corpus (see 1c).

### 1b. README roadmap — every box unchecked

- [ ] more scenarios: cross-server confused deputy (two servers), tool-chain
      permission escalation, tools/list shadowing (impersonate a popular name)
- [ ] severity-weighted coverage score in the summary (not just pass/fail)
- [ ] MITRE ATLAS IDs + descriptions rendered into `report.md`
- [ ] SIEM export: emit Sigma-compatible rules from the lab's rule YAML
- [ ] harness API (`lab/harness.py`): point the trace+rules pipeline at an
      EXTERNAL MCP server, same contract as the scenarios
- [ ] real-LLM agent driver OR an explicit `README.md` "Limitations" section
      stating the agent is scripted (documented limitation is an acceptable,
      ship-blocking deliverable; BYOK driver is a stretch goal — needs
      aggregator sign-off because of the no-network constraint: keep it out of
      `lab/`, opt-in module, never in CI)

### 1c. Gaps a reviewer will still find

1. **Negative-detection tests missing.** Only one benign control proves nothing
   about over-fit. Required: `tests/test_negatives.py` asserting NO rule fires
   on benign-but-suspicious traces — legit `https://app.example/upload` tool
   call, a `send_report` tool, a benign `tools/list_changed` notification.
   Build from `HACK/blue/mk_traces.py`.
2. **New scenarios must ship with positive AND negative tests** in the same
   commit (AGENTS.md rule 6 energy, applied to every scenario).
3. **Root hash is not anchored.** `trace.py` says it honestly but the report
   could carry the root hash (last line's `hash`) so CI logs anchor it.
4. `tests/test_evidence_lines_exist` passes vacuously on a fresh clone (out/
   gitignored). CI order papers over it; make the test self-contained
   (generate one trace via `run_scenario` into a temp dir).
5. README/AGENTS/BUILD/HERMES are four docs; FINISH round adds a fifth. Final
   README must be the single honest entrypoint: quickstart, contracts,
   limitations, roadmap-with-truth.

---

## 2. Roles (3 references unchanged, new aggregator)

Reference agents keep HERMES_GUIDE §2 lenses, ownership, and report format.
This round their job is PROPOSE, one batch, against the current tree:

- **Red** — merge-readiness pass over `HACK/attack_scenarios/scratch`: rebase the 3 proposals
  onto current `evaluate.py`/`matching.py`, add ONE new attack from §1b
  (cross-server confused deputy is the strongest), with scenario + server +
  expected rule. Flag any current rule the new attacks evade.
- **Blue** — attack the merged set: write the negative corpus (§1c.1), prove
  each tightened rule still catches the v2 attacks, and specify the minimum
  engine additions (sequence? source-of-argument tracking: "url arg value was
  first seen in a tools/call.result, not user input") with rule examples.
- **Harness** — the two test fixes (§1c.1, §1c.4), root-hash-in-report, then
  `harness.py` skeleton for external servers behind one clean entrypoint.

**Aggregator (new — this round's decision-maker):**

1. Read `HACK/decisions.md`; extend it, don't replace it. Record every
   adjudication in the Decision record (currently empty).
2. Apply order (unchanged): harness -> engine -> scenarios+rules+tests ->
   reporting/docs.
3. Enforce the invariants after EVERY batch, paste output in the commit msg:
   `summary.py` exit 0 with 3+N attacks DETECTED, control zero-fire,
   `unittest` green, canary hygiene, file-size contract.
4. Conflict rule unchanged (AGENTS.md): precision beats recall; rule yields,
   rationale in commit message.
5. Ship v0.2: README rewritten (status of every roadmap box honest, Limitations
   section present), roadmap boxes checked or removed, version bump,
   tagged `v0.2`.

---

## 3. Definition of done

- [ ] All 3 `HACK/attack_scenarios/scratch` proposals merged or rejected-with-rationale in
      `HACK/decisions.md` (no third possibility)
- [ ] At least 2 new attack scenarios (one from §1b list), each with
      positive+negative test in the same commit
- [ ] `tests/test_negatives.py`: benign-but-suspicious traces fire ZERO rules
- [ ] `test_evidence_lines_exist` no longer depends on committed `out/`
- [ ] Root hash in `report.json`; `report.md` shows ATLAS id + title
- [ ] Summary shows severity-weighted score column (pass/fail rows still shown)
- [ ] README single entrypoint: quickstart, contracts, Limitations, roadmap
      with real statuses. AGENTS.md/BUILD_GUIDE.md/HERMES_GUIDE.md get a
      one-line header: status + superseded-by-what
- [ ] `python lab/summary.py` exit 0; `python -m unittest discover -s tests -v`
      fully green; CI green on ubuntu+windows
- [ ] No new runtime dependency. No network at runtime. `*.example` only.
- [ ] Version `0.2.0` in `pyproject.toml`, annotated tag `v0.2`

## 4. Rules of engagement (inherited, binding)

1. Run `summary.py` + `unittest` before and after every change; paste both.
2. PyYAML is the dependency cap. No network at runtime, ever.
3. Canary hosts `*.example` / `*.invalid` only.
4. A fix without a test is not a fix. A detection without trace-line
   evidence is not a detection.
5. `lab/*.py` under ~200 lines (CI fails at 220) — split, don't bloat.
6. Small commits: `fix|feat|docs(area): what + why`. No force-push.
7. References write only under `HACK/<role>/`; only the aggregator touches
   `lab/`, `tests/`, docs.

## 5. Report format (every agent, as HERMES §4)

```
## Findings / Proposals (ranked worst/strongest-first)
### N. <severity> <title>
- where:  file:line
- what:   symptom or payoff
- repro:  exact commands + output
- fix:    concrete patch under HACK/<role>/
- test:   the test that locks it in
## Invariants check
(summary.py + unittest output)
## Deliberately out of scope
```
