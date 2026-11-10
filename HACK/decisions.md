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

---

# FINISH round (v0.2) — aggregator decision record

Baseline for this round: commit `10b609b` (checkpoint of the verified six-defect
fixes + matching/report split). Invariants at baseline, run on this tree:

    python lab/summary.py                      -> 3 attacks [X], control zero-fire, exit 0
    python -m unittest discover -s tests       -> 7/7 OK
    wc -l lab/*.py                             -> max 187 (mcp_client), CI cap 220
    canary hygiene                             -> only localhost + *.example/*.invalid

FINISH_GUIDE §0's "already fixed" table is real code on this tree. References
were dispatched against `10b609b` with an explicit do-not-redo list.

## Decision record

D1 (process) — checkpoint before merge. The guide's "base commit" predated the
matching.py/report.py split; committing it first (crouton, step5, hy3 all
converged) means nothing rebases onto the old monolithic evaluate.py.

D2 — rugpull_late (append-only rug-pull). Root cause (200-char excerpt tracking)
was already closed by tools_sha256 (verified via HACK/aggregator/probe.py part
D before and after the fix). Merge as a LOCK-IN scenario for the digest fix,
gated on Red's live run showing mcp_schema_drift fires with line numbers.

D3 — rugpull_notify (notifications/tools/list_changed). Merge only once
McpClient handles JSON-RPC notifications (read-until-matching-id; record; and
client-initiated re-list on tools/list_changed — behavior a real MCP client
 owes anyway, per step5). Draft under HACK/aggregator/scratch/clientv2/;
scenario must NOT also use after_each_call (double-list would double the
drift signal).

D4 — tool_poisoning_v2 (exfil destination arrives via get_settings tool
result). NO current match key sees tool-result content, so the rule-level
fix is out of scope for v0.2 (step5, crouton, hy3 agree). Accepted MINIMUM
(this round): McpClient records the full result as `result` on
tools/call.result (excerpt stays for humans only) — evidence capture without
detection claims. The provenance rule (`arguments_url_seen_in_result`) ships
in v0.3 with Blue's spec. Rationale: recording is two lines and makes the
evasion auditable now; inventing a cross-line provenance engine inside a
release sprint is where precision goes to die.

D5 — rule split. Digest tracking made ANY mid-session tool addition a
critical alert; a benign plugin registration would trip mcp_schema_drift.
Split: mcp_schema_drift stays critical (drift AND suspicious tool call —
schema-rugpull-001 keeps firing because the agent calls export_secrets);
new informational mcp_schema_change fires on digest movement alone
(requires new engine key `on_change`, evidence = first-seen + every change
line). Gives the negative corpus a precise assertion.

D6 — mcp_tool_poisoning branches. Branch 1 (canary/exfil/dump/export_ + URL)
stays high: names that only mean "push data out". Branch 2 (send_/upload_/
post_ + URL + payload key) over-fires on a legit upload_backup carrying
`data` (Blue's required negative case 6). Pending Blue's run: either tighten
payload keys to sensitive markers or downgrade branch 2 to confidence:
medium. Precision beats recall (AGENTS.md 4); the corpus decides, not taste.

D7 — arguments_value_not_in allowlist stays engine-side for v0.2. It reads
trace content only (no scenario coupling, keeps evaluate() a pure function
of trace+rule). Consequence recorded: a cross-server-confused-deputy scenario
whose second server uses a non-localhost callback would FALSE-FIRE, so the
§1b new attack is tools/list shadowing or tool-chain escalation; cross-server
deputy is deferred with the multi-spawn harness (D8).

D8 — new §1b attack = tools/list shadowing (single process, honest MCP
traffic, no fake cross-server). Cross-server confused deputy requires
multi-spawn client changes; deferred to v0.3 as part of harness.py (the guide
marks harness itself a roadmap item; one clean entrypoint only).

D9 — line budget. mcp_client.py is 187 and must absorb notification handling;
CI fails at 220. Split transport out: lab/rpc_stdio.py (framing + id-routed
read loop), mcp_client.py keeps MCP semantics. Draft first, measured, then
merge — never merge-and-pray.

Deferred for v0.2 (documented in README Limitations, not silently skipped):
real-LLM driver (no-network constraint; opt-in only), SIEM/Sigma export,
full harness API, source-of-argument provenance RULE, cross-server deputy.

## Draft landed: notification-aware client (supports D3/D9)

HACK/aggregator/scratch/clientv2/ holds a tested draft (no lab/ edits yet —
Blue and Red are measuring current rules, and a mid-run client change would
stale their evidence):

- rpc_stdio.py — id-routed read loop; id-less messages are notifications,
  recorded and never consumed as responses; mismatched-id response raises.
- mcp_client_v2.py — re-lists on notifications/tools/list_changed (deferred
  so callbacks never re-enter the read loop; re-list line carries reason=);
  tools/call.result now records the FULL result as `result` (D4 evidence).
- Proof (mcp_client_v2_proof.py) against Red's listchanged_server.py:
  chain intact 16 lines; notification recorded at line 9; digest moves
  6969d4e->f1c7d3f (listings at lines 5,12); EXISTING rules fire with no rule
  changes: mcp_schema_drift critical lines [12,16], mcp_tool_poisoning
  high line [15]. -W error::ResourceWarning clean.
- Control (old_client_control.py): the same server through the CURRENT client
  eats the notification (ping's response = None, notification NOWHERE in the
  trace, single tools/list) — the mis-parse is proven, not asserted.

D3 gate: satisfied on the client side. Merge of rugpull_notify still awaits
Red's live adjudication (their run must reproduce the miss with the old
client); applying to lab/ is the harness batch's job.
