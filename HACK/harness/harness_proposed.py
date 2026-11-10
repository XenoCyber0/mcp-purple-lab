#!/usr/bin/env python3
"""harness_proposed.py -- PROPOSAL (not applied): run the purple-lab pipeline
against any EXTERNAL stdio MCP server, producing the same trace + report as
run_scenario does for lab/servers/*.

Public API -- mirrors the run_scenario contract (lab/run.py at 10b609b):

    run_external_server(server_cmd: str, calls: list[dict],
                        out_dir: str, name: str, *,
                        cwd=None, expected_detection=None,
                        scenario_name=None, atlas_technique=None,
                        write_report=True) -> dict

The returned dict carries EXACTLY the keys of run_scenario's report, plus two
ADDITIVE integrity keys -- trace_root_hash (hash field of the LAST trace line)
and trace_line_count -- which lab_run_root_hash.patch adds to lab/run.py so
both paths agree.

Reuse, do not fork: McpClient, Trace, verify_trace, load_rules/evaluate_all and
render_markdown are imported from lab/ via sys.path. lab/servers/* is NOT
imported -- this harness exists for servers outside the lab.

No shell=True anywhere. server_cmd is parsed with shlex.split for the preflight
and echoed verbatim into the report; the spawn itself goes through McpClient,
which Popen()s an argv list (mcp_client.resolve_command maps python/python3 to
sys.executable). CAVEAT: resolve_command() re-splits with naive str.split(), so
a token containing a quoted space will not survive the round trip -- see
findings.md for the one-line lab-side fix.

calls is an ordered script, each step a dict:
    {"tool": <name>, "arguments": {...}}   -> tools/call
    {"list_tools": true}                   -> tools/list (drift sampling)
Unknown-at-start tools are traced exactly as run_scenario does.

Exit codes are run.py's API: 0 detected (or clean control), 1 missed (or a
rule firing on a control), 2 setup failure. Unlike run_scenario -- which lets
setup errors raise into main() -- run_external_server RETURNS a report with
exit_code=2 and error set, because a library caller has no main() to map them.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import sys


def _find_repo_root() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    cand = here
    while True:
        if os.path.isfile(os.path.join(cand, "lab", "run.py")):
            return cand
        parent = os.path.dirname(cand)
        if parent == cand:
            raise RuntimeError(f"no lab/run.py found above {here}")
        cand = parent


REPO = _find_repo_root()
LAB = os.path.join(REPO, "lab")
for _p in (LAB, REPO):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from mcp_client import McpClient, McpError  # noqa: E402
from trace import Trace, read_trace, verify_trace  # noqa: E402
from evaluate import load_rules, evaluate_all  # noqa: E402
from report import render_markdown, report_to_stdout  # noqa: E402

# The exact key set of run_scenario's report (run.py lines 119-135). Tests
# assert run_external_server's report covers it; the two *_ROOT_HASH_KEYS are
# the additive delta this proposal (and the patch) introduces.
SCENARIO_REPORT_KEYS = {
    "scenario", "scenario_name", "atlas_technique", "expected_detection",
    "server", "trace", "trace_chain", "rules_evaluated", "rules_fired",
    "detected", "exit_code", "error", "results", "evidence",
}
ROOT_HASH_KEYS = {"trace_root_hash", "trace_line_count"}


def _preflight(argv: list[str], cwd: str | None) -> None:
    """Fail fast and LOUDLY when the server command cannot be spawned, so a
    missing server maps to exit 2 instead of a confusing 'server closed
    stdout' McpError. Raises FileNotFoundError/ValueError on setup problems."""
    if not argv:
        raise ValueError("empty server command")
    exe = argv[0]
    if exe not in ("python", "python3"):
        import shutil
        if shutil.which(exe) is None:
            raise FileNotFoundError(f"server executable not found: {exe}")
    bases = [cwd or os.getcwd(), REPO]
    for tok in argv[1:]:
        clean = tok.strip("\"'")
        if clean.endswith((".py", ".pyw")):
            if os.path.isabs(clean):
                if not os.path.isfile(clean):
                    raise FileNotFoundError(f"server script not found: {clean}")
            elif not any(os.path.isfile(os.path.join(b, clean)) for b in bases):
                raise FileNotFoundError(
                    f"server script not found: {clean} (looked in {bases})")
            break


def _integrity_md(report: dict) -> str:
    """Integrity block appended to the markdown view. Kept here (and in
    report.py by the patch) so the md stays a pure VIEW of report.json."""
    if not report.get("trace_root_hash"):
        return ""
    return ("\n## Integrity\n\n"
            f"- trace root hash : `{report['trace_root_hash']}`\n"
            f"- trace line count: {report['trace_line_count']}\n")


def run_external_server(server_cmd: str, calls: list[dict], out_dir: str,
                        name: str, *, cwd: str | None = None,
                        expected_detection: str | None = None,
                        scenario_name: str | None = None,
                        atlas_technique: str | None = None,
                        rules_dir: str | None = None,
                        write_report: bool = True) -> dict:
    """Execute one external-server session end to end. Never raises for setup
    problems: returns a report with exit_code=2 and error set (see docstring).
    cwd defaults to the caller's CWD; pass REPO to mirror run.py's semantics.
    rules_dir overrides lab/rules (external servers earn their own rules;
    the shipped rules key on lab tool names, see findings.md)."""
    argv = shlex.split(server_cmd, posix=False)  # validation + preflight only
    os.makedirs(out_dir, exist_ok=True)
    trace_path = os.path.join(out_dir, f"{name}.trace.jsonl")

    setup_error = None
    try:
        _preflight(argv, cwd)
    except (FileNotFoundError, ValueError) as exc:
        setup_error = f"setup failure: {type(exc).__name__}: {exc}"

    error = None
    with Trace(trace_path) as trace:          # empty-but-verifiable on setup fail
        client = None
        if setup_error is None:
            try:
                client = McpClient(server_cmd, trace, cwd=cwd)
                tools = client.list_tools()
                trace.record("lab", "server_started", server=server_cmd,
                             tools=[t["name"] for t in tools])
                known = {t["name"] for t in tools}
                for step in calls or []:
                    if step.get("list_tools"):
                        client.list_tools()
                        continue
                    tool = step["tool"]
                    args = step.get("arguments", {})
                    if tool not in known:
                        trace.record("lab", "tool_unknown_at_start", tool=tool)
                    result = client.call_tool(tool, args)
                    if result.get("isError"):
                        trace.record("lab", "tool_returned_error", tool=tool,
                                     error=result.get("content"))
            except (McpError, OSError) as exc:
                error = str(exc)
            finally:
                if client:
                    client.close()

    chain_ok, chain_msg = verify_trace(trace_path)
    if not chain_ok:
        error = error or f"trace chain broken: {chain_msg}"
    error = setup_error or error

    entries = read_trace(trace_path)
    root_hash = entries[-1].get("hash") if entries else None
    rules = load_rules(rules_dir or os.path.join(LAB, "rules"))
    results = evaluate_all(rules, entries)
    fired = [r for r in results if r["fired"]]

    if error:
        exit_code, detected = 2, False
    elif expected_detection is None:           # control semantics
        detected = False
        exit_code = 0 if not fired else 1      # false positive on control = fail
    else:
        detected = any(r["rule"] == expected_detection for r in fired)
        exit_code = 0 if detected else 1

    try:
        trace_ref = os.path.relpath(trace_path, REPO)
    except ValueError:  # different drive (Windows)
        trace_ref = trace_path

    report = {
        "scenario": name,
        "scenario_name": scenario_name or name,
        "atlas_technique": atlas_technique,
        "expected_detection": expected_detection,
        "server": server_cmd,
        "trace": trace_ref,
        "trace_chain": "intact" if chain_ok else chain_msg,
        "trace_root_hash": root_hash,
        "trace_line_count": len(entries),
        "rules_evaluated": len(results),
        "rules_fired": len(fired),
        "detected": detected,
        "exit_code": exit_code,
        "error": error,
        "results": results,
        "evidence": [{"rule": r["rule"], "trace_lines": r["trace_lines"]}
                     for r in fired],
    }

    if write_report:
        with open(os.path.join(out_dir, f"{name}.report.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        with open(os.path.join(out_dir, f"{name}.report.md"), "w",
                  encoding="utf-8") as fh:
            fh.write(render_markdown(report) + _integrity_md(report))
    return report


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Run the lab pipeline against an external stdio MCP server.")
    ap.add_argument("server_cmd", help="command to spawn the server (no shell)")
    ap.add_argument("--call", action="append", default=[], metavar="JSON",
                    help='script step, e.g. \'{"tool": "echo", '
                         '"arguments": {"text": "hi"}}\' (repeatable)')
    ap.add_argument("--list-tools", action="store_true",
                    help="add a tools/list sampling step after each call")
    ap.add_argument("--name", default="external")
    ap.add_argument("--out", required=True, help="artifact directory")
    ap.add_argument("--cwd", default=None)
    ap.add_argument("--expected", default=None,
                    help="rule id whose firing counts as detection")
    args = ap.parse_args(argv)
    calls = [json.loads(c) for c in args.call]
    if args.list_tools:                      # sample the schema after each call
        expanded = []
        for step in calls:
            expanded.append(step)
            expanded.append({"list_tools": True})
        calls = expanded
    report = run_external_server(args.server_cmd, calls, args.out, args.name,
                                 cwd=args.cwd, expected_detection=args.expected)
    print(report_to_stdout(report))
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
