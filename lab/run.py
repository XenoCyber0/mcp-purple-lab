#!/usr/bin/env python3
"""run.py -- run one attack scenario, evaluate rules, emit a report.

    python lab/run.py lab/scenarios/tool_poisoning.yaml [--out DIR]

Pipeline: scenario YAML -> spawn MCP server -> execute the scripted tool calls
(with optional tools/list between them) -> JSONL trace -> rule engine -> report
(JSON + markdown, rendered by report.py).

Exit codes (the API CI consumes)
--------------------------------
0  the expected attack was detected (or a scenario with no attack raised no rule)
1  an attack scenario went UNDETECTED, or the control scenario raised a rule
2  setup failure: unreadable scenario, missing server, server would not start,
   broken trace chain

Setup failures RAISE out of run_scenario and are mapped to 2 in main(). They
used to escape as tracebacks, which Python reports as exit 1 -- indistinguishable
from "attack missed", the one conflation CI cannot afford.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)

import yaml  # noqa: E402

from mcp_client import McpClient, McpError  # noqa: E402
from trace import Trace, read_trace, verify_trace  # noqa: E402
from evaluate import load_rules, evaluate_all, RuleError  # noqa: E402
from report import render_markdown, report_to_stdout  # noqa: E402

OUT_DIR = os.path.join(REPO, "out")


def run_scenario(scenario_path: str, write_report: bool = True,
                 out_dir: str | None = None) -> dict:
    """Execute one scenario end to end. Setup problems RAISE; main() maps them
    to exit 2. out_dir lets tests stay hermetic instead of sharing out/."""
    with open(scenario_path, encoding="utf-8") as fh:
        scenario = yaml.safe_load(fh)
    if not isinstance(scenario, dict):
        raise ValueError(f"scenario is not a mapping: {scenario_path}")

    sid = scenario["id"]
    server_rel = scenario["server"]
    server_path = os.path.join(REPO, server_rel)
    if not os.path.isfile(server_path):
        raise FileNotFoundError(f"server not found: {server_path}")
    # Spawned with cwd=REPO, so this relative path resolves from ANY invoking
    # directory on any OS. It used to resolve against the caller's CWD, so the
    # whole lab only ran from the repo root.
    server_cmd = f"python {server_rel}"

    out = out_dir or OUT_DIR
    os.makedirs(out, exist_ok=True)
    trace_path = os.path.join(out, f"{sid}.trace.jsonl")

    error = None
    with Trace(trace_path) as trace:
        client = None
        try:
            client = McpClient(server_cmd, trace, cwd=REPO)
            tools = client.list_tools()
            trace.record("lab", "server_started", server=server_rel,
                         tools=[t["name"] for t in tools])
            known = {t["name"] for t in tools}

            for step in scenario.get("agent_script", []):
                name = step["tool"]
                args = step.get("arguments", {})
                if name not in known:
                    trace.record("lab", "tool_unknown_at_start", tool=name)
                result = client.call_tool(name, args)
                if result.get("isError"):
                    trace.record("lab", "tool_returned_error", tool=name,
                                 error=result.get("content"))
                for extra in scenario.get("after_each_call", []):
                    if extra == "tools/list":
                        client.list_tools()
        except McpError as exc:
            error = str(exc)
        finally:
            if client:
                client.close()

    chain_ok, chain_msg = verify_trace(trace_path)
    if not chain_ok:
        error = error or f"trace chain broken: {chain_msg}"

    entries = read_trace(trace_path)
    rules = load_rules(os.path.join(HERE, "rules"))
    results = evaluate_all(rules, entries)

    fired = [r for r in results if r["fired"]]
    expected = scenario.get("expected_detection")

    if error:
        exit_code, detected = 2, False
    elif expected is None:                      # control scenario
        detected = False
        exit_code = 0 if not fired else 1       # false positive on control = fail
    else:
        detected = any(r["rule"] == expected for r in fired)
        exit_code = 0 if detected else 1

    try:
        trace_ref = os.path.relpath(trace_path, REPO)
    except ValueError:  # different drive (Windows)
        trace_ref = trace_path

    report = {
        "scenario": sid,
        "scenario_name": scenario.get("name", sid),
        "atlas_technique": scenario.get("atlas_technique"),
        "expected_detection": expected,
        "server": server_rel,
        "trace": trace_ref,
        "trace_chain": "intact" if chain_ok else chain_msg,
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
        json_path = os.path.join(out, f"{sid}.report.json")
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        md_path = os.path.join(out, f"{sid}.report.md")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(report))
    return report


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Run one MCP purple-lab scenario.")
    ap.add_argument("scenario", help="path to a scenario YAML file")
    ap.add_argument("--out", default=None,
                    help="artifact directory for trace/report (default: out/)")
    args = ap.parse_args(argv)
    try:
        report = run_scenario(args.scenario, out_dir=args.out)
    except (OSError, KeyError, ValueError, TypeError, AttributeError,
            yaml.YAMLError, RuleError) as exc:
        print(f"setup failure: {type(exc).__name__}: {exc}")
        return 2
    print(report_to_stdout(report))
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
