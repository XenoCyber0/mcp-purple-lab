#!/usr/bin/env python3
"""run.py -- run one attack scenario, evaluate rules, emit a report.

    python lab/run.py lab/scenarios/tool_poisoning.yaml

Pipeline: scenario YAML -> spawn MCP server -> execute the scripted tool
calls (with optional tools/list between them) -> JSONL trace -> rule engine
-> report (JSON + markdown).

Exit codes
----------
0  the expected attack was detected (or a scenario with no attack raised no rule)
1  an attack scenario went UNDETECTED, or the control scenario raised a rule
2  setup failure (bad scenario file, server would not start)
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
from trace import Trace, read_trace  # noqa: E402
from evaluate import load_rules, evaluate_all  # noqa: E402

OUT_DIR = os.path.join(REPO, "out")


def run_scenario(scenario_path: str, write_report: bool = True) -> dict:
    with open(scenario_path, encoding="utf-8") as fh:
        scenario = yaml.safe_load(fh)

    sid = scenario["id"]
    server_rel = scenario["server"]
    server_path = os.path.join(REPO, server_rel)
    if not os.path.isfile(server_path):
        raise FileNotFoundError(f"server not found: {server_path}")
    # servers are spawned with cwd=REPO, so use the relative path
    server_cmd = f"python {server_rel}"

    os.makedirs(OUT_DIR, exist_ok=True)
    trace_path = os.path.join(OUT_DIR, f"{sid}.trace.jsonl")

    trace = Trace(trace_path)
    client = None
    error = None
    try:
        client = McpClient(server_cmd, trace)
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
        trace.close()

    entries = read_trace(trace_path)
    rules = load_rules(os.path.join(HERE, "rules"))
    results = evaluate_all(rules, entries)

    fired = [r for r in results if r["fired"]]
    expected = scenario.get("expected_detection")
    is_control = expected is None

    if error:
        exit_code = 2
        detected = False
    elif is_control:
        detected = False
        exit_code = 0 if not fired else 1  # false positive on control = fail
    else:
        detected = any(r["rule"] == expected for r in fired)
        exit_code = 0 if detected else 1

    report = {
        "scenario": sid,
        "scenario_name": scenario.get("name", sid),
        "atlas_technique": scenario.get("atlas_technique"),
        "expected_detection": expected,
        "server": server_rel,
        "trace": os.path.relpath(trace_path, REPO),
        "rules_evaluated": len(results),
        "rules_fired": len(fired),
        "detected": detected,
        "exit_code": exit_code,
        "error": error,
        "results": results,
        "evidence": [
            {"rule": r["rule"], "trace_lines": r["trace_lines"]}
            for r in fired
        ],
    }

    if write_report:
        json_path = os.path.join(OUT_DIR, f"{sid}.report.json")
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        md_path = os.path.join(OUT_DIR, f"{sid}.report.md")
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(report))
    return report


def render_markdown(report: dict) -> str:
    verdict = "DETECTED" if report["detected"] else (
        "MISSED" if report["expected_detection"] else "clean (control)")
    lines = [
        f"# {report['scenario']} - {report['scenario_name']}",
        "",
        f"- expected rule : `{report['expected_detection']}`"
        if report["expected_detection"] else "- expected rule : none (control)",
        f"- ATLAS         : {report['atlas_technique'] or '-'}",
        f"- trace         : `{report['trace']}`",
        f"- rules fired   : {report['rules_fired']}/{report['rules_evaluated']}",
        f"- verdict       : **{verdict}** (exit {report['exit_code']})",
        "",
        "## Rules",
        "",
        "| rule | severity | fired | trace lines |",
        "|---|---|---|---|",
    ]
    for r in report["results"]:
        fired = "YES" if r["fired"] else "no"
        ev = ", ".join(str(n) for n in r["trace_lines"]) or "-"
        lines.append(f"| `{r['rule']}` | {r['severity']} | {fired} | {ev} |")
    if report.get("error"):
        lines += ["", f"ERROR: {report['error']}"]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("scenario", help="path to a scenario YAML file")
    args = ap.parse_args(argv)
    report = run_scenario(args.scenario)
    print(report_to_stdout(report))
    return report["exit_code"]


def report_to_stdout(report: dict) -> str:
    verdict = "DETECTED" if report["detected"] else (
        "MISSED" if report["expected_detection"] else "clean (control)")
    return (
        f"scenario : {report['scenario']}\n"
        f"expected : {report['expected_detection'] or '(control)'}\n"
        f"fired    : {report['rules_fired']}/{report['rules_evaluated']} rules\n"
        f"verdict  : {verdict} (exit {report['exit_code']})"
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
