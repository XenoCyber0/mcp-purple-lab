"""Rendering for run.py reports.

Split out of run.py to keep both files inside the repo's ~200-line contract. The
markdown is a VIEW of report.json, never a second source of truth: every field it
prints is read from the report dict, and tests assert the two agree.
"""
from __future__ import annotations


def verdict_of(report: dict) -> str:
    if report["detected"]:
        return "DETECTED"
    return "MISSED" if report["expected_detection"] else "clean (control)"


def render_markdown(report: dict) -> str:
    lines = [
        f"# {report['scenario']} - {report['scenario_name']}",
        "",
        f"- expected rule : `{report['expected_detection']}`"
        if report["expected_detection"] else "- expected rule : none (control)",
        f"- ATLAS         : {report['atlas_technique'] or '-'}",
        f"- trace         : `{report['trace']}` (chain {report['trace_chain']})",
        f"- rules fired   : {report['rules_fired']}/{report['rules_evaluated']}",
        f"- verdict       : **{verdict_of(report)}** (exit {report['exit_code']})",
        "",
        "## Rules",
        "",
        "| rule | severity | confidence | atlas | fired | trace lines |",
        "|---|---|---|---|---|---|",
    ]
    for r in report["results"]:
        ev = ", ".join(str(n) for n in r["trace_lines"]) or "-"
        lines.append(f"| `{r['rule']}` | {r['severity']} | {r['confidence']} | "
                     f"{r['atlas_technique'] or '-'} | "
                     f"{'YES' if r['fired'] else 'no'} | {ev} |")
    if report.get("error"):
        lines += ["", f"ERROR: {report['error']}"]
    return "\n".join(lines) + "\n"


def report_to_stdout(report: dict) -> str:
    return (
        f"scenario : {report['scenario']}\n"
        f"expected : {report['expected_detection'] or '(control)'}\n"
        f"fired    : {report['rules_fired']}/{report['rules_evaluated']} rules\n"
        f"chain    : {report['trace_chain']}\n"
        f"verdict  : {verdict_of(report)} (exit {report['exit_code']})"
    )
