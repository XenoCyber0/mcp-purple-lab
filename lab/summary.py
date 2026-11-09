#!/usr/bin/env python3
"""Run every scenario and print a coverage matrix.

    python lab/summary.py

One row per scenario, one column per rule -- the "did our detection stack cover
our attack surface" view:

    X       the expected rule fired
    x       a different rule also fired
    MISSED  the expected rule did NOT fire

Column widths are computed from the actual rule ids and cell contents. They
used to be hardcoded at 28 chars, so a longer rule id or evidence list
silently overlapped its neighbour: the matrix lied by formatting, on the exact
line a reviewer reads first.

Exit codes mirror run.py, with setup failure taking precedence:
2  any scenario failed to run (server would not start, broken trace chain)
1  an attack went undetected, or the control raised a rule
0  everything ran and the coverage invariants hold
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)

import run as runner  # noqa: E402
from evaluate import load_rules  # noqa: E402

MIN_COL = 12
SCEN_COL_MIN = 22
PAD = 2


def _widths(rows: list[list[str]], headers: list[str],
            labels: list[str]) -> tuple[int, list[int]]:
    scen_w = max([len("scenario")] + [len(s) for s in labels] + [SCEN_COL_MIN])
    col_w = [max(MIN_COL, max(len(c) for c in [h] + [r[i] for r in rows]))
             for i, h in enumerate(headers)]
    return scen_w, col_w


def main() -> int:
    rules = [r.id for r in load_rules(os.path.join(HERE, "rules"))]
    scen_dir = os.path.join(HERE, "scenarios")
    scenarios = sorted(f for f in os.listdir(scen_dir) if f.endswith(".yaml"))

    rows: list[list[str]] = []
    labels: list[str] = []
    codes: list[int] = []
    notes: list[str] = []

    for name in scenarios:
        try:
            report = runner.run_scenario(os.path.join(scen_dir, name))
        except Exception as exc:  # noqa: BLE001 -- a row must not kill the matrix
            labels.append(name.replace(".yaml", ""))
            rows.append(["!"] * len(rules))
            codes.append(2)
            notes.append(f"{name}: setup failure: {type(exc).__name__}: {exc}")
            continue

        labels.append(report["scenario"])
        codes.append(report["exit_code"])
        if report["trace_chain"] != "intact":
            notes.append(f"{report['scenario']}: trace chain broken: {report['trace_chain']}")
        if report["error"]:
            notes.append(f"{report['scenario']}: {report['error']}")

        cells = []
        for rid in rules:
            got = next((r for r in report["results"] if r["rule"] == rid), None)
            if got and got["fired"]:
                mark = "X" if rid == report["expected_detection"] else "x"
                cells.append(f"[{mark}] " + ",".join(map(str, got["trace_lines"])))
            elif rid == report["expected_detection"]:
                cells.append("MISSED")
            else:
                cells.append("-")
        rows.append(cells)

    scen_w, col_w = _widths(rows, rules, labels)
    sep = "-" * (scen_w + PAD * len(col_w) + sum(col_w))

    def fmt(label: str, cells: list[str]) -> str:
        parts = [label.ljust(scen_w)]
        parts += [c.rjust(w) for c, w in zip(cells, col_w)]
        return (" " * PAD).join(parts)

    print(fmt("scenario", rules))
    print(sep)
    for label, cells in zip(labels, rows):
        print(fmt(label, cells))
    print(sep)
    print("X = expected rule fired | x = another rule also fired | "
          "MISSED = expected rule did NOT fire")
    for n in notes:
        print("NOTE " + n)
    print(f"{len(labels)} scenarios, {len(rules)} rules")

    if any(c == 2 for c in codes):
        return 2   # could not evaluate: do not report a detection verdict
    return 1 if any(c == 1 for c in codes) else 0


if __name__ == "__main__":
    sys.exit(main())
