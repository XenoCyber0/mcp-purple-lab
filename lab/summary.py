#!/usr/bin/env python3
"""Run every scenario and print a coverage matrix.

    python lab/summary.py

One row per scenario, one column per rule. Cell = fired rule that cited this
scenario's trace, or a blank if it did not. This is the "did our detection
stack cover our attack surface" view.
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


def main() -> int:
    rules = [r.id for r in load_rules(os.path.join(HERE, "rules"))]
    scen_dir = os.path.join(HERE, "scenarios")
    scenarios = sorted(f for f in os.listdir(scen_dir) if f.endswith(".yaml"))

    header = "scenario".ljust(24) + "".join(r.rjust(28) for r in rules)
    print(header)
    print("-" * len(header))

    failures = 0
    for name in scenarios:
        report = runner.run_scenario(os.path.join(scen_dir, name))
        if report["expected_detection"] and not report["detected"]:
            failures += 1
        cells = []
        for rid in rules:
            got = next((r for r in report["results"] if r["rule"] == rid), None)
            if got and got["fired"]:
                mark = "X" if rid == report["expected_detection"] else "x"
                cells.append(f"[{mark}] lines {','.join(map(str, got['trace_lines']))}")
            else:
                cells.append("MISSED" if rid == report["expected_detection"] else "-")
        print(report["scenario"].ljust(24) + "".join(c.rjust(28) for c in cells))

    print("-" * len(header))
    print("X = expected rule fired | x = another rule also fired | "
          "MISSED = expected rule did NOT fire")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
