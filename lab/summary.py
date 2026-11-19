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

import argparse
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

DEFAULT_WEIGHTS = {"low": 1, "medium": 3, "high": 5, "critical": 10}
WEIGHT_ORDER = ("low", "medium", "high", "critical")


def parse_weights(text: str) -> dict[str, float]:
    """Parse "low=1,medium=3,..." into a weight map.

    Raises ValueError on a missing value or malformed entry instead of
    quietly falling back to the defaults -- a typo'd weight would otherwise
    silently change the gate.
    """
    weights: dict[str, float] = {}
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"expected name=number, got {part!r}")
        name, _, raw = part.partition("=")
        name, raw = name.strip(), raw.strip()
        if not name or not raw:
            raise ValueError(f"expected name=number, got {part!r}")
        try:
            value = float(raw)
        except ValueError:
            raise ValueError(f"weight for {name!r} is not a number: {raw!r}") from None
        weights[name] = int(value) if value.is_integer() else value
    if not weights:
        raise ValueError("no severity weights given")
    return weights


def score(pairs: list[tuple[str, bool]],
          weights: dict[str, float]) -> tuple[float, float, float]:
    """Sum expected-rule weights; return (earned, total, pct).

    Unknown severities fall back to 1 so a new rule label cannot KeyError
    the gate. With no expected rules at all the percentage is 0.
    """
    earned = total = 0
    for sev, detected in pairs:
        w = weights.get(sev, 1)
        total += w
        if detected:
            earned += w
    pct = 100.0 * earned / total if total else 0.0
    return earned, total, pct


def _num(value: float) -> str:
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else f"{value:g}"
    return str(value)


def _weights_text(weights: dict[str, float]) -> str:
    names = [n for n in WEIGHT_ORDER if n in weights]
    names += sorted(n for n in weights if n not in WEIGHT_ORDER)
    return " ".join(f"{n}={_num(weights[n])}" for n in names)


def _widths(rows: list[list[str]], headers: list[str],
            labels: list[str]) -> tuple[int, list[int]]:
    scen_w = max([len("scenario")] + [len(s) for s in labels] + [SCEN_COL_MIN])
    col_w = [max(MIN_COL, max(len(c) for c in [h] + [r[i] for r in rows]))
             for i, h in enumerate(headers)]
    return scen_w, col_w


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Run every scenario and print a coverage matrix.")
    ap.add_argument("--threshold", type=float, default=None,
                    help="gate on the severity-weighted score (percentage)")
    ap.add_argument("--severity-weights", default=None,
                    help="override weights, e.g. low=1,medium=3,high=5,critical=10")
    args = ap.parse_args(argv)

    weights = DEFAULT_WEIGHTS
    if args.severity_weights is not None:
        try:
            weights = parse_weights(args.severity_weights)
        except ValueError as exc:
            print(f"bad --severity-weights: {exc}")
            return 2

    rule_objs = load_rules(os.path.join(HERE, "rules"))
    rules = [r.id for r in rule_objs]
    sev_by_rule = {r.id: r.severity for r in rule_objs}
    scen_dir = os.path.join(HERE, "scenarios")
    scenarios = sorted(f for f in os.listdir(scen_dir) if f.endswith(".yaml"))

    rows: list[list[str]] = []
    labels: list[str] = []
    codes: list[int] = []
    notes: list[str] = []
    pairs: list[tuple[str, bool]] = []

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
        expected = report["expected_detection"]
        if expected is not None:
            detected = any(r["rule"] == expected and r["fired"]
                           for r in report["results"])
            pairs.append((sev_by_rule.get(expected, "unknown"), detected))
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

    earned, total, pct = score(pairs, weights)
    if args.threshold is not None:
        print(f"score: {_num(earned)}/{_num(total)} = {pct:.1f}% "
              f"({_weights_text(weights)} threshold={_num(args.threshold)})")

    if any(c == 2 for c in codes):
        return 2   # could not evaluate: do not report a detection verdict
    if args.threshold is not None:
        return 0 if pct >= args.threshold else 1
    return 1 if any(c == 1 for c in codes) else 0


if __name__ == "__main__":
    sys.exit(main())
