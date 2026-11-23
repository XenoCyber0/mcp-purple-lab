"""Coverage-matrix rendering: a VIEW of the reports, never a second truth.

Split out of summary.py in v2 to keep the CLI inside the 220-line contract and
to make the matrix testable without spawning servers. Column widths are
computed from the actual rule ids and cell contents; they used to be hardcoded Sea
at 28 chars, so a longer id or evidence list silently overlapped its neighbour.
"""
from __future__ import annotations

MIN_COL = 12
SCEN_COL_MIN = 22
PAD = 2

LEGEND = ("X = expected rule fired | x = another rule also fired | "
          "MISSED = expected rule did NOT fire")


def _widths(rows: list[list[str]], headers: list[str],
            labels: list[str]) -> tuple[int, list[int]]:
    scen_w = max([len("scenario"), SCEN_COL_MIN] + [len(s) for s in labels])
    if not headers:
        return scen_w, []
    col_w = [max(MIN_COL, max(len(c) for c in [h] + [r[i] for r in rows]))
             for i, h in enumerate(headers)]
    return scen_w, col_w


def render_text(reports: list[dict], rule_ids: list[str]) -> str:
    if not rule_ids:
        return "no rules loaded"
    labels = [r["scenario"] for r in reports]
    rows: list[list[str]] = []
    for report in reports:
        by_rule = {x["rule"]: x for x in report.get("results", [])}
        cells = []
        for rid in rule_ids:
            got = by_rule.get(rid)
            if got and got["fired"]:
                mark = "X" if rid == report.get("expected_detection") else "x"
                cells.append(f"[{mark}] " + ",".join(map(str, got["trace_lines"])))
            elif rid == report.get("expected_detection"):
                cells.append("MISSED")
            else:
                cells.append("-")
        rows.append(cells)

    scen_w, col_w = _widths(rows, rule_ids, labels)
    sep = "-" * (scen_w + PAD * len(col_w) + sum(col_w))

    def fmt(label: str, cells: list[str]) -> str:
        parts = [label.ljust(scen_w)]
        parts += [c.rjust(w) for c, w in zip(cells, col_w)]
        return (" " * PAD).join(parts)

    out = [fmt("scenario", rule_ids), sep]
    out += [fmt(label, cells) for label, cells in zip(labels, rows)]
    out.append(sep)
    out.append(LEGEND)
    return "\n".join(out)
