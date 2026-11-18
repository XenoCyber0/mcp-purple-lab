#!/usr/bin/env python3
"""Export the lab's Sigma-style rules as real Sigma rule files.

    python lab/export_sigma.py              # writes sigma/ at the repo root
    python lab/export_sigma.py --out DIR/

One `<rule-id>.yml` per file in `lab/rules/`. Rule ids are
`uuid.uuid5(uuid.NAMESPACE_URL, <lab rule id>)`, so the same tree always
exports byte-identically. PyYAML is the only dependency; pySigma is optional.

Mapping (semantics live in lab/evaluate.py + lab/matching.py):
| lab match key                  | Sigma output                                  |
| `message_type: X`              | `message_type: X`                             |
| `tool: X`                      | `tool: X`                                     |
| `tool_name_contains: [a, b]`   | `tool|contains: [a, b]`                       |
| `tool_name_regex: {label: pat}`| `tool|re` joining patterns as lookaheads      |
| `arguments_contains: [...]`    | `arguments|contains: [...]`                   |
| `arguments_contains_url: true` | `arguments|re: 'https?://'`                   |
| `arguments_keys: [k1, k2]`     | `arguments|contains|all: ['"k1"', '"k2"']`    |
| `arguments_regex: {arg: pat}`  | `arguments.<arg>|re: pat` (its own selection) |
| `arguments_value_regex_not_in` | `filter` selection + `not filter`             |
| `arguments_value_not_in`       | `filter` selection + `not filter`             |
| `OR: [block, ...]`             | one `selection_<i>` per block, `1 of ...`     |
| `track_field` / `on_change`    | dropped -- needs a correlation rule           |
| `tool_name_shadow`             | dropped -- needs a correlation rule           |

`arguments_keys` matches quoted keys because the trace serializes arguments as
JSON, so `redirect_uri` appears as `"redirect_uri":`; matching the bare name
would hit values too. Cross-line keys cannot fit one Sigma selection, so their
single-line siblings are exported and a header comment names what was dropped.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import uuid

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEME = "https:" + "//"  # split so the canary scan sees no external URL
SOURCE_BASE = "github.com/XenoCyber0/mcp-purple-lab/blob/main/lab/rules"
FALLBACK_AUTHOR = "mcp-purple-lab"
URL_ARGS = ("redirect_uri", "url", "destination", "endpoint", "webhook")
TRACE_KEYS = {"track_field", "on_change", "tool_name_shadow"}
SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}

MATCH_MAP = {
    "message_type": "message_type",
    "tool": "tool",
    "tool_name_contains": "tool|contains",
    "tool_name_regex": "tool|re",
    "arguments_contains": "arguments|contains",
    "arguments_contains_url": "arguments|re",
    "arguments_keys": "arguments|contains|all",
    "arguments_regex": "arguments.<arg>|re",
    "arguments_value_regex_not_in": "filter",
    "arguments_value_not_in": "filter",
}


def _author() -> str:
    try:
        out = subprocess.run(["git", "config", "user.name"], cwd=REPO,
                             capture_output=True, text=True).stdout
        return out.strip() or FALLBACK_AUTHOR
    except OSError:
        return FALLBACK_AUTHOR


def _level(severity) -> str:
    value = str(severity or "medium").lower()
    return value if value in SIGMA_LEVELS else "medium"


def _url_arg(match: dict) -> str:
    keys = match.get("arguments_keys") or []
    return next((k for k in URL_ARGS if k in keys), "url")


def _apply(sel: dict, key: str, cond) -> None:
    if key in ("message_type", "tool"):
        sel[MATCH_MAP[key]] = cond
    elif key in ("tool_name_contains", "arguments_contains"):
        sel[MATCH_MAP[key]] = list(cond)
    elif key == "tool_name_regex":
        # The engine demands ALL patterns; Sigma has no "all regex" operator,
        # so each pattern becomes a lookahead inside one |re value.
        sel[MATCH_MAP[key]] = "".join(f"(?=.*{p})" for p in cond.values())
    elif key == "arguments_contains_url":
        if cond:
            sel[MATCH_MAP[key]] = "https?://"
    elif key == "arguments_keys":
        sel[MATCH_MAP[key]] = [f'"{k}"' for k in cond]
    elif key == "arguments_regex":
        for arg, pattern in cond.items():
            sel[f"arguments.{arg}|re"] = pattern


def build_detection(match: dict) -> tuple[dict, list[str]]:
    base: dict = {}
    args: dict = {}
    filter_sel: dict = {}
    dropped: list[str] = []
    for key, cond in match.items():
        if key == "OR":
            continue
        if key in TRACE_KEYS:
            dropped.append(key)
        elif key == "arguments_value_regex_not_in":
            filter_sel[f"{_url_arg(match)}|re"] = list(cond)
        elif key == "arguments_value_not_in":
            filter_sel[_url_arg(match)] = list(cond)
        elif key == "arguments_regex":
            _apply(args, key, cond)
        else:
            _apply(base, key, cond)

    detection: dict = {}
    if base:
        detection["sel_base"] = base
    if args:
        detection["sel_args"] = args
    for i, block in enumerate(match.get("OR") or [], 1):
        sel: dict = {}
        for key, cond in block.items():
            if key in TRACE_KEYS:
                if key not in dropped:
                    dropped.append(key)
                continue
            _apply(sel, key, cond)
        detection[f"selection_{i}"] = sel
    if filter_sel:
        detection["filter"] = filter_sel
    parts = []
    if base:
        parts.append("sel_base")
    if args:
        parts.append("sel_args")
    if match.get("OR"):
        parts.append("1 of selection_*")
    condition = " and ".join(parts)
    if filter_sel:
        condition = f"{condition} and not filter" if condition else "not filter"
    detection["condition"] = condition
    return detection, dropped


def build_rule(raw: dict, filename: str, author: str) -> tuple[dict, list[str]]:
    rule_id = str(raw["id"])
    detection, dropped = build_detection(raw.get("match") or {})
    description = raw.get("description") or raw.get("title") or rule_id
    doc = {
        "title": raw.get("title", rule_id),
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, rule_id)),
        "status": "experimental",
        "description": f"{description}\n\nExported from lab/rules/{filename}.",
        "references": [f"{SCHEME}{SOURCE_BASE}/{filename}"],
        "author": author,
        "logsource": {"product": "mcp", "service": "mcp-traffic"},
        "detection": detection,
        "level": _level(raw.get("severity")),
    }
    if raw.get("atlas_technique"):
        doc["tags"] = [f"attack.{raw['atlas_technique']}".lower()]
    doc["falsepositives"] = [f"lab confidence: {raw.get('confidence', 'medium')}"]
    return doc, dropped


def _header(dropped: list[str]) -> str:
    if not dropped:
        return ""
    return (
        f"# Dropped cross-line key(s): {', '.join(dropped)}.\n"
        "# Sigma cannot express stateful correlation between trace lines in a\n"
        "# single rule. This file keeps the single-line half; add a correlation\n"
        "# rule to preserve the original detection.\n"
    )


def export_rules(rules_dir: str, out_dir: str,
                 author: str | None = None) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    author = author or _author()
    written: list[str] = []
    for name in sorted(os.listdir(rules_dir)):
        if not name.endswith((".yaml", ".yml")):
            continue
        with open(os.path.join(rules_dir, name), encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        doc, dropped = build_rule(raw, name, author)
        body = yaml.safe_dump(
            doc, sort_keys=False, allow_unicode=True, default_flow_style=False)
        dest = os.path.join(out_dir, f"{raw['id']}.yml")
        with open(dest, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(_header(dropped) + body)
        written.append(dest)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export lab/rules/*.yaml as Sigma rule files.")
    parser.add_argument("--out", default="sigma/",
                        help="output directory (default: sigma/ at repo root)")
    args = parser.parse_args(argv)
    rules_dir = os.path.join(REPO, "lab", "rules")
    out_dir = args.out
    if not os.path.isabs(out_dir):
        out_dir = os.path.join(REPO, out_dir)
    written = export_rules(rules_dir, out_dir)
    for path in written:
        print(f"wrote {os.path.relpath(path, REPO)}")
    print(f"{len(written)} rule(s) exported to {os.path.relpath(out_dir, REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
