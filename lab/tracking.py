"""Cross-line match keys: state that no single trace line can express.

Extracted from evaluate.py in v2 to keep that module inside the 220-line CI
contract. Two relations live here, both documented in evaluate.py's docstring:

* `tool_name_shadow` -- a called name strictly extends a name advertised on a
  tools/list.result line (fetch_all over fetch). The relation spans lines.
* `track_field` / `on_change` -- remember a field across every tools/list.result
  line and fire when it moves (schema rug-pull).
"""
from __future__ import annotations

import json

from matching import arguments_text, line_matches


def baseline_tool_names(trace: list[dict]) -> set[str]:
    """Every tool name advertised on any tools/list.result line."""
    names: set[str] = set()
    for entry in trace:
        if entry.get("message_type") != "tools/list.result":
            continue
        listed = entry.get("tool_names")
        if isinstance(listed, list):
            names.update(str(n) for n in listed)
            continue
        tools = entry.get("tools")
        if isinstance(tools, list):
            names.update(
                str(t["name"]) for t in tools
                if isinstance(t, dict) and t.get("name")
            )
    return names


def shadow_hits(match: dict, trace: list[dict],
                args_texts: list[str] | None = None) -> list[int]:
    """tools/call lines whose name STRICTLY extends another advertised name.

    fetch_all shadows fetch; fetch itself shadows nothing. A prefix pair alone
    is not an attack -- the rule's sibling keys must also match (URL + payload),
    which is what keeps the benign control clean.
    """
    if not match.get("tool_name_shadow"):
        return []
    baseline = baseline_tool_names(trace)
    if args_texts is None:
        args_texts = [arguments_text(e) for e in trace]
    hits: list[int] = []
    for i, (entry, text) in enumerate(zip(trace, args_texts), 1):
        tool = entry.get("tool") or ""
        if not any(other != tool and tool.startswith(other)
                   for other in baseline):
            continue
        if line_matches(match, entry, text):
            hits.append(i)
    return hits


def change_hits(match: dict, trace: list[dict]) -> list[int]:
    """Lines where a tracked tools/list.result field changed between calls."""
    field = match["track_field"]
    fire_on_change = bool((match.get("on_change") or {}).get("fired", True))
    seen = None
    changed: list[int] = []
    for i, entry in enumerate(trace, 1):
        if entry.get("message_type") != "tools/list.result":
            continue
        value = entry.get(field)
        if value is None:
            continue
        norm = value if isinstance(value, str) else json.dumps(
            value, sort_keys=True, default=str)
        if seen is not None and norm != seen:
            changed.append(i)  # this line is proof the schema moved
        seen = norm
    # Flag suspicious tool CALLS only once the schema actually moved (or when
    # the rule opted out of change-tracking). Firing on the name list alone
    # degrades the rule into a blunt tool-name blacklist.
    if not changed and fire_on_change:
        return []
    drift_lines = changed if fire_on_change else []
    extra: list[int] = []
    for block in match.get("OR") or []:
        subs = block.get("tool_name_contains", [])
        if not subs:
            continue
        for i, entry in enumerate(trace, 1):
            if entry.get("message_type") != "tools/call.result":
                continue
            if any(s in (entry.get("tool") or "") for s in subs):
                extra.append(i)
    return sorted(set(drift_lines + extra))
