#!/usr/bin/env python3
"""Blue-lens evaluator: run the REAL lab/evaluate.py engine against traces.

Read-only w.r.t. lab/. Never writes outside HACK/blue/.

    python HACK/blue/run_probe.py                          # shipped rules, probe corpus
    python HACK/blue/run_probe.py --rules HACK/blue/rules_tight
    python HACK/blue/run_probe.py --traces HACK/blue/ref   # faithfulness check on out/ copies
    python HACK/blue/run_probe.py --only OB1,EV6
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
LAB = os.path.join(REPO, "lab")
sys.path.insert(0, LAB)

from evaluate import load_rules, evaluate_all  # noqa: E402
from trace import read_trace  # noqa: E402

SHOW_URL = re.compile(r"https?://[^\s\"'\\]+", re.IGNORECASE)


def _texts(entry):
    args = entry.get("arguments")
    return (entry.get("tool") or "",
            json.dumps(args, default=str) if args is not None else "",
            args if isinstance(args, dict) else None)


def key_detail(entry, key, cond):
    """Human-readable 'why did this key evaluate true' for a single key."""
    tool, args_text, args = _texts(entry)
    if key == "message_type":
        return f"message_type=={cond!r} (entry={entry.get('message_type')!r})"
    if key == "tool":
        return f"tool=={cond!r} (entry={tool!r})"
    if key == "tool_name_contains":
        hit = [s for s in cond if s in tool]
        return f"tool_name_contains hit={hit!r} against tool={tool!r} [list={cond}]"
    if key == "arguments_contains":
        hit = [s for s in cond if s in args_text]
        return f"arguments_contains hit={hit!r} in args_text={args_text[:120]!r}"
    if key == "arguments_contains_url":
        urls = SHOW_URL.findall(args_text)
        return (f"arguments_contains_url={cond} -> urls={urls!r} "
                f"in args_text={args_text[:120]!r}")
    if key == "arguments_keys":
        return f"arguments_keys={cond} all present in args keys={list(args or [])}"
    if key == "arguments_value_not_in":
        picked = next((k for k in ("redirect_uri", "url") if args and k in args), None)
        val = args.get(picked) if (picked and args) else None
        return (f"arguments_value_not_in: engine picked arg key {picked!r} "
                f"(hard-coded search order redirect_uri,url) value={val!r} "
                f"not in allowlist={cond}")
    if key == "track_field":
        return f"track_field={cond!r} (cross-line tracker; other sibling keys ignored)"
    return f"{key}={cond!r} -> UNKNOWN KEY, _cond_matches returns False"


def explain(rule, entry):
    m = rule.match
    out = []
    if "track_field" in m:
        out.append(f"      mode=track_field; sibling keys ignored={[k for k in m if k != 'track_field']}")
        return out
    if "OR" in m:
        ignored = [k for k in m if k != "OR"]
        out.append(f"      mode=OR; SIBLING KEYS DROPPED BY ENGINE: {ignored}")
        for i, b in enumerate(m["OR"]):
            t = [k for k, c in b.items() if rule._cond_matches(entry, k, c)]
            f = [k for k in b if k not in t]
            out.append(f"      OR[{i}]: true={t} false={f}")
            for k in t:
                out.append(f"        * {key_detail(entry, k, b[k])}")
        return out
    t = [k for k, c in m.items() if rule._cond_matches(entry, k, c)]
    f = [k for k in m if k not in t]
    out.append(f"      mode=AND; true={t} false={f}")
    for k in t:
        out.append(f"        * {key_detail(entry, k, m[k])}")
    return out


def drift_diag(entries):
    ls = [(i, e) for i, e in enumerate(entries, 1)
          if e.get("message_type") == "tools/list.result"]
    rows = []
    for (ia, ea), (ib, eb) in zip(ls, ls[1:]):
        va, vb = ea.get("result"), eb.get("result")
        if va is None or vb is None:
            continue
        na, nb = json.dumps(va, sort_keys=True, default=str), json.dumps(vb, sort_keys=True, default=str)
        div = 0
        while div < min(len(na), len(nb)) and na[div] == nb[div]:
            div += 1
        rows.append((ia, ib, type(va).__name__, len(na), len(nb), na == nb, div))
    return rows


def show(name, entries, rules, only):
    print("=" * 79)
    print(f"TRACE {name}  ({len(entries)} lines)")
    print("=" * 79)
    results = evaluate_all(rules, entries)
    fired_any = False
    for r in results:
        if only and not any(o.lower() in name.lower() for o in only):
            continue
        tag = "FIRED" if r["fired"] else "quiet"
        print(f"  [{tag:5}] {r['rule']:26} sev={r['severity']:8} "
              f"lines={r['trace_lines'] or '-'} count={r['match_count']}")
        if r["fired"]:
            fired_any = True
            rule = next(x for x in rules if x.id == r["rule"])
            for ln in r["trace_lines"]:
                e = entries[ln - 1]
                brief = {k: e.get(k) for k in ("dir", "message_type", "tool") if k in e}
                print(f"    L{ln}: {brief}")
                for line in explain(rule, e):
                    print(line)
    for ia, ib, ty, la, lb, eq, div in drift_diag(entries):
        print(f"  DRIFT-DIAG tools/list L{ia}->L{ib}: type={ty} "
              f"jsonlen={la}/{lb} equal={eq} first_divergence_char={div}")
    return fired_any


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default=os.path.join(LAB, "rules"))
    ap.add_argument("--traces", default=os.path.join(HERE, "traces"))
    ap.add_argument("--only", default="")
    a = ap.parse_args()

    rules_dir = a.rules if os.path.isabs(a.rules) else os.path.join(REPO, a.rules)
    rules = load_rules(rules_dir)
    dirs = [d if os.path.isabs(d) else os.path.join(REPO, d) for d in a.traces.split(",") if d]
    print(f"RULES DIR : {os.path.relpath(rules_dir, REPO)}")
    print(f"TRACE DIRS: {[os.path.relpath(d, REPO) for d in dirs]}\n")
    only = [x for x in a.only.split(",") if x]

    n_fire = 0
    n_trace = 0
    for d in dirs:
        for f in sorted(os.listdir(d)):
            if not f.endswith(".jsonl"):
                continue
            if only and not any(o.lower() in f.lower() for o in only):
                continue
            n_trace += 1
            if show(f, read_trace(os.path.join(d, f)), rules, only):
                n_fire += 1
            print()
    print(f"== {n_fire}/{n_trace} traces raised >=1 rule")


if __name__ == "__main__":
    main()
