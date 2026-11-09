#!/usr/bin/env python3
"""Proof harness for HACK/blue: negatives under CURRENT rules, then the full
matrix under the PROPOSED ruleset via an in-process shim.

Writes nothing outside HACK/blue/. Imports lab/ read-only; monkeypatches
matching.cond_matches IN THIS PROCESS ONLY to add the three proposed keys
(arguments_any_key, arguments_value_not_matching, result_sourced_arguments)
so the proposed rules in HACK/blue/proposed_rules/ are executable evidence,
not prose. lab/ on disk is untouched.

    Section 1 (current rules): every negative must fire zero, with sanity
      gates (rules loaded == 3 with expected ids, attack corpus still fires).
    Section 2 (proposed ruleset): negatives zero, attacks fire, including the
      three result-sourced exfil traces via mcp_result_sourced_destination.
    Section 3 (reorder proof): neg_tools_list_reorder digests are equal while
      the raw tool-list JSON differs -> name-sorted digest is order-invariant,
      and the digest is not dead weight (reorder_then_append still fires).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
LAB = os.path.join(REPO, "lab")
sys.path.insert(0, LAB)

import matching  # noqa: E402
from evaluate import load_rules, evaluate_all, Rule  # noqa: E402
from trace import verify_trace, read_trace  # noqa: E402
from mcp_client import tools_digest  # noqa: E402

_orig_cond = matching.cond_matches
URL_TOKEN = re.compile(r"https?://[^\s\"'\\}\]]+", re.IGNORECASE)


def _args(entry):
    return entry.get("arguments")


def cond_shim(entry, key, cond):
    """Proposed single-line keys; everything else falls through to the engine."""
    args = _args(entry)
    if key == "arguments_any_key":
        return isinstance(args, dict) and any(k in args for k in cond)
    if key == "arguments_value_not_matching":
        # Negated allowlist: cond = {arg_name: [allow_regex, ...]}. Line
        # matches when >=1 listed arg is present and EVERY present one fails
        # all of its own allow patterns. A present whitelisted value kills
        # the line (that's the point); no listed arg present -> no signal.
        if not isinstance(args, dict):
            return False
        present = [(k, args[k]) for k in cond if k in args]
        if not present:
            return False
        return all(not any(re.fullmatch(p, str(v)) for p in cond[k])
                   for k, v in present)
    return _orig_cond(entry, key, cond)


def proposed_result_sourced(trace, spec):
    """Cross-line key: fire on a tools/call whose URL argument value was first
    seen in an EARLIER tools/call.result line (server-provided destination).
    Reads `result` (full, per the spec) and falls back to `result_excerpt`
    with a truncation caveat."""
    fired = []
    seen_urls: list[str] = []
    for i, entry in enumerate(trace, 1):
        mt = entry.get("message_type")
        if mt == "tools/call.result":
            blob = entry.get("result") or entry.get("result_excerpt") or ""
            if isinstance(blob, (dict, list)):
                blob = json.dumps(blob, default=str)
            seen_urls.extend(URL_TOKEN.findall(str(blob)))
            continue
        if mt != "tools/call":
            continue
        args = entry.get("arguments")
        if not isinstance(args, dict):
            continue
        for arg_name in spec:
            val = args.get(arg_name)
            if isinstance(val, str) and any(
                    u.rstrip(".,)") in val for u in seen_urls):
                fired.append(i)
                break
    return fired


def evaluate_proposed(rules_dir, trace):
    out = []
    for rule in load_rules(rules_dir):
        spec = rule.match.get("result_sourced_arguments")
        if spec:
            hits = proposed_result_sourced(trace, spec)
        else:
            hits = rule.evaluate(trace)
        out.append({"rule": rule.id, "fired": bool(hits),
                    "trace_lines": hits})
    return out


def load(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        return json.load(fh)


def fired_current(entries, rules):
    return [r["rule"] for r in evaluate_all(rules, entries) if r["fired"]]


def main() -> int:
    neg = load("negatives.json")
    atk = load("attack_cases.json")
    rules = load_rules(os.path.join(LAB, "rules"))
    ids = sorted(r.id for r in rules)
    expect_ids = sorted(["mcp_oauth_confused_deputy", "mcp_schema_drift",
                         "mcp_tool_poisoning"])
    assert ids == expect_ids, f"sanity gate: loaded {ids}"
    print(f"[gate] rules loaded = {len(rules)}: {ids}")

    fail = 0

    print("\n== Section 1: current rules vs negative corpus ==")
    zero = set(neg["_assertions_for_test_negatives_py"]["zero_fire_cases"])
    exempt = neg["_assertions_for_test_negatives_py"]["known_fp_exemptions"]
    for name, case in sorted(neg["cases"].items()):
        path = os.path.join(REPO, case["trace_file"])
        ok, msg = verify_trace(path)
        assert ok, f"{name}: trace chain broken: {msg}"
        entries = read_trace(path)
        fired = fired_current(entries, rules)
        if name in zero:
            status = "PASS zero" if not fired else "FAIL unexpected fire"
            if fired:
                fail += 1
        elif name in exempt:
            want = exempt[name]["fires"]
            status = ("PASS known-FP (expected)"
                      if fired == want else f"FAIL expected {want} got {fired}")
            if fired != want:
                fail += 1
        else:
            status = "unclassified"
            fail += 1
        fired_s = ", ".join(fired) if fired else "[]"
        print(f"  {name:38s} fired={fired_s:48s} {status}")

    print("\n== Section 1b: current rules vs attack corpus (sanity) ==")
    for name, case in sorted(atk["cases"].items()):
        entries = read_trace(os.path.join(REPO, case["trace_file"]))
        fired = fired_current(entries, rules)
        intended = case["intended_rule"].split(" ")[0]
        okp = intended in fired
        if intended.startswith("mcp_result_sourced") or "PROPOSED" in case["intended_rule"]:
            okp = fired == []  # expected MISS is the proof for these
            tag = "EXPECTED MISS (proof)" if not fired else "UNEXPECTED FIRE"
        else:
            tag = "DETECTED" if okp else "MISSED (regression!)"
        if not okp:
            fail += 1
        fired_s = ", ".join(fired) if fired else "[]"
        print(f"  {name:38s} fired={fired_s:48s} {tag}")

    print("\n== Section 2: PROPOSED ruleset (shim) ==")
    matching.KNOWN_KEYS.update({"arguments_any_key",
                                "arguments_value_not_matching",
                                "result_sourced_arguments"})
    matching.cond_matches = cond_shim
    # re-load proposed rules through the patched validator
    prop_dir = os.path.join(HERE, "proposed_rules")
    prop_rules = [Rule(os.path.join(prop_dir, f))
                  for f in sorted(os.listdir(prop_dir))
                  if f.endswith((".yaml", ".yml"))]
    print(f"  proposed rules loaded: {sorted(r.id for r in prop_rules)}")
    for label, doc, want in (("negative", neg, "zero"), ("attack", atk, "fire")):
        for name, case in sorted(doc["cases"].items()):
            entries = read_trace(os.path.join(REPO, case["trace_file"]))
            res = evaluate_proposed(prop_dir, entries)
            fired = [r["rule"] for r in res if r["fired"]]
            lines = {r["rule"]: r["trace_lines"] for r in res if r["fired"]}
            if want == "zero":
                # case6 is allowed to fire ONLY if allowlist config missing;
                # with proposed allowlist it must be zero.
                okp = not fired
            else:
                intended = case["intended_rule"].split(" ")[0]
                okp = intended in fired
            if not okp:
                fail += 1
            print(f"  [{label:8s}] {name:38s} fired={lines or '[]'} "
                  f"{'ok' if okp else 'FAIL'}")

    print("\n== Section 3: reorder-invariance proof ==")
    entries = read_trace(os.path.join(
        REPO, neg["cases"]["neg_tools_list_reorder"]["trace_file"]))
    lists = [e for e in entries if e["message_type"] == "tools/list.result"]
    digests = [e["tools_sha256"] for e in lists]
    raws = [json.dumps(e["tools"], sort_keys=True) for e in lists]
    assert len(set(digests)) == 1, "digests differ on a pure reorder"
    assert len(set(raws)) > 1, "raw listings identical: reorder not exercised"
    recomputed = [tools_digest(e["tools"]) for e in lists]
    assert recomputed == digests, "digest not re-derivable from line's tools"
    print(f"  {len(lists)} listings, raw JSON distinct={len(set(raws))}, "
          f"digests all equal={digests[0][:16]}... (recomputed: equal)")
    ent2 = read_trace(os.path.join(
        REPO, atk["cases"]["reorder_then_append"]["trace_file"]))
    drift = [r for r in evaluate_all(rules, ent2)
             if r["rule"] == "mcp_schema_drift"][0]
    print(f"  reorder_then_append fires mcp_schema_drift on lines "
          f"{drift['trace_lines']} -> digest is order-invariant, not inert")
    if not drift["fired"]:
        fail += 1

    print(f"\n{'ALL PROOFS PASS' if fail == 0 else f'{fail} FAILURE(S)'}")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
