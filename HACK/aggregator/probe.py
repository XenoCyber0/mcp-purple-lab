#!/usr/bin/env python3
"""Aggregator verification probe. Read-only w.r.t. the repo: every trace and
temp rule is written under HACK/aggregator/scratch, never out/.

Proves/disproves four defects found by inspection:
  A  run.py builds a CWD-RELATIVE server command but McpClient's Popen passes
     no cwd -> the whole lab only runs from the repo root.
  B  Rule.line_matches returns early on `OR`, silently discarding sibling keys
     (message_type) -> rules fire on line types they declare they exclude.
  C  `on_change` and any unimplemented match key return False with no error ->
     a typo'd key is a permanent, invisible false negative.
  D  track_field compares mcp_client.excerpt()'d results, truncated at 200
     chars -> drift confined to the tail of a tools/list is undetectable.
"""
import json
import os
import sys

LAB = r"./lab"
SCRATCH = r"./HACK/aggregator/scratch"
os.makedirs(SCRATCH, exist_ok=True)
sys.path.insert(0, LAB)

import yaml  # noqa: E402
from trace import Trace, excerpt, read_trace  # noqa: E402
from mcp_client import McpClient  # noqa: E402
from evaluate import Rule  # noqa: E402

print("cwd          =", os.getcwd())
print("sys.executable =", os.path.basename(sys.executable))
print()

# ---------------------------------------------------------------- A
print("A) server command is relative, Popen passes no cwd")
tp = os.path.join(SCRATCH, "a.trace.jsonl")
t = Trace(tp)
try:
    c = McpClient("python lab/servers/benign_server.py", t)
    print("   relative cmd from this cwd -> SPAWNED OK (defect not reproduced)")
    c.close()
except Exception as exc:  # noqa: BLE001
    print("   relative cmd from this cwd -> %s: %s"
          % (type(exc).__name__, str(exc)[:180]))
finally:
    t.close()

tp2 = os.path.join(SCRATCH, "a2.trace.jsonl")
t2 = Trace(tp2)
try:
    c2 = McpClient("python " + os.path.join(LAB, "servers", "benign_server.py"), t2)
    print("   absolute cmd               -> SPAWNED OK, tools=%s"
          % [x["name"] for x in c2.list_tools()])
    c2.close()
except Exception as exc:  # noqa: BLE001
    print("   absolute cmd               -> %s: %s"
          % (type(exc).__name__, str(exc)[:180]))
finally:
    t2.close()
    print("   lines in a2 trace:", len(read_trace(tp2)))
print()


def mk(name, data):
    p = os.path.join(SCRATCH, name)
    with open(p, "w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh)
    return Rule(p)

# ---------------------------------------------------------------- B
print("B) `OR` short-circuits sibling match keys")
r = mk("b.yaml", {
    "id": "or_swallows_siblings",
    "match": {"message_type": "tools/call",
              "OR": [{"tool_name_contains": ["send_"]}]},
})
trace_b = [
    {"dir": "out", "message_type": "tools/call", "tool": "send_report",
     "arguments": {"body": "quarterly"}},
    {"dir": "in", "message_type": "tools/call.result", "tool": "send_report",
     "isError": False},
    {"dir": "in", "message_type": "tools/list.result", "tool": "send_report"},
    {"dir": "lab", "message_type": "server_started", "server": "x"},
]
print("   declared message_type=tools/call, fired lines =", r.evaluate(trace_b))
print("   ^ 1 is the only legitimate line; 2 and 3 are other message types")
print()

# ---------------------------------------------------------------- C
print("C) unimplemented / typo'd match keys fail silently")
rc = mk("c1.yaml", {"id": "typo", "match": {"message_typ": "tools/call",
                                            "tool": "send_report"}})
print("   rule with key 'message_typ' fired lines =", rc.evaluate(trace_b),
      "<- expected 1, got nothing, no error raised")
rd = mk("c2.yaml", {"id": "on_change_ignored",
                    "match": {"message_type": "tools/list.result",
                              "track_field": "result",
                              "on_change": {"fired": False}}})
trace_d = [
    {"dir": "in", "message_type": "tools/list.result", "result": '{"tools": ["ping"]}'},
    {"dir": "in", "message_type": "tools/list.result", "result": '{"tools": ["ping", "export_secrets"]}'},
]
print("   on_change.fired=False still fires?", rd.evaluate(trace_d),
      "<- engine never reads on_change at all")
print()

# ---------------------------------------------------------------- D
print("D) excerpt() truncation hides tail-of-list drift")
first = {"tools": [{"name": "a" * 1, "description": "D" * 380},
                   {"name": "ping", "description": "Health check."}]}
after = json.loads(json.dumps(first))
after["tools"].append({"name": "export_secrets",
                       "description": "Export stored credentials."})
e1, e2 = excerpt(first), excerpt(after)
print("   excerpt equal after a tool was ADDED?", e1 == e2)
print("   excerpt len =", len(e1), "(window =", 200, "chars)")
rr = mk("d.yaml", {"id": "drift", "match": {"message_type": "tools/list.result",
                                            "track_field": "result"}})
trace_e = [
    {"dir": "in", "message_type": "tools/list.result", "result": e1},
    {"dir": "in", "message_type": "tools/list.result", "result": e2},
]
print("   mcp_schema_drift-style rule fired lines =", rr.evaluate(trace_e),
      "<- empty means the rug-pull is invisible")
print()

# ------------------------------------------------- E: cross-fire on control
print("E) benign-but-suspicious: legit tool name + legit https arg")
re_ = mk("e.yaml", {"id": "mcp_tool_poisoning_as_shipped",
                    "match": {"message_type": "tools/call",
                              "OR": [{"tool_name_contains": ["canary", "send_",
                                                             "exfil", "upload_",
                                                             "report_"]},
                                     {"arguments_contains_url": True}]}})
trace_f = [
    {"dir": "out", "message_type": "tools/call", "tool": "render_report",
     "arguments": {"fmt": "pdf"}},
    {"dir": "out", "message_type": "tools/call", "tool": "fetch_doc",
     "arguments": {"url": "https://app.example/docs/intro"}},
    {"dir": "out", "message_type": "tools/call", "tool": "read_file",
     "arguments": {"path": "notes.txt"}},
]
print("   fired lines =", re_.evaluate(trace_f),
      "<- 1 and 2 are entirely benign")
print()
print("probe scratch:", SCRATCH)
