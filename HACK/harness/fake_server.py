#!/usr/bin/env python3
"""fake_server.py -- PROPOSAL fixture: minimal stdlib MCP server over stdio.

Used ONLY by HACK/harness/test_harness_proposed.py (and manual harness smoke
runs). It is NOT a lab scenario server: nothing under lab/ imports or runs it.

Protocol: newline-delimited JSON-RPC 2.0 over stdin/stdout. stdout carries
protocol messages ONLY (every response flushed immediately); diagnostics go
to stderr. Implements initialize, notifications/initialized (no reply),
tools/list and tools/call; unknown methods answer JSON-RPC -32601. EOF exits.

Tools:
  send_report  {destination, data}  -> "report sent" (destination must be a
                                      reserved canary domain: *.example/*.invalid)
  echo         {text}               -> text unchanged

Modes (for harness defect probing, default is boring and deterministic):
  --notify-before-response   emit a notifications/message NOTIFICATION with no
                             "id" immediately before every response. Per
                             JSON-RPC the client must skip notifications and
                             keep waiting for the object whose id matches.
                             McpClient._read() does not: it treats the next
                             JSON object as the response -- this flag is the
                             repro for that defect (see findings.md).
"""
from __future__ import annotations

import json
import sys

TOOLS = [
    {
        "name": "send_report",
        "description": "Send a report to a destination URL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "destination": {"type": "string"},
                "data": {"type": "string"},
            },
            "required": ["destination", "data"],
        },
    },
    {
        "name": "echo",
        "description": "Return the supplied text unchanged.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
]


def write(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def notify() -> None:
    """A server->client notification: has a method, deliberately NO id."""
    write({"jsonrpc": "2.0", "method": "notifications/message",
           "params": {"level": "info", "data": "progress"}})


def call_tool(name: str, args: dict) -> dict:
    if name == "echo":
        return {"content": [{"type": "text", "text": str(args.get("text", ""))}],
                "isError": False}
    if name == "send_report":
        dest = str(args.get("destination", ""))
        # Lab hygiene: refuse anything that is not a reserved canary domain.
        if not dest.endswith((".example", ".invalid")) and "://" not in dest:
            return {"content": [{"type": "text", "text": "invalid destination"}],
                    "isError": True}
        return {"content": [{"type": "text",
                             "text": f"report sent to {dest}"}],
                "isError": False}
    return {"content": [{"type": "text", "text": f"unknown tool: {name}"}],
            "isError": True}


def handle(req: dict, announce: bool) -> None:
    method = req.get("method")
    if "id" not in req:                      # client notification: never replies
        return
    rid = req["id"]
    if announce:
        notify()                             # the misread trigger
    params = req.get("params") or {}
    if method == "initialize":
        result = {"protocolVersion": params.get("protocolVersion", "2024-11-05"),
                  "capabilities": {"tools": {}},
                  "serverInfo": {"name": "fake-external-mcp", "version": "0.1.0"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        result = call_tool(str(params.get("name", "")),
                           params.get("arguments") or {})
    else:
        write({"jsonrpc": "2.0", "id": rid,
               "error": {"code": -32601, "message": f"method not found: {method}"}})
        return
    write({"jsonrpc": "2.0", "id": rid, "result": result})


def main(argv: list[str]) -> int:
    announce = "--notify-before-response" in argv
    sys.stderr.write(f"fake_server up (notify={announce})\n")
    sys.stderr.flush()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            sys.stderr.write(f"non-JSON on stdin: {line[:80]!r}\n")
            continue
        handle(req, announce)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
