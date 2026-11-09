#!/usr/bin/env python3
"""Minimal stdlib MCP client over stdio.

Speaks just enough JSON-RPC 2.0 to run the lab: initialize, tools/list,
tools/call. Every message is mirrored to a Trace.

No MCP SDK, no network, no LLM. Deterministic.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from trace import Trace, excerpt  # noqa: E402


def resolve_command(cmd: str) -> list[str]:
    """Windows: `python` needs the real interpreter, not the Store shim."""
    parts = cmd.split()
    if os.name == "nt" and parts[0] in ("python", "python3"):
        return [sys.executable] + parts[1:]
    return parts


class McpError(Exception):
    pass


class McpClient:
    """A spawned MCP server we can call tools on."""

    def __init__(self, server_cmd: str, trace: Trace):
        self.trace = trace
        self._id = 0
        self.proc = subprocess.Popen(
            resolve_command(server_cmd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.tools: list[dict] = []
        self.initialize()

    # ---------- plumbing ----------

    def _send(self, method: str, params: dict | None) -> None:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def _read(self) -> dict:
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise McpError(f"server closed stdout. stderr: {err[:300]}")
        return json.loads(line)

    def request(self, method: str, params: dict | None = None) -> dict:
        self._send(method, params)
        self.trace.record("out", method, id=self._id, params=excerpt(params or {}))
        resp = self._read()
        if "error" in resp:
            self.trace.record("in", f"{method}.error", error=resp["error"])
            raise McpError(f"{method} failed: {resp['error']}")
        self.trace.record("in", f"{method}.result", result=excerpt(resp.get("result")))
        return resp["result"]

    def notify(self, method: str, params: dict | None = None) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        self.trace.record("out", f"notification.{method}", params=excerpt(params or {}))

    # ---------- MCP methods ----------

    def initialize(self) -> None:
        self.request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-purple-lab", "version": "0.1.0"},
        })
        self.notify("notifications/initialized")

    def list_tools(self) -> list[dict]:
        result = self.request("tools/list")
        self.tools = result.get("tools", [])
        return self.tools

    def call_tool(self, name: str, arguments: dict) -> dict:
        self.trace.record(
            "out", "tools/call", tool=name, arguments=arguments, ts=int(time.time() * 1000)
        )
        self._send("tools/call", {"name": name, "arguments": arguments})
        resp = self._read()
        result = resp.get("result") or {"isError": True, "content": resp.get("error")}
        self.trace.record(
            "in", "tools/call.result", tool=name,
            isError=bool(result.get("isError")), result_excerpt=excerpt(result),
        )
        return result

    def close(self) -> None:
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
