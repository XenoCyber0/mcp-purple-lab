#!/usr/bin/env python3
"""Minimal stdlib MCP client over stdio.

Speaks just enough JSON-RPC 2.0 to run the lab: initialize, tools/list,
tools/call, and server-pushed notifications. Every message is mirrored to a
Trace.

Transport framing lives in rpc_stdio.StdioRpc: reads route by request id, so
a server pushing notifications/tools/list_changed (spec-compliant) can no
longer shift every later message by one. On list_changed the client re-lists
(deferred, so a callback never re-enters the read loop); the re-list carries
a fresh digest, which is what mcp_schema_drift consumes.

No MCP SDK, no network, no LLM. Deterministic.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from trace import Trace, excerpt  # noqa: E402
from rpc_stdio import RpcError, StdioRpc  # noqa: E402

LIST_CHANGED = "notifications/tools/list_changed"


def resolve_command(cmd: str) -> list[str]:
    """`python foo.py` -> [<this interpreter>, foo.py] on EVERY OS.

    Resolving to sys.executable everywhere (not only on Windows) keeps a Linux
    CI runner spawning the interpreter actually running the lab, venv
    included, instead of whatever bare `python` happens to be on PATH.
    """
    parts = cmd.split()
    if parts and parts[0] in ("python", "python3"):
        return [sys.executable] + parts[1:]
    return parts


def tools_digest(tools: list[dict]) -> str:
    """SHA-256 over the canonical tool list: sorted by name, keys sorted.

    Sorting by name means a server merely reordering an otherwise identical
    list is NOT drift; adding, removing, or changing any field of any tool IS.
    A digest over the FULL list cannot be evaded by appending a tool past a
    200-char preview window, which is how a real rug-pull actually lands.
    """
    canon = json.dumps(sorted(tools, key=lambda t: t.get("name", "")),
                       sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


class McpError(Exception):
    pass


class McpClient:
    """A spawned MCP server we can call tools on."""

    def __init__(self, server_cmd: str, trace: Trace, cwd: str | None = None,
                 rescan_on_list_changed: bool = True):
        self.trace = trace
        self._id = 0
        self._stderr_lines: list[str] = []
        self._rescan_pending = False
        self.rescan_on_list_changed = rescan_on_list_changed
        self.proc = subprocess.Popen(
            resolve_command(server_cmd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
        )
        # Drain stderr on a daemon thread. Without this a chatty server fills
        # the ~64 KB pipe buffer and blocks in write() while we sit on
        # stdout.readline() -- a deadlock that looks like a hung scenario and
        # is indistinguishable from a real hang in CI.
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()
        # write+flush closure: an unflushed line never reaches the pipe and
        # read_until blocks forever -- the old client flushed after every write.
        def _write(line: str) -> None:
            self.proc.stdin.write(line)
            self.proc.stdin.flush()
        self.rpc = StdioRpc(_write, self.proc.stdout.readline,
                            on_notification=self._on_notification)
        self.tools: list[dict] = []
        self.initialize()

    def _drain_stderr(self) -> None:
        if self.proc.stderr is None:
            return
        try:
            for line in self.proc.stderr:
                self._stderr_lines.append(line.rstrip())
        except (ValueError, OSError):
            pass  # parent closed the pipe during close(); normal shutdown

    def stderr_tail(self, limit: int = 12) -> str:
        return " | ".join(self._stderr_lines[-limit:])

    def _on_notification(self, msg: dict) -> None:
        method = msg.get("method", "notification.unknown")
        self.trace.record("in", method, params=msg.get("params"))
        if method == LIST_CHANGED and self.rescan_on_list_changed:
            self._rescan_pending = True

    # ---------- plumbing ----------

    def request(self, method: str, params: dict | None = None,
                enrich=None) -> dict:
        """enrich: optional callable(result) -> extra fields merged into the
        `.result` trace line. tools/list uses it to record the full tool list
        and its digest rather than only a truncated preview."""
        self._id += 1
        rid = self._id
        self.trace.record("out", method, id=rid, params=excerpt(params or {}))
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        try:
            self.rpc.send(msg)
            resp = self.rpc.read_until(rid)
        except OSError as exc:
            raise McpError(f"write failed: {exc}") from exc
        except RpcError as exc:
            raise McpError(f"{method}: {exc}. "
                           f"stderr: {self.stderr_tail()[:300]}") from exc
        if "error" in resp:
            self.trace.record("in", f"{method}.error", error=resp["error"])
            raise McpError(f"{method} failed: {resp['error']}")
        result = resp.get("result")
        fields: dict = {"result": excerpt(result)}
        if enrich:
            fields.update(enrich(result if isinstance(result, dict) else {}))
        self.trace.record("in", f"{method}.result", **fields)
        # Deferred rescan: never re-enter the read loop from a callback.
        if self._rescan_pending and method != "tools/list":
            self._rescan_pending = False
            self.list_tools(reason=LIST_CHANGED)
        return result

    def notify(self, method: str, params: dict | None = None) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.rpc.send(msg)
        self.trace.record("out", f"notification.{method}",
                          params=excerpt(params or {}))

    # ---------- MCP methods ----------

    def initialize(self) -> None:
        self.request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-purple-lab", "version": "0.1.0"},
        })
        self.notify("notifications/initialized")

    def list_tools(self, reason: str | None = None) -> list[dict]:
        def enrich(result: dict) -> dict:
            tools = result.get("tools", [])
            fields = {"tool_names": [t.get("name") for t in tools],
                      "tools": tools,
                      "tools_sha256": tools_digest(tools)}
            if reason:
                fields["reason"] = reason
            return fields
        result = self.request("tools/list", enrich=enrich)
        self.tools = result.get("tools", [])
        return self.tools

    def call_tool(self, name: str, arguments: dict) -> dict:
        self.trace.record("out", "tools/call", tool=name, arguments=arguments,
                          ts=int(time.time() * 1000))
        self._id += 1
        rid = self._id
        try:
            self.rpc.send({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                           "params": {"name": name, "arguments": arguments}})
            resp = self.rpc.read_until(rid)
        except OSError as exc:
            raise McpError(f"write failed: {exc}") from exc
        except RpcError as exc:
            raise McpError(f"tools/call {name}: {exc}") from exc
        result = resp.get("result") or {"isError": True, "content": resp.get("error")}
        # `result` is the FULL payload: the evidence layer for provenance
        # rules (D4). `result_excerpt` stays for humans only, never an input.
        self.trace.record("in", "tools/call.result", tool=name,
                          isError=bool(result.get("isError")),
                          result=result, result_excerpt=excerpt(result))
        if self._rescan_pending:
            self._rescan_pending = False
            self.list_tools(reason=LIST_CHANGED)
        return result

    def close(self) -> None:
        for pipe in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            try:
                if pipe and not pipe.closed:
                    pipe.close()
            except OSError:
                pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=2)
        self._stderr_thread.join(timeout=2.0)
