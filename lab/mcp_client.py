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

import os
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from trace import Trace, excerpt  # noqa: E402
from rpc_stdio import RpcError, StdioRpc  # noqa: E402
from mcp_proto import (  # noqa: E402
    LIST_CHANGED, PROTOCOL_VERSION, READ_TIMEOUT, VERSION,
    LineReader, McpError, initialize_session, resolve_command, shutdown,
    tools_digest,
)


class McpClient:
    """A spawned MCP server we can call tools on."""

    def __init__(self, server_cmd, trace: Trace, cwd: str | None = None,
                 timeout: float = READ_TIMEOUT,
                 protocol_version: str = PROTOCOL_VERSION,
                 rescan_on_list_changed: bool = True):
        self.trace = trace
        self.timeout = float(timeout)
        self.protocol_version = protocol_version
        self.server_info: dict = {}
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
            encoding="utf-8",
            errors="replace",
            bufsize=1,
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
        self._reader = LineReader(self.proc.stdout)
        self.rpc = StdioRpc(_write,
                            lambda: self._reader.readline(self.timeout),
                            on_notification=self._on_notification,
                            on_server_request=self._on_server_request)
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

    def _kill(self) -> None:
        try:
            self.proc.kill()
        except OSError:
            pass

    def _on_notification(self, msg: dict) -> None:
        method = msg.get("method", "notification.unknown")
        self.trace.record("in", method, params=msg.get("params"))
        if method == LIST_CHANGED and self.rescan_on_list_changed:
            self._rescan_pending = True

    def _on_server_request(self, msg: dict) -> None:
        """A server asking US a question (roots/list, sampling/...).

        The transport already answered -32601; recording it turns a silent
        stream oddity into evidence a reviewer can see in the trace.
        """
        self.trace.record("in", "server.request", method=msg.get("method"),
                          params=excerpt(msg.get("params") or {}))

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
        except TimeoutError as exc:
            self._kill()
            raise McpError(f"{method}: {exc}; server killed. "
                           f"stderr: {self.stderr_tail()[:300]}") from exc
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
        initialize_session(self)

    def list_tools(self, reason: str | None = None) -> list[dict]:
        def enrich(result: dict) -> dict:
            tools = result.get("tools", [])
            fields = {"tool_names": [t.get("name") for t in tools],
                      "tools": tools,
                      "tools_sha256": tools_digest(tools)}
            if reason:
                fields["reason"] = reason
            return fields
        result = self.request("tools/list", enrich=enrich) or {}
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
        except TimeoutError as exc:
            self._kill()
            raise McpError(f"tools/call {name}: {exc}; server killed") from exc
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
        shutdown(self.proc, self._stderr_thread)
