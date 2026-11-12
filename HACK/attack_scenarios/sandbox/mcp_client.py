#!/usr/bin/env python3
"""Minimal stdlib MCP client over stdio.

Speaks just enough JSON-RPC 2.0 to run the lab: initialize, tools/list,
tools/call. Every message is mirrored to a Trace.

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

    def __init__(self, server_cmd: str, trace: Trace, cwd: str | None = None):
        self.trace = trace
        self._id = 0
        self._stderr_lines: list[str] = []
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
            self._stderr_thread.join(timeout=1.0)
            raise McpError(
                f"server closed stdout. stderr: {self.stderr_tail()[:300]}")
        try:
            return json.loads(line)
        except json.JSONDecodeError as exc:
            raise McpError(f"server sent non-JSON: {line[:200]!r}") from exc

    def request(self, method: str, params: dict | None = None,
                enrich=None) -> dict:
        """enrich: optional callable(result) -> extra fields merged into the
        `.result` trace line. tools/list uses it to record the full tool list
        and its digest rather than only a truncated preview."""
        self._send(method, params)
        self.trace.record("out", method, id=self._id, params=excerpt(params or {}))
        resp = self._read()
        if "error" in resp:
            self.trace.record("in", f"{method}.error", error=resp["error"])
            raise McpError(f"{method} failed: {resp['error']}")
        result = resp.get("result")
        fields: dict = {"result": excerpt(result)}
        if enrich:
            fields.update(enrich(result if isinstance(result, dict) else {}))
        self.trace.record("in", f"{method}.result", **fields)
        return result

    def notify(self, method: str, params: dict | None = None) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
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

    def list_tools(self) -> list[dict]:
        def enrich(result: dict) -> dict:
            tools = result.get("tools", [])
            return {"tool_names": [t.get("name") for t in tools],
                    "tools": tools,
                    "tools_sha256": tools_digest(tools)}
        result = self.request("tools/list", enrich=enrich)
        self.tools = result.get("tools", [])
        return self.tools

    def call_tool(self, name: str, arguments: dict) -> dict:
        self.trace.record("out", "tools/call", tool=name, arguments=arguments,
                          ts=int(time.time() * 1000))
        self._send("tools/call", {"name": name, "arguments": arguments})
        resp = self._read()
        result = resp.get("result") or {"isError": True, "content": resp.get("error")}
        self.trace.record("in", "tools/call.result", tool=name,
                          isError=bool(result.get("isError")),
                          result_excerpt=excerpt(result))
        return result

    def close(self) -> None:
        """Close every pipe and join the drain thread.

        Leaking stdout/stderr emitted a ResourceWarning per scenario run and,
        on Windows, held the child's file map open until the GC got to it.
        """
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
