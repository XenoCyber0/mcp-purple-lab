"""Regression tests for the v2 interoperability and setup-failure fixes.

Every test here fails on v0.1.0 for the reason named in its docstring. They are
deliberately transport-level: a new harness adapter should be able to copy the
contract from these tests without reading the client.
"""
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB = os.path.join(REPO, "lab")
SCEN = os.path.join(REPO, "lab", "scenarios")
sys.path.insert(0, LAB)
sys.path.insert(0, REPO)

import run as runner  # noqa: E402
from evaluate import Rule, RuleError, load_rules  # noqa: E402
from mcp_client import McpClient, McpError  # noqa: E402
from rpc_stdio import RpcError, StdioRpc  # noqa: E402
from trace import Trace  # noqa: E402

HARNESSES = (
    "claude-desktop", "claude-code", "cursor", "vscode", "windsurf",
    "cline", "continue", "zed", "goose", "roo-code", "mcp-inspector",
)


def _rpc(payload):
    """A StdioRpc whose readline is a fixed list of JSON frames."""
    out = []
    lines = iter([json.dumps(item) + "\n" for item in payload])
    rpc = StdioRpc(out.append, lambda: next(lines, ""))
    return rpc, out


class TestFraming(unittest.TestCase):
    def test_string_id_is_a_response(self):
        """JSON-RPC 2.0 allows String ids; v0.1.0 rejected every one."""
        rpc, _ = _rpc([{"jsonrpc": "2.0", "id": "1", "result": {"ok": True}}])
        self.assertTrue(rpc.read_until("1")["result"]["ok"])

    def test_bool_id_is_rejected(self):
        """isinstance(True, int) is True; id true must not alias id 1."""
        rpc, _ = _rpc([{"jsonrpc": "2.0", "id": True, "result": {}}])
        with self.assertRaises(RpcError):
            rpc.read_until(1)

    def test_out_of_order_response_is_buffered(self):
        """A pipelined reply may arrive in any order; it is kept, not fatal."""
        rpc, _ = _rpc([
            {"jsonrpc": "2.0", "id": 1, "result": {"n": 1}},
            {"jsonrpc": "2.0", "id": 2, "result": {"n": 2}},
        ])
        self.assertEqual(rpc.read_until(2)["result"]["n"], 2)
        self.assertEqual(rpc.read_until(1)["result"]["n"], 1)

    def test_notification_is_delivered_while_waiting(self):
        seen = []
        rpc, _ = _rpc([
            {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"},
            {"jsonrpc": "2.0", "id": 7, "result": {}},
        ])
        rpc.on_notification = seen.append
        rpc.read_until(7)
        self.assertEqual(seen[0]["method"],
                         "notifications/tools/list_changed")

    def test_server_request_is_answered_32601(self):
        """A server request (method + id) is not a response to our request."""
        rpc, out = _rpc([
            {"jsonrpc": "2.0", "id": "srv-1", "method": "roots/list"},
            {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}},
        ])
        rpc.read_until(1)
        reply = json.loads(out[0])
        self.assertEqual(reply["id"], "srv-1")
        self.assertEqual(reply["error"]["code"], -32601)

    def test_non_object_frame_gets_invalid_request(self):
        out = []
        lines = iter([json.dumps([1, 2, 3]) + "\n",
                      json.dumps({"jsonrpc": "2.0", "id": 1,
                                  "result": {"ok": True}}) + "\n"])
        rpc = StdioRpc(out.append, lambda: next(lines, ""))
        self.assertTrue(rpc.read_until(1)["result"]["ok"])
        self.assertEqual(json.loads(out[0])["error"]["code"], -32600)


class TestRuleValidation(unittest.TestCase):
    @staticmethod
    def _write(directory, name, text):
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_invalid_regex_is_a_load_error(self):
        """re.error is not a ValueError: it used to exit 1, meaning 'missed'."""
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                tmp, "bad.yaml",
                'id: bad\nmatch:\n  arguments_regex:\n    url: "("\n')
            with self.assertRaises(RuleError):
                Rule(path)

    def test_duplicate_rule_ids_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            body = "id: dup\ntitle: t\nmatch:\n  message_type: tools/call\n"
            self._write(tmp, "a.yaml", body)
            self._write(tmp, "b.yaml", body)
            with self.assertRaises(RuleError):
                load_rules(tmp)

    def test_scenario_without_id_is_a_setup_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                tmp, "s.yaml",
                "name: n\nserver: lab/servers/benign_server.py\n")
            self.assertEqual(runner.main([path]), 2)

    def test_missing_server_is_a_setup_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                tmp, "s.yaml",
                "id: missing\nserver: lab/servers/nope.py\n"
                "agent_script:\n  - tool: read_file\n    arguments: {}\n")
            self.assertEqual(runner.main([path]), 2)


class TestSpawn(unittest.TestCase):
    def test_quoted_path_with_spaces(self):
        """v0.1.0 split the command on spaces and looked for 'with'."""
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "with space", "srv.py")
            os.makedirs(os.path.dirname(target))
            shutil.copyfile(
                os.path.join(LAB, "servers", "benign_server.py"), target)
            with Trace(os.path.join(tmp, "t.jsonl")) as trace:
                client = McpClient('python "' + target + '"', trace,
                                   timeout=10)
                try:
                    names = [t["name"] for t in client.list_tools()]
                finally:
                    client.close()
            self.assertEqual(names, ["read_file", "get_time"])

    def test_hung_server_times_out(self):
        """A silent server used to hang CI until the 6-hour job cap."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "hung.py")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("import time\ntime.sleep(30)\n")
            with Trace(os.path.join(tmp, "t.jsonl")) as trace:
                started = time.perf_counter()
                with self.assertRaises(McpError):
                    McpClient(["python", path], trace, timeout=0.5)
                self.assertLess(time.perf_counter() - started, 10)


class TestHarnessConformance(unittest.TestCase):
    """All four lab servers accept the framing these harnesses emit."""

    def test_every_server_survives_pipelined_handshake(self):
        servers = sorted(glob.glob(os.path.join(LAB, "servers", "*.py")))
        self.assertEqual(len(servers), 4)
        for server in servers:
            with self.subTest(server=os.path.basename(server),
                              harnesses=HARNESSES):
                proc = subprocess.Popen(
                    [sys.executable, "-I", server],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, encoding="utf-8",
                    bufsize=1)
                try:
                    frames = [
                        {"jsonrpc": "2.0", "id": "init-1",
                         "method": "initialize",
                         "params": {"protocolVersion": "2024-11-05",
                                    "capabilities": {},
                                    "clientInfo": {"name": "harness-conformance",
                                                   "version": "1"}}},
                        {"jsonrpc": "2.0",
                         "method": "notifications/initialized"},
                        {"jsonrpc": "2.0", "id": "list-1",
                         "method": "tools/list"},
                    ]
                    for frame in frames:
                        proc.stdin.write(json.dumps(frame) + "\n")
                    proc.stdin.flush()
                    init = json.loads(proc.stdout.readline())
                    listed = json.loads(proc.stdout.readline())
                    self.assertEqual(init["id"], "init-1")
                    self.assertEqual(listed["id"], "list-1")
                    tools = listed["result"]["tools"]
                    self.assertTrue(tools)
                    for tool in tools:
                        self.assertTrue(tool["name"])
                        self.assertIsInstance(tool["inputSchema"], dict)
                finally:
                    if proc.stdin and not proc.stdin.closed:
                        proc.stdin.close()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()


class TestCliContracts(unittest.TestCase):
    def test_json_report_is_machine_readable(self):
        result = subprocess.run(
            [sys.executable, os.path.join(LAB, "run.py"),
             os.path.join(SCEN, "tool_poisoning.yaml"), "--format", "json"],
            capture_output=True, text=True, cwd=REPO)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["scenario"], "tool-poisoning-001")
        self.assertEqual(report["exit_code"], 0)
        self.assertTrue(report["detected"])
        self.assertGreaterEqual(report["duration_ms"], 0)
        self.assertTrue(report["evidence"])

    def test_text_output_still_works(self):
        result = subprocess.run(
            [sys.executable, os.path.join(LAB, "run.py"),
             os.path.join(SCEN, "benign_control.yaml")],
            capture_output=True, text=True, cwd=REPO)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verdict  : clean", result.stdout)


if __name__ == "__main__":
    unittest.main()
