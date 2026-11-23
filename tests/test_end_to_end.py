"""End-to-end tests for the lab.

Runs every scenario through run.py's pipeline and asserts the loop works:

  * each attack scenario is DETECTED by its expected rule (exit 0)
  * the benign control raises NO rule (exit 0, clean)
  * a forged detection is impossible: every fired rule cites trace lines
  * evaluating rules against an empty trace fires nothing
"""
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "lab"))
sys.path.insert(0, REPO)

import run as runner  # noqa: E402
from evaluate import evaluate_all, load_rules  # noqa: E402
from trace import read_trace  # noqa: E402

SCEN_DIR = os.path.join(REPO, "lab", "scenarios")


class TestScenarios(unittest.TestCase):
    def _run(self, name):
        path = os.path.join(SCEN_DIR, name)
        report = runner.run_scenario(path, write_report=False)
        self.assertIsNone(report["error"], report["error"])
        return report

    def test_tool_poisoning_detected(self):
        r = self._run("tool_poisoning.yaml")
        self.assertEqual(r["exit_code"], 0, r)
        self.assertTrue(r["detected"])
        fired = [x["rule"] for x in r["results"] if x["fired"]]
        self.assertIn("mcp_tool_poisoning", fired)

    def test_schema_rugpull_detected(self):
        r = self._run("schema_rugpull.yaml")
        self.assertEqual(r["exit_code"], 0, r)
        self.assertTrue(r["detected"])
        fired = [x["rule"] for x in r["results"] if x["fired"]]
        self.assertIn("mcp_schema_drift", fired)

    def test_confused_deputy_detected(self):
        r = self._run("confused_deputy.yaml")
        self.assertEqual(r["exit_code"], 0, r)
        self.assertTrue(r["detected"])
        fired = [x["rule"] for x in r["results"] if x["fired"]]
        self.assertIn("mcp_oauth_confused_deputy", fired)

    def test_benign_control_clean(self):
        r = self._run("benign_control.yaml")
        self.assertEqual(r["exit_code"], 0, r)
        self.assertFalse(r["detected"])
        self.assertEqual(r["rules_fired"], 0,
                         "no rule may fire on the benign control")

    def test_every_fired_rule_has_evidence(self):
        """A detection with no trace lines would be a fabricated detection."""
        for name in os.listdir(SCEN_DIR):
            if not name.endswith(".yaml"):
                continue
            report = runner.run_scenario(
                os.path.join(SCEN_DIR, name), write_report=False)
            for rule_result in report["results"]:
                if rule_result["fired"]:
                    self.assertTrue(
                        rule_result["trace_lines"],
                        f"{name}: {rule_result['rule']} fired with no evidence")


class TestRuleEngine(unittest.TestCase):
    def test_empty_trace_fires_nothing(self):
        rules = load_rules(os.path.join(REPO, "lab", "rules"))
        results = evaluate_all(rules, [])
        self.assertTrue(all(not r["fired"] for r in results))

    def test_evidence_lines_exist(self):
        """Regenerate the traces, then prove every cited line is in range."""
        rules = load_rules(os.path.join(REPO, "lab", "rules"))
        for name in sorted(os.listdir(SCEN_DIR)):
            if not name.endswith(".yaml"):
                continue
            with tempfile.TemporaryDirectory() as tmp:
                report = runner.run_scenario(
                    os.path.join(SCEN_DIR, name), out_dir=tmp)
                self.assertIsNone(report["error"], report["error"])
                trace_path = os.path.join(
                    tmp, report["scenario"] + ".trace.jsonl")
                entries = read_trace(trace_path)
                for result in evaluate_all(rules, entries):
                    for line in result["trace_lines"]:
                        self.assertGreater(line, 0)
                        self.assertLessEqual(
                            line, len(entries),
                            f"{name}: line {line} out of range")


if __name__ == "__main__":
    unittest.main()
