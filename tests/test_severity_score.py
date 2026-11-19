"""Unit tests for the severity-weighted coverage score.

The pure helpers are checked directly; the gate at the bottom runs main() with
its output swallowed, since the exit code is the contract.
"""
import contextlib
import io
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "lab"))
sys.path.insert(0, REPO)

import summary  # noqa: E402


class TestScore(unittest.TestCase):
    def test_all_detected_is_100(self):
        pairs = [("low", True), ("medium", True),
                 ("high", True), ("critical", True)]
        earned, total, pct = summary.score(pairs, summary.DEFAULT_WEIGHTS)
        self.assertEqual(earned, total)
        self.assertEqual(pct, 100.0)
        self.assertEqual(total, 19)

    def test_missed_critical_costs_its_weight(self):
        pairs = [("critical", False), ("high", True)]
        earned, total, pct = summary.score(pairs, summary.DEFAULT_WEIGHTS)
        self.assertEqual((earned, total), (5, 15))
        self.assertAlmostEqual(pct, 100.0 * 5 / 15)
        self.assertLess(pct, 100.0)

    def test_custom_weights_are_used(self):
        weights = summary.parse_weights("critical=20,high=5,medium=2,low=1")
        pairs = [("critical", True), ("low", False)]
        earned, total, pct = summary.score(pairs, weights)
        self.assertEqual((earned, total), (20, 21))
        self.assertAlmostEqual(pct, 100.0 * 20 / 21)

    def test_unknown_severity_is_deterministic(self):
        earned, total, pct = summary.score(
            [("brand-new", True)], summary.DEFAULT_WEIGHTS)
        self.assertEqual((earned, total, pct), (1, 1, 100.0))


class TestParseWeights(unittest.TestCase):
    def test_missing_value_raises(self):
        with self.assertRaises(ValueError):
            summary.parse_weights("low=")

    def test_missing_equals_raises(self):
        with self.assertRaises(ValueError):
            summary.parse_weights("low")

    def test_non_numeric_raises(self):
        with self.assertRaises(ValueError):
            summary.parse_weights("low=abc")

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            summary.parse_weights("")


class TestThresholdGate(unittest.TestCase):
    """The gate itself -- main() with --threshold, output swallowed."""

    def _run(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = summary.main(list(argv))
        return code, buf.getvalue()

    def test_threshold_at_full_score_passes(self):
        code, out = self._run("--threshold", "100")
        self.assertEqual(code, 0, out)
        self.assertIn("score: ", out)

    def test_threshold_above_score_fails(self):
        code, out = self._run("--threshold", "101")
        self.assertEqual(code, 1, out)

    def test_no_threshold_prints_no_score_line(self):
        code, out = self._run()
        self.assertEqual(code, 0, out)
        self.assertNotIn("score: ", out)


if __name__ == "__main__":
    unittest.main()
