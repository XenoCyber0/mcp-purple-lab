"""Tests for the Sigma exporter.

Asserts one file per lab rule, that each file is real YAML with the fields a
SIEM needs, and that exporting twice is byte-identical.
"""
import os
import sys
import tempfile
import unittest
import uuid

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "lab"))
sys.path.insert(0, REPO)

import export_sigma  # noqa: E402

RULES = os.path.join(REPO, "lab", "rules")


class TestSigmaExport(unittest.TestCase):
    def _export(self, out):
        return export_sigma.export_rules(RULES, out, author="test-author")

    def test_one_file_per_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            written = self._export(os.path.join(tmp, "sigma"))
            sources = [n for n in os.listdir(RULES)
                       if n.endswith((".yaml", ".yml"))]
            self.assertEqual(len(written), len(sources))
            for path in written:
                self.assertTrue(os.path.isfile(path))

    def test_required_fields_and_uuid(self):
        with tempfile.TemporaryDirectory() as tmp:
            for path in self._export(os.path.join(tmp, "sigma")):
                with open(path, encoding="utf-8") as fh:
                    doc = yaml.safe_load(fh)
                for field in ("title", "id", "logsource", "detection", "level"):
                    self.assertIn(field, doc, path)
                self.assertEqual(str(uuid.UUID(doc["id"])), doc["id"])
                self.assertIn("condition", doc["detection"])

    def test_export_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self._export(os.path.join(tmp, "a"))
            second = self._export(os.path.join(tmp, "b"))
            for left, right in zip(first, second):
                with open(left, "rb") as fh:
                    a = fh.read()
                with open(right, "rb") as fh:
                    b = fh.read()
                self.assertEqual(a, b, os.path.basename(left))


if __name__ == "__main__":
    unittest.main()
