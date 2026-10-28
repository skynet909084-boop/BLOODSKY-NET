"""Offline checks for honest manual hardware release acceptance."""
import json
from pathlib import Path
import tempfile
import unittest

from tools.release_gate import CHECKS, evaluate, main, template


class ReleaseGateTests(unittest.TestCase):
    def test_template_is_never_auto_pass(self):
        payload = template()
        self.assertEqual(len(payload["checks"]), len(CHECKS))
        self.assertTrue(all(c["status"] == "not_run" for c in payload["checks"]))
        self.assertFalse(evaluate(payload)[0])

    def test_missing_is_blocking(self):
        payload = template()
        payload["checks"].pop()
        ok, reasons = evaluate(payload)
        self.assertFalse(ok)
        self.assertTrue(any("absent" in x for x in reasons))

    def test_duplicate_is_rejected(self):
        payload = template()
        payload["checks"].append(dict(payload["checks"][0]))
        with self.assertRaises(ValueError):
            evaluate(payload)

    def test_unknown_is_rejected(self):
        payload = template()
        payload["checks"][0]["id"] = "imaginary_device"
        with self.assertRaises(ValueError):
            evaluate(payload)

    def test_pass_without_evidence_is_blocking(self):
        payload = template()
        for c in payload["checks"]:
            c.update(status="pass", environment="Windows / physical switch", evidence="")
        self.assertFalse(evaluate(payload)[0])

    def test_full_manual_report_can_pass(self):
        payload = template()
        for c in payload["checks"]:
            c.update(status="pass", environment="Lab inventory ID", evidence="Acceptance log reference")
        self.assertTrue(evaluate(payload)[0])

    def test_invalid_state_rejected(self):
        payload = template()
        payload["checks"][0]["status"] = "maybe"
        with self.assertRaises(ValueError):
            evaluate(payload)

    def test_wrong_version_rejected(self):
        payload = template()
        payload["target_version"] = "0.9.0-rc1"
        with self.assertRaises(ValueError):
            evaluate(payload)

    def test_cli_template_is_safe_and_check_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "acceptance.json"
            self.assertEqual(main(["--template", str(file)]), 0)
            self.assertEqual(main(["--check", str(file)]), 1)
            self.assertEqual(main(["--template", str(file)]), 2)  # no overwrite
            saved = json.loads(file.read_text("utf-8"))
            self.assertEqual(saved["checks"][0]["status"], "not_run")

    def test_no_auto_hardware_scanning(self):
        code = (Path(__file__).resolve().parents[1] / "tools/release_gate.py").read_text("utf-8")
        self.assertNotIn("import socket", code)
        self.assertNotIn("import subprocess", code)
        self.assertNotIn("pysnmp", code)


if __name__ == "__main__":
    unittest.main()
