from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.fixes import fixer_for, is_fixable
from security_scanner.fixes import deterministic as d


class ConfigFixerTests(unittest.TestCase):
    def test_privileged_true_flipped(self):
        self.assertEqual(d.fix_privileged("    privileged: true"), "    privileged: false")

    def test_privileged_false_is_noop(self):
        self.assertIsNone(d.fix_privileged("    privileged: false"))

    def test_allow_privilege_escalation_flipped(self):
        self.assertEqual(
            d.fix_allow_privilege_escalation("  allowPrivilegeEscalation: true"),
            "  allowPrivilegeEscalation: false",
        )

    def test_unrelated_true_untouched(self):
        self.assertIsNone(d.fix_privileged("readOnlyRootFilesystem: true"))

    def test_rules_are_registered(self):
        self.assertTrue(is_fixable("config.compose-privileged"))
        self.assertTrue(is_fixable("config.k8s-privileged-container"))
        self.assertIs(fixer_for("config.k8s-allow-privilege-escalation"), d.fix_allow_privilege_escalation)


if __name__ == "__main__":
    unittest.main()
