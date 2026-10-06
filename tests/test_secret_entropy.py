from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.checks.secrets import _looks_like_placeholder, _shannon_entropy


class SecretEntropyTests(unittest.TestCase):
    def test_low_entropy_values_are_placeholders(self):
        self.assertTrue(_looks_like_placeholder("aaaaaaaa"))
        self.assertTrue(_looks_like_placeholder("abcabcabc"))

    def test_high_entropy_values_are_not_placeholders(self):
        self.assertFalse(_looks_like_placeholder("aKq9Z2xV7pLm3Rt8"))
        self.assertFalse(_looks_like_placeholder("sk-proj-9fKd82MzQ1Lp"))

    def test_named_placeholders_still_caught(self):
        self.assertTrue(_looks_like_placeholder("changeme"))
        self.assertTrue(_looks_like_placeholder("your_api_key"))

    def test_entropy_monotonic(self):
        self.assertEqual(_shannon_entropy("aaaa"), 0.0)
        self.assertGreater(_shannon_entropy("abcd"), _shannon_entropy("aabb"))


if __name__ == "__main__":
    unittest.main()
