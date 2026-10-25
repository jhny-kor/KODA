from __future__ import annotations

import os
from pathlib import Path
import unittest
from unittest.mock import patch

from security_scanner import eol_data, osv_vulnerabilities, vuln_intel
from security_scanner.ai.provider import LLMUnavailable, complete


class ClosedNetworkTests(unittest.TestCase):
    def test_legacy_options_cannot_start_public_lookups(self):
        with patch.dict(os.environ, {"KODA_OFFLINE_MODE": "1"}), patch("urllib.request.urlopen", side_effect=AssertionError("unexpected HTTP")) as http:
            self.assertEqual(osv_vulnerabilities.query_osv_findings(())[0], [])
            self.assertTrue(osv_vulnerabilities.query_osv_findings(())[1])
            self.assertEqual(vuln_intel.query_vulnerability_intel(["CVE-2021-44228"])[0], {})
            self.assertIsNone(eol_data.query_cycle_eol("ubuntu", "22.04")[0])
            with self.assertRaises(LLMUnavailable):
                complete("private source", model="openai/example")
            with patch.dict(os.environ, {"KODA_LLM_API_BASE": "https://public.example"}):
                with self.assertRaises(LLMUnavailable):
                    complete("private source", model="ollama/example")
            http.assert_not_called()

    def test_osv_exclusion_also_applies_outside_offline_mode(self):
        with patch.dict(os.environ, {"KODA_OFFLINE_MODE": "0", "KODA_EXCLUDE_OSV": "1"}), patch("urllib.request.urlopen", side_effect=AssertionError("unexpected HTTP")) as http:
            findings, warnings = osv_vulnerabilities.query_osv_findings(())
            self.assertFalse(findings)
            self.assertTrue(warnings)
            http.assert_not_called()

    def test_linux_runtime_defaults_exclude_online_intelligence(self):
        root = Path(__file__).resolve().parents[1]
        launcher = (root / "platforms/linux/bin/koda").read_text()
        dockerfile = (root / "platforms/linux/docker/Dockerfile").read_text()
        self.assertIn('KODA_OFFLINE_MODE="${KODA_OFFLINE_MODE:-1}"', launcher)
        self.assertIn("KODA_EXCLUDE_OSV=1", launcher)
        self.assertIn("KODA_OFFLINE_MODE=1", dockerfile)
        gateway = (root / "platforms/linux/suite/gateway.conf.template").read_text()
        self.assertNotIn("location /dependency-track", gateway)
        self.assertIn("vulnerability-intelligence/import-csv", gateway)


if __name__ == "__main__":
    unittest.main()
