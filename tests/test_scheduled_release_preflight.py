import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "scheduled_release_preflight", ROOT / "platforms/linux/scheduled-release/preflight.py"
)
preflight = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(preflight)


class ScheduledReleasePreflightTests(unittest.TestCase):
    def test_obsolete_backend_baseline_cannot_extend_native_contract(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract = root / "contract"
            contract.mkdir()
            expected = {"koda_tracker/app.py": "current"}
            legacy = {"koda_tracker/app.py": "20260910"}
            (contract / "tracker-backend-sha256.json").write_text(json.dumps(expected))
            (contract / "tracker-backend-baselines.json").write_text(json.dumps({"20260910-ui1": legacy}))
            with patch.object(preflight, "command", return_value=json.dumps(legacy)):
                with self.assertRaises(preflight.PreflightError):
                    preflight.check_backend_hashes(contract, {"portal-api": "api", "portal-worker": "worker"}, root)
            with patch.object(preflight, "command", return_value=json.dumps({"koda_tracker/app.py": "unknown"})):
                with self.assertRaises(preflight.PreflightError):
                    preflight.check_backend_hashes(contract, {"portal-api": "api", "portal-worker": "worker"}, root)

    def test_current_contract_has_only_native_services_and_no_legacy_hashes(self):
        native = dict.fromkeys(preflight.SERVICES, {})
        preflight.require_native_services(native)
        with self.assertRaisesRegex(preflight.PreflightError, "full installation"):
            preflight.require_native_services({**native, "dtrack-frontend": {}})
        contract = ROOT / "platforms/linux/scheduled-release/contract"
        hashes = json.loads((contract / "tracker-backend-sha256.json").read_text())
        self.assertNotIn("dtrack.py", hashes)
        self.assertNotIn("migration.py", hashes)
        self.assertFalse((contract / "tracker-backend-baselines.json").exists())
        self.assertEqual((contract / "koda-suite").read_bytes(), (ROOT / "platforms/linux/suite/koda-suite").read_bytes())
        self.assertEqual((contract / "tracker/compose.integration.yaml").read_bytes(), (ROOT / "platforms/linux/suite/compose.integration.yaml").read_bytes())

    def test_chunked_digest_contract_is_normalized(self):
        self.assertEqual(
            preflight.normalize_digest_map({"app.py": ["0123456789abcdef", "fedcba9876543210"]}),
            {"app.py": "0123456789abcdeffedcba9876543210"},
        )


if __name__ == "__main__":
    unittest.main()
