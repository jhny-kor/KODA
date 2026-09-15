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
    def test_reviewed_tracker_backend_baseline(self):
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
                preflight.check_backend_hashes(contract, {"portal-api": "api", "portal-worker": "worker"}, root)
            with patch.object(preflight, "command", return_value=json.dumps({"koda_tracker/app.py": "unknown"})):
                with self.assertRaises(preflight.PreflightError):
                    preflight.check_backend_hashes(contract, {"portal-api": "api", "portal-worker": "worker"}, root)


if __name__ == "__main__":
    unittest.main()
