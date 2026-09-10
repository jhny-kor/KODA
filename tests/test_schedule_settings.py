import json
import tempfile
import unittest
from pathlib import Path

from security_scanner.portal_store import PortalStore
from security_scanner.schedule_settings import DEFAULTS, get_settings, save_settings


class ScheduleSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = PortalStore(Path(self.tempdir.name) / "portal.sqlite3")

    def tearDown(self):
        self.tempdir.cleanup()

    def test_lazy_default_is_disabled_and_persisted(self):
        settings = get_settings(self.store)
        self.assertEqual({key: settings[key] for key in DEFAULTS}, DEFAULTS)
        self.assertFalse(get_settings(self.store)["enabled"])

    def test_save_validates_integer_bounds_and_nan(self):
        saved = save_settings(self.store, {**DEFAULTS, "enabled": True, "gap_seconds": 45}, "admin")
        self.assertTrue(saved["enabled"])
        self.assertEqual(saved["gap_seconds"], 45)
        for payload in (
            {**DEFAULTS, "cpu_limit": 0},
            {**DEFAULTS, "memory_limit_bytes": float("nan")},
            {**DEFAULTS, "concurrency": 2},
            {**DEFAULTS, "enabled": 1},
        ):
            with self.assertRaises(ValueError):
                save_settings(self.store, payload, "admin")

    def test_unknown_keys_are_rejected_without_recording_values(self):
        with self.assertRaises(ValueError):
            save_settings(self.store, {**DEFAULTS, "gitlab_token": "secret-value"}, "admin")
        event = self.store.audit_events(1)[0]
        self.assertEqual(event["action"], "schedule_worker_settings.rejected")
        self.assertIn("gitlab_token", event["detail_json"])
        self.assertNotIn("secret-value", event["detail_json"])

    def test_save_audit_contains_no_settings_secret(self):
        save_settings(self.store, {**DEFAULTS, "enabled": True}, "admin")
        event = self.store.audit_events(1)[0]
        self.assertEqual(event["action"], "schedule_worker_settings.updated")
        self.assertNotIn("memory_limit_bytes", event["detail_json"])
        self.assertNotIn("rate_bytes_per_sec", event["detail_json"])


if __name__ == "__main__":
    unittest.main()
