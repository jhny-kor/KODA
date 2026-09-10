"""Executable checks replacing the historical remaining-item reproduction."""
import unittest

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromNames([
        "tests.test_schedule_api", "tests.test_schedule_transport",
        "tests.test_schedule_process_limits", "tests.test_schedule_settings",
    ])
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
