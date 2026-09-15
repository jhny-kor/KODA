import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('preflight', ROOT / 'platforms/linux/scheduled-release/preflight.py')
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class ScheduleMountTests(unittest.TestCase):
    def test_vulnerability_data_volume_is_read_only(self):
        mount = dict(Type='volume', Name='koda-vuln-data', Destination='/var/lib/koda-vuln-data', RW=False)
        preflight.check_dashboard_mount(mount, Path('/tmp'))
        for change in (dict(RW=True), dict(Type='bind'), dict(Destination='/var/lib/koda-vuln-data/extra')):
            with self.subTest(change=change):
                with self.assertRaises(preflight.PreflightError):
                    preflight.check_dashboard_mount({**mount, **change}, Path('/tmp'))

    def test_standard_mounts_and_rejected_variants(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)
            for destination, relative in (('/run/koda/ssh', 'schedule-ssh'), ('/run/koda/schedule', 'data/koda-portal/schedule-auth')):
                source = prefix / relative
                source.mkdir(parents=True)
                mount = dict(Type='bind', Source=str(source), Destination=destination, RW=False)
                preflight.check_dashboard_mount(mount, prefix)
                for change in (dict(RW=True), dict(Type='volume'), dict(Source=str(prefix / 'missing')), dict(Destination=destination + '/extra')):
                    with self.subTest(destination=destination, change=change):
                        with self.assertRaises(preflight.PreflightError):
                            preflight.check_dashboard_mount({**mount, **change}, prefix)
            with self.assertRaises(preflight.PreflightError):
                preflight.check_dashboard_mount({**mount, 'Source': str(prefix / 'schedule-ssh')}, prefix)


if __name__ == '__main__':
    unittest.main()
