import io
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


class ScheduledPackageTests(unittest.TestCase):
    def test_bundle_contains_images_source_launchers_and_valid_manifest(self):
        repo = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location('scheduled_package', repo / 'platforms/linux/package-scheduled-patch.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            tracker = root / 'tracker'
            for directory in ('apps/api/koda_tracker', 'apps/web/src', 'apps/web/public'):
                (tracker / directory).mkdir(parents=True)
            (tracker / 'apps/api/pyproject.toml').write_text('[project]\nname="test"\n')
            def command(*args):
                if args[:3] == ('docker', 'image', 'inspect'):
                    return json.dumps([{'Os': 'linux', 'Architecture': 'amd64', 'Id': 'sha256:' + 'a' * 64, 'Size': 10}])
                return 'commit' if 'rev-parse' in args else 'dirty'
            def save(args, **kwargs):
                with tarfile.open(args[3], 'w') as archive:
                    entries = {'config.json': b'{}', 'manifest.json': json.dumps([{'RepoTags': [ref], 'Config': 'config.json'} for ref in args[4:]]).encode()}
                    for name, data in entries.items():
                        info = tarfile.TarInfo(name); info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))
            with patch.object(module, 'command', side_effect=command), patch.object(module.subprocess, 'run', side_effect=save), patch('sys.argv', ['package', '--output-dir', str(root / 'out'), '--tracker-repo', str(tracker)]):
                module.main()
            archive_path = next((root / 'out').glob('*.tar.gz'))
            with tarfile.open(archive_path) as archive:
                base = archive.getnames()[0]
                manifest = archive.extractfile(base + '/manifest.sha256').read().decode()
                for line in manifest.splitlines():
                    sha, name = line.split('  ', 1)
                    self.assertEqual(hashlib.sha256(archive.extractfile(base + '/' + name).read()).hexdigest(), sha)
                for name in ('apply.sh', 'rollback.sh', 'images.tar', 'launchers/koda-suite', 'launchers/koda-docker', 'source/koda/security_scanner/schedule_api_worker.py'):
                    self.assertIn(base + '/' + name, archive.getnames())
                for launcher in ('koda-suite', 'koda-docker'):
                    self.assertTrue(archive.getmember(base + '/launchers/' + launcher).mode & 0o111)
                self.assertEqual(len(json.load(archive.extractfile(base + '/image-inventory.json'))), 3)
            self.assertEqual(archive_path.with_suffix('.gz.sha256').read_text().split()[0], module.digest(archive_path))
