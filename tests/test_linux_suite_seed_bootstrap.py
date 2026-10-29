"""Exercise the canonical signed first-install seed and Suite packaging boundary."""
import gzip
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TRACKER = ROOT.parent / "security-sbom-dependecy"


def archive(path, files):
    with tarfile.open(path, "w:gz") as output:
        for name, value in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(value)
            output.addfile(member, io.BytesIO(value))


class SignedSuiteSeedTests(unittest.TestCase):
    def setUp(self):
        if not (TRACKER / "scripts/collect-unified-data.py").is_file():
            self.skipTest("adjacent Tracker collector is required")
        self.temporary = tempfile.TemporaryDirectory(prefix="koda-seed-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sources = self.root / "sources"
        self.sources.mkdir()
        self.keys = self.root / "keys"
        self.keys.mkdir()
        self.private = self.keys / "data-private.pem"
        self.public = self.keys / "data-public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", self.private], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", self.private, "-pubout", "-out", self.public], check=True, capture_output=True)
        self.epss = self.sources / "epss.csv.gz"
        self.epss.write_bytes(gzip.compress(b"#model_version:v2025.03.14,score_date:2026-10-09\ncve,epss,percentile\nCVE-2026-12345,.8,.99\n"))
        (self.root / "empty.env").write_text("")
        self.binary = self.root / 'bin'
        self.binary.mkdir()
        docker = self.binary / 'docker'
        docker.write_text('''#!/usr/bin/env python3
import json, os, shutil, sys, tarfile
from pathlib import Path
arguments = sys.argv[1:]
assert arguments[:2] == ['run', '--rm']
assert arguments[-3:] == ['db', 'import', '/database.tar.zst']
assert arguments[arguments.index('--entrypoint') + 1] == '/grype'
assert arguments[arguments.index('--network') + 1] == 'none'
assert '--user' in arguments and '--read-only' in arguments
assert '-v' not in arguments  # UTC archive filenames contain colons.
mounts = [dict(part.split('=', 1) if '=' in part else (part, True) for part in arguments[index + 1].split(','))
          for index, value in enumerate(arguments) if value == '--mount']
incoming = next(mount for mount in mounts if mount['target'] == '/database.tar.zst')
destination = next(mount for mount in mounts if mount['target'] == '/grype-cache')
assert incoming['readonly']
with tarfile.open(incoming['source']) as archive:
    assert archive.getnames() == ['vulnerability.db']
    target = Path(destination['source']) / '6'
    target.mkdir()
    with (target / 'vulnerability.db').open('wb') as output:
        shutil.copyfileobj(archive.extractfile('vulnerability.db'), output)
    (target / 'import.json').write_text('{"importedBy":"fixture Docker Grype import"}')
Path(os.environ['TEST_GRYPE_IMPORT_LOG']).write_text(json.dumps(arguments))
''')
        docker.chmod(0o755)

    def bundle(self, bundled_epss=False):
        database = io.BytesIO()
        with tarfile.open(fileobj=database, mode="w") as output:
            for name, value in {"vulnerability.db": b"fixture-db"}.items():
                member = tarfile.TarInfo(name)
                member.size = len(value)
                output.addfile(member, io.BytesIO(value))
        raw = database.getvalue()
        database_name = 'vulnerability-db_v6.1.10_2026-10-10T00:34:49Z_123.tar.zst'
        version = ("grype_db=" + database_name + "\ngrype_db_checksum=sha256:" + hashlib.sha256(raw).hexdigest() + "\ncisa_kev_date_released=2026-10-08\n").encode()
        files = {
            "koda/versions.txt": version,
            "koda/grype-db/incoming/" + database_name: raw,
            "koda/grype-db/incoming/vulnerability-db_v99.0.0_2099-01-01T00:00:00Z_999.tar.zst": b'not the declared database',
            "koda/vuln-data/known_exploited_vulnerabilities.json": b'{"dateReleased":"2026-10-08","vulnerabilities":[]}',
            "koda/vuln-data/nvd/nvdcve-2.0-2026.json.gz": gzip.compress(b'{"vulnerabilities":[{"cve":{"id":"CVE-2026-12345","descriptions":[{"lang":"en","value":"fixture"}]}}]}'),
        }
        if bundled_epss:
            files["koda/vuln-data/epss.csv.gz"] = self.epss.read_bytes()
        bundle = self.sources / "koda.tar.gz"
        archive(bundle, files)
        return bundle

    def run_builder(self, *, bundled_epss=False, external_epss=True, signing_key=True):
        output = self.root / "result/seed"
        environment = os.environ | {
            "KODA_LINUX_BUNDLE": str(self.bundle(bundled_epss)),
            "KODA_TRACKER_REPO": str(TRACKER), "ENV_FILE": str(self.root / "empty.env"),
            "PATH": str(self.binary) + os.pathsep + os.environ['PATH'],
            "TEST_GRYPE_IMPORT_LOG": str(self.root / 'grype-import.json'),
        }
        for name in ("KODA_DATA_UPDATE_SIGNING_KEY", "KODA_EPSS_SNAPSHOT", "KODA_INTELLIGENCE_SNAPSHOT"):
            environment.pop(name, None)
        if signing_key:
            environment["KODA_DATA_UPDATE_SIGNING_KEY"] = str(self.private)
        if external_epss:
            environment["KODA_EPSS_SNAPSHOT"] = str(self.epss)
        result = subprocess.run(["bash", ROOT / "platforms/linux/build-suite-vuln-bundle.sh", output],
                                env=environment, capture_output=True, text=True)
        return result, output

    def test_canonical_builder_signs_unified_seed_and_preserves_source_dates(self):
        result, output = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        metadata = (output / "metadata.env").read_text()
        self.assertIn("UNIFIED_BOOTSTRAP_FILE=unified-update.tar.gz\n", metadata)
        self.assertEqual({path.name for path in output.iterdir()}, {'metadata.env', 'manifest.sha256', 'unified-update.tar.gz'})
        manifest = dict(line.split()[::-1] for line in (output / "manifest.sha256").read_text().splitlines())
        bootstrap = output / "unified-update.tar.gz"
        self.assertEqual(manifest["unified-update.tar.gz"], hashlib.sha256(bootstrap.read_bytes()).hexdigest())
        with tarfile.open(bootstrap) as signed:
            values = signed.extractfile("metadata.env").read()
            self.assertIn(b"DATASET_TYPE=unified\n", values)
            self.assertIn(b"GRYPE_DATASET_DATE=2026-10-10\n", values)
            self.assertIn(b"KEV_DATASET_DATE=2026-10-08\n", values)
            self.assertIn(b"EPSS_DATASET_DATE=2026-10-09\n", values)
            self.assertIn(b'CVE-2026-12345', signed.extractfile("nvd.json").read())
            self.assertIn(b'fixture Docker Grype import', signed.extractfile('grype-db/6/import.json').read())
            proof = self.root / "proof"
            proof.mkdir()
            for name in ("manifest.sha256", "manifest.sha256.sig"):
                (proof / name).write_bytes(signed.extractfile(name).read())
            self.assertFalse(any("private" in name for name in signed.getnames()))
        subprocess.run(["openssl", "dgst", "-sha256", "-verify", self.public, "-signature", proof / "manifest.sha256.sig", proof / "manifest.sha256"], check=True, capture_output=True)
        self.assertFalse(any("private" in str(path.relative_to(output)) for path in output.rglob("*")))
        imported = (self.root / 'grype-import.json').read_text()
        self.assertIn('vulnerability-db_v6.1.10_2026-10-10T00:34:49Z_123.tar.zst', imported)
        self.assertNotIn('vulnerability-db_v99', imported)

    def verify_seed(self, output):
        return subprocess.run(['bash', TRACKER / 'scripts/verify-vuln-bundle.sh', output],
                              env=os.environ | {'ENV_FILE': str(self.root / 'empty.env')},
                              capture_output=True, text=True)

    def test_compact_verifier_rejects_extra_raw_data_and_missing_signature_proof(self):
        result, output = self.run_builder()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        duplicate = output / 'grype-db'
        duplicate.mkdir()
        self.assertNotEqual(self.verify_seed(output).returncode, 0)
        duplicate.rmdir()
        bootstrap = output / 'unified-update.tar.gz'
        with tarfile.open(bootstrap) as signed:
            values = {member.name: signed.extractfile(member).read() for member in signed if member.isfile() and member.name != 'manifest.sha256.sig'}
        archive(bootstrap, values)
        (output / 'manifest.sha256').write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n'
                                                       for path in sorted(output.iterdir()) if path.name != 'manifest.sha256'))
        rejected = self.verify_seed(output)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn('original metadata, manifest and signature', rejected.stderr)

    def test_bundled_epss_is_accepted_without_an_override(self):
        result, output = self.run_builder(bundled_epss=True, external_epss=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((output / "unified-update.tar.gz").is_file())

    def test_missing_key_or_epss_never_publishes_a_partial_seed(self):
        result, output = self.run_builder(signing_key=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("KODA_DATA_UPDATE_SIGNING_KEY", result.stderr)
        self.assertFalse(output.exists())
        result, output = self.run_builder(external_epss=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("EPSS", result.stderr)
        self.assertFalse(output.exists())

    def test_invalid_epss_and_private_key_within_source_are_rejected(self):
        self.epss.write_bytes(b"not FIRST data")
        result, output = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())
        self.private = Path(shutil.copy2(self.private, self.sources / "private.pem"))
        result, output = self.run_builder()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside output and collected source", result.stderr)
        self.assertFalse(output.exists())


class SuiteSeedGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="koda-seed-guard-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.koda = self.root / "koda.tar.gz"
        revision = subprocess.check_output(['git', '-C', ROOT, 'rev-parse', 'HEAD'], text=True).strip()
        dirty = bool(subprocess.check_output(['git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=all'], text=True).strip())
        koda_files = {"koda/" + name: b"fixture" for name in ("manifest.sha256", "install.sh", "koda-docker.sh", "image-ref.txt")}
        koda_files['koda/versions.txt'] = f'git_revision={revision}\ngit_worktree_dirty={str(dirty).lower()}\n'.encode()
        archive(self.koda, koda_files)
        self.marker = self.root / "verifier-called"
        tracker = self.root / 'tracker-repo'
        (tracker / 'scripts').mkdir(parents=True)
        (tracker / '.env.example').write_text('PUBLIC_HTTP_PORT=8088\n')
        self.verifier = tracker / 'scripts/verify-airgap-release.sh'
        self.verifier.write_text('#!/bin/sh\ntouch "$TEST_VERIFIER_MARKER"\nexit "${TEST_VERIFIER_EXIT:-42}"\n')
        self.verifier.chmod(0o755)
        subprocess.run(['git', 'init', '-q', tracker], check=True)
        subprocess.run(['git', '-C', tracker, 'add', '.'], check=True)
        subprocess.run(['git', '-C', tracker, '-c', 'user.name=KODA Test', '-c', 'user.email=koda@example.invalid', 'commit', '-qm', 'fixture'], check=True)
        self.tracker_revision = subprocess.check_output(['git', '-C', tracker, 'rev-parse', 'HEAD'], text=True).strip()

    def run_guard(self, *, bootstrap=True, signature=True, covered=True, complete=False):
        unified = self.root / "unified.tar.gz"
        files = {"metadata.env": b"DATASET_TYPE=unified\n", "manifest.sha256": b"fixture-manifest\n"}
        if signature:
            files["manifest.sha256.sig"] = b"fixture-signature"
        archive(unified, files)
        payload = unified.read_bytes()
        seed_metadata = b"UNIFIED_BOOTSTRAP_FILE=unified-update.tar.gz\n"
        seed_manifest = (hashlib.sha256(payload).hexdigest() + "  unified-update.tar.gz\n").encode() if covered else b""
        tracker = self.root / "tracker.tar.gz"
        members = {"./metadata.env": ('ANALYSIS_BACKEND=koda-native\nVULNERABILITY_BUNDLE=included\nTRACKER_WORKTREE_DIRTY=false\nTRACKER_GIT_REVISION=' + self.tracker_revision + '\n').encode(),
                   "vulnerability-data/metadata.env": seed_metadata,
                   "vulnerability-data/manifest.sha256": seed_manifest}
        if bootstrap:
            members["vulnerability-data/unified-update.tar.gz"] = payload
        archive(tracker, members)
        if complete:
            tracker.with_name(tracker.name + '.sig').write_bytes(b'fixture release signature')
            tracker.with_name(tracker.name + '.sha256').write_text(hashlib.sha256(tracker.read_bytes()).hexdigest() + '  ' + tracker.name + '\n')
        environment = os.environ | {"KODA_DOCKER_BUNDLE": str(self.koda), "KODA_TRACKER_BUNDLE": str(tracker),
                                    "KODA_TRACKER_VERIFIER": str(self.verifier), "TEST_VERIFIER_MARKER": str(self.marker),
                                    "TEST_VERIFIER_EXIT": '0' if complete else '42', 'KODA_SUITE_ALLOW_DIRTY': '1'}
        return subprocess.run(["bash", ROOT / "platforms/linux/package-suite-offline.sh", self.root / "suite.tar.gz"],
                              env=environment, capture_output=True, text=True)

    def test_legacy_seed_without_signed_bootstrap_is_rejected_before_packaging(self):
        result = self.run_guard(bootstrap=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signed unified first-install bootstrap", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_bootstrap_requires_manifest_coverage_and_original_signature_proof(self):
        for kwargs in ({"covered": False}, {"signature": False}):
            with self.subTest(**kwargs):
                result = self.run_guard(**kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.marker.exists())

    def test_complete_bootstrap_reaches_existing_outer_release_verifier(self):
        result = self.run_guard()
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        self.assertTrue(self.marker.exists())

    def test_tracker_signature_sidecars_remain_adjacent_and_outer_manifest_covers_them(self):
        result = self.run_guard(complete=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with tarfile.open(self.root / 'suite.tar.gz') as suite:
            package = suite.getnames()[0].split('/')[0]
            manifest = suite.extractfile(package + '/manifest.sha256').read().decode()
            hashes = dict(line.split()[::-1] for line in manifest.splitlines())
            for suffix in ('.sig', '.sha256'):
                relative = 'bundles/tracker.tar.gz' + suffix
                value = suite.extractfile(package + '/' + relative).read()
                self.assertEqual(value, (self.root / ('tracker.tar.gz' + suffix)).read_bytes())
                self.assertEqual(hashes[relative], hashlib.sha256(value).hexdigest())


if __name__ == "__main__":
    unittest.main()
