"""Exercise the real Linux packager without downloading renderer dependencies."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
NEW_DB = "vulnerability-db_new.tar.zst"
OLD_DB = "vulnerability-db_old.tar.zst"
NEW_BYTES = b"current approved database fixture"


class SelectedGrypeDatabasePackagingTests(unittest.TestCase):
    def fixture(self, root, *, databases=None, versions="selected", manifest=True):
        repo = root / "repo"
        linux = repo / "platforms/linux"
        python = repo / "platforms/shared/python"
        (linux / "bin").mkdir(parents=True)
        (linux / "examples").mkdir()
        (python / "security_scanner").mkdir(parents=True)
        shutil.copy2(ROOT / "platforms/linux/package.sh", linux / "package.sh")
        for name in ("bin/koda", "install.sh", "README-offline.md"):
            (linux / name).write_text("fixture " + name + "\n")
        (linux / "examples/example.json").write_text("{}\n")
        (python / "pyproject.toml").write_text('version = "0.1.0"\n')
        (python / "security_scanner/__init__.py").write_text("# runtime fixture\n")
        assets = root / "assets"
        files = {
            "tools/syft": b"syft executable fixture\n",
            "tools/grype": b"grype executable fixture\n",
            "tools/LICENSES/grype.txt": b"license fixture\n",
            "vuln-data/nvd/nvdcve-2.0-2026.json.gz": b"NVD fixture",
            "vuln-data/known_exploited_vulnerabilities.json": b'{}',
            "vuln-data/epss_scores.csv.gz": b"EPSS fixture",
            "grype-db/db/vulnerability.db": b"previously imported cache",
        }
        for name, content in (databases or {OLD_DB: b"old database", NEW_DB: NEW_BYTES}).items():
            files["grype-db/incoming/" + name] = content
        if versions == "selected":
            versions = f"grype_db={NEW_DB}\ngrype_db_checksum=sha256:{hashlib.sha256(NEW_BYTES).hexdigest()}\n"
        if versions is not None:
            files["versions.txt"] = versions.encode()
        for name, content in files.items():
            path = assets / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        if manifest:
            (assets / "manifest.sha256").write_text("".join(
                hashlib.sha256(content).hexdigest() + "  " + name + "\n"
                for name, content in sorted(files.items())
            ))
        binary = root / "bin"
        binary.mkdir()
        # Only network/renderer provisioning is replaced. Selection, copying,
        # metadata handling and the actual tar invocation run unchanged.
        wrapper = binary / "python3"
        wrapper.write_text(f"#!{sys.executable}\n" + r'''
import os
from pathlib import Path
import sys
args = sys.argv[1:]
if args[:3] == ['-m', 'pip', 'download']:
    wheels = Path(args[args.index('-d') + 1])
    wheels.mkdir(parents=True, exist_ok=True)
    (wheels / 'playwright-fixture.whl').write_bytes(b'renderer wheel')
elif args[:2] == ['-m', 'venv']:
    binary = Path(args[2]) / 'bin'
    binary.mkdir(parents=True)
    (binary / 'pip').write_text('#!/bin/sh\nexit 0\n')
    (binary / 'python').write_text('#!/bin/sh\nmkdir -p "$PLAYWRIGHT_BROWSERS_PATH/chromium-fixture"\nprintf renderer > "$PLAYWRIGHT_BROWSERS_PATH/chromium-fixture/chrome"\n')
    (binary / 'pip').chmod(0o755)
    (binary / 'python').chmod(0o755)
else:
    os.execv(os.environ['PACKAGING_REAL_PYTHON'], [os.environ['PACKAGING_REAL_PYTHON'], *args])
''')
        wrapper.chmod(0o755)
        env = os.environ | {
            "PATH": str(binary) + os.pathsep + os.environ["PATH"],
            "PACKAGING_REAL_PYTHON": sys.executable,
            "KODA_LINUX_ARCH": "x86_64",
            "KODA_OFFLINE_ASSET_DIR": str(assets),
            "KODA_LINUX_DIST_DIR": str(root / "dist"),
            # macOS bsdtar otherwise adds AppleDouble records; production
            # renderer packaging executes tar inside its Linux container.
            "COPYFILE_DISABLE": "1",
        }
        return linux / "package.sh", assets, env

    def package(self, script, env):
        return subprocess.run(["bash", str(script)], env=env, text=True, capture_output=True)

    def test_only_declared_database_is_packaged_and_source_cache_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script, assets, env = self.fixture(root)
            before = {p.relative_to(assets): p.read_bytes() for p in assets.rglob("*") if p.is_file()}
            result = self.package(script, env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(before, {p.relative_to(assets): p.read_bytes() for p in assets.rglob("*") if p.is_file()})
            with tarfile.open(root / "dist/koda-linux-x86_64-0.1.0.tar.gz") as archive:
                base = "koda-linux-x86_64-0.1.0/"
                db_files = [name[len(base):] for name in archive.getnames() if name.startswith(base + "grype-db/") and archive.getmember(name).isfile()]
                self.assertEqual(db_files, ["grype-db/incoming/" + NEW_DB])
                self.assertEqual(archive.extractfile(base + db_files[0]).read(), NEW_BYTES)
                for relative in ("tools/LICENSES/grype.txt", "vuln-data/epss_scores.csv.gz", "vuln-data/nvd/nvdcve-2.0-2026.json.gz", "versions.txt"):
                    self.assertEqual(archive.extractfile(base + relative).read(), (assets / relative).read_bytes())
                self.assertIn(base + "app/render-wheels/playwright-fixture.whl", archive.getnames())
                self.assertIn(base + "ms-playwright/chromium-fixture/chrome", archive.getnames())
                manifest = archive.extractfile(base + "manifest.sha256").read().decode()
                self.assertNotIn(OLD_DB, manifest)
                self.assertNotIn("grype-db/db/", manifest)
                self.assertIn(NEW_DB, manifest)
                for line in manifest.splitlines():
                    expected, relative = line.split(maxsplit=1)
                    self.assertEqual(hashlib.sha256(archive.extractfile(base + relative).read()).hexdigest(), expected)

    def test_declared_checksum_mismatch_is_rejected_before_archive_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script, _, env = self.fixture(root, versions=f"grype_db={NEW_DB}\ngrype_db_checksum=sha256:{'0' * 64}\n")
            result = self.package(script, env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Grype DB checksum mismatch", result.stderr)
            self.assertFalse(list((root / "dist").glob("*.tar.gz")))

    def test_one_manual_archive_without_selection_metadata_remains_supported(self):
        for versions, manifest in ((None, True), (None, False), ("syft=manual\n", True)):
            with self.subTest(versions=versions, manifest=manifest), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                script, _, env = self.fixture(root, databases={NEW_DB: NEW_BYTES}, versions=versions, manifest=manifest)
                result = self.package(script, env)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                with tarfile.open(root / "dist/koda-linux-x86_64-0.1.0.tar.gz") as archive:
                    self.assertEqual(archive.extractfile("koda-linux-x86_64-0.1.0/grype-db/incoming/" + NEW_DB).read(), NEW_BYTES)

    def test_ambiguous_manual_archives_are_rejected_without_deleting_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script, assets, env = self.fixture(root, versions=None)
            result = self.package(script, env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ambiguous Grype DB archives", result.stderr)
            self.assertEqual((assets / "grype-db/incoming/" / OLD_DB).read_bytes(), b"old database")
            self.assertEqual((assets / "grype-db/incoming/" / NEW_DB).read_bytes(), NEW_BYTES)

    def test_missing_declared_archive_never_falls_back_to_old_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script, _, env = self.fixture(root, databases={OLD_DB: b"old database"})
            result = self.package(script, env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("selected Grype DB archive is missing", result.stderr)

    def test_unsafe_or_incomplete_selection_metadata_is_rejected(self):
        checksum = hashlib.sha256(NEW_BYTES).hexdigest()
        cases = (
            (f"grype_db=../{NEW_DB}\ngrype_db_checksum={checksum}\n", "unsafe Grype DB filename"),
            (f"grype_db=nested/{NEW_DB}\ngrype_db_checksum={checksum}\n", "unsafe Grype DB filename"),
            (f"grype_db=/tmp/{NEW_DB}\ngrype_db_checksum={checksum}\n", "unsafe Grype DB filename"),
            (f"grype_db=bad\\name.tar.zst\ngrype_db_checksum={checksum}\n", "unsafe Grype DB filename"),
            (f"grype_db={NEW_DB}\n", "incomplete Grype DB selection metadata"),
            (f"grype_db_checksum={checksum}\n", "incomplete Grype DB selection metadata"),
            (f"grype_db={NEW_DB}\ngrype_db_checksum=sha512:invalid\n", "invalid Grype DB checksum"),
            (f"grype_db={NEW_DB}\ngrype_db={OLD_DB}\ngrype_db_checksum={checksum}\n", "duplicate Grype DB selection metadata"),
        )
        for versions, message in cases:
            with self.subTest(versions=versions), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                script, _, env = self.fixture(root, versions=versions)
                result = self.package(script, env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_selected_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script, assets, env = self.fixture(root)
            selected = assets / "grype-db/incoming" / NEW_DB
            selected.unlink()
            outside = root / "outside.tar.zst"
            outside.write_bytes(NEW_BYTES)
            selected.symlink_to(outside)
            result = self.package(script, env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe Grype DB archive", result.stderr)


if __name__ == "__main__":
    unittest.main()
