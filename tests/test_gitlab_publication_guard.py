from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts" / "gitlab_publication_guard.py"
INSTALLER = ROOT / "scripts" / "install_gitlab_push_guard.sh"
spec = importlib.util.spec_from_file_location("gitlab_publication_guard", GUARD)
guard = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(guard)


class GitLabTargetTests(unittest.TestCase):
    def test_only_gitlab_hosts_are_routed(self):
        for url in (
            "https://gitlab.example.test/team/koda.git",
            "git@gitlab.example.test:team/koda.git",
            "ssh://git@gitlab.example.com:2222/team/koda.git",
            "https://GITLAB.COM/team/koda.git",
        ):
            with self.subTest(url=url):
                self.assertTrue(guard.is_gitlab_target(url))
        for url in (
            "https://github.com/team/koda.git",
            "git@github.com:team/koda.git",
            "https://example.com/gitlab.example.test/koda.git",
            "https://notgitlab.example.test/koda.git",
            "/tmp/gitlab.local/repository.git",
        ):
            with self.subTest(url=url):
                self.assertFalse(guard.is_gitlab_target(url))


class GitLabPublicationGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Guard Test")
        self.git("config", "user.email", "guard@example.invalid")

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.repo), *args], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ).stdout.strip()

    def write(self, name, text):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def run_guard(self, *args, stdin=""):
        return subprocess.run(
            [sys.executable, str(GUARD), "--repo", str(self.repo), *args],
            input=stdin, capture_output=True, text=True,
        )

    def test_inspects_commit_and_ignores_dirty_worktree(self):
        self.write("README.md", "배포 안내\n")
        clean = self.commit()
        self.write("README.md", "https://github.com/private/token-value\n")
        result = self.run_guard("--check", clean)
        self.assertEqual(result.returncode, 0, result.stderr)
        dirty = self.commit()
        self.write("README.md", "배포 안내\n")
        result = self.run_guard("--check", dirty)
        self.assertEqual(result.returncode, 1)
        self.assertIn("README.md", result.stderr)
        self.assertNotIn("token-value", result.stderr)

    def test_document_hosts_and_marketplace_text_rejected_with_line_numbers(self):
        self.write("docs/check.md", "일반 문서\nhttps://GITHUB.COM/project\n앱 스토어 배포\n")
        result = self.run_guard("--check", self.commit())
        self.assertEqual(result.returncode, 1)
        self.assertIn("'docs/check.md':2", result.stderr)
        self.assertIn("'docs/check.md':3", result.stderr)

    def test_encoded_hosts_across_document_types_and_unusual_paths(self):
        fixtures = {
            "docs/path\twith\nnewline.md": "https%253A%252F%252FGitHub%252eCOM/repo",
            "diagrams/guide.svg": "https://apps&#46;apple&#46;com/app",
            "dist/report.html": "//user.github.io/guide",
            "docs/evidence.json": '{"reference": "https:\\/\\/raw.githubusercontent.com/repo"}',
            "platforms/linux/docs/guide.txt": "https://github.blog/news",
            "docs/assets.md": "https://githubassets.com/file\nhttps://itunes.apple.com/app",
            "docs/marketplace.markdown": "App&#32;Store",
        }
        for name, text in fixtures.items():
            self.write(name, text)
        result = self.run_guard("--check", self.commit())
        self.assertEqual(result.returncode, 1)
        for name in fixtures:
            self.assertIn(repr(name), result.stderr)

    def test_dedicated_store_assets_and_scripts_rejected(self):
        fixtures = (
            "platforms/macos/packaging/README.ko.md",
            "platforms/macos/packaging/assets/KODA-AppStore-1024.png",
            "platforms/macos/packaging/ExportOptions-app-store.plist",
            "platforms/macos/scripts/archive-koda-app-store.command",
            "platforms/macos/packaging/store-assets/screenshot.png",
            "docs/store-release.md",
        )
        for name in fixtures:
            self.write(name, "fixture")
        result = self.run_guard("--check", self.commit())
        self.assertEqual(result.returncode, 1)
        for name in fixtures:
            self.assertIn(name, result.stderr)

    def test_functional_source_downloads_entitlements_and_icons_are_preserved(self):
        for name, text in {
            "platforms/macos/scripts/prepare-java.command": "curl https://github.com/tool/releases/file",
            "platforms/shared/python/scanner.py": 'URL = "https://raw.githubusercontent.com/tool/data"',
            "platforms/macos/packaging/KODA.entitlements": "<plist>runtime</plist>",
            "platforms/macos/packaging/KODA.iconset/icon_512x512.png": "runtime icon",
            "platforms/macos/app/Assets.xcassets/AppIcon.appiconset/Contents.json": "{}",
            "README.md": "설치 문서 https://gitlab.example.test/team/koda\n",
        }.items():
            self.write(name, text)
        result = self.run_guard("--check", self.commit())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_github_push_is_untouched_even_with_forbidden_commit(self):
        self.write("README.md", "App Store https://github.com/team/koda")
        oid = self.commit()
        result = self.run_guard(
            "origin", "https://github.com/team/koda.git",
            stdin=f"refs/heads/main {oid} refs/heads/main {'0' * 40}\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_gitlab_push_checks_each_new_tree_and_skips_deletions(self):
        self.write("README.md", "https://github.com/team/koda")
        oid = self.commit()
        result = self.run_guard(
            "government", "git@gitlab.example.test:team/koda.git",
            stdin=f"refs/heads/main {oid} refs/heads/main {'0' * 40}\n",
        )
        self.assertEqual(result.returncode, 1)
        deletion = self.run_guard(
            "government", "https://gitlab.example.test/team/koda.git",
            stdin=f"(delete) {'0' * 64} refs/heads/main {oid}\n",
        )
        self.assertEqual(deletion.returncode, 0, deletion.stderr)

    def test_fail_closed_on_uninspectable_ref_or_malformed_record(self):
        self.write("README.md", "설치 문서")
        self.commit()
        bad_ref = self.run_guard("--check", "missing")
        self.assertEqual(bad_ref.returncode, 1)
        malformed = self.run_guard("government", "https://gitlab.com/team/koda", stdin="invalid\n")
        self.assertEqual(malformed.returncode, 1)

    def test_forbidden_intermediate_commit_cannot_hide_behind_clean_leaf(self):
        self.write("README.md", "설치 문서")
        parent = self.commit()
        self.write("README.md", "https://github.com/private/token-value")
        self.commit()
        self.write("README.md", "현재 설치 문서")
        leaf = self.commit()
        result = self.run_guard(
            "government", "https://gitlab.example.test/team/koda.git",
            stdin=f"refs/heads/main {leaf} refs/heads/main {parent}\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("README.md", result.stderr)
        self.assertNotIn("token-value", result.stderr)

    def test_existing_remote_history_is_exempt_but_missing_tip_fails_closed(self):
        self.write("README.md", "https://github.com/historical/document")
        historical = self.commit()
        self.write("README.md", "현재 설치 문서")
        leaf = self.commit()
        accepted = self.run_guard(
            "government", "https://gitlab.example.test/team/koda.git",
            stdin=f"refs/heads/main {leaf} refs/heads/main {historical}\n",
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        missing = self.run_guard(
            "government", "https://gitlab.example.test/team/koda.git",
            stdin=f"refs/heads/main {leaf} refs/heads/main {'a' * 40}\n",
        )
        self.assertEqual(missing.returncode, 1)
        self.assertIn("fetch the GitLab remote", missing.stderr)

    def test_new_gitlab_branch_uses_only_matching_gitlab_tracking_history(self):
        gitlab_url = "https://gitlab.example.test/team/koda.git"
        self.git("remote", "add", "government", gitlab_url)
        self.git("remote", "add", "origin", "https://github.com/team/koda.git")
        self.write("README.md", "https://github.com/historical/document")
        historical = self.commit()
        self.git("update-ref", "refs/remotes/origin/main", historical)
        self.write("README.md", "현재 설치 문서")
        leaf = self.commit()
        update = f"refs/heads/new {leaf} refs/heads/new {'0' * 40}\n"
        rejected = self.run_guard("government", gitlab_url, stdin=update)
        self.assertEqual(rejected.returncode, 1)
        self.git("update-ref", "refs/remotes/government/main", historical)
        accepted = self.run_guard("government", gitlab_url, stdin=update)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        other_gitlab = self.run_guard("government", "https://gitlab.example.com/other/koda.git", stdin=update)
        self.assertEqual(other_gitlab.returncode, 1)

    def test_installer_is_idempotent_and_does_not_overwrite_another_hook(self):
        self.write("scripts/gitlab_publication_guard.py", GUARD.read_text())
        self.write("scripts/install_gitlab_push_guard.sh", INSTALLER.read_text())
        installer = self.repo / "scripts/install_gitlab_push_guard.sh"
        hook = self.repo / ".git/hooks/pre-push"
        hook.write_text("#!/bin/sh\nexit 0 # existing\n")
        failed = subprocess.run(["sh", str(installer)], capture_output=True, text=True)
        self.assertEqual(failed.returncode, 1)
        self.assertIn("existing", hook.read_text())
        hook.unlink()
        for _ in range(2):
            result = subprocess.run(["sh", str(installer)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.access(hook, os.X_OK))
        self.write("README.md", "https://github.com/private/token-value")
        oid = self.commit()
        actual_hook = subprocess.run(
            [str(hook), "government", "https://gitlab.com/team/koda"],
            cwd=self.repo, input=f"refs/heads/main {oid} refs/heads/main {'0' * 40}\n",
            capture_output=True, text=True,
        )
        self.assertEqual(actual_hook.returncode, 1)
        self.assertNotIn("token-value", actual_hook.stderr)


if __name__ == "__main__":
    unittest.main()
