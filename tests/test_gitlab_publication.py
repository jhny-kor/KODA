from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import publish_gitlab as publisher
from gitlab_publication_guard import check_revision


class GitLabPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.source, self.target = root / "source", root / "target"
        for repo in (self.source, self.target):
            repo.mkdir()
            self.git(repo, "init", "-q")
            self.git(repo, "config", "user.name", "Test")
            self.git(repo, "config", "user.email", "test@example.invalid")
            self.git(repo, "config", "core.hooksPath", "/dev/null")

    def git(self, repo, *args):
        return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.PIPE).decode().strip()

    def write(self, repo, name, body):
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)

    def commit(self, repo):
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "fixture")
        return self.git(repo, "rev-parse", "HEAD")

    def fixture(self):
        self.write(self.target, "README.md", "# KODA 한국어 시작 안내\n")
        self.write(self.target, "docs/guide.md", "# 이전 한국어 가이드\n")
        self.write(self.target, "docs/details.md", "# 이전 상세 한국어 안내\n")
        self.write(self.target, "docs/gitlab-publication.md", "# 사내 게시 기준 유지\n")
        self.write(self.target, "SECURITY.md", "# 사내 신고 정책 유지\n")
        self.write(self.target, ".gitignore", "local-settings/\n")
        self.write(self.target, "local-only.py", "preserve = True\n")
        self.commit(self.target)
        self.write(self.source, "README.md", "# English upstream\nhttps://github.com/org/source\n")
        self.write(self.source, "docs/guide.ko.md", "# 한국어 사용 안내\n\n"
                   "점검 대상 소스와 환경을 확인하고 설치된 버전을 확인하세요.\n"
                   "[상세](details.ko.md) [출처](https://github.com/org/reference)\n"
                   "[배포 안내](../platforms/macos/packaging/README.ko.md)\n"
                   "[앱 설치](https://apps.apple.com/app/id123)\n"
                   "[English](guide.md)\n")
        self.write(self.source, "docs/details.ko.md", "# 한국어 상세 안내\n"
                   "한국어 상세 안내를 통해 점검 환경과 결과를 확인할 수 있습니다.\n")
        self.write(self.source, "docs/guide.md", "# English guide\n")
        self.write(self.source, "SECURITY.ko.md", "# 원본 신고 정책\nhttps://github.com/org/source/security\n")
        self.write(self.source, "scanner.py", 'TOOLS_URL = "https://github.com/org/tool/releases"\n')
        self.write(self.source, "platforms/macos/packaging/KODA.entitlements", "sandbox enabled\n")
        self.write(self.source, "platforms/macos/packaging/assets/KODA.icns", "runtime icon\n")
        self.write(self.source, "platforms/macos/packaging/assets/KODA-AppStore-1024.png", "store image\n")
        self.write(self.source, "platforms/macos/scripts/archive-koda-app-store.command", "store submission\n")
        self.write(self.source, ".gitignore", "upstream-only/\n")
        return self.commit(self.source)

    def test_committed_source_and_korean_docs_publish_without_changing_runtime_urls(self):
        revision = self.fixture()
        self.write(self.source, "scanner.py", "uncommitted = True\n")
        self.write(self.source, "private.env", "uncommitted private setting\n")
        result = publisher.sync_committed_tree(self.source, revision, self.target)
        self.assertIn("https://github.com/org/tool", (self.target / "scanner.py").read_text())
        self.assertFalse((self.target / "private.env").exists())
        self.assertTrue((self.target / "local-only.py").exists())
        self.assertEqual((self.target / ".gitignore").read_text(), "local-settings/\n")
        self.assertEqual((self.target / "SECURITY.md").read_text(), "# 사내 신고 정책 유지\n")
        document = (self.target / "docs/guide.md").read_text()
        self.assertIn("[상세](details.md)", document)
        self.assertIn("출처", document)
        self.assertNotIn("packaging/README.ko.md", document)
        self.assertNotIn("github.com", document)
        self.assertNotIn("apps.apple.com", document)
        self.assertNotIn("English", document)
        self.assertFalse((self.target / "docs/guide.ko.md").exists())
        self.assertFalse((self.target / "platforms/macos/packaging/assets/KODA-AppStore-1024.png").exists())
        self.assertTrue((self.target / "platforms/macos/packaging/assets/KODA.icns").exists())
        self.assertFalse((self.target / "platforms/macos/scripts/archive-koda-app-store.command").exists())
        self.assertEqual(publisher.validate_local_links(self.target, result["written_files"]), [])
        oid = self.commit(self.target)
        self.assertEqual(check_revision(str(self.target), oid), [])

    def test_packaging_required_korean_filename_is_retained_and_missing_links_fail(self):
        revision = self.fixture()
        self.write(self.target, "platforms/linux/suite/README.ko.md", "# 운영 안내\n")
        self.commit(self.target)
        self.write(self.source, "platforms/linux/suite/README.ko.md", "# 통합 운영 안내\n"
                   "통합 운영 안내에서 설치 환경과 데이터 보존 방법을 확인하세요.\n"
                   "[없는 문서](missing.md)\n")
        revision = self.commit(self.source)
        result = publisher.sync_committed_tree(self.source, revision, self.target)
        self.assertEqual(result["document_map"]["platforms/linux/suite/README.ko.md"], "platforms/linux/suite/README.ko.md")
        self.assertEqual(publisher.validate_local_links(self.target, result["written_files"]),
                         ["platforms/linux/suite/README.ko.md: missing.md"])

    def test_document_json_is_sanitized_without_corrupting_structure(self):
        revision = self.fixture()
        self.write(self.source, "docs/verification.json", json.dumps({
            "publication_scope": "GitHub source and App Store submission",
            "links": ["https://github.com/org/source", "https://apps.apple.com/app/id123"],
            "count": 7,
        }))
        revision = self.commit(self.source)
        publisher.sync_committed_tree(self.source, revision, self.target)
        data = json.loads((self.target / "docs/verification.json").read_text())
        self.assertEqual(data["count"], 7)
        self.assertEqual(data["links"], ["", ""])
        self.assertEqual(data["published_source_revision"], revision)
        self.assertEqual(check_revision(str(self.target), self.commit(self.target)), [])


if __name__ == "__main__":
    unittest.main()
