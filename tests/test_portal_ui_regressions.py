import unittest
import io
import tarfile
import tempfile
from pathlib import Path

from security_scanner.linux_portal import _comparison_data
from security_scanner.portal_integrations import gitlab_archive_root
from security_scanner.portal_views import gitlab_admin_page


class _ComparisonStore:
    def __init__(self, runs, inputs=None):
        self.runs = runs
        self.inputs = inputs or {}

    def run(self, run_id):
        return self.runs[run_id]

    def can(self, subject_id, project_id, permission):
        return True

    def project(self, project_id):
        return {"project_id": project_id, "name": "demo"}

    def input(self, input_id):
        return self.inputs[input_id]


class PortalUiRegressionTests(unittest.TestCase):
    def test_gitlab_archive_root_reads_each_branch_archive_member_root(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for root in ("demo-main-a1", "demo-feature-b2"):
                path = Path(directory) / f"{root}.tar.gz"
                with tarfile.open(path, "w:gz") as archive:
                    info = tarfile.TarInfo(f"{root}/src/a.py")
                    body = b"print(1)\n"
                    info.size = len(body)
                    archive.addfile(info, io.BytesIO(body))
                paths.append(path)
            self.assertEqual([gitlab_archive_root(path) for path in paths], ["demo-main-a1", "demo-feature-b2"])

    def test_comparison_strips_only_known_archive_root(self):
        base = {"project_id": "p", "status": "completed", "snapshot": {
            "gitlab_project_id": 7, "gitlab_path_with_namespace": "group/demo",
            "gitlab_commit_sha": "a" * 40, "archive_root": "group-demo-root",
        }}
        runs = {
            "left": {**base, "result": {"findings": [{"rule_id": "R", "path": "group-demo-root/src/a.py", "line": 3}]}},
            "right": {**base, "result": {"findings": [{"rule_id": "R", "path": "src/a.py", "line": 3}]}},
        }
        result = _comparison_data(_ComparisonStore(runs), "subject", "left", "right")
        self.assertEqual(result["counts"], {"new": 0, "resolved": 0, "persistent": 1})
        self.assertEqual(result["findings"][0]["path"], "src/a.py")

    def test_comparison_keeps_unknown_top_directory(self):
        base = {"project_id": "p", "status": "completed", "snapshot": {
            "gitlab_project_id": 7, "gitlab_path_with_namespace": "group/demo", "gitlab_commit_sha": "a" * 40,
        }}
        runs = {
            "left": {**base, "result": {"findings": [{"rule_id": "R", "path": "unknown/src/a.py", "line": 3}]}},
            "right": {**base, "result": {"findings": [{"rule_id": "R", "path": "unknown/src/a.py", "line": 3}]}},
        }
        self.assertEqual(_comparison_data(_ComparisonStore(runs), "subject", "left", "right")["findings"][0]["path"], "unknown/src/a.py")

    def test_comparison_normalizes_distinct_gitlab_branch_archive_roots(self):
        base = {"project_id": "p", "status": "completed", "snapshot": {
            "gitlab_project_id": 7, "gitlab_path_with_namespace": "group/demo",
            "gitlab_commit_sha": "a" * 40,
        }}
        left = {**base, "snapshot": {**base["snapshot"], "gitlab_archive_root": "demo-main-a1"},
                "result": {"findings": [{"rule_id": "R", "path": "demo-main-a1/src/a.py", "line": 3}]}}
        right = {**base, "snapshot": {**base["snapshot"], "gitlab_archive_root": "demo-feature-b2"},
                 "result": {"findings": [{"rule_id": "R", "path": "demo-feature-b2/src/a.py", "line": 3}]}}
        result = _comparison_data(_ComparisonStore({"left": left, "right": right}), "subject", "left", "right")
        self.assertEqual(result["counts"], {"new": 0, "resolved": 0, "persistent": 1})

    def test_comparison_does_not_guess_legacy_gitlab_archive_root(self):
        base = {"project_id": "p", "status": "completed", "snapshot": {
            "gitlab_project_id": 7, "gitlab_path_with_namespace": "group/demo",
            "gitlab_commit_sha": "a" * 40,
        }}
        runs = {
            "left": {**base, "result": {"findings": [{"rule_id": "R", "path": "demo-a/src/a.py", "line": 3}]}},
            "right": {**base, "result": {"findings": [{"rule_id": "R", "path": "src/a.py", "line": 3}]}},
        }
        result = _comparison_data(_ComparisonStore(runs), "subject", "left", "right")
        self.assertEqual(result["counts"]["persistent"], 0)

    def test_comparison_strips_uploaded_archive_filename_prefix(self):
        base = {"project_id": "p", "status": "completed", "snapshot": {
            "input_id": "input-1", "gitlab_project_id": None,
        }}
        runs = {
            "left": {**base, "result": {"findings": [{"rule_id": "R", "path": "source.tar.gz.extracted/repo/src/a.py", "line": 3}]}},
            "right": {**base, "result": {"findings": [{"rule_id": "R", "path": "source.tar.gz.extracted/repo/src/a.py", "line": 3}]}},
        }
        result = _comparison_data(_ComparisonStore(runs, {"input-1": {"name": "source.tar.gz"}}), "subject", "left", "right")
        self.assertEqual(result["findings"][0]["path"], "repo/src/a.py")

    def test_gitlab_admin_keeps_selection_state_when_filter_rerenders(self):
        html = gitlab_admin_page(
            [{"project_id": "p", "name": "demo"}],
            [{"mapping_id": "m", "project_id": "p", "project_name": "demo", "gitlab_project_id": 7,
              "path_with_namespace": "group/demo", "tracker_service_id": "svc", "tracker_environment_id": "env"}],
            configuration={}, schedule_targets=[], worker_settings={}, server_connections=[], server_mappings=[],
        )
        self.assertIn("gitlabSelected", html)
        self.assertIn("gitlab-select-all", html)
        self.assertIn("gitlabSelected.add", html)
        self.assertIn("gitlabSelected.delete", html)

    def test_admin_markup_restores_memberships_and_has_screen_accordions(self):
        from security_scanner.portal_views import admin_page
        self.assertIn("권한관리", admin_page("x", ""))
        source = Path("platforms/shared/python/security_scanner/linux_portal.py").read_text(encoding="utf-8")
        self.assertIn("syncMembershipForProject", source)
        self.assertIn("permission-screen", source)


if __name__ == "__main__":
    unittest.main()
