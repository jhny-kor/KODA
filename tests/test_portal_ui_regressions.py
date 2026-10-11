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

    def test_comparison_normalizes_nested_gitlab_archive_and_extraction_roots(self):
        base = {"project_id": "p", "status": "completed", "snapshot": {
            "gitlab_project_id": 7, "gitlab_path_with_namespace": "group/demo",
            "gitlab_commit_sha": "a" * 40,
        }}
        left = {**base, "snapshot": {**base["snapshot"], "gitlab_archive_root": "demo-main-a1",
                                      "input_id": "left"},
                "result": {"findings": [{"rule_id": "R", "path": "left.tar.gz.extracted/demo-main-a1/src/a.py", "line": 3}]}}
        right = {**base, "snapshot": {**base["snapshot"], "gitlab_archive_root": "demo-feature-b2",
                                       "input_id": "right"},
                 "result": {"findings": [{"rule_id": "R", "path": "right.tar.gz.extracted/demo-feature-b2/src/a.py", "line": 3}]}}
        store = _ComparisonStore({"left": left, "right": right}, {
            "left": {"name": "left.tar.gz"}, "right": {"name": "right.tar.gz"},
        })
        result = _comparison_data(store, "subject", "left", "right")
        self.assertEqual(result["counts"], {"new": 0, "resolved": 0, "persistent": 1})

    def test_scheduled_gitlab_comparison_restores_selected_source_directory(self):
        base = {"project_id": "p", "status": "completed", "snapshot": {
            "source_type": "scheduled_server", "scheduled_source_kind": "gitlab",
            "source_gitlab_project_id": 7, "source_gitlab_path": "group/demo",
            "gitlab_project_id": 99, "gitlab_path_with_namespace": "group/results",
            "source_gitlab_directory": "services/api",
        }}
        left = {**base, "result": {"findings": [{"rule_id": "R", "path": "main.py", "line": 3}]}}
        right = {**base, "result": {"findings": [{"rule_id": "R", "path": "services/api/main.py", "line": 3}]}}
        result = _comparison_data(_ComparisonStore({"left": left, "right": right}), "subject", "left", "right")
        self.assertEqual(result["counts"], {"new": 0, "resolved": 0, "persistent": 1})

    def test_scheduled_gitlab_comparison_rejects_different_source_repo_with_same_result_repo(self):
        base = {"project_id": "p", "status": "completed", "snapshot": {
            "source_type": "scheduled_server", "scheduled_source_kind": "gitlab",
            "source_gitlab_project_id": 7, "source_gitlab_path": "group/demo",
            "gitlab_project_id": 99, "gitlab_path_with_namespace": "group/results",
        }}
        right = {**base, "snapshot": {**base["snapshot"], "source_gitlab_project_id": 8,
                                       "source_gitlab_path": "group/other"}}
        with self.assertRaises(ValueError):
            _comparison_data(_ComparisonStore({"left": base, "right": right}), "subject", "left", "right")

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
        self.assertNotIn("<details class='permission-screen'>", source)
        self.assertIn("permission-feature-screen", source)

    def test_role_feature_permissions_are_screen_grouped_and_role_scoped(self):
        source = Path("platforms/shared/python/security_scanner/linux_portal.py").read_text(encoding="utf-8")
        self.assertIn("permission-feature-screen", source)
        self.assertIn("data-permission-shared", source)
        self.assertIn("box.dataset.permissionShared", source)
        self.assertIn("box.name", source)
        self.assertIn("!roles[k].includes(v)", source)

    def test_result_and_project_buttons_follow_feature_permissions(self):
        from security_scanner.portal_views import projects_page, project_page, run_page, runs_page
        project = {"project_id": "p", "name": "demo"}
        run = {"run_id": "r", "project_id": "p", "status": "completed", "round_number": 1,
               "policy_version": 1, "snapshot": {"gitlab_project_id": 1}, "result": {"findings": []}}
        delivery = {"status": "failed", "gitlab_result_status": "failed"}
        denied = run_page(run, admin=False, feature_permissions=set(), tracker=delivery, gitlab_issues={"status": "failed"})
        for marker in ("?format=pdf", "id='tracker-retry'", "id='gitlab-result-retry'", "id='gitlab-issues-retry'"):
            self.assertNotIn(marker, denied)
        allowed = run_page(run, admin=False, feature_permissions={"runs.export", "runs.tracker.publish", "runs.gitlab.result.publish", "runs.gitlab.issues.publish"}, tracker=delivery, gitlab_issues={"status": "failed"})
        for marker in ("?format=pdf", "id='tracker-retry'", "id='gitlab-result-retry'", "id='gitlab-issues-retry'"):
            self.assertIn(marker, allowed)
        active_run = {**run, "status": "running", "snapshot": {"scan_scope": "source"}}
        self.assertNotIn("id='cancel'", run_page(active_run, admin=False, feature_permissions={"scan.library.create"}))
        self.assertIn("id='cancel'", run_page(active_run, admin=False, feature_permissions={"scan.source.create"}))
        self.assertIn("id='create'", projects_page([project], admin=False, can_create=True))
        self.assertNotIn("id='create'", projects_page([project], admin=False, can_create=False))
        self.assertIn("data-delete-project='p'", project_page(project, [], [], admin=False, can_upload=False, can_scan=False, can_delete=True))
        self.assertNotIn("data-delete-project='p'", project_page(project, [], [], admin=False, can_upload=False, can_scan=False, can_delete=False))
        self.assertIn("data-delete-run='r'", runs_page([(project, [run])], admin=False, run_permissions={"r": {"runs.delete"}}))
        self.assertNotIn("data-delete-run='r'", runs_page([(project, [run])], admin=False, run_permissions={"r": set()}))

    def test_role_scan_execution_permissions_are_independent_by_screen(self):
        source = Path("platforms/shared/python/security_scanner/linux_portal.py").read_text(encoding="utf-8")
        views = Path("platforms/shared/python/security_scanner/portal_views.py").read_text(encoding="utf-8")
        self.assertIn('feature_accordion("라이브러리 취약점", ("input.manage", "scan.library.create")', source)
        self.assertIn('feature_accordion("소스코드 취약점", ("input.manage", "scan.source.create")', source)
        self.assertIn('"scan.library.create":', views)
        self.assertIn('"scan.source.create":', views)
        self.assertNotIn('feature_accordion("라이브러리 취약점", ("input.manage", "scan.create")', source)
        self.assertNotIn('feature_accordion("소스코드 취약점", ("input.manage", "scan.create")', source)

    def test_rule_bulk_controls_cover_groups_and_visible_search_scope(self):
        source = Path("platforms/shared/python/security_scanner/linux_portal.py").read_text(encoding="utf-8")
        self.assertIn("data-rule-group-action='enable'", source)
        self.assertIn("data-rule-group-action='disable'", source)
        self.assertIn("data-rule-action='enable'", source)
        self.assertIn("visibleRuleCards", source)
        self.assertIn("peer.dataset.ruleId===box.dataset.ruleId", source)


if __name__ == "__main__":
    unittest.main()
