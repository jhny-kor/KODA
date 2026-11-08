import io
import tarfile
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import PropertyMock, patch

from security_scanner.linux_portal import _comparison_data, _run_scan
from security_scanner.manual_gitlab import select_manual_files
from security_scanner.portal_integrations import _gitlab_mr_summary, _gitlab_scan_report
from security_scanner.portal_store import PortalStore
from security_scanner.server import scan_directory_payload
import test_linux_portal as portal_tests


class ManualGitLabScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = PortalStore(self.root / "portal.db")
        self.admin = str(uuid.uuid4())
        self.store.bootstrap(self.admin)
        self.project = self.store.create_project("manual delta", self.admin)
        self.mapping = self.store.set_gitlab_repositories(self.project, [{
            "gitlab_project_id": 42, "path_with_namespace": "group/demo", "name": "demo", "default_branch": "main",
            "tracker_service_id": "svc", "tracker_environment_id": "env", "tracker_token_ref": "fixture",
        }])[0]

    def run_scan(self, files, *, branch="main", scope="source", standard="local", perform=True, mode="changed"):
        self.number = getattr(self, "number", 0) + 1
        path = self.root / "inputs" / f"input-{self.number}.tar.gz"
        path.parent.mkdir(exist_ok=True)
        archive_root = f"demo-{self.number}"
        with tarfile.open(path, "w:gz") as archive:
            for name, content in files.items():
                member = tarfile.TarInfo(f"{archive_root}/{name}")
                body = content.encode()
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
        input_id = self.store.add_input(self.project, path.name, path, self.admin)
        run = self.store.create_scan(self.admin, self.project, input_id, standard, "all", scope, source_snapshot={
            "gitlab_mapping_id": self.mapping["mapping_id"], "gitlab_project_id": 42,
            "gitlab_path_with_namespace": "group/demo", "gitlab_ref_type": "branch", "gitlab_ref_name": branch,
            "gitlab_commit_sha": f"{self.number:040x}", "gitlab_archive_root": archive_root,
        }, gitlab_scan_mode=mode)
        if perform:
            _run_scan(self.store, run["run_id"], deliver=False)
        saved = self.store.run(run["run_id"])
        if perform:
            self.assertEqual(saved["status"], "completed", saved.get("error"))
        return saved

    def test_first_scan_full_then_changed_and_deleted_then_no_changes(self):
        first = self.run_scan({"src/a.py": "print(1)", "src/old.py": "print(2)"})
        scope = first["snapshot"]["file_scope"]
        self.assertEqual((scope["requested_mode"], scope["effective_mode"], scope["reason"]), ("changed", "full", "no_baseline"))
        second = self.run_scan({"src/a.py": "print(3)", "src/new.py": "print(4)"})
        scope = second["snapshot"]["file_scope"]
        self.assertEqual((scope["effective_mode"], scope["new_files"], scope["changed_files"], scope["deleted_files"]), ("changed", 1, 1, 1))
        self.assertEqual(scope["baseline_run_id"], first["run_id"])
        self.assertEqual(scope["selected_paths"], ["src/a.py", "src/new.py"])
        third = self.run_scan({"src/a.py": "print(3)", "src/new.py": "print(4)"})
        scope = third["snapshot"]["file_scope"]
        self.assertEqual((scope["effective_mode"], scope["reason"], scope["scanned_files"]), ("changed", "unchanged", 0))
        self.assertEqual(third["result"]["findings"], [])
        self.assertTrue(all(stage["status"] == "skipped" for stage in third["result"]["analysis_stages"].values()))
        self.assertEqual(third["result"]["scan"]["file_scope"], scope)

    def test_mode_is_frozen_at_submission(self):
        self.run_scan({"src/a.py": "print(1)"})
        queued = self.run_scan({"src/a.py": "print(2)"}, perform=False)
        _run_scan(self.store, queued["run_id"], deliver=False)
        saved = self.store.run(queued["run_id"])
        self.assertEqual(saved["snapshot"]["file_scope"]["effective_mode"], "changed")
        full = self.run_scan({"src/a.py": "print(2)"}, mode="full")
        self.assertEqual(full["snapshot"]["file_scope"]["effective_mode"], "full")

    def test_deleted_full_scan_forces_full_even_when_successful_delta_remains(self):
        first = self.run_scan({"src/a.py": "print(1)"})
        delta = self.run_scan({"src/a.py": "print(2)"})
        self.assertEqual(delta["snapshot"]["file_scope"]["effective_mode"], "changed")
        self.assertEqual(delta["snapshot"]["file_scope"]["full_scan_run_id"], first["run_id"])
        self.store.delete_run(first["run_id"], self.admin)
        regenerated = self.run_scan({"src/a.py": "print(2)"})
        scope = regenerated["snapshot"]["file_scope"]
        self.assertEqual((scope["requested_mode"], scope["effective_mode"], scope["reason"]), ("changed", "full", "no_baseline"))
        next_delta = self.run_scan({"src/a.py": "print(3)"})
        self.assertEqual(next_delta["snapshot"]["file_scope"]["effective_mode"], "changed")
        self.assertEqual(next_delta["snapshot"]["file_scope"]["full_scan_run_id"], regenerated["run_id"])
        self.assertEqual(next_delta["snapshot"]["file_scope"]["baseline_run_id"], regenerated["run_id"])

    def test_deleting_all_repository_results_forces_full_on_next_changed_request(self):
        first = self.run_scan({"src/a.py": "print(1)"})
        second = self.run_scan({"src/a.py": "print(2)"})
        self.store.delete_run(first["run_id"], self.admin)
        self.store.delete_run(second["run_id"], self.admin)
        next_run = self.run_scan({"src/a.py": "print(3)"})
        self.assertEqual(next_run["snapshot"]["file_scope"]["effective_mode"], "full")
        self.assertEqual(next_run["snapshot"]["file_scope"]["reason"], "no_baseline")

    def test_branch_and_policy_changes_require_full(self):
        self.run_scan({"src/a.py": "print(1)"})
        branch = self.run_scan({"src/a.py": "print(1)"}, branch="feature")
        self.assertEqual(branch["snapshot"]["file_scope"]["reason"], "no_baseline")
        standard = self.run_scan({"src/a.py": "print(1)"}, standard="owasp-top-10-2025")
        self.assertEqual(standard["snapshot"]["file_scope"]["reason"], "settings_changed")

    def test_selected_files_are_actually_filtered_for_local_scan(self):
        key = "AK" + "IA" + "Q7M2X9P4R6T8V3W5"
        first = self.run_scan({"src/config.env": f"AWS_ACCESS_KEY_ID={key}\n", "src/app.py": "print(1)"})
        self.assertTrue(first["result"]["findings"])
        with patch("security_scanner.scanner.SecurityScanner._scan_file", autospec=True, return_value=[]) as scan_file:
            second = self.run_scan({"src/config.env": f"AWS_ACCESS_KEY_ID={key}\n", "src/app.py": "print(2)"})
        self.assertEqual({call.args[1].name for call in scan_file.call_args_list}, {"app.py"})
        self.assertEqual(second["result"]["findings"], [])
        comparison = _comparison_data(self.store, self.admin, first["run_id"], second["run_id"])
        self.assertEqual(comparison["counts"]["resolved"], 0)
        self.assertGreater(comparison["counts"]["unassessed"], 0)

    def test_sw49_retains_whole_project_context_and_scopes_findings(self):
        files = {"src/a.py": "print(1)", "src/b.py": "print(2)"}
        self.run_scan(files, standard="sw-dev-security-49")
        with patch("security_scanner.scanner.SecurityScanner._scan_file", autospec=True, return_value=[]) as scan_file:
            second = self.run_scan({**files, "src/a.py": "print(3)"}, standard="sw-dev-security-49")
        self.assertEqual({call.args[1].name for call in scan_file.call_args_list}, {"a.py", "b.py"})
        scope = second["snapshot"]["file_scope"]
        self.assertEqual((scope["scanned_files"], scope["context_files"]), (1, 2))
        self.assertIn("전체 프로젝트 문맥", scope["context_note"])

    def test_library_context_and_ignore_policy_selection(self):
        root = self.root / "selection"
        root.mkdir()
        for name, content in {"app.py": "print(1)", "requirements.txt": "requests==2.31.0"}.items():
            (root / name).write_text(content)
        run = {"snapshot": {"requested_scan_mode": "changed", "scan_scope": "all", "standard": "local"}}
        manifest, _, scope = select_manual_files(root, run, None)
        baseline = {"run_id": "baseline", "manifest": manifest, "snapshot": {**run["snapshot"], "file_scope": scope}}
        _, selected, scope = select_manual_files(root, run, baseline)
        self.assertEqual([p.name for p in selected], ["requirements.txt"])
        self.assertEqual(scope["dependency_context_files"], 1)
        (root / ".koda-ignore.yml").write_text("rules: []")
        _, selected, scope = select_manual_files(root, run, baseline)
        self.assertIsNone(selected)
        self.assertEqual(scope["reason"], "settings_changed")

    def test_partial_metadata_in_gitlab_publication(self):
        self.run_scan({"a.py": "print(1)"})
        run = self.run_scan({"a.py": "print(2)"})
        report = _gitlab_scan_report(run, "", {})
        self.assertEqual(report["inspection"]["fileScope"]["effective_mode"], "changed")
        _, body, _ = _gitlab_mr_summary(report, ".koda/result.json")
        self.assertIn("신규·변경 파일만", body)
        self.assertIn("실제 점검 범위", body)

    def test_new_file_after_delta_is_new_in_comparison(self):
        self.run_scan({"a.py": "print(1)"})
        before = self.run_scan({"a.py": "print(2)"})
        key = "AK" + "IA" + "Q7M2X9P4R6T8V3W5"
        after = self.run_scan({"a.py": "print(2)", "config.env": f"AWS_ACCESS_KEY_ID={key}\n"})
        comparison = _comparison_data(self.store, self.admin, before["run_id"], after["run_id"])
        self.assertGreater(comparison["counts"]["new"], 0)
        self.assertFalse(any(item["status"] == "unassessed" for item in comparison["findings"]))

    def test_comparison_preserves_unknown_historical_server_but_rejects_known_mismatch(self):
        before = self.run_scan({"a.py": "print(1)"})
        after = self.run_scan({"a.py": "print(2)"})
        after["snapshot"]["gitlab_instance_url"] = "https://gitlab.example.internal"
        with patch.object(self.store, "run", side_effect=lambda key: before if key == before["run_id"] else after):
            _comparison_data(self.store, self.admin, before["run_id"], after["run_id"])
            before["snapshot"]["gitlab_instance_url"] = "https://other.example.internal"
            with self.assertRaisesRegex(ValueError, "same server"):
                _comparison_data(self.store, self.admin, before["run_id"], after["run_id"])


class ManualGitLabModeHttpTests(unittest.TestCase):
    setUp = portal_tests.LinuxPortalHttpTests.setUp
    tearDown = portal_tests.LinuxPortalHttpTests.tearDown
    headers = portal_tests.LinuxPortalHttpTests.headers
    request = portal_tests.LinuxPortalHttpTests.request

    def test_analyst_selects_mode_per_run_and_admin_mode_endpoint_is_removed(self):
        self.server.portal_worker.close()
        project = self.server.portal_store.create_project("modes", self.admin)
        mapping = self.server.portal_store.set_gitlab_repositories(project, [{
            "gitlab_project_id": 42, "path_with_namespace": "group/demo", "name": "demo", "default_branch": "main",
            "tracker_service_id": "svc", "tracker_environment_id": "env", "tracker_token_ref": "private",
        }])[0]
        endpoint = f"/koda/api/v1/admin/gitlab/repositories/{mapping['mapping_id']}/scan-mode"
        self.assertEqual(self.request(endpoint, method="POST", headers=self.headers(), payload={"manual_scan_mode": "changed"})[0], 404)
        analyst = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(analyst, "analyst")
        self.server.portal_store.set_subject(analyst, status="enabled", system_admin=False, actor=self.admin)
        self.server.portal_store.set_membership(project, analyst, "analyst", self.admin)
        payload = {"project_id": project, "gitlab_repository_id": mapping["mapping_id"],
                   "ref_type": "branch", "ref_name": "main", "standard": "local",
                   "standard_category": "all", "scan_scope": "source"}

        def fake_download(_project, _sha, target, **kwargs):
            with tarfile.open(target, "w:gz") as archive:
                member = tarfile.TarInfo("repo-main/src/app.py")
                body = b"print(1)"
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
            return "a" * 64, target.stat().st_size

        with patch.object(type(self.server.portal_worker), "available", new_callable=PropertyMock, return_value=True), \
             patch.object(self.server.portal_worker, "enqueue"), \
             patch("security_scanner.linux_portal.resolve_gitlab_ref", return_value="a" * 40) as resolve, \
             patch("security_scanner.linux_portal.download_gitlab_archive", side_effect=fake_download):
            for mode in ("changed", "full", None):
                submitted = dict(payload)
                if mode is not None:
                    submitted["gitlab_scan_mode"] = mode
                status, run = self.request("/koda/api/v1/scans", method="POST", headers=self.headers(analyst), payload=submitted)
                self.assertEqual(status, 202, run)
                saved = self.server.portal_store.run(run["run_id"])
                self.assertEqual(saved["snapshot"]["requested_scan_mode"], mode or "full")
            resolve.reset_mock()
            for mode in ("", "invalid", None, [], True):
                status, _ = self.request("/koda/api/v1/scans", method="POST", headers=self.headers(analyst), payload={**payload, "gitlab_scan_mode": mode})
                self.assertEqual(status, 422)
            resolve.assert_not_called()
            self.assertEqual(self.request("/koda/api/v1/scans", method="POST", headers=self.headers(analyst), payload={
                "project_id": project, "input_id": str(uuid.uuid4()), "standard": "local", "standard_category": "all",
                "gitlab_scan_mode": "changed", "scan_scope": "source",
            })[0], 422)

    def test_empty_selection_never_executes_scanner(self):
        with tempfile.TemporaryDirectory() as root, patch("security_scanner.server.SecurityScanner.scan") as scan:
            payload = scan_directory_payload(root, scan_scope="source", file_selection=())
        scan.assert_not_called()
        self.assertEqual(payload["findings_by_language"]["ko"], [])
