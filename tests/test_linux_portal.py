import datetime as dt
import base64
from collections import Counter
import csv
import hashlib
import http.client
import io
import json
import os
import tempfile
import tarfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path
from unittest.mock import patch

from security_scanner.portal_identity import IdentityError, identity_from_headers
from security_scanner.portal_integrations import (
    IntegrationError,
    _gitlab_scan_report,
    _gitlab_mr_summary,
    _gitlab_settings,
    create_gitlab_issue,
    find_gitlab_issue,
    find_gitlab_issue_note,
    gitlab_configuration,
    list_gitlab_refs,
    provision_tracker_repository,
    publish_tracker_result,
    remove_gitlab_configuration,
    save_gitlab_configuration,
    test_gitlab_write_configuration,
)
from security_scanner.linux_portal import MAX_INPUT_BYTES, _deliver_gitlab_issues, _deliver_gitlab_result, _deliver_tracker, _run_delivery, create_portal_server
from security_scanner.grype_adapter import GrypeMatch, GrypeResult
from security_scanner.portal_store import GLOBAL_ROLE_POLICY_ID, SCREEN_PERMISSIONS, PortalStore
from security_scanner.portal_views import format_portal_time
from security_scanner.reporting import render_html_pair_zip_from_payload
from security_scanner.server import scan_directory_payload
from security_scanner.schedule_worker import RemoteFile


class LinuxPortalStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PortalStore(Path(self.tmp.name) / "portal.sqlite3")
        self.admin = str(uuid.uuid4())
        self.store.bootstrap(self.admin)
        self.project = self.store.create_project("demo")
        self.store.set_membership(self.project, self.admin, "admin")
        target = Path(self.tmp.name) / "input.txt"
        target.write_text("secret", encoding="utf-8")
        self.input_id = self.store.add_input(self.project, "input.txt", target)

    def tearDown(self):
        self.tmp.cleanup()

    def gitlab_run(self, findings, scope="source"):
        mappings = self.store.gitlab_repositories(self.project)
        mapping = mappings[0] if mappings else self.store.set_gitlab_repositories(self.project, [{
            "gitlab_project_id": 42, "path_with_namespace": "group/demo", "name": "demo",
            "default_branch": "main", "tracker_service_id": "service-1",
            "tracker_environment_id": "environment-1", "tracker_token_ref": "demo.token",
        }], self.admin)[0]
        target = Path(self.tmp.name) / f"gitlab-{uuid.uuid4().hex}.tar.gz"
        target.write_bytes(b"archive")
        input_id = self.store.add_input(self.project, target.name, target)
        run = self.store.create_scan(self.admin, self.project, input_id, "local", "all", scope, source_snapshot={
            "gitlab_mapping_id": mapping["mapping_id"], "gitlab_project_id": 42,
            "gitlab_path_with_namespace": "group/demo", "gitlab_ref_type": "branch",
            "gitlab_ref_name": "main", "gitlab_commit_sha": "a" * 40,
            "gitlab_archive_sha256": "b" * 64, "gitlab_fetched_at": self.store._now(),
            "gitlab_default_branch": "main", "tracker_service_id": "service-1",
            "tracker_environment_id": "environment-1", "tracker_token_ref": "demo.token",
        })
        self.store.complete_run(run["run_id"], result={"findings": findings, "sbom": {"components": []}})
        return self.store.run(run["run_id"])

    def test_header_identity_and_expiry(self):
        headers = {
            "X-KODA-Identity-ID": self.admin,
            "X-KODA-Identity-Expires": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=1)).isoformat(),
            "X-KODA-Identity-Display": "YWRtaW4",
        }
        self.assertEqual(identity_from_headers(headers).display, "admin")
        headers["X-KODA-Identity-Expires"] = "2000-01-01T00:00:00+00:00"
        with self.assertRaises(IdentityError):
            identity_from_headers(headers)

    def test_gitlab_ref_pagination_rejects_repeated_page(self):
        with patch("security_scanner.portal_integrations._gitlab_json", return_value=([], {"X-Next-Page": "1"})):
            with self.assertRaises(IntegrationError):
                list_gitlab_refs(42, "branch")

    def test_gitlab_write_token_requires_api_scope_and_same_account(self):
        account = {"id": 7, "username": "scanner"}
        with patch("security_scanner.portal_integrations._gitlab_status", side_effect=[account, account]), patch(
            "security_scanner.portal_integrations._gitlab_json", side_effect=[
                ({"scopes": ["read_api"]}, {}), ({"scopes": ["api"]}, {}),
            ],
        ):
            self.assertEqual(test_gitlab_write_configuration(
                "https://gitlab.example.internal", "read-token", "write-token",
            ), account)
        with patch("security_scanner.portal_integrations._gitlab_status", side_effect=[account, account]), patch(
            "security_scanner.portal_integrations._gitlab_json", side_effect=[
                ({"scopes": ["read_api"]}, {}), ({"scopes": ["write_repository"]}, {}),
            ],
        ):
            with self.assertRaisesRegex(IntegrationError, "api 범위"):
                test_gitlab_write_configuration(
                    "https://gitlab.example.internal", "read-token", "write-token",
                )
        with patch("security_scanner.portal_integrations._gitlab_status", side_effect=[account, {"id": 8, "username": "other"}]), patch(
            "security_scanner.portal_integrations._gitlab_json", side_effect=[
                ({"scopes": ["read_api"]}, {}), ({"scopes": ["api"]}, {}),
            ],
        ):
            with self.assertRaisesRegex(IntegrationError, "같은 계정"):
                test_gitlab_write_configuration(
                    "https://gitlab.example.internal", "read-token", "write-token",
                )

    def test_gitlab_issue_client_always_creates_confidential_issue(self):
        with patch("security_scanner.portal_integrations._gitlab_write_json", return_value={
            "iid": 3, "web_url": "https://gitlab.example/group/demo/-/issues/3",
        }) as request:
            issue = create_gitlab_issue(42, "title", "body", settings_dir=Path(self.tmp.name))
        self.assertEqual(issue["iid"], 3)
        self.assertEqual(request.call_args.kwargs["payload"], {
            "title": "title", "description": "body", "confidential": True,
        })

    def test_confirmed_security_findings_create_and_reuse_open_or_closed_gitlab_issues(self):
        confirmed = {
            "rule_id": "code.demo", "category": "code", "severity": "high", "title": "Demo flaw",
            "path": "src/demo.py", "line": 7, "target": "demo", "evidence": "masked evidence",
            "description": "description", "recommendation": "fix it", "verification_status": "confirmed",
            "issue_key": "code.demo|src/demo.py|7", "trace": [{"raw": "must-not-leave-koda"}],
        }
        excluded = {**confirmed, "rule_id": "code.review", "issue_key": "review", "verification_status": "needs_review"}
        run1 = self.gitlab_run([
            confirmed, excluded,
            {**confirmed, "category": "quality", "issue_key": "quality"},
            {**confirmed, "category": "dependencies", "issue_key": "dependency"},
        ])
        with patch("security_scanner.linux_portal.find_gitlab_issue", return_value=None), patch(
            "security_scanner.linux_portal.create_gitlab_issue", return_value={
                "iid": 1, "web_url": "https://gitlab.example/group/demo/-/issues/1", "state": "opened",
            },
        ) as created:
            first = _deliver_gitlab_issues(self.store, run1["run_id"])
        self.assertEqual((first["status"], first["total_count"], first["created_count"]), ("completed", 1, 1))
        self.assertNotIn("must-not-leave-koda", created.call_args.args[2])
        self.assertIn("[KODA][HIGH] Demo flaw", created.call_args.args[1])

        run2 = self.gitlab_run([confirmed])
        opened = {"iid": 1, "web_url": "https://gitlab.example/group/demo/-/issues/1", "state": "opened"}
        with patch("security_scanner.linux_portal.get_gitlab_issue", return_value=opened), patch(
            "security_scanner.linux_portal.find_gitlab_issue_note", return_value=None,
        ), patch("security_scanner.linux_portal.add_gitlab_issue_note", return_value={"id": 9}) as noted:
            second = _deliver_gitlab_issues(self.store, run2["run_id"])
        self.assertEqual((second["status"], second["reused_count"]), ("completed", 1))
        self.assertIn(run2["run_id"], noted.call_args.args[2])

        run3 = self.gitlab_run([confirmed])
        with patch("security_scanner.linux_portal.get_gitlab_issue", return_value={**opened, "state": "closed"}), patch(
            "security_scanner.linux_portal.find_gitlab_issue_note", return_value=None,
        ), patch("security_scanner.linux_portal.add_gitlab_issue_note", return_value={"id": 10}) as noted_closed, patch(
            "security_scanner.linux_portal.create_gitlab_issue",
        ) as recreated:
            third = _deliver_gitlab_issues(self.store, run3["run_id"])
        self.assertEqual((third["status"], third["reused_count"]), ("completed", 1))
        noted_closed.assert_called_once()
        recreated.assert_not_called()

    def test_gitlab_marker_search_paginates_issues_and_notes(self):
        marker = "<!-- koda-finding:" + "a" * 64 + " -->"
        first_page = [{"description": "other"} for _ in range(100)]
        expected_issue = {"iid": 7, "description": marker}
        with patch("security_scanner.portal_integrations._gitlab_json", side_effect=[
            (first_page, {"X-Next-Page": "2"}), ([expected_issue], {"X-Next-Page": ""}),
        ]) as request:
            self.assertEqual(find_gitlab_issue(42, marker, settings_dir=Path(self.tmp.name)), expected_issue)
        self.assertEqual(request.call_args_list[1].args[1]["page"], "2")

        note_marker = "<!-- koda-delivery:run:item -->"
        expected_note = {"id": 8, "body": note_marker}
        with patch("security_scanner.portal_integrations._gitlab_json", side_effect=[
            ([{"body": "other"}] * 100, {"X-Next-Page": "2"}), ([expected_note], {}),
        ]):
            self.assertEqual(find_gitlab_issue_note(42, 7, note_marker, settings_dir=Path(self.tmp.name)), expected_note)

    def test_gitlab_issue_partial_retry_and_restart_recovery(self):
        findings = [{
            "rule_id": f"code.demo.{index}", "category": "code", "severity": "medium", "title": f"Finding {index}",
            "path": f"src/{index}.py", "line": index, "verification_status": "confirmed", "issue_key": f"finding-{index}",
        } for index in (1, 2)]
        run = self.gitlab_run(findings)
        with patch("security_scanner.linux_portal.find_gitlab_issue", return_value=None), patch(
            "security_scanner.linux_portal.create_gitlab_issue", side_effect=[
                IntegrationError("invalid item", status=400),
                {"iid": 2, "web_url": "https://gitlab.example/group/demo/-/issues/2", "state": "opened"},
            ],
        ):
            partial = _deliver_gitlab_issues(self.store, run["run_id"])
        self.assertEqual((partial["status"], partial["created_count"], partial["failed_count"]), ("partial", 1, 1))
        with patch("security_scanner.linux_portal.find_gitlab_issue", return_value=None), patch(
            "security_scanner.linux_portal.create_gitlab_issue", return_value={
                "iid": 1, "web_url": "https://gitlab.example/group/demo/-/issues/1", "state": "opened",
            },
        ) as retried:
            completed = _deliver_gitlab_issues(self.store, run["run_id"], retry=True)
        self.assertEqual((completed["status"], completed["created_count"], completed["failed_count"]), ("completed", 2, 0))
        retried.assert_called_once()

        recovering = self.gitlab_run(findings[:1])
        self.store.claim_gitlab_issue_delivery(recovering["run_id"])
        reopened = PortalStore(Path(self.tmp.name) / "portal.sqlite3")
        self.assertIn(recovering["run_id"], reopened.recover_gitlab_issue_deliveries())
        self.assertEqual(reopened.gitlab_issue_delivery(recovering["run_id"])["status"], "pending")

    def test_gitlab_issue_crash_marker_and_system_failure_do_not_duplicate_or_fail_scan(self):
        finding = {
            "rule_id": "code.crash", "category": "code", "severity": "critical", "title": "Crash safe",
            "path": "src/crash.py", "line": 1, "verification_status": "confirmed", "issue_key": "crash-safe",
        }
        run = self.gitlab_run([finding])
        self.store.claim_gitlab_issue_delivery(run["run_id"])
        self.store.prepare_gitlab_issue_items(run["run_id"], 42, [{
            "finding_index": 0, "finding_key": "crash-safe",
        }])
        self.store.claim_gitlab_issue_item(run["run_id"], "crash-safe")
        reopened = PortalStore(Path(self.tmp.name) / "portal.sqlite3")
        reopened.recover_gitlab_issue_deliveries()
        recovered_issue = {"iid": 11, "web_url": "https://gitlab.example/group/demo/-/issues/11", "state": "opened"}
        with patch("security_scanner.linux_portal.find_gitlab_issue", return_value=recovered_issue), patch(
            "security_scanner.linux_portal.create_gitlab_issue",
        ) as create:
            delivery = _deliver_gitlab_issues(reopened, run["run_id"])
        self.assertEqual((delivery["status"], delivery["created_count"]), ("completed", 1))
        create.assert_not_called()

        failed_run = self.gitlab_run([{**finding, "issue_key": "system-failure"}])
        with patch("security_scanner.linux_portal.find_gitlab_issue", side_effect=IntegrationError("rate limited", status=429)):
            failed = _deliver_gitlab_issues(self.store, failed_run["run_id"])
        self.assertEqual((failed["status"], failed["failed_count"]), ("failed", 1))
        self.assertEqual(self.store.run(failed_run["run_id"])["status"], "completed")
        self.assertEqual(self.store.tracker_delivery(failed_run["run_id"])["status"], "pending")

    def test_guarded_retries_finalize_sending_state_after_unexpected_errors(self):
        tracker_run = self.gitlab_run([])

        def crash_tracker(store, run_id, *, retry=False):
            store.claim_tracker_delivery(run_id, retry=retry)
            raise OSError("tracker socket failed")

        with patch("security_scanner.linux_portal._deliver_tracker", side_effect=crash_tracker), self.assertRaises(OSError):
            _run_delivery(self.store, "tracker", tracker_run["run_id"])
        self.assertEqual(self.store.tracker_delivery(tracker_run["run_id"])["status"], "failed")

        result_run = self.gitlab_run([])
        self.store.claim_tracker_delivery(result_run["run_id"])
        self.store.finish_tracker_delivery(result_run["run_id"], "completed", tracker_run_id="tracker-result")

        def crash_result(store, run_id, *, retry=False):
            store.claim_gitlab_result(run_id, retry=retry)
            raise TypeError("malformed GitLab result")

        with patch("security_scanner.linux_portal._deliver_gitlab_result", side_effect=crash_result), self.assertRaises(TypeError):
            _run_delivery(self.store, "gitlab_result", result_run["run_id"])
        self.assertEqual(self.store.tracker_delivery(result_run["run_id"])["gitlab_result_status"], "failed")

        issue_run = self.gitlab_run([{
            "rule_id": "code.guard", "category": "code", "severity": "high", "title": "guard",
            "verification_status": "confirmed", "issue_key": "guarded-item",
        }])

        def crash_issues(store, run_id, *, retry=False):
            store.claim_gitlab_issue_delivery(run_id, retry=retry)
            store.prepare_gitlab_issue_items(run_id, 42, [{"finding_index": 0, "finding_key": "guarded-item"}])
            store.claim_gitlab_issue_item(run_id, "guarded-item")
            raise KeyError("malformed issue result")

        with patch("security_scanner.linux_portal._deliver_gitlab_issues", side_effect=crash_issues), self.assertRaises(KeyError):
            _run_delivery(self.store, "issues", issue_run["run_id"])
        self.assertEqual(self.store.gitlab_issue_delivery(issue_run["run_id"])["status"], "failed")

    def test_gitlab_result_retry_uses_snapshotted_tracker_token(self):
        run = self.gitlab_run([], scope="all")
        self.store.claim_tracker_delivery(run["run_id"])
        self.store.finish_tracker_delivery(run["run_id"], "completed", tracker_run_id="tracker-result")
        tracker_result = {"run": {"runUrl": None}, "analysis": {"findings": []}}
        with patch(
            "security_scanner.linux_portal.fetch_tracker_result", return_value=tracker_result,
        ) as fetch, patch(
            "security_scanner.linux_portal.publish_tracker_result",
            return_value={"mergeRequestUrl": "https://gitlab.example/mr/1", "issueUrls": []},
        ):
            delivery = _deliver_gitlab_result(self.store, run["run_id"])
        self.assertEqual(delivery["gitlab_result_status"], "completed")
        self.assertEqual(fetch.call_args.args[0]["tracker_token_ref"], "demo.token")

    def test_gitlab_web_configuration_uses_private_files_and_environment_lock(self):
        directory = Path(self.tmp.name) / "integrations"
        environment = {"KODA_GITLAB_URL": "", "KODA_GITLAB_TOKEN_FILE": "", "KODA_GITLAB_WRITE_TOKEN_FILE": "", "KODA_GITLAB_CA_FILE": ""}
        with patch.dict(os.environ, environment):
            saved = save_gitlab_configuration(directory, "https://gitlab.example.internal/", "glpat-secret", write_token="glpat-write-secret")
            self.assertEqual(saved, {
                "configured": True, "locked": False, "source": "web",
                "url": "https://gitlab.example.internal", "write_configured": True, "ca_configured": False,
            })
            self.assertEqual((directory / "gitlab.token").read_text(encoding="utf-8"), "glpat-secret\n")
            self.assertEqual((directory / "gitlab-write.token").read_text(encoding="utf-8"), "glpat-write-secret\n")
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual((directory / "gitlab.token").stat().st_mode & 0o777, 0o600)
            self.assertEqual((directory / "gitlab.json").stat().st_mode & 0o777, 0o600)
            self.assertNotIn("glpat-secret", (directory / "gitlab.json").read_text(encoding="utf-8"))
            self.assertEqual(_gitlab_settings(directory)[:2], ("https://gitlab.example.internal", "glpat-secret"))
            save_gitlab_configuration(directory, "https://gitlab.example.internal", "", write_token="")
            self.assertEqual((directory / "gitlab.token").read_text(encoding="utf-8"), "glpat-secret\n")
            self.assertEqual((directory / "gitlab-write.token").read_text(encoding="utf-8"), "glpat-write-secret\n")
            remove_gitlab_configuration(directory)
            self.assertFalse(gitlab_configuration(directory)["configured"])
        token_file = Path(self.tmp.name) / "operator.token"
        token_file.write_text("operator-secret\n", encoding="utf-8")
        with patch.dict(os.environ, {
            "KODA_GITLAB_URL": "https://operator.example.internal",
            "KODA_GITLAB_TOKEN_FILE": str(token_file), "KODA_GITLAB_WRITE_TOKEN_FILE": str(token_file), "KODA_GITLAB_CA_FILE": "",
        }):
            self.assertTrue(gitlab_configuration(directory)["locked"])
            with self.assertRaises(IntegrationError):
                save_gitlab_configuration(directory, "https://other.example.internal", "other-secret")

    def test_tracker_provisioning_stores_rotated_service_token_privately(self):
        provisioning_file = Path(self.tmp.name) / "tracker-provisioning.token"
        provisioning_file.write_text("provision-secret\n", encoding="utf-8")
        token_dir = Path(self.tmp.name) / "tracker-tokens"
        token_dir.mkdir(mode=0o733)
        token_dir.chmod(0o733)
        with patch.dict(os.environ, {
            "KODA_TRACKER_URL": "https://tracker.example.internal",
            "KODA_TRACKER_PROVISIONING_TOKEN_FILE": str(provisioning_file),
            "KODA_TRACKER_TOKEN_DIR": str(token_dir),
        }), patch("security_scanner.portal_integrations._tracker_request_json", return_value={
            "serviceId": "service-1", "environmentId": "environment-1", "uploadToken": "upload-secret",
        }) as request:
            result = provision_tracker_repository("https://gitlab.example.internal", {
                "id": 42, "path_with_namespace": "group/demo",
            })
        self.assertEqual(result, {
            "tracker_service_id": "service-1", "tracker_environment_id": "environment-1",
            "tracker_token_ref": "gitlab-42.token",
        })
        self.assertEqual((token_dir / "gitlab-42.token").read_text(encoding="utf-8"), "upload-secret\n")
        self.assertEqual((token_dir / "gitlab-42.token").stat().st_mode & 0o777, 0o600)
        self.assertEqual(token_dir.stat().st_mode & 0o777, 0o733)
        self.assertEqual(request.call_args.args[:2], ("/api/v1/integrations/koda/repositories", "provision-secret"))

    def test_gitlab_result_branch_versions_use_korean_date_and_account(self):
        import subprocess
        with patch.object(self.store, "_now", return_value="2026-09-05T15:00:00+00:00"):
            first = self.gitlab_run([])
            second = self.gitlab_run([])
        prefix = "koda/results/demo/20260906/round-"
        self.assertEqual(first["snapshot"]["gitlab_result_branch"], prefix + "1")
        self.assertEqual(second["snapshot"]["gitlab_result_branch"], prefix + "2")
        with patch.object(self.store, "_now", return_value="2026-09-06T15:00:00+00:00"):
            third = self.gitlab_run([])
        self.assertEqual(third["snapshot"]["gitlab_result_version"], 1)
        self.assertEqual(third["snapshot"]["gitlab_result_branch"], "koda/results/demo/20260907/round-1")
        self.assertEqual(third["snapshot"]["gitlab_result_date"], "2026-09-07")
        self.assertEqual(self.store.run(first["run_id"])["snapshot"], first["snapshot"])
        self.project = self.store.create_project("한글 프로젝트 / [태그] " + "긴이름" * 25)
        self.store.set_membership(self.project, self.admin, "admin")
        korean = self.gitlab_run([])
        branch = korean["snapshot"]["gitlab_result_branch"]
        self.assertIn("한글-프로젝트", branch)
        subprocess.run(["git", "check-ref-format", "--branch", branch], check=True, capture_output=True)
        self.assertEqual(korean["snapshot"]["gitlab_result_version"], 1)

    def test_gitlab_result_branch_versions_are_serialized_across_connections(self):
        from concurrent.futures import ThreadPoolExecutor
        first = self.gitlab_run([])
        source = {key: value for key, value in first["snapshot"].items() if key in {
            "gitlab_mapping_id", "gitlab_project_id", "gitlab_commit_sha",
        }}
        def create(_):
            store = PortalStore(Path(self.tmp.name) / "portal.sqlite3")
            return store.create_scan(self.admin, self.project, self.input_id, "local", "all", source_snapshot=source)
        with ThreadPoolExecutor(max_workers=4) as pool:
            runs = list(pool.map(create, range(4)))
        self.assertEqual(sorted(run["snapshot"]["gitlab_result_version"] for run in runs), [2, 3, 4, 5])

    def test_detailed_gitlab_report_and_mr_retry_preserve_human_content(self):
        finding = {"category": "code", "severity": "high", "rule_id": "SQL-1", "title": "SQL injection",
                   "path": "app.py", "line": 7, "evidence": "redacted evidence", "recommendation": "parameterize",
                   "verification_status": "review", "cwe_ids": ["CWE-89"], "trace": "DO-NOT-EXPORT"}
        run = self.gitlab_run([finding, {**finding, "category": "dependencies", "rule_id": "LIB-1"}])
        tracker = {"analysis": {"state": "succeeded", "findings": []}}
        report = _gitlab_scan_report(run, "tracker-1", tracker)
        self.assertEqual(report["schemaVersion"], 2)
        self.assertEqual(report["inspection"]["accountId"], self.admin)
        self.assertEqual(report["kodaResult"]["findings"][0]["recommendation"], "parameterize")
        self.assertNotIn("DO-NOT-EXPORT", json.dumps(report))
        self.assertNotIn("tracker_token_ref", json.dumps(report))
        self.assertIn("sbom", report["kodaResult"])
        file_path = f".koda/scan-results/{run['run_id']}.json"
        title, body, labels = _gitlab_mr_summary(report, file_path)
        self.assertIn("v1", title)
        self.assertIn("app.py:7", body)
        self.assertIn("review", body)
        self.assertIn("category:dependencies", labels)
        self.assertIn("severity:high", labels)
        encoded = base64.b64encode((json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()).decode()
        existing = {"iid": 7, "web_url": "https://gitlab.example/mr/7", "description": "operator note", "labels": ["manual"]}
        def write(path, query=None, *, settings_dir, method="GET", payload=None):
            if method == "GET":
                return [existing.copy()]
            self.assertEqual((method, path), ("PUT", "/projects/42/merge_requests/7"))
            existing.update(description=payload["description"], labels=existing["labels"] + payload["add_labels"].split(","))
            return existing.copy()
        with patch("security_scanner.portal_integrations._gitlab_optional_json", return_value={"encoding": "base64", "content": encoded}), patch(
            "security_scanner.portal_integrations._gitlab_write_json", side_effect=write,
        ) as request:
            for _ in range(2):
                publish_tracker_result({"default_branch": "main"}, run, "tracker-1", tracker, settings_dir=self.tmp.name)
        self.assertEqual(sum(call.kwargs.get("method") == "PUT" for call in request.call_args_list), 1)
        self.assertEqual(existing["description"], body + "\n\noperator note")
        self.assertIn("manual", existing["labels"])

    def test_mr_limits_display_without_truncating_json(self):
        findings = [{"category": "code", "severity": "high", "rule_id": str(i), "title": "a|b\n/close"} for i in range(51)]
        report = _gitlab_scan_report({"result": {"findings": findings}}, "tracker", {})
        _, body, _ = _gitlab_mr_summary(report, "result.json")
        self.assertEqual(len(report["kodaResult"]["findings"]), 51)
        self.assertIn("1건 생략", body)
        self.assertNotIn("\n/close", body)
        self.assertIn("a&#124;b /close", body)

    def test_tracker_result_is_committed_to_mr_and_confidential_issue(self):
        calls = []
        run = self.gitlab_run([])

        def write(path, query=None, *, settings_dir, method="GET", payload=None):
            calls.append((path, query, method, payload))
            if path.endswith("/repository/commits"):
                return {"web_url": "https://gitlab.example/group/demo/-/commit/1"}
            if path.endswith("/merge_requests") and method == "GET":
                return []
            if path.endswith("/merge_requests"):
                return {"web_url": "https://gitlab.example/group/demo/-/merge_requests/1"}
            if path.endswith("/issues") and method == "GET":
                return []
            if path.endswith("/issues"):
                return {"web_url": "https://gitlab.example/group/demo/-/issues/1"}
            self.fail(path)

        with patch("security_scanner.portal_integrations._gitlab_optional_json", side_effect=[None, None, None]), patch(
            "security_scanner.portal_integrations.find_gitlab_issue", return_value=None,
        ), patch(
            "security_scanner.portal_integrations._gitlab_write_json", side_effect=write,
        ):
            result = publish_tracker_result(
                {"gitlab_project_id": 42, "default_branch": "main"},
                run,
                "tracker-run-1", {"run": {"runUrl": "https://tracker.example/runs/tracker-run-1"}, "analysis": {"findings": [{
                    "canonicalId": "CVE-2026-1234", "severity": "high", "cvssScore": 8.1,
                    "component": "demo", "installedVersion": "1.0", "fixedIn": ["1.1"],
                }, {
                    "canonicalId": "CVE-2026-1234", "severity": "high", "cvssScore": 8.1,
                    "component": "demo", "installedVersion": "1.0", "fixedIn": ["1.2"],
                }, {
                    "canonicalId": "CVE-2026-1234", "severity": "low", "cvssScore": 3.0,
                    "component": "demo", "installedVersion": "1.0", "fixedIn": ["1.3"],
                }]}}, settings_dir=Path(self.tmp.name),
            )
        self.assertEqual(result["mergeRequestUrl"], "https://gitlab.example/group/demo/-/merge_requests/1")
        self.assertEqual(result["issueUrls"], ["https://gitlab.example/group/demo/-/issues/1"])
        commit_payload = next(payload for path, _, method, payload in calls if path.endswith("/repository/commits") and method == "POST")
        self.assertEqual((commit_payload["branch"], commit_payload["start_sha"]), (run["snapshot"]["gitlab_result_branch"], "a" * 40))
        self.assertEqual(commit_payload["actions"][0]["file_path"], f".koda/scan-results/{run['run_id']}.json")
        self.assertEqual(json.loads(commit_payload["actions"][0]["content"])["inspection"]["accountId"], self.admin)
        merge_payload = next(payload for path, _, method, payload in calls if path.endswith("/merge_requests") and method == "POST")
        self.assertFalse(merge_payload["remove_source_branch"])
        issue_payload = next(payload for path, _, method, payload in calls if path.endswith("/issues") and method == "POST")
        self.assertTrue(issue_payload["confidential"])
        self.assertIn("CVE-2026-1234", issue_payload["description"])
        self.assertIn("| demo | 1.0 | 1.1, 1.2 |", issue_payload["description"])
        self.assertEqual(issue_payload["description"].count("| CVE-2026-1234 |"), 2)
        self.assertIn("<!-- koda-sbom-tracker-run:tracker-run-1 -->", issue_payload["description"])
        self.assertIn("https://tracker.example/runs/tracker-run-1", issue_payload["description"])

    def test_merged_tracker_result_is_not_recommitted_when_target_file_matches(self):
        commit_sha = "b" * 40
        run = {"run_id": "koda-run-2", "snapshot": {
            "gitlab_project_id": 42, "gitlab_path_with_namespace": "group/demo",
            "gitlab_ref_type": "branch", "gitlab_ref_name": "main", "gitlab_commit_sha": commit_sha,
        }}
        tracker_result = {"analysis": {"findings": []}}
        report = _gitlab_scan_report(run, "tracker-run-2", tracker_result)
        encoded = base64.b64encode((json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()).decode()
        with patch("security_scanner.portal_integrations._gitlab_optional_json", side_effect=[None, {
            "encoding": "base64", "content": encoded,
        }]), patch("security_scanner.portal_integrations._gitlab_write_json", return_value=[{
            "web_url": "https://gitlab.example/group/demo/-/merge_requests/1",
        }]) as write:
            result = publish_tracker_result(
                {"gitlab_project_id": 42, "default_branch": "main"}, run,
                "tracker-run-2", tracker_result, settings_dir=Path(self.tmp.name),
            )
        self.assertEqual(result["mergeRequestUrl"], "https://gitlab.example/group/demo/-/merge_requests/1")
        self.assertFalse(any(call.args[0].endswith("/repository/commits") for call in write.call_args_list))

    def test_malformed_gitlab_result_file_is_rejected_before_commit(self):
        with patch("security_scanner.portal_integrations._gitlab_optional_json", return_value={
            "encoding": "base64", "content": "not-base64%%%",
        }), patch("security_scanner.portal_integrations._gitlab_write_json") as write, self.assertRaisesRegex(
            IntegrationError, "base64",
        ):
            publish_tracker_result(
                {"gitlab_project_id": 42, "default_branch": "main"},
                {"run_id": "koda-malformed", "snapshot": {
                    "gitlab_project_id": 42, "gitlab_commit_sha": "e" * 40,
                }},
                "tracker-malformed", {"analysis": {"findings": []}}, settings_dir=Path(self.tmp.name),
            )
        write.assert_not_called()

    def test_legacy_run_new_report_is_committed_even_when_tracker_analysis_matches(self):
        commit_sha = "c" * 40
        analysis = {"findings": [{"canonicalId": "CVE-2026-4321", "component": "demo", "version": "1.0"}]}
        previous = {
            "schemaVersion": 1,
            "source": {"commitSha": commit_sha},
            "kodaRunId": "old-koda-run", "trackerRunId": "old-tracker-run",
            "trackerResult": {"analysis": analysis},
        }
        encoded = base64.b64encode(json.dumps(previous).encode()).decode()
        calls = []

        def write(path, query=None, *, settings_dir, method="GET", payload=None):
            calls.append((path, method, payload))
            if path.endswith("/repository/commits"):
                return {"web_url": "https://gitlab.example/commit/new"}
            if path.endswith("/merge_requests"):
                return [{"web_url": "https://gitlab.example/group/demo/-/merge_requests/1"}]
            if path.endswith("/issues"):
                return [{
                    "iid": 9, "web_url": "https://gitlab.example/group/demo/-/issues/9",
                    "description": f"<!-- koda-sbom-tracker:{commit_sha} -->",
                }]
            self.fail(path)

        existing_issue = {
            "iid": 9, "web_url": "https://gitlab.example/group/demo/-/issues/9",
            "description": f"<!-- koda-sbom-tracker:{commit_sha} -->",
        }
        with patch("security_scanner.portal_integrations._gitlab_optional_json", return_value={
            "encoding": "base64", "content": encoded,
        }), patch("security_scanner.portal_integrations.find_gitlab_issue", return_value=existing_issue), patch(
            "security_scanner.portal_integrations._gitlab_write_json", side_effect=write,
        ), patch(
            "security_scanner.portal_integrations.find_gitlab_issue_note", return_value=None,
        ), patch("security_scanner.portal_integrations.add_gitlab_issue_note") as add_note:
            publish_tracker_result(
                {"gitlab_project_id": 42, "default_branch": "main"},
                {"run_id": "new-koda-run", "snapshot": {
                    "gitlab_project_id": 42, "gitlab_commit_sha": commit_sha,
                }},
                "new-tracker-run", {"analysis": analysis}, settings_dir=Path(self.tmp.name),
            )
        self.assertTrue(any(path.endswith("/repository/commits") for path, _, _ in calls))
        add_note.assert_called_once()
        self.assertIn("<!-- koda-sbom-tracker-run:new-tracker-run -->", add_note.call_args.args[2])

    def test_tracker_summary_issue_limits_rows_and_reports_omissions(self):
        findings = [{
            "canonicalId": f"CVE-2026-{10000 + index}", "severity": "medium",
            "component": f"component-{index}", "installedVersion": "1.0",
        } for index in range(201)]
        issue_payload = {}

        def write(path, query=None, *, settings_dir, method="GET", payload=None):
            if path.endswith("/repository/commits"):
                return {"web_url": "https://gitlab.example/commit/1"}
            if path.endswith("/merge_requests") and method == "GET":
                return [{"web_url": "https://gitlab.example/mr/1"}]
            if path.endswith("/issues") and method == "GET":
                return []
            if path.endswith("/issues"):
                issue_payload.update(payload)
                return {"web_url": "https://gitlab.example/issue/1"}
            self.fail(path)

        with patch("security_scanner.portal_integrations._gitlab_optional_json", side_effect=[None, None, None]), patch(
            "security_scanner.portal_integrations.find_gitlab_issue", return_value=None,
        ), patch(
            "security_scanner.portal_integrations._gitlab_write_json", side_effect=write,
        ):
            publish_tracker_result(
                {"gitlab_project_id": 42, "default_branch": "main"},
                {"run_id": "koda-limit", "snapshot": {"gitlab_project_id": 42, "gitlab_commit_sha": "d" * 40}},
                "tracker-limit", {"analysis": {"findings": findings}}, settings_dir=Path(self.tmp.name),
            )
        self.assertEqual(issue_payload["description"].count("| CVE-2026-"), 200)
        self.assertIn("전체 201건 · 생략 1건", issue_payload["description"])

    def test_round_snapshot_and_injection_rejection(self):
        run = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")
        snapshot = run["snapshot"]
        self.assertEqual(run["round_number"], 1)
        self.assertEqual(snapshot["input_hash"], hashlib.sha256(b"secret").hexdigest())
        with self.assertRaises(ValueError):
            self.store.create_scan(self.admin, self.project, self.input_id, "local", "all", disabled_rules=("secret.x",))
        self.store.set_rule_policy(self.project, ("secret.x",), expected_version=1)
        run2 = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")
        self.assertEqual(run2["round_number"], 2)
        self.assertEqual(run["snapshot"]["rule_policy_version"], 1)

    def test_delete_terminal_run_hides_result_and_preserves_rounds_and_audit(self):
        first = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")
        self.store.complete_run(first["run_id"], result={"findings": [{"id": "keep-me"}]})
        Path(self.tmp.name, "input.txt").write_text("secret", encoding="utf-8")
        second = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")
        self.store.complete_run(second["run_id"], result={"findings": [{"id": "keep-too"}]})
        Path(self.tmp.name, "input.txt").write_text("secret", encoding="utf-8")
        self.store.delete_run(first["run_id"], self.admin)
        with self.assertRaises(KeyError):
            self.store.run(first["run_id"])
        with self.store._db() as db:
            self.assertIsNone(db.execute("SELECT result_json FROM scan_runs WHERE run_id=?", (first["run_id"],)).fetchone()[0])
            self.assertIsNone(db.execute("SELECT result_json FROM analysis_revisions WHERE run_id=?", (first["run_id"],)).fetchone()[0])
        self.assertEqual([run["run_id"] for run in self.store.list_runs(self.project)], [second["run_id"]])
        self.assertIn("scan.deleted", {event["action"] for event in self.store.audit_events(None)})
        Path(self.tmp.name, "input.txt").write_text("secret", encoding="utf-8")
        third = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")
        self.assertEqual(third["round_number"], 3)
        self.store.complete_run(third["run_id"], result={"findings": []})
        self.store.delete_run(third["run_id"], self.admin)
        Path(self.tmp.name, "input.txt").write_text("secret", encoding="utf-8")
        fourth = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")
        self.assertEqual(fourth["round_number"], 4)
        with self.assertRaises(KeyError):
            self.store.complete_run(third["run_id"], result={"findings": []})

    def test_delete_run_rejects_active_delivery(self):
        run = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")
        self.store.complete_run(run["run_id"], result={"findings": []})
        with self.store._db() as db:
            now = self.store._now()
            db.execute("INSERT INTO tracker_deliveries(run_id,status,attempts,created_at,updated_at) VALUES(?,?,?,?,?)", (run["run_id"], "sending", 1, now, now))
        with self.assertRaisesRegex(ValueError, "결과 전송"):
            self.store.delete_run(run["run_id"], self.admin)

    def test_delete_run_rejects_queued_run(self):
        run = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")
        with self.assertRaisesRegex(ValueError, "실행 중인 점검"):
            self.store.delete_run(run["run_id"], self.admin)

    def test_scan_scope_is_immutable_and_validated(self):
        library = self.store.create_scan(self.admin, self.project, self.input_id, "ignored", "ignored", "library")
        self.assertEqual(library["snapshot"]["scan_scope"], "library")
        self.assertEqual((library["standard"], library["standard_category"]), ("local", "all"))
        source = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all", "source")
        self.assertEqual(source["snapshot"]["scan_scope"], "source")
        self.assertEqual(self.store.list_runs(self.project)[0]["scan_scope"], "source")
        with self.assertRaises(ValueError):
            self.store.create_scan(self.admin, self.project, self.input_id, "local", "all", "unknown")

    def test_last_admin_and_project_isolation(self):
        with self.assertRaises(ValueError):
            self.store.set_subject(self.admin, status="disabled")
        other = str(uuid.uuid4()); self.store.ensure_subject(other); self.store.set_subject(other, status="enabled")
        with self.assertRaises(ValueError):
            self.store.bootstrap(other)
        self.assertFalse(self.store.can(other, str(uuid.uuid4())))

    def test_role_policy_is_global_and_persists_after_restart(self):
        viewer = str(uuid.uuid4())
        self.store.ensure_subject(viewer, "viewer")
        self.store.set_subject(viewer, status="enabled", actor=self.admin)
        self.store.set_membership(self.project, viewer, "viewer", self.admin)
        self.assertTrue(self.store.can(viewer, self.project, "project.view"))
        self.assertFalse(self.store.can(viewer, self.project, "scan.create"))
        with self.assertRaises(ValueError):
            self.store.set_role_policy({"viewer": ["system.admin"]}, 1, self.admin)
        second = self.store.create_project("second")
        self.store.set_membership(second, viewer, "viewer", self.admin)
        policy = self.store.role_policy()
        self.store.set_role_policy({"viewer": ["dashboard.view"]}, policy["version"], self.admin)
        self.assertTrue(self.store.can(viewer, self.project, "dashboard.view"))
        self.assertTrue(self.store.can(viewer, second, "dashboard.view"))
        self.assertFalse(self.store.can(viewer, second, "runs.view"))
        reopened = PortalStore(Path(self.tmp.name) / "portal.sqlite3")
        self.assertEqual(reopened.list_inputs(self.project)[0]["input_id"], self.input_id)
        self.assertEqual(reopened.role_policy()["version"], 2)

    def test_legacy_project_view_migrates_once_to_screen_permissions(self):
        encoded = self.store._json({"legacy": ["project.view"]})
        with self.store._db() as db:
            db.execute("DELETE FROM role_policies WHERE project_id=?", (GLOBAL_ROLE_POLICY_ID,))
            db.execute(
                "INSERT INTO role_policies VALUES(?,?,?,?,?)",
                (self.project, 2, encoded, hashlib.sha256(encoded.encode()).hexdigest(), self.store._now()),
            )
        reopened = PortalStore(Path(self.tmp.name) / "portal.sqlite3")
        policy = reopened.role_policy()
        self.assertEqual(policy["version"], 1)
        self.assertEqual(set(policy["roles"]["legacy"]), set(SCREEN_PERMISSIONS))
        self.assertNotIn("project.view", policy["roles"]["legacy"])
        self.assertIn("role_policy.migrated", {event["action"] for event in reopened.audit_events(None)})
        self.assertEqual(PortalStore(Path(self.tmp.name) / "portal.sqlite3").role_policy()["version"], 1)

    def test_user_visible_time_is_seoul_without_changing_utc_storage(self):
        self.assertEqual(format_portal_time("2026-01-01T00:00:00+00:00"), "2026-01-01 09:00:00")
        self.assertRegex(self.store._now(), r"[+]00:00$")

    def test_cve_only_scan_drops_non_cve_dependency_results(self):
        target = Path(self.tmp.name) / "requirements.txt"
        target.write_text("demo==1.0\n", encoding="utf-8")
        cve = GrypeMatch(
            "GHSA-with-cve", ("CVE-2026-1234",), "demo", "1.0", "pkg:pypi/demo@1.0",
            ("1.1",), "high", ("requirements.txt",), (), ("GHSA-with-cve",),
        )
        ghsa = GrypeMatch(
            "GHSA-only", (), "demo", "1.0", "pkg:pypi/demo@1.0",
            (), "high", ("requirements.txt",), (), ("GHSA-only",),
        )
        grype = GrypeResult((cve, ghsa), "test", {"built": "2026-08-28"}, "", False)
        with patch("security_scanner.server.inspect_grype", return_value={"available": True}), patch(
            "security_scanner.server.run_grype_purls", return_value=grype
        ):
            payload = scan_directory_payload(
                str(target), allow_file=True, standard="local", standard_category="all",
                scan_scope="library", enable_local_vulnerabilities=True, cve_only=True,
            )
        encoded = json.dumps(payload, ensure_ascii=False)
        self.assertEqual(payload["scan"]["local_vulnerability"]["matched_vulnerabilities"], 1)
        self.assertIn("CVE-2026-1234", encoded)
        self.assertIn("dependency.osv-known-vulnerability|pkg:pypi/demo@1.0|CVE-2026-1234", encoded)
        self.assertNotIn("GHSA-only", encoded)

    def test_run_progress_cancel_and_recovery(self):
        run = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")
        self.assertTrue(self.store.mark_run_running(run["run_id"]))
        self.assertTrue(self.store.set_run_progress(run["run_id"], "scanning", 35))
        cancelling = self.store.request_cancel(run["run_id"], self.admin)
        self.assertEqual(cancelling["status"], "cancelling")
        self.store.complete_run(run["run_id"], result={"findings": []})
        cancelled = self.store.run(run["run_id"])
        self.assertEqual((cancelled["status"], cancelled["stage"], cancelled["result"]), ("cancelled", "cancelled", None))
        self.assertFalse(Path(self.store.input(self.input_id)["path"]).exists())
        with self.assertRaises(ValueError):
            self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")

    def test_recovery_removes_terminal_input_left_by_previous_process(self):
        run = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")
        self.store.complete_run(run["run_id"], result={"findings": []})
        path = Path(self.store.input(self.input_id)["path"])
        path.write_text("stale copy", encoding="utf-8")
        reopened = PortalStore(Path(self.tmp.name) / "portal.sqlite3")
        self.assertEqual(reopened.recover_incomplete_runs(), [])
        self.assertFalse(path.exists())

    def test_gitlab_mapping_snapshot_and_tracker_state_persist(self):
        mapping = self.store.set_gitlab_repositories(self.project, [{
            "gitlab_project_id": 42, "path_with_namespace": "group/demo", "name": "demo",
            "default_branch": "main", "tracker_service_id": "service-1",
            "tracker_environment_id": "environment-1", "tracker_token_ref": "demo.token",
        }], self.admin)[0]
        run = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all", "source", source_snapshot={
            "gitlab_mapping_id": mapping["mapping_id"], "gitlab_project_id": 42,
            "gitlab_path_with_namespace": "group/demo", "gitlab_ref_type": "branch",
            "gitlab_ref_name": "main", "gitlab_commit_sha": "a" * 40,
            "gitlab_archive_sha256": "b" * 64, "gitlab_fetched_at": self.store._now(),
            "gitlab_default_branch": "main",
            "tracker_service_id": "service-1", "tracker_environment_id": "environment-1",
            "tracker_token_ref": "demo.token",
        })
        self.assertEqual(run["snapshot"]["gitlab_commit_sha"], "a" * 40)
        self.store.mark_run_running(run["run_id"])
        self.store.complete_run(run["run_id"], result={"findings": [], "sbom": {"components": []}})
        self.assertEqual(self.store.claim_tracker_delivery(run["run_id"])["attempts"], 1)
        self.store.finish_tracker_delivery(run["run_id"], "failed", error="offline")
        self.store.remove_gitlab_repository(mapping["mapping_id"], self.admin)
        self.assertEqual(self.store.gitlab_repositories(self.project), [])
        self.assertEqual(self.store.gitlab_repository(mapping["mapping_id"], include_disabled=True)["enabled"], 0)
        self.store.claim_tracker_delivery(run["run_id"], retry=True)
        reopened = PortalStore(Path(self.tmp.name) / "portal.sqlite3")
        self.assertEqual(reopened.recover_tracker_deliveries(), [run["run_id"]])
        self.assertEqual(reopened.tracker_delivery(run["run_id"])["status"], "pending")

    def test_legacy_combined_failure_migrates_to_gitlab_result_and_keeps_tracker_run(self):
        run = self.gitlab_run([])
        self.store.claim_tracker_delivery(run["run_id"])
        self.store.finish_tracker_delivery(
            run["run_id"], "failed", tracker_run_id="tracker-run-legacy", error="GitLab unavailable",
        )
        self.store.claim_tracker_delivery(run["run_id"], retry=True)
        failed_again = self.store.finish_tracker_delivery(run["run_id"], "failed", error="still unavailable")
        self.assertEqual(failed_again["tracker_run_id"], "tracker-run-legacy")

        migrated = PortalStore(Path(self.tmp.name) / "portal.sqlite3").tracker_delivery(run["run_id"])
        self.assertEqual(migrated["status"], "completed")
        self.assertEqual(migrated["gitlab_result_status"], "failed")
        self.assertEqual(migrated["gitlab_result_last_error"], "still unavailable")
        self.assertIsNone(migrated["last_error"])

    def test_completed_gitlab_run_delivers_sbom_to_tracker(self):
        mapping = self.store.set_gitlab_repositories(self.project, [{
            "gitlab_project_id": 42, "path_with_namespace": "group/demo", "name": "demo",
            "default_branch": "main", "tracker_service_id": "service-1",
            "tracker_environment_id": "environment-1", "tracker_token_ref": "demo.token",
        }], self.admin)[0]
        run = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all", "all", source_snapshot={
            "gitlab_mapping_id": mapping["mapping_id"], "gitlab_project_id": 42,
            "gitlab_path_with_namespace": "group/demo", "gitlab_ref_type": "branch",
            "gitlab_ref_name": "main", "gitlab_commit_sha": "a" * 40,
            "gitlab_archive_sha256": "b" * 64, "gitlab_fetched_at": self.store._now(),
            "gitlab_default_branch": "main",
            "tracker_service_id": "service-1", "tracker_environment_id": "environment-1",
            "tracker_token_ref": "demo.token",
        })
        self.store.mark_run_running(run["run_id"])
        self.store.complete_run(run["run_id"], result={"findings": [], "sbom": {"components": [{"name": "demo"}]}})
        self.store.set_gitlab_repositories(self.project, [{
            "gitlab_project_id": 42, "path_with_namespace": "group/demo", "name": "demo",
            "default_branch": "main", "tracker_service_id": "service-2",
            "tracker_environment_id": "environment-2", "tracker_token_ref": "changed.token",
        }], self.admin)
        with patch("security_scanner.linux_portal.send_tracker_sbom", return_value="tracker-run-1") as send, patch(
            "security_scanner.linux_portal.fetch_tracker_result", return_value={"analysis": {"findings": []}},
        ), patch("security_scanner.linux_portal.publish_tracker_result", return_value={
            "mergeRequestUrl": "https://gitlab.example/group/demo/-/merge_requests/1",
            "issueUrls": ["https://gitlab.example/group/demo/-/issues/1"],
        }):
            delivery = _deliver_tracker(self.store, run["run_id"])
        self.assertEqual((delivery["status"], delivery["tracker_run_id"], delivery["attempts"]), ("completed", "tracker-run-1", 1))
        send.assert_called_once()
        self.assertEqual(send.call_args.args[0]["tracker_service_id"], "service-1")
        self.assertEqual(delivery["gitlab_merge_request_url"], "https://gitlab.example/group/demo/-/merge_requests/1")
        self.assertEqual(delivery["gitlab_issue_urls"], ["https://gitlab.example/group/demo/-/issues/1"])
        with self.assertRaises(ValueError):
            _deliver_tracker(self.store, run["run_id"], retry=True)


class LinuxPortalHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.admin = str(uuid.uuid4())
        self.server = create_portal_server(
            "127.0.0.1", 0, db_path=Path(self.tmp.name) / "portal.sqlite3",
            input_dir=Path(self.tmp.name) / "inputs",
        )
        self.server.portal_store.bootstrap(self.admin)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def test_schedule_resource_settings_require_admin_and_persist(self):
        endpoint = "/koda/api/v1/admin/schedule-settings"
        status, initial = self.request(endpoint, headers=self.headers())
        self.assertEqual(status, 200)
        self.assertFalse(initial["enabled"])
        status, saved = self.request(endpoint, method="POST", headers=self.headers(), payload={"enabled": True, "rate_bytes_per_sec": 1048576})
        self.assertEqual(status, 200)
        self.assertEqual(saved["rate_bytes_per_sec"], 1048576)
        self.assertEqual(self.request(endpoint, headers=self.headers())[1]["version"], saved["version"])
        outsider = str(uuid.uuid4())
        store = self.server.portal_store
        store.ensure_subject(outsider, "viewer")
        store.set_subject(outsider, status="enabled", system_admin=False, actor=self.admin)
        self.assertEqual(self.request(endpoint, headers=self.headers(outsider))[0], 403)
        self.assertEqual(self.request(endpoint, method="POST", headers=self.headers(outsider), payload={"enabled": False})[0], 403)
        self.assertEqual(self.request(endpoint, method="POST", headers=self.headers(), payload={"cpu_limit": 0})[0], 422)

    def headers(self, subject=None, display="admin"):
        return {
            "X-KODA-Identity-ID": subject or self.admin,
            "X-KODA-Identity-Expires": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).isoformat(),
            "X-KODA-Identity-Display": base64.urlsafe_b64encode(display.encode()).rstrip(b"=").decode(),
        }

    def request(self, path, *, method="GET", payload=None, headers=None):
        body = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(self.base + path, data=body, method=method, headers=headers or {})
        if payload is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                raw = response.read()
                return response.status, json.loads(raw) if response.headers.get_content_type() == "application/json" else (raw if response.headers.get_content_type() == "image/x-icon" else raw.decode())
        except urllib.error.HTTPError as exc:
            try:
                raw = exc.read()
                return exc.code, json.loads(raw) if exc.headers.get_content_type() == "application/json" else raw.decode()
            finally:
                exc.close()

    def test_login_registration_and_admin_pages(self):
        status, body = self.request("/koda/login?next=https://evil.example")
        self.assertEqual(status, 200)
        self.assertIn("LDAP 계정", body)
        self.assertIn("<link rel='icon' href='/koda/assets/KODA.ico'>", body)
        self.assertIn("/koda/assets/KODA.ico", body)
        self.assertNotIn("Tracker", body)
        self.assertIn('location="/koda/"', body)
        status, body = self.request("/koda/login?next=/koda/%3C/script%3Ealert(1)%3C/script%3E")
        self.assertEqual(status, 200)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn('location="/koda/"', body)
        self.assertIn("회원가입", body)
        self.assertIn("/api/v1/auth/register", body)
        approved_tracker_user = str(uuid.uuid4())
        status, me = self.request("/koda/api/v1/me", headers=self.headers(approved_tracker_user, "approved"))
        self.assertEqual((status, me["status"]), (200, "enabled"))
        self.assertEqual(self.request("/koda/api/v1/projects", headers=self.headers(approved_tracker_user)), (403, {"code": "forbidden"}))
        status, admin_page = self.request("/koda/admin/subjects", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("<link rel='icon' href='/koda/assets/KODA.ico'>", admin_page)
        self.assertIn("/koda/assets/KODA.ico", admin_page)
        self.assertNotIn("Tracker", admin_page.split("</nav>", 1)[0])
        self.assertNotIn("회원가입과 계정 승인은 KODA-SBOM-Tracker", admin_page)
        self.assertIn("KODA 관리자", admin_page)
        self.assertIn("삭제</button>", admin_page)
        self.assertIn("id='subject-admin-filter'", admin_page)
        self.assertIn("id='subject-role-filter'", admin_page)
        self.assertIn("data-roles=", admin_page)
        self.assertIn("프로젝트 역할", admin_page)
        self.assertIn("<h2>계정 현황</h2>", admin_page)
        self.assertIn("<h2>취약점 DB</h2>", self.request("/koda/admin/vulnerability-db", headers=self.headers())[1])
        self.assertNotIn("name='status'", admin_page)
        self.assertIn("<button>저장</button>", admin_page)
        self.assertIn("class='topbar'", admin_page)
        self.assertIn("id='account-toggle'", admin_page)
        self.assertIn("id='account-panel'", admin_page)
        self.assertIn("id='account-logout'", admin_page)
        self.assertIn("json('/koda/api/v1/me')", admin_page)
        self.assertNotIn("class='side-bottom'", admin_page)
        self.assertNotIn("id='logout'", admin_page)
        self.assertNotIn("<option>pending</option>", admin_page)
        self.assertIn("syncSubject()", admin_page)

    def test_tracker_identity_preserves_legacy_disabled_subject(self):
        subject = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(subject, "legacy")
        self.server.portal_store.set_subject(subject, status="disabled", actor=self.admin)
        status, me = self.request("/koda/api/v1/me", headers=self.headers(subject, "legacy"))
        self.assertEqual((status, me["status"]), (200, "disabled"))

    def test_delete_koda_registration_keeps_history_and_allows_tracker_reentry(self):
        subject = str(uuid.uuid4())
        project = self.server.portal_store.create_project("registration delete", self.admin)
        self.server.portal_store.ensure_subject(subject, "registered")
        self.server.portal_store.set_subject(subject, status="enabled", actor=self.admin)
        self.server.portal_store.set_membership(project, subject, "viewer", self.admin)
        status, result = self.request(
            f"/koda/api/v1/admin/subjects/{subject}", method="DELETE", headers=self.headers(),
        )
        self.assertEqual((status, result), (200, {"ok": True}))
        self.assertIsNone(self.server.portal_store.subject(subject))
        self.assertNotIn(subject, {membership["subject_id"] for membership in self.server.portal_store.list_memberships(project)})
        self.assertIn("subject.registration_deleted", {event["action"] for event in self.server.portal_store.audit_events(None)})
        status, me = self.request("/koda/api/v1/me", headers=self.headers(subject, "registered"))
        self.assertEqual((status, me["status"]), (200, "enabled"))
        self.assertEqual(self.server.portal_store.list_memberships(subject), [])

    def test_delete_registration_rejects_self_and_last_admin(self):
        status, body = self.request(
            f"/koda/api/v1/admin/subjects/{self.admin}", method="DELETE", headers=self.headers(),
        )
        self.assertEqual((status, body["code"]), (422, "invalid_request"))

    def test_delete_registration_rejects_tombstoned_subject(self):
        subject = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(subject, "revoked")
        self.server.portal_store.set_subject(subject, status="tombstoned", actor=self.admin)
        status, body = self.request(
            f"/koda/api/v1/admin/subjects/{subject}", method="DELETE", headers=self.headers(),
        )
        self.assertEqual((status, body["code"]), (422, "invalid_request"))

    def test_run_deletion_is_system_admin_only(self):
        project = self.server.portal_store.create_project("run deletion", self.admin)
        target = Path(self.tmp.name) / "run-delete.txt"
        target.write_text("input", encoding="utf-8")
        input_id = self.server.portal_store.add_input(project, target.name, target, self.admin)
        run = self.server.portal_store.create_scan(self.admin, project, input_id, "local", "all")
        self.server.portal_store.complete_run(run["run_id"], result={"findings": []})
        viewer = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(viewer, "viewer")
        self.server.portal_store.set_subject(viewer, status="enabled", actor=self.admin)
        self.server.portal_store.set_membership(project, viewer, "viewer", self.admin)
        status, body = self.request(f"/koda/api/v1/runs/{run['run_id']}", method="DELETE", headers=self.headers(viewer, "viewer"))
        self.assertEqual((status, body["code"]), (403, "forbidden"))
        status, body = self.request(f"/koda/api/v1/runs/{run['run_id']}", method="DELETE", headers=self.headers())
        self.assertEqual((status, body), (200, {"ok": True}))
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run['run_id']}", headers=self.headers())[0], 404)
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run['run_id']}/report?format=json", headers=self.headers())[0], 404)
        self.assertEqual(self.request(f"/koda/api/v1/compare?left={run['run_id']}&right={run['run_id']}", headers=self.headers())[0], 404)
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run['run_id']}/retry", method="POST", payload={}, headers=self.headers())[0], 404)

    def test_admin_controls_project_access_per_user(self):
        project = self.server.portal_store.create_project("project access", self.admin)
        viewer = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(viewer, "viewer")
        self.server.portal_store.set_subject(viewer, status="enabled", actor=self.admin)
        status, page = self.request("/koda/admin/subjects", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("사용자별 프로젝트 접근", page)
        self.assertIn("class='check-label'", page)
        self.assertIn("접근 해제", page)
        self.assertIn("project access", page)

        payload = {"project_id": project, "subject_id": viewer, "role": "viewer"}
        self.assertEqual(self.request("/koda/api/v1/admin/memberships", method="POST", payload=payload, headers=self.headers()), (200, {"ok": True}))
        self.assertTrue(self.server.portal_store.can(viewer, project, "runs.view"))
        status, page = self.request("/koda/admin/subjects", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn(viewer, page)
        payload["role"] = ""
        self.assertEqual(self.request("/koda/api/v1/admin/memberships", method="POST", payload=payload, headers=self.headers()), (200, {"ok": True}))
        self.assertFalse(self.server.portal_store.can(viewer, project, "runs.view"))
        self.assertIn("membership.removed", {event["action"] for event in self.server.portal_store.audit_events(None)})

    def test_user_guide_is_available_without_project_permissions(self):
        viewer = str(uuid.uuid4())
        status, guide = self.request("/koda/guide", headers=self.headers(viewer, "일반 사용자"))
        self.assertEqual(status, 200)
        self.assertIn("KODA 사용 가이드", guide)
        self.assertIn("data-nav='guide'", guide)
        self.assertIn("라이브러리 취약점 점검", guide)
        self.assertIn("CVE", guide)
        self.assertIn("CVSS", guide)
        self.assertIn("CWE", guide)
        self.assertIn("OWASP Top 10:2025", guide)
        self.assertIn("소프트웨어 개발보안 49", guide)
        self.assertIn("현재 KODA 카탈로그에 등록된 27개 기준", guide)
        self.assertNotIn("<strong>전체</strong><code>local</code>", guide)
        self.assertNotIn("관리자 설정</h3>", guide)
        self.assertNotIn("사용 가이드 목차", guide)
        self.assertNotIn("권한에 따라 보이는 실행 메뉴", guide)

    def test_empty_project_pages_explain_onboarding(self):
        status, body = self.request("/koda/scans/new", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("프로젝트 생성으로 이동", body)
        status, body = self.request("/koda/projects", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("프로젝트를 생성하면", body)
        viewer = str(uuid.uuid4())
        viewer_headers = self.headers(viewer, "승인된 사용자")
        status, body = self.request("/koda/scans/new", headers=viewer_headers)
        self.assertEqual(status, 403)
        self.assertIn("이 화면에 접근할 권한이 없습니다", body)
        status, body = self.request("/koda/projects", headers=viewer_headers)
        self.assertEqual(status, 403)
        self.assertIn("이 화면에 접근할 권한이 없습니다", body)

    def test_gitlab_catalog_mapping_ref_and_scan_snapshot(self):
        project = self.server.portal_store.create_project("GitLab project", self.admin)
        remote = {"id": 42, "name": "demo", "path_with_namespace": "group/demo", "default_branch": "main"}
        with patch("security_scanner.linux_portal.gitlab_status", return_value={"username": "scanner", "name": "Scanner"}), patch(
            "security_scanner.linux_portal.list_gitlab_projects", return_value=[remote]
        ), patch("security_scanner.linux_portal.gitlab_configuration", return_value={
            "configured": True, "write_configured": True, "locked": False, "source": "web",
            "url": "https://gitlab.example.internal", "ca_configured": False,
        }), patch("security_scanner.linux_portal.provision_tracker_repository", return_value={
            "tracker_service_id": "service-1", "tracker_environment_id": "environment-1",
            "tracker_token_ref": "gitlab-42.token",
        }):
            status, page = self.request("/koda/admin/gitlab", headers=self.headers())
            self.assertEqual(status, 200)
            self.assertIn("GitLab 서비스 계정", page)
            self.assertIn("GitLab 연결 설정", page)
            self.assertIn("저장소 조회 PAT", page)
            self.assertIn("결과 저장 PAT", page)
            self.assertIn("연결 시 자동 생성·재사용", page)
            self.assertNotIn("data-service=", page)
            self.assertEqual(self.request("/koda/api/v1/admin/gitlab/status", headers=self.headers())[0], 200)
            status, mappings = self.request("/koda/api/v1/admin/gitlab/mappings", method="POST", headers=self.headers(), payload={
                "project_id": project, "mappings": [{"gitlab_project_id": 42}],
            })
        self.assertEqual(status, 200)
        mapping_id = mappings[0]["mapping_id"]
        status, scan_page = self.request("/koda/scans/library", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("input-source-switch", scan_page)
        self.assertIn("gitlab-repository-row", scan_page)
        self.assertIn("gitlab-ref-row", scan_page)
        status, visible = self.request(f"/koda/api/v1/projects/{project}/gitlab/repositories", headers=self.headers())
        self.assertEqual((status, visible[0]["path_with_namespace"]), (200, "group/demo"))
        self.assertNotIn("tracker_token_ref", visible[0])
        viewer, outsider = str(uuid.uuid4()), str(uuid.uuid4())
        self.server.portal_store.ensure_subject(viewer, "viewer")
        self.server.portal_store.ensure_subject(outsider, "outsider")
        self.server.portal_store.set_subject(viewer, status="enabled", system_admin=False, display="viewer", actor=self.admin)
        self.server.portal_store.set_subject(outsider, status="enabled", system_admin=False, display="outsider", actor=self.admin)
        self.server.portal_store.set_membership(project, viewer, "analyst", self.admin)
        self.assertEqual(self.request(
            f"/koda/api/v1/projects/{project}/gitlab/repositories", headers=self.headers(viewer)
        )[0], 200)
        self.assertEqual(self.request(
            f"/koda/api/v1/projects/{project}/gitlab/repositories", headers=self.headers(outsider)
        )[0], 404)
        self.assertEqual(self.request("/koda/api/v1/admin/gitlab/status", headers=self.headers(viewer))[0], 403)
        with patch("security_scanner.linux_portal.list_gitlab_refs", return_value=[{"name": "main", "commit_sha": "a" * 40}]):
            status, refs = self.request(f"/koda/api/v1/projects/{project}/gitlab/repositories/{mapping_id}/refs?type=branch", headers=self.headers())
        self.assertEqual((status, refs[0]["name"]), (200, "main"))

        def fake_download(_project_id, _sha, target, *, max_bytes, settings_dir=None):
            self.assertEqual(max_bytes, MAX_INPUT_BYTES)
            self.assertEqual(settings_dir, Path(self.tmp.name) / "integrations")
            with tarfile.open(target, "w:gz") as archive:
                body = b"# valid fixture\n"
                info = tarfile.TarInfo("demo-main-aaaaaaaa/src/app.py")
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
            return "b" * 64, target.stat().st_size

        with patch("security_scanner.linux_portal.resolve_gitlab_ref", return_value="a" * 40), patch(
            "security_scanner.linux_portal.download_gitlab_archive", side_effect=fake_download
        ), patch.object(self.server.portal_worker, "enqueue"):
            status, run = self.request("/koda/api/v1/scans", method="POST", headers=self.headers(), payload={
                "project_id": project, "gitlab_repository_id": mapping_id,
                "ref_type": "branch", "ref_name": "main", "standard": "local",
                "standard_category": "all", "scan_scope": "source",
            })
        self.assertEqual(status, 202)
        saved = self.server.portal_store.run(run["run_id"])
        self.assertEqual(saved["snapshot"]["gitlab_commit_sha"], "a" * 40)
        self.assertEqual(saved["snapshot"]["gitlab_path_with_namespace"], "group/demo")
        self.assertEqual(saved["snapshot"]["tracker_service_id"], "service-1")
        before = set((Path(self.tmp.name) / "inputs").glob("*.tar.gz"))
        with patch("security_scanner.linux_portal.resolve_gitlab_ref", return_value="a" * 40), patch(
            "security_scanner.linux_portal.download_gitlab_archive", side_effect=fake_download
        ), patch.object(self.server.portal_store, "add_input", side_effect=ValueError("database rejected input")):
            status, _ = self.request("/koda/api/v1/scans", method="POST", headers=self.headers(), payload={
                "project_id": project, "gitlab_repository_id": mapping_id,
                "ref_type": "branch", "ref_name": "main", "standard": "local",
                "standard_category": "all", "scan_scope": "source",
            })
        self.assertEqual(status, 422)
        self.assertEqual(set((Path(self.tmp.name) / "inputs").glob("*.tar.gz")), before)

    def test_gitlab_configuration_api_never_returns_or_audits_token(self):
        payload = {"url": "https://gitlab.example.internal", "token": "glpat-web-secret", "write_token": "glpat-write-secret", "ca_pem": ""}
        account = {"id": 7, "username": "scanner", "name": "Scanner", "state": "active"}
        with patch.dict(os.environ, {"KODA_GITLAB_URL": "", "KODA_GITLAB_TOKEN_FILE": "", "KODA_GITLAB_WRITE_TOKEN_FILE": "", "KODA_GITLAB_CA_FILE": ""}), patch(
            "security_scanner.linux_portal.test_gitlab_configuration", return_value=account,
        ), patch(
            "security_scanner.linux_portal.test_gitlab_write_configuration", return_value=account,
        ):
            status, tested = self.request(
                "/koda/api/v1/admin/gitlab/configuration/test", method="POST",
                headers=self.headers(), payload={key: value for key, value in payload.items() if key != "write_token"},
            )
            self.assertEqual((status, tested["account"]["username"]), (200, "scanner"))
            status, saved = self.request(
                "/koda/api/v1/admin/gitlab/configuration", method="POST",
                headers=self.headers(), payload=payload,
            )
            self.assertEqual((status, saved["configured"], saved["write_configured"], saved["locked"]), (200, True, True, False))
            self.assertNotIn("token", saved)
            status, page = self.request("/koda/admin/gitlab", headers=self.headers())
            self.assertEqual(status, 200)
            self.assertIn("https://gitlab.example.internal", page)
            self.assertNotIn("glpat-web-secret", page)
            self.assertIn("비워 두면 기존 PAT 유지", page)
            status, preserved = self.request(
                "/koda/api/v1/admin/gitlab/configuration", method="POST", headers=self.headers(),
                payload={"url": payload["url"], "token": "", "write_token": "", "ca_pem": ""},
            )
            self.assertEqual((status, preserved["configured"], preserved["write_configured"]), (200, True, True))
            integration_dir = Path(self.tmp.name) / "integrations"
            self.assertEqual((integration_dir / "gitlab.token").read_text(), "glpat-web-secret\n")
            self.assertEqual((integration_dir / "gitlab-write.token").read_text(), "glpat-write-secret\n")
            events = self.server.portal_store.audit_events(None)
            encoded = json.dumps(events, ensure_ascii=False)
            self.assertIn("gitlab.configuration.updated", encoded)
            self.assertNotIn("glpat-web-secret", encoded)
            self.assertNotIn("glpat-write-secret", encoded)
            status, removed = self.request(
                "/koda/api/v1/admin/gitlab/configuration", method="DELETE", headers=self.headers(),
            )
            self.assertEqual((status, removed), (200, {"ok": True}))
            self.assertFalse((Path(self.tmp.name) / "integrations" / "gitlab.token").exists())
            self.assertFalse((Path(self.tmp.name) / "integrations" / "gitlab-write.token").exists())
        viewer = str(uuid.uuid4())
        self.assertEqual(self.request(
            "/koda/api/v1/admin/gitlab/configuration", headers=self.headers(viewer),
        )[0], 403)

    def test_schedule_connection_and_access_probes_are_admin_only(self):
        payload = {
            "host": "server.internal", "port": 22, "username": "koda-readonly",
            "ssh_key_ref": "/run/koda/ssh/id_ed25519",
            "known_hosts_file": "/run/koda/ssh/known_hosts",
            "remote_directory": "/srv/application", "exclude_paths": [],
            "max_files": 10, "max_bytes": 1000, "timeout_seconds": 30,
        }
        with patch("security_scanner.schedule_worker.OpenSSHCollector") as collector_type:
            collector = collector_type.return_value
            collector.list_files.return_value = [RemoteFile("app.py", 7, 1700000000.0)]
            status, connected = self.request(
                "/koda/api/v1/admin/schedules/test-connection", method="POST",
                headers=self.headers(), payload=payload,
            )
            self.assertEqual((status, connected), (200, {"ok": True}))
            collector.test_connection.assert_called_once()
            status, access = self.request(
                "/koda/api/v1/admin/schedules/test-access", method="POST",
                headers=self.headers(), payload=payload,
            )
            self.assertEqual((status, access), (200, {"ok": True, "fileCount": 1, "totalBytes": 7}))
            collector.list_files.assert_called_once()
        viewer = str(uuid.uuid4())
        self.assertEqual(self.request(
            "/koda/api/v1/admin/schedules/test-connection", method="POST",
            headers=self.headers(viewer), payload=payload,
        )[0], 403)

    def test_gitlab_issue_status_api_hides_project_and_retry_is_admin_only(self):
        store = self.server.portal_store
        project = store.create_project("Issue API", self.admin)
        store.set_membership(project, self.admin, "admin", self.admin)
        mapping = store.set_gitlab_repositories(project, [{
            "gitlab_project_id": 77, "path_with_namespace": "group/issues", "name": "issues",
            "default_branch": "main", "tracker_service_id": "service-77",
            "tracker_environment_id": "environment-77", "tracker_token_ref": "issues.token",
        }], self.admin)[0]
        target = Path(self.tmp.name) / "issue-api.tar.gz"
        target.write_bytes(b"archive")
        input_id = store.add_input(project, target.name, target)
        run = store.create_scan(self.admin, project, input_id, "local", "all", "source", source_snapshot={
            "gitlab_mapping_id": mapping["mapping_id"], "gitlab_project_id": 77,
            "gitlab_path_with_namespace": "group/issues", "gitlab_ref_type": "branch", "gitlab_ref_name": "main",
            "gitlab_commit_sha": "c" * 40, "gitlab_archive_sha256": "d" * 64,
            "gitlab_fetched_at": store._now(), "gitlab_default_branch": "main",
            "tracker_service_id": "service-77", "tracker_environment_id": "environment-77", "tracker_token_ref": "issues.token",
        })
        store.complete_run(run["run_id"], result={"findings": [{
            "rule_id": "code.api", "category": "code", "severity": "high", "title": "API finding",
            "path": "api.py", "line": 1, "verification_status": "confirmed", "issue_key": "api-finding",
        }, {
            "rule_id": "dependency.cve", "category": "dependencies", "severity": "medium",
            "title": "Library finding", "path": "requirements.txt", "verification_status": "confirmed",
        }]})
        store.claim_tracker_delivery(run["run_id"])
        store.finish_tracker_delivery(
            run["run_id"], "completed", tracker_run_id="tracker-ui-1",
            tracker_run_url="https://tracker.example/?page=runs&runId=tracker-ui-1",
        )
        store.claim_gitlab_result(run["run_id"])
        store.finish_gitlab_result(
            run["run_id"], "failed", error="GitLab unavailable",
            issue_urls=["https://gitlab.example/group/issues/-/issues/10"],
        )
        store.claim_gitlab_issue_delivery(run["run_id"])
        store.prepare_gitlab_issue_items(run["run_id"], 77, [{"finding_index": 0, "finding_key": "api-finding"}])
        store.finish_gitlab_issue_item(run["run_id"], "api-finding", "failed", error="offline")
        store.finish_gitlab_issue_delivery(run["run_id"])

        viewer, outsider = str(uuid.uuid4()), str(uuid.uuid4())
        for subject in (viewer, outsider):
            store.ensure_subject(subject, subject)
            store.set_subject(subject, status="enabled", system_admin=False, display=subject, actor=self.admin)
        store.set_membership(project, viewer, "viewer", self.admin)
        endpoint = f"/koda/api/v1/runs/{run['run_id']}/gitlab/issues"
        self.assertEqual(self.request(endpoint, headers=self.headers(outsider))[0], 404)
        status, payload = self.request(endpoint, headers=self.headers(viewer))
        self.assertEqual((status, payload["status"], payload["items"][0]["status"]), (200, "failed", "failed"))
        self.assertEqual(self.request(endpoint + "/retry", method="POST", headers=self.headers(viewer), payload={})[0], 403)
        with patch("security_scanner.linux_portal._deliver_gitlab_issues", return_value={"status": "completed"}) as retry:
            self.assertEqual(self.request(endpoint + "/retry", method="POST", headers=self.headers(), payload={})[0], 200)
        retry.assert_called_once_with(store, run["run_id"], retry=True)
        status, page = self.request(f"/koda/runs/{run['run_id']}", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("GitLab 취약점 이슈 등록", page)
        self.assertIn("GitLab 이슈", page)
        self.assertIn("실패 항목 재시도", page)
        self.assertIn("KODA-SBOM-Tracker 전송", page)
        self.assertIn("Tracker 실행 화면", page)
        self.assertIn("GitLab 결과 등록 재시도", page)
        self.assertIn("요약 이슈에 포함", page)
        self.assertIn("https://gitlab.example/group/issues/-/issues/10", page)
        self.assertIn("json(`/koda/api/v1/runs/${runId}/gitlab/result/retry`", page)

    def test_scope_menus_render_independent_scan_pages(self):
        project = self.server.portal_store.create_project("scope pages", self.admin)
        target = Path(self.tmp.name) / "scope.py"
        target.write_text("print('scope')\n", encoding="utf-8")
        self.server.portal_store.add_input(project, target.name, target, self.admin)
        status, library = self.request("/koda/scans/library", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("라이브러리 보안취약점 점검", library)
        self.assertIn("scope=\"library\"", library)
        self.assertIn("CVE가 연결된 Grype 결과만 표시", library)
        self.assertNotIn("<select id='standards'", library)
        self.assertNotIn("<select id='category'", library)
        self.assertIn("<input id='input' type='hidden'>", library)
        self.assertNotIn("등록된 입력", library)
        self.assertIn("href='/koda/scans/source'", library)
        status, all_scan = self.request("/koda/scans/new", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn('scope="all"', all_scan)
        self.assertIn("<select id='standards'>", all_scan)
        status, source = self.request("/koda/scans/source", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("소스코드 보안취약점 점검", source)
        self.assertIn("scope=\"source\"", source)
        self.assertIn('<option value="local">전체</option>', source)
        self.assertNotIn("등록된 입력", source)
        self.assertIn("href='/koda/scans/library'", source)

    def test_screen_permissions_hide_navigation_and_keep_resource_404(self):
        project = self.server.portal_store.create_project("partial access", self.admin)
        target = Path(self.tmp.name) / "partial.py"
        target.write_text("print('ok')\n", encoding="utf-8")
        input_id = self.server.portal_store.add_input(project, target.name, target, self.admin)
        run = self.server.portal_store.create_scan(self.admin, project, input_id, "local", "all")
        viewer = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(viewer, "viewer")
        self.server.portal_store.set_subject(viewer, status="enabled", actor=self.admin)
        self.server.portal_store.set_membership(project, viewer, "viewer", self.admin)
        policy = self.server.portal_store.role_policy()
        self.server.portal_store.set_role_policy({"viewer": ["dashboard.view"]}, policy["version"], self.admin)
        viewer_headers = self.headers(viewer, "viewer")

        status, dashboard_page = self.request("/koda", headers=viewer_headers)
        self.assertEqual(status, 200)
        navigation = dashboard_page.split("</nav>", 1)[0]
        self.assertNotIn("href='/koda/runs'", navigation)
        self.assertNotIn("href='/koda/scans/library'", navigation)
        self.assertNotIn("href='/koda/projects'", navigation)
        self.assertEqual(self.request("/koda/runs", headers=viewer_headers)[0], 403)
        self.assertEqual(self.request("/koda/scans/library", headers=viewer_headers)[0], 403)
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run['run_id']}", headers=viewer_headers)[0], 404)
        self.assertEqual(self.request("/koda/runs", headers=self.headers())[0], 200)

    def test_compare_hides_unauthorized_cross_project_runs_as_404(self):
        first = self.server.portal_store.create_project("compare allowed", self.admin)
        second = self.server.portal_store.create_project("compare hidden", self.admin)
        target = Path(self.tmp.name) / "compare.py"
        target.write_text("print('compare')\n", encoding="utf-8")
        first_input = self.server.portal_store.add_input(first, target.name, target, self.admin)
        second_input = self.server.portal_store.add_input(second, target.name, target, self.admin)
        first_run = self.server.portal_store.create_scan(self.admin, first, first_input, "local", "all")
        second_run = self.server.portal_store.create_scan(self.admin, second, second_input, "local", "all")
        self.server.portal_store.complete_run(first_run["run_id"], result={"findings": []})
        self.server.portal_store.complete_run(second_run["run_id"], result={"findings": []})
        viewer = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(viewer, "viewer")
        self.server.portal_store.set_subject(viewer, status="enabled", actor=self.admin)
        self.server.portal_store.set_membership(first, viewer, "viewer", self.admin)
        policy = self.server.portal_store.role_policy()
        self.server.portal_store.set_role_policy({"viewer": ["compare.view"]}, policy["version"], self.admin)
        status, body = self.request(
            f"/koda/api/v1/compare?left={first_run['run_id']}&right={second_run['run_id']}",
            headers=self.headers(viewer, "viewer"),
        )
        self.assertEqual(status, 404)
        self.assertEqual(body, {"code": "not_found"})

    def test_role_policy_labels_screens_and_features_in_korean(self):
        self.server.portal_store.create_project("role labels", self.admin)
        status, body = self.request("/koda/admin/roles", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("KODA 전역 역할 정책", body)
        self.assertIn("화면 접근 권한", body)
        self.assertIn("기능 실행 권한", body)
        self.assertIn("라이브러리 점검", body)
        self.assertIn("프로젝트 관리자", body)
        self.assertIn("dashboard.view", body)
        self.assertNotIn("project.view", body)
        self.assertNotIn("project.manage", body)
        self.assertNotIn("<th>권한</th>", body)
        self.assertNotIn("<select name='project'>", body)
        self.assertIn("aria-current='page'", body)

        policy = self.server.portal_store.role_policy()
        status, updated = self.request("/koda/api/v1/admin/roles", method="POST", payload={
            "expected_version": policy["version"], "roles": {"viewer": ["dashboard.view"]},
        }, headers=self.headers())
        self.assertEqual((status, updated["version"]), (200, policy["version"] + 1))
        self.assertEqual(self.request("/koda/api/v1/admin/roles", method="POST", payload={
            "project_id": "legacy", "expected_version": updated["version"], "roles": updated["roles"],
        }, headers=self.headers())[0], 422)

    def test_rule_cards_include_all_standards_and_sync_duplicate_rules(self):
        project = self.server.portal_store.create_project("rule catalog", self.admin)
        status, body = self.request(f"/koda/admin/rules?project={project}", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("OWASP", body)
        self.assertIn("SW49", body)
        self.assertIn("상세 매핑", body)
        self.assertIn("공식 통제 ID", body)
        self.assertIn("지원 수준", body)
        self.assertIn("CWE-862", body)
        self.assertNotIn("<summary>전체 (106)</summary>", body)
        self.assertIn("[data-rule-card]+[data-rule-card]", body)
        rule_ids = Counter(value.split("'", 1)[0] for value in body.split("data-rule-id='")[1:])
        self.assertTrue(any(count > 1 for count in rule_ids.values()))
        self.assertIn("peer.dataset.ruleId===box.dataset.ruleId", body)

    def test_audit_xlsx_contains_kst_actor_project_and_detail(self):
        project = self.server.portal_store.create_project("audit project", self.admin)
        with self.server.portal_store._db() as db:
            db.execute(
                "INSERT INTO audit_events(subject_id,action,project_id,detail_json,created_at) VALUES(?,?,?,?,?)",
                (self.admin, "audit.test", project, '{"note":"확인"}', "2026-01-01T00:00:00+00:00"),
            )
        request = urllib.request.Request(
            self.base + "/koda/api/v1/admin/audit?format=xlsx", headers=self.headers(),
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read()
            self.assertEqual(response.headers.get_content_type(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            sheet = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
        for expected in ("발생 시간", "사용자 ID", "주체 ID", "프로젝트명", "상세 JSON", "2026-01-01 09:00:00", "admin", self.admin, "audit project", project, "audit.test", "확인"):
            self.assertIn(expected, sheet)

        viewer = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(viewer, "viewer")
        self.server.portal_store.set_subject(viewer, status="enabled", actor=self.admin)
        self.assertEqual(self.request("/koda/api/v1/admin/audit?format=xlsx", headers=self.headers(viewer))[0], 403)

    def test_public_koda_icon_asset(self):
        status, body = self.request("/koda/assets/KODA.ico")
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"\x00\x00\x01\x00"))
        self.assertEqual(self.request("/koda/assets/missing.ico")[0], 404)

    def test_project_upload_scan_round_and_injection_rejection(self):
        status, created = self.request("/koda/api/v1/projects", method="POST", payload={"name": "portal"}, headers=self.headers())
        self.assertEqual(status, 201)
        project_id = created["project_id"]
        request = urllib.request.Request(
            self.base + f"/koda/api/v1/projects/{project_id}/inputs?name=demo.py",
            data=b"AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n", method="POST",
            headers={**self.headers(), "Content-Type": "application/octet-stream"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            status, uploaded = response.status, json.loads(response.read())
        self.assertEqual(status, 201)
        scan = {"project_id": project_id, "input_id": uploaded["input_id"], "standard": "local", "standard_category": "all"}
        injected = dict(scan, disabled_rules=["secret.rule"])
        self.assertEqual(self.request("/koda/api/v1/scans", method="POST", payload=injected, headers=self.headers())[0], 422)
        status, run = self.request("/koda/api/v1/scans", method="POST", payload=scan, headers=self.headers())
        self.assertEqual((status, run["round_number"]), (202, 1))
        for _ in range(100):
            _, detail = self.request(f"/koda/api/v1/runs/{run['run_id']}", headers=self.headers())
            if detail["status"] in {"completed", "failed"}:
                break
            time.sleep(.02)
        self.assertEqual(detail["status"], "completed", detail.get("error"))
        self.assertEqual(detail["snapshot"]["requested_by"], self.admin)
        self.assertIsInstance(detail["result"], dict)
        self.assertTrue(detail["result"]["findings"])
        self.assertIn("analysis_stages", detail["result"])
        self.assertIn("local_vulnerability", detail["result"]["scan"])
        self.assertIn("queried_components", detail["result"]["scan"]["local_vulnerability"])
        self.assertFalse(Path(self.server.portal_store.input(uploaded["input_id"])["path"]).exists())

    def test_streaming_upload_limit_and_vulnerability_database_status(self):
        _, created = self.request("/koda/api/v1/projects", method="POST", payload={"name": "large input"}, headers=self.headers())
        project_id = created["project_id"]
        request = urllib.request.Request(
            self.base + f"/koda/api/v1/projects/{project_id}/inputs?name=demo.zip",
            data=b"zip-content", method="POST", headers={**self.headers(), "Content-Type": "application/octet-stream"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            uploaded = json.loads(response.read())
            self.assertEqual(response.status, 201)
        self.assertEqual(uploaded["size"], len(b"zip-content"))
        self.assertEqual(self.server.portal_store.list_inputs(project_id)[0]["name"], "demo.zip")
        status, scan_page = self.request("/koda/scans/new", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("최대 1 GB", scan_page)
        self.assertNotIn("최대 1 GiB", scan_page)
        self.assertIn("application/octet-stream", scan_page)
        self.assertIn("/koda/api/v1/vulnerability-db", scan_page)
        self.assertEqual(
            self.request(
                f"/koda/api/v1/projects/{project_id}/inputs?name=legacy.json",
                method="POST", payload={"content": "emlw"}, headers=self.headers(),
            )[0],
            415,
        )

        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        connection.putrequest("POST", f"/koda/api/v1/projects/{project_id}/inputs?name=too-large.zip")
        for name, value in self.headers().items():
            connection.putheader(name, value)
        connection.putheader("Content-Type", "application/octet-stream")
        connection.putheader("Content-Length", str(MAX_INPUT_BYTES + 1))
        connection.endheaders()
        response = connection.getresponse()
        self.assertEqual(response.status, 413)
        response.read(); connection.close()

        status_value = {"configured": True, "available": True, "version": "0.99.1", "database": {"built": "2026-08-17"}, "warning": ""}
        with patch("security_scanner.linux_portal._vulnerability_database_status", return_value=status_value):
            self.assertEqual(self.request("/koda/api/v1/vulnerability-db", headers=self.headers()), (200, status_value))
            status, page = self.request("/koda/admin/vulnerability-db", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("0.99.1", page)
        self.assertIn("2026-08-17", page)
        self.assertIn("<div class='panel-body'><ul class='summary-list'>", page)

    def test_cancel_and_comparison_exports(self):
        project = self.server.portal_store.create_project("history", self.admin)
        targets = [Path(self.tmp.name) / name for name in ("history-first.py", "history-second.py", "history-comparison.py")]
        for target in targets:
            target.write_text("print('history')\n", encoding="utf-8")
        input_ids = [self.server.portal_store.add_input(project, target.name, target, self.admin) for target in targets]
        first = self.server.portal_store.create_scan(self.admin, project, input_ids[0], "local", "all")
        self.server.portal_store.complete_run(first["run_id"], result={"findings": [{"rule_id": "rule.old", "title": "old", "severity": "low", "category": "code", "path": "a.py", "line": 1}]})
        second = self.server.portal_store.create_scan(self.admin, project, input_ids[1], "local", "all")
        status, cancelled = self.request(f"/koda/api/v1/runs/{second['run_id']}/cancel", method="POST", payload={}, headers=self.headers())
        self.assertEqual((status, cancelled["status"]), (200, "cancelled"))
        cancelled_comparison = f"left={first['run_id']}&right={second['run_id']}"
        self.assertEqual(self.request(f"/koda/api/v1/compare?{cancelled_comparison}", headers=self.headers())[0], 422)
        self.assertEqual(self.request(f"/koda/api/v1/runs/{second['run_id']}/retry", method="POST", payload={}, headers=self.headers())[0], 404)

        comparison_run = self.server.portal_store.create_scan(self.admin, project, input_ids[2], "local", "all")
        self.server.portal_store.complete_run(comparison_run["run_id"], result={"findings": [{"rule_id": "rule.new", "title": "new", "severity": "high", "category": "code", "path": "b.py", "line": 2}]})
        query = f"left={first['run_id']}&right={comparison_run['run_id']}"
        status, page = self.request(f"/koda/compare?{query}", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("항목별 비교", page)
        self.assertIn("rule.old", page)
        self.assertIn("rule.new", page)
        status, comparison = self.request(f"/koda/api/v1/compare?{query}&format=json", headers=self.headers())
        self.assertEqual((status, comparison["counts"]), (200, {"new": 1, "resolved": 1, "persistent": 0}))
        request = urllib.request.Request(self.base + f"/koda/api/v1/compare?{query}&format=csv", headers=self.headers())
        with urllib.request.urlopen(request, timeout=10) as response:
            self.assertTrue(response.read().startswith(b"\xef\xbb\xbf"))

    def test_cross_project_run_is_hidden_and_policy_versions_conflict(self):
        project = self.server.portal_store.create_project("private", self.admin)
        target = Path(self.tmp.name) / "input.txt"
        target.write_text("safe", encoding="utf-8")
        input_id = self.server.portal_store.add_input(project, "input.txt", target, self.admin)
        run = self.server.portal_store.create_scan(self.admin, project, input_id, "local", "all")
        other = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(other, "other")
        self.server.portal_store.set_subject(other, status="enabled", actor=self.admin)
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run['run_id']}", headers=self.headers(other, "other"))[0], 404)
        body = {"project_id": project, "expected_version": 0, "disabled_rules": []}
        self.assertEqual(self.request("/koda/api/v1/admin/rules", method="POST", payload=body, headers=self.headers())[0], 409)

    def test_completed_run_downloads_authorized_nis_sbom_csv(self):
        project = self.server.portal_store.create_project("NIS export", self.admin)
        target = Path(self.tmp.name) / "dependency.txt"
        target.write_text("package", encoding="utf-8")
        input_id = self.server.portal_store.add_input(project, "dependency.txt", target, self.admin)
        run = self.server.portal_store.create_scan(self.admin, project, input_id, "local", "all")
        self.server.portal_store.complete_run(run["run_id"], result={
            "findings": [],
            "components": [{"name": "demo", "version": "1.2.3", "path": "requirements.txt", "purl": "pkg:pypi/demo@1.2.3"}],
            "sbom": {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "demo", "version": "1.2.3"}]},
            "nis_sbom": {"rows": [{"SBOM Standard": "NIS 1.0", "Product Name": "demo-app", "Component Name": "demo", "Component Version": "1.2.3"}]},
        })

        status, page = self.request(f"/koda/runs/{run['run_id']}", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("국정원 NIS-SBOM 1.0 (CSV)", page)
        self.assertIn(f"/koda/api/v1/runs/{run['run_id']}/sbom", page)

        request = urllib.request.Request(
            self.base + f"/koda/api/v1/runs/{run['run_id']}/sbom?format=nis-sbom",
            headers=self.headers(),
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            raw, headers = response.read(), response.headers
            self.assertEqual(response.status, 200)
        self.assertEqual(headers.get_content_type(), "text/csv")
        self.assertEqual(headers.get_content_charset(), "utf-8")
        self.assertEqual(headers["Content-Disposition"], 'attachment; filename="koda-round-1-nis-sbom-1.0.csv"')
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
        self.assertEqual(rows[0]["SBOM Standard"], "NIS 1.0")
        self.assertEqual(rows[0]["Component Name"], "demo")

        unauthorized = {"X-KODA-Identity-Display": base64.urlsafe_b64encode(b"unknown").rstrip(b"=").decode()}
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run['run_id']}/sbom?format=nis-sbom", headers=unauthorized)[0], 401)
        other = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(other, "other")
        self.server.portal_store.set_subject(other, status="enabled", actor=self.admin)
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run['run_id']}/sbom?format=nis-sbom", headers=self.headers(other, "other"))[0], 404)

    def test_completed_run_separates_library_source_and_quality_tabs(self):
        project = self.server.portal_store.create_project("분류 탭", self.admin)
        target = Path(self.tmp.name) / "app.py"
        target.write_text("print('demo')\n", encoding="utf-8")
        input_id = self.server.portal_store.add_input(project, target.name, target, self.admin)
        run = self.server.portal_store.create_scan(self.admin, project, input_id, "local", "all")
        self.server.portal_store.complete_run(run["run_id"], result={"findings": [
            {"rule_id": "dependency.osv", "title": "취약한 라이브러리", "severity": "high", "category": "dependencies", "path": "requirements.txt"},
            {"rule_id": "code.sql", "title": "동적 SQL", "severity": "critical", "category": "code", "path": target.name},
            {"rule_id": "secret.literal", "title": "비밀정보", "severity": "high", "category": "secrets", "path": target.name},
            {"rule_id": "screen.alt", "title": "대체 텍스트", "severity": "low", "category": "screen_quality", "path": "index.html"},
        ]})

        status, result_page = self.request(f"/koda/runs/{run['run_id']}", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("라이브러리 취약점 1", result_page)
        self.assertIn("소스코드 취약점 2", result_page)
        self.assertIn("품질 점검 1", result_page)
        self.assertEqual(result_page.count("data-group='library'"), 1)
        self.assertEqual(result_page.count("data-group='source'"), 2)
        self.assertEqual(result_page.count("data-group='quality'"), 1)
        self.assertIn(">라이브러리</td>", result_page)
        self.assertIn(">소스코드</td>", result_page)
        self.assertIn(">비밀정보</td>", result_page)
        self.assertIn(">화면품질</td>", result_page)
        self.assertNotIn("다시 실행", result_page)
        self.assertNotIn("/retry", result_page)
        self.assertNotIn("format=hwpx", result_page)
        self.assertNotIn("href='/koda/compare?right=", result_page)
        self.assertNotIn("<a class='button' href='/koda/scans/library'>", result_page)
        self.assertNotIn("<a class='button' href='/koda/scans/source'>", result_page)
        self.assertIn("class='resizable-table'", result_page)
        self.assertEqual(result_page.count("class='column-resizer'"), 6)
        self.assertIn("ArrowRight", result_page)
        self.assertIn("align-items:center;justify-content:center;text-align:center", result_page)

    def test_completed_run_report_uses_the_shared_windows_cli_renderer(self):
        project = self.server.portal_store.create_project("CLI report", self.admin)
        target = Path(self.tmp.name) / "unsafe.py"
        target.write_text("password = 'secret'\n", encoding="utf-8")
        input_id = self.server.portal_store.add_input(project, target.name, target, self.admin)
        run = self.server.portal_store.create_scan(self.admin, project, input_id, "local", "all")
        result = {
            "scan": {"path": target.name, "kind": "source", "standard": "local", "standard_category": "all"},
            "findings": [{"rule_id": "secret.literal", "title": "하드코딩된 비밀정보", "severity": "high", "category": "security", "path": target.name, "line": 1}],
            "components": [],
        }
        self.server.portal_store.complete_run(run["run_id"], result=result)

        request = urllib.request.Request(
            self.base + f"/koda/api/v1/runs/{run['run_id']}/report?format=html",
            headers=self.headers(),
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            actual, response_headers = response.read(), response.headers
        self.assertEqual(response_headers.get_content_type(), "application/zip")
        self.assertEqual(response_headers["Content-Disposition"], 'attachment; filename="koda-round-1-report.zip"')

        expected = render_html_pair_zip_from_payload(result, "ko")
        with zipfile.ZipFile(io.BytesIO(actual)) as actual_zip, zipfile.ZipFile(io.BytesIO(expected)) as expected_zip:
            self.assertEqual(actual_zip.namelist(), ["report.html", "report-detail.html"])
            for name in actual_zip.namelist():
                self.assertEqual(actual_zip.read(name), expected_zip.read(name))
                request = urllib.request.Request(
                    self.base + f"/koda/api/v1/runs/{run['run_id']}/{name}",
                    headers=self.headers(),
                )
                with urllib.request.urlopen(request, timeout=10) as response:
                    self.assertEqual(response.headers.get_content_type(), "text/html")
                    self.assertEqual(response.read(), expected_zip.read(name))

        status, markdown = self.request(f"/koda/api/v1/runs/{run['run_id']}/report?format=markdown", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("하드코딩된 비밀정보", markdown)
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run['run_id']}/report?format=unknown", headers=self.headers())[0], 422)

    def test_library_run_opens_a_library_vulnerability_report(self):
        project = self.server.portal_store.create_project("library report", self.admin)
        target = Path(self.tmp.name) / "requirements.txt"
        target.write_text("demo==1.0\n", encoding="utf-8")
        input_id = self.server.portal_store.add_input(project, target.name, target, self.admin)
        run = self.server.portal_store.create_scan(self.admin, project, input_id, "local", "all", scan_scope="library")
        result = {
            "findings": [{"rule_id": "CVE-2026-0001", "title": "취약한 라이브러리", "severity": "critical", "category": "dependencies", "path": target.name}],
            "components": [],
        }
        self.server.portal_store.complete_run(run["run_id"], result=result)

        status, result_page = self.request(f"/koda/runs/{run['run_id']}", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("라이브러리 취약점 보고서", result_page)
        status, main = self.request(f"/koda/api/v1/runs/{run['run_id']}/report.html", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("Java 라이브러리 취약점 요약", main)
        self.assertIn("JAVA SECURITY REPORT", main)
        self.assertNotIn("소스 보안 분석 요약", main)
        status, detail = self.request(f"/koda/api/v1/runs/{run['run_id']}/report-detail.html", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("라이브러리 취약점 상세", detail)
        self.assertIn("구성요소 근거", detail)


if __name__ == "__main__":
    unittest.main()
