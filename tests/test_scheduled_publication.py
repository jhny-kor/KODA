import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_scanner.portal_integrations import publish_tracker_result


class ScheduledPublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def run_data(self, *, findings=None, run_id="run-1"):
        return {
            "run_id": run_id,
            "project_id": "project-1",
            "requested_by": "operator-1",
            "snapshot": {
                "source_type": "scheduled_server",
                "gitlab_project_id": 42,
                "gitlab_target_branch": "main",
                "schedule_target_id": "target-1",
                "schedule_run_id": run_id,
                "remote_server": "app.example",
                "remote_directory": "/srv/app",
                "scan_mode": "changed",
                "rule_policy_version": 3,
            },
            "result": {"findings": [], "sbom": {"components": []}, "scan": {"changed": True}},
        }

    def tracker(self, findings=None, *, state="completed"):
        return {"run": {"state": state}, "analysis": {"state": state, "findings": findings or []}}

    def write(self, calls, path, query=None, *, settings_dir, method="GET", payload=None):
        calls.append((path, query, method, payload))
        if path.endswith("/merge_requests") and method == "GET":
            return []
        if path.endswith("/merge_requests"):
            return {"web_url": "https://gitlab.example/mr/1", "iid": 1}
        if path.endswith("/repository/commits"):
            return {"web_url": "https://gitlab.example/commit/1"}
        if path.endswith("/issues"):
            return {"iid": len([item for item in calls if item[0].endswith("/issues") and item[2] == "POST"]), "web_url": "https://gitlab.example/issue/1"}
        self.fail(path)

    def test_scheduled_uses_target_branch_and_reuses_closed_mr(self):
        calls = []
        existing_mr = [{"iid": 8, "web_url": "https://gitlab.example/mr/8", "state": "merged", "description": "old", "labels": []}]

        def write(path, query=None, *, settings_dir, method="GET", payload=None):
            calls.append((path, query, method, payload))
            if path.endswith("/merge_requests") and method == "GET":
                return existing_mr
            if path.endswith("/repository/commits"):
                return {"web_url": "https://gitlab.example/commit/1"}
            if path.endswith("/merge_requests/8"):
                return {"iid": 8, "web_url": existing_mr[0]["web_url"]}
            self.fail(path)

        with patch("security_scanner.portal_integrations._gitlab_optional_json", return_value=None), patch(
            "security_scanner.portal_integrations._gitlab_write_json", side_effect=write,
        ):
            result = publish_tracker_result({"default_branch": "main"}, self.run_data(), "tracker-1", self.tracker(), settings_dir=Path(self.tmp.name))
        mr_query = next(query for path, query, method, _ in calls if path.endswith("/merge_requests") and method == "GET")
        self.assertEqual(mr_query["state"], "all")
        self.assertEqual(result["mergeRequestUrl"], existing_mr[0]["web_url"])
        commit = next(payload for path, _, method, payload in calls if path.endswith("/repository/commits"))
        self.assertEqual(commit["branch"], "koda/scheduled/target-1/run-1")
        self.assertEqual(commit["actions"][0]["file_path"], ".koda/scheduled-results/target-1/run-1.json")

    def test_tracker_completion_refreshes_koda_json(self):
        run = self.run_data()
        pending_report = {
            "schemaVersion": 2, "source": {"type": "scheduled_server"}, "inspection": {},
            "kodaRunId": run["run_id"], "trackerRunId": "pending", "kodaResult": run["result"],
            "trackerResult": self.tracker(state="failed"),
        }
        encoded = base64.b64encode((json.dumps(pending_report, sort_keys=True) + "\n").encode()).decode()
        calls = []
        with patch("security_scanner.portal_integrations._gitlab_optional_json", side_effect=[
            {"encoding": "base64", "content": encoded}, None,
        ]), patch("security_scanner.portal_integrations._gitlab_write_json", side_effect=lambda *args, **kwargs: self.write(calls, *args, **kwargs)):
            publish_tracker_result({"default_branch": "main"}, run, "tracker-completed", self.tracker(), settings_dir=Path(self.tmp.name))
        commit = next(payload for path, _, method, payload in calls if path.endswith("/repository/commits") and method == "POST")
        refreshed = json.loads(commit["actions"][0]["content"])
        self.assertEqual(refreshed["trackerRunId"], "tracker-completed")
        self.assertEqual(refreshed["source"]["server"], "app.example")

    def test_each_scheduled_vulnerability_keeps_stable_issue_marker(self):
        first = self.run_data(findings=[], run_id="run-1")
        findings = [
            {"canonicalId": "CVE-2026-1111", "component": "a", "version": "1"},
            {"canonicalId": "CVE-2026-2222", "component": "b", "version": "2"},
        ]
        calls = []
        with patch("security_scanner.portal_integrations._gitlab_optional_json", return_value=None), patch(
            "security_scanner.portal_integrations.find_gitlab_issue", return_value=None,
        ), patch("security_scanner.portal_integrations._gitlab_write_json", side_effect=lambda *args, **kwargs: self.write(calls, *args, **kwargs)):
            publish_tracker_result({"default_branch": "main"}, first, "tracker-1", self.tracker(findings), settings_dir=Path(self.tmp.name))
        descriptions = [payload["description"] for path, _, method, payload in calls if path.endswith("/issues") and method == "POST"]
        self.assertEqual(len(descriptions), 2)
        self.assertNotEqual(descriptions[0].splitlines()[0], descriptions[1].splitlines()[0])
        self.assertTrue(all("target-1" in description for description in descriptions))

    def test_incremental_without_findings_does_not_close_issue(self):
        calls = []
        with patch("security_scanner.portal_integrations._gitlab_optional_json", return_value=None), patch(
            "security_scanner.portal_integrations._gitlab_write_json", side_effect=lambda *args, **kwargs: self.write(calls, *args, **kwargs),
        ):
            result = publish_tracker_result({"default_branch": "main"}, self.run_data(), "tracker-empty", self.tracker(), settings_dir=Path(self.tmp.name))
        self.assertEqual(result["issueUrls"], [])
        self.assertFalse(any(path.endswith("/close") or (method == "PUT" and "/issues/" in path) for path, _, method, _ in calls))


if __name__ == "__main__":
    unittest.main()
