"""Portal response-size and renderer-isolation regressions."""
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from unittest.mock import Mock, patch

import test_linux_portal as fixtures
from security_scanner import portal_reports


class PortalPaginationTests(unittest.TestCase):
    tearDown = fixtures.LinuxPortalHttpTests.tearDown
    headers = fixtures.LinuxPortalHttpTests.headers
    request = fixtures.LinuxPortalHttpTests.request

    def setUp(self):
        fixtures.LinuxPortalHttpTests.setUp(self)
        # Query fixtures persist synthetic results; an embedded analyzer must
        # not race their completion or replace them with a real empty scan.
        self.server.portal_worker.close()

    def make_run(self, count=35):
        store = self.server.portal_store
        project = store.create_project("pagination", self.admin)
        target = Path(self.tmp.name) / "input.txt"
        target.write_text("source", encoding="utf-8")
        input_id = store.add_input(project, target.name, target, self.admin)
        run = store.create_scan(self.admin, project, input_id, "local", "all")
        findings = [{
            "title": f"Finding {index}", "rule_id": f"rule.{index}", "path": target.name,
            "line": index + 1, "severity": "critical" if index % 2 else "high",
            "category": "dependencies" if index % 2 else "code",
            "description": "PRIVATE LARGE DETAIL " + "x" * 20000,
            "evidence": f"evidence {index}", "recommendation": "fix",
        } for index in range(count)]
        store.complete_run(run["run_id"], result={"findings": findings, "source_context": "WHOLE SOURCE CONTEXT", "components": []})
        self.assertEqual(store.run_summary(run["run_id"])["result"]["finding_count"], count)
        return project, run["run_id"]

    def test_run_html_is_a_bounded_page_with_lazy_detail(self):
        _, run_id = self.make_run()
        with patch.object(self.server.portal_store, "run", side_effect=AssertionError("full result loaded")):
            status, body = self.request(f"/koda/runs/{run_id}", headers=self.headers())
            self.assertEqual(status, 200)
            self.assertEqual(body.count("class='finding-row'"), 25)
            self.assertNotIn("PRIVATE LARGE DETAIL", body)
            self.assertNotIn("WHOLE SOURCE CONTEXT", body)
            self.assertIn("/status`", body)
            self.assertNotIn("setInterval", body)
            self.assertIn("/findings/${summary.finding_index}", body)
            self.assertIn("1 / 2 · 35건", body)
            status, second = self.request(f"/koda/runs/{run_id}?page=2", headers=self.headers())
            self.assertEqual(status, 200)
            self.assertEqual(second.count("class='finding-row'"), 10)
            self.assertIn("data-finding-index='25'", second)
            status, detail = self.request(f"/koda/api/v1/runs/{run_id}/findings/25", headers=self.headers())
            self.assertEqual(status, 200)
            self.assertEqual(detail["evidence"], "evidence 25")

    def test_finding_search_and_severity_apply_before_pagination(self):
        _, run_id = self.make_run()
        status, result = self.request(f"/koda/api/v1/runs/{run_id}/findings?group=library&severity=critical&page_size=5&page=2", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertEqual(result["total"], 17)
        self.assertEqual([item["finding_index"] for item in result["items"]], [11, 13, 15, 17, 19])
        status, result = self.request(f"/koda/api/v1/runs/{run_id}/findings?search=rule.34", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertEqual([item["finding_index"] for item in result["items"]], [34])
        self.assertNotIn("description", result["items"][0])
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run_id}/findings/999", headers=self.headers())[0], 404)

    def test_status_and_dashboard_do_not_load_full_results(self):
        _, run_id = self.make_run()
        with patch.object(self.server.portal_store, "run", side_effect=AssertionError("full result loaded")):
            status, result = self.request(f"/koda/api/v1/runs/{run_id}/status", headers=self.headers())
            self.assertEqual(status, 200)
            self.assertEqual(result["status"], "completed")
            self.assertNotIn("result", result)
            self.assertNotIn("snapshot", result)
            self.assertLess(len(json.dumps(result)), 3000)
            status, dashboard = self.request("/koda/", headers=self.headers())
            self.assertEqual(status, 200)
            self.assertIn("<small>심각</small><strong>17</strong>", dashboard)
            self.assertNotIn("PRIVATE LARGE DETAIL", dashboard)

    def test_list_pagination_and_permissions(self):
        project, run_id = self.make_run(0)
        store = self.server.portal_store
        for index in range(13):
            target = Path(self.tmp.name) / f"input-{index}.txt"
            target.write_text("source", encoding="utf-8")
            input_id = store.add_input(project, target.name, target, self.admin)
            row = store.create_scan(self.admin, project, input_id, "local", "all")
            store.complete_run(row["run_id"], result={"findings": []})
        status, body = self.request("/koda/runs?page_size=10&page=2", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertEqual(body.count("data-source='manual'"), 4)
        self.assertIn("2 / 2 · 14건", body)
        status, listing = self.request("/koda/api/v1/runs?page_size=5&page=2", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertEqual(listing["total"], 14)
        self.assertEqual(len(listing["items"]), 5)
        self.assertNotIn("result", listing["items"][0])
        outsider = str(uuid.uuid4())
        store.ensure_subject(outsider, "outsider")
        store.set_subject(outsider, status="enabled", system_admin=False, actor=self.admin)
        for suffix in ("status", "findings", "findings/0"):
            self.assertEqual(self.request(f"/koda/api/v1/runs/{run_id}/{suffix}", headers=self.headers(outsider, "outsider"))[0], 404)
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run_id}/status")[0], 401)

    def test_invalid_page_parameters_are_rejected(self):
        _, run_id = self.make_run(1)
        for query in ("page=0", "page=-1", "page=abc", "page_size=0", "page_size=101"):
            for endpoint in ("/koda/runs", f"/koda/runs/{run_id}", "/koda/api/v1/runs", f"/koda/api/v1/runs/{run_id}/findings"):
                self.assertEqual(self.request(endpoint + "?" + query, headers=self.headers())[0], 422)

    def test_export_retains_every_finding_and_context(self):
        _, run_id = self.make_run()
        with patch.object(self.server.portal_store, "run", side_effect=AssertionError("full result loaded in HTTP")):
            status, result = self.request(f"/koda/api/v1/runs/{run_id}/report?format=json", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertEqual(len(result["findings"]), 35)
        self.assertEqual(result["source_context"], "WHOLE SOURCE CONTEXT")

    def test_report_busy_does_not_block_status(self):
        _, run_id = self.make_run(1)
        portal_reports._REPORT_SLOT.acquire()
        try:
            status, result = self.request(f"/koda/api/v1/runs/{run_id}/report?format=json", headers=self.headers())
            self.assertEqual(status, 503)
            self.assertEqual(result["code"], "report_busy")
            self.assertEqual(self.request(f"/koda/api/v1/runs/{run_id}/status", headers=self.headers())[0], 200)
        finally:
            portal_reports._REPORT_SLOT.release()

    def test_report_timeout_kills_renderer_while_web_stays_responsive(self):
        _, run_id = self.make_run(1)
        original = subprocess.Popen
        processes, response = [], []
        started = threading.Event()
        def slow_renderer(command, **kwargs):
            process = original([command[0], "-c", "import time; time.sleep(30)"], **kwargs)
            processes.append(process)
            started.set()
            return process
        with patch.dict(os.environ, {"KODA_PORTAL_REPORT_TIMEOUT_SECONDS": "1"}), patch.object(portal_reports.subprocess, "Popen", side_effect=slow_renderer):
            thread = threading.Thread(target=lambda: response.append(self.request(f"/koda/api/v1/runs/{run_id}/report?format=json", headers=self.headers())))
            thread.start()
            self.assertTrue(started.wait(3))
            before = time.monotonic()
            self.assertEqual(self.request(f"/koda/api/v1/runs/{run_id}/status", headers=self.headers())[0], 200)
            self.assertLess(time.monotonic() - before, .8)
            thread.join(4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 503)
        self.assertEqual(response[0][1]["code"], "report_timeout")
        self.assertEqual(processes[0].poll(), -signal.SIGKILL)

    def test_rss_budget_includes_and_kills_detached_browser_child(self):
        _, run_id = self.make_run(1)
        budget = 256 * 1024**2
        original = subprocess.Popen
        child_file = Path(self.tmp.name) / "browser.pid"
        proc_root = Path(self.tmp.name) / "proc"
        proc_root.mkdir()
        processes, browser_ids = [], []
        code = "import subprocess,sys,time,os; from pathlib import Path; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],start_new_session=True); Path(os.environ['TEST_REPORT_CHILD_FILE']).write_text(str(p.pid)); time.sleep(30)"
        def renderer_with_browser(command, **kwargs):
            process = original([command[0], "-c", code], **kwargs)
            processes.append(process)
            deadline = time.monotonic() + 3
            while not child_file.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            browser = int(child_file.read_text())
            browser_ids.append(browser)
            # Mac test host has no /proc. Supply Linux-shaped stat snapshots of
            # the actual sleeper processes, with the browser in another group.
            _write_process_stat(proc_root, process.pid, os.getpid(), process.pid, 11, 8)
            _write_process_stat(proc_root, browser, process.pid, browser, 22, budget // os.sysconf("SC_PAGE_SIZE") + 1)
            return process
        try:
            with patch.dict(os.environ, {"KODA_PORTAL_REPORT_MEMORY_BYTES": str(budget), "TEST_REPORT_CHILD_FILE": str(child_file)}), patch.object(portal_reports.sys, "platform", "linux"), patch.object(portal_reports, "_PROC_ROOT", proc_root), patch.object(portal_reports.subprocess, "Popen", side_effect=renderer_with_browser):
                status, result = self.request(f"/koda/api/v1/runs/{run_id}/report?format=pdf", headers=self.headers())
            self.assertEqual((status, result["code"]), (503, "report_memory_exceeded"))
            self.assertEqual(processes[0].poll(), -signal.SIGKILL)
            state = subprocess.run(["ps", "-p", str(browser_ids[0]), "-o", "stat="], capture_output=True, text=True).stdout.strip()
            self.assertTrue(not state or state.startswith("Z"), state)
            # Cleanup releases admission even after a memory-budget failure.
            self.assertEqual(self.request(f"/koda/api/v1/runs/{run_id}/report?format=json", headers=self.headers())[0], 200)
        finally:
            for process in processes:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            for browser in browser_ids:
                try:
                    os.kill(browser, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    @unittest.skipUnless(shutil.which("node"), "requires Node")
    def test_server_pagination_scripts_parse(self):
        _, run_id = self.make_run(2)
        for endpoint in ("/koda/runs", f"/koda/runs/{run_id}"):
            status, body = self.request(endpoint, headers=self.headers())
            self.assertEqual(status, 200)
            scripts = re.findall(r"<script(?: [^>]*)?>(.*?)</script>", body, re.S)
            result = subprocess.run([shutil.which("node"), "-e", "const fs=require('fs'); for(const s of JSON.parse(fs.readFileSync(0,'utf8')))new Function(s)"], input=json.dumps(scripts), text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)


def _write_process_stat(root, pid, parent, group, started, rss_pages):
    directory = root / str(pid)
    directory.mkdir(exist_ok=True)
    fields = ["S", str(parent), str(group)] + ["0"] * 19
    fields[19], fields[20], fields[21] = str(started), str(8 * 1024**3), str(rss_pages)
    (directory / "stat").write_text(f"{pid} (renderer (worker)) " + " ".join(fields))


class PortalReportBudgetTests(unittest.TestCase):
    def test_linux_snapshot_tracks_detached_and_reparented_descendants(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_process_stat(root, 100, 1, 100, 10, 2)
            _write_process_stat(root, 101, 100, 100, 20, 3)
            _write_process_stat(root, 102, 101, 102, 30, 5)
            _write_process_stat(root, 999, 1, 999, 40, 100000)
            tracked = {}
            with patch.object(portal_reports, "_PROC_ROOT", root):
                self.assertEqual(portal_reports._sample_report_memory(100, tracked), 10 * os.sysconf("SC_PAGE_SIZE"))
                self.assertEqual(tracked, {100: 10, 101: 20, 102: 30})
                # A browser detached from the driver remains within the budget
                # after reparenting; a reused PID is no longer our process.
                _write_process_stat(root, 102, 1, 102, 30, 5)
                self.assertEqual(portal_reports._sample_report_memory(100, tracked), 10 * os.sysconf("SC_PAGE_SIZE"))
                _write_process_stat(root, 102, 1, 102, 99, 50000)
                self.assertEqual(portal_reports._sample_report_memory(100, tracked), 5 * os.sysconf("SC_PAGE_SIZE"))
                # A reused leader PID must not admit an unrelated group/tree or
                # replace the old identity used by final cleanup checks.
                _write_process_stat(root, 100, 1, 100, 1010, 90000)
                _write_process_stat(root, 103, 100, 100, 1050, 90000)
                self.assertEqual(portal_reports._sample_report_memory(100, tracked), 3 * os.sysconf("SC_PAGE_SIZE"))
                self.assertEqual(tracked[100], 10)
                self.assertNotIn(103, tracked)
                process = Mock(pid=100)
                with patch.object(portal_reports.os, "killpg") as kill_group, patch.object(portal_reports.os, "kill") as kill:
                    portal_reports._kill_group(process, tracked)
                kill_group.assert_not_called()
                kill.assert_called_once_with(101, signal.SIGKILL)
                process.wait.assert_called_once()

    def test_pdf_keeps_inherited_virtual_limit_for_chromium(self):
        from security_scanner import process_limits
        inherited = (portal_reports.resource.RLIM_INFINITY, portal_reports.resource.RLIM_INFINITY)
        with patch.object(portal_reports.resource, "getrlimit", return_value=inherited), patch.object(process_limits, "apply_limits") as limits, patch.object(portal_reports.resource, "setrlimit") as restore:
            portal_reports._apply_report_limits("pdf", 2 * 1024**3)
            limits.assert_called_once_with({"cpus": 1, "memory_bytes": 2 * 1024**3})
            restore.assert_called_once_with(portal_reports.resource.RLIMIT_AS, inherited)
            restore.reset_mock()
            portal_reports._apply_report_limits("json", 2 * 1024**3)
            restore.assert_not_called()


if __name__ == "__main__":
    unittest.main()
