import datetime as dt
import tempfile
import subprocess
import time
import os
import signal
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from security_scanner.portal_store import PortalStore
from security_scanner.schedule_worker import RemoteFile, ScheduleRunner


class FakeCollector:
    def __init__(self):
        self.files = [RemoteFile("app/main.py", 7, 1700000000.0)]
        self.fetched = []

    def list_files(self, target):
        return list(self.files)

    def fetch(self, target, remote_file, destination):
        self.fetched.append(remote_file.relative_path)
        destination.write_text("print(1)\n", encoding="utf-8")


class ScheduleWorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PortalStore(Path(self.tmp.name) / "portal.sqlite3")
        self.admin = str(uuid.uuid4())
        self.store.bootstrap(self.admin)
        self.project = self.store.create_project("scheduled-demo")
        self.store.set_membership(self.project, self.admin, "admin")
        self.target = self.store.save_schedule_target({
            "project_id": self.project,
            "name": "test-server",
            "host": "server.internal",
            "port": 22,
            "username": "koda-readonly",
            "ssh_key_ref": "/run/koda/ssh/id_ed25519",
            "known_hosts_file": "/run/koda/ssh/known_hosts",
            "remote_directory": "/srv/app",
            "scan_scope": "source",
            "standard": "local",
            "standard_category": "all",
            "enabled": True,
        }, self.admin)

    def tearDown(self):
        self.tmp.cleanup()

    def test_success_deletes_archive_and_keeps_hash_baseline(self):
        collector = FakeCollector()

        def complete(store, run_id):
            self.assertTrue(store.mark_run_running(run_id))
            store.complete_run(run_id, result={"findings": [], "sbom": {"components": []}})

        runner = ScheduleRunner(self.store, collector=collector, work_dir=Path(self.tmp.name) / "schedule-work", sleep=lambda _: None)
        with patch.object(runner, "_analyze", side_effect=lambda run_id, deadline: complete(self.store, run_id)):
            result = runner.run_target(self.target, scheduled_for="2026-09-07")

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["cleanup_status"], "completed")
        self.assertEqual(collector.fetched, ["app/main.py"])
        self.assertEqual(set(self.store.baseline_schedule_files(self.target["target_id"])), {"app/main.py"})
        self.assertTrue(self.store.baseline_schedule_files(self.target["target_id"])["app/main.py"]["sha256"])
        self.assertEqual(list((Path(self.tmp.name) / "schedule-work").iterdir()), [])

    def test_changed_run_with_no_manifest_delta_is_still_recorded(self):
        collector = FakeCollector()

        def complete(store, run_id):
            store.mark_run_running(run_id)
            store.complete_run(run_id, result={"findings": [], "sbom": {"components": []}})

        runner = ScheduleRunner(self.store, collector=collector, work_dir=Path(self.tmp.name) / "schedule-work", sleep=lambda _: None)
        with patch.object(runner, "_analyze", side_effect=lambda run_id, deadline: complete(self.store, run_id)):
            runner.run_target(self.target, scheduled_for="2026-09-06")
            collector.fetched.clear()
            result = runner.run_target(self.target, scheduled_for="2026-09-07")

        self.assertEqual(result["mode"], "changed")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["changed_files"], 0)
        self.assertEqual(collector.fetched, [])
        self.assertFalse(any((Path(self.tmp.name) / "schedule-work").iterdir()))

    def test_rule_policy_change_forces_full_and_library_manifest_is_collected(self):
        collector = FakeCollector()
        collector.files.append(RemoteFile("package-lock.json", 7, 1700000000.0))
        target = self.store.save_schedule_target({**self.target, "scan_scope": "all", "enabled": True}, self.admin)

        def complete(store, run_id):
            store.mark_run_running(run_id)
            store.complete_run(run_id, result={"findings": [], "sbom": {"components": []}})

        runner = ScheduleRunner(self.store, collector=collector, work_dir=Path(self.tmp.name) / "schedule-work", sleep=lambda _: None)
        with patch.object(runner, "_analyze", side_effect=lambda run_id, deadline: complete(self.store, run_id)):
            runner.run_target(target, scheduled_for="2026-09-06")
            collector.fetched.clear()
            changed = runner.run_target(target, scheduled_for="2026-09-07")
            self.assertEqual(changed["mode"], "changed")
            self.assertEqual(collector.fetched, ["package-lock.json"])
            self.store.set_rule_policy(self.project, ["secret.x"], expected_version=1)
            collector.fetched.clear()
            full = runner.run_target(target, scheduled_for="2026-09-08")

        self.assertEqual(full["mode"], "full")
        self.assertEqual(set(collector.fetched), {"app/main.py", "package-lock.json"})
        scan = self.store.run(full["run_id"])
        self.assertEqual(scan["snapshot"]["changed_files"], ["app/main.py", "package-lock.json"])
        self.assertEqual(scan["snapshot"]["files_total"], 2)

    def test_failed_collection_marks_cleanup_without_leaving_workdir(self):
        class FailingCollector(FakeCollector):
            def list_files(self, target):
                raise RuntimeError("connection reset")

        runner = ScheduleRunner(self.store, collector=FailingCollector(), work_dir=Path(self.tmp.name) / "schedule-work", sleep=lambda _: None)
        result = runner.run_target(self.target, scheduled_for="2026-09-07")

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["cleanup_status"], "completed")
        self.assertFalse(any((Path(self.tmp.name) / "schedule-work").iterdir()))
        self.assertEqual(self.store.list_inputs(self.project), [])

    def runner(self):
        return ScheduleRunner(self.store, collector=FakeCollector(), work_dir=Path(self.tmp.name) / "schedule-work", sleep=lambda _: None)

    def mapped_target(self):
        mapping = self.store.set_gitlab_repositories(self.project, [{
            "gitlab_project_id": 42, "path_with_namespace": "group/demo", "name": "demo",
            "default_branch": "main", "tracker_service_id": "service-1",
            "tracker_environment_id": "environment-1", "tracker_token_ref": "demo.token",
        }], self.admin)[0]
        return self.store.save_schedule_target({**self.target, "gitlab_mapping_id": mapping["mapping_id"]}, self.admin)

    def test_real_analyzer_process_stores_result_and_cleans_every_copy(self):
        runner = self.runner()
        result = runner.run_target(self.target, scheduled_for="2026-09-07")
        self.assertEqual(result["status"], "completed", result)
        self.assertIsInstance(self.store.run(result["run_id"])["result"], dict)
        self.assertFalse(list(runner.work_dir.iterdir()))
        self.assertFalse(Path(self.store.input(self.store.run(result["run_id"])["input_id"])["path"]).exists())

    def test_every_copy_deleted_before_tracker_and_gitlab_delivery(self):
        runner, target = self.runner(), self.mapped_target()
        seen = []
        def analyze(run_id, deadline):
            self.store.mark_run_running(run_id)
            self.store.complete_run(run_id, result={"findings": [], "sbom": {"components": []}})
        def deliver(store, kind, run_id, **kwargs):
            self.assertFalse(list(runner.work_dir.iterdir()))
            self.assertIsNotNone(store.run(run_id)["result"])
            self.assertEqual(store.schedule_run(store.run(run_id)["snapshot"]["schedule_run_id"])["cleanup_status"], "completed")
            seen.append(kind)
        with patch.object(runner, "_analyze", side_effect=analyze), patch("security_scanner.linux_portal._run_delivery", side_effect=deliver):
            result = runner.run_target(target, scheduled_for="2026-09-07")
        self.assertEqual(result["status"], "completed")
        self.assertIn("tracker", seen)
        self.assertIn("issues", seen)

    def test_saved_result_retry_never_recollects_or_reuploads_sbom(self):
        runner, target = self.runner(), self.mapped_target()
        target = self.store.save_schedule_target(target | {"scan_scope": "all"}, self.admin)
        published = []
        def analyze(run_id, deadline):
            self.store.mark_run_running(run_id)
            self.store.complete_run(run_id, result={"findings": [], "sbom": {"components": []}})
        def publish(mapping, run, tracker_id, result, **kwargs):
            self.assertFalse(list(runner.work_dir.iterdir()))
            published.append((run["run_id"], result["run"]["state"]))
            return {"mergeRequestUrl": "https://gitlab.invalid/mr/1"}
        with patch.object(runner, "_analyze", side_effect=analyze) as engine, patch("security_scanner.linux_portal.send_tracker_sbom", return_value="tracker-1") as upload, patch("security_scanner.linux_portal.fetch_tracker_result", side_effect=[ConnectionError("temporary outage"), {"run": {"state": "completed"}, "analysis": {}}]), patch("security_scanner.linux_portal.publish_tracker_result", side_effect=publish):
            result = runner.run_target(target, scheduled_for="2026-09-07")
            self.assertEqual(self.store.tracker_delivery(result["run_id"])["status"], "failed")
            fetched = list(runner.collector.fetched)
            with patch.object(runner, "_now", return_value=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=16)):
                runner.retry_deliveries()
            self.assertEqual(self.store.tracker_delivery(result["run_id"])["status"], "completed")
            self.assertEqual(runner.collector.fetched, fetched)
            self.assertEqual(engine.call_count, 1)
            self.assertEqual(upload.call_count, 1)
        self.assertEqual(published, [(result["run_id"], "pending"), (result["run_id"], "completed")])

    def test_cleanup_failure_blocks_publication_and_recovery_retries_cleanup(self):
        runner, target = self.runner(), self.mapped_target()
        def analyze(run_id, deadline):
            self.store.mark_run_running(run_id)
            self.store.complete_run(run_id, result={"findings": [], "sbom": {"components": []}})
        with patch.object(runner, "_analyze", side_effect=analyze), patch("security_scanner.schedule_worker.shutil.rmtree", side_effect=OSError("cleanup denied")), patch("security_scanner.linux_portal._run_delivery") as deliver:
            result = runner.run_target(target, scheduled_for="2026-09-07")
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["cleanup_status"], "failed")
            self.assertTrue(list(runner.work_dir.iterdir()))
            deliver.assert_not_called()
        runner.recover()
        recovered = self.store.schedule_run(result["schedule_run_id"])
        self.assertEqual(recovered["cleanup_status"], "completed")
        self.assertFalse(list(runner.work_dir.iterdir()))

    def test_timeout_and_cancellation_leave_no_copies(self):
        for cancel, day in ((False, "2026-09-07"), (True, "2026-09-08")):
            runner = self.runner()
            def interrupt(run_id, deadline):
                self.store.mark_run_running(run_id)
                if cancel:
                    self.store.request_cancel(run_id, self.admin)
                raise TimeoutError("bounded analysis")
            with patch.object(runner, "_analyze", side_effect=interrupt):
                result = runner.run_target(self.target, scheduled_for=day)
            self.assertEqual(result["status"], "cancelled" if cancel else "failed")
            self.assertEqual(result["cleanup_status"], "completed")
            self.assertFalse(list(runner.work_dir.iterdir()))

    def test_timeout_really_kills_analyzer_process_group(self):
        runner = self.runner()
        scheduled = self.store.begin_schedule_run(self.target["target_id"], "2026-09-07", "full", 1)
        root = runner.work_dir / "koda-schedule-test"
        archive, _, _ = runner._archive(self.target, [RemoteFile("app.py", 7, 1)], root)
        input_id = self.store.add_input(self.project, "test.tar.gz", archive)
        run = self.store.create_scheduled_scan(self.project, input_id, "local", "all", "source", runner._snapshot(self.target, scheduled, "full", []))
        child = subprocess.Popen(["python3", "-c", "import time; time.sleep(60)"], start_new_session=True)
        try:
            with patch("security_scanner.schedule_worker.subprocess.Popen", return_value=child):
                with self.assertRaises(TimeoutError):
                    runner._analyze(run["run_id"], time.monotonic() + .1)
            self.assertIsNotNone(child.poll())
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()

    def test_disk_shortage_and_manual_work_pause_new_scans(self):
        runner = self.runner()
        with patch.object(runner, "_disk_available", return_value=False), patch.object(runner, "_analyze") as analyze:
            self.assertEqual(runner.run_once(dt.datetime(2026, 9, 7, 2, tzinfo=dt.timezone(dt.timedelta(hours=9)))), [])
            analyze.assert_not_called()
        with patch.object(self.store, "has_active_manual_work", return_value=True), patch.object(runner, "_analyze") as analyze:
            self.assertEqual(runner.run_once(scheduled_for="2026-09-07"), [])
            analyze.assert_not_called()

    def test_portal_restart_cannot_claim_live_scheduled_analysis(self):
        runner = self.runner()
        def analyze(run_id, deadline):
            self.store.mark_run_running(run_id)
            self.assertNotIn(run_id, self.store.recover_incomplete_runs())
            self.assertEqual(self.store.run(run_id)["status"], "running")
            self.store.complete_run(run_id, result={"findings": []})
        with patch.object(runner, "_analyze", side_effect=analyze):
            result = runner.run_target(self.target, scheduled_for="2026-09-07")
        self.assertEqual(result["status"], "completed")

    def test_transfer_limit_and_strict_host_key_options(self):
        from security_scanner.schedule_worker import OpenSSHCollector
        from tests.test_schedule_transport import child_popen
        calls = []
        actual = child_popen(b"x")
        def execute(args, **kwargs):
            calls.append(args)
            return actual(args, **kwargs)
        collector = OpenSSHCollector(popen=execute)
        collector.fetch(self.target, RemoteFile("app.py", 1, 1), Path(self.tmp.name) / "app.py")
        self.assertIn("StrictHostKeyChecking=yes", calls[0])
        self.assertEqual(calls[0][0], "ssh")
        with self.assertRaises(ValueError):
            collector.test_connection({**self.target, "username": "-oProxyCommand=evil"})

    def test_file_limit_failure_moves_to_next_target_without_retrying_forever(self):
        runner = self.runner()
        oversized = self.store.save_schedule_target({**self.target, "max_files": 1}, self.admin)
        runner.collector.files.append(RemoteFile("extra.py", 1, 1))
        first = runner.run_target(oversized, scheduled_for="2026-09-07")
        self.assertEqual(first["status"], "failed")
        with patch.object(runner.collector, "list_files") as listing:
            second = runner.run_target(oversized, scheduled_for="2026-09-07")
            listing.assert_not_called()
        self.assertEqual(second["schedule_run_id"], first["schedule_run_id"])

    def test_transport_retries_have_one_five_fifteen_minute_backoff(self):
        delays, runner = [], self.runner()
        runner._sleep = delays.append
        attempts = []
        def operation():
            attempts.append(1)
            if len(attempts) < 4:
                raise RuntimeError("connection reset")
            return "ok"
        with patch.dict(os.environ, {"KODA_SCHEDULE_NO_SLEEP": "0"}):
            self.assertEqual(runner._retry(operation, self.target), "ok")
        self.assertEqual(delays, [60, 300, 900])


if __name__ == "__main__":
    unittest.main()
