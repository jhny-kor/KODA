"""Production schedule publication belongs to the delivery worker."""
import contextlib
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

from security_scanner import schedule_api
from security_scanner.portal_store import PortalStore


class PortalScheduleDeliveryTests(unittest.TestCase):
    def test_external_tick_never_starts_publisher_or_resets_live_deliveries(self):
        store = MagicMock()
        store.path = "fixture.sqlite3"
        with patch.dict(os.environ, {"KODA_PORTAL_EXTERNAL_WORKER": "1"}), \
                patch.dict(schedule_api._TICKS, {}, clear=True), \
                patch("security_scanner.schedule_worker.ScheduleRunner") as runner, \
                patch.object(schedule_api.threading, "Thread") as thread:
            schedule_api._tick(store)
            thread.assert_not_called()
            runner.assert_not_called()
            store._db.assert_not_called()
            self.assertEqual(schedule_api._TICKS, {})

    def test_legacy_tick_keeps_recovery_publication_and_retention_behavior(self):
        store = MagicMock()
        store.path = "fixture.sqlite3"
        with patch.dict(os.environ, {"KODA_PORTAL_EXTERNAL_WORKER": "0"}), \
                patch.dict(schedule_api._TICKS, {}, clear=True), \
                patch("security_scanner.schedule_worker.ScheduleRunner") as runner, \
                patch.object(schedule_api.threading, "Thread") as thread:
            schedule_api._tick(store)
            self.assertTrue(schedule_api._TICKS[store.path])
            thread.return_value.start.assert_called_once_with()
            db = store._db.return_value.__enter__.return_value
            recovery = [call.args[0] for call in db.execute.call_args_list]
            self.assertEqual(len(recovery), 3)
            self.assertTrue(all("='pending'" in sql and "='sending'" in sql for sql in recovery))
            thread.call_args.kwargs["target"]()
            runner.assert_called_once_with(store)
            runner.return_value.retry_deliveries.assert_called_once_with()
            store.prune_schedule_runs.assert_called_once_with(90)
            self.assertFalse(schedule_api._TICKS[store.path])
            self.assertIn("DELETE FROM schedule_api_receipts", db.execute.call_args.args[0])


class ScheduledPublicationOwnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = PortalStore(self.root / "portal.sqlite3")
        self.actor = str(uuid.uuid4())
        self.store.bootstrap(self.actor)
        self.project = self.store.create_project("scheduled-delivery", self.actor)
        self.target = self.store.save_schedule_target({
            "project_id": self.project, "name": "server", "host": "server.internal", "username": "scan",
            "ssh_key_ref": "/run/koda/ssh/key", "known_hosts_file": "/run/koda/ssh/known_hosts",
            "remote_directory": "/srv/app", "scan_scope": "source", "enabled": True,
        }, self.actor)

    def scheduled(self, day, *, cleanup="completed", status="completed"):
        scheduled = self.store.begin_schedule_run(self.target["target_id"], day, "full", self.target["config_version"])
        source = self.root / (uuid.uuid4().hex + ".py")
        source.write_text("print(1)")
        input_id = self.store.add_input(self.project, source.name, source)
        run = self.store.create_scheduled_scan(self.project, input_id, "local", "all", "source", {
            "source_type": "scheduled_server", "schedule_run_id": scheduled["schedule_run_id"],
            "schedule_target_id": self.target["target_id"], "remote_server": "server.internal",
            "remote_directory": "/srv/app", "gitlab_mapping_id": "fixture-mapping", "gitlab_project_id": 42,
            "gitlab_path_with_namespace": "group/project", "scheduled_for": day,
        })
        self.store.complete_run(run["run_id"], {"findings": []})
        self.store.update_schedule_run(scheduled["schedule_run_id"], status=status, cleanup_status=cleanup)
        return scheduled["schedule_run_id"], run["run_id"]

    def acknowledge(self, store, kind, run_id, *, retry=False):
        if kind == "tracker":
            store.claim_tracker_delivery(run_id, retry=retry)
            return store.finish_tracker_delivery(run_id, "completed", tracker_run_id="fixture-remote")
        if kind == "gitlab_result":
            store.claim_gitlab_result(run_id, retry=retry)
            return store.finish_gitlab_result(run_id, "completed", merge_request_url="https://gitlab.example/mr/1")
        store.claim_gitlab_issue_delivery(run_id, retry=retry)
        return store.finish_gitlab_issue_delivery(run_id)

    def test_delivery_owner_publishes_only_completed_clean_results_and_projects_status(self):
        from security_scanner.portal_worker import process_scheduled_publications
        eligible, eligible_run = self.scheduled("2026-10-01")
        pending_cleanup, pending_run = self.scheduled("2026-10-02", cleanup="pending")
        failed, failed_run = self.scheduled("2026-10-03", status="failed")
        with patch("security_scanner.linux_portal._run_delivery", side_effect=self.acknowledge) as publication:
            process_scheduled_publications(self.store)
            self.assertEqual([call.args[1:3] for call in publication.call_args_list], [
                ("tracker", eligible_run), ("gitlab_result", eligible_run), ("issues", eligible_run),
            ])
            process_scheduled_publications(self.store)
            self.assertEqual(publication.call_count, 3)
        projected = self.store.schedule_run(eligible)
        self.assertEqual((projected["tracker_status"], projected["gitlab_status"]), ("completed", "completed"))
        for schedule_id, run_id in ((pending_cleanup, pending_run), (failed, failed_run)):
            self.assertEqual(self.store.tracker_delivery(run_id)["status"], "pending")
            self.assertEqual(self.store.gitlab_issue_delivery(run_id)["status"], "pending")
            self.assertEqual(self.store.schedule_run(schedule_id)["tracker_status"], "pending")

    def test_external_tick_preserves_sending_until_delivery_owner_recovers(self):
        from security_scanner.portal_worker import recover_scheduled_publications
        scheduled, run_id = self.scheduled("2026-10-01")
        with self.store._db() as db:
            db.execute("UPDATE tracker_deliveries SET status='sending',gitlab_result_status='sending' WHERE run_id=?", (run_id,))
            db.execute("UPDATE gitlab_issue_deliveries SET status='sending' WHERE run_id=?", (run_id,))
        with patch.dict(os.environ, {"KODA_PORTAL_EXTERNAL_WORKER": "1"}):
            schedule_api._tick(self.store)
        self.assertEqual(self.store.tracker_delivery(run_id)["status"], "sending")
        recover_scheduled_publications(self.store)
        delivery = self.store.tracker_delivery(run_id)
        self.assertEqual((delivery["status"], delivery["gitlab_result_status"]), ("pending", "pending"))
        self.assertEqual(self.store.gitlab_issue_delivery(run_id)["status"], "pending")

    def test_scheduled_result_encoding_keeps_writer_free_and_cached_summary_matches(self):
        from security_scanner.schedule_settings import save_settings
        schedule_api._ensure(self.store)
        save_settings(self.store, {"enabled": True, "min_free_bytes": 0, "gap_seconds": 0})
        self.store.begin_schedule_run(self.target["target_id"], "2026-10-01", "full", self.target["config_version"])
        job = schedule_api._next(self.store, "fixture-worker")["job"]
        result = {"findings": [{"category": "code", "severity": "high", "title": "fixture", "context": "x" * 100000}]}
        payload = {
            "schedule_run_id": job["schedule_run_id"], "lease_token": job["lease_token"], "result": result,
            "manifest": [{"relative_path": "app.py", "size": 9, "mtime": 1, "sha256": hashlib.sha256(b"print(1)\n").hexdigest()}],
            "counts": {"files_total": 1, "changed_files": 1, "changed_paths": ["app.py"]},
        }
        lease, context, row = schedule_api._leased(self.store, payload)
        original = self.store._json
        result_encodes = []
        def encode(value):
            if value is result:
                with contextlib.closing(sqlite3.connect(self.store.path, timeout=.02, isolation_level=None)) as other:
                    other.execute("BEGIN IMMEDIATE")
                    other.execute("ROLLBACK")
                result_encodes.append(True)
            return original(value)
        with patch.object(self.store, "_json", side_effect=encode):
            reply = schedule_api._persist(self.store, row, context, payload)
        self.assertEqual(len(result_encodes), 1)
        saved = self.store.run(reply["run_id"])
        self.assertEqual(saved["result"], result)
        self.assertEqual(saved["snapshot"], {**context["snapshot"], "files_total": 1, "changed_files": ["app.py"]})
        with self.store._db() as db:
            persisted = db.execute("SELECT snapshot_json,result_json,result_summary_json FROM scan_runs WHERE run_id=?", (reply["run_id"],)).fetchone()
            revision = db.execute("SELECT snapshot_json,result_json FROM analysis_revisions WHERE run_id=?", (reply["run_id"],)).fetchone()
            self.assertEqual((revision["snapshot_json"], revision["result_json"]), (persisted["snapshot_json"], persisted["result_json"]))
            self.assertEqual(json.loads(persisted["result_summary_json"]), self.store._result_summary(result))
            live_lease = dict(db.execute("SELECT * FROM schedule_api_lease WHERE slot=1").fetchone())
        self.assertEqual(live_lease, lease)
        fingerprint = hashlib.sha256(schedule_api._json_bytes({"result": result, "manifest": payload["manifest"], "counts": payload["counts"]})).hexdigest()
        self.assertEqual(self.store.schedule_run(job["schedule_run_id"])["metadata"]["result_digest"], fingerprint)
        _, context, latest = schedule_api._leased(self.store, payload)
        self.assertEqual(schedule_api._persist(self.store, latest, context, payload), reply)


if __name__ == "__main__":
    unittest.main()
