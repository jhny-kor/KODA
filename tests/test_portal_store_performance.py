"""Response-size and writer-lock regressions for portal query paths."""
import contextlib
import json
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from security_scanner.portal_store import PortalStore


class PortalStorePerformanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = PortalStore(self.root / "portal.sqlite3")
        self.admin = str(uuid.uuid4())
        self.store.ensure_subject(self.admin, "admin")
        self.store.set_subject(self.admin, status="enabled", system_admin=True)
        self.project = self.store.create_project("performance", self.admin)

    def create_run(self, findings=None, *, scope="source", project=None):
        path = self.root / (uuid.uuid4().hex + ".py")
        path.write_text("print(1)\n")
        project = project or self.project
        input_id = self.store.add_input(project, path.name, path, self.admin)
        run = self.store.create_scan(self.admin, project, input_id, "local", "all", scope)
        if findings is not None:
            self.store.complete_run(run["run_id"], {"findings": findings, "analysis_stages": {"source": {"status": "completed"}}})
        return run

    @contextlib.contextmanager
    def reject_column(self, column):
        original = self.store._db
        @contextlib.contextmanager
        def guarded():
            with original() as db:
                db.set_authorizer(lambda action, table, name, *_: sqlite3.SQLITE_DENY
                                  if action == sqlite3.SQLITE_READ and table == "scan_runs" and name == column
                                  else sqlite3.SQLITE_OK)
                yield db
        with patch.object(self.store, "_db", guarded):
            yield

    def test_unchanged_subject_authentication_never_requests_writer_lock(self):
        before = self.store.subject(self.admin)
        with contextlib.closing(sqlite3.connect(self.store.path, isolation_level=None)) as writer:
            writer.execute("BEGIN IMMEDIATE")
            original = self.store._db
            @contextlib.contextmanager
            def impatient():
                with original() as db:
                    db.execute("PRAGMA busy_timeout=20")
                    yield db
            with patch.object(self.store, "_db", impatient):
                self.assertEqual(self.store.ensure_subject(self.admin, "admin"), before)
            writer.execute("ROLLBACK")

    def test_result_serialization_keeps_writer_available_and_late_cancel_wins(self):
        run = self.create_run()
        self.assertTrue(self.store.mark_run_running(run["run_id"]))
        payload = {"findings": [{"severity": "high", "title": "payload"}]}
        original = self.store._json
        def serialize(value):
            if value is payload:
                with contextlib.closing(sqlite3.connect(self.store.path, timeout=.02, isolation_level=None)) as other:
                    other.execute("UPDATE scan_runs SET cancel_requested=1,status='cancelling' WHERE run_id=?", (run["run_id"],))
            return original(value)
        with patch.object(self.store, "_json", serialize):
            self.store.complete_run(run["run_id"], payload)
        saved = self.store.run(run["run_id"])
        self.assertEqual(saved["status"], "cancelled")
        self.assertIsNone(saved["result"])

    def test_list_status_and_dashboard_do_not_select_full_results(self):
        run = self.create_run([{"severity": "high", "category": "code", "context": "x" * 200000}])
        with self.reject_column("result_json"):
            rows = self.store.list_runs(self.project)
            self.assertEqual(rows[0]["run_id"], run["run_id"])
            status = self.store.run_status(run["run_id"])
            self.assertEqual(status["status"], "completed")
            self.assertNotIn("snapshot", status)
            dashboard = self.store.dashboard_summary([self.project])
            self.assertEqual(dashboard["severity_counts"]["high"], 1)
        self.assertLess(len(json.dumps(dashboard)), 5000)

    def test_pagination_filters_before_limit_and_preserves_total(self):
        runs = [self.create_run([], scope=scope) for scope in ("source", "library", "source", "library", "source")]
        rows = self.store.paginate_runs([self.project], page=2, page_size=2, scan_scope="source", status="completed", source="manual")
        self.assertEqual(rows["total"], 3)
        self.assertEqual([row["run_id"] for row in rows["items"]], [runs[0]["run_id"]])
        self.assertEqual(self.store.paginate_runs([], page_size=50)["items"], [])
        self.assertEqual(self.store.project_summary(self.project), {"input_count": 5, "run_count": 5})

    def test_finding_pages_keep_stable_indexes_and_omit_source_context(self):
        run = self.create_run([
            {"severity": "high", "category": "code", "title": "one", "verification_status": "confirmed", "context": "private context"},
            {"severity": "low", "category": "dependencies", "title": "two"},
            {"severity": "high", "category": "code", "title": "three", "context": "x" * 100000},
        ])
        page = self.store.run_findings(run["run_id"], page=2, page_size=1, group="source", severity="high")
        self.assertEqual(page["total"], 2)
        self.assertEqual(page["items"][0]["finding_index"], 2)
        self.assertNotIn("context", page["items"][0])
        self.assertEqual(self.store.run_finding(run["run_id"], 0)["context"], "private context")
        summary = self.store.run_summary(run["run_id"])
        self.assertEqual(summary["result"]["group_counts"], {"source": 2, "library": 1, "quality": 0})
        self.assertNotIn("findings", summary["result"])
        with self.assertRaises(KeyError):
            self.store.run_finding(run["run_id"], 99)

    def test_legacy_summary_is_upgraded_without_returning_full_context(self):
        run = self.create_run([{"severity": "critical", "category": "dependencies", "context": "x" * 100000}])
        with self.store._db() as db:
            db.execute("UPDATE scan_runs SET result_summary_json=NULL WHERE run_id=?", (run["run_id"],))
        summary = self.store.run_summary(run["run_id"])
        self.assertEqual(summary["result"]["severity_counts"]["critical"], 1)
        self.assertLess(len(json.dumps(summary)), 5000)
        self.assertEqual(self.store.dashboard_summary([self.project])["severity_counts"]["critical"], 1)

    def test_legacy_dashboard_never_traverses_results_and_worker_backfill_is_bounded(self):
        runs = [self.create_run([{"severity": "high", "context": "x" * 100000}]) for _ in range(3)]
        with self.store._db() as db:
            db.execute("UPDATE scan_runs SET result_summary_json=NULL")
        with self.reject_column("result_json"):
            summary = self.store.dashboard_summary([self.project])
        self.assertEqual(summary["summary_pending"], 3)
        self.assertTrue(summary["projects"][0]["latest_completed"]["summary_pending"])
        self.assertIsNone(summary["projects"][0]["latest_completed"]["result"])
        self.assertEqual(self.store.backfill_result_summaries(limit=1), 1)
        self.assertEqual(self.store.dashboard_summary([self.project])["summary_pending"], 2)
        self.assertEqual(self.store.backfill_result_summaries(limit=10), 2)
        final = self.store.dashboard_summary([self.project])
        self.assertEqual(final["summary_pending"], 0)
        self.assertEqual(final["severity_counts"]["high"], len(runs))

    def test_summary_metadata_is_bounded_and_preserves_only_display_fields(self):
        result = {
            "findings": [], "scan": {"scope": "source", "path": "x" * 100000, "internal": "x" * 100000},
            "analysis_stages": {"source": {"status": "completed", "internal": "x" * 100000}},
            "warnings": ["x" * 100000] * 100,
        }
        summary = self.store._result_summary(result)
        self.assertLess(len(json.dumps(summary)), 25000)
        self.assertEqual(summary["scan"]["scope"], "source")
        self.assertNotIn("internal", summary["scan"])
        self.assertNotIn("internal", summary["analysis_stages"]["source"])

    def test_dashboard_omits_large_schedule_snapshot_and_detail_preserves_it(self):
        run = self.create_run([])
        snapshot = {**run["snapshot"], "changed_files": ["x" * 1000] * 1000}
        with self.store._db() as db:
            db.execute("UPDATE scan_runs SET snapshot_json=? WHERE run_id=?", (json.dumps(snapshot), run["run_id"]))
        dashboard = self.store.dashboard_summary([self.project])
        self.assertLess(len(json.dumps(dashboard)), 5000)
        self.assertNotIn("changed_files", dashboard["projects"][0]["latest"]["snapshot"])
        self.assertEqual(len(self.store.run_summary(run["run_id"])["snapshot"]["changed_files"]), 1000)

    def test_terminal_completion_is_idempotent_and_cannot_overwrite_result(self):
        run = self.create_run([{"title": "first"}])
        self.store.complete_run(run["run_id"], {"findings": [{"title": "late child"}]}, error="late supervisor")
        saved = self.store.run(run["run_id"])
        self.assertEqual(saved["status"], "completed")
        self.assertEqual(saved["result"]["findings"], [{"title": "first"}])

    def test_result_deletion_removes_cached_summary_and_dashboard_counts(self):
        run = self.create_run([{"severity": "critical", "category": "code"}])
        self.store.delete_run(run['run_id'], self.admin)
        with self.store._db() as db:
            row = db.execute('SELECT result_json,result_summary_json FROM scan_runs WHERE run_id=?', (run['run_id'],)).fetchone()
        self.assertIsNone(row['result_json'])
        self.assertIsNone(row['result_summary_json'])
        self.assertEqual(self.store.dashboard_summary([self.project])['severity_counts']['critical'], 0)

    def test_status_publication_pending_covers_optional_durable_jobs(self):
        run = self.create_run([])
        self.assertFalse(self.store.run_status(run["run_id"])["publication_pending"])
        with self.store._db() as db:
            db.execute("CREATE TABLE portal_delivery_jobs(run_id TEXT,status TEXT)")
            db.execute("INSERT INTO portal_delivery_jobs VALUES(?,'queued')", (run["run_id"],))
        self.assertTrue(self.store.run_status(run["run_id"])["publication_pending"])
        with self.store._db() as db:
            db.execute("UPDATE portal_delivery_jobs SET status='completed'")
        self.assertFalse(self.store.run_status(run["run_id"])["publication_pending"])

    def test_schedule_pagination_keeps_failures_without_result_and_omits_metadata(self):
        target = self.store.save_schedule_target({
            "project_id": self.project, "name": "server", "host": "server.internal", "username": "scan",
            "ssh_key_ref": "/run/koda/ssh/key", "known_hosts_file": "/run/koda/ssh/known_hosts",
            "remote_directory": "/srv/app", "scan_scope": "source", "enabled": True,
        }, self.admin)
        for day in ("2026-10-01", "2026-10-02", "2026-10-03"):
            row = self.store.begin_schedule_run(target["target_id"], day, "full", target["config_version"])
            self.store.update_schedule_run(row["schedule_run_id"], status="failed", metadata={"large": "x" * 100000})
        rows = self.store.paginate_schedule_runs([self.project], page=2, page_size=2, status="failed", scan_scope="source")
        self.assertEqual(rows["total"], 3)
        self.assertEqual(len(rows["items"]), 1)
        self.assertIsNone(rows["items"][0]["run_id"])
        self.assertEqual(rows["items"][0]["metadata"], {})
        self.assertIn("server.internal", rows["items"][0]["round_label"])

    def test_queued_publication_blocks_run_and_project_deletion_until_finished(self):
        from security_scanner.portal_worker import enqueue_delivery
        run = self.create_run([])
        self.store.set_role_policy({"admin": ["runs.delete", "project.delete"]}, self.store.role_policy()["version"], self.admin)
        enqueue_delivery(self.store, "tracker", run["run_id"])
        with self.assertRaisesRegex(ValueError, "전송"):
            self.store.delete_run(run["run_id"], self.admin)
        with self.assertRaisesRegex(ValueError, "전송"):
            self.store.delete_project(self.project, self.admin)
        with self.store._db() as db:
            db.execute("UPDATE portal_delivery_jobs SET status='completed'")
        self.store.delete_run(run["run_id"], self.admin)
        self.store.delete_project(self.project, self.admin)
        with self.store._db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM portal_delivery_jobs").fetchone()[0], 0)

    def test_retention_preserves_queued_publication_then_removes_terminal_job_history(self):
        from security_scanner.portal_worker import enqueue_delivery
        run = self.create_run([])
        target = self.store.save_schedule_target({
            "project_id": self.project, "name": "retention", "host": "server.internal", "username": "scan",
            "ssh_key_ref": "/run/koda/ssh/key", "known_hosts_file": "/run/koda/ssh/known_hosts",
            "remote_directory": "/srv/app", "scan_scope": "source", "enabled": True,
        }, self.admin)
        scheduled = self.store.begin_schedule_run(target["target_id"], "2020-01-01", "full", target["config_version"])
        self.store.update_schedule_run(scheduled["schedule_run_id"], run_id=run["run_id"], status="completed", cleanup_status="completed")
        with self.store._db() as db:
            db.execute("UPDATE schedule_runs SET created_at='2020-01-01' WHERE schedule_run_id=?", (scheduled["schedule_run_id"],))
        enqueue_delivery(self.store, "tracker", run["run_id"])
        self.assertEqual(self.store.prune_schedule_runs(1), 0)
        with self.store._db() as db:
            db.execute("UPDATE portal_delivery_jobs SET status='failed'")
        self.assertEqual(self.store.prune_schedule_runs(1), 1)
        with self.assertRaises(KeyError):
            self.store.run(run["run_id"])
        with self.store._db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM portal_delivery_jobs").fetchone()[0], 0)

    def test_tombstoned_subject_is_not_updated_by_authentication(self):
        subject = str(uuid.uuid4())
        self.store.ensure_subject(subject, "before")
        self.store.set_subject(subject, status="tombstoned")
        self.assertEqual(self.store.ensure_subject(subject, "after")["display"], "before")


if __name__ == "__main__":
    unittest.main()
