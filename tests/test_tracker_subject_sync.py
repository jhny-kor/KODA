import json
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

from security_scanner.portal_store import PortalStore
from security_scanner.tracker_subject_sync import TrackerSubjectSyncError, TrackerSubjectSynchronizer


class TrackerSubjectSyncTests(unittest.TestCase):
    def make_sync(self, root, store, snapshot):
        snapshot = {"snapshotAt": datetime.now(timezone.utc).isoformat(), "users": snapshot}
        return TrackerSubjectSynchronizer(
            store,
            Path(root) / "tracker-subject-sync.json",
            lambda: snapshot,
        )

    def test_initial_snapshot_enables_new_users_but_preserves_local_disabled_and_tombstone(self):
        with tempfile.TemporaryDirectory() as root:
            store = PortalStore(Path(root) / "portal.db")
            admin = str(uuid.uuid4())
            store.bootstrap(admin)
            disabled, tombstoned, new = (str(uuid.uuid4()) for _ in range(3))
            store.ensure_subject(disabled, "local-disabled")
            store.set_subject(disabled, status="disabled", actor=admin)
            store.ensure_subject(tombstoned, "local-tombstone")
            store.set_subject(tombstoned, status="tombstoned", actor=admin)
            result = self.make_sync(root, store, [
                {"id": disabled, "username": "disabled", "status": "approved"},
                {"id": tombstoned, "username": "tombstone", "status": "approved"},
                {"id": new, "username": "new", "status": "approved"},
            ]).sync()
            self.assertEqual(store.subject(disabled)["status"], "disabled")
            self.assertEqual(store.subject(tombstoned)["status"], "tombstoned")
            self.assertEqual(store.subject(new)["status"], "enabled")
            self.assertEqual(result["skipped"], 2)

    def test_revoke_then_reapprove_reenables_tracker_managed_subject(self):
        with tempfile.TemporaryDirectory() as root:
            store = PortalStore(Path(root) / "portal.db")
            subject = str(uuid.uuid4())
            sync = self.make_sync(root, store, [{"id": subject, "status": "approved"}])
            sync.sync()
            sync.fetch_users = lambda: {"snapshotAt": datetime.now(timezone.utc).isoformat(), "users": [{"id": subject, "status": "revoked"}]}
            sync.sync()
            self.assertEqual(store.subject(subject)["status"], "disabled")
            sync.fetch_users = lambda: {"snapshotAt": datetime.now(timezone.utc).isoformat(), "users": [{"id": subject, "status": "approved"}]}
            sync.sync()
            self.assertEqual(store.subject(subject)["status"], "enabled")

    def test_local_disable_after_revoke_is_never_resurrected(self):
        with tempfile.TemporaryDirectory() as root:
            store = PortalStore(Path(root) / "portal.db")
            subject = str(uuid.uuid4())
            sync = self.make_sync(root, store, [{"id": subject, "status": "approved"}])
            sync.sync()
            sync.fetch_users = lambda: {"snapshotAt": datetime.now(timezone.utc).isoformat(), "users": [{"id": subject, "status": "revoked"}]}
            sync.sync()
            store.set_subject(subject, status="disabled", actor="local-admin")
            sync.fetch_users = lambda: {"snapshotAt": datetime.now(timezone.utc).isoformat(), "users": [{"id": subject, "status": "approved"}]}
            sync.sync()
            self.assertEqual(store.subject(subject)["status"], "disabled")

    def test_missing_or_stale_snapshot_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            store = PortalStore(Path(root) / "portal.db")
            subject = str(uuid.uuid4())
            sync = self.make_sync(root, store, [{"id": subject, "status": "approved"}])
            sync.fetch_users = lambda: {"users": [{"id": subject, "status": "approved"}]}
            with self.assertRaises(TrackerSubjectSyncError):
                sync.sync()
            sync.fetch_users = lambda: {"snapshotAt": "2020-01-01T00:00:00Z", "users": [{"id": subject, "status": "approved"}]}
            with self.assertRaises(TrackerSubjectSyncError):
                sync.sync()

    def test_malformed_or_failed_snapshot_is_durable_and_does_not_mutate(self):
        with tempfile.TemporaryDirectory() as root:
            store = PortalStore(Path(root) / "portal.db")
            subject = str(uuid.uuid4())
            sync = self.make_sync(root, store, [{"id": subject, "status": "approved"}])
            sync.sync()
            sync.fetch_users = lambda: {"snapshotAt": datetime.now(timezone.utc).isoformat(), "users": [{"id": subject, "status": "approved"}, {"id": subject, "status": "approved"}]}
            with self.assertRaises(TrackerSubjectSyncError):
                sync.sync()
            self.assertEqual(store.subject(subject)["status"], "enabled")
            state = json.loads((Path(root) / "tracker-subject-sync.json").read_text())
            self.assertTrue(state["pending"])
            self.assertEqual(state["attempts"], 1)


if __name__ == "__main__":
    unittest.main()
