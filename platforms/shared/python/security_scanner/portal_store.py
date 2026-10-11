"""Durable SQLite state for the authenticated Linux portal."""
from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import shutil
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path

from .models import SCAN_SCOPE_CATEGORIES


SCREEN_PERMISSIONS = frozenset({
    "dashboard.view", "scan.library.view", "scan.source.view", "runs.view", "compare.view", "projects.view",
})
SCOPED_SCAN_PERMISSIONS = frozenset({"scan.library.create", "scan.source.create"})
FEATURE_PERMISSIONS = frozenset({
    "input.manage", "scan.create", *SCOPED_SCAN_PERMISSIONS, "project.manage",
    "runs.export", "runs.delete", "runs.tracker.publish", "runs.gitlab.result.publish",
    "runs.gitlab.issues.publish", "project.create", "project.delete",
})
LEGACY_PROJECT_PERMISSION = "project.view"
DEFAULT_ROLE_PERMISSIONS = {
    "admin": {*SCREEN_PERMISSIONS, "runs.export", "input.manage", *SCOPED_SCAN_PERMISSIONS, "project.manage"},
    "manager": {*SCREEN_PERMISSIONS, "runs.export", "input.manage", *SCOPED_SCAN_PERMISSIONS},
    "analyst": {*SCREEN_PERMISSIONS, "runs.export", "input.manage", *SCOPED_SCAN_PERMISSIONS},
    "uploader": {"dashboard.view", "scan.library.view", "scan.source.view", "runs.view", "runs.export", "projects.view", "input.manage", *SCOPED_SCAN_PERMISSIONS},
    "viewer": {"dashboard.view", "runs.view", "runs.export", "projects.view"},
}
PROJECT_PERMISSIONS = frozenset().union(*DEFAULT_ROLE_PERMISSIONS.values(), FEATURE_PERMISSIONS, {LEGACY_PROJECT_PERMISSION, "scan.create"})
RESERVED_PERMISSIONS = {"system.admin", "subjects.manage", "roles.manage", "rules.manage"}
TERMINAL_RUN_STATUSES = frozenset({"completed", "failed", "cancelled"})
GLOBAL_ROLE_POLICY_ID = "__koda_global__"


class VersionConflict(ValueError):
    pass


class UploadQuotaExceeded(ValueError):
    pass


MAX_UPLOAD_FILES = 10_000

# Result blobs can contain many megabytes of source context. Metadata queries
# deliberately name their columns so adding a result column never bloats them.
RUN_METADATA_COLUMNS = (
    "run_id", "project_id", "round_number", "status", "standard", "standard_category",
    "input_id", "policy_version", "requested_by", "error", "created_at", "completed_at",
    "stage", "progress", "cancel_requested", "deleted_at",
)
SCHEDULE_RUN_METADATA_COLUMNS = (
    "schedule_run_id", "target_id", "scheduled_for", "mode", "status", "stage", "config_version",
    "run_id", "files_total", "changed_files", "cleanup_status", "cleanup_error", "tracker_status",
    "gitlab_status", "error", "started_at", "completed_at", "created_at", "updated_at",
)
RUN_LIST_SNAPSHOT_SQL = (
    "json_object('scan_scope',COALESCE(json_extract(r.snapshot_json,'$.scan_scope'),'all'),"
    "'source_type',json_extract(r.snapshot_json,'$.source_type')) AS snapshot_json"
)


class PortalStore:
    def __init__(self, path: str | Path):
        self.path = str(Path(path).expanduser())
        self._lock = threading.RLock()
        self._upload_locks: dict[str, tuple[int, Path]] = {}
        self._init()

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            yield db
        finally:
            db.close()

    def _init(self) -> None:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS subjects(
                  subject_id TEXT PRIMARY KEY, display TEXT NOT NULL,
                  status TEXT NOT NULL CHECK(status IN ('pending','enabled','disabled','tombstoned')),
                  system_admin INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS projects(
                  project_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS memberships(
                  project_id TEXT NOT NULL, subject_id TEXT NOT NULL, role TEXT NOT NULL,
                  PRIMARY KEY(project_id,subject_id),
                  FOREIGN KEY(project_id) REFERENCES projects(project_id),
                  FOREIGN KEY(subject_id) REFERENCES subjects(subject_id));
                CREATE TABLE IF NOT EXISTS role_policies(
                  project_id TEXT NOT NULL, version INTEGER NOT NULL,
                  roles_json TEXT NOT NULL, hash TEXT NOT NULL, created_at TEXT NOT NULL,
                  PRIMARY KEY(project_id,version));
                CREATE TABLE IF NOT EXISTS portal_migrations(
                  migration_id TEXT PRIMARY KEY, applied_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS inputs(
                  input_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, name TEXT NOT NULL,
                  path TEXT NOT NULL, content_hash TEXT NOT NULL, created_at TEXT NOT NULL,
                  FOREIGN KEY(project_id) REFERENCES projects(project_id));
                CREATE TABLE IF NOT EXISTS upload_reservations(
                  reservation_id TEXT PRIMARY KEY, root TEXT NOT NULL,
                  temporary_path TEXT NOT NULL, target_path TEXT NOT NULL,
                  reserved_bytes INTEGER NOT NULL, created_at TEXT NOT NULL,
                  owner_lock INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS rule_policies(
                  project_id TEXT NOT NULL, version INTEGER NOT NULL,
                  rules_json TEXT NOT NULL, hash TEXT NOT NULL, created_at TEXT NOT NULL,
                  PRIMARY KEY(project_id,version));
                CREATE TABLE IF NOT EXISTS scan_runs(
                  run_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, round_number INTEGER NOT NULL,
                  status TEXT NOT NULL, standard TEXT NOT NULL, standard_category TEXT NOT NULL,
                  input_id TEXT NOT NULL, policy_version INTEGER NOT NULL, requested_by TEXT NOT NULL,
                  snapshot_json TEXT NOT NULL, result_json TEXT, error TEXT,
                  created_at TEXT NOT NULL, completed_at TEXT,
                  stage TEXT NOT NULL DEFAULT 'queued', progress INTEGER NOT NULL DEFAULT 0,
                  cancel_requested INTEGER NOT NULL DEFAULT 0,
                  UNIQUE(project_id,round_number));
                CREATE TABLE IF NOT EXISTS analysis_revisions(
                  revision_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                  snapshot_json TEXT NOT NULL, result_json TEXT, created_at TEXT NOT NULL,
                  UNIQUE(run_id,sequence));
                CREATE TABLE IF NOT EXISTS audit_events(
                  id INTEGER PRIMARY KEY AUTOINCREMENT, subject_id TEXT, action TEXT NOT NULL,
                  project_id TEXT, detail_json TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS gitlab_repositories(
                  mapping_id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
                  gitlab_project_id INTEGER NOT NULL UNIQUE, path_with_namespace TEXT NOT NULL,
                  name TEXT NOT NULL, default_branch TEXT NOT NULL DEFAULT '',
                  tracker_service_id TEXT NOT NULL, tracker_environment_id TEXT NOT NULL,
                  tracker_token_ref TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                  FOREIGN KEY(project_id) REFERENCES projects(project_id));
                CREATE TABLE IF NOT EXISTS server_connections(
                  connection_id TEXT PRIMARY KEY, name TEXT NOT NULL,
                  host TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 22,
                  username TEXT NOT NULL, ssh_key_ref TEXT NOT NULL,
                  known_hosts_file TEXT NOT NULL, host_key_fingerprint TEXT NOT NULL DEFAULT '',
                  enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS project_server_connections(
                  project_id TEXT NOT NULL, connection_id TEXT NOT NULL,
                  created_at TEXT NOT NULL, PRIMARY KEY(project_id,connection_id),
                  FOREIGN KEY(project_id) REFERENCES projects(project_id),
                  FOREIGN KEY(connection_id) REFERENCES server_connections(connection_id));
                CREATE INDEX IF NOT EXISTS idx_server_connections_enabled ON server_connections(enabled,name);
                CREATE TABLE IF NOT EXISTS tracker_deliveries(
                  run_id TEXT PRIMARY KEY, status TEXT NOT NULL,
                  attempts INTEGER NOT NULL DEFAULT 0, tracker_run_id TEXT,
                  last_error TEXT, gitlab_merge_request_url TEXT,
                  gitlab_issue_urls_json TEXT NOT NULL DEFAULT '[]',
                  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                  FOREIGN KEY(run_id) REFERENCES scan_runs(run_id));
                CREATE TABLE IF NOT EXISTS gitlab_issue_deliveries(
                  run_id TEXT PRIMARY KEY, status TEXT NOT NULL,
                  attempts INTEGER NOT NULL DEFAULT 0, total_count INTEGER NOT NULL DEFAULT 0,
                  created_count INTEGER NOT NULL DEFAULT 0, reused_count INTEGER NOT NULL DEFAULT 0,
                  failed_count INTEGER NOT NULL DEFAULT 0, last_error TEXT,
                  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                  FOREIGN KEY(run_id) REFERENCES scan_runs(run_id));
                CREATE TABLE IF NOT EXISTS gitlab_issue_links(
                  link_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, gitlab_project_id INTEGER NOT NULL,
                  finding_key TEXT NOT NULL, finding_index INTEGER NOT NULL, status TEXT NOT NULL,
                  issue_iid INTEGER, issue_url TEXT, last_error TEXT,
                  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                  UNIQUE(run_id,finding_key),
                  FOREIGN KEY(run_id) REFERENCES scan_runs(run_id));
                CREATE INDEX IF NOT EXISTS idx_gitlab_issue_links_finding
                  ON gitlab_issue_links(gitlab_project_id,finding_key,created_at DESC);
                CREATE TABLE IF NOT EXISTS schedule_targets(
                  target_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, name TEXT NOT NULL,
                  host TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 22, username TEXT NOT NULL,
                  ssh_key_ref TEXT NOT NULL, known_hosts_file TEXT NOT NULL, remote_directory TEXT NOT NULL,
                  exclude_json TEXT NOT NULL DEFAULT '[]', standard TEXT NOT NULL DEFAULT 'local',
                  standard_category TEXT NOT NULL DEFAULT 'all', scan_scope TEXT NOT NULL DEFAULT 'all',
                  disabled_rules_json TEXT NOT NULL DEFAULT '[]', gitlab_mapping_id TEXT,
                  gitlab_target_branch TEXT NOT NULL DEFAULT '',
                  source_kind TEXT NOT NULL DEFAULT 'server',
                  schedule_frequency TEXT NOT NULL DEFAULT 'daily',
                  schedule_time TEXT NOT NULL DEFAULT '01:00',
                  schedule_weekdays_json TEXT NOT NULL DEFAULT '[0,1,2,3,4,5,6]',
                  schedule_interval_hours INTEGER NOT NULL DEFAULT 24,
                  source_gitlab_mapping_id TEXT, source_gitlab_ref TEXT NOT NULL DEFAULT '',
                  source_gitlab_ref_type TEXT NOT NULL DEFAULT 'branch',
                  source_gitlab_directory TEXT NOT NULL DEFAULT '',
                  server_connection_id TEXT,
                  enabled INTEGER NOT NULL DEFAULT 0, order_index INTEGER NOT NULL DEFAULT 0,
                  config_version INTEGER NOT NULL DEFAULT 1, max_files INTEGER NOT NULL DEFAULT 200000,
                  max_bytes INTEGER NOT NULL DEFAULT 2147483648, timeout_seconds INTEGER NOT NULL DEFAULT 21600,
                  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                  FOREIGN KEY(project_id) REFERENCES projects(project_id));
                CREATE INDEX IF NOT EXISTS idx_schedule_targets_order ON schedule_targets(enabled,order_index,target_id);
                CREATE TABLE IF NOT EXISTS schedule_runs(
                  schedule_run_id TEXT PRIMARY KEY, target_id TEXT NOT NULL, scheduled_for TEXT NOT NULL,
                  mode TEXT NOT NULL CHECK(mode IN ('full','changed')), status TEXT NOT NULL DEFAULT 'queued',
                  stage TEXT NOT NULL DEFAULT 'queued', config_version INTEGER NOT NULL DEFAULT 1,
                  run_id TEXT, files_total INTEGER NOT NULL DEFAULT 0, changed_files INTEGER NOT NULL DEFAULT 0,
                  cleanup_status TEXT NOT NULL DEFAULT 'pending', cleanup_error TEXT,
                  tracker_status TEXT NOT NULL DEFAULT 'pending', gitlab_status TEXT NOT NULL DEFAULT 'pending',
                  error TEXT, metadata_json TEXT NOT NULL DEFAULT '{}',
                  started_at TEXT, completed_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                  UNIQUE(target_id,scheduled_for),
                  FOREIGN KEY(target_id) REFERENCES schedule_targets(target_id),
                  FOREIGN KEY(run_id) REFERENCES scan_runs(run_id));
                CREATE INDEX IF NOT EXISTS idx_schedule_runs_target ON schedule_runs(target_id,scheduled_for DESC);
                CREATE TABLE IF NOT EXISTS schedule_files(
                  target_id TEXT NOT NULL, relative_path TEXT NOT NULL, size INTEGER NOT NULL,
                  mtime REAL NOT NULL, sha256 TEXT NOT NULL, updated_at TEXT NOT NULL,
                  PRIMARY KEY(target_id,relative_path), FOREIGN KEY(target_id) REFERENCES schedule_targets(target_id));
                """
            )
            input_columns = {row[1] for row in db.execute("PRAGMA table_info(inputs)")}
            reservation_columns = {row[1] for row in db.execute("PRAGMA table_info(upload_reservations)")}
            if "owner_lock" not in reservation_columns:
                # Legacy reservations have no reliable owner liveness signal.
                db.execute("ALTER TABLE upload_reservations ADD COLUMN owner_lock INTEGER NOT NULL DEFAULT 0")
            if "registered_by" not in input_columns:
                db.execute("ALTER TABLE inputs ADD COLUMN registered_by TEXT")
                for event in db.execute("SELECT subject_id,detail_json FROM audit_events WHERE action='input.created' ORDER BY id"):
                    detail = json.loads(event["detail_json"])
                    db.execute("UPDATE inputs SET registered_by=? WHERE input_id=? AND registered_by IS NULL", (event["subject_id"], detail.get("input_id")))
            columns = {row[1] for row in db.execute("PRAGMA table_info(scan_runs)")}
            for definition in (
                "deleted_at TEXT",
                "result_summary_json TEXT",
                "stage TEXT NOT NULL DEFAULT 'queued'",
                "progress INTEGER NOT NULL DEFAULT 0",
                "cancel_requested INTEGER NOT NULL DEFAULT 0",
            ):
                if definition.split()[0] not in columns:
                    db.execute(f"ALTER TABLE scan_runs ADD COLUMN {definition}")
            db.executescript(
                "CREATE INDEX IF NOT EXISTS idx_scan_runs_project_visible ON scan_runs(project_id,deleted_at,round_number DESC);"
                "CREATE INDEX IF NOT EXISTS idx_scan_runs_visible_created ON scan_runs(deleted_at,created_at DESC);"
                "CREATE INDEX IF NOT EXISTS idx_scan_runs_input_status ON scan_runs(input_id,status);"
                "CREATE INDEX IF NOT EXISTS idx_scan_runs_status_created ON scan_runs(status,created_at);"
                "CREATE INDEX IF NOT EXISTS idx_schedule_runs_run ON schedule_runs(run_id);"
                "CREATE INDEX IF NOT EXISTS idx_inputs_project_created ON inputs(project_id,created_at DESC);"
                "CREATE INDEX IF NOT EXISTS idx_memberships_subject ON memberships(subject_id,project_id);"
            )
            tracker_columns = {row[1] for row in db.execute("PRAGMA table_info(tracker_deliveries)")}
            for definition in (
                "gitlab_merge_request_url TEXT",
                "gitlab_issue_urls_json TEXT NOT NULL DEFAULT '[]'",
                "tracker_run_url TEXT",
                "gitlab_result_status TEXT NOT NULL DEFAULT 'pending'",
                "gitlab_result_attempts INTEGER NOT NULL DEFAULT 0",
                "gitlab_result_last_error TEXT",
            ):
                if definition.split()[0] not in tracker_columns:
                    db.execute(f"ALTER TABLE tracker_deliveries ADD COLUMN {definition}")
            target_columns = {row[1] for row in db.execute("PRAGMA table_info(schedule_targets)")}
            for definition in (
                "source_kind TEXT NOT NULL DEFAULT 'server'",
                "schedule_frequency TEXT NOT NULL DEFAULT 'daily'",
                "schedule_time TEXT NOT NULL DEFAULT '01:00'",
                "schedule_weekdays_json TEXT NOT NULL DEFAULT '[0,1,2,3,4,5,6]'",
                "schedule_interval_hours INTEGER NOT NULL DEFAULT 24",
                "source_gitlab_mapping_id TEXT",
                "source_gitlab_ref TEXT NOT NULL DEFAULT ''",
                "source_gitlab_ref_type TEXT NOT NULL DEFAULT 'branch'",
                "source_gitlab_directory TEXT NOT NULL DEFAULT ''",
                "server_connection_id TEXT",
            ):
                if definition.split()[0] not in target_columns:
                    db.execute(f"ALTER TABLE schedule_targets ADD COLUMN {definition}")
            # Older rows predate the split delivery state. A saved Tracker run
            # means upload/analysis completed and the old failure belonged to
            # the GitLab publishing half of the former combined state.
            db.execute(
                "UPDATE tracker_deliveries SET gitlab_result_status='completed' "
                "WHERE gitlab_result_status='pending' AND gitlab_merge_request_url IS NOT NULL"
            )
            db.execute(
                "UPDATE tracker_deliveries SET status='completed',last_error=NULL,gitlab_result_status='failed',"
                "gitlab_result_last_error=COALESCE(gitlab_result_last_error,last_error) "
                "WHERE gitlab_result_status='pending' AND status='failed' AND tracker_run_id IS NOT NULL"
            )
            self._migrate_legacy_role_permissions(db)
            self._ensure_global_role_policy(db)

    def _migrate_legacy_role_permissions(self, db) -> None:
        """Give legacy project viewers explicit access to every screen once."""
        db.execute("BEGIN IMMEDIATE")
        try:
            export_migration = not db.execute(
                "SELECT 1 FROM portal_migrations WHERE migration_id=?", ("runs.export.v1",)
            ).fetchone()
            rows = db.execute(
                "SELECT p.project_id,p.version,p.roles_json FROM role_policies p "
                "WHERE p.version=(SELECT max(version) FROM role_policies WHERE project_id=p.project_id)"
            ).fetchall()
            for row in rows:
                roles = json.loads(row["roles_json"])
                migrated = False
                for permissions in roles.values():
                    if LEGACY_PROJECT_PERMISSION in permissions or "scan.create" in permissions:
                        merged = set(permissions) - {LEGACY_PROJECT_PERMISSION, "scan.create"}
                        if LEGACY_PROJECT_PERMISSION in permissions:
                            merged |= SCREEN_PERMISSIONS
                        if "scan.create" in permissions:
                            merged |= SCOPED_SCAN_PERMISSIONS
                        if merged != set(permissions):
                            permissions[:] = sorted(merged)
                            migrated = True
                    if export_migration and "runs.view" in permissions and "runs.export" not in permissions:
                        # Result downloads were historically covered by runs.view.
                        # Preserve that access when introducing the explicit export gate.
                        permissions.append("runs.export")
                        permissions.sort()
                        migrated = True
                if not migrated:
                    continue
                encoded, now = self._json(roles), self._now()
                version = int(row["version"]) + 1
                digest = hashlib.sha256(encoded.encode()).hexdigest()
                db.execute("INSERT INTO role_policies VALUES(?,?,?,?,?)", (row["project_id"], version, encoded, digest, now))
                self._audit_db(db, None, "role_policy.migrated", row["project_id"], {
                    "from_version": int(row["version"]), "version": version, "reason": "legacy project.view screen access",
                })
            if export_migration:
                db.execute(
                    "INSERT INTO portal_migrations(migration_id,applied_at) VALUES(?,?)",
                    ("runs.export.v1", self._now()),
                )
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise

    def _ensure_global_role_policy(self, db) -> None:
        """Create one KODA-wide role policy from the most evolved legacy policy."""
        if db.execute("SELECT 1 FROM role_policies WHERE project_id=? LIMIT 1", (GLOBAL_ROLE_POLICY_ID,)).fetchone():
            return
        source = db.execute(
            "SELECT project_id,roles_json FROM role_policies WHERE project_id!=? "
            "ORDER BY version DESC,created_at DESC LIMIT 1",
            (GLOBAL_ROLE_POLICY_ID,),
        ).fetchone()
        roles_json = source["roles_json"] if source else self._json({key: sorted(value) for key, value in DEFAULT_ROLE_PERMISSIONS.items()})
        now = self._now()
        digest = hashlib.sha256(roles_json.encode()).hexdigest()
        db.execute("INSERT INTO role_policies VALUES(?,?,?,?,?)", (GLOBAL_ROLE_POLICY_ID, 1, roles_json, digest, now))
        self._audit_db(db, None, "role_policy.globalized", None, {
            "version": 1, "source_project_id": source["project_id"] if source else None,
        })

    @staticmethod
    def _now() -> str:
        return dt.datetime.now(dt.timezone.utc).isoformat()

    @staticmethod
    def _json(value: object) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _dict(row: sqlite3.Row | None) -> dict | None:
        return dict(row) if row else None

    def subject(self, subject_id: str) -> dict | None:
        with self._db() as db:
            return self._dict(db.execute("SELECT * FROM subjects WHERE subject_id=?", (str(subject_id),)).fetchone())

    def project(self, project_id: str) -> dict | None:
        with self._db() as db:
            return self._dict(db.execute("SELECT * FROM projects WHERE project_id=?", (str(project_id),)).fetchone())

    def delete_project(self, project_id: str, actor: str | None = None) -> dict:
        """Delete a project and its local data after proving it is quiescent.

        External Tracker/GitLab objects are deliberately left untouched.  Input
        files are removed only after the transaction commits and only when no
        remaining scan references them.
        """
        project_id, actor = str(project_id), (str(actor) if actor is not None else None)
        paths: list[Path] = []
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            project = db.execute("SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
            if not project:
                db.execute("ROLLBACK")
                raise KeyError("project not found")
            if actor and not self.can(str(actor), project_id, "project.delete"):
                db.execute("ROLLBACK")
                raise PermissionError("project deletion denied")
            active_run = db.execute(
                "SELECT 1 FROM scan_runs WHERE project_id=? AND status NOT IN ('completed','failed','cancelled') LIMIT 1",
                (project_id,),
            ).fetchone()
            active_schedule = db.execute(
                "SELECT 1 FROM schedule_runs sr JOIN schedule_targets st ON st.target_id=sr.target_id "
                "WHERE st.project_id=? AND sr.status NOT IN ('completed','failed','cancelled') LIMIT 1",
                (project_id,),
            ).fetchone()
            if active_run or active_schedule:
                db.execute("ROLLBACK")
                raise ValueError("실행 중인 점검이 있는 프로젝트는 삭제할 수 없습니다")
            # The internal schedule API keeps a lease separately from the
            # durable run status.  Treat a matching lease as active even when
            # its worker has not yet written the next status transition.
            has_lease_table = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schedule_api_lease'"
            ).fetchone()
            if has_lease_table and db.execute(
                "SELECT 1 FROM schedule_api_lease l JOIN schedule_targets t ON t.target_id=(SELECT target_id FROM schedule_runs WHERE schedule_run_id=l.schedule_run_id) WHERE t.project_id=? LIMIT 1",
                (project_id,),
            ).fetchone():
                db.execute("ROLLBACK")
                raise ValueError("스케줄 worker lease가 있는 프로젝트는 삭제할 수 없습니다")
            sending = db.execute(
                "SELECT 1 FROM tracker_deliveries d JOIN scan_runs r USING(run_id) "
                "WHERE r.project_id=? AND (d.status='sending' OR d.gitlab_result_status='sending') "
                "UNION ALL SELECT 1 FROM gitlab_issue_deliveries d JOIN scan_runs r USING(run_id) "
                "WHERE r.project_id=? AND d.status='sending' "
                "UNION ALL SELECT 1 FROM gitlab_issue_links l JOIN scan_runs r USING(run_id) "
                "WHERE r.project_id=? AND l.status='creating' LIMIT 1",
                (project_id, project_id, project_id),
            ).fetchone()
            has_delivery_jobs = bool(db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='portal_delivery_jobs'"
            ).fetchone())
            if has_delivery_jobs:
                sending = sending or db.execute(
                    "SELECT 1 FROM portal_delivery_jobs d JOIN scan_runs r USING(run_id) "
                    "WHERE r.project_id=? AND d.status IN ('queued','running') LIMIT 1", (project_id,),
                ).fetchone()
            if sending:
                db.execute("ROLLBACK")
                raise ValueError("결과 전송 중인 프로젝트는 삭제할 수 없습니다")

            # Capture source paths before deleting the rows.  They are unlinked
            # after commit so a failed transaction cannot lose user files.
            paths = [Path(row[0]) for row in db.execute(
                "SELECT DISTINCT i.path FROM inputs i WHERE i.project_id=? AND i.path!=''", (project_id,)
            ) if row[0]]
            target_ids = [row[0] for row in db.execute(
                "SELECT target_id FROM schedule_targets WHERE project_id=?", (project_id,)
            )]
            schedule_run_ids = [row[0] for row in db.execute(
                "SELECT schedule_run_id FROM schedule_runs WHERE target_id IN (%s)" % ",".join("?" * len(target_ids)),
                target_ids,
            )] if target_ids else []
            run_ids = [row[0] for row in db.execute(
                "SELECT run_id FROM scan_runs WHERE project_id=?", (project_id,)
            )]
            if target_ids:
                target_marks = ",".join("?" * len(target_ids))
                db.execute(f"DELETE FROM schedule_files WHERE target_id IN ({target_marks})", target_ids)
                if schedule_run_ids and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schedule_api_receipts'").fetchone():
                    run_marks = ",".join("?" * len(schedule_run_ids))
                    db.execute(f"DELETE FROM schedule_api_receipts WHERE schedule_run_id IN ({run_marks})", schedule_run_ids)
                db.execute(f"DELETE FROM schedule_runs WHERE target_id IN ({target_marks})", target_ids)
            if run_ids:
                marks = ",".join("?" * len(run_ids))
                if has_delivery_jobs:
                    db.execute(f"DELETE FROM portal_delivery_jobs WHERE run_id IN ({marks})", run_ids)
                db.execute(f"DELETE FROM gitlab_issue_links WHERE run_id IN ({marks})", run_ids)
                db.execute(f"DELETE FROM gitlab_issue_deliveries WHERE run_id IN ({marks})", run_ids)
                db.execute(f"DELETE FROM tracker_deliveries WHERE run_id IN ({marks})", run_ids)
                db.execute(f"DELETE FROM analysis_revisions WHERE run_id IN ({marks})", run_ids)
            db.execute("DELETE FROM scan_runs WHERE project_id=?", (project_id,))
            db.execute("DELETE FROM inputs WHERE project_id=?", (project_id,))
            db.execute("DELETE FROM schedule_targets WHERE project_id=?", (project_id,))
            db.execute("DELETE FROM project_server_connections WHERE project_id=?", (project_id,))
            db.execute("DELETE FROM memberships WHERE project_id=?", (project_id,))
            db.execute("DELETE FROM gitlab_repositories WHERE project_id=?", (project_id,))
            db.execute("DELETE FROM rule_policies WHERE project_id=?", (project_id,))
            db.execute("DELETE FROM role_policies WHERE project_id=?", (project_id,))
            self._audit_db(db, actor, "project.deleted", project_id, {
                "name": project["name"], "runs_deleted": len(run_ids), "schedule_targets_deleted": len(target_ids),
            })
            db.execute("DELETE FROM projects WHERE project_id=?", (project_id,))
            db.execute("COMMIT")
        root = Path(self.path).resolve().parent
        cleanup_errors: list[dict[str, str]] = []
        for path in paths:
            try:
                resolved = path.resolve(strict=False)
                if resolved == root or root not in resolved.parents:
                    continue
                # Another project may intentionally reference the same source
                # path.  Re-check after commit before removing anything.
                with self._db() as db:
                    if db.execute("SELECT 1 FROM inputs WHERE path=? LIMIT 1", (str(path),)).fetchone():
                        continue
                if path.is_symlink() or path.is_file():
                    path.unlink(missing_ok=True)
            except OSError as exc:
                cleanup_errors.append({"path": str(path), "error": str(exc)[:500]})
        if cleanup_errors:
            self.record_audit(actor, "project.cleanup_failed", {
                "project_id": project_id, "paths": cleanup_errors,
            })
        return {"project_id": project_id, "name": project["name"], "deleted": True, "cleanup_errors": cleanup_errors}

    def ensure_subject(self, subject_id: str, display: str = "") -> dict:
        subject_id, display = str(uuid.UUID(str(subject_id))), display[:128]
        with self._db() as db:
            row = db.execute("SELECT * FROM subjects WHERE subject_id=?", (subject_id,)).fetchone()
            if row and (row["status"] == "tombstoned" or row["display"] == display):
                return dict(row)
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            # A concurrent admin change must win over the authentication read.
            row = db.execute("SELECT * FROM subjects WHERE subject_id=?", (subject_id,)).fetchone()
            now = self._now()
            if not row:
                db.execute(
                    "INSERT INTO subjects(subject_id,display,status,created_at,updated_at) VALUES(?,?,'pending',?,?)",
                    (subject_id, display, now, now),
                )
            elif row["status"] != "tombstoned" and row["display"] != display:
                db.execute("UPDATE subjects SET display=?,updated_at=? WHERE subject_id=?", (display, now, subject_id))
            result = dict(db.execute("SELECT * FROM subjects WHERE subject_id=?", (subject_id,)).fetchone())
            db.execute("COMMIT")
            return result

    def list_subjects(self) -> list[dict]:
        with self._db() as db:
            return [dict(row) for row in db.execute("SELECT * FROM subjects ORDER BY display,subject_id")]

    def set_subject(self, subject_id: str, *, status=None, system_admin=None, display=None, actor=None) -> dict:
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM subjects WHERE subject_id=?", (str(subject_id),)).fetchone()
            if not row:
                raise KeyError("subject not found")
            new_status = status if status is not None else row["status"]
            if new_status not in {"pending", "enabled", "disabled", "tombstoned"}:
                raise ValueError("invalid subject status")
            new_admin = int(row["system_admin"] if system_admin is None else bool(system_admin))
            if row["system_admin"] and row["status"] == "enabled" and (new_status != "enabled" or not new_admin):
                count = db.execute(
                    "SELECT count(*) FROM subjects WHERE status='enabled' AND system_admin=1"
                ).fetchone()[0]
                if count <= 1:
                    raise ValueError("last enabled system administrator")
            db.execute(
                "UPDATE subjects SET status=?,system_admin=?,display=?,updated_at=? WHERE subject_id=?",
                (new_status, new_admin, display if display is not None else row["display"], self._now(), str(subject_id)),
            )
            updated = dict(db.execute("SELECT * FROM subjects WHERE subject_id=?", (str(subject_id),)).fetchone())
            self._audit_db(db, actor, "subject.updated", None, {"subject_id": str(subject_id), "status": new_status, "system_admin": bool(new_admin)})
            db.execute("COMMIT")
            return updated

    def delete_subject_registration(self, subject_id: str, actor: str) -> None:
        """Remove KODA registration while retaining Tracker identity and scan history."""
        subject_id, actor = str(subject_id), str(actor)
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM subjects WHERE subject_id=?", (subject_id,)).fetchone()
            if not row:
                raise KeyError("subject not found")
            if row["status"] == "tombstoned":
                raise ValueError("tombstoned subject cannot be deleted")
            if subject_id == actor:
                raise ValueError("cannot delete current administrator registration")
            if row["system_admin"]:
                admins = db.execute(
                    "SELECT count(*) FROM subjects WHERE status='enabled' AND system_admin=1"
                ).fetchone()[0]
                if admins <= 1:
                    raise ValueError("last enabled system administrator")
            db.execute("DELETE FROM memberships WHERE subject_id=?", (subject_id,))
            db.execute("DELETE FROM subjects WHERE subject_id=?", (subject_id,))
            self._audit_db(db, actor, "subject.registration_deleted", None, {
                "subject_id": subject_id, "memberships_deleted": True,
            })
            db.execute("COMMIT")

    def bootstrap(self, subject_id: str) -> dict:
        with self._db() as db:
            existing_admin = db.execute(
                "SELECT subject_id FROM subjects WHERE status='enabled' AND system_admin=1 LIMIT 1"
            ).fetchone()
        if existing_admin and existing_admin["subject_id"] != str(subject_id):
            raise ValueError("portal bootstrap has already been completed")
        existing = self.subject(subject_id)
        if existing and existing["status"] == "tombstoned":
            raise ValueError("tombstoned subject cannot be bootstrapped")
        self.ensure_subject(subject_id)
        return self.set_subject(subject_id, status="enabled", system_admin=True, actor=subject_id)

    def create_project(self, name: str, actor: str | None = None, project_id: str | None = None) -> str:
        name = name.strip()
        if not 1 <= len(name) <= 128:
            raise ValueError("project name is required")
        if actor and not self.can_global(actor, "project.create"):
            raise PermissionError("project creation denied")
        project_id, now = str(project_id or uuid.uuid4()), self._now()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO projects(project_id,name,created_at) VALUES(?,?,?)", (project_id, name, now))
            rules = self._json([])
            db.execute("INSERT INTO rule_policies VALUES(?,?,?,?,?)", (project_id, 1, rules, hashlib.sha256(rules.encode()).hexdigest(), now))
            if actor:
                db.execute("INSERT INTO memberships VALUES(?,?,?)", (project_id, str(actor), "admin"))
            self._audit_db(db, actor, "project.created", project_id, {"name": name})
            db.execute("COMMIT")
        return project_id

    def list_projects(self, subject_id: str) -> list[dict]:
        subject = self.subject(subject_id)
        if not subject or subject["status"] != "enabled":
            return []
        with self._db() as db:
            if subject["system_admin"]:
                rows = db.execute("SELECT * FROM projects ORDER BY name")
            else:
                rows = db.execute(
                    "SELECT p.* FROM projects p JOIN memberships m USING(project_id) "
                    "WHERE m.subject_id=? ORDER BY p.name",
                    (str(subject_id),),
                )
            return [dict(row) for row in rows]

    def can_global(self, subject_id: str, permission: str) -> bool:
        """Check a permission granted by any project role of an enabled user."""
        subject = self.subject(subject_id)
        if not subject or subject["status"] != "enabled":
            return False
        if subject["system_admin"]:
            return True
        with self._db() as db:
            roles = db.execute(
                "SELECT DISTINCT role FROM memberships WHERE subject_id=?", (str(subject_id),)
            ).fetchall()
        try:
            policy_roles = self.role_policy()["roles"]
        except KeyError:
            return False
        return any(permission in set(policy_roles.get(row["role"], [])) for row in roles)

    def gitlab_repositories(self, project_id: str | None = None) -> list[dict]:
        with self._db() as db:
            if project_id is None:
                rows = db.execute(
                    "SELECT g.*,p.name AS project_name FROM gitlab_repositories g JOIN projects p USING(project_id) "
                    "ORDER BY g.path_with_namespace"
                )
            else:
                rows = db.execute(
                    "SELECT g.*,p.name AS project_name FROM gitlab_repositories g JOIN projects p USING(project_id) "
                    "WHERE g.project_id=? AND g.enabled=1 ORDER BY g.path_with_namespace", (str(project_id),)
                )
            return [dict(row) for row in rows]

    def gitlab_repository(self, mapping_id: str, project_id: str | None = None, *, include_disabled: bool = False) -> dict:
        enabled = "" if include_disabled else " AND enabled=1"
        with self._db() as db:
            if project_id is None:
                row = db.execute("SELECT * FROM gitlab_repositories WHERE mapping_id=?" + enabled, (str(mapping_id),)).fetchone()
            else:
                row = db.execute(
                    "SELECT * FROM gitlab_repositories WHERE mapping_id=? AND project_id=?" + enabled,
                    (str(mapping_id), str(project_id)),
                ).fetchone()
        if not row:
            raise KeyError("GitLab repository mapping not found")
        return dict(row)

    def set_gitlab_repositories(self, project_id: str, mappings: list[dict], actor: str | None = None) -> list[dict]:
        if not self.project(project_id) or not isinstance(mappings, list) or not mappings:
            raise ValueError("invalid GitLab repository mappings")
        now = self._now()
        saved = []
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            for value in mappings:
                if not isinstance(value, dict) or set(value) != {
                    "gitlab_project_id", "path_with_namespace", "name", "default_branch",
                    "tracker_service_id", "tracker_environment_id", "tracker_token_ref",
                }:
                    raise ValueError("invalid GitLab repository mapping")
                gitlab_project_id = int(value["gitlab_project_id"])
                strings = {key: str(value[key]).strip() for key in value if key != "gitlab_project_id"}
                if gitlab_project_id <= 0 or not all(strings.values()) or not all(len(item) <= 255 for item in strings.values()):
                    raise ValueError("invalid GitLab repository mapping")
                existing = db.execute(
                    "SELECT mapping_id,created_at FROM gitlab_repositories WHERE gitlab_project_id=?", (gitlab_project_id,)
                ).fetchone()
                mapping_id = existing["mapping_id"] if existing else str(uuid.uuid4())
                created_at = existing["created_at"] if existing else now
                db.execute(
                    "INSERT INTO gitlab_repositories(mapping_id,project_id,gitlab_project_id,path_with_namespace,name,default_branch,tracker_service_id,tracker_environment_id,tracker_token_ref,enabled,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,1,?,?) ON CONFLICT(gitlab_project_id) DO UPDATE SET "
                    "project_id=excluded.project_id,path_with_namespace=excluded.path_with_namespace,name=excluded.name,default_branch=excluded.default_branch,"
                    "tracker_service_id=excluded.tracker_service_id,tracker_environment_id=excluded.tracker_environment_id,tracker_token_ref=excluded.tracker_token_ref,enabled=1,updated_at=excluded.updated_at",
                    (mapping_id, str(project_id), gitlab_project_id, strings["path_with_namespace"], strings["name"], strings["default_branch"],
                     strings["tracker_service_id"], strings["tracker_environment_id"], strings["tracker_token_ref"], created_at, now),
                )
                self._audit_db(db, actor, "gitlab_repository.mapped", project_id, {
                    "mapping_id": mapping_id, "gitlab_project_id": gitlab_project_id,
                    "path_with_namespace": strings["path_with_namespace"],
                })
                saved.append(mapping_id)
            db.execute("COMMIT")
        return [self.gitlab_repository(mapping_id) for mapping_id in saved]

    def remove_gitlab_repository(self, mapping_id: str, actor: str | None = None) -> None:
        with self._db() as db:
            row = db.execute("SELECT * FROM gitlab_repositories WHERE mapping_id=?", (str(mapping_id),)).fetchone()
            if not row:
                raise KeyError("GitLab repository mapping not found")
            db.execute("UPDATE gitlab_repositories SET enabled=0,updated_at=? WHERE mapping_id=?", (self._now(), str(mapping_id)))
            self._audit_db(db, actor, "gitlab_repository.unmapped", row["project_id"], {
                "mapping_id": str(mapping_id), "gitlab_project_id": row["gitlab_project_id"],
            })

    def list_server_connections(self, project_id: str | None = None, *, include_disabled: bool = False) -> list[dict]:
        where = "" if include_disabled else " WHERE s.enabled=1"
        args: list[str] = []
        if project_id is not None:
            where += (" AND " if where else " WHERE ") + "psc.project_id=?"
            args.append(str(project_id))
        with self._db() as db:
            rows = db.execute(
                "SELECT s.*,GROUP_CONCAT(psc.project_id) AS project_ids "
                "FROM server_connections s LEFT JOIN project_server_connections psc ON psc.connection_id=s.connection_id"
                + where + " GROUP BY s.connection_id ORDER BY s.name,s.connection_id", args).fetchall()
        return [self._server_connection_dict(row) for row in rows]

    @staticmethod
    def _server_connection_dict(row: sqlite3.Row) -> dict:
        value = dict(row)
        value["enabled"] = bool(value.get("enabled"))
        value["project_ids"] = [item for item in (value.pop("project_ids", "") or "").split(",") if item]
        return value

    def server_connection(self, connection_id: str, *, include_disabled: bool = False) -> dict:
        rows = self.list_server_connections(include_disabled=include_disabled)
        for row in rows:
            if row["connection_id"] == str(connection_id):
                return row
        raise KeyError("server connection not found")

    def save_server_connection(self, config: dict, actor: str | None = None) -> dict:
        if not isinstance(config, dict):
            raise ValueError("invalid server connection")
        connection_id = str(config.get("connection_id") or uuid.uuid4()).strip()
        name, host, username = (str(config.get(key) or "").strip() for key in ("name", "host", "username"))
        ssh_key_ref, known_hosts_file = (str(config.get(key) or "").strip() for key in ("ssh_key_ref", "known_hosts_file"))
        fingerprint = str(config.get("host_key_fingerprint") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", connection_id) or not name or not host or not username or not ssh_key_ref or not known_hosts_file:
            raise ValueError("server connection fields are required")
        if any(len(value) > 1024 for value in (name, host, username, ssh_key_ref, known_hosts_file, fingerprint)):
            raise ValueError("server connection field is too long")
        if any(any(ord(char) < 32 for char in value) for value in (name, host, username, ssh_key_ref, known_hosts_file, fingerprint)):
            raise ValueError("server connection fields contain an invalid control character")
        if not Path(ssh_key_ref).expanduser().is_absolute() or not Path(known_hosts_file).expanduser().is_absolute():
            raise ValueError("SSH key and known-hosts paths must be absolute")
        port = int(config.get("port", 22))
        if not 1 <= port <= 65535:
            raise ValueError("invalid SSH port")
        project_ids = config.get("project_ids")
        if project_ids is None:
            with self._db() as db:
                project_ids = [row[0] for row in db.execute("SELECT project_id FROM project_server_connections WHERE connection_id=?", (connection_id,))]
        if not isinstance(project_ids, list) or any(not str(item).strip() for item in project_ids):
            raise ValueError("project_ids must be a list")
        project_ids = sorted(set(str(item).strip() for item in project_ids))
        now = self._now()
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if any(not db.execute("SELECT 1 FROM projects WHERE project_id=?", (item,)).fetchone() for item in project_ids):
                db.execute("ROLLBACK"); raise KeyError("project not found")
            old = db.execute("SELECT created_at FROM server_connections WHERE connection_id=?", (connection_id,)).fetchone()
            old_projects = {row[0] for row in db.execute("SELECT project_id FROM project_server_connections WHERE connection_id=?", (connection_id,))}
            removed_projects = old_projects - set(project_ids)
            if removed_projects and db.execute("SELECT 1 FROM schedule_targets WHERE server_connection_id=? AND project_id IN (%s)" % ",".join("?" * len(removed_projects)), (connection_id, *removed_projects)).fetchone():
                db.execute("ROLLBACK"); raise ValueError("server connection is used by an enabled schedule")
            if old and not bool(config.get("enabled", True)) and db.execute("SELECT 1 FROM schedule_targets WHERE server_connection_id=?", (connection_id,)).fetchone():
                db.execute("ROLLBACK"); raise ValueError("server connection is used by an enabled schedule")
            db.execute(
                "INSERT INTO server_connections(connection_id,name,host,port,username,ssh_key_ref,known_hosts_file,host_key_fingerprint,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(connection_id) DO UPDATE SET name=excluded.name,host=excluded.host,port=excluded.port,username=excluded.username,ssh_key_ref=excluded.ssh_key_ref,known_hosts_file=excluded.known_hosts_file,host_key_fingerprint=excluded.host_key_fingerprint,enabled=excluded.enabled,updated_at=excluded.updated_at",
                (connection_id,name,host,port,username,ssh_key_ref,known_hosts_file,fingerprint,int(bool(config.get("enabled", True))),old["created_at"] if old else now,now))
            db.execute("DELETE FROM project_server_connections WHERE connection_id=?", (connection_id,))
            db.executemany("INSERT INTO project_server_connections(project_id,connection_id,created_at) VALUES(?,?,?)", [(item,connection_id,now) for item in project_ids])
            # Keep existing targets usable by the worker while ensuring a changed connection is a new config version.
            db.execute("UPDATE schedule_targets SET host=?,port=?,username=?,ssh_key_ref=?,known_hosts_file=?,server_connection_id=?,config_version=config_version+1,updated_at=? WHERE server_connection_id=?", (host,port,username,ssh_key_ref,known_hosts_file,connection_id,now,connection_id))
            self._audit_db(db, actor, "server_connection.updated", None, {"connection_id": connection_id, "project_ids": project_ids, "enabled": bool(config.get("enabled", True))})
            db.execute("COMMIT")
        return self.server_connection(connection_id, include_disabled=True)

    def remove_server_connection(self, connection_id: str, actor: str | None = None) -> None:
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM server_connections WHERE connection_id=?", (str(connection_id),)).fetchone()
            if not row:
                db.execute("ROLLBACK"); raise KeyError("server connection not found")
            if db.execute("SELECT 1 FROM schedule_targets WHERE server_connection_id=?", (str(connection_id),)).fetchone():
                db.execute("ROLLBACK"); raise ValueError("server connection is used by an enabled schedule")
            now = self._now()
            db.execute("UPDATE server_connections SET enabled=0,updated_at=? WHERE connection_id=?", (now,str(connection_id)))
            self._audit_db(db, actor, "server_connection.disabled", None, {"connection_id": str(connection_id)})
            db.execute("COMMIT")

    def list_schedule_targets(self, *, enabled_only: bool = False) -> list[dict]:
        where = "WHERE t.enabled=1" if enabled_only else ""
        with self._db() as db:
            rows = db.execute(
                "SELECT t.*,p.name AS project_name FROM schedule_targets t "
                "JOIN projects p ON p.project_id=t.project_id "
                f"{where} ORDER BY t.order_index,t.name,t.target_id"
            ).fetchall()
        return [self._schedule_target_dict(row) for row in rows]

    def schedule_target(self, target_id: str) -> dict:
        with self._db() as db:
            row = db.execute(
                "SELECT t.*,p.name AS project_name FROM schedule_targets t "
                "JOIN projects p ON p.project_id=t.project_id WHERE t.target_id=?",
                (str(target_id),),
            ).fetchone()
        if not row:
            raise KeyError("schedule target not found")
        return self._schedule_target_dict(row)

    @staticmethod
    def _schedule_target_dict(row: sqlite3.Row) -> dict:
        value = dict(row)
        value["exclude_paths"] = json.loads(value.pop("exclude_json") or "[]")
        value["disabled_rules"] = json.loads(value.pop("disabled_rules_json") or "[]")
        value["schedule_weekdays"] = json.loads(value.pop("schedule_weekdays_json") or "[0,1,2,3,4,5,6]")
        value["enabled"] = bool(value.get("enabled"))
        return value

    def save_schedule_target(self, config: dict, actor: str | None = None) -> dict:
        if not isinstance(config, dict):
            raise ValueError("invalid schedule target")
        target_id = str(config.get("target_id") or uuid.uuid4()).strip()
        project_id = str(config.get("project_id") or "").strip()
        name = str(config.get("name") or "").strip()
        source_kind = str(config.get("source_kind") or "server").strip().lower()
        if source_kind not in {"server", "gitlab"}:
            raise ValueError("invalid schedule source kind")
        server_connection_id = str(config.get("server_connection_id") or "").strip() or None
        if source_kind == "gitlab" and server_connection_id:
            raise ValueError("GitLab targets cannot use a server connection")
        host = str(config.get("host") or "").strip()
        username = str(config.get("username") or "").strip()
        ssh_key_ref = str(config.get("ssh_key_ref") or "").strip()
        known_hosts_file = str(config.get("known_hosts_file") or "").strip()
        remote_directory = str(config.get("remote_directory") or "").strip()
        if source_kind == "server" and server_connection_id:
            with self._db() as db:
                connection = db.execute(
                    "SELECT s.* FROM server_connections s JOIN project_server_connections psc ON psc.connection_id=s.connection_id "
                    "WHERE s.connection_id=? AND psc.project_id=? AND s.enabled=1", (server_connection_id, project_id)
                ).fetchone()
            if not connection:
                raise ValueError("server connection is not enabled for this project")
            host, port, username = connection["host"], int(connection["port"]), connection["username"]
            ssh_key_ref, known_hosts_file = connection["ssh_key_ref"], connection["known_hosts_file"]
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", target_id) or not project_id or not name:
            raise ValueError("schedule target connection fields are required")
        if source_kind == "server" and not all((host, username, ssh_key_ref, known_hosts_file, remote_directory)):
            raise ValueError("server schedule connection fields are required")
        if any(len(value) > 1024 for value in (host, username, ssh_key_ref, known_hosts_file, remote_directory)) or len(name) > 255:
            raise ValueError("schedule target field is too long")
        if any(any(ord(char) < 32 for char in value) for value in (host, username, ssh_key_ref, known_hosts_file, remote_directory)):
            raise ValueError("schedule target fields contain an invalid control character")
        if source_kind == "server" and not remote_directory.startswith("/"):
            raise ValueError("remote directory must be an absolute path")
        if source_kind == "server" and (not Path(ssh_key_ref).expanduser().is_absolute() or not Path(known_hosts_file).expanduser().is_absolute()):
            raise ValueError("SSH key and known-hosts paths must be absolute")
        port = int(config.get("port", 22))
        if not 1 <= port <= 65535:
            raise ValueError("invalid SSH port")
        scan_scope = str(config.get("scan_scope") or "all")
        if scan_scope not in SCAN_SCOPE_CATEGORIES:
            raise ValueError("invalid scan scope")
        standard = str(config.get("standard") or ("local" if scan_scope == "library" else "local"))
        standard_category = str(config.get("standard_category") or "all")
        if scan_scope == "library":
            standard, standard_category = "local", "all"
        from .standards import resolve_standard_selection

        resolve_standard_selection(standard, standard_category)
        excludes = config.get("exclude_paths", config.get("excludes", []))
        disabled_rules = config.get("disabled_rules", [])
        if not isinstance(excludes, list) or any(
            not isinstance(item, str) or not item.strip() or any(ord(char) < 32 for char in item)
            for item in excludes
        ):
            raise ValueError("invalid excluded path list")
        if not isinstance(disabled_rules, list) or any(
            not isinstance(item, str) or not item.strip() or any(ord(char) < 32 for char in item)
            for item in disabled_rules
        ):
            raise ValueError("invalid disabled rule list")
        max_files, max_bytes, timeout_seconds = (
            int(config.get("max_files", 200_000)), int(config.get("max_bytes", 2 * 1024 * 1024 * 1024)),
            int(config.get("timeout_seconds", 21_600)),
        )
        if not 1 <= max_files <= 200_000 or not 1 <= max_bytes <= 4 * 1024 * 1024 * 1024 or not 60 <= timeout_seconds <= 86_400:
            raise ValueError("invalid schedule resource limit")
        mapping_id = str(config.get("gitlab_mapping_id") or "").strip() or None
        gitlab_target_branch = str(config.get("gitlab_target_branch") or "").strip()
        if len(gitlab_target_branch) > 255 or any(char in gitlab_target_branch for char in "\r\n"):
            raise ValueError("invalid GitLab target branch")
        schedule_frequency = str(config.get("schedule_frequency") or "daily").strip().lower()
        if schedule_frequency not in {"daily", "weekly", "hourly"}:
            raise ValueError("invalid schedule frequency")
        schedule_time = str(config.get("schedule_time") or "01:00").strip()
        if not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", schedule_time):
            raise ValueError("schedule time must be HH:MM")
        weekdays = config.get("schedule_weekdays", [0, 1, 2, 3, 4, 5, 6])
        if not isinstance(weekdays, list) or not weekdays or any(type(day) is not int or day < 0 or day > 6 for day in weekdays):
            raise ValueError("schedule weekdays must contain Python weekday numbers 0-6")
        weekdays = sorted(set(weekdays))
        interval_hours = int(config.get("schedule_interval_hours", 24))
        if schedule_frequency == "hourly" and interval_hours not in {1, 2, 3, 4, 6, 8, 12, 24}:
            raise ValueError("schedule interval must divide 24 hours")
        if schedule_frequency != "hourly":
            interval_hours = 24
        source_gitlab_mapping_id = str(config.get("source_gitlab_mapping_id") or "").strip() or None
        source_gitlab_ref = str(config.get("source_gitlab_ref") or "").strip()
        source_gitlab_ref_type = str(config.get("source_gitlab_ref_type") or "branch").strip().lower()
        source_gitlab_directory = str(config.get("source_gitlab_directory") or "").strip()
        if source_gitlab_ref_type not in {"branch", "tag"}:
            raise ValueError("GitLab source ref type must be branch or tag")
        if any(ord(char) < 32 for char in source_gitlab_ref):
            raise ValueError("invalid GitLab source ref")
        if source_kind == "gitlab" and source_gitlab_ref_type == "tag" and not source_gitlab_ref:
            raise ValueError("GitLab tag name is required")
        if len(source_gitlab_ref) > 255:
            raise ValueError("GitLab source ref is too long")
        if len(source_gitlab_directory) > 1024 or any(ord(char) < 32 for char in source_gitlab_directory):
            raise ValueError("invalid GitLab source directory")
        if source_gitlab_directory in {"", "/"}:
            source_gitlab_directory = ""
        else:
            if "\\" in source_gitlab_directory or any(part in {".", ".."} for part in source_gitlab_directory.split("/")):
                raise ValueError("invalid GitLab source directory")
            source_gitlab_directory = source_gitlab_directory.strip("/")
        if source_kind == "gitlab":
            source_gitlab_mapping_id = source_gitlab_mapping_id or mapping_id
            if not source_gitlab_mapping_id:
                raise ValueError("GitLab schedule source requires a repository")
        order_index = int(config.get("order_index", 0))
        if order_index < 0:
            raise ValueError("invalid schedule order")
        now = self._now()
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM projects WHERE project_id=?", (project_id,)).fetchone():
                db.execute("ROLLBACK")
                raise KeyError("project not found")
            if mapping_id:
                mapping = db.execute(
                    "SELECT project_id FROM gitlab_repositories WHERE mapping_id=? AND enabled=1", (mapping_id,)
                ).fetchone()
                if not mapping or mapping["project_id"] != project_id:
                    db.execute("ROLLBACK")
                    raise ValueError("GitLab mapping does not belong to project")
            if source_gitlab_mapping_id and source_gitlab_mapping_id != mapping_id:
                source_mapping = db.execute(
                    "SELECT project_id,default_branch FROM gitlab_repositories WHERE mapping_id=? AND enabled=1",
                    (source_gitlab_mapping_id,),
                ).fetchone()
                if not source_mapping or source_mapping["project_id"] != project_id:
                    db.execute("ROLLBACK")
                    raise ValueError("GitLab source mapping does not belong to project")
            elif source_gitlab_mapping_id:
                source_mapping = db.execute(
                    "SELECT project_id,default_branch FROM gitlab_repositories WHERE mapping_id=? AND enabled=1",
                    (source_gitlab_mapping_id,),
                ).fetchone()
                if not source_mapping or source_mapping["project_id"] != project_id:
                    db.execute("ROLLBACK")
                    raise ValueError("GitLab source mapping does not belong to project")
            if source_kind == "gitlab" and not source_gitlab_ref:
                source_gitlab_ref = str(source_mapping["default_branch"] or "").strip()
                if not source_gitlab_ref:
                    db.execute("ROLLBACK")
                    raise ValueError("GitLab source ref is required when default branch is unavailable")
            existing = db.execute("SELECT config_version,created_at FROM schedule_targets WHERE target_id=?", (target_id,)).fetchone()
            version = int(existing["config_version"]) + 1 if existing else 1
            created_at = existing["created_at"] if existing else now
            db.execute(
                "INSERT INTO schedule_targets(target_id,project_id,name,host,port,username,ssh_key_ref,known_hosts_file,remote_directory,exclude_json,standard,standard_category,scan_scope,disabled_rules_json,gitlab_mapping_id,gitlab_target_branch,source_kind,schedule_frequency,schedule_time,schedule_weekdays_json,schedule_interval_hours,source_gitlab_mapping_id,source_gitlab_ref,source_gitlab_ref_type,source_gitlab_directory,server_connection_id,enabled,order_index,config_version,max_files,max_bytes,timeout_seconds,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(target_id) DO UPDATE SET "
                "project_id=excluded.project_id,name=excluded.name,host=excluded.host,port=excluded.port,username=excluded.username,ssh_key_ref=excluded.ssh_key_ref,known_hosts_file=excluded.known_hosts_file,remote_directory=excluded.remote_directory,exclude_json=excluded.exclude_json,standard=excluded.standard,standard_category=excluded.standard_category,scan_scope=excluded.scan_scope,disabled_rules_json=excluded.disabled_rules_json,gitlab_mapping_id=excluded.gitlab_mapping_id,gitlab_target_branch=excluded.gitlab_target_branch,source_kind=excluded.source_kind,schedule_frequency=excluded.schedule_frequency,schedule_time=excluded.schedule_time,schedule_weekdays_json=excluded.schedule_weekdays_json,schedule_interval_hours=excluded.schedule_interval_hours,source_gitlab_mapping_id=excluded.source_gitlab_mapping_id,source_gitlab_ref=excluded.source_gitlab_ref,source_gitlab_ref_type=excluded.source_gitlab_ref_type,source_gitlab_directory=excluded.source_gitlab_directory,server_connection_id=excluded.server_connection_id,enabled=excluded.enabled,order_index=excluded.order_index,config_version=excluded.config_version,max_files=excluded.max_files,max_bytes=excluded.max_bytes,timeout_seconds=excluded.timeout_seconds,updated_at=excluded.updated_at",
                (target_id, project_id, name, host, port, username, ssh_key_ref, known_hosts_file, remote_directory,
                 self._json(sorted(set(item.strip() for item in excludes))), standard, standard_category, scan_scope,
                 self._json(sorted(set(item.strip() for item in disabled_rules))), mapping_id, gitlab_target_branch, source_kind, schedule_frequency, schedule_time, self._json(weekdays), interval_hours, source_gitlab_mapping_id, source_gitlab_ref, source_gitlab_ref_type, source_gitlab_directory, server_connection_id, int(bool(config.get("enabled", False))),
                 order_index, version, max_files, max_bytes, timeout_seconds, created_at, now),
            )
            self._audit_db(db, actor, "schedule_target.updated", project_id, {"target_id": target_id, "enabled": bool(config.get("enabled", False)), "config_version": version})
            db.execute("COMMIT")
        return self.schedule_target(target_id)

    def disable_schedule_target(self, target_id: str, actor: str | None = None) -> dict:
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT project_id FROM schedule_targets WHERE target_id=?", (str(target_id),)).fetchone()
            if not row:
                db.execute("ROLLBACK")
                raise KeyError("schedule target not found")
            db.execute("UPDATE schedule_targets SET enabled=0,config_version=config_version+1,updated_at=? WHERE target_id=?", (self._now(), str(target_id)))
            self._audit_db(db, actor, "schedule_target.disabled", row["project_id"], {"target_id": str(target_id)})
            db.execute("COMMIT")
        return self.schedule_target(target_id)

    def baseline_schedule_files(self, target_id: str) -> dict[str, dict]:
        with self._db() as db:
            rows = db.execute("SELECT * FROM schedule_files WHERE target_id=?", (str(target_id),)).fetchall()
        return {str(row["relative_path"]): dict(row) for row in rows}

    def replace_schedule_files(self, target_id: str, files: list[dict]) -> None:
        now = self._now()
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM schedule_files WHERE target_id=?", (str(target_id),))
            for item in files:
                db.execute(
                    "INSERT INTO schedule_files(target_id,relative_path,size,mtime,sha256,updated_at) VALUES(?,?,?,?,?,?)",
                    (str(target_id), str(item["relative_path"]), int(item["size"]), float(item["mtime"]), str(item["sha256"]), now),
                )
            db.execute("COMMIT")

    def begin_schedule_run(self, target_id: str, scheduled_for: str, mode: str, config_version: int) -> dict:
        if mode not in {"full", "changed"}:
            raise ValueError("invalid schedule mode")
        now = self._now()
        schedule_run_id = str(uuid.uuid4())
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM schedule_targets WHERE target_id=?", (str(target_id),)).fetchone():
                db.execute("ROLLBACK")
                raise KeyError("schedule target not found")
            db.execute(
                "INSERT OR IGNORE INTO schedule_runs(schedule_run_id,target_id,scheduled_for,mode,status,stage,config_version,created_at,updated_at) VALUES(?,?,?,?,'queued','queued',?,?,?)",
                (schedule_run_id, str(target_id), str(scheduled_for), mode, int(config_version), now, now),
            )
            row = db.execute("SELECT * FROM schedule_runs WHERE target_id=? AND scheduled_for=?", (str(target_id), str(scheduled_for))).fetchone()
            db.execute("COMMIT")
        return self.schedule_run(row["schedule_run_id"])

    def update_schedule_run(self, schedule_run_id: str, **fields) -> dict:
        allowed = {"status", "stage", "config_version", "run_id", "files_total", "changed_files", "cleanup_status", "cleanup_error", "tracker_status", "gitlab_status", "error", "metadata", "started_at", "completed_at"}
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError("invalid schedule run fields")
        values = dict(fields)
        if "metadata" in values:
            values["metadata_json"] = self._json(values.pop("metadata") or {})
        if not values:
            return self.schedule_run(schedule_run_id)
        values["updated_at"] = self._now()
        assignments = ",".join(f"{key}=?" for key in values)
        with self._lock, self._db() as db:
            db.execute("UPDATE schedule_runs SET " + assignments + " WHERE schedule_run_id=?", (*values.values(), str(schedule_run_id)))
        return self.schedule_run(schedule_run_id)

    def schedule_run(self, schedule_run_id: str, *, include_metadata: bool = True) -> dict:
        fields = "sr.*" if include_metadata else ",".join(f"sr.{name}" for name in SCHEDULE_RUN_METADATA_COLUMNS) + ",'{}' AS metadata_json"
        with self._db() as db:
            row = db.execute(
                f"SELECT {fields},r.round_number,(SELECT COUNT(*) FROM schedule_runs prior JOIN schedule_targets pt ON pt.target_id=prior.target_id "
                "WHERE pt.project_id=t.project_id AND pt.source_kind=t.source_kind AND "
                "(CASE WHEN t.source_kind='gitlab' THEN "
                "(SELECT gitlab_project_id FROM gitlab_repositories WHERE mapping_id=pt.source_gitlab_mapping_id)="
                "(SELECT gitlab_project_id FROM gitlab_repositories WHERE mapping_id=t.source_gitlab_mapping_id) "
                "ELSE pt.host=t.host AND pt.port=t.port END) "
                "AND substr(prior.scheduled_for,1,10)=substr(sr.scheduled_for,1,10) "
                "AND (prior.scheduled_for<sr.scheduled_for OR (prior.scheduled_for=sr.scheduled_for AND prior.rowid<=sr.rowid))) AS scheduled_round,"
                "t.name AS target_name,t.host,t.remote_directory,t.source_kind,t.source_gitlab_directory,g.path_with_namespace AS source_gitlab_path "
                "FROM schedule_runs sr JOIN schedule_targets t ON t.target_id=sr.target_id LEFT JOIN scan_runs r ON r.run_id=sr.run_id "
                "LEFT JOIN gitlab_repositories g ON g.mapping_id=t.source_gitlab_mapping_id WHERE sr.schedule_run_id=?",
                (str(schedule_run_id),),
            ).fetchone()
        if not row:
            raise KeyError("schedule run not found")
        return self._schedule_run_dict(row)

    def paginate_schedule_runs(self, project_ids: list[str], *, page=1, page_size=50, search="", status="", scan_scope="") -> dict:
        page, page_size = self._page_values(page, page_size)
        result = {"items": [], "total": 0, "page": page, "page_size": page_size}
        ids = list(dict.fromkeys(str(value) for value in project_ids))
        if not ids:
            return result
        clauses = ["t.project_id IN (" + ",".join("?" for _ in ids) + ")", "(r.run_id IS NULL OR r.deleted_at IS NULL)"]
        values = list(ids)
        if status:
            clauses.append("sr.status=?")
            values.append(str(status))
        if scan_scope:
            clauses.append("t.scan_scope=?")
            values.append(str(scan_scope))
        if search:
            clauses.append("(p.name LIKE ? ESCAPE '\\' OR t.name LIKE ? ESCAPE '\\' OR t.host LIKE ? ESCAPE '\\' OR sr.scheduled_for LIKE ? ESCAPE '\\')")
            pattern = "%" + str(search)[:500].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            values.extend([pattern] * 4)
        where = " AND ".join(clauses)
        joins = "FROM schedule_runs sr JOIN schedule_targets t ON t.target_id=sr.target_id JOIN projects p ON p.project_id=t.project_id LEFT JOIN scan_runs r ON r.run_id=sr.run_id "
        with self._db() as db:
            result["total"] = db.execute(f"SELECT count(*) {joins}WHERE {where}", values).fetchone()[0]
            rows = db.execute(
                "SELECT sr.schedule_run_id,t.project_id,p.name AS project_name,t.name,t.scan_scope,t.standard "
                f"{joins}WHERE {where} ORDER BY sr.scheduled_for DESC,sr.created_at DESC,sr.schedule_run_id LIMIT ? OFFSET ?",
                (*values, page_size, (page - 1) * page_size),
            ).fetchall()
        result["items"] = [{**self.schedule_run(row["schedule_run_id"], include_metadata=False), **dict(row)} for row in rows]
        return result

    @staticmethod
    def _schedule_run_dict(row: sqlite3.Row | None) -> dict:
        if not row:
            raise KeyError("schedule run not found")
        value = dict(row)
        value["metadata"] = json.loads(value.pop("metadata_json") or "{}")
        value["round_label"] = PortalStore._schedule_round_label(value)
        value["display_round"] = value["round_label"]
        return value

    @staticmethod
    def _schedule_round_label(value: dict) -> str:
        day = str(value.get("scheduled_for") or "")[:10] or "—"
        if value.get("source_kind") == "gitlab":
            source = value.get("source_gitlab_path") or value.get("source_gitlab_directory") or "GitLab"
        else:
            source = value.get("host") or value.get("target_name") or value.get("remote_directory") or "서버"
        round_number = value.get("scheduled_round") or value.get("round_number")
        return f"{day} · {source} · {round_number if round_number is not None else '대기'}회차"

    def list_schedule_runs(self, target_id: str | None = None, limit: int = 100) -> list[dict]:
        with self._db() as db:
            fields = (
                "sr.*,r.round_number,(SELECT COUNT(*) FROM schedule_runs prior JOIN schedule_targets pt ON pt.target_id=prior.target_id "
                "WHERE pt.project_id=t.project_id AND pt.source_kind=t.source_kind AND "
                "(CASE WHEN t.source_kind='gitlab' THEN "
                "(SELECT gitlab_project_id FROM gitlab_repositories WHERE mapping_id=pt.source_gitlab_mapping_id)="
                "(SELECT gitlab_project_id FROM gitlab_repositories WHERE mapping_id=t.source_gitlab_mapping_id) "
                "ELSE pt.host=t.host AND pt.port=t.port END) "
                "AND substr(prior.scheduled_for,1,10)=substr(sr.scheduled_for,1,10) "
                "AND (prior.scheduled_for<sr.scheduled_for OR (prior.scheduled_for=sr.scheduled_for AND prior.rowid<=sr.rowid))) AS scheduled_round,"
                "t.name AS target_name,t.host,t.remote_directory,t.source_kind,"
                "t.source_gitlab_directory,g.path_with_namespace AS source_gitlab_path"
            )
            if target_id:
                rows = db.execute(
                    f"SELECT {fields} FROM schedule_runs sr JOIN schedule_targets t ON t.target_id=sr.target_id "
                    "LEFT JOIN scan_runs r ON r.run_id=sr.run_id LEFT JOIN gitlab_repositories g ON g.mapping_id=t.source_gitlab_mapping_id "
                    "WHERE sr.target_id=? ORDER BY sr.scheduled_for DESC LIMIT ?",
                    (str(target_id), min(max(int(limit), 1), 500)),
                ).fetchall()
            else:
                rows = db.execute(
                    f"SELECT {fields} FROM schedule_runs sr JOIN schedule_targets t ON t.target_id=sr.target_id "
                    "LEFT JOIN scan_runs r ON r.run_id=sr.run_id LEFT JOIN gitlab_repositories g ON g.mapping_id=t.source_gitlab_mapping_id "
                    "ORDER BY sr.scheduled_for DESC LIMIT ?", (min(max(int(limit), 1), 500),)
                ).fetchall()
        return [self._schedule_run_dict(row) for row in rows]

    def last_schedule_run(self, target_id: str) -> dict | None:
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM schedule_runs WHERE target_id=? AND status='completed' AND cleanup_status='completed' "
                "ORDER BY scheduled_for DESC,created_at DESC LIMIT 1", (str(target_id),)
            ).fetchone()
        return self.schedule_run(row["schedule_run_id"]) if row else None

    def has_active_schedule_work(self, target_id: str | None = None) -> bool:
        with self._db() as db:
            if target_id:
                row = db.execute(
                    "SELECT 1 FROM schedule_runs WHERE target_id=? AND status IN ('running','cancelling') LIMIT 1",
                    (str(target_id),),
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT 1 FROM schedule_runs WHERE status IN ('running','cancelling') LIMIT 1"
                ).fetchone()
        return bool(row)

    def claim_schedule_run(self, schedule_run_id: str) -> bool:
        """Atomically claim a queued/recovered target for one worker."""
        now = self._now()
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if (self._manual_work_busy(db) or self._schedule_api_busy(db)
                or db.execute("SELECT 1 FROM scan_runs WHERE status IN ('running','cancelling') LIMIT 1").fetchone()):
                db.execute("ROLLBACK")
                return False
            changed = db.execute(
                "UPDATE schedule_runs SET status='running',stage='listing',run_id=NULL,files_total=0,"
                "changed_files=0,cleanup_status='pending',cleanup_error=NULL,tracker_status='pending',"
                "gitlab_status='pending',metadata_json='{}',error=NULL,started_at=?,completed_at=NULL,updated_at=? "
                "WHERE schedule_run_id=? AND status='queued' AND NOT EXISTS(SELECT 1 FROM schedule_runs WHERE status IN ('running','cancelling'))",
                (now, now, str(schedule_run_id)),
            ).rowcount
            db.execute("COMMIT")
        return bool(changed)

    @staticmethod
    def _schedule_api_busy(db) -> bool:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schedule_api_lease'").fetchone():
            return False
        return bool(db.execute("SELECT 1 FROM schedule_api_lease LIMIT 1").fetchone())

    @staticmethod
    def _manual_work_busy(db) -> bool:
        rows = db.execute("SELECT snapshot_json FROM scan_runs WHERE status IN ('queued','running','cancelling')").fetchall()
        for row in rows:
            try:
                if json.loads(row["snapshot_json"]).get("source_type") != "scheduled_server":
                    return True
            except (TypeError, ValueError, AttributeError):
                return True
        return False

    def has_active_manual_work(self) -> bool:
        with self._db() as db:
            return self._manual_work_busy(db)

    @staticmethod
    def _next_manual_run(db) -> str | None:
        rows = db.execute(
            "SELECT run_id,snapshot_json FROM scan_runs WHERE status='queued' AND cancel_requested=0 "
            "ORDER BY created_at,rowid"
        )
        for row in rows:
            if json.loads(row["snapshot_json"]).get("source_type") != "scheduled_server":
                return row["run_id"]
        return None

    def next_queued_manual_run(self) -> str | None:
        with self._db() as db:
            return self._next_manual_run(db)

    def create_scheduled_scan(self, project_id: str, input_id: str, standard: str, standard_category: str, scan_scope: str, source_snapshot: dict) -> dict:
        if scan_scope == "library":
            standard, standard_category = "local", "all"
        if scan_scope not in SCAN_SCOPE_CATEGORIES or not isinstance(source_snapshot, dict) or source_snapshot.get("source_type") != "scheduled_server":
            raise ValueError("invalid scheduled scan options")
        from .standards import resolve_standard_selection

        resolve_standard_selection(standard, standard_category)
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            source = db.execute("SELECT * FROM inputs WHERE input_id=? AND project_id=?", (str(input_id), str(project_id))).fetchone()
            if not source or not Path(source["path"]).is_file():
                db.execute("ROLLBACK")
                raise ValueError("scheduled input is unavailable")
            policy = db.execute("SELECT * FROM rule_policies WHERE project_id=? ORDER BY version DESC LIMIT 1", (str(project_id),)).fetchone()
            if not policy:
                db.execute("ROLLBACK")
                raise KeyError("rule policy not found")
            round_number = (db.execute("SELECT max(round_number) FROM scan_runs WHERE project_id=?", (str(project_id),)).fetchone()[0] or 0) + 1
            disabled_rules = sorted(set(source_snapshot.get("disabled_rules", [])) | set(json.loads(policy["rules_json"])))
            source_snapshot = {**source_snapshot, "disabled_rules": disabled_rules}
            if not isinstance(disabled_rules, list) or any(not isinstance(item, str) for item in disabled_rules):
                db.execute("ROLLBACK")
                raise ValueError("invalid scheduled rule policy")
            snapshot = {
                "input_id": str(input_id), "input_hash": source["content_hash"], "standard": standard,
                "standard_category": standard_category, "scan_scope": scan_scope,
                "disabled_rules": sorted(set(disabled_rules)), "rule_policy_version": policy["version"],
                "rule_policy_hash": policy["hash"], "scanner_version": _scanner_version(),
                "requested_by": "schedule-worker", **source_snapshot,
            }
            if snapshot.get("gitlab_mapping_id"):
                project_name = db.execute("SELECT name FROM projects WHERE project_id=?", (str(project_id),)).fetchone()[0]
                slug = re.sub(r"[^\w-]+", "-", project_name, flags=re.UNICODE).strip("-_" )
                slug = slug.encode("utf-8")[:72].decode("utf-8", errors="ignore") or "project"
                day = str(snapshot.get("scheduled_for") or self._now())[:10].replace("-", "")
                previous = db.execute("SELECT snapshot_json FROM scan_runs WHERE project_id=?", (str(project_id),)).fetchall()
                scheduled_source = str(snapshot.get("scheduled_source_kind") or "")
                if not scheduled_source and snapshot.get("source_type") == "scheduled_server":
                    scheduled_source = "server"
                source_id = snapshot.get("source_gitlab_project_id")
                source_path = str(snapshot.get("source_gitlab_path") or "")
                source_label = source_path
                if not source_label and scheduled_source:
                    source_label = str(snapshot.get("remote_server") or snapshot.get("remote_directory") or "scheduled")
                source_slug = re.sub(r"[^\w-]+", "-", source_label, flags=re.UNICODE).strip("-_")
                source_slug = source_slug.encode("utf-8")[:56].decode("utf-8", errors="ignore")
                if scheduled_source == "gitlab" and source_id is not None:
                    source_slug = f"{source_slug or 'gitlab'}-{source_id}"

                def same_scheduled_source(value):
                    if not scheduled_source:
                        return True
                    previous_source = value.get("scheduled_source_kind") or ("server" if value.get("source_type") == "scheduled_server" else "")
                    if previous_source != scheduled_source:
                        return False
                    if scheduled_source == "gitlab":
                        return value.get("source_gitlab_project_id") == source_id
                    return str(value.get("remote_server") or "") == str(snapshot.get("remote_server") or "")

                versions = []
                for row in previous:
                    try:
                        value = json.loads(row[0])
                        if (str(value.get("gitlab_result_date", "")).replace("-", "") == day and
                                same_scheduled_source(value)):
                            versions.append(int(value.get("gitlab_result_version", 0)))
                    except (TypeError, ValueError, json.JSONDecodeError):
                        continue
                version = 1 + max(versions, default=0)
                branch_parts = ["koda", "results", slug]
                if source_slug:
                    branch_parts.append(source_slug)
                branch_parts.extend((day, f"round-{version}"))
                snapshot.update(gitlab_result_date=f"{day[:4]}-{day[4:6]}-{day[6:]}", gitlab_result_version=version,
                                gitlab_result_branch="/".join(branch_parts))
            run_id, revision_id, now = str(uuid.uuid4()), str(uuid.uuid4()), self._now()
            db.execute(
                "INSERT INTO scan_runs(run_id,project_id,round_number,status,standard,standard_category,input_id,policy_version,requested_by,snapshot_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, str(project_id), round_number, "queued", standard, standard_category, str(input_id), policy["version"], "schedule-worker", self._json(snapshot), now),
            )
            db.execute("INSERT INTO analysis_revisions(revision_id,run_id,sequence,snapshot_json,created_at) VALUES(?,?,?,?,?)", (revision_id, run_id, 1, self._json(snapshot), now))
            db.execute("UPDATE schedule_runs SET run_id=? WHERE schedule_run_id=?", (run_id, source_snapshot["schedule_run_id"]))
            self._audit_db(db, "schedule-worker", "scan.created.scheduled", project_id, {"run_id": run_id, "round_number": round_number, "target_id": source_snapshot.get("schedule_target_id")})
            db.execute("COMMIT")
        return self.run(run_id)

    def set_membership(self, project_id: str, subject_id: str, role: str, actor: str | None = None) -> None:
        policy = self.role_policy()
        if role not in policy["roles"]:
            raise ValueError("unknown role")
        with self._db() as db:
            db.execute(
                "INSERT INTO memberships(project_id,subject_id,role) VALUES(?,?,?) "
                "ON CONFLICT(project_id,subject_id) DO UPDATE SET role=excluded.role",
                (str(project_id), str(subject_id), role),
            )
            self._audit_db(db, actor, "membership.updated", project_id, {"subject_id": str(subject_id), "role": role})

    def list_memberships(self, project_id: str) -> list[dict]:
        with self._db() as db:
            rows = db.execute(
                "SELECT m.project_id,m.subject_id,m.role,s.display,s.status FROM memberships m "
                "JOIN subjects s USING(subject_id) WHERE m.project_id=? ORDER BY s.display,m.subject_id",
                (str(project_id),),
            )
            return [dict(row) for row in rows]

    def list_memberships_all(self) -> list[dict]:
        with self._db() as db:
            rows = db.execute(
                "SELECT m.project_id,p.name AS project_name,m.subject_id,m.role,s.display,s.status "
                "FROM memberships m JOIN projects p USING(project_id) JOIN subjects s USING(subject_id) "
                "ORDER BY p.name,s.display,m.subject_id"
            )
            return [dict(row) for row in rows]

    def remove_membership(self, project_id: str, subject_id: str, actor: str | None = None) -> None:
        with self._db() as db:
            db.execute("DELETE FROM memberships WHERE project_id=? AND subject_id=?", (str(project_id), str(subject_id)))
            self._audit_db(db, actor, "membership.removed", project_id, {"subject_id": str(subject_id)})

    def role_policy(self, project_id: str | None = None) -> dict:
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM role_policies WHERE project_id=? ORDER BY version DESC LIMIT 1", (GLOBAL_ROLE_POLICY_ID,)
            ).fetchone()
        if not row:
            raise KeyError("role policy not found")
        result = dict(row)
        result["roles"] = json.loads(result.pop("roles_json"))
        return result

    def set_role_policy(self, roles: dict, expected_version: int, actor: str | None = None) -> dict:
        normalized: dict[str, list[str]] = {}
        for role, permissions in dict(roles).items():
            if not isinstance(role, str) or not role or not isinstance(permissions, list):
                raise ValueError("invalid role policy")
            permission_set = set(permissions)
            if len(permission_set) != len(permissions) or permission_set - PROJECT_PERMISSIONS or permission_set & RESERVED_PERMISSIONS:
                raise ValueError("unknown, duplicate, or reserved permission")
            if LEGACY_PROJECT_PERMISSION in permission_set:
                permission_set = (permission_set - {LEGACY_PROJECT_PERMISSION}) | SCREEN_PERMISSIONS
            if "scan.create" in permission_set:
                permission_set = (permission_set - {"scan.create"}) | SCOPED_SCAN_PERMISSIONS
            normalized[role] = sorted(permission_set)
        if not normalized:
            raise ValueError("at least one role is required")
        encoded, now = self._json(normalized), self._now()
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT max(version) FROM role_policies WHERE project_id=?", (GLOBAL_ROLE_POLICY_ID,)).fetchone()[0] or 0
            if int(expected_version) != current:
                raise VersionConflict("stale role policy version")
            version = current + 1
            digest = hashlib.sha256(encoded.encode()).hexdigest()
            db.execute("INSERT INTO role_policies VALUES(?,?,?,?,?)", (GLOBAL_ROLE_POLICY_ID, version, encoded, digest, now))
            self._audit_db(db, actor, "role_policy.updated", None, {"version": version})
            db.execute("COMMIT")
        return {"version": version, "hash": digest, "roles": normalized}

    def can(self, subject_id: str, project_id: str, permission: str = "project.view") -> bool:
        subject = self.subject(subject_id)
        if not subject or subject["status"] != "enabled":
            return False
        if subject["system_admin"]:
            return True
        with self._db() as db:
            member = db.execute(
                "SELECT role FROM memberships WHERE project_id=? AND subject_id=?", (str(project_id), str(subject_id))
            ).fetchone()
        if not member:
            return False
        try:
            permissions = set(self.role_policy()["roles"].get(member["role"], []))
        except KeyError:
            return False
        aliases = {"view": "project.view", "scan": "scan.create", "upload": "input.manage", "manage": "project.manage"}
        requested = aliases.get(permission, permission)
        if requested == "scan.create":
            return bool(permissions & SCOPED_SCAN_PERMISSIONS) or "scan.create" in permissions
        if requested in SCOPED_SCAN_PERMISSIONS:
            return requested in permissions or "scan.create" in permissions
        return requested in permissions or (requested == LEGACY_PROJECT_PERMISSION and bool(permissions & SCREEN_PERMISSIONS))

    def reserve_upload(self, root: str | Path, temporary: str | Path, target: str | Path,
                       maximum_bytes: int, quota_bytes: int, *, exact: bool = True) -> tuple[str, int]:
        """Reserve capacity before writing. The SQLite write lock serializes competing uploads."""
        root = Path(root).resolve()
        temporary, target = Path(temporary).resolve(), Path(target).resolve()
        if temporary.parent != root or target.parent != root or temporary == target:
            raise ValueError("upload paths must be direct children of the input directory")
        if maximum_bytes <= 0 or quota_bytes <= 0:
            raise ValueError("upload limit must be positive")
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if temporary.exists() or target.exists():
                raise ValueError("upload destination already exists")
            reservations = db.execute(
                "SELECT * FROM upload_reservations WHERE root=?",
                (str(root),),
            ).fetchall()
            self._reap_stale_uploads(db, root, reservations)
            # Filesystem cleanup cannot roll back. Persist the matching row
            # deletions even if the new request is rejected by a quota check.
            db.execute("COMMIT")
            db.execute("BEGIN IMMEDIATE")
            self._reap_orphan_upload_locks(db, root)
            if temporary.exists() or target.exists():
                raise ValueError("upload destination already exists")
            reservations = db.execute("SELECT * FROM upload_reservations WHERE root=?", (str(root),)).fetchall()
            reserved_paths = {path for row in reservations for path in (row["temporary_path"], row["target_path"])}
            used = sum(row["reserved_bytes"] for row in reservations)
            # Include legacy and orphan files; terminal inputs whose source was
            # deleted no longer consume disk. Active writes are charged at their
            # full reservation instead of their changing on-disk size.
            file_count = len(reservations)
            if file_count >= MAX_UPLOAD_FILES:
                raise UploadQuotaExceeded("portal input file count quota exceeded")
            for path in root.iterdir():
                if (not path.is_file() or str(path.resolve()) in reserved_paths
                        or (path.name.startswith(".upload-reservation-") and path.name.endswith(".lock"))):
                    continue
                file_count += 1
                if file_count >= MAX_UPLOAD_FILES:
                    raise UploadQuotaExceeded("portal input file count quota exceeded")
                used += path.stat().st_size
            available = max(0, quota_bytes - used)
            allowance = maximum_bytes if exact else min(maximum_bytes, available)
            if allowance > available or allowance == 0:
                raise UploadQuotaExceeded("portal input storage quota exceeded")
            reservation_id = str(uuid.uuid4())
            lock_path = root / f".upload-reservation-{reservation_id}.lock"
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                db.execute(
                    "INSERT INTO upload_reservations"
                    "(reservation_id,root,temporary_path,target_path,reserved_bytes,created_at,owner_lock) "
                    "VALUES(?,?,?,?,?,?,1)",
                    (reservation_id, str(root), str(temporary), str(target), allowance, self._now()),
                )
                db.execute("COMMIT")
            except BaseException:
                os.close(lock_fd)
                lock_path.unlink(missing_ok=True)
                raise
            self._upload_locks[reservation_id] = (lock_fd, lock_path)
        return reservation_id, allowance

    def _reap_stale_uploads(self, db: sqlite3.Connection, root: Path, reservations: list[sqlite3.Row]) -> None:
        """Remove abandoned writes only after acquiring their process-held lock."""
        for row in reservations:
            reservation_id = row["reservation_id"]
            if not row["owner_lock"] or reservation_id in self._upload_locks:
                continue
            try:
                canonical_id = str(uuid.UUID(reservation_id))
            except ValueError:
                continue
            if canonical_id != reservation_id:
                continue
            lock_path = root / f".upload-reservation-{reservation_id}.lock"
            try:
                lock_fd = os.open(lock_path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
            except OSError:
                # A missing or replaced lock cannot prove that its owner died.
                continue
            try:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    continue
                paths = (Path(row["temporary_path"]), Path(row["target_path"]))
                if any(path.parent != root for path in paths):
                    continue
                if db.execute(
                    "SELECT 1 FROM inputs WHERE path IN (?,?) LIMIT 1", tuple(str(path) for path in paths)
                ).fetchone():
                    continue
                try:
                    for path in paths:
                        path.unlink(missing_ok=True)
                except OSError:
                    # Retain the reservation until every uncommitted file is gone.
                    continue
                db.execute("DELETE FROM upload_reservations WHERE reservation_id=?", (reservation_id,))
            finally:
                os.close(lock_fd)

    def _reap_orphan_upload_locks(self, db: sqlite3.Connection, root: Path) -> None:
        active_ids = {row[0] for row in db.execute(
            "SELECT reservation_id FROM upload_reservations WHERE root=?", (str(root),)
        )}
        for lock_path in root.glob(".upload-reservation-*.lock"):
            reservation_id = lock_path.name[len(".upload-reservation-"):-len(".lock")]
            if reservation_id in active_ids:
                continue
            try:
                if str(uuid.UUID(reservation_id)) != reservation_id:
                    continue
                lock_fd = os.open(lock_path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
            except (OSError, ValueError):
                continue
            try:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    lock_path.unlink(missing_ok=True)
                except OSError:
                    pass
            finally:
                os.close(lock_fd)

    def _release_upload_lock(self, reservation_id: str) -> None:
        lock = self._upload_locks.pop(reservation_id, None)
        if lock:
            lock_fd, lock_path = lock
            try:
                lock_path.unlink(missing_ok=True)
            except OSError:
                pass
            finally:
                os.close(lock_fd)

    def release_upload(self, reservation_id: str) -> None:
        with self._lock, self._db() as db:
            db.execute("DELETE FROM upload_reservations WHERE reservation_id=?", (reservation_id,))
            self._release_upload_lock(reservation_id)

    def add_input(self, project_id: str, name: str, path: str | Path, actor: str | None = None, content_hash="", *, reservation_id: str | None = None) -> str:
        path = Path(path)
        content_hash = content_hash or hashlib.sha256(path.read_bytes()).hexdigest()
        input_id = str(uuid.uuid4())
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if reservation_id:
                reservation = db.execute("SELECT target_path FROM upload_reservations WHERE reservation_id=?", (reservation_id,)).fetchone()
                if not reservation or reservation["target_path"] != str(path.resolve()):
                    raise ValueError("upload reservation does not match input")
            db.execute("INSERT INTO inputs(input_id,project_id,name,path,content_hash,created_at,registered_by) VALUES(?,?,?,?,?,?,?)", (input_id, str(project_id), name[:255], str(path), content_hash, self._now(), actor))
            self._audit_db(db, actor, "input.created", project_id, {"input_id": input_id, "name": name[:255], "sha256": content_hash})
            if reservation_id:
                db.execute("DELETE FROM upload_reservations WHERE reservation_id=?", (reservation_id,))
            db.execute("COMMIT")
            if reservation_id:
                self._release_upload_lock(reservation_id)
        return input_id

    def list_inputs(self, project_id: str) -> list[dict]:
        with self._db() as db:
            rows = [dict(row) for row in db.execute(
                "SELECT i.*,s.display AS registered_by_id FROM inputs i LEFT JOIN subjects s ON s.subject_id=i.registered_by "
                "WHERE i.project_id=? ORDER BY i.created_at DESC", (str(project_id),))]
            for row in rows:
                row["registered_by_id"] = row["registered_by_id"] or ("schedule-worker" if row["registered_by"] == "schedule-worker" else "기록 없음")
                row["runs"] = [dict(run) for run in db.execute(
                    "SELECT run_id,round_number FROM scan_runs WHERE input_id=? AND deleted_at IS NULL ORDER BY round_number", (row["input_id"],))]
        for row in rows:
            row["available"] = Path(row["path"]).is_file()
        return rows

    def input(self, input_id: str) -> dict:
        with self._db() as db:
            row = db.execute("SELECT * FROM inputs WHERE input_id=?", (str(input_id),)).fetchone()
        if not row:
            raise KeyError("input not found")
        return dict(row)

    def rule_policy(self, project_id: str) -> dict:
        with self._db() as db:
            row = db.execute("SELECT * FROM rule_policies WHERE project_id=? ORDER BY version DESC LIMIT 1", (str(project_id),)).fetchone()
        if not row:
            raise KeyError("rule policy not found")
        result = dict(row)
        result["disabled_rules"] = json.loads(result.pop("rules_json"))
        return result

    def set_rule_policy(self, project_id: str, rules: list[str] | tuple[str, ...], expected_version: int, actor: str | None = None) -> dict:
        if not isinstance(rules, (list, tuple)) or any(not isinstance(item, str) or not item for item in rules):
            raise ValueError("invalid disabled rule list")
        encoded, now = self._json(sorted(set(rules))), self._now()
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT max(version) FROM rule_policies WHERE project_id=?", (str(project_id),)).fetchone()[0] or 0
            if int(expected_version) != current:
                raise VersionConflict("stale rule policy version")
            version, digest = current + 1, hashlib.sha256(encoded.encode()).hexdigest()
            db.execute("INSERT INTO rule_policies VALUES(?,?,?,?,?)", (str(project_id), version, encoded, digest, now))
            self._audit_db(db, actor, "rule_policy.updated", project_id, {"version": version})
            db.execute("COMMIT")
        return {"version": version, "hash": digest, "disabled_rules": json.loads(encoded)}

    def create_scan(
        self,
        subject_id: str,
        project_id: str,
        input_id: str,
        standard: str,
        standard_category: str,
        scan_scope: str = "all",
        source_snapshot: dict | None = None,
        **unsafe,
    ) -> dict:
        if scan_scope == "library":
            standard, standard_category = "local", "all"
        if (
            unsafe
            or not isinstance(standard, str)
            or not isinstance(standard_category, str)
            or scan_scope not in SCAN_SCOPE_CATEGORIES
        ):
            raise ValueError("unsupported scan options")
        required_scan_permission = {
            "library": "scan.library.create",
            "source": "scan.source.create",
            "all": None,
        }[scan_scope]
        if (required_scan_permission and not self.can(subject_id, project_id, required_scan_permission)) or (
            scan_scope == "all" and not all(self.can(subject_id, project_id, permission) for permission in SCOPED_SCAN_PERMISSIONS)
        ):
            raise PermissionError("project access denied")
        # Validate the selection before reserving a durable round.
        from .standards import resolve_standard_selection

        resolve_standard_selection(standard, standard_category)
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if (required_scan_permission and not self.can(subject_id, project_id, required_scan_permission)) or (
                scan_scope == "all" and not all(self.can(subject_id, project_id, permission) for permission in SCOPED_SCAN_PERMISSIONS)
            ):
                raise PermissionError("project access denied")
            source = db.execute("SELECT * FROM inputs WHERE input_id=? AND project_id=?", (str(input_id), str(project_id))).fetchone()
            if not source:
                raise KeyError("input not found")
            if not Path(source["path"]).is_file():
                raise ValueError("input file is no longer available; upload it again")
            policy = db.execute("SELECT * FROM rule_policies WHERE project_id=? ORDER BY version DESC LIMIT 1", (str(project_id),)).fetchone()
            if not policy:
                raise KeyError("rule policy not found")
            round_number = (db.execute("SELECT max(round_number) FROM scan_runs WHERE project_id=?", (str(project_id),)).fetchone()[0] or 0) + 1
            disabled_rules = json.loads(policy["rules_json"])
            snapshot = {
                "input_id": str(input_id), "input_hash": source["content_hash"],
                "standard": standard, "standard_category": standard_category,
                "scan_scope": scan_scope,
                "disabled_rules": disabled_rules, "rule_policy_version": policy["version"],
                "rule_policy_hash": policy["hash"], "scanner_version": _scanner_version(),
                "requested_by": str(subject_id),
            }
            if source_snapshot:
                allowed = {
                    "gitlab_mapping_id", "gitlab_project_id", "gitlab_path_with_namespace",
                    "gitlab_ref_type", "gitlab_ref_name", "gitlab_commit_sha",
                    "gitlab_archive_sha256", "gitlab_default_branch", "gitlab_fetched_at",
                    "gitlab_archive_root",
                    "tracker_service_id", "tracker_environment_id", "tracker_token_ref",
                }
                if not isinstance(source_snapshot, dict) or not set(source_snapshot) <= allowed:
                    raise ValueError("invalid source snapshot")
                snapshot.update(source_snapshot)
            run_id, revision_id, now = str(uuid.uuid4()), str(uuid.uuid4()), self._now()
            if snapshot.get("gitlab_mapping_id"):
                # Allocate under BEGIN IMMEDIATE; tombstoned runs still reserve
                # their version so deletion/restart cannot reuse a result branch.
                day = dt.datetime.fromisoformat(now).astimezone(dt.timezone(dt.timedelta(hours=9))).date()
                start = dt.datetime.combine(day, dt.time(), dt.timezone(dt.timedelta(hours=9)))
                previous = db.execute(
                    "SELECT snapshot_json FROM scan_runs WHERE project_id=? "
                    "AND created_at>=? AND created_at<?",
                    (str(project_id), start.astimezone(dt.timezone.utc).isoformat(),
                     (start + dt.timedelta(days=1)).astimezone(dt.timezone.utc).isoformat()),
                ).fetchall()
                version = 1 + max((int(json.loads(row[0]).get("gitlab_result_version", 0)) for row in previous), default=0)
                project_name = db.execute("SELECT name FROM projects WHERE project_id=?", (str(project_id),)).fetchone()[0]
                display = db.execute("SELECT display FROM subjects WHERE subject_id=?", (str(subject_id),)).fetchone()[0]
                # Keep Korean names readable, but exclude Git ref syntax and
                # bound UTF-8 length. Project ID disambiguates normalized names.
                slug = re.sub(r"[^\w-]+", "-", project_name, flags=re.UNICODE).strip("-_")
                slug = slug.encode("utf-8")[:72].decode("utf-8", errors="ignore") or "project"
                snapshot.update({
                    "project_name": project_name, "requested_by_display": display,
                    "gitlab_result_date": day.isoformat(), "gitlab_result_version": version,
                    "gitlab_result_branch": f"koda/results/{slug}/{day:%Y%m%d}/round-{version}",
                })
            db.execute(
                "INSERT INTO scan_runs(run_id,project_id,round_number,status,standard,standard_category,input_id,policy_version,requested_by,snapshot_json,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, str(project_id), round_number, "queued", standard, standard_category, str(input_id), policy["version"], str(subject_id), self._json(snapshot), now),
            )
            db.execute("INSERT INTO analysis_revisions(revision_id,run_id,sequence,snapshot_json,created_at) VALUES(?,?,?,?,?)", (revision_id, run_id, 1, self._json(snapshot), now))
            self._audit_db(db, subject_id, "scan.created", project_id, {"run_id": run_id, "round_number": round_number})
            db.execute("COMMIT")
        return self.run(run_id)

    def mark_run_running(self, run_id: str) -> bool:
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
            if not row or row["status"] != "queued" or row["cancel_requested"]:
                db.execute("ROLLBACK")
                return False
            snapshot = json.loads(row["snapshot_json"])
            owner = snapshot.get("schedule_run_id") if snapshot.get("source_type") == "scheduled_server" else None
            if snapshot.get("source_type") == "scheduled_server":
                parent = db.execute(
                    "SELECT 1 FROM schedule_runs WHERE schedule_run_id=? AND run_id=? AND status='running'",
                    (owner, str(run_id)),
                ).fetchone()
                if not parent:
                    db.execute("ROLLBACK")
                    return False
            elif self._next_manual_run(db) != str(run_id):
                db.execute("ROLLBACK")
                return False
            busy = (
                db.execute("SELECT 1 FROM scan_runs WHERE status IN ('running','cancelling') LIMIT 1").fetchone()
                or db.execute(
                    "SELECT 1 FROM schedule_runs WHERE status IN ('running','cancelling') "
                    "AND schedule_run_id<>? LIMIT 1", (owner or "",),
                ).fetchone()
                or self._schedule_api_busy(db)
            )
            if busy:
                db.execute("ROLLBACK")
                return False
            changed = db.execute(
                "UPDATE scan_runs SET status='running',stage='preparing',progress=5 "
                "WHERE run_id=? AND status='queued' AND cancel_requested=0",
                (str(run_id),),
            ).rowcount
            db.execute("COMMIT")
            return bool(changed)

    def set_run_progress(self, run_id: str, stage: str, progress: int) -> bool:
        if stage not in {"preparing", "scanning", "finalizing"} or not 0 <= int(progress) <= 99:
            raise ValueError("invalid run progress")
        with self._db() as db:
            changed = db.execute(
                "UPDATE scan_runs SET stage=?,progress=? WHERE run_id=? AND status='running' AND cancel_requested=0",
                (stage, int(progress), str(run_id)),
            ).rowcount
            return bool(changed)

    def request_cancel(self, run_id: str, actor: str | None = None) -> dict:
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
            if not row:
                raise KeyError("run not found")
            if row["status"] not in {"queued", "running", "cancelling"}:
                raise ValueError("run is not cancellable")
            status, stage, completed = (
                ("cancelled", "cancelled", self._now())
                if row["status"] == "queued"
                else ("cancelling", "cancelling", None)
            )
            db.execute(
                "UPDATE scan_runs SET cancel_requested=1,status=?,stage=?,completed_at=COALESCE(?,completed_at) WHERE run_id=?",
                (status, stage, completed, str(run_id)),
            )
            self._audit_db(db, actor, "scan.cancel_requested", row["project_id"], {"run_id": str(run_id)})
            db.execute("COMMIT")
        result = self.run(run_id)
        if result["status"] == "cancelled":
            self.cleanup_input_for_run(run_id)
        return result

    def recover_incomplete_runs(self) -> list[str]:
        with self._lock, self._db() as db:
            db.execute("UPDATE scan_runs SET status='cancelled',stage='cancelled',completed_at=? WHERE status IN ('running','cancelling') AND cancel_requested=1 AND run_id NOT IN (SELECT run_id FROM schedule_runs WHERE run_id IS NOT NULL)", (self._now(),))
            db.execute("UPDATE scan_runs SET status='queued',stage='queued',progress=0 WHERE status IN ('running','cancelling') AND cancel_requested=0 AND run_id NOT IN (SELECT run_id FROM schedule_runs WHERE run_id IS NOT NULL)")
            queued = [row[0] for row in db.execute("SELECT run_id FROM scan_runs WHERE status='queued' AND run_id NOT IN (SELECT run_id FROM schedule_runs WHERE run_id IS NOT NULL) ORDER BY created_at")]
        self.cleanup_terminal_inputs()
        return queued

    def recover_tracker_deliveries(self) -> list[str]:
        with self._lock, self._db() as db:
            db.execute("UPDATE tracker_deliveries SET status='pending',updated_at=? WHERE status='sending' AND run_id NOT IN (SELECT run_id FROM schedule_runs WHERE run_id IS NOT NULL)", (self._now(),))
            return [row[0] for row in db.execute(
                "SELECT d.run_id FROM tracker_deliveries d JOIN scan_runs r USING(run_id) "
                "WHERE d.status='pending' AND r.status='completed' AND r.deleted_at IS NULL AND r.run_id NOT IN (SELECT run_id FROM schedule_runs WHERE run_id IS NOT NULL) ORDER BY d.created_at"
            )]

    def recover_gitlab_results(self) -> list[str]:
        with self._lock, self._db() as db:
            db.execute("UPDATE tracker_deliveries SET gitlab_result_status='pending',updated_at=? WHERE gitlab_result_status='sending' AND run_id NOT IN (SELECT run_id FROM schedule_runs WHERE run_id IS NOT NULL)", (self._now(),))
            return [row[0] for row in db.execute(
                "SELECT d.run_id FROM tracker_deliveries d JOIN scan_runs r USING(run_id) "
                "WHERE d.gitlab_result_status='pending' AND d.status='completed' AND r.status='completed' AND r.deleted_at IS NULL AND r.run_id NOT IN (SELECT run_id FROM schedule_runs WHERE run_id IS NOT NULL) ORDER BY d.created_at"
            )]

    def cleanup_input_for_run(self, run_id: str) -> bool:
        """Remove a terminal run's source file while retaining its result metadata."""
        with self._lock:
            with self._db() as db:
                run = db.execute("SELECT input_id,status FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
                if not run or run["status"] not in TERMINAL_RUN_STATUSES:
                    return False
                active = db.execute(
                    "SELECT 1 FROM scan_runs WHERE input_id=? AND status NOT IN ('completed','failed','cancelled') LIMIT 1",
                    (run["input_id"],),
                ).fetchone()
                if active:
                    return False
                source = db.execute("SELECT path FROM inputs WHERE input_id=?", (run["input_id"],)).fetchone()
            if not source:
                return False
            if not source["path"]:
                return True  # Result-only scheduled input has no filesystem source.
            path = Path(source["path"])
            try:
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=False)
                else:
                    path.unlink(missing_ok=True)
            except OSError:
                return False
            return True

    def cleanup_terminal_inputs(self) -> int:
        with self._lock:
            with self._db() as db:
                run_ids = [row[0] for row in db.execute("SELECT run_id FROM scan_runs WHERE status IN ('completed','failed','cancelled')")]
            return sum(self.cleanup_input_for_run(run_id) for run_id in run_ids)

    def prune_schedule_runs(self, days: int = 90) -> int:
        """Delete terminal scheduled results older than the configured retention window."""
        days = int(days)
        if days < 1:
            raise ValueError("retention days must be positive")
        cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()
        paths: list[Path] = []
        deleted = 0
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            has_delivery_jobs = bool(db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='portal_delivery_jobs'"
            ).fetchone())
            delivery_gate = (
                " AND NOT EXISTS(SELECT 1 FROM portal_delivery_jobs j WHERE j.run_id=sr.run_id AND j.status IN ('queued','running'))"
                if has_delivery_jobs else ""
            )
            rows = db.execute(
                "SELECT sr.schedule_run_id,sr.run_id,r.input_id,i.path FROM schedule_runs sr "
                "LEFT JOIN scan_runs r ON r.run_id=sr.run_id LEFT JOIN inputs i ON i.input_id=r.input_id "
                "WHERE sr.created_at<? AND sr.cleanup_status='completed' AND sr.status IN ('completed','failed','cancelled') AND NOT EXISTS(SELECT 1 FROM tracker_deliveries d WHERE d.run_id=sr.run_id AND (d.status='sending' OR d.gitlab_result_status='sending'))" + delivery_gate,
                (cutoff,),
            ).fetchall()
            for row in rows:
                schedule_run_id, run_id, input_id = row["schedule_run_id"], row["run_id"], row["input_id"]
                db.execute("DELETE FROM schedule_runs WHERE schedule_run_id=?", (schedule_run_id,))
                if run_id:
                    if has_delivery_jobs:
                        db.execute("DELETE FROM portal_delivery_jobs WHERE run_id=?", (run_id,))
                    db.execute("DELETE FROM tracker_deliveries WHERE run_id=?", (run_id,))
                    db.execute("DELETE FROM gitlab_issue_deliveries WHERE run_id=?", (run_id,))
                    db.execute("DELETE FROM gitlab_issue_links WHERE run_id=?", (run_id,))
                    db.execute("DELETE FROM analysis_revisions WHERE run_id=?", (run_id,))
                    # Inputs may be shared with a manually-created run; only
                    # remove the row and path when this is the final reference.
                    shared = db.execute(
                        "SELECT 1 FROM scan_runs WHERE input_id=? AND run_id<>? LIMIT 1", (input_id, run_id)
                    ).fetchone() if input_id else None
                    db.execute("DELETE FROM scan_runs WHERE run_id=?", (run_id,))
                    if input_id and not shared:
                        db.execute("DELETE FROM inputs WHERE input_id=?", (input_id,))
                        if row["path"]:
                            paths.append(Path(row["path"]))
                deleted += 1
            db.execute("COMMIT")
        for path in paths:
            try:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink(missing_ok=True)
            except OSError:
                # Retention is best effort for already-unlinked files; the
                # durable rows are removed only after all references are gone.
                continue
        return deleted

    def complete_run(self, run_id: str, result: dict | None = None, error: str | None = None) -> None:
        # Encoding large findings/source context holds no SQLite write lock.
        encoded_result = self._json(result) if result is not None else None
        encoded_summary = self._json(self._result_summary(result))
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT status,cancel_requested,snapshot_json,deleted_at FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
            if not current or current["deleted_at"] is not None:
                db.execute("ROLLBACK")
                raise KeyError("run not found")
            if current["status"] in TERMINAL_RUN_STATUSES:
                # A supervisor and child may finish together; the first durable
                # terminal state wins, including an already accepted cancel.
                db.execute("ROLLBACK")
                self.cleanup_input_for_run(run_id)
                return
            cancelled = bool(current["cancel_requested"])
            status = "cancelled" if cancelled else ("failed" if error else "completed")
            stage, progress, completed = status, (0 if cancelled else 100), self._now()
            result_json = None if cancelled else encoded_result
            db.execute(
                "UPDATE scan_runs SET status=?,stage=?,progress=?,result_json=?,result_summary_json=?,error=?,completed_at=? WHERE run_id=?",
                (status, stage, progress, result_json, None if cancelled else encoded_summary, None if cancelled else error, completed, str(run_id)),
            )
            db.execute("UPDATE analysis_revisions SET result_json=? WHERE run_id=? AND sequence=1", (result_json, str(run_id)))
            row = db.execute("SELECT requested_by,project_id FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
            if row:
                self._audit_db(db, row["requested_by"], f"scan.{status}", row["project_id"], {"run_id": str(run_id), "error": error or ""})
            if status == "completed" and json.loads(current["snapshot_json"]).get("gitlab_mapping_id"):
                db.execute(
                    "INSERT OR IGNORE INTO tracker_deliveries(run_id,status,attempts,created_at,updated_at) VALUES(?,'pending',0,?,?)",
                    (str(run_id), completed, completed),
                )
                db.execute(
                    "INSERT OR IGNORE INTO gitlab_issue_deliveries(run_id,status,attempts,created_at,updated_at) VALUES(?,'pending',0,?,?)",
                    (str(run_id), completed, completed),
                )
            db.execute("COMMIT")
        self.cleanup_input_for_run(run_id)

    def tracker_delivery(self, run_id: str) -> dict | None:
        with self._db() as db:
            row = self._dict(db.execute(
                "SELECT d.*,r.round_number,r.snapshot_json FROM tracker_deliveries d JOIN scan_runs r USING(run_id) WHERE d.run_id=?",
                (str(run_id),),
            ).fetchone())
            if row:
                row["gitlab_issue_urls"] = json.loads(row.pop("gitlab_issue_urls_json") or "[]")
                snapshot = json.loads(row.pop("snapshot_json") or "{}")
                row["gitlab_project_id"] = snapshot.get("gitlab_project_id")
                row["gitlab_repository"] = snapshot.get("gitlab_path_with_namespace")
                row["gitlab_result_branch"] = snapshot.get("gitlab_result_branch")
                row["gitlab_result_round"] = snapshot.get("gitlab_result_version") or row.get("round_number")
                match = re.search(r"/merge_requests/(\d+)(?:[/?#]|$)", str(row.get("gitlab_merge_request_url") or ""))
                row["gitlab_merge_request_iid"] = int(match.group(1)) if match else None
            return row

    def skip_source_tracker_delivery(self, run_id: str) -> dict:
        """Retain the GitLab delivery record without contacting Tracker."""
        run = self.run(run_id)
        if run.get("status") != "completed" or run.get("snapshot", {}).get("scan_scope") != "source":
            raise ValueError("completed source-only run required")
        with self._lock, self._db() as db:
            db.execute("UPDATE tracker_deliveries SET status='skipped',last_error=NULL,updated_at=? WHERE run_id=?", (self._now(), str(run_id)))
        return self.tracker_delivery(run_id) or {}

    def claim_tracker_delivery(self, run_id: str, *, retry: bool = False) -> dict:
        now, expected = self._now(), "failed" if retry else "pending"
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE tracker_deliveries SET status='sending',attempts=attempts+1,last_error=NULL,updated_at=? "
                "WHERE run_id=? AND status=? AND EXISTS(SELECT 1 FROM scan_runs WHERE run_id=? AND status='completed' AND deleted_at IS NULL)",
                (now, str(run_id), expected, str(run_id)),
            ).rowcount
            row = db.execute("SELECT * FROM tracker_deliveries WHERE run_id=?", (str(run_id),)).fetchone()
            if not row:
                db.execute("ROLLBACK")
                raise KeyError("Tracker delivery not found")
            if not changed:
                db.execute("ROLLBACK")
                raise ValueError("Tracker delivery cannot be claimed")
            run = db.execute("SELECT requested_by,project_id FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
            self._audit_db(db, run["requested_by"], "tracker.sending", run["project_id"], {"run_id": str(run_id)})
            db.execute("COMMIT")
            return dict(row)

    def finish_tracker_delivery(self, run_id: str, status: str, *, tracker_run_id: str = "", tracker_run_url: str = "", error: str = "") -> dict:
        if status not in {"completed", "failed"}:
            raise ValueError("invalid Tracker delivery result")
        now = self._now()
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE tracker_deliveries SET status=?,tracker_run_id=COALESCE(?,tracker_run_id),"
                "tracker_run_url=COALESCE(?,tracker_run_url),last_error=?,updated_at=? WHERE run_id=? AND status='sending'",
                (status, tracker_run_id or None, tracker_run_url or _tracker_run_url(tracker_run_id) or None, error[:1000] or None, now, str(run_id)),
            ).rowcount
            if not changed:
                db.execute("ROLLBACK")
                raise ValueError("Tracker delivery is not being sent")
            row = dict(db.execute("SELECT * FROM tracker_deliveries WHERE run_id=?", (str(run_id),)).fetchone())
            run = db.execute("SELECT requested_by,project_id FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
            self._audit_db(db, run["requested_by"], f"tracker.{status}", run["project_id"], {
                "run_id": str(run_id), "tracker_run_id": tracker_run_id, "error": error[:200],
            })
            db.execute("COMMIT")
            row["gitlab_issue_urls"] = json.loads(row.pop("gitlab_issue_urls_json") or "[]")
            return row

    def claim_gitlab_result(
        self, run_id: str, *, retry: bool = False, allow_tracker_failure: bool = False, refresh: bool = False,
    ) -> dict:
        expected = ("failed", "pending", "completed") if refresh else (("failed", "pending") if retry else ("pending",))
        placeholders = ",".join("?" for _ in expected)
        tracker_status = "status IN ('completed','failed','skipped')" if allow_tracker_failure else "status IN ('completed','skipped')"
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                f"UPDATE tracker_deliveries SET gitlab_result_status='sending',gitlab_result_attempts=gitlab_result_attempts+1,gitlab_result_last_error=NULL,updated_at=? "
                f"WHERE run_id=? AND gitlab_result_status IN ({placeholders}) AND {tracker_status} AND EXISTS(SELECT 1 FROM scan_runs WHERE run_id=? AND status='completed' AND deleted_at IS NULL)",
                (self._now(), str(run_id), *expected, str(run_id)),
            ).rowcount
            row = db.execute("SELECT * FROM tracker_deliveries WHERE run_id=?", (str(run_id),)).fetchone()
            if not row:
                db.execute("ROLLBACK")
                raise KeyError("Tracker delivery not found")
            if not changed:
                db.execute("ROLLBACK")
                raise ValueError("GitLab result cannot be claimed")
            db.execute("COMMIT")
            return dict(row)

    def finish_gitlab_result(self, run_id: str, status: str, *, error: str = "", merge_request_url: str = "", issue_urls: list[str] | None = None) -> dict:
        if status not in {"completed", "failed"}:
            raise ValueError("invalid GitLab result status")
        with self._lock, self._db() as db:
            changed = db.execute(
                "UPDATE tracker_deliveries SET gitlab_result_status=?,gitlab_result_last_error=?,gitlab_merge_request_url=?,gitlab_issue_urls_json=?,updated_at=? WHERE run_id=? AND gitlab_result_status='sending'",
                (status, error[:1000] or None, merge_request_url or None, self._json(issue_urls or []), self._now(), str(run_id)),
            ).rowcount
            if not changed:
                raise ValueError("GitLab result is not being sent")
        return self.tracker_delivery(run_id)

    def gitlab_issue_delivery(self, run_id: str) -> dict | None:
        with self._db() as db:
            row = self._dict(db.execute(
                "SELECT d.*,r.round_number,r.snapshot_json FROM gitlab_issue_deliveries d JOIN scan_runs r USING(run_id) WHERE d.run_id=?",
                (str(run_id),),
            ).fetchone())
            if row:
                snapshot = json.loads(row.pop("snapshot_json") or "{}")
                row["gitlab_project_id"] = snapshot.get("gitlab_project_id")
                row["gitlab_repository"] = snapshot.get("gitlab_path_with_namespace")
                row["gitlab_result_round"] = snapshot.get("gitlab_result_version") or row.get("round_number")
                row["items"] = [dict(item) for item in db.execute(
                    "SELECT * FROM gitlab_issue_links WHERE run_id=? ORDER BY finding_index", (str(run_id),),
                )]
            return row

    def recover_gitlab_issue_deliveries(self) -> list[str]:
        with self._lock, self._db() as db:
            db.execute("UPDATE gitlab_issue_deliveries SET status='pending',updated_at=? WHERE status='sending' AND run_id NOT IN (SELECT run_id FROM schedule_runs WHERE run_id IS NOT NULL)", (self._now(),))
            return [row[0] for row in db.execute(
                "SELECT d.run_id FROM gitlab_issue_deliveries d JOIN scan_runs r USING(run_id) "
                "WHERE d.status='pending' AND r.status='completed' AND r.deleted_at IS NULL AND r.run_id NOT IN (SELECT run_id FROM schedule_runs WHERE run_id IS NOT NULL) ORDER BY d.created_at"
            )]

    def claim_gitlab_issue_delivery(self, run_id: str, *, retry: bool = False) -> dict:
        now = self._now()
        expected = ("failed", "partial") if retry else ("pending",)
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if retry:
                db.execute(
                    "UPDATE gitlab_issue_links SET status='pending',last_error=NULL,updated_at=? WHERE run_id=? AND status='failed'",
                    (now, str(run_id)),
                )
            placeholders = ",".join("?" for _ in expected)
            changed = db.execute(
                f"UPDATE gitlab_issue_deliveries SET status='sending',attempts=attempts+1,last_error=NULL,updated_at=? "
                f"WHERE run_id=? AND status IN ({placeholders}) AND EXISTS(SELECT 1 FROM scan_runs WHERE run_id=? AND status='completed' AND deleted_at IS NULL)",
                (now, str(run_id), *expected, str(run_id)),
            ).rowcount
            row = db.execute("SELECT * FROM gitlab_issue_deliveries WHERE run_id=?", (str(run_id),)).fetchone()
            if not row:
                db.execute("ROLLBACK")
                raise KeyError("GitLab issue delivery not found")
            if not changed:
                db.execute("ROLLBACK")
                raise ValueError("GitLab issue delivery cannot be claimed")
            run = db.execute("SELECT requested_by,project_id FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
            self._audit_db(db, run["requested_by"], "gitlab.issues.sending", run["project_id"], {"run_id": str(run_id), "retry": retry})
            db.execute("COMMIT")
            return dict(row)

    def prepare_gitlab_issue_items(self, run_id: str, gitlab_project_id: int, items: list[dict]) -> list[dict]:
        now = self._now()
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM gitlab_issue_deliveries WHERE run_id=? AND status='sending'", (str(run_id),)).fetchone():
                db.execute("ROLLBACK")
                raise ValueError("GitLab issue delivery is not being sent")
            for item in items:
                db.execute(
                    "INSERT OR IGNORE INTO gitlab_issue_links(link_id,run_id,gitlab_project_id,finding_key,finding_index,status,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,'pending',?,?)",
                    (str(uuid.uuid4()), str(run_id), int(gitlab_project_id), str(item["finding_key"]), int(item["finding_index"]), now, now),
                )
            db.execute("UPDATE gitlab_issue_deliveries SET total_count=?,updated_at=? WHERE run_id=?", (len(items), now, str(run_id)))
            db.execute("COMMIT")
        return (self.gitlab_issue_delivery(run_id) or {}).get("items", [])

    def claim_gitlab_issue_item(self, run_id: str, finding_key: str) -> dict:
        now = self._now()
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM gitlab_issue_links WHERE run_id=? AND finding_key=?", (str(run_id), str(finding_key)),
            ).fetchone()
            if not row:
                db.execute("ROLLBACK")
                raise KeyError("GitLab issue item not found")
            previous = row["status"]
            if previous in {"pending", "failed"}:
                db.execute(
                    "UPDATE gitlab_issue_links SET status='creating',last_error=NULL,updated_at=? WHERE run_id=? AND finding_key=?",
                    (now, str(run_id), str(finding_key)),
                )
            elif previous not in {"creating", "created", "reused"}:
                db.execute("ROLLBACK")
                raise ValueError("GitLab issue item cannot be claimed")
            db.execute("COMMIT")
            result = dict(row)
            result["previous_status"] = previous
            return result

    def finish_gitlab_issue_item(self, run_id: str, finding_key: str, status: str, *, issue_iid: int | None = None, issue_url: str = "", error: str = "") -> dict:
        if status not in {"created", "reused", "failed"}:
            raise ValueError("invalid GitLab issue item result")
        with self._lock, self._db() as db:
            changed = db.execute(
                "UPDATE gitlab_issue_links SET status=?,issue_iid=?,issue_url=?,last_error=?,updated_at=? WHERE run_id=? AND finding_key=?",
                (status, issue_iid, issue_url or None, error[:1000] or None, self._now(), str(run_id), str(finding_key)),
            ).rowcount
            if not changed:
                raise KeyError("GitLab issue item not found")
            return dict(db.execute("SELECT * FROM gitlab_issue_links WHERE run_id=? AND finding_key=?", (str(run_id), str(finding_key))).fetchone())

    def previous_gitlab_issue(self, gitlab_project_id: int, finding_key: str, run_id: str) -> dict | None:
        with self._db() as db:
            return self._dict(db.execute(
                "SELECT * FROM gitlab_issue_links WHERE gitlab_project_id=? AND finding_key=? AND run_id<>? "
                "AND status IN ('created','reused') AND issue_iid IS NOT NULL ORDER BY created_at DESC LIMIT 1",
                (int(gitlab_project_id), str(finding_key), str(run_id)),
            ).fetchone())

    def finish_gitlab_issue_delivery(self, run_id: str, *, error: str = "") -> dict:
        now = self._now()
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if error:
                db.execute(
                    "UPDATE gitlab_issue_links SET status='failed',last_error=?,updated_at=? WHERE run_id=? AND status IN ('pending','creating')",
                    (error[:1000], now, str(run_id)),
                )
            counts = {row["status"]: row["count"] for row in db.execute(
                "SELECT status,count(*) AS count FROM gitlab_issue_links WHERE run_id=? GROUP BY status", (str(run_id),),
            )}
            created, reused, failed = counts.get("created", 0), counts.get("reused", 0), counts.get("failed", 0)
            status = "completed" if not failed else ("partial" if created or reused else "failed")
            changed = db.execute(
                "UPDATE gitlab_issue_deliveries SET status=?,created_count=?,reused_count=?,failed_count=?,last_error=?,updated_at=? "
                "WHERE run_id=? AND status='sending'",
                (status, created, reused, failed, error[:1000] or None, now, str(run_id)),
            ).rowcount
            if not changed:
                db.execute("ROLLBACK")
                raise ValueError("GitLab issue delivery is not being sent")
            run = db.execute("SELECT requested_by,project_id FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
            self._audit_db(db, run["requested_by"], f"gitlab.issues.{status}", run["project_id"], {
                "run_id": str(run_id), "created": created, "reused": reused, "failed": failed, "error": error[:200],
            })
            db.execute("COMMIT")
        return self.gitlab_issue_delivery(run_id)

    @staticmethod
    def _result_summary(result: dict | None) -> dict:
        """Keep only small presentation metadata; findings stay in the result."""
        result = result if isinstance(result, dict) else {}
        counts = dict.fromkeys(("critical", "high", "medium", "low", "info"), 0)
        groups = dict.fromkeys(("library", "source", "quality"), 0)
        findings = result.get("findings") if isinstance(result.get("findings"), list) else []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity", "info")).lower()
            counts[severity if severity in counts else "info"] += 1
            category = str(finding.get("category", "")).lower()
            group = "library" if category == "dependencies" else "quality" if category in {"quality", "screen_quality"} else "source"
            groups[group] += 1
        summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
        def scalars(value, keys, max_length=1000):
            if not isinstance(value, dict):
                return {}
            return {key: (value[key][:max_length] if isinstance(value[key], str) else value[key])
                    for key in keys if key in value and isinstance(value[key], (str, int, float, bool, type(None)))}
        small_summary = scalars(summary, ("finding_count", "risk_score", "target_count"))
        for key in ("by_severity", "by_category"):
            if isinstance(summary.get(key), dict):
                small_summary[key] = {str(name)[:128]: number for name, number in list(summary[key].items())[:64]
                                      if isinstance(number, (int, float))}
        stages = result.get("analysis_stages") if isinstance(result.get("analysis_stages"), dict) else {}
        scan = scalars(result.get("scan"), ("scope", "kind", "standard", "standard_category", "enable_local_vulnerabilities", "path"), 512)
        if isinstance(result.get("scan"), dict) and isinstance(result["scan"].get("local_vulnerability"), dict):
            scan["local_vulnerability"] = scalars(result["scan"]["local_vulnerability"], (
                "status", "version", "queried_components", "matched_vulnerabilities", "available", "warning",
            ))
        warnings = result.get("warnings") if isinstance(result.get("warnings"), list) else []
        return {
            "summary": small_summary,
            "analysis_stages": {key: scalars(stages[key], (
                "status", "finding_count", "version", "queried_components", "warning", "completed_at", "duration_seconds",
            )) for key in ("source", "library", "quality") if key in stages},
            "scan": scan,
            "warnings": [str(item)[:1000] for item in warnings[:20]],
            "severity_counts": counts, "group_counts": groups, "finding_count": sum(counts.values()),
        }

    def _load_result_summary(self, run_id: str) -> dict | None:
        with self._db() as db:
            row = db.execute(
                "SELECT result_summary_json,status,completed_at FROM scan_runs WHERE run_id=? AND deleted_at IS NULL",
                (str(run_id),),
            ).fetchone()
            if not row:
                raise KeyError("run not found")
            if row["result_summary_json"] is not None:
                return json.loads(row["result_summary_json"])
            # Legacy results are projected inside SQLite. Source snippets and
            # complete findings never cross the connection for a summary read.
            metadata = db.execute(
                "SELECT result_json IS NOT NULL AS has_result,json_object("
                "'summary',json_extract(result_json,'$.summary'),"
                "'analysis_stages',json_extract(result_json,'$.analysis_stages'),"
                "'scan',json_extract(result_json,'$.scan'),"
                "'warnings',json_extract(result_json,'$.warnings')) AS metadata "
                "FROM scan_runs WHERE run_id=? AND deleted_at IS NULL", (str(run_id),),
            ).fetchone()
            if not metadata:
                return None
            value = self._result_summary(json.loads(metadata["metadata"]))
            for count in db.execute(
                "SELECT lower(COALESCE(json_extract(f.value,'$.severity'),'info')) AS severity,"
                "lower(COALESCE(json_extract(f.value,'$.category'),'')) AS category,count(*) AS count "
                "FROM scan_runs r,json_each(r.result_json,'$.findings') f "
                "WHERE r.run_id=? AND r.deleted_at IS NULL AND f.type='object' GROUP BY severity,category",
                (str(run_id),),
            ):
                severity, category, number = count["severity"], count["category"], count["count"]
                value["severity_counts"][severity if severity in value["severity_counts"] else "info"] += number
                group = "library" if category == "dependencies" else "quality" if category in {"quality", "screen_quality"} else "source"
                value["group_counts"][group] += number
            value["finding_count"] = sum(value["severity_counts"].values())
        encoded = self._json(value)
        # Encoding and legacy JSON traversal finish before this brief write.
        with self._db() as db:
            db.execute(
                "UPDATE scan_runs SET result_summary_json=? WHERE run_id=? AND deleted_at IS NULL "
                "AND result_summary_json IS NULL AND status=? AND completed_at IS ?",
                (encoded, str(run_id), row["status"], row["completed_at"]),
            )
        return value

    def backfill_result_summaries(self, limit: int = 10) -> int:
        """Upgrade legacy rows in bounded worker batches, outside HTTP paths."""
        with self._db() as db:
            run_ids = [row[0] for row in db.execute(
                "SELECT run_id FROM scan_runs WHERE deleted_at IS NULL AND status='completed' "
                "AND result_summary_json IS NULL ORDER BY created_at DESC LIMIT ?", (min(100, max(1, int(limit))),),
            )]
        for run_id in run_ids:
            try:
                self._load_result_summary(run_id)
            except KeyError:
                continue  # A concurrent deletion owns its result cleanup.
        return len(run_ids)

    @staticmethod
    def _run_metadata(row) -> dict:
        if not row:
            raise KeyError("run not found")
        value = dict(row)
        display = value.get("requested_by_id") or ("schedule-worker" if value.get("requested_by") == "schedule-worker" else "기록 없음")
        value["requested_by_id"] = value["requested_by_display"] = display
        return value

    def run_status(self, run_id: str) -> dict:
        columns = ",".join(f"r.{name}" for name in RUN_METADATA_COLUMNS)
        with self._db() as db:
            row = db.execute(
                f"SELECT {columns},s.display AS requested_by_id FROM scan_runs r "
                "LEFT JOIN subjects s ON s.subject_id=r.requested_by WHERE r.run_id=? AND r.deleted_at IS NULL",
                (str(run_id),),
            ).fetchone()
            value = self._run_metadata(row)
            pending = False
            if value["status"] == "completed":
                pending = bool(db.execute(
                    "SELECT 1 FROM tracker_deliveries WHERE run_id=? AND (status IN ('pending','sending') "
                    "OR (status IN ('completed','skipped') AND gitlab_result_status IN ('pending','sending'))) "
                    "UNION ALL SELECT 1 FROM gitlab_issue_deliveries WHERE run_id=? AND status IN ('pending','sending') LIMIT 1",
                    (str(run_id), str(run_id)),
                ).fetchone())
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='portal_delivery_jobs'").fetchone():
                    pending = pending or bool(db.execute(
                        "SELECT 1 FROM portal_delivery_jobs WHERE run_id=? AND status IN ('queued','running') LIMIT 1",
                        (str(run_id),),
                    ).fetchone())
            value["publication_pending"] = pending
        return value

    def run_summary(self, run_id: str, *, cached_only: bool = False) -> dict:
        value = self.run_status(run_id)
        snapshot = RUN_LIST_SNAPSHOT_SQL if cached_only else "r.snapshot_json"
        with self._db() as db:
            row = db.execute(f"SELECT {snapshot},r.result_summary_json FROM scan_runs r WHERE r.run_id=? AND r.deleted_at IS NULL", (str(run_id),)).fetchone()
        if not row:
            raise KeyError("run not found")
        value["snapshot"] = json.loads(row["snapshot_json"])
        value["scan_scope"] = value["snapshot"].get("scan_scope", "all")
        value["summary_pending"] = value["status"] == "completed" and row["result_summary_json"] is None
        value["result"] = (json.loads(row["result_summary_json"]) if row["result_summary_json"] else None) if cached_only else self._load_result_summary(run_id)
        if not cached_only and value["result"] is not None:
            value["summary_pending"] = False
        return value

    def project_summary(self, project_id: str) -> dict:
        with self._db() as db:
            return {
                "input_count": db.execute("SELECT count(*) FROM inputs WHERE project_id=?", (str(project_id),)).fetchone()[0],
                "run_count": db.execute("SELECT count(*) FROM scan_runs WHERE project_id=? AND deleted_at IS NULL", (str(project_id),)).fetchone()[0],
            }

    def dashboard_summary(self, project_ids: list[str]) -> dict:
        ids = list(dict.fromkeys(str(value) for value in project_ids))
        counts = dict.fromkeys(("critical", "high", "medium", "low", "info"), 0)
        output = {"total_runs": 0, "completed_runs": 0, "severity_counts": counts, "summary_pending": 0, "projects": []}
        if not ids:
            return output
        placeholders = ",".join("?" for _ in ids)
        with self._db() as db:
            aggregates = list(db.execute(
                "SELECT project_id,count(*) AS total,sum(status='completed') AS completed,"
                "sum(status='completed' AND result_summary_json IS NULL) AS pending,"
                + ",".join(
                    f"sum(CASE WHEN status='completed' THEN COALESCE(json_extract(result_summary_json,'$.severity_counts.{severity}'),0) ELSE 0 END) AS {severity}"
                    for severity in counts
                ) + f" FROM scan_runs WHERE project_id IN ({placeholders}) AND deleted_at IS NULL GROUP BY project_id", ids,
            ))
            for row in aggregates:
                output["total_runs"] += row["total"]
                output["completed_runs"] += row["completed"]
                output["summary_pending"] += row["pending"]
                for severity in counts:
                    counts[severity] += row[severity]
            for project_id in ids:
                summary = self.project_summary(project_id)
                latest = db.execute(
                    "SELECT run_id FROM scan_runs WHERE project_id=? AND deleted_at IS NULL ORDER BY created_at DESC,round_number DESC LIMIT 1",
                    (project_id,),
                ).fetchone()
                done = db.execute(
                    "SELECT run_id FROM scan_runs WHERE project_id=? AND deleted_at IS NULL AND status='completed' ORDER BY created_at DESC,round_number DESC LIMIT 1",
                    (project_id,),
                ).fetchone()
                output["projects"].append({
                    "project_id": project_id, **summary,
                    "latest": self.run_summary(latest[0], cached_only=True) if latest else None,
                    "latest_completed": self.run_summary(done[0], cached_only=True) if done else None,
                })
        return output

    @staticmethod
    def _page_values(page: int, page_size: int) -> tuple[int, int]:
        return max(1, int(page)), min(100, max(1, int(page_size)))

    def paginate_runs(self, project_ids: list[str], *, page=1, page_size=50, search="", status="", scan_scope="", source="") -> dict:
        page, page_size = self._page_values(page, page_size)
        result = {"items": [], "total": 0, "page": page, "page_size": page_size}
        ids = list(dict.fromkeys(str(value) for value in project_ids))
        if not ids:
            return result
        clauses = ["r.deleted_at IS NULL", "r.project_id IN (" + ",".join("?" for _ in ids) + ")"]
        values = list(ids)
        if status:
            clauses.append("COALESCE(sr.status,r.status)=?")
            values.append(str(status))
        if scan_scope:
            clauses.append("COALESCE(json_extract(r.snapshot_json,'$.scan_scope'),'all')=?")
            values.append(str(scan_scope))
        if source:
            clauses.append("COALESCE(json_extract(r.snapshot_json,'$.source_type'),'manual')=?")
            values.append(str(source))
        if search:
            clauses.append("(p.name LIKE ? ESCAPE '\\' OR s.display LIKE ? ESCAPE '\\' OR CAST(r.round_number AS TEXT) LIKE ? ESCAPE '\\' OR r.created_at LIKE ? ESCAPE '\\')")
            pattern = "%" + str(search)[:500].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            values.extend([pattern] * 4)
        where = " AND ".join(clauses)
        joins = "FROM scan_runs r JOIN projects p ON p.project_id=r.project_id LEFT JOIN subjects s ON s.subject_id=r.requested_by LEFT JOIN schedule_runs sr ON sr.run_id=r.run_id "
        columns = ",".join(f"r.{name}" for name in RUN_METADATA_COLUMNS)
        with self._db() as db:
            result["total"] = db.execute(f"SELECT count(*) {joins}WHERE {where}", values).fetchone()[0]
            rows = db.execute(
                f"SELECT {columns},{RUN_LIST_SNAPSHOT_SQL},s.display AS requested_by_id,p.name AS project_name {joins}WHERE {where} "
                "ORDER BY r.created_at DESC,r.round_number DESC,r.run_id LIMIT ? OFFSET ?",
                (*values, page_size, (page - 1) * page_size),
            ).fetchall()
            result["items"] = [self._listed_run(db, row) for row in rows]
        return result

    def run_findings(self, run_id: str, *, page=1, page_size=50, search="", group="", severity="") -> dict:
        page, page_size = self._page_values(page, page_size)
        self.run_status(run_id)
        clauses = ["r.run_id=?", "r.deleted_at IS NULL", "f.type='object'"]
        values = [str(run_id)]
        category = "lower(COALESCE(json_extract(f.value,'$.category'),''))"
        if group:
            if group not in {"library", "source", "quality"}:
                raise ValueError("invalid finding group")
            clauses.append({"library": f"{category}='dependencies'", "quality": f"{category} IN ('quality','screen_quality')", "source": f"{category} NOT IN ('dependencies','quality','screen_quality')"}[group])
        if severity:
            clauses.append("lower(COALESCE(json_extract(f.value,'$.severity'),'info'))=?")
            values.append(str(severity).lower())
        if search:
            clauses.append("(json_extract(f.value,'$.title') LIKE ? ESCAPE '\\' OR json_extract(f.value,'$.rule_id') LIKE ? ESCAPE '\\' OR json_extract(f.value,'$.path') LIKE ? ESCAPE '\\')")
            pattern = "%" + str(search)[:500].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            values.extend([pattern] * 3)
        where = " AND ".join(clauses)
        keys = ("severity", "category", "rule_id", "title", "path", "line", "verification_status", "issue_key")
        projection = ",".join(f"json_extract(f.value,'$.{key}') AS {key}" for key in keys)
        source_sql = "FROM scan_runs r,json_each(r.result_json,'$.findings') f "
        with self._db() as db:
            total = db.execute(f"SELECT count(*) {source_sql}WHERE {where}", values).fetchone()[0]
            rows = db.execute(
                f"SELECT CAST(f.key AS INTEGER) AS finding_index,{projection} {source_sql}WHERE {where} "
                "ORDER BY CAST(f.key AS INTEGER) LIMIT ? OFFSET ?", (*values, page_size, (page - 1) * page_size),
            ).fetchall()
        return {"items": [dict(row) for row in rows], "total": total, "page": page, "page_size": page_size}

    def run_finding(self, run_id: str, index: int) -> dict:
        index = int(index)
        if index < 0:
            raise KeyError("finding not found")
        with self._db() as db:
            row = db.execute(
                "SELECT json_extract(result_json,?) AS finding FROM scan_runs WHERE run_id=? AND deleted_at IS NULL",
                (f"$.findings[{index}]", str(run_id)),
            ).fetchone()
        if not row or not row["finding"]:
            raise KeyError("finding not found")
        finding = json.loads(row["finding"])
        if not isinstance(finding, dict):
            raise KeyError("finding not found")
        return {**finding, "finding_index": index}

    def run(self, run_id: str) -> dict:
        with self._db() as db:
            row = db.execute(
                "SELECT r.*,s.display AS requested_by_id FROM scan_runs r LEFT JOIN subjects s ON s.subject_id=r.requested_by "
                "WHERE r.run_id=? AND r.deleted_at IS NULL", (str(run_id),)
            ).fetchone()
        if not row:
            raise KeyError("run not found")
        result = dict(row)
        result["snapshot"] = json.loads(result.pop("snapshot_json"))
        result["requested_by_id"] = result.get("requested_by_id") or ("schedule-worker" if result.get("requested_by") == "schedule-worker" else "기록 없음")
        result["requested_by_display"] = result["requested_by_id"]
        result_json = result.pop("result_json")
        result.pop("result_summary_json", None)
        result["result"] = json.loads(result_json) if result_json else None
        return result

    def _listed_run(self, db, row) -> dict:
        value = self._run_metadata(row)
        snapshot = json.loads(value.pop("snapshot_json"))
        value["scan_scope"] = snapshot.get("scan_scope", "all")
        value["source"] = snapshot.get("source_type") or "manual"
        if value["source"] == "scheduled_server":
            scheduled = db.execute("SELECT schedule_run_id FROM schedule_runs WHERE run_id=?", (value["run_id"],)).fetchone()
            if scheduled:
                schedule = self.schedule_run(scheduled["schedule_run_id"], include_metadata=False)
                for field in ("status", "cleanup_status", "schedule_run_id", "scheduled_for", "round_label", "display_round"):
                    value[field] = schedule[field]
        return value

    def list_runs(self, project_id: str, *, limit: int | None = None, offset: int = 0) -> list[dict]:
        columns = ",".join(f"r.{name}" for name in RUN_METADATA_COLUMNS)
        query = f"SELECT {columns},{RUN_LIST_SNAPSHOT_SQL},s.display AS requested_by_id FROM scan_runs r LEFT JOIN subjects s ON s.subject_id=r.requested_by WHERE r.project_id=? AND r.deleted_at IS NULL ORDER BY r.round_number DESC"
        values: tuple = (str(project_id),)
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            values += (min(max(int(limit), 1), 100), max(0, int(offset)))
        with self._db() as db:
            return [self._listed_run(db, row) for row in db.execute(query, values)]

    def delete_run(self, run_id: str, actor: str) -> None:
        """Logically remove a terminal local result without touching external deliveries."""
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            run = db.execute("SELECT * FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
            if not run or run["deleted_at"] is not None:
                raise KeyError("run not found")
            if not self.can(actor, run["project_id"], "runs.delete"):
                db.execute("ROLLBACK")
                raise PermissionError("run deletion denied")
            if run["status"] not in TERMINAL_RUN_STATUSES:
                raise ValueError("실행 중인 점검은 삭제할 수 없습니다")
            sending = db.execute(
                "SELECT 1 FROM tracker_deliveries WHERE run_id=? AND (status='sending' OR gitlab_result_status='sending') "
                "UNION ALL SELECT 1 FROM gitlab_issue_deliveries WHERE run_id=? AND status='sending' "
                "UNION ALL SELECT 1 FROM gitlab_issue_links WHERE run_id=? AND status='creating' LIMIT 1",
                (str(run_id), str(run_id), str(run_id)),
            ).fetchone()
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='portal_delivery_jobs'").fetchone():
                sending = sending or db.execute(
                    "SELECT 1 FROM portal_delivery_jobs WHERE run_id=? AND status IN ('queued','running') LIMIT 1",
                    (str(run_id),),
                ).fetchone()
            if sending:
                raise ValueError("결과 전송 중인 점검은 삭제할 수 없습니다")
            now = self._now()
            db.execute("UPDATE scan_runs SET deleted_at=?,result_json=NULL,result_summary_json=NULL WHERE run_id=? AND deleted_at IS NULL", (now, str(run_id)))
            db.execute("UPDATE analysis_revisions SET result_json=NULL WHERE run_id=?", (str(run_id),))
            self._audit_db(db, actor, "scan.deleted", run["project_id"], {"run_id": str(run_id), "round_number": run["round_number"]})
            db.execute("COMMIT")

    def audit_events(self, limit: int | None = 100) -> list[dict]:
        with self._db() as db:
            if limit is None:
                rows = db.execute("SELECT * FROM audit_events ORDER BY id DESC")
            else:
                rows = db.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (min(max(int(limit), 1), 500),))
            return [dict(row) for row in rows]

    def record_audit(self, subject_id: str | None, action: str, detail: dict) -> None:
        with self._lock, self._db() as db:
            self._audit_db(db, subject_id, action, None, detail)

    def discard_input(self, input_id: str) -> None:
        """Remove an unqueued input created while preparing a remote scan."""
        with self._lock, self._db() as db:
            row = db.execute("SELECT path FROM inputs WHERE input_id=?", (str(input_id),)).fetchone()
            if not row:
                return
            if db.execute("SELECT 1 FROM scan_runs WHERE input_id=?", (str(input_id),)).fetchone():
                raise ValueError("input is already used by a scan")
            db.execute("DELETE FROM inputs WHERE input_id=?", (str(input_id),))
        if not row["path"]:
            return
        path = Path(row["path"])
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=False)
        else:
            path.unlink(missing_ok=True)

    def _audit_db(self, db, subject_id, action, project_id, detail) -> None:
        db.execute(
            "INSERT INTO audit_events(subject_id,action,project_id,detail_json,created_at) VALUES(?,?,?,?,?)",
            (str(subject_id) if subject_id else None, action, str(project_id) if project_id else None, self._json(detail), self._now()),
        )


def _scanner_version() -> str:
    try:
        from importlib.metadata import version

        return version("koda-security-scanner")
    except Exception:
        return "development"
def _tracker_run_url(tracker_run_id: str) -> str | None:
    origin = os.environ.get("KODA_TRACKER_PUBLIC_ORIGIN", "").strip().rstrip("/")
    if not origin or not tracker_run_id:
        return None
    from urllib.parse import quote
    return f"{origin}/?page=runs&runId={quote(str(tracker_run_id), safe='')}"
