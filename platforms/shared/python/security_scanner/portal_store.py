"""Durable SQLite state for the authenticated Linux portal."""
from __future__ import annotations

import datetime as dt
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
FEATURE_PERMISSIONS = frozenset({"input.manage", "scan.create", "project.manage"})
LEGACY_PROJECT_PERMISSION = "project.view"
DEFAULT_ROLE_PERMISSIONS = {
    "admin": {*SCREEN_PERMISSIONS, *FEATURE_PERMISSIONS},
    "manager": {*SCREEN_PERMISSIONS, "input.manage", "scan.create"},
    "analyst": {*SCREEN_PERMISSIONS, "input.manage", "scan.create"},
    "uploader": {"dashboard.view", "scan.library.view", "scan.source.view", "runs.view", "projects.view", "input.manage", "scan.create"},
    "viewer": {"dashboard.view", "runs.view", "projects.view"},
}
PROJECT_PERMISSIONS = frozenset().union(*DEFAULT_ROLE_PERMISSIONS.values(), {LEGACY_PROJECT_PERMISSION})
RESERVED_PERMISSIONS = {"system.admin", "subjects.manage", "roles.manage", "rules.manage"}
TERMINAL_RUN_STATUSES = frozenset({"completed", "failed", "cancelled"})
GLOBAL_ROLE_POLICY_ID = "__koda_global__"


class VersionConflict(ValueError):
    pass


class PortalStore:
    def __init__(self, path: str | Path):
        self.path = str(Path(path).expanduser())
        self._lock = threading.RLock()
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
                CREATE TABLE IF NOT EXISTS inputs(
                  input_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, name TEXT NOT NULL,
                  path TEXT NOT NULL, content_hash TEXT NOT NULL, created_at TEXT NOT NULL,
                  FOREIGN KEY(project_id) REFERENCES projects(project_id));
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
                  max_bytes INTEGER NOT NULL DEFAULT 1073741824, timeout_seconds INTEGER NOT NULL DEFAULT 14400,
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
            if "registered_by" not in input_columns:
                db.execute("ALTER TABLE inputs ADD COLUMN registered_by TEXT")
                for event in db.execute("SELECT subject_id,detail_json FROM audit_events WHERE action='input.created' ORDER BY id"):
                    detail = json.loads(event["detail_json"])
                    db.execute("UPDATE inputs SET registered_by=? WHERE input_id=? AND registered_by IS NULL", (event["subject_id"], detail.get("input_id")))
            columns = {row[1] for row in db.execute("PRAGMA table_info(scan_runs)")}
            for definition in (
                "deleted_at TEXT",
                "stage TEXT NOT NULL DEFAULT 'queued'",
                "progress INTEGER NOT NULL DEFAULT 0",
                "cancel_requested INTEGER NOT NULL DEFAULT 0",
            ):
                if definition.split()[0] not in columns:
                    db.execute(f"ALTER TABLE scan_runs ADD COLUMN {definition}")
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
            rows = db.execute(
                "SELECT p.project_id,p.version,p.roles_json FROM role_policies p "
                "WHERE p.version=(SELECT max(version) FROM role_policies WHERE project_id=p.project_id)"
            ).fetchall()
            for row in rows:
                roles = json.loads(row["roles_json"])
                migrated = False
                for permissions in roles.values():
                    if LEGACY_PROJECT_PERMISSION in permissions:
                        merged = (set(permissions) - {LEGACY_PROJECT_PERMISSION}) | SCREEN_PERMISSIONS
                        if merged != set(permissions):
                            permissions[:] = sorted(merged)
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

    def ensure_subject(self, subject_id: str, display: str = "") -> dict:
        subject_id, now = str(uuid.UUID(str(subject_id))), self._now()
        with self._lock, self._db() as db:
            db.execute(
                "INSERT OR IGNORE INTO subjects(subject_id,display,status,created_at,updated_at) "
                "VALUES(?,?,'pending',?,?)",
                (subject_id, display[:128], now, now),
            )
            db.execute(
                "UPDATE subjects SET display=?,updated_at=? WHERE subject_id=? AND status!='tombstoned' AND display!=?",
                (display[:128], now, subject_id, display[:128]),
            )
            return dict(db.execute("SELECT * FROM subjects WHERE subject_id=?", (subject_id,)).fetchone())

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
            int(config.get("max_files", 200_000)), int(config.get("max_bytes", 1024 * 1024 * 1024)),
            int(config.get("timeout_seconds", 14_400)),
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
        return self._schedule_run_dict(row)

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

    def schedule_run(self, schedule_run_id: str) -> dict:
        with self._db() as db:
            row = db.execute("SELECT * FROM schedule_runs WHERE schedule_run_id=?", (str(schedule_run_id),)).fetchone()
        if not row:
            raise KeyError("schedule run not found")
        return self._schedule_run_dict(row)

    @staticmethod
    def _schedule_run_dict(row: sqlite3.Row | None) -> dict:
        if not row:
            raise KeyError("schedule run not found")
        value = dict(row)
        value["metadata"] = json.loads(value.pop("metadata_json") or "{}")
        return value

    def list_schedule_runs(self, target_id: str | None = None, limit: int = 100) -> list[dict]:
        with self._db() as db:
            if target_id:
                rows = db.execute("SELECT * FROM schedule_runs WHERE target_id=? ORDER BY scheduled_for DESC LIMIT ?", (str(target_id), min(max(int(limit), 1), 500))).fetchall()
            else:
                rows = db.execute("SELECT * FROM schedule_runs ORDER BY scheduled_for DESC LIMIT ?", (min(max(int(limit), 1), 500),)).fetchall()
        return [self._schedule_run_dict(row) for row in rows]

    def last_schedule_run(self, target_id: str) -> dict | None:
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM schedule_runs WHERE target_id=? AND status='completed' AND cleanup_status='completed' "
                "ORDER BY scheduled_for DESC,created_at DESC LIMIT 1", (str(target_id),)
            ).fetchone()
        return self._schedule_run_dict(row) if row else None

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
            changed = db.execute(
                "UPDATE schedule_runs SET status='running',stage='listing',run_id=NULL,files_total=0,"
                "changed_files=0,cleanup_status='pending',cleanup_error=NULL,tracker_status='pending',"
                "gitlab_status='pending',metadata_json='{}',error=NULL,started_at=?,completed_at=NULL,updated_at=? "
                "WHERE schedule_run_id=? AND status='queued' AND NOT EXISTS(SELECT 1 FROM schedule_runs WHERE status IN ('running','cancelling'))",
                (now, now, str(schedule_run_id)),
            ).rowcount
            db.execute("COMMIT")
        return bool(changed)

    def has_active_manual_work(self) -> bool:
        with self._db() as db:
            rows = db.execute("SELECT status,snapshot_json FROM scan_runs WHERE status IN ('queued','running','cancelling')").fetchall()
        for row in rows:
            try:
                if json.loads(row["snapshot_json"]).get("source_type") != "scheduled_server":
                    return True
            except (TypeError, json.JSONDecodeError):
                return True
        return False

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
                version = 1 + max((int(json.loads(row[0]).get("gitlab_result_version", 0)) for row in previous
                                   if str(json.loads(row[0]).get("gitlab_result_date", "")).replace("-", "") == day), default=0)
                snapshot.update(gitlab_result_date=f"{day[:4]}-{day[4:6]}-{day[6:]}", gitlab_result_version=version,
                                gitlab_result_branch=f"koda/results/{slug}/{day}/round-{version}")
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
        return requested in permissions or (requested == LEGACY_PROJECT_PERMISSION and bool(permissions & SCREEN_PERMISSIONS))

    def add_input(self, project_id: str, name: str, path: str | Path, actor: str | None = None, content_hash="") -> str:
        path = Path(path)
        content_hash = content_hash or hashlib.sha256(path.read_bytes()).hexdigest()
        input_id = str(uuid.uuid4())
        with self._db() as db:
            db.execute("INSERT INTO inputs(input_id,project_id,name,path,content_hash,created_at,registered_by) VALUES(?,?,?,?,?,?,?)", (input_id, str(project_id), name[:255], str(path), content_hash, self._now(), actor))
            self._audit_db(db, actor, "input.created", project_id, {"input_id": input_id, "name": name[:255], "sha256": content_hash})
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
        if not self.can(subject_id, project_id, "scan.create"):
            raise PermissionError("project access denied")
        # Validate the selection before reserving a durable round.
        from .standards import resolve_standard_selection

        resolve_standard_selection(standard, standard_category)
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not self.can(subject_id, project_id, "scan.create"):
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
        with self._db() as db:
            changed = db.execute(
                "UPDATE scan_runs SET status='running',stage='preparing',progress=5 "
                "WHERE run_id=? AND status='queued' AND cancel_requested=0",
                (str(run_id),),
            ).rowcount
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
            rows = db.execute(
                "SELECT sr.schedule_run_id,sr.run_id,r.input_id,i.path FROM schedule_runs sr "
                "LEFT JOIN scan_runs r ON r.run_id=sr.run_id LEFT JOIN inputs i ON i.input_id=r.input_id "
                "WHERE sr.created_at<? AND sr.cleanup_status='completed' AND sr.status IN ('completed','failed','cancelled') AND NOT EXISTS(SELECT 1 FROM tracker_deliveries d WHERE d.run_id=sr.run_id AND (d.status='sending' OR d.gitlab_result_status='sending'))",
                (cutoff,),
            ).fetchall()
            for row in rows:
                schedule_run_id, run_id, input_id = row["schedule_run_id"], row["run_id"], row["input_id"]
                db.execute("DELETE FROM schedule_runs WHERE schedule_run_id=?", (schedule_run_id,))
                if run_id:
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
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT cancel_requested,snapshot_json,deleted_at FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
            if not current or current["deleted_at"] is not None:
                db.execute("ROLLBACK")
                raise KeyError("run not found")
            cancelled = bool(current["cancel_requested"])
            status = "cancelled" if cancelled else ("failed" if error else "completed")
            stage, progress, completed = status, (0 if cancelled else 100), self._now()
            result_json = None if cancelled else (self._json(result) if result is not None else None)
            db.execute(
                "UPDATE scan_runs SET status=?,stage=?,progress=?,result_json=?,error=?,completed_at=? WHERE run_id=?",
                (status, stage, progress, result_json, None if cancelled else error, completed, str(run_id)),
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
            row = self._dict(db.execute("SELECT * FROM tracker_deliveries WHERE run_id=?", (str(run_id),)).fetchone())
            if row:
                row["gitlab_issue_urls"] = json.loads(row.pop("gitlab_issue_urls_json") or "[]")
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
            row = self._dict(db.execute("SELECT * FROM gitlab_issue_deliveries WHERE run_id=?", (str(run_id),)).fetchone())
            if row:
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

    def run(self, run_id: str) -> dict:
        with self._db() as db:
            row = db.execute("SELECT * FROM scan_runs WHERE run_id=? AND deleted_at IS NULL", (str(run_id),)).fetchone()
        if not row:
            raise KeyError("run not found")
        result = dict(row)
        result["snapshot"] = json.loads(result.pop("snapshot_json"))
        result_json = result.pop("result_json")
        result["result"] = json.loads(result_json) if result_json else None
        return result

    def list_runs(self, project_id: str) -> list[dict]:
        with self._db() as db:
            rows = db.execute("SELECT r.*,s.display AS requested_by_id FROM scan_runs r LEFT JOIN subjects s ON s.subject_id=r.requested_by WHERE r.project_id=? AND r.deleted_at IS NULL ORDER BY r.round_number DESC", (str(project_id),))
            runs = []
            for row in rows:
                value = dict(row)
                snapshot = json.loads(value.pop("snapshot_json"))
                value.pop("result_json", None)
                value["requested_by_id"] = value["requested_by_id"] or ("schedule-worker" if value["requested_by"] == "schedule-worker" else "기록 없음")
                value["scan_scope"] = snapshot.get("scan_scope", "all")
                value["source"] = snapshot.get("source_type") or "manual"
                if value["source"] == "scheduled_server":
                    scheduled = db.execute("SELECT status,cleanup_status FROM schedule_runs WHERE run_id=?", (value["run_id"],)).fetchone()
                    if scheduled:
                        value["status"] = scheduled["status"]
                        value["cleanup_status"] = scheduled["cleanup_status"]
                runs.append(value)
            return runs

    def delete_run(self, run_id: str, actor: str) -> None:
        """Logically remove a terminal local result without touching external deliveries."""
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            run = db.execute("SELECT * FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
            if not run or run["deleted_at"] is not None:
                raise KeyError("run not found")
            if run["status"] not in TERMINAL_RUN_STATUSES:
                raise ValueError("실행 중인 점검은 삭제할 수 없습니다")
            sending = db.execute(
                "SELECT 1 FROM tracker_deliveries WHERE run_id=? AND (status='sending' OR gitlab_result_status='sending') "
                "UNION ALL SELECT 1 FROM gitlab_issue_deliveries WHERE run_id=? AND status='sending' "
                "UNION ALL SELECT 1 FROM gitlab_issue_links WHERE run_id=? AND status='creating' LIMIT 1",
                (str(run_id), str(run_id), str(run_id)),
            ).fetchone()
            if sending:
                raise ValueError("결과 전송 중인 점검은 삭제할 수 없습니다")
            now = self._now()
            db.execute("UPDATE scan_runs SET deleted_at=?,result_json=NULL WHERE run_id=? AND deleted_at IS NULL", (now, str(run_id)))
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
