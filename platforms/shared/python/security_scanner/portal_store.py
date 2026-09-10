"""Durable SQLite state for the authenticated Linux portal."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
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
                """
            )
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
            db.execute("INSERT INTO inputs VALUES(?,?,?,?,?,?)", (input_id, str(project_id), name[:255], str(path), content_hash, self._now()))
            self._audit_db(db, actor, "input.created", project_id, {"input_id": input_id, "name": name[:255], "sha256": content_hash})
        return input_id

    def list_inputs(self, project_id: str) -> list[dict]:
        with self._db() as db:
            rows = [dict(row) for row in db.execute("SELECT * FROM inputs WHERE project_id=? ORDER BY created_at DESC", (str(project_id),))]
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
                    "SELECT snapshot_json FROM scan_runs WHERE project_id=? AND requested_by=? "
                    "AND created_at>=? AND created_at<?",
                    (str(project_id), str(subject_id), start.astimezone(dt.timezone.utc).isoformat(),
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
                    "gitlab_result_branch": f"koda/results/{day:%Y%m%d}/{slug}-{str(project_id)[:8]}/{subject_id}/v{version}",
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
            db.execute("UPDATE scan_runs SET status='cancelled',stage='cancelled',completed_at=? WHERE status IN ('running','cancelling') AND cancel_requested=1", (self._now(),))
            db.execute("UPDATE scan_runs SET status='queued',stage='queued',progress=0 WHERE status IN ('running','cancelling') AND cancel_requested=0")
            queued = [row[0] for row in db.execute("SELECT run_id FROM scan_runs WHERE status='queued' ORDER BY created_at")]
        self.cleanup_terminal_inputs()
        return queued

    def recover_tracker_deliveries(self) -> list[str]:
        with self._lock, self._db() as db:
            db.execute("UPDATE tracker_deliveries SET status='pending',updated_at=? WHERE status='sending'", (self._now(),))
            return [row[0] for row in db.execute(
                "SELECT d.run_id FROM tracker_deliveries d JOIN scan_runs r USING(run_id) "
                "WHERE d.status='pending' AND r.status='completed' AND r.deleted_at IS NULL ORDER BY d.created_at"
            )]

    def recover_gitlab_results(self) -> list[str]:
        with self._lock, self._db() as db:
            db.execute("UPDATE tracker_deliveries SET gitlab_result_status='pending',updated_at=? WHERE gitlab_result_status='sending'", (self._now(),))
            return [row[0] for row in db.execute(
                "SELECT d.run_id FROM tracker_deliveries d JOIN scan_runs r USING(run_id) "
                "WHERE d.gitlab_result_status='pending' AND d.status='completed' AND r.status='completed' AND r.deleted_at IS NULL ORDER BY d.created_at"
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
                path = Path(source["path"])
            try:
                path.unlink(missing_ok=True)
            except OSError:
                return False
            return True

    def cleanup_terminal_inputs(self) -> int:
        with self._lock:
            with self._db() as db:
                run_ids = [row[0] for row in db.execute("SELECT run_id FROM scan_runs WHERE status IN ('completed','failed','cancelled')")]
            return sum(self.cleanup_input_for_run(run_id) for run_id in run_ids)

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

    def claim_gitlab_result(self, run_id: str, *, retry: bool = False) -> dict:
        expected = ("failed", "pending") if retry else ("pending",)
        placeholders = ",".join("?" for _ in expected)
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                f"UPDATE tracker_deliveries SET gitlab_result_status='sending',gitlab_result_attempts=gitlab_result_attempts+1,gitlab_result_last_error=NULL,updated_at=? "
                f"WHERE run_id=? AND gitlab_result_status IN ({placeholders}) AND status='completed' AND EXISTS(SELECT 1 FROM scan_runs WHERE run_id=? AND status='completed' AND deleted_at IS NULL)",
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
            db.execute("UPDATE gitlab_issue_deliveries SET status='pending',updated_at=? WHERE status='sending'", (self._now(),))
            return [row[0] for row in db.execute(
                "SELECT d.run_id FROM gitlab_issue_deliveries d JOIN scan_runs r USING(run_id) "
                "WHERE d.status='pending' AND r.status='completed' AND r.deleted_at IS NULL ORDER BY d.created_at"
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
            rows = db.execute("SELECT * FROM scan_runs WHERE project_id=? AND deleted_at IS NULL ORDER BY round_number DESC", (str(project_id),))
            runs = []
            for row in rows:
                value = dict(row)
                snapshot = json.loads(value.pop("snapshot_json"))
                value.pop("result_json", None)
                value["scan_scope"] = snapshot.get("scan_scope", "all")
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
        Path(row["path"]).unlink(missing_ok=True)

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
