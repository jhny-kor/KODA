"""Persisted, non-secret settings for the scheduled inspection worker."""
from __future__ import annotations

import json
import math
from datetime import datetime, timezone


DEFAULTS = {
    "enabled": False,
    "cpu_limit": 1,
    "memory_limit_bytes": 4 * 1024**3,
    "rate_bytes_per_sec": 5 * 1024**2,
    "gap_seconds": 30,
    "min_free_bytes": 1024**3,
    "concurrency": 1,
}
_LIMITS = {
    "cpu_limit": (1, 32),
    "memory_limit_bytes": (256 * 1024**2, 64 * 1024**3),
    "rate_bytes_per_sec": (64 * 1024, 1024**3),
    "gap_seconds": (0, 3600),
    "min_free_bytes": (0, 1024**4),
    "concurrency": (1, 1),
}


def _ensure(db) -> None:
    db.execute(
        """CREATE TABLE IF NOT EXISTS schedule_worker_settings(
          settings_id INTEGER PRIMARY KEY CHECK(settings_id=1),
          settings_json TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
          updated_at TEXT NOT NULL, updated_by TEXT)"""
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("schedule settings must be an object")
    unknown = sorted(set(payload) - set(DEFAULTS))
    if unknown:
        raise ValueError("unknown schedule settings: " + ", ".join(unknown))
    result = dict(DEFAULTS)
    result.update(payload)
    if not isinstance(result["enabled"], bool):
        raise ValueError("enabled must be boolean")
    for key, (lower, upper) in _LIMITS.items():
        value = result[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{key} must be an integer")
        if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()):
            raise ValueError(f"{key} must be an integer")
        value = int(value)
        if value < lower or value > upper:
            raise ValueError(f"{key} is outside the allowed range")
        result[key] = value
    return result


def get_settings(store) -> dict:
    """Return settings, creating the disabled safe default lazily."""
    with store._lock, store._db() as db:
        _ensure(db)
        row = db.execute("SELECT settings_json,version,updated_at FROM schedule_worker_settings WHERE settings_id=1").fetchone()
        if not row:
            settings = dict(DEFAULTS)
            db.execute(
                "INSERT INTO schedule_worker_settings(settings_id,settings_json,version,updated_at,updated_by) VALUES(1,?,?,?,?)",
                (json.dumps(settings, sort_keys=True), 1, _now(), "system"),
            )
            return settings | {"version": 1}
        try:
            settings = _validate(json.loads(row["settings_json"]))
        except (TypeError, ValueError, json.JSONDecodeError):
            settings = dict(DEFAULTS)
        return settings | {"version": int(row["version"]), "updated_at": row["updated_at"]}


def save_settings(store, payload: dict, actor: str | None = None) -> dict:
    """Merge, validate and save within one SQLite write transaction."""
    if not isinstance(payload, dict):
        raise ValueError("schedule settings must be an object")
    unknown = sorted(set(payload) - set(DEFAULTS))
    if unknown:
        store.record_audit(actor, "schedule_worker_settings.rejected", {"unknown_keys": unknown})
        raise ValueError("unknown schedule settings: " + ", ".join(unknown))
    with store._lock, store._db() as db:
        _ensure(db)
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT settings_json,version FROM schedule_worker_settings WHERE settings_id=1").fetchone()
        base = dict(DEFAULTS)
        if row:
            try:
                base = _validate(json.loads(row["settings_json"]))
            except (TypeError, ValueError):
                pass
        settings = _validate(base | payload)
        version = int(row["version"]) + 1 if row else 1
        now = _now()
        db.execute(
            "INSERT INTO schedule_worker_settings(settings_id,settings_json,version,updated_at,updated_by) VALUES(1,?,?,?,?) "
            "ON CONFLICT(settings_id) DO UPDATE SET settings_json=excluded.settings_json,version=excluded.version,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
            (json.dumps(settings, sort_keys=True), version, now, actor),
        )
        store._audit_db(db, actor, "schedule_worker_settings.updated", None, {"version": version, "enabled": settings["enabled"]})
        db.execute("COMMIT")
        return settings | {"version": version, "updated_at": now}
