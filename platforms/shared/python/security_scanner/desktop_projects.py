"""Per-user project targets and score snapshots for the local dashboard."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path


def _database() -> sqlite3.Connection:
    base = Path(os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
    folder = base / "KODA"
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    db = sqlite3.connect(folder / "desktop-projects.sqlite3")
    db.execute("CREATE TABLE IF NOT EXISTS profiles (id INTEGER PRIMARY KEY AUTOINCREMENT, paths TEXT NOT NULL UNIQUE)")
    db.execute("CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY, snapshot TEXT NOT NULL)")
    return db


def project_paths(value: object, *, existing: bool = False) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 128:
        raise ValueError("Select between 1 and 128 project targets")
    paths: list[Path] = []
    for item in value:
        if not isinstance(item, str) or not item.strip() or len(item) > 32767:
            raise ValueError("Invalid project path")
        path = Path(item)
        if not path.is_absolute():
            raise ValueError("Project paths must be absolute")
        if (not existing or path.is_dir() or path.is_file()) and path not in paths:
            paths.append(path)
    return [str(path) for path in paths]


def project_action(request: dict) -> dict:
    action = request.get("action")
    with closing(_database()) as db, db:
        if action == "save":
            paths = project_paths(request.get("paths"))
            if any(not (Path(path).is_dir() or Path(path).is_file()) for path in paths):
                raise ValueError("A selected project target no longer exists")
            db.execute("INSERT OR REPLACE INTO profiles(paths) VALUES (?)", (json.dumps(paths),))
            db.execute("DELETE FROM profiles WHERE id NOT IN (SELECT id FROM profiles ORDER BY id DESC LIMIT 30)")
        elif action == "load":
            row = db.execute("SELECT paths FROM profiles WHERE id = ?", (int(request.get("id", 0)),)).fetchone()
            if row is None:
                raise ValueError("Profile no longer exists")
            saved = json.loads(row[0])
            available = project_paths(saved, existing=True)
            if not available:
                raise ValueError("No targets in this profile could be found")
            return {"paths": available, "missing": len(saved) - len(available)}
        elif action == "delete":
            db.execute("DELETE FROM profiles WHERE id = ?", (int(request.get("id", 0)),))
        elif action == "clear-history":
            db.execute("DELETE FROM history")
        elif action != "list":
            raise ValueError("Unknown project action")
        return {
            "profiles": [
                {"id": row[0], "paths": json.loads(row[1])}
                for row in db.execute("SELECT id, paths FROM profiles ORDER BY id DESC")
            ],
            "history": [json.loads(row[0]) for row in db.execute("SELECT snapshot FROM history ORDER BY id DESC")],
        }


def record_score(payload: dict, targets: list[str]) -> None:
    summary = payload["summary"]
    snapshot = {
        "date": payload["generated_at"],
        "targets": targets,
        "score": summary["risk_score"],
        "count": summary["displayed_finding_count"],
        "severity": summary["by_severity"],
    }
    with closing(_database()) as db, db:
        db.execute("INSERT INTO history(snapshot) VALUES (?)", (json.dumps(snapshot),))
        db.execute("DELETE FROM history WHERE id NOT IN (SELECT id FROM history ORDER BY id DESC LIMIT 100)")
