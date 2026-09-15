"""Synchronize approved Tracker identities into the local KODA subject store."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import uuid
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        return None


def fetch_tracker_users() -> dict[str, object]:
    """Fetch one authenticated Tracker identity snapshot using the KODA secret."""
    base = (os.environ.get("KODA_TRACKER_URL") or os.environ.get("KODA_SSBOM_TRACKER_URL") or "").strip().rstrip("/")
    parsed = urlparse(base)
    token_file = os.environ.get("KODA_TRACKER_PROVISIONING_TOKEN_FILE", "").strip()
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or not token_file:
        raise TrackerSubjectSyncError("Tracker 사용자 동기화 설정이 올바르지 않습니다")
    try:
        token = Path(token_file).expanduser().read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise TrackerSubjectSyncError("Tracker 사용자 동기화 비밀값을 읽을 수 없습니다") from exc
    if not token or len(token) > 16 * 1024:
        raise TrackerSubjectSyncError("Tracker 사용자 동기화 비밀값이 올바르지 않습니다")
    request = Request(
        base + "/api/v1/integrations/koda/users",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "KODA-Portal/1"},
    )
    try:
        context = None
        if parsed.scheme == "https":
            ca_file = os.environ.get("KODA_TRACKER_CA_FILE", "").strip()
            context = ssl.create_default_context(cafile=str(Path(ca_file).expanduser())) if ca_file else ssl.create_default_context()
        opener = build_opener(_NoRedirect(), *([HTTPSHandler(context=context)] if context else []))
        with opener.open(request, timeout=20) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise TrackerSubjectSyncError("Tracker 사용자 응답이 너무 큽니다")
            value = json.loads(raw)
    except HTTPError as exc:
        raise TrackerSubjectSyncError(f"Tracker 사용자 요청 실패 ({exc.code})") from exc
    except (URLError, OSError, json.JSONDecodeError) as exc:
        raise TrackerSubjectSyncError("Tracker 사용자 연결에 실패했습니다") from exc
    if not isinstance(value, dict):
        raise TrackerSubjectSyncError("Tracker 사용자 응답 형식이 올바르지 않습니다")
    return value


class TrackerSubjectSyncError(RuntimeError):
    """The authoritative Tracker snapshot could not be trusted or applied."""


class TrackerSubjectSynchronizer:
    """Apply complete Tracker snapshots without changing local access policy.

    ``store`` intentionally only needs PortalStore's public subject methods. A
    JSON state file keeps source state separate from local disabled/tombstoned
    state and makes failed polls retryable across process restarts.
    """

    def __init__(self, store, state_path: str | Path, fetch_users: Callable[[], object], *, max_snapshot_age_seconds: int = 300):
        self.store = store
        self.state_path = Path(state_path).expanduser()
        self.fetch_users = fetch_users
        self.max_snapshot_age_seconds = max(30, int(max_snapshot_age_seconds))
        self._lock = threading.RLock()

    def sync(self) -> dict[str, object]:
        with self._lock:
            try:
                users = self._read_snapshot(self.fetch_users())
                result = self._apply(users)
                self._write_state({
                    "pending": False,
                    "attempts": 0,
                    "last_error": "",
                    "synced_at": datetime.now(timezone.utc).isoformat(),
                    "subjects": result.pop("subjects"),
                })
                return result
            except Exception as exc:
                state = self._read_state()
                self._write_state({
                    **state,
                    "pending": True,
                    "attempts": int(state.get("attempts", 0)) + 1,
                    "last_error": str(exc)[:500],
                })
                if isinstance(exc, TrackerSubjectSyncError):
                    raise
                raise TrackerSubjectSyncError("Tracker 사용자 동기화에 실패했습니다") from exc

    def retry_pending(self) -> dict[str, object] | None:
        if not self._read_state().get("pending"):
            return None
        return self.sync()

    def status(self) -> dict[str, object]:
        state = self._read_state()
        return {
            "configured": True,
            "pending": bool(state.get("pending")),
            "attempts": int(state.get("attempts", 0) or 0),
            "lastError": str(state.get("last_error") or ""),
            "syncedAt": state.get("synced_at"),
        }

    def _read_snapshot(self, value: object) -> dict[str, dict[str, str]]:
        if not isinstance(value, Mapping):
            raise TrackerSubjectSyncError("Tracker 사용자 스냅샷 형식이 올바르지 않습니다")
        snapshot_at = value.get("snapshotAt")
        if not isinstance(snapshot_at, str) or not snapshot_at.strip():
            raise TrackerSubjectSyncError("Tracker 사용자 스냅샷 시각이 없습니다")
        try:
            timestamp = datetime.fromisoformat(snapshot_at.replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                raise ValueError
            age = (datetime.now(timezone.utc) - timestamp.astimezone(timezone.utc)).total_seconds()
        except (TypeError, ValueError) as exc:
            raise TrackerSubjectSyncError("Tracker 사용자 스냅샷 시각이 올바르지 않습니다") from exc
        if age < -60 or age > self.max_snapshot_age_seconds:
            raise TrackerSubjectSyncError("Tracker 사용자 스냅샷이 만료되었습니다")
        value = value.get("users")
        if not isinstance(value, list) or not value:
            # An empty, complete snapshot is valid and revokes all previously
            # known identities; malformed/non-list responses are not.
            if value == []:
                return {}
            raise TrackerSubjectSyncError("Tracker 사용자 목록 형식이 올바르지 않습니다")
        result: dict[str, dict[str, str]] = {}
        for item in value:
            if not isinstance(item, Mapping):
                raise TrackerSubjectSyncError("Tracker 사용자 항목 형식이 올바르지 않습니다")
            try:
                subject_id = str(uuid.UUID(str(item.get("id"))))
            except (ValueError, AttributeError, TypeError) as exc:
                raise TrackerSubjectSyncError("Tracker 사용자 ID가 올바르지 않습니다") from exc
            if subject_id in result:
                raise TrackerSubjectSyncError("Tracker 사용자 목록에 중복 ID가 있습니다")
            status_value = item.get("status")
            if not isinstance(status_value, str) or not status_value.strip():
                raise TrackerSubjectSyncError("Tracker 사용자 상태가 없습니다")
            status = status_value.strip().casefold()
            if status not in {"approved", "active", "revoked", "inactive", "disabled", "pending"}:
                raise TrackerSubjectSyncError("Tracker 사용자 상태가 올바르지 않습니다")
            result[subject_id] = {
                "source_state": "approved" if status in {"approved", "active"} else "revoked",
                "display": str(item.get("username") or subject_id)[:128],
            }
        return result

    def _apply(self, users: dict[str, dict[str, str]]) -> dict[str, object]:
        state = self._read_state()
        previous = state.get("subjects") if isinstance(state.get("subjects"), dict) else {}
        known = {str(key): value for key, value in previous.items() if isinstance(value, Mapping)}
        targets = dict(users)
        for subject_id in known:
            targets.setdefault(subject_id, {"source_state": "revoked", "display": subject_id})
        enabled = disabled = skipped = 0
        subjects: dict[str, dict[str, object]] = {}
        for subject_id, target in targets.items():
            source_state = target["source_state"]
            local = self.store.subject(subject_id)
            if local is not None and local.get("status") == "tombstoned":
                skipped += 1
                subjects[subject_id] = {"source_state": source_state, "managed_status": "tombstoned"}
                continue
            prior = known.get(subject_id, {})
            prior_managed = prior.get("managed_status")
            if source_state == "approved":
                if local is None:
                    self.store.ensure_subject(subject_id, target.get("display") or subject_id)
                    local = self.store.subject(subject_id)
                if local and local.get("status") == "pending":
                    self.store.set_subject(subject_id, status="enabled", actor="tracker-sync")
                    enabled += 1
                elif local and local.get("status") == "disabled" and prior.get("source_state") == "revoked" and prior_managed == "disabled" and self._last_sync_disabled(subject_id):
                    self.store.set_subject(subject_id, status="enabled", actor="tracker-sync")
                    enabled += 1
                elif local and local.get("status") == "enabled":
                    enabled += 1
                else:
                    skipped += 1
                managed_status = "enabled" if local and local.get("status") == "enabled" else str(local.get("status") if local else "unknown")
            else:
                if local and local.get("status") in {"enabled", "pending"}:
                    self.store.set_subject(subject_id, status="disabled", actor="tracker-sync")
                    disabled += 1
                managed_status = "disabled" if local else "absent"
            subjects[subject_id] = {"source_state": source_state, "managed_status": managed_status}
        return {"enabled": enabled, "disabled": disabled, "skipped": skipped, "subjects": subjects}

    def _last_sync_disabled(self, subject_id: str) -> bool:
        for event in self.store.audit_events(None):
            if event.get("action") != "subject.updated":
                continue
            try:
                detail = json.loads(event.get("detail_json") or "{}")
            except (TypeError, json.JSONDecodeError):
                return False
            if detail.get("subject_id") == subject_id:
                return event.get("subject_id") == "tracker-sync" and detail.get("status") == "disabled"
        return False

    def _read_state(self) -> dict[str, object]:
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return {}

    def _write_state(self, value: dict[str, object]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{self.state_path.name}.", dir=self.state_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                json.dump(value, output, ensure_ascii=False, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.state_path)
        except Exception:
            Path(temporary).unlink(missing_ok=True)
            raise
