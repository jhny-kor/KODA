"""Small, authenticated API boundary between the scheduled worker and KODA.

The worker must not open the portal SQLite database in production.  The HTTP
client below intentionally exposes only schedule operations; it is not a
generic database RPC layer.  The portal handler can use ``dispatch`` for the
same allow-listed operations without duplicating validation.
"""
from __future__ import annotations

import hmac
import json
import os
from pathlib import Path
import urllib.error
import urllib.request
from typing import Any


API_PREFIX = "/internal/koda/schedule/v1"
DEFAULT_JSON_BYTES = 500 * 1024 * 1024
MAX_RESPONSE_BYTES = 500 * 1024 * 1024


def configured_json_bytes() -> int:
    """Return the JSON body limit, bounded by the source-level hard maximum."""
    raw = os.environ.get("KODA_JSON_MAX_BYTES", "").strip()
    if not raw:
        return DEFAULT_JSON_BYTES
    try:
        return max(1, min(int(raw), MAX_RESPONSE_BYTES))
    except ValueError as exc:
        raise ScheduleApiError(503, "KODA_JSON_MAX_BYTES must be an integer") from exc


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ScheduleApiError(502, "schedule API redirects are not allowed")


_OPENER = urllib.request.build_opener(_NoRedirect)


class ScheduleApiError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def api_token() -> str:
    token = os.environ.get("KODA_SCHEDULE_API_TOKEN", "").strip()
    token_file = os.environ.get("KODA_SCHEDULE_API_TOKEN_FILE", "").strip()
    if not token_file and os.environ.get("KODA_PORTAL_DATA_DIR"):
        token_file = str(Path(os.environ["KODA_PORTAL_DATA_DIR"]) / "schedule-auth" / "token")
    if not token and token_file:
        path = Path(token_file).expanduser()
        if not path.is_absolute():
            raise ScheduleApiError(503, "schedule API token file must be absolute")
        try:
            token = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ScheduleApiError(503, "schedule API token file is unavailable") from exc
    if len(token) < 32:
        raise ScheduleApiError(503, "schedule internal API token is not configured")
    return token


def authorize(headers: dict[str, str], expected: str | None = None) -> bool:
    """Constant-time bearer-token check; callers must pass only internal traffic."""
    value = next((v for k, v in headers.items() if k.lower() == "authorization"), "")
    supplied = value[7:].strip() if value.startswith("Bearer ") else ""
    try:
        secret = expected or api_token()
    except ScheduleApiError:
        return False
    return bool(len(secret) >= 32 and supplied and hmac.compare_digest(supplied, secret))


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class ScheduleApiClient:
    """Allow-listed client used by the production worker."""

    def __init__(self, base_url: str | None = None, token: str | None = None, timeout: int = 30):
        self.base_url = (base_url or os.environ.get("KODA_SCHEDULE_API_URL", "")).rstrip("/")
        self.token = token or api_token()
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("schedule API URL must be HTTP(S)")
        self.timeout = max(1, int(timeout))

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        if not path.startswith(API_PREFIX + "/"):
            raise ValueError("schedule API path is not allow-listed")
        body = _json_bytes(payload) if payload is not None else None
        json_limit = configured_json_bytes()
        if body and len(body) > json_limit:
            raise ScheduleApiError(413, "scheduled payload exceeds API size limit")
        request = urllib.request.Request(
            self.base_url + path, data=body, method=method.upper(),
            headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json", **({"Content-Type": "application/json"} if body else {})},
        )
        try:
            with _OPENER.open(request, timeout=self.timeout) as response:
                raw = response.read(json_limit + 1)
                status = response.status
        except urllib.error.HTTPError as exc:
            try:
                raw = exc.read(json_limit + 1)
            finally:
                exc.close()
            try:
                detail = json.loads(raw).get("detail", "schedule API request failed")
            except (ValueError, AttributeError):
                detail = "schedule API request failed"
            raise ScheduleApiError(exc.code, str(detail)[:500]) from exc
        except (OSError, TimeoutError) as exc:
            raise ScheduleApiError(503, "schedule API unavailable") from exc
        if len(raw) > json_limit:
            raise ScheduleApiError(502, "schedule API response too large")
        try:
            value = json.loads(raw or b"null")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ScheduleApiError(502, "invalid schedule API response") from exc
        if status >= 400:
            raise ScheduleApiError(status, str(value.get("detail", "schedule API request failed"))[:500])
        return value


    def state(self):
        return self.request("GET", API_PREFIX + "/state")

    def next(self, worker_id):
        return self.request("POST", API_PREFIX + "/next", {"worker_id": worker_id})

    def action(self, action, job, **fields):
        if action not in {"heartbeat", "persist", "cleanup", "fail"}:
            raise ValueError("unknown scheduled operation")
        return self.request("POST", API_PREFIX + "/" + action, {
            "schedule_run_id": job["schedule_run_id"], "lease_token": job["lease_token"], **fields,
        })

    def tick(self):
        return self.request("POST", API_PREFIX + "/tick", {})

# These operations are server-side only; worker never receives SQL, portal
# paths, user records or publication credentials.
import datetime as dt
import hashlib
import re
import secrets
import threading
import uuid
from .schedule_settings import get_settings

_TICK_LOCK = threading.Lock()
_TICKS = {}


def _ensure(store):
    with store._db() as db:
        db.execute("CREATE TABLE IF NOT EXISTS schedule_api_receipts(schedule_run_id TEXT PRIMARY KEY,token_hash TEXT NOT NULL,reply_json TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS schedule_api_lease(slot INTEGER PRIMARY KEY CHECK(slot=1),worker_id TEXT NOT NULL,lease_token TEXT NOT NULL,schedule_run_id TEXT NOT NULL,context_json TEXT NOT NULL)")


def _job_context(store, target, scheduled):
    policy = store.rule_policy(target["project_id"])
    policy = {k: policy[k] for k in ("version", "hash", "disabled_rules")}
    snapshot = {
        "source_type": "scheduled_server", "schedule_target_id": target["target_id"],
        "schedule_run_id": scheduled["schedule_run_id"], "scheduled_for": scheduled["scheduled_for"],
        "remote_server": f"{target['host']}:{target['port']}", "remote_directory": target["remote_directory"],
        "scan_mode": scheduled["mode"], "schedule_config_version": target["config_version"],
        "standard": target["standard"], "standard_category": target["standard_category"],
        "scan_scope": target["scan_scope"], "requested_by": "schedule-worker",
        "disabled_rules": sorted(set(policy["disabled_rules"]) | set(target["disabled_rules"])),
        "rule_policy_version": policy["version"], "rule_policy_hash": policy["hash"],
        "gitlab_mapping_id": target.get("gitlab_mapping_id") or "",
        "gitlab_target_branch": target.get("gitlab_target_branch") or "",
        # Scheduled GitLab archives are re-packed with relative member names;
        # the scan input therefore has no synthetic top-level archive root.
        "gitlab_archive_root": "",
    }
    if target.get("source_kind") == "gitlab":
        source = store.gitlab_repository(target["source_gitlab_mapping_id"], target["project_id"])
        snapshot.update(
            scheduled_source_kind="gitlab", source_gitlab_project_id=source["gitlab_project_id"],
            source_gitlab_path=source["path_with_namespace"],
            source_gitlab_ref=target["source_gitlab_ref"],
            source_gitlab_ref_type=target.get("source_gitlab_ref_type", "branch"),
            remote_server="GitLab:" + source["path_with_namespace"],
            remote_directory=target.get("source_gitlab_directory") or "/",
        )
    if target.get("gitlab_mapping_id"):
        mapping = store.gitlab_repository(target["gitlab_mapping_id"], target["project_id"])
        snapshot.update(gitlab_project_id=mapping["gitlab_project_id"], gitlab_path_with_namespace=mapping["path_with_namespace"],
                        gitlab_default_branch=target.get("gitlab_target_branch") or mapping["default_branch"],
                        tracker_service_id=mapping["tracker_service_id"], tracker_environment_id=mapping["tracker_environment_id"],
                        tracker_token_ref=mapping["tracker_token_ref"])
    return {"target": target, "policy": policy, "snapshot": snapshot,
            "baseline": store.baseline_schedule_files(target["target_id"]), "mode": scheduled["mode"]}


def _public_job(context, row, lease_token):
    target = {k: v for k, v in context["target"].items() if k not in {"gitlab_mapping_id", "gitlab_target_branch"}}
    return {"schedule_run_id": row["schedule_run_id"], "lease_token": lease_token,
            "target": target, "policy": context["policy"], "baseline": context["baseline"],
            "mode": context["mode"], "status": row["status"], "stage": row["stage"],
            "run_id": row.get("run_id"), "scheduled_for": row["scheduled_for"]}


def _mode(store, target, day):
    last = store.last_schedule_run(target["target_id"])
    if not last or last["config_version"] != target["config_version"] or dt.date.fromisoformat(day[:10]).weekday() == 6:
        return "full"
    previous = store.run(last["run_id"])["snapshot"] if last.get("run_id") else {}
    policy = store.rule_policy(target["project_id"])
    if previous.get("rule_policy_hash") != policy["hash"] or previous.get("rule_policy_version") != policy["version"]:
        return "full"
    if last.get("files_total") and not store.baseline_schedule_files(target["target_id"]):
        return "full"
    return "changed"


def _next(store, worker_id):
    if not isinstance(worker_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", worker_id):
        raise ValueError("invalid worker identifier")
    with store._lock:
        settings = get_settings(store)
        with store._db() as db:
            lease = db.execute("SELECT * FROM schedule_api_lease WHERE slot=1").fetchone()
        if lease:
            job = None
            if lease["worker_id"] == worker_id:
                row = store.schedule_run(lease["schedule_run_id"])
                job = _public_job(json.loads(lease["context_json"]), row, lease["lease_token"])
            return {"settings": settings, "job": job}
        if not settings["enabled"] or store.has_active_manual_work():
            return {"settings": settings, "job": None}
        targets = store.list_schedule_targets(enabled_only=True)
        now = dt.datetime.now(dt.timezone(dt.timedelta(hours=9)))
        with store._db() as db:
            pending = db.execute("SELECT sr.* FROM schedule_runs sr JOIN schedule_targets t ON t.target_id=sr.target_id WHERE t.enabled=1 AND sr.status IN ('queued','running','cancelling') ORDER BY sr.scheduled_for,t.order_index,t.target_id").fetchall()
        # Drain persisted work before creating another batch; missed slots are
        # coalesced to the latest due slot, never backfilled into a storm.
        if not pending:
            from .schedule_timing import due_slot
            for target in targets:
                slot = due_slot(target, now)
                if slot:
                    store.begin_schedule_run(target["target_id"], slot, _mode(store, target, slot), target["config_version"])
            with store._db() as db:
                pending = db.execute("SELECT sr.* FROM schedule_runs sr JOIN schedule_targets t ON t.target_id=sr.target_id WHERE t.enabled=1 AND sr.status='queued' ORDER BY sr.scheduled_for,t.order_index,t.target_id").fetchall()
        by_id = {target["target_id"]: target for target in targets}
        for queued in pending:
            if queued["status"] != "queued":
                continue
            target = by_id[queued["target_id"]]
            row = dict(queued)
            day = row["scheduled_for"]
            # A queued target may have waited across a policy/settings edit.
            row["mode"] = _mode(store, target, day)
            row["config_version"] = target["config_version"]
            try:
                context = _job_context(store, target, row)
            except (KeyError, ValueError):
                store.update_schedule_run(row["schedule_run_id"], status="failed", stage="failed", cleanup_status="completed", error="Scheduled repository mapping is unavailable", completed_at=store._now())
                continue
            token = secrets.token_urlsafe(32)
            with store._db() as db:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT 1 FROM schedule_api_lease").fetchone() or db.execute("SELECT 1 FROM schedule_runs WHERE status IN ('running','cancelling')").fetchone():
                    return {"settings": settings, "job": None}
                db.execute("INSERT INTO schedule_api_lease VALUES(1,?,?,?,?)", (worker_id, token, row["schedule_run_id"], json.dumps(context)))
                db.execute("UPDATE schedule_runs SET status='running',stage='collecting',cleanup_status='pending',mode=?,config_version=?,started_at=?,updated_at=? WHERE schedule_run_id=?", (row["mode"], row["config_version"], store._now(), store._now(), row["schedule_run_id"]))
                db.execute("COMMIT")
            return {"settings": settings, "job": _public_job(context, store.schedule_run(row["schedule_run_id"]), token)}
        return {"settings": settings, "job": None}


def _leased(store, payload):
    with store._db() as db:
        lease = db.execute("SELECT * FROM schedule_api_lease WHERE slot=1").fetchone()
    if not lease or lease["schedule_run_id"] != payload["schedule_run_id"] or not isinstance(payload["lease_token"], str) or not hmac.compare_digest(lease["lease_token"], payload["lease_token"]):
        raise PermissionError("invalid scheduled lease")
    return dict(lease), json.loads(lease["context_json"]), store.schedule_run(lease["schedule_run_id"])


def _manifest(payload, target):
    manifest, counts = payload["manifest"], payload["counts"]
    if not isinstance(manifest, list) or len(manifest) > target["max_files"] or not isinstance(counts, dict) or set(counts) != {"files_total", "changed_files", "changed_paths"}:
        raise ValueError("invalid scheduled manifest")
    seen, total = set(), 0
    for item in manifest:
        if not isinstance(item, dict) or set(item) != {"relative_path", "size", "mtime", "sha256"}:
            raise ValueError("invalid manifest entry")
        path = item["relative_path"]
        if not isinstance(path, str) or not path or path.startswith("/") or ".." in path.split("/") or any(ord(c) < 32 for c in path) or path in seen:
            raise ValueError("invalid manifest path")
        if isinstance(item["size"], bool) or not isinstance(item["size"], int) or item["size"] < 0 or not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise ValueError("invalid manifest fingerprint")
        import math
        if isinstance(item["mtime"], bool) or not isinstance(item["mtime"], (int, float)) or not math.isfinite(item["mtime"]):
            raise ValueError("invalid manifest timestamp")
        seen.add(path)
        total += item["size"]
    if counts["files_total"] != len(manifest) or isinstance(counts["changed_files"], bool) or not isinstance(counts["changed_files"], int) or counts["changed_files"] < 0 or not isinstance(counts["changed_paths"], list) or counts["changed_files"] != len(counts["changed_paths"]) or any(not isinstance(p, str) or p.startswith("/") or ".." in p.split("/") for p in counts["changed_paths"]):
        raise ValueError("invalid manifest counts")
    return manifest, counts


def _persist(store, row, context, payload):
    if not isinstance(payload["result"], dict) or row["status"] != "running":
        raise ValueError("result not accepted in current state")
    manifest, counts = _manifest(payload, context["target"])
    result = payload["result"]
    # Results may include finding evidence, but never accept an archive or a
    # source path as input to the portal filesystem.
    fingerprint = hashlib.sha256(_json_bytes({"result": result, "manifest": manifest, "counts": counts})).hexdigest()
    if row.get("run_id"):
        metadata = row.get("metadata") or {}
        if metadata.get("result_digest") != fingerprint:
            raise ValueError("a different result is already persisted for this execution")
        return {"run_id": row["run_id"], "status": "persisted"}
    target = context["target"]
    snapshot = {**context["snapshot"], "files_total": counts["files_total"], "changed_files": counts["changed_paths"]}
    now, run_id, input_id, revision_id = store._now(), str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    with store._db() as db:
        db.execute("BEGIN IMMEDIATE")
        number = (db.execute("SELECT max(round_number) FROM scan_runs WHERE project_id=?", (target["project_id"],)).fetchone()[0] or 0) + 1
        db.execute("INSERT INTO inputs(input_id,project_id,name,path,content_hash,created_at,registered_by) VALUES(?,?,?,?,?,?,?)", (input_id, target["project_id"], "scheduled-result.json", "", "", now, "schedule-worker"))
        db.execute("INSERT INTO scan_runs(run_id,project_id,round_number,status,standard,standard_category,input_id,policy_version,requested_by,snapshot_json,created_at,result_json,completed_at,progress,stage) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (run_id,target["project_id"],number,"completed",target["standard"],target["standard_category"],input_id,context["policy"]["version"],"schedule-worker",store._json(snapshot),now,store._json(result),now,100,"completed"))
        db.execute("INSERT INTO analysis_revisions(revision_id,run_id,sequence,snapshot_json,result_json,created_at) VALUES(?,?,?,?,?,?)", (revision_id,run_id,1,store._json(snapshot),store._json(result),now))
        metadata = {"result_digest":fingerprint,"server":target["host"],"directory":target["remote_directory"],"mode":row["mode"]}
        db.execute("UPDATE schedule_runs SET run_id=?,stage='persisted',files_total=?,changed_files=?,metadata_json=?,updated_at=? WHERE schedule_run_id=?", (run_id,counts["files_total"],counts["changed_files"],store._json(metadata),now,row["schedule_run_id"]))
        # Baseline commits with the result. New collection remains blocked by
        # the lease until cleanup is acknowledged.
        db.execute("DELETE FROM schedule_files WHERE target_id=?", (target["target_id"],))
        db.executemany("INSERT INTO schedule_files(target_id,relative_path,size,mtime,sha256,updated_at) VALUES(?,?,?,?,?,?)", [(target["target_id"],x["relative_path"],x["size"],x["mtime"],x["sha256"],now) for x in manifest])
        if snapshot.get("gitlab_mapping_id"):
            db.execute("INSERT INTO tracker_deliveries(run_id,status,attempts,created_at,updated_at) VALUES(?,'pending',0,?,?)", (run_id,now,now))
            db.execute("INSERT INTO gitlab_issue_deliveries(run_id,status,attempts,created_at,updated_at) VALUES(?,'pending',0,?,?)", (run_id,now,now))
        db.execute("COMMIT")
    return {"run_id": run_id, "status": "persisted"}


def _tick(store):
    def deliver():
        from .schedule_worker import ScheduleRunner
        try:
            runner = ScheduleRunner(store)
            runner.retry_deliveries()
            store.prune_schedule_runs(90)
            with store._db() as db:
                db.execute("DELETE FROM schedule_api_receipts WHERE schedule_run_id NOT IN (SELECT schedule_run_id FROM schedule_runs)")
        finally:
            with _TICK_LOCK:
                _TICKS[store.path] = False
    with _TICK_LOCK:
        if _TICKS.get(store.path):
            return
        if store.path not in _TICKS:
            with store._db() as db:
                for table, column in (("tracker_deliveries", "status"), ("tracker_deliveries", "gitlab_result_status"), ("gitlab_issue_deliveries", "status")):
                    db.execute(f"UPDATE {table} SET {column}='pending' WHERE {column}='sending' AND run_id IN (SELECT run_id FROM schedule_runs)")
        _TICKS[store.path] = True
        threading.Thread(target=deliver, daemon=True, name="koda-schedule-delivery").start()


def dispatch(path, method, payload, *, store, **_):
    schemas = {"next": {"worker_id"}, "tick": set(),
               "heartbeat": {"schedule_run_id", "lease_token"},
               "persist": {"schedule_run_id", "lease_token", "result", "manifest", "counts"},
               "cleanup": {"schedule_run_id", "lease_token", "success", "error"},
               "fail": {"schedule_run_id", "lease_token", "error", "cancelled", "retryable"}}
    _ensure(store)
    if method == "GET" and path == API_PREFIX + "/state":
        return 200, {"settings": get_settings(store), "manual_busy": store.has_active_manual_work()}
    action = path.removeprefix(API_PREFIX + "/")
    if action not in schemas:
        return 404, {"code": "not_found"}
    if method != "POST":
        return 405, {"code": "method_not_allowed"}
    if not isinstance(payload, dict) or set(payload) != schemas[action]:
        return 422, {"code": "invalid_fields"}
    if action == "next":
        return 200, _next(store, payload["worker_id"])
    if action == "tick":
        _tick(store)
        return 202, {"accepted": True}
    with store._lock:
        try:
            lease, context, row = _leased(store, payload)
        except PermissionError:
            if action in {"cleanup", "persist", "fail"} and isinstance(payload["lease_token"], str):
                with store._db() as db:
                    receipt = db.execute("SELECT * FROM schedule_api_receipts WHERE schedule_run_id=?", (payload["schedule_run_id"],)).fetchone()
                if receipt and hmac.compare_digest(receipt["token_hash"], hashlib.sha256(payload["lease_token"].encode()).hexdigest()):
                    reply = json.loads(receipt["reply_json"])
                    return 200, reply
            return 403, {"code": "invalid_lease"}
        if action == "heartbeat":
            cancelled = row["status"] == "cancelling" or bool(row.get("run_id") and store.run(row["run_id"]).get("cancel_requested"))
            return 200, {"cancel_requested": cancelled, "manual_busy": store.has_active_manual_work(), "settings": get_settings(store)}
        if action == "persist":
            if row["status"] == "cancelling":
                return 409, {"code": "cancelled", "detail": "scheduled scan cancelled"}
            return 200, _persist(store, row, context, payload)
        if not isinstance(payload["error"], str) or len(payload["error"]) > 2000:
            raise ValueError("invalid scheduled error")
        if action == "fail":
            if any(not isinstance(payload[k], bool) for k in ("cancelled", "retryable")):
                raise ValueError("invalid failure state")
            if row.get("run_id"):
                return 409, {"code": "result_already_persisted"}
            state = "cancelled" if payload["cancelled"] else "failed"
            return 200, store.update_schedule_run(row["schedule_run_id"], status=state, stage="recollect" if payload["retryable"] else state, error=payload["error"])
        if not isinstance(payload["success"], bool):
            raise ValueError("invalid cleanup acknowledgement")
        if not payload["success"]:
            return 200, store.update_schedule_run(row["schedule_run_id"], cleanup_status="failed", cleanup_error=payload["error"])
        if not row.get("run_id") and row["status"] not in {"failed", "cancelled"}:
            return 409, {"code": "result_or_failure_required"}
        state = "completed" if row.get("run_id") else ("queued" if row["stage"] == "recollect" else row["status"])
        with store._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE schedule_runs SET status=?,stage=?,cleanup_status='completed',cleanup_error=NULL,completed_at=?,updated_at=? WHERE schedule_run_id=?", (state,state,store._now() if state != "queued" else None,store._now(),row["schedule_run_id"]))
            reply = {"schedule_run_id": row["schedule_run_id"], "run_id": row.get("run_id"), "status": state, "cleanup_status": "completed"}
            db.execute("INSERT OR REPLACE INTO schedule_api_receipts VALUES(?,?,?)", (row["schedule_run_id"],hashlib.sha256(payload["lease_token"].encode()).hexdigest(),store._json(reply)))
            db.execute("DELETE FROM schedule_api_lease WHERE slot=1")
            db.execute("COMMIT")
        return 200, store.schedule_run(row["schedule_run_id"])
