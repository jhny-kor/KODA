"""Stream the leased GitLab source without storing originals in the portal."""
import json
import time

from .portal_integrations import IntegrationError, _gitlab_open, resolve_gitlab_ref
from .schedule_api import _leased


def serve_archive(handler, store, payload, settings_dir):
    if not isinstance(payload, dict) or set(payload) != {"schedule_run_id", "lease_token"}:
        return handler._json(422, {"code": "invalid_fields"})
    try:
        with store._lock:
            _, context, row = _leased(store, payload)
            target = context["target"]
            if target.get("source_kind") != "gitlab" or row["status"] != "running" or row.get("run_id"):
                return handler._json(409, {"code": "source_unavailable"})
            mapping = store.gitlab_repository(target["source_gitlab_mapping_id"], target["project_id"])
            if not mapping.get("enabled", True):
                return handler._json(403, {"code": "source_disabled"})
        sha = context["snapshot"].get("source_gitlab_commit_sha")
        if not sha:
            sha = resolve_gitlab_ref(mapping["gitlab_project_id"], target.get("source_gitlab_ref_type", "branch"), target["source_gitlab_ref"], settings_dir)
            with store._lock:
                _, current, row = _leased(store, payload)
                if row["status"] != "running":
                    return handler._json(409, {"code": "cancelled"})
                # A repeated request always uses the original resolved commit.
                sha = current["snapshot"].setdefault("source_gitlab_commit_sha", sha)
                with store._db() as db:
                    db.execute("UPDATE schedule_api_lease SET context_json=? WHERE slot=1", (json.dumps(current),))
        response = _gitlab_open(f"/projects/{int(mapping['gitlab_project_id'])}/repository/archive.tar.gz",
                                {"sha": sha, "include_lfs_blobs": "false"}, timeout=30, settings_dir=settings_dir)
    except PermissionError:
        return handler._json(403, {"code": "invalid_lease"})
    except IntegrationError as exc:
        # Do not forward GitLab response bodies or credentials to the worker.
        return handler._json(503 if not exc.status or exc.status >= 500 or exc.status == 429 else 422, {"code": "gitlab_source_unavailable"})
    sent = False
    try:
        with response:
            kind = str(response.headers.get("Content-Type", "")).lower()
            if kind.startswith("text/") or "json" in kind:
                return handler._json(502, {"code": "invalid_gitlab_archive"})
            if int(response.headers.get("Content-Length", "0") or 0) > target["max_bytes"]:
                return handler._json(413, {"code": "archive_too_large"})
            handler.send_response(200)
            handler.send_header("Content-Type", "application/gzip")
            handler.send_header("Transfer-Encoding", "chunked")
            handler.send_header("Connection", "close")
            handler.end_headers()
            sent = True
            handler.close_connection = True
            total, started, checked = 0, time.monotonic(), 0
            while True:
                now = time.monotonic()
                if now - started > target["timeout_seconds"]:
                    raise TimeoutError("archive deadline")
                if now - checked >= 1:
                    with store._lock:
                        _, _, row = _leased(store, payload)
                    if row["status"] != "running":
                        raise InterruptedError("cancelled")
                    checked = now
                block = response.read(64 * 1024)
                if not block:
                    break
                total += len(block)
                if total > target["max_bytes"]:
                    raise ValueError("archive limit")
                handler.wfile.write(f"{len(block):X}\r\n".encode() + block + b"\r\n")
            # Only a complete upstream download receives the terminating chunk.
            handler.wfile.write(b"0\r\n\r\n")
    except (OSError, ValueError, PermissionError):
        handler.close_connection = True
        if not sent:
            return handler._json(502, {"code": "gitlab_stream_failed"})
