"""Nightly, sequential remote-directory scans for the Linux KODA portal.

The worker deliberately uses the system OpenSSH client.  It keeps remote
files read-only, stores only the persisted scan result, and removes its local
working tree in every terminal path.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import signal
import sys
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, Protocol

from .portal_store import PortalStore

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python 3.10+ has zoneinfo
    ZoneInfo = None  # type: ignore[assignment,misc]


KST = ZoneInfo("Asia/Seoul") if ZoneInfo else dt.timezone(dt.timedelta(hours=9))
RETRY_DELAYS = (60, 300, 900)
_PERMANENT_REMOTE_ERROR_MARKERS = (
    "permission denied", "authentication failed", "host key verification failed",
    "remote host identification has changed", "could not resolve hostname", "name or service not known",
    "no such file or directory", "not a directory", "cannot access", "bad configuration option",
)
_TRANSIENT_REMOTE_ERROR_MARKERS = (
    "connection reset", "connection timed out", "connection refused", "network is unreachable",
    "temporarily unavailable", "broken pipe", "lost connection", "try again",
)
SCHEDULE_PROBE_FIELDS = frozenset({
    "host", "port", "username", "ssh_key_ref", "known_hosts_file", "remote_directory",
    "exclude_paths", "max_files", "max_bytes", "timeout_seconds",
})
_DEPENDENCY_MANIFEST_NAMES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "package.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "requirements.in", "pyproject.toml", "poetry.lock", "Pipfile.lock",
    "go.mod", "go.sum", "Cargo.lock", "Gemfile.lock", "composer.lock", "pom.xml", "packages.config",
})


def schedule_probe_target(payload: dict) -> dict:
    """Validate the non-secret connection settings used by admin probes."""
    if not isinstance(payload, dict):
        raise ValueError("schedule probe payload must be an object")
    unknown = sorted(set(payload) - SCHEDULE_PROBE_FIELDS)
    if unknown:
        raise ValueError(f"invalid schedule probe fields: {', '.join(unknown)}")
    required = ("host", "username", "ssh_key_ref", "known_hosts_file", "remote_directory")
    values = {key: str(payload.get(key) or "").strip() for key in required}
    if any(not value for value in values.values()):
        raise ValueError("schedule probe connection fields are required")
    if any(any(char in value for char in "\x00\r\n") for value in values.values()):
        raise ValueError("schedule probe fields contain an invalid control character")
    if not values["remote_directory"].startswith("/"):
        raise ValueError("remote directory must be an absolute path")
    if not Path(values["ssh_key_ref"]).expanduser().is_absolute() or not Path(values["known_hosts_file"]).expanduser().is_absolute():
        raise ValueError("SSH key and known-hosts paths must be absolute")
    try:
        port = int(payload.get("port", 22))
        max_files = int(payload.get("max_files", 200_000))
        max_bytes = int(payload.get("max_bytes", 1024 * 1024 * 1024))
        timeout_seconds = int(payload.get("timeout_seconds", 60))
    except (TypeError, ValueError) as exc:
        raise ValueError("schedule probe numeric fields are invalid") from exc
    if not 1 <= port <= 65535:
        raise ValueError("invalid SSH port")
    if not 1 <= max_files <= 200_000 or not 1 <= max_bytes <= 4 * 1024 * 1024 * 1024:
        raise ValueError("invalid schedule probe resource limit")
    if not 1 <= timeout_seconds <= 300:
        raise ValueError("invalid schedule probe timeout")
    excludes = payload.get("exclude_paths") or []
    if isinstance(excludes, str):
        excludes = [item.strip() for item in excludes.splitlines() if item.strip()]
    if not isinstance(excludes, list) or any(
        not isinstance(item, str) or not item.strip() or any(ord(char) < 32 for char in item)
        for item in excludes
    ):
        raise ValueError("invalid excluded path list")
    return {
        **values, "port": port, "exclude_paths": sorted(set(item.strip() for item in excludes)),
        "max_files": max_files, "max_bytes": max_bytes, "timeout_seconds": timeout_seconds,
    }


from .schedule_transport import (
    OpenSSHCollector, RemoteFile, RemoteCollector, _ssh_options,
    _remote_name, _excluded, _retryable_remote_error,
)


class ScheduleRunner:
    """Own one KODA-host scheduler and never runs two targets concurrently."""

    def __init__(
        self,
        store: PortalStore,
        *,
        collector: RemoteCollector | None = None,
        work_dir: str | Path | None = None,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], dt.datetime] | None = None,
    ):
        self.store = store
        self.collector = collector or OpenSSHCollector()
        self.work_dir = Path(work_dir or os.environ.get("KODA_SCHEDULE_WORK_DIR") or Path(store.path).parent / "schedule-work").expanduser()
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._sleep = sleep
        self._now = now or (lambda: dt.datetime.now(KST))

    def recover(self) -> None:
        """Only the exclusive schedule owner may remove abandoned copies."""
        failed_paths = []
        for path in self.work_dir.glob("koda-schedule-*"):
            try:
                if path.is_symlink() or not path.is_dir():
                    path.unlink(missing_ok=True)
                else:
                    shutil.rmtree(path)
            except OSError:
                failed_paths.append(str(path))
        self._cleanup_blocked = bool(failed_paths)
        for item in self.store.list_schedule_runs(limit=500):
            if item["cleanup_status"] == "completed" and item["status"] not in {"running", "cancelling"}:
                continue
            run_id = item.get("run_id")
            cleaned = not failed_paths
            status = item["status"]
            if run_id:
                try:
                    run = self.store.run(run_id)
                    if run["status"] in {"queued", "running", "cancelling"}:
                        self.store.complete_run(run_id, error="워커 재시작으로 중단됨; 원본을 다시 수집합니다")
                        status = "cancelled" if run.get("cancel_requested") else "queued"
                    elif run["status"] == "completed":
                        status = "completed"
                    cleaned = self.store.cleanup_input_for_run(run_id) and cleaned
                except KeyError:
                    status = "queued"
            elif status in {"running", "cancelling"}:
                status = "queued"
            self.store.update_schedule_run(
                item["schedule_run_id"], status=status if cleaned else "failed",
                stage="recovered" if cleaned else "cleanup_failed",
                cleanup_status="completed" if cleaned else "failed",
                cleanup_error=None if cleaned else "남은 임시 원본 정리 실패: " + ", ".join(failed_paths)[:1000],
            )
        # Delivery claims belong to this worker and can now be safely recovered.
        with self.store._db() as db:
            for table, column in (("tracker_deliveries", "status"), ("tracker_deliveries", "gitlab_result_status"), ("gitlab_issue_deliveries", "status")):
                db.execute(f"UPDATE {table} SET {column}='pending' WHERE {column}='sending' AND run_id IN (SELECT run_id FROM schedule_runs)")
        self.store.prune_schedule_runs(90)

    def run_forever(self) -> None:
        self.recover()
        while True:
            self.run_once(self._now())
            self._sleep(60)

    def run_once(self, when: dt.datetime | None = None, *, scheduled_for: str | None = None) -> list[dict]:
        when = (when or self._now()).astimezone(KST)
        self.retry_deliveries()
        targets = self.store.list_schedule_targets(enabled_only=True)
        enabled_ids = {t["target_id"] for t in targets}
        pending = [r["scheduled_for"] for r in self.store.list_schedule_runs(limit=500) if r["target_id"] in enabled_ids and r["status"] in {"queued", "running", "cancelling"}]
        scheduled_for = min(pending) if pending else (scheduled_for or (when.date().isoformat() if when.hour >= 1 else ""))
        if not scheduled_for or getattr(self, "_cleanup_blocked", False):
            return []
        # Persist the day's queue before starting; restart resumes the old date.
        for target in targets:
            self.store.begin_schedule_run(target["target_id"], scheduled_for, self._mode(target, scheduled_for), target["config_version"])
        results = []
        for target in targets:
            if self.store.has_active_manual_work() or self.store.has_active_schedule_work():
                break
            if not self._disk_available(int(target["max_bytes"]) * 3):
                break
            current = next((r for r in self.store.list_schedule_runs(target["target_id"]) if r["scheduled_for"] == scheduled_for), None)
            if current and current["status"] in {"completed", "failed", "cancelled"}:
                continue
            result = self.run_target(target, scheduled_for=scheduled_for)
            results.append(result)
            if result.get("started_at") and os.environ.get("KODA_SCHEDULE_NO_SLEEP") != "1":
                self._sleep(float(os.environ.get("KODA_SCHEDULE_GAP_SECONDS", "30")))
        self.store.prune_schedule_runs(90)
        return results

    def _disk_available(self, needed: int) -> bool:
        reserve = int(os.environ.get("KODA_SCHEDULE_MIN_FREE_BYTES", "1073741824"))
        return shutil.disk_usage(self.work_dir).free >= needed + reserve

    def retry_deliveries(self) -> None:
        from .linux_portal import _run_delivery

        with self.store._db() as db:
            pending = db.execute("""SELECT DISTINCT sr.* FROM schedule_runs sr
                LEFT JOIN tracker_deliveries t ON t.run_id=sr.run_id
                LEFT JOIN gitlab_issue_deliveries g ON g.run_id=sr.run_id
                WHERE sr.cleanup_status='completed' AND sr.status='completed' AND sr.run_id IS NOT NULL
                AND (t.status IN ('pending','failed','partial') OR t.gitlab_result_status IN ('pending','failed','partial')
                     OR g.status IN ('pending','failed','partial')) ORDER BY sr.scheduled_for,sr.created_at""").fetchall()
        for row in pending:
            scheduled = self.store._schedule_run_dict(row)
            if self.store.has_active_manual_work():
                return
            run_id = scheduled["run_id"]
            for kind in ("tracker", "gitlab_result", "issues"):
                state = (self.store.gitlab_issue_delivery(run_id) if kind == "issues" else self.store.tracker_delivery(run_id)) or {}
                prefix = "gitlab_result_" if kind == "gitlab_result" else ""
                status = state.get(prefix + "status")
                if status not in {"pending", "failed", "partial"}:
                    continue
                if kind == "gitlab_result" and state.get("status") not in {"completed", "skipped"}:
                    continue
                attempts = int(state.get(prefix + "attempts") or 0)
                if attempts:
                    updated = dt.datetime.fromisoformat(state["updated_at"])
                    if (self._now().astimezone(dt.timezone.utc) - updated).total_seconds() < RETRY_DELAYS[min(attempts - 1, 2)]:
                        continue
                try:
                    _run_delivery(self.store, kind, run_id, retry=status in {"failed", "partial"})
                except Exception as exc:
                    self.store.record_audit("schedule-worker", "schedule.delivery_failed", {"run_id": run_id, "kind": kind, "error": str(exc)[:500]})
            tracker = self.store.tracker_delivery(run_id) or {}
            issues = self.store.gitlab_issue_delivery(run_id) or {}
            result_status = tracker.get("gitlab_result_status", "not_configured")
            issue_status = issues.get("status", "not_configured")
            gitlab_status = ("completed" if result_status == issue_status == "completed" else
                             "failed" if "failed" in {result_status, issue_status} else
                             "partial" if "partial" in {result_status, issue_status} else result_status)
            self.store.update_schedule_run(scheduled["schedule_run_id"], tracker_status=tracker.get("status", "not_configured"), gitlab_status=gitlab_status)

    def _analyze(self, run_id: str, deadline: float) -> None:
        # A process group lets timeout/cancellation stop analyzer subprocesses too.
        process = subprocess.Popen(
            [sys.executable, "-m", "security_scanner.schedule_worker", "--db", self.store.path, "--scan-run", run_id],
            start_new_session=True,
        )
        try:
            while process.poll() is None:
                if self.store.run(run_id).get("cancel_requested"):
                    raise RuntimeError("스케줄 점검이 취소되었습니다")
                if time.monotonic() >= deadline:
                    raise TimeoutError("스케줄 디렉토리 제한시간을 초과했습니다")
                time.sleep(0.2)
            if process.returncode:
                raise RuntimeError(f"분석 프로세스 종료: {process.returncode}")
        finally:
            # Kill descendants even when the analyzer parent exited first.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()

    def _mode(self, target: dict, scheduled_for: str) -> str:
        last = self.store.last_schedule_run(target["target_id"])
        if not last or (last.get("files_total") and not self.store.baseline_schedule_files(target["target_id"])) or int(last.get("config_version") or 0) != int(target.get("config_version") or 0):
            return "full"
        try:
            # A rule-policy edit changes the scan semantics even when the
            # remote manifest is unchanged, so the next run must re-check all
            # files. Read the immutable policy snapshot from the completed
            # scan rather than trusting the mutable target row.
            policy = self.store.rule_policy(target["project_id"])
            previous_run_id = str(last.get("run_id") or "")
            previous = self.store.run(previous_run_id) if previous_run_id else None
            previous_snapshot = (previous or {}).get("snapshot") or {}
            if (
                int(previous_snapshot.get("rule_policy_version") or 0) != int(policy.get("version") or 0)
                or str(previous_snapshot.get("rule_policy_hash") or "") != str(policy.get("hash") or "")
            ):
                return "full"
            day = dt.date.fromisoformat(scheduled_for).weekday()
        except (KeyError, TypeError, ValueError):
            return "full"
        return "full" if day == 6 else "changed"

    def _retry(self, operation: Callable[[], object], target: dict, *, deadline: float | None = None) -> object:
        delays = RETRY_DELAYS
        for attempt in range(len(delays) + 1):
            try:
                value = operation()
                if deadline is not None and time.monotonic() > deadline:
                    raise TimeoutError("스케줄 디렉토리 제한시간을 초과했습니다")
                return value
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                if not _retryable_remote_error(exc):
                    raise
                if attempt >= len(delays):
                    raise
                if deadline is not None and time.monotonic() + delays[attempt] >= deadline:
                    raise TimeoutError("스케줄 디렉토리 제한시간을 초과했습니다") from exc
                self.store.record_audit("schedule-worker", "schedule.retry", {
                    "project_id": target["project_id"], "target_id": target["target_id"],
                    "attempt": attempt + 1, "error": str(exc)[:500],
                })
                if os.environ.get("KODA_SCHEDULE_NO_SLEEP") != "1":
                    self._sleep(delays[attempt])
        raise AssertionError("unreachable")

    @staticmethod
    def _manifest_diff(current: list[RemoteFile], baseline: dict[str, dict], mode: str) -> list[RemoteFile]:
        if mode == "full":
            return list(current)
        return [
            item for item in current
            if item.relative_path not in baseline
            or int(baseline[item.relative_path]["size"]) != item.size
            or float(baseline[item.relative_path]["mtime"]) != item.mtime
        ]

    @staticmethod
    def _dependency_manifest(item: RemoteFile) -> bool:
        """Keep library manifests in changed scans so the SBOM stays complete."""
        name = PurePosixPath(item.relative_path).name
        return (
            name in _DEPENDENCY_MANIFEST_NAMES
            or name.endswith("-requirements.txt")
            or name.endswith((".csproj", ".fsproj", ".vbproj"))
            or name == "Dockerfile"
            or name.startswith("Dockerfile.")
        )

    @staticmethod
    def _hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _archive(self, target: dict, files: list[RemoteFile], root: Path, *, deadline: float | None = None) -> tuple[Path, list[RemoteFile], int]:
        source_root, archive = root / "files", root / "source.tar.gz"
        source_root.mkdir(parents=True, exist_ok=True)
        collected: list[RemoteFile] = []
        total_bytes = 0
        for remote_file in files:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("스케줄 디렉토리 제한시간을 초과했습니다")
            if not self._disk_available(remote_file.size * 3):
                raise OSError("임시 점검 디스크 여유 공간이 부족합니다")
            if len(collected) >= int(target["max_files"]):
                raise ValueError("원격 파일 수 제한을 초과했습니다")
            if total_bytes + remote_file.size > int(target["max_bytes"]):
                raise ValueError("원격 수집 용량 제한을 초과했습니다")
            destination = source_root.joinpath(*PurePosixPath(remote_file.relative_path).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            def fetch_one(rf=remote_file, dest=destination):
                call_target = target
                if deadline is not None:
                    remaining = int(deadline - time.monotonic())
                    if remaining < 1:
                        raise TimeoutError("스케줄 디렉토리 제한시간을 초과했습니다")
                    call_target = {**target, "timeout_seconds": min(int(target["timeout_seconds"]), remaining)}
                return self.collector.fetch(call_target, rf, dest)

            self._retry(fetch_one, target, deadline=deadline)
            if not destination.is_file():
                raise RuntimeError(f"원격 파일 수집 결과가 없습니다: {remote_file.relative_path}")
            actual_size = destination.stat().st_size
            if actual_size > int(target["max_bytes"]) or total_bytes + actual_size > int(target["max_bytes"]):
                raise ValueError("원격 수집 용량 제한을 초과했습니다")
            actual_hash = self._hash(destination)
            collected.append(RemoteFile(remote_file.relative_path, actual_size, remote_file.mtime, actual_hash))
            total_bytes += actual_size
        with tarfile.open(archive, "w:gz") as bundle:
            for remote_file in collected:
                path = source_root.joinpath(*PurePosixPath(remote_file.relative_path).parts)
                bundle.add(path, arcname=remote_file.relative_path, recursive=False)
        return archive, collected, total_bytes

    def _snapshot(
        self, target: dict, schedule_run: dict, mode: str, files: list[RemoteFile], *, files_total: int | None = None,
    ) -> dict:
        snapshot = {
            "source_type": "scheduled_server",
            "schedule_target_id": target["target_id"],
            "schedule_run_id": schedule_run["schedule_run_id"],
            "scheduled_for": schedule_run.get("scheduled_for"),
            "remote_server": f"{target['host']}:{target['port']}",
            "remote_directory": target["remote_directory"],
            "scan_mode": mode,
            "changed_files": [item.relative_path for item in files],
            "files_total": int(files_total if files_total is not None else len(files)),
            # The policy version is filled by PortalStore from the immutable
            # project policy; keep target configuration changes separate so a
            # target edit cannot masquerade as a rule-policy revision.
            "schedule_config_version": target.get("config_version", 1),
            "disabled_rules": list(target.get("disabled_rules") or []),
            "schedule_max_files": target["max_files"], "schedule_max_bytes": target["max_bytes"],
            "gitlab_mapping_id": target.get("gitlab_mapping_id") or "",
            "gitlab_target_branch": target.get("gitlab_target_branch") or "",
        }
        if target.get("gitlab_mapping_id"):
            try:
                mapping = self.store.gitlab_repository(target["gitlab_mapping_id"], target["project_id"])
            except KeyError:
                mapping = None
            if mapping:
                snapshot.update({
                    "gitlab_project_id": mapping["gitlab_project_id"],
                    "gitlab_path_with_namespace": mapping["path_with_namespace"],
                    "gitlab_default_branch": target.get("gitlab_target_branch") or mapping["default_branch"],
                    "tracker_service_id": mapping["tracker_service_id"],
                    "tracker_environment_id": mapping["tracker_environment_id"],
                    "tracker_token_ref": mapping["tracker_token_ref"],
                })
        return snapshot

    def run_target(self, target: dict, *, scheduled_for: str | None = None) -> dict:
        scheduled_for = scheduled_for or self._now().astimezone(KST).date().isoformat()
        mode = self._mode(target, scheduled_for)
        schedule_run = self.store.begin_schedule_run(target["target_id"], scheduled_for, mode, int(target.get("config_version", 1)))
        if schedule_run["status"] in {"completed", "failed", "cancelled"}:
            return schedule_run
        if not self.store.claim_schedule_run(schedule_run["schedule_run_id"]):
            return self.store.schedule_run(schedule_run["schedule_run_id"])
        schedule_run = self.store.schedule_run(schedule_run["schedule_run_id"])
        root = Path(tempfile.mkdtemp(prefix="koda-schedule-", dir=self.work_dir))
        archive: Path | None = None
        input_id: str | None = None
        run_id: str | None = None
        cleanup_ok = True
        cleanup_error = ""
        try:
            deadline = time.monotonic() + int(target["timeout_seconds"])
            self.store.update_schedule_run(schedule_run["schedule_run_id"], status="running", stage="listing", started_at=dt.datetime.now(dt.timezone.utc).isoformat())
            def list_current():
                remaining = int(deadline - time.monotonic())
                if remaining < 1:
                    raise TimeoutError("스케줄 디렉토리 제한시간을 초과했습니다")
                return self.collector.list_files({**target, "timeout_seconds": remaining})
            current = self._retry(list_current, target, deadline=deadline)
            if not isinstance(current, list):
                raise RuntimeError("원격 파일 목록이 올바르지 않습니다")
            if len(current) > int(target["max_files"]):
                raise ValueError("원격 파일 수 제한을 초과했습니다")
            if any(item.size < 0 for item in current):
                raise ValueError("원격 파일 크기가 올바르지 않습니다")
            baseline = self.store.baseline_schedule_files(target["target_id"])
            changed = self._manifest_diff(current, baseline, mode)
            archive_files = list(changed)
            if mode == "changed" and target.get("scan_scope") in {"all", "library"}:
                changed_paths = {item.relative_path for item in changed}
                archive_files.extend(
                    item for item in current
                    if item.relative_path not in changed_paths and self._dependency_manifest(item)
                )
            self.store.update_schedule_run(
                schedule_run["schedule_run_id"], stage="collecting", files_total=len(current), changed_files=len(changed),
                metadata={"server": target["host"], "directory": target["remote_directory"], "mode": mode},
            )
            if not self._disk_available(sum(item.size for item in archive_files) * 3):
                self.store.update_schedule_run(schedule_run["schedule_run_id"], status="queued", stage="disk_wait")
                return self.store.schedule_run(schedule_run["schedule_run_id"])
            archive, collected, total_bytes = self._archive(target, archive_files, root, deadline=deadline)
            metadata = {
                "server": target["host"], "directory": target["remote_directory"], "mode": mode,
                "changedFiles": [item.relative_path for item in changed], "filesTotal": len(current),
                "cleanupStatus": "pending", "scheduleRunId": schedule_run["schedule_run_id"],
            }
            self.store.update_schedule_run(schedule_run["schedule_run_id"], stage="analyzing", metadata=metadata)
            input_id = self.store.add_input(
                target["project_id"], f"scheduled-{target['target_id']}-{scheduled_for}.tar.gz", archive,
                "schedule-worker", self._hash(archive),
            )
            snapshot = self._snapshot(target, schedule_run, mode, changed, files_total=len(current))
            run = self.store.create_scheduled_scan(
                target["project_id"], input_id, target["standard"], target["standard_category"], target["scan_scope"], snapshot,
            )
            run_id = run["run_id"]
            self.store.update_schedule_run(schedule_run["schedule_run_id"], run_id=run["run_id"])
            while self.store.has_active_manual_work():
                if time.monotonic() >= deadline:
                    raise TimeoutError("수동 점검 대기 중 스케줄 제한시간을 초과했습니다")
                self._sleep(1)
            self._analyze(run["run_id"], deadline)
            if time.monotonic() > deadline:
                raise TimeoutError("스케줄 디렉토리 제한시간을 초과했습니다")
            finished = self.store.run(run["run_id"])
            tracker = self.store.tracker_delivery(run["run_id"])
            issue = self.store.gitlab_issue_delivery(run["run_id"])
            input_path = Path(self.store.input(input_id)["path"])
            self.store.cleanup_input_for_run(run["run_id"])
            cleanup_ok = not input_path.exists()
            if not cleanup_ok:
                raise RuntimeError("임시 수집 원본 정리에 실패했습니다")
            # All copies, including collected files and extraction, go before delivery.
            shutil.rmtree(root)
            metadata["cleanupStatus"] = "completed"
            run_status = str(finished.get("status") or "failed")
            terminal_status = run_status if run_status in {"completed", "failed", "cancelled"} else "failed"
            self.store.update_schedule_run(
                schedule_run["schedule_run_id"], status=terminal_status,
                stage="completed" if terminal_status == "completed" else terminal_status,
                cleanup_status="completed", tracker_status=(tracker or {}).get("status", "not_configured"),
                gitlab_status=(issue or {}).get("status", (tracker or {}).get("gitlab_result_status", "not_configured")),
                metadata=metadata, completed_at=dt.datetime.now(dt.timezone.utc).isoformat(),
            )
            if terminal_status == "completed":
                collected_by_path = {item.relative_path: item for item in collected}
                baseline_files = []
                for item in current:
                    fetched = collected_by_path.get(item.relative_path)
                    previous = baseline.get(item.relative_path) or {}
                    sha256 = fetched.sha256 if fetched else str(previous.get("sha256") or "")
                    if not sha256:
                        raise RuntimeError(f"기준 해시를 저장할 수 없습니다: {item.relative_path}")
                    baseline_files.append({**item.__dict__, "sha256": sha256})
                self.store.replace_schedule_files(target["target_id"], baseline_files)
        except Exception as exc:
            if run_id and self.store.run(run_id)["status"] not in {"completed", "failed", "cancelled"}:
                self.store.complete_run(run_id, error=str(exc)[:2000])
            cancelled = bool(run_id and self.store.run(run_id)["status"] == "cancelled")
            self.store.update_schedule_run(
                schedule_run["schedule_run_id"], status="cancelled" if cancelled else "failed", stage="failed", error=str(exc)[:2000],
                cleanup_status="pending", cleanup_error=None,
                completed_at=dt.datetime.now(dt.timezone.utc).isoformat(),
            )
        finally:
            cleanup_ok, cleanup_error = True, ""
            try:
                if input_id:
                    if run_id:
                        source_path = Path(self.store.input(input_id)["path"])
                        self.store.cleanup_input_for_run(run_id)
                        if source_path.exists():
                            raise OSError("임시 입력 파일 정리에 실패했습니다")
                    else:
                        self.store.discard_input(input_id)
                if root.exists():
                    shutil.rmtree(root, ignore_errors=False)
            except (KeyError, OSError, ValueError) as exc:
                cleanup_ok, cleanup_error = False, str(exc)[:1000]
            try:
                if not cleanup_ok:
                    self.store.update_schedule_run(
                        schedule_run["schedule_run_id"], status="failed", stage="failed",
                        cleanup_status="failed", cleanup_error=cleanup_error,
                    )
                else:
                    self.store.update_schedule_run(
                        schedule_run["schedule_run_id"], cleanup_status="completed", cleanup_error=None,
                    )
            except KeyError:
                pass
            except OSError as exc:
                try:
                    self.store.update_schedule_run(
                        schedule_run["schedule_run_id"], status="failed", stage="failed",
                        cleanup_status="failed", cleanup_error=str(exc)[:1000],
                    )
                except KeyError:
                    pass
        self.retry_deliveries()
        return self.store.schedule_run(schedule_run["schedule_run_id"])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="KODA nightly remote-directory schedule worker")
    parser.add_argument("--db", default=os.environ.get("KODA_PORTAL_DB", "koda-portal.sqlite3"))
    parser.add_argument("--work-dir", default=os.environ.get("KODA_SCHEDULE_WORK_DIR"))
    parser.add_argument("--scan-run", help=argparse.SUPPRESS)
    parser.add_argument("--once", action="store_true", help="run the current KST schedule date once")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.scan_run:
        from .linux_portal import _run_scan
        _run_scan(PortalStore(args.db), args.scan_run)
        return 0
    if os.environ.get("KODA_SCHEDULE_API_URL"):
        from .schedule_api_worker import ApiScheduleRunner
        import fcntl
        state = Path(os.environ.get("KODA_SCHEDULE_STATE_DIR", "/var/lib/koda-schedule"))
        state.mkdir(parents=True, exist_ok=True)
        with (state / "worker.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return 0
            runner = ApiScheduleRunner(work_dir=args.work_dir)
            runner.run_once() if args.once else runner.run_forever()
        return 0
    raise ValueError("KODA_SCHEDULE_API_URL is required; portal database access is not a worker deployment mode")


if __name__ == "__main__":
    raise SystemExit(main())
