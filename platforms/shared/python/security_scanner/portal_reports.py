"""Bounded report rendering outside the portal HTTP process."""
from __future__ import annotations

import argparse
import io
import json
import logging
import os
from pathlib import Path
import resource
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import quote
import zipfile


_REPORT_SLOT = threading.BoundedSemaphore(1)
_LOG = logging.getLogger(__name__)
_PROC_ROOT = Path("/proc")
REPORT_FORMATS = {
    "html": ("application/zip", "zip"),
    "markdown": ("text/markdown; charset=utf-8", "md"),
    "md": ("text/markdown; charset=utf-8", "md"),
    "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"),
    "hwpx": ("application/hwp+zip", "hwpx"),
    "pdf": ("application/pdf", "pdf"),
    "json": ("application/json; charset=utf-8", "json"),
    "report.html": ("text/html; charset=utf-8", "html"),
    "report-detail.html": ("text/html; charset=utf-8", "html"),
    "report-vulnerabilities.html": ("text/html; charset=utf-8", "html"),
}


class ReportExportError(RuntimeError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def _process_stat(path: Path) -> tuple[int, int, int, int]:
    # comm may contain spaces or ')'; fields after its closing ')' start at
    # state (3). ppid=4, pgrp=5, starttime=22, rss=24 in Linux proc_pid_stat.
    fields = path.read_text().rsplit(") ", 1)[1].split()
    return int(fields[1]), int(fields[2]), int(fields[19]), int(fields[21]) * os.sysconf("SC_PAGE_SIZE")


def _sample_report_memory(root_pid: int, tracked: dict[int, int]) -> int:
    stats = {}
    for directory in _PROC_ROOT.iterdir():
        if directory.name.isdecimal():
            try:
                stats[int(directory.name)] = _process_stat(directory / "stat")
            except (OSError, ValueError, IndexError):
                continue  # exited during this snapshot
    root = stats.get(root_pid)
    same_root = root is None or root_pid not in tracked or root[2] == tracked[root_pid]
    members = {pid for pid, (_, group, start, _) in stats.items()
               if (same_root and (pid == root_pid or group == root_pid)) or tracked.get(pid) == start}
    while True:
        descendants = {pid for pid, (parent, _, _, _) in stats.items() if parent in members}
        if descendants <= members:
            break
        members.update(descendants)
    tracked.update({pid: stats[pid][2] for pid in members})
    # This is a sampled RSS sum (shared pages may be counted more than once),
    # not a kernel memory ceiling. Include Playwright's detached browser tree.
    return sum(stats[pid][3] for pid in members)


def _wait_for_report(process: subprocess.Popen, timeout: int, memory_bytes: int, tracked: dict[int, int]) -> None:
    if sys.platform != "linux":
        process.wait(timeout=timeout)
        return
    deadline = time.monotonic() + timeout
    while process.poll() is None:
        try:
            resident = _sample_report_memory(process.pid, tracked)
        except OSError:
            raise ReportExportError("report_monitor_unavailable", "보고서 메모리 상태를 확인하지 못했습니다.") from None
        if resident > memory_bytes:
            raise ReportExportError("report_memory_exceeded", "보고서 생성 메모리 예산을 초과했습니다.")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, timeout)
        try:
            process.wait(timeout=min(.2, remaining))
        except subprocess.TimeoutExpired:
            pass


def _kill_group(process: subprocess.Popen, tracked: dict[int, int] | None = None) -> None:
    same_root = True
    if tracked and process.pid in tracked:
        try:
            same_root = _process_stat(_PROC_ROOT / str(process.pid) / "stat")[2] == tracked[process.pid]
        except (OSError, ValueError, IndexError):
            pass  # the original group can still contain the lifetime watchdog
    try:
        if same_root:
            os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    for pid, started in (tracked or {}).items():
        try:
            if _process_stat(_PROC_ROOT / str(pid) / "stat")[2] == started:
                os.kill(pid, signal.SIGKILL)
        except (OSError, ValueError, IndexError):
            pass  # exited or PID was reused
    process.wait()


def _apply_report_limits(report_format: str, memory_bytes: int) -> None:
    from .process_limits import apply_limits
    inherited_address_limit = resource.getrlimit(resource.RLIMIT_AS)
    apply_limits({"cpus": 1, "memory_bytes": memory_bytes})
    if report_format == "pdf":
        # Chromium/V8 reserves large virtual cages; actual RSS is monitored by
        # the HTTP parent. Preserve any explicit limit inherited from the host.
        resource.setrlimit(resource.RLIMIT_AS, inherited_address_limit)


def render_portal_report(db_path: str, run_id: str, report_format: str, language: str) -> tuple[bytes, str, str]:
    """One renderer at a time, with a wall deadline and private temporary files.

    Loading the full result, serialization and Chromium run in the child. The
    child watches the HTTP parent and kills its tools if the parent disappears.
    Linux samples aggregate descendant RSS, including detached Chromium. This
    is a best-effort guard inside the shared web cgroup, not hard isolation.
    """
    if report_format not in REPORT_FORMATS:
        raise ValueError("unsupported report format")
    if not _REPORT_SLOT.acquire(blocking=False):
        raise ReportExportError("report_busy", "다른 보고서를 생성 중입니다. 잠시 후 다시 시도하세요.")
    try:
        try:
            timeout = max(1, min(3600, int(os.environ.get("KODA_PORTAL_REPORT_TIMEOUT_SECONDS", "90"))))
            memory_bytes = int(os.environ.get("KODA_PORTAL_REPORT_MEMORY_BYTES", str(2 * 1024**3)))
            if memory_bytes < 256 * 1024**2:
                raise ValueError("report memory budget must be at least 256 MiB")
        except ValueError:
            raise ReportExportError("report_configuration_invalid", "보고서 생성 시간 또는 메모리 제한 설정이 올바르지 않습니다.") from None
        with tempfile.TemporaryDirectory(prefix="koda-report-") as temporary:
            directory = Path(temporary)
            output, error = directory / "report.bin", directory / "error.json"
            environment = dict(os.environ)
            package_root = str(Path(__file__).resolve().parents[1])
            environment["PYTHONPATH"] = package_root + (os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else "")
            try:
                process = subprocess.Popen(
                    [sys.executable, "-m", "security_scanner.portal_reports", "--db", db_path,
                     "--run", run_id, "--format", report_format, "--language", language,
                     "--output", str(output), "--error", str(error), "--parent", str(os.getpid())],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    env=environment, start_new_session=True,
                )
            except OSError as exc:
                _LOG.warning("Run %s report renderer could not start: %s", run_id, type(exc).__name__)
                raise ReportExportError("report_unavailable", "보고서 생성기를 시작하지 못했습니다.") from None
            tracked: dict[int, int] = {}
            try:
                _wait_for_report(process, timeout, memory_bytes, tracked)
            except subprocess.TimeoutExpired:
                raise ReportExportError("report_timeout", "보고서 생성 제한 시간을 초과했습니다.") from None
            finally:
                # Also remove subprocess tools after a renderer exits early.
                if sys.platform == "linux":
                    try:
                        _sample_report_memory(process.pid, tracked)
                    except OSError:
                        pass
                _kill_group(process, tracked)
            if error.exists():
                failure = json.loads(error.read_text(encoding="utf-8"))
                _LOG.warning("Run %s report %s failed: %s", run_id, report_format, failure.get("cause", failure["code"]))
                raise ReportExportError(failure["code"], failure["detail"])
            if process.returncode or not output.exists():
                _LOG.warning("Run %s report %s renderer exited with code %s", run_id, report_format, process.returncode)
                raise ReportExportError("report_failed", "보고서를 생성하지 못했습니다. 서버 자원과 로그를 확인하세요.")
            content_type, extension = REPORT_FORMATS[report_format]
            return output.read_bytes(), content_type, extension
    finally:
        _REPORT_SLOT.release()


def _render(args) -> bytes:
    from .reporting import render_html_pair_zip_from_payload, render_hwpx, render_markdown_from_payload, render_pdf, render_xlsx

    db = sqlite3.connect("file:" + quote(str(Path(args.db).resolve()), safe="/") + "?mode=ro", uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    try:
        row = db.execute("SELECT result_json,snapshot_json,standard,standard_category,status FROM scan_runs WHERE run_id=? AND deleted_at IS NULL", (args.run,)).fetchone()
    finally:
        db.close()
    if row is None or row["status"] != "completed":
        raise ValueError("completed run no longer available")
    result = json.loads(row["result_json"]) if row["result_json"] else {}
    snapshot, scan = json.loads(row["snapshot_json"]), dict(result.get("scan") or {})
    scan.setdefault("scope", snapshot.get("scan_scope") or "all")
    scan.setdefault("standard", row["standard"] or snapshot.get("standard"))
    scan.setdefault("standard_category", row["standard_category"] or snapshot.get("standard_category"))
    result["scan"] = scan
    if args.format.endswith(".html"):
        with zipfile.ZipFile(io.BytesIO(render_html_pair_zip_from_payload(result, args.language))) as archive:
            return archive.read(args.format)
    if args.format == "html":
        return render_html_pair_zip_from_payload(result, args.language)
    if args.format in {"md", "markdown"}:
        return render_markdown_from_payload(result, args.language).encode("utf-8")
    if args.format == "xlsx":
        return render_xlsx(result, args.language)
    if args.format == "hwpx":
        return render_hwpx(result, args.language)
    if args.format == "pdf":
        return render_pdf(result, args.language)
    return (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--format", choices=REPORT_FORMATS, required=True)
    parser.add_argument("--language", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--error", required=True)
    parser.add_argument("--parent", type=int, required=True)
    args = parser.parse_args()
    from .process_limits import bind_parent_lifetime
    bind_parent_lifetime(args.parent)
    temporary = Path(args.output).parent
    tempfile.tempdir = str(temporary)
    os.environ["TMPDIR"] = str(temporary)
    try:
        _apply_report_limits(args.format, int(os.environ.get("KODA_PORTAL_REPORT_MEMORY_BYTES", str(2 * 1024**3))))
        Path(args.output).write_bytes(_render(args))
        return 0
    except Exception as exc:
        from .reporting import PdfExportError
        code = "pdf_unavailable" if isinstance(exc, PdfExportError) else "report_failed"
        detail = str(exc)[:500] if isinstance(exc, PdfExportError) else "보고서를 생성하지 못했습니다. 서버 자원과 로그를 확인하세요."
        Path(args.error).write_text(json.dumps({"code": code, "detail": detail, "cause": type(exc).__name__}), encoding="utf-8")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
