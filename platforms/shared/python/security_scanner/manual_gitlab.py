"""File selection for manual GitLab scans; scheduled scans keep their own policy."""
from __future__ import annotations

import hashlib
from pathlib import Path

from .ignore import IGNORE_FILENAMES
from .models import ScannerConfig, TargetConfig
from .scanner import SecurityScanner
from .schedule_transport import RemoteFile
from .schedule_worker import ScheduleRunner


def scanner_fingerprint() -> str:
    # Also works in offline source installs whose advertised version is development.
    root = Path(__file__).parent
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.py")):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    resources = root / "resources" / "sw49"
    for path in sorted(resources.glob("*.json")):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def repository_inventory(root: Path) -> tuple[dict[str, str], dict[str, Path]]:
    target = TargetConfig(name=root.name, path=root)
    scanner = SecurityScanner(ScannerConfig(targets=(target,)))
    paths = {path.relative_to(root).as_posix(): path for path in scanner._iter_files(target)}
    if scanner.warnings:
        raise OSError("GitLab 저장소 파일 목록을 완전히 읽지 못했습니다: " + "; ".join(scanner.warnings))
    manifest = {}
    for name, path in sorted(paths.items()):
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        manifest[name] = digest.hexdigest()
    return manifest, paths


def select_manual_files(root: Path, run: dict, baseline: dict | None):
    snapshot = run["snapshot"]
    manifest, paths = repository_inventory(root)
    fingerprint = scanner_fingerprint()
    previous = baseline["snapshot"] if baseline else {}
    previous_scope = previous.get("file_scope") or {}
    settings = ("standard", "standard_category", "scan_scope", "rule_policy_hash", "rule_policy_version", "scanner_version")
    requested = snapshot.get("requested_scan_mode", "full")
    effective, reason = "full", "configured_full"
    old_manifest = baseline["manifest"] if baseline else {}
    compatible = bool(baseline) and all(snapshot.get(key) == previous.get(key) for key in settings)
    compatible = compatible and previous_scope.get("scanner_fingerprint") == fingerprint
    full_snapshot = (baseline or {}).get("full_scan_snapshot", previous if previous_scope.get("effective_mode") == "full" else {})
    compatible = compatible and all(snapshot.get(key) == full_snapshot.get(key) for key in settings)
    compatible = compatible and (full_snapshot.get("file_scope") or {}).get("scanner_fingerprint") == fingerprint
    if requested == "changed":
        if not baseline:
            reason = "no_baseline"
        elif not compatible:
            reason = "settings_changed"
        else:
            effective, reason = "changed", "changed_files"
    new = sorted(set(manifest) - set(old_manifest))
    changed = sorted(name for name in manifest.keys() & old_manifest.keys() if manifest[name] != old_manifest[name])
    deleted = sorted(set(old_manifest) - set(manifest))
    # Repository ignore rules affect otherwise unchanged files, so re-evaluate all.
    if effective == "changed" and any(Path(name).name in IGNORE_FILENAMES for name in new + changed + deleted):
        effective, reason = "full", "settings_changed"
    selected = set(paths) if effective == "full" else set(new + changed)
    context = set()
    if effective == "changed" and snapshot.get("scan_scope") in {"all", "library"}:
        context = {name for name, path in paths.items()
                   if name not in selected and ScheduleRunner._dependency_manifest(RemoteFile(name, path.stat().st_size, 0))}
        selected.update(context)
    if effective == "changed" and not new and not changed:
        reason = "unchanged"
    whole_context = effective == "changed" and bool(selected) and snapshot.get("standard") == "sw-dev-security-49"
    scope = {
        "requested_mode": requested, "effective_mode": effective, "reason": reason,
        "baseline_run_id": baseline["run_id"] if baseline else None,
        "full_scan_run_id": baseline.get("full_scan_run_id", baseline["run_id"]) if baseline else None,
        "baseline_commit": previous.get("gitlab_commit_sha"),
        "current_commit": snapshot.get("gitlab_commit_sha"),
        "files_total": len(paths), "scanned_files": len(selected),
        "new_files": len(new), "changed_files": len(changed), "deleted_files": len(deleted),
        "dependency_context_files": len(context), "context_files": len(paths) if whole_context else len(selected),
        "context_note": "전체 프로젝트 문맥을 분석하고 신규·변경 파일 관련 결과만 표시합니다." if whole_context else "",
        "selected_paths": sorted(selected), "deleted_paths": deleted,
        "scanner_fingerprint": fingerprint,
    }
    selection = tuple(paths[name] for name in sorted(selected)) if effective == "changed" else None
    return manifest, selection, scope
