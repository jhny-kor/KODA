"""Pin the approved shared vulnerability release; managed installs never fall back."""
from __future__ import annotations

import json
import os
import sys
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from functools import wraps

_release: ContextVar[Path | None] = ContextVar("koda_data_release", default=None)
_pinned: ContextVar[bool] = ContextVar("koda_data_pinned", default=False)
_status: ContextVar[str] = ContextVar("koda_data_status", default="")
DEFAULT_ROOT = Path("/var/lib/koda-vuln-data")


def managed_root() -> Path:
    return Path(os.environ.get("KODA_VULN_DATA_ROOT", "").strip() or DEFAULT_ROOT)


def managed_data_required() -> bool:
    # A configured shared root or persistent marker cannot be disabled by a flag.
    return bool(sys.platform.startswith("linux") or
                os.environ.get("KODA_VULN_DATA_ROOT", "").strip() or
                (managed_root() / ".managed.json").exists() or
                (managed_root() / ".managed.json").is_symlink() or
                os.environ.get("KODA_REQUIRE_MANAGED_DATA", "").lower() in {"1", "true", "yes"})


@contextmanager
def pinned_release():
    if _pinned.get():
        yield _release.get()
        return
    release = None
    reason = ""
    lease = None
    if managed_data_required():
        try:
            base = managed_root().resolve(strict=True)
            lock = base / ".release.lock"
            if lock.exists():
                if lock.is_symlink():
                    raise ValueError("unsafe vulnerability data lock")
                import fcntl
                lease = lock.open("rb")  # shared volume is mounted read-only
                fcntl.flock(lease.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
            marker = base / ".managed.json"
            state = None
            if not marker.is_file() or lease is None:
                raise ValueError("approved managed marker/read lease is missing")
            if marker.exists():
                if marker.is_symlink() or marker.stat().st_size > 65536 or lease is None:
                    raise ValueError("invalid managed data marker or missing read lease")
                state = json.loads(marker.read_text(encoding="utf-8"))
                if state.get("format") != "koda-managed-vulnerability-data-v1" or state.get("state") != "active":
                    raise ValueError("approved vulnerability data is not active")
            release = (base / "current").resolve(strict=True)
            if not release.is_dir() or not release.is_relative_to(base / "releases"):
                raise ValueError("invalid approved vulnerability data path")
            if state and state.get("currentVersion") != release.name:
                raise ValueError("approved data marker differs from current release")
            from .approved_release import verify_approved_release
            verify_approved_release(release)
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            release = None
            reason = f"승인 취약점 데이터 사용 불가: {exc}; 내장·캐시 데이터로 대체하지 않습니다."
            if lease is not None:
                lease.close()
                lease = None
    tokens = (_release.set(release), _pinned.set(True), _status.set(reason))
    try:
        yield release
    finally:
        _release.reset(tokens[0]); _pinned.reset(tokens[1]); _status.reset(tokens[2])
        if lease is not None:
            lease.close()


def data_unavailable_reason() -> str:
    if _pinned.get():
        return _status.get()
    with pinned_release():
        return _status.get()


def grype_cache_dir() -> Path | None:
    if not _pinned.get() and managed_data_required():
        with pinned_release():
            return grype_cache_dir()
    release = _release.get()
    if release is None:
        return None
    path = (release / "grype-db").resolve()
    return path if path.is_relative_to(release) else None


def release_metadata() -> dict[str, str]:
    if not _pinned.get() and managed_data_required():
        with pinned_release():
            return release_metadata()
    release = _release.get()
    if release is None:
        return {"status": "unavailable", "warning": _status.get()} if managed_data_required() else {}
    metadata = (release / "metadata.env").read_text(encoding="utf-8")
    if len(metadata) > 65536:
        raise ValueError("취약점 데이터 메타데이터가 너무 큽니다")
    values = dict(line.split("=", 1) for line in metadata.splitlines() if "=" in line and not line.startswith("#"))
    return {"release": release.name, **values}


def _path(key: str) -> Path | None:
    if not _pinned.get() and managed_data_required():
        with pinned_release():
            return _path(key)
    release = _release.get()
    if release is None:
        return None
    relative = release_metadata().get(key)
    if not relative:
        return None
    path = (release / relative).resolve()
    if not path.is_relative_to(release):
        raise ValueError("취약점 데이터 파일 경로가 올바르지 않습니다")
    return path if path.is_file() else None


def vulnerability_paths() -> tuple[Path | None, Path | None]:
    if managed_data_required():
        return _path("NVD_INDEX"), _path("KEV_CATALOG")
    return tuple(Path(value) if value else None for value in (
        os.environ.get("KODA_NVD_DATA", "/opt/koda/vuln-data/nvd"),
        os.environ.get("KODA_CISA_KEV", "/opt/koda/vuln-data/known_exploited_vulnerabilities.json")))


def epss_path() -> Path | None:
    if managed_data_required():
        return _path("EPSS_SNAPSHOT")
    value = os.environ.get("KODA_EPSS_DATA", "").strip()
    path = Path(value or "/opt/koda/vuln-data/epss.csv.gz")
    return path if value or path.is_file() else None


def intelligence_path() -> Path | None:
    if managed_data_required():
        return _path("INTELLIGENCE_INDEX")
    value = os.environ.get("KODA_INTELLIGENCE_DATA", "").strip()
    path = Path(value or "/opt/koda/vuln-data/intelligence.json")
    return path if value or path.is_file() else None


def approved_data_read(function):
    """Hold the shared release lease for the complete local read operation."""
    @wraps(function)
    def invoke(*args, **kwargs):
        with pinned_release():
            return function(*args, **kwargs)
    return invoke
