"""Pin the shared, immutable vulnerability release for one scan/thread."""
from __future__ import annotations

import os
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

_release: ContextVar[Path | None] = ContextVar("koda_data_release", default=None)


@contextmanager
def pinned_release():
    root = os.environ.get("KODA_VULN_DATA_ROOT", "").strip()
    release = None
    if root:
        base = Path(root).resolve(strict=True)
        release = (base / "current").resolve(strict=True)
        if not release.is_dir() or not release.is_relative_to(base / "releases"):
            raise ValueError("취약점 데이터 활성 경로가 올바르지 않습니다")
    token = _release.set(release)
    try:
        yield release
    finally:
        _release.reset(token)


def grype_cache_dir() -> Path | None:
    release = _release.get()
    return release / "grype-db" if release else None


def release_metadata() -> dict[str, str]:
    release = _release.get()
    if release is None:
        return {}
    metadata = (release / "metadata.env").read_text(encoding="utf-8")
    if len(metadata) > 65536:
        raise ValueError("취약점 데이터 메타데이터가 너무 큽니다")
    values = dict(line.split("=", 1) for line in metadata.splitlines() if "=" in line and not line.startswith("#"))
    return {"release": release.name, **values}


def vulnerability_paths() -> tuple[Path | None, Path | None]:
    release = _release.get()
    if release:
        values = release_metadata()
        result = []
        for key, default in (("NVD_INDEX", "nvd.json"), ("KEV_CATALOG", "kev.json")):
            path = (release / values.get(key, default)).resolve()
            if not path.is_relative_to(release):
                raise ValueError("취약점 데이터 파일 경로가 올바르지 않습니다")
            result.append(path if path.is_file() else None)
        return tuple(result)
    return tuple(Path(value) if value else None for value in (
        os.environ.get("KODA_NVD_DATA", "/opt/koda/vuln-data/nvd"),
        os.environ.get("KODA_CISA_KEV", "/opt/koda/vuln-data/known_exploited_vulnerabilities.json"),
    ))
