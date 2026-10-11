from __future__ import annotations

import fnmatch
import hashlib
import stat
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path, PurePosixPath


ARCHIVE_SUFFIXES = (".jar", ".war", ".ear")
MAX_COMPRESSION_RATIO = 1_000
DEFAULT_MAX_DEPTH = 8
DEFAULT_MAX_ENTRIES = 10_000
DEFAULT_MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_SINGLE_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_RETAINED_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_CENTRAL_DIRECTORY_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ArchiveLocation:
    outer_path: Path
    nested_path: str = ""

    def display(self) -> str:
        return str(self.outer_path) if not self.nested_path else f"{self.outer_path}!/{self.nested_path}"


@dataclass(frozen=True, slots=True)
class ArchiveArtifact:
    location: ArchiveLocation
    filename: str
    archive_type: str
    sha256: str
    size: int
    modified_at: str
    payload: bytes


@dataclass(frozen=True, slots=True)
class ArchiveScan:
    artifacts: tuple[ArchiveArtifact, ...]
    warnings: tuple[str, ...]
    entries_scanned: int = 0
    expanded_bytes: int = 0
    retained_bytes: int = 0
    outer_archives: int = 0
    limit_exceeded: bool = False

    def __iter__(self):
        return iter(self.artifacts)


@dataclass(slots=True)
class _ArchiveBudget:
    max_entries: int
    max_expanded_bytes: int
    max_retained_bytes: int
    entries: int = 0
    expanded_bytes: int = 0
    retained_bytes: int = 0
    outer_archives: int = 0

    def can_retain(self, size: int) -> bool:
        return 0 <= size <= self.max_retained_bytes - self.retained_bytes

    def can_expand(self, size: int) -> bool:
        return self.can_retain(size) and 0 <= size <= self.max_expanded_bytes - self.expanded_bytes


def scan_archives(
    target: Path,
    *,
    excludes: tuple[str, ...] = (),
    max_depth: int | None = None,
    max_entries: int | None = None,
    max_uncompressed_bytes: int | None = None,
    max_retained_bytes: int | None = None,
    _seen_outer_paths: set[Path] | None = None,
    _max_outer_archives: int = DEFAULT_MAX_ENTRIES,
) -> ArchiveScan:
    root = target.expanduser().resolve()
    if not root.is_dir() and not root.is_file():
        raise ValueError(f"Java scan target does not exist: {target}")
    if any(limit is not None and limit < 1 for limit in (max_depth, max_entries, max_uncompressed_bytes, max_retained_bytes)):
        raise ValueError("archive limits must be positive")
    max_depth = max_depth if max_depth is not None else DEFAULT_MAX_DEPTH
    budget = _ArchiveBudget(
        max_entries=max_entries if max_entries is not None else DEFAULT_MAX_ENTRIES,
        max_expanded_bytes=max_uncompressed_bytes if max_uncompressed_bytes is not None else DEFAULT_MAX_UNCOMPRESSED_BYTES,
        max_retained_bytes=min(max_retained_bytes or MAX_RETAINED_ARCHIVE_BYTES, MAX_RETAINED_ARCHIVE_BYTES),
    )

    artifacts: list[ArchiveArtifact] = []
    warnings: list[str] = []
    paths = (root,) if root.is_file() else root.rglob("*")
    seen_outer_paths = _seen_outer_paths if _seen_outer_paths is not None else set()
    limit_exceeded = False
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.suffix.lower() not in ARCHIVE_SUFFIXES:
            continue
        relative = path.name if root.is_file() else path.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.name, pattern) for pattern in excludes):
            continue
        canonical = path.resolve()
        if canonical in seen_outer_paths:
            continue
        seen_outer_paths.add(canonical)
        if budget.outer_archives >= _max_outer_archives:
            warnings.append("Archive file count limit exceeded; remaining archives skipped")
            limit_exceeded = True
            break
        budget.outer_archives += 1
        try:
            remaining = min(MAX_SINGLE_ARCHIVE_BYTES, budget.max_retained_bytes - budget.retained_bytes)
            with path.open("rb") as source:
                payload = source.read(remaining + 1)
            if len(payload) > remaining:
                warnings.append(f"Archive byte limit exceeded: {path}")
                limit_exceeded = True
                continue
            modified_at = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
        except OSError as exc:
            warnings.append(f"Could not read archive {path}: {exc}")
            continue
        budget.retained_bytes += len(payload)
        _walk_archive(
            ArchiveArtifact(
                location=ArchiveLocation(path),
                filename=path.name,
                archive_type=path.suffix.lower().lstrip("."),
                sha256=_sha256(payload),
                size=len(payload),
                modified_at=modified_at,
                payload=payload,
            ),
            max_depth=max_depth,
            budget=budget,
            artifacts=artifacts,
            warnings=warnings,
        )
    return ArchiveScan(tuple(artifacts), tuple(warnings), budget.entries, budget.expanded_bytes,
                       budget.retained_bytes, budget.outer_archives,
                       limit_exceeded or any("limit exceeded" in warning or "Maximum nested archive depth reached" in warning
                                             or "Suspicious ZIP compression ratio" in warning for warning in warnings))


def scan_archive_targets(
    targets: tuple[Path, ...], *, excludes: tuple[str, ...] = (), max_depth: int | None = None
) -> ArchiveScan:
    """Apply one resource budget to all targets in a Java scan or verification."""
    artifacts: list[ArchiveArtifact] = []
    warnings: list[str] = []
    seen: set[tuple[str, str]] = set()
    entries = expanded = retained = outer_count = 0
    seen_outer_paths: set[Path] = set()
    limit_exceeded = False
    for target in targets:
        if (outer_count >= DEFAULT_MAX_ENTRIES or entries >= DEFAULT_MAX_ENTRIES or expanded >= DEFAULT_MAX_UNCOMPRESSED_BYTES
                or retained >= MAX_RETAINED_ARCHIVE_BYTES):
            warnings.append("Aggregate archive byte or entry limit exceeded; remaining targets skipped")
            limit_exceeded = True
            break
        scan = scan_archives(
            target,
            excludes=excludes,
            max_depth=max_depth,
            max_entries=DEFAULT_MAX_ENTRIES - entries,
            max_uncompressed_bytes=DEFAULT_MAX_UNCOMPRESSED_BYTES - expanded,
            max_retained_bytes=MAX_RETAINED_ARCHIVE_BYTES - retained,
            _seen_outer_paths=seen_outer_paths,
            _max_outer_archives=DEFAULT_MAX_ENTRIES - outer_count,
        )
        entries += scan.entries_scanned
        expanded += scan.expanded_bytes
        retained += scan.retained_bytes
        outer_count += scan.outer_archives
        limit_exceeded = limit_exceeded or scan.limit_exceeded
        warnings.extend(scan.warnings)
        for artifact in scan.artifacts:
            key = (artifact.location.display(), artifact.sha256)
            if key not in seen:
                seen.add(key)
                artifacts.append(artifact)
    return ArchiveScan(tuple(artifacts), tuple(dict.fromkeys(warnings)), entries, expanded,
                       retained, outer_count, limit_exceeded)


def _walk_archive(
    artifact: ArchiveArtifact,
    *,
    max_depth: int | None,
    budget: _ArchiveBudget,
    artifacts: list[ArchiveArtifact],
    warnings: list[str],
) -> None:
    artifacts.append(artifact)
    if artifact.archive_type not in {"jar", "war", "ear"}:
        return
    if not _bounded_zip_directory(artifact.payload, budget.max_entries - budget.entries):
        warnings.append(f"Archive central-directory limit exceeded: {artifact.location.display()}")
        return
    try:
        with zipfile.ZipFile(BytesIO(artifact.payload)) as archive:
            members = archive.infolist()
            if len(members) > budget.max_entries - budget.entries:
                warnings.append(f"Archive entry limit exceeded: {artifact.location.display()}")
                return
            budget.entries += len(members)
            for member in members:
                if _unsafe_member(member):
                    warnings.append(f"unsafe ZIP path skipped: {artifact.location.display()}!/{member.filename}")
                    continue
                if member.is_dir() or _is_zip_symlink(member):
                    if _is_zip_symlink(member):
                        warnings.append(f"ZIP symlink skipped: {artifact.location.display()}!/{member.filename}")
                    continue
                if not _is_java_archive_name(member.filename):
                    continue
                depth = artifact.location.nested_path.count("!/") + (2 if artifact.location.nested_path else 1)
                if max_depth is not None and depth > max_depth:
                    warnings.append(f"Maximum nested archive depth reached: {artifact.location.display()}!/{member.filename}")
                    continue
                if member.flag_bits & 0x1:
                    warnings.append(f"Encrypted ZIP entry skipped: {artifact.location.display()}!/{member.filename}")
                    continue
                if (not member.compress_size and member.file_size) or (
                    member.compress_size and member.file_size / member.compress_size > MAX_COMPRESSION_RATIO
                ):
                    warnings.append(f"Suspicious ZIP compression ratio: {artifact.location.display()}!/{member.filename}")
                    continue
                if not budget.can_expand(member.file_size):
                    warnings.append(f"Archive byte limit exceeded: {artifact.location.display()}!/{member.filename}")
                    continue
                try:
                    with archive.open(member) as source:
                        payload = source.read(member.file_size + 1)
                except (OSError, RuntimeError, ValueError, EOFError, zipfile.BadZipFile, zlib.error) as exc:
                    warnings.append(f"Could not read nested archive {artifact.location.display()}!/{member.filename}: {exc}")
                    continue
                if len(payload) != member.file_size or not budget.can_expand(len(payload)):
                    warnings.append(f"Archive byte limit exceeded: {artifact.location.display()}!/{member.filename}")
                    continue
                budget.expanded_bytes += len(payload)
                budget.retained_bytes += len(payload)
                nested_location = ArchiveLocation(
                    artifact.location.outer_path,
                    f"{artifact.location.nested_path}!/{member.filename}".lstrip("!/"),
                )
                nested = ArchiveArtifact(
                    location=nested_location,
                    filename=Path(member.filename).name,
                    archive_type=Path(member.filename).suffix.lower().lstrip("."),
                    sha256=_sha256(payload),
                    size=len(payload),
                    modified_at=artifact.modified_at,
                    payload=payload,
                )
                _walk_archive(
                    nested,
                    max_depth=max_depth,
                    budget=budget,
                    artifacts=artifacts,
                    warnings=warnings,
                )
    except (OSError, ValueError, zipfile.BadZipFile, EOFError) as exc:
        warnings.append(f"Corrupt ZIP skipped: {artifact.location.display()}: {exc}")


def _bounded_zip_directory(payload: bytes, remaining_entries: int) -> bool:
    # ZipFile materializes the whole central directory before callers can inspect
    # infolist(), so reject oversized metadata before constructing ZipFile.
    tail = payload[-(65_535 + 22):]
    marker = tail.rfind(b"PK\x05\x06")
    if marker < 0 or len(tail) - marker < 22:
        return True  # ZipFile will report a corrupt archive.
    entries = int.from_bytes(tail[marker + 10:marker + 12], "little")
    directory_bytes = int.from_bytes(tail[marker + 12:marker + 16], "little")
    return (entries != 0xFFFF and directory_bytes != 0xFFFF_FFFF
            and entries <= remaining_entries and directory_bytes <= MAX_CENTRAL_DIRECTORY_BYTES)


def _is_java_archive_name(name: str) -> bool:
    return Path(name).suffix.lower() in ARCHIVE_SUFFIXES


def _unsafe_member(member: zipfile.ZipInfo) -> bool:
    path = PurePosixPath(member.filename)
    return path.is_absolute() or ".." in path.parts or "\x00" in member.filename


def _is_zip_symlink(member: zipfile.ZipInfo) -> bool:
    mode = (member.external_attr >> 16) & 0xFFFF
    return stat.S_IFMT(mode) == stat.S_IFLNK


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
