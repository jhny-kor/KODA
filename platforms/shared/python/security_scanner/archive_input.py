from __future__ import annotations

import gzip
import stat
import tarfile
import zipfile
from pathlib import Path
from typing import BinaryIO

from .config import ConfigError


ARCHIVE_SUFFIXES = (
    ".zip",
    ".jar",
    ".war",
    ".ear",
    ".tar",
    ".tgz",
    ".tar.gz",
    ".tbz",
    ".tbz2",
    ".tar.bz2",
    ".txz",
    ".tar.xz",
    ".gz",
)


def looks_like_archive(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)


def prepare_input_target(
    path: Path,
    archive_extract_root: Path | None,
    *,
    max_files: int | None = None,
    max_bytes: int | None = None,
) -> Path:
    if not path.exists() or not path.is_file() or not looks_like_archive(path):
        return path
    if archive_extract_root is None:
        raise ConfigError("Archive input requires a temporary extraction directory")
    if max_files is not None and max_files <= 0:
        raise ConfigError("Archive file limit must be positive")
    if max_bytes is not None and max_bytes <= 0:
        raise ConfigError("Archive extraction limit must be positive")

    target_dir = archive_extract_root / _archive_target_name(path)
    target_dir.mkdir(parents=True, exist_ok=True)
    budget = {"files": 0, "bytes": 0}
    try:
        if path.stat().st_size == 0:
            raise ConfigError(f"Archive input is empty: {path.name}. Check the original file and upload again.")
        if zipfile.is_zipfile(path):
            _extract_zip(path, target_dir, budget, max_files, max_bytes)
            return target_dir
        if tarfile.is_tarfile(path):
            _extract_tar(path, target_dir, budget, max_files, max_bytes)
            return target_dir
        if path.suffix.lower() == ".gz":
            _extract_gzip(path, target_dir, budget, max_files, max_bytes)
            return target_dir
        if path.suffix.lower() in {".zip", ".jar", ".war", ".ear"}:
            raise ConfigError(
                f"Invalid or incomplete ZIP archive: {path.name}. "
                "The ZIP directory could not be read. Check for a damaged or incomplete upload, "
                "split archive parts, or a file whose actual format differs from its extension."
            )
    except ConfigError:
        raise
    except (OSError, tarfile.TarError, zipfile.BadZipFile, EOFError, RuntimeError) as exc:
        raise ConfigError(f"Could not extract archive target {path}: {exc}") from exc

    raise ConfigError(f"Unsupported archive format: {path}")


def _archive_target_name(path: Path) -> str:
    safe_name = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in path.name)
    return f"{safe_name}.extracted"


def _safe_destination(root: Path, member_name: str) -> Path:
    if not member_name or "\0" in member_name:
        raise ConfigError("Archive contains an invalid member name")
    destination = (root / member_name).resolve()
    root_resolved = root.resolve()
    if destination != root_resolved and root_resolved not in destination.parents:
        raise ConfigError(f"Archive contains unsafe path: {member_name}")
    return destination


def _reserve_file(
    member_name: str,
    declared_size: int,
    budget: dict[str, int],
    max_files: int | None,
    max_bytes: int | None,
) -> None:
    if declared_size < 0:
        raise ConfigError(f"Archive member has an invalid size: {member_name}")
    if max_files is not None and budget["files"] + 1 > max_files:
        raise ConfigError(f"Archive contains more than {max_files} files")
    if max_bytes is not None and budget["bytes"] + declared_size > max_bytes:
        raise ConfigError(f"Archive expands beyond {max_bytes} bytes")
    budget["files"] += 1


def _copy_member(source: BinaryIO, destination: Path, budget: dict[str, int], max_bytes: int | None) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as output:
        while chunk := source.read(1024 * 1024):
            if max_bytes is not None and budget["bytes"] + len(chunk) > max_bytes:
                raise ConfigError(f"Archive expands beyond {max_bytes} bytes")
            output.write(chunk)
            budget["bytes"] += len(chunk)


def _extract_zip(
    path: Path,
    target_dir: Path,
    budget: dict[str, int],
    max_files: int | None,
    max_bytes: int | None,
) -> None:
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            destination = _safe_destination(target_dir, member.filename)
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if stat.S_IFMT(member.external_attr >> 16) == stat.S_IFLNK:
                raise ConfigError(f"Archive contains a symbolic link: {member.filename}")
            if member.flag_bits & 1:
                raise ConfigError(
                    f"Encrypted ZIP member requires a password and is not supported: {member.filename}. "
                    "Upload an unencrypted ZIP archive."
                )
            _reserve_file(member.filename, member.file_size, budget, max_files, max_bytes)
            try:
                with archive.open(member) as source:
                    _copy_member(source, destination, budget, max_bytes)
            except NotImplementedError as exc:
                raise ConfigError(
                    f"Unsupported ZIP compression method {member.compress_type}: {member.filename}. "
                    "Recompress using ZIP Deflate or Store."
                ) from exc


def _extract_tar(
    path: Path,
    target_dir: Path,
    budget: dict[str, int],
    max_files: int | None,
    max_bytes: int | None,
) -> None:
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            destination = _safe_destination(target_dir, member.name)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if member.issym() or member.islnk():
                raise ConfigError(f"Archive contains a link: {member.name}")
            if not member.isfile():
                raise ConfigError(f"Archive contains an unsupported member type: {member.name}")
            _reserve_file(member.name, member.size, budget, max_files, max_bytes)
            source = archive.extractfile(member)
            if source is None:
                raise ConfigError(f"Could not read archive member: {member.name}")
            with source:
                _copy_member(source, destination, budget, max_bytes)


def _extract_gzip(
    path: Path,
    target_dir: Path,
    budget: dict[str, int],
    max_files: int | None,
    max_bytes: int | None,
) -> None:
    output_name = path.name[:-3] if path.name.lower().endswith(".gz") else f"{path.name}.out"
    destination = _safe_destination(target_dir, output_name)
    _reserve_file(output_name, 0, budget, max_files, max_bytes)
    with gzip.open(path, "rb") as source:
        _copy_member(source, destination, budget, max_bytes)
