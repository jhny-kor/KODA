from __future__ import annotations

import gzip
import io
import lzma
import os
import stat
import struct
import tarfile
import zipfile
from pathlib import Path
from types import MethodType
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

MAX_ARCHIVE_MEMBERS = 400_000
MAX_ARCHIVE_BYTES = 4 * 1024**3
MAX_ZIP_DIRECTORY_BYTES = 128 * 1024**2
MAX_TAR_METADATA_BYTES = 64 * 1024**2
MAX_TAR_METADATA_RECORD_BYTES = 64 * 1024
MAX_TAR_GLOBAL_METADATA_BYTES = 16 * 1024
MAX_TAR_GLOBAL_KEYS = 64
MAX_TAR_METADATA_NESTING = 16
DECODER_MEMORY_LIMIT = 64 * 1024**2
DECODE_CHUNK_BYTES = 1024 * 1024
_ZSTD_METHOD = getattr(zipfile, "ZIP_ZSTANDARD", None)
_ZSTD = getattr(zipfile, "zstd", None)
_DECOMPRESSION_ERRORS = (lzma.LZMAError,) + ((_ZSTD.ZstdError,) if _ZSTD is not None else ())
_DecompressReader = (lzma._streams if hasattr(lzma, "_streams") else lzma._compression).DecompressReader
# A tool may omit directory records and list only files in nested paths.
IMPLICIT_DIRECTORY_ALLOWANCE = 1024


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
    max_members = min(max_files, MAX_ARCHIVE_MEMBERS) if max_files is not None else MAX_ARCHIVE_MEMBERS
    max_nodes = max_members + IMPLICIT_DIRECTORY_ALLOWANCE
    budget = {"bytes": 0, "nodes": 0}
    try:
        if path.stat().st_size == 0:
            raise ConfigError(f"Archive input is empty: {path.name}. Check the original file and upload again.")
        with path.open("rb") as source:
            if validate_zip_directory(source, max_members=max_members):
                _extract_zip(source, target_dir, budget, max_nodes, max_bytes)
                return target_dir
        try:
            archive = open_bounded_tar(path, max_members=max_members, max_bytes=max_bytes)
        except tarfile.ReadError:
            archive = None
        if archive is not None:
            with archive:
                _extract_tar(archive, target_dir, budget, max_nodes, max_bytes)
            return target_dir
        if path.suffix.lower() == ".gz":
            _extract_gzip(path, target_dir, budget, max_nodes, max_bytes)
            return target_dir
        if path.suffix.lower() in {".zip", ".jar", ".war", ".ear"}:
            raise ConfigError(
                f"Invalid or incomplete ZIP archive: {path.name}. "
                "The ZIP directory could not be read. Check for a damaged or incomplete upload, "
                "split archive parts, or a file whose actual format differs from its extension."
            )
    except ConfigError:
        raise
    except (OSError, tarfile.TarError, zipfile.BadZipFile, EOFError, RuntimeError) + _DECOMPRESSION_ERRORS as exc:
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


def _check_member_size(
    member_name: str,
    declared_size: int,
    budget: dict[str, int],
    max_bytes: int | None,
) -> None:
    if declared_size < 0:
        raise ConfigError(f"Archive member has an invalid size: {member_name}")
    if max_bytes is not None and budget["bytes"] + declared_size > max_bytes:
        raise ConfigError(f"Archive expands beyond {max_bytes} bytes")


def _reserve_nodes(root: Path, destination: Path, budget: dict[str, int], max_nodes: int) -> None:
    """Charge new output files and both explicit and implicit directories."""
    while destination != root and not destination.exists():
        budget["nodes"] += 1
        if budget["nodes"] > max_nodes:
            raise ConfigError(f"Archive extraction requires more than {max_nodes} filesystem entries")
        destination = destination.parent


def _copy_member(source: BinaryIO, destination: Path, budget: dict[str, int], max_bytes: int | None) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as output:
        while chunk := source.read(DECODE_CHUNK_BYTES):
            if max_bytes is not None and budget["bytes"] + len(chunk) > max_bytes:
                raise ConfigError(f"Archive expands beyond {max_bytes} bytes")
            output.write(chunk)
            budget["bytes"] += len(chunk)


def validate_zip_directory(
    source: BinaryIO,
    *,
    max_members: int,
    max_metadata_bytes: int = MAX_ZIP_DIRECTORY_BYTES,
) -> bool:
    """Bound the bytes and actual record count before ZipFile materializes them."""
    # Match the standard library's EOCD/ZIP64 recognition on the same stream.
    end = zipfile._EndRecData(source)
    if end is None:
        return False
    size = end[zipfile._ECD_SIZE]
    if size > max_metadata_bytes:
        raise ConfigError(f"ZIP central directory exceeds {max_metadata_bytes} bytes")
    if end[zipfile._ECD_ENTRIES_TOTAL] > max_members:
        raise ConfigError(f"Archive contains more than {max_members} files or directory entries")
    directory_end = end[zipfile._ECD_LOCATION]
    if end[zipfile._ECD_SIGNATURE] == zipfile.stringEndArchive64:
        # Older supported CPython versions leave the original EOCD position in
        # _EndRecData64, while newer ones report the ZIP64 record position.
        source.seek(directory_end)
        if source.read(4) == zipfile.stringEndArchive:
            directory_end -= zipfile.sizeEndCentDir64 + zipfile.sizeEndCentDir64Locator
    start = directory_end - size
    if start < 0:
        raise zipfile.BadZipFile("Bad offset for central directory")

    source.seek(start)
    count = 0
    remaining = size
    while remaining:
        header = source.read(zipfile.sizeCentralDir)
        if len(header) != zipfile.sizeCentralDir or not header.startswith(zipfile.stringCentralDir):
            raise zipfile.BadZipFile("Invalid central directory header")
        fields = struct.unpack(zipfile.structCentralDir, header)
        variable_bytes = fields[zipfile._CD_FILENAME_LENGTH] + fields[zipfile._CD_EXTRA_FIELD_LENGTH] + fields[zipfile._CD_COMMENT_LENGTH]
        remaining -= zipfile.sizeCentralDir + variable_bytes
        if remaining < 0:
            raise zipfile.BadZipFile("Truncated central directory")
        count += 1
        if count > max_members:
            raise ConfigError(f"Archive contains more than {max_members} files or directory entries")
        source.seek(variable_bytes, os.SEEK_CUR)
    if count != end[zipfile._ECD_ENTRIES_TOTAL]:
        raise zipfile.BadZipFile("Inconsistent central directory entry count")
    return True


class _LimitedZipLzma:
    def __init__(self):
        self._decoder = None
        self._header = bytearray()

    @property
    def needs_input(self) -> bool:
        return self._decoder is None or self._decoder.needs_input

    @property
    def eof(self) -> bool:
        return self._decoder is not None and self._decoder.eof

    def decompress(self, data: bytes, max_length: int) -> bytes:
        if self._decoder is None:
            taken = min(len(data), 9 - len(self._header))
            self._header.extend(data[:taken])
            if len(self._header) < 9:
                return b""
            if self._header[2:4] != b"\x05\x00":
                raise zipfile.BadZipFile("Invalid ZIP LZMA codec header")
            filters = lzma._decode_filter_properties(lzma.FILTER_LZMA1, bytes(self._header[4:]))
            if filters["dict_size"] > DECODER_MEMORY_LIMIT:
                raise ConfigError("ZIP LZMA dictionary exceeds the decoder memory limit")
            self._decoder = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[filters])
            data = data[taken:]
        return self._decoder.decompress(data, max_length)


def _bounded_zip_read1(member, size: int) -> bytes:
    if member._eof or size <= 0:
        return b""
    # ZipExtFile can replace the decompressor on a backward seek. Apply the
    # decoder policy before the first input reaches any new instance.
    decoder = member._decompressor
    if member._compress_type == zipfile.ZIP_LZMA and not isinstance(decoder, _LimitedZipLzma):
        decoder = member._decompressor = _LimitedZipLzma()
    if member._compress_type == _ZSTD_METHOD and decoder is not member._bounded_zstd:
        decoder = member._decompressor = member._bounded_zstd = _ZSTD.ZstdDecompressor(
            options={_ZSTD.DecompressionParameter.window_log_max: DECODER_MEMORY_LIMIT.bit_length() - 1}
        )
    size = min(size, DECODE_CHUNK_BYTES, member._left)
    try:
        data = member._read2(size) if decoder.needs_input else b""
        data = decoder.decompress(data, size)
    except (OSError,) + _DECOMPRESSION_ERRORS as exc:
        raise zipfile.BadZipFile(f"Could not decode ZIP member: {exc}") from exc
    member._left -= len(data)
    member._eof = member._left <= 0 or decoder.eof or (member._compress_left <= 0 and decoder.needs_input)
    if member._eof and member._left:
        raise zipfile.BadZipFile("Truncated compressed ZIP member")
    member._update_crc(data)
    return data


class BoundedZipFile(zipfile.ZipFile):
    """ZipFile with output and decoder-memory bounds for optional codecs."""

    def open(self, name, mode="r", pwd=None, *, force_zip64=False):
        member = super().open(name, mode, pwd, force_zip64=force_zip64)
        # CPython limits DEFLATE output directly but does not pass max_length
        # to the other decompressors. Bind the limit to this member only.
        if mode == "r" and member._compress_type in (zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA, _ZSTD_METHOD):
            member._bounded_zstd = None
            member._read1 = MethodType(_bounded_zip_read1, member)
        return member


def _extract_zip(
    source: BinaryIO,
    target_dir: Path,
    budget: dict[str, int],
    max_nodes: int,
    max_bytes: int | None,
) -> None:
    with BoundedZipFile(source) as archive:
        for member in archive.infolist():
            destination = _safe_destination(target_dir, member.filename)
            if stat.S_IFMT(member.external_attr >> 16) == stat.S_IFLNK:
                raise ConfigError(f"Archive contains a symbolic link: {member.filename}")
            _reserve_nodes(target_dir, destination, budget, max_nodes)
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if member.flag_bits & 1:
                raise ConfigError(
                    f"Encrypted ZIP member requires a password and is not supported: {member.filename}. "
                    "Upload an unencrypted ZIP archive."
                )
            _check_member_size(member.filename, member.file_size, budget, max_bytes)
            try:
                with archive.open(member) as source:
                    _copy_member(source, destination, budget, max_bytes)
            except NotImplementedError as exc:
                raise ConfigError(
                    f"Unsupported ZIP compression method {member.compress_type}: {member.filename}. "
                    "Recompress using ZIP Deflate or Store."
                ) from exc


class _BoundedTarInfo(tarfile.TarInfo):
    def _proc_member(self, archive):
        # tarfile reads PAX/GNU extension payloads and follows their next
        # headers before returning a member to the archive iterator.
        if len(archive.pax_headers) > MAX_TAR_GLOBAL_KEYS:
            raise ConfigError("TAR global metadata contains too many fields")
        if self.type not in (
            tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK,
            tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
        ):
            return super()._proc_member(archive)
        if not 0 <= self.size <= MAX_TAR_METADATA_RECORD_BYTES:
            raise ConfigError("TAR metadata record exceeds its size limit")
        size = self._block(self.size)
        archive.metadata_bytes += size + tarfile.BLOCKSIZE
        archive.metadata_records += 1
        if (archive.metadata_bytes > MAX_TAR_METADATA_BYTES
                or archive.metadata_records > archive.max_members + MAX_TAR_METADATA_NESTING):
            raise ConfigError("TAR metadata exceeds its archive limit")
        if self.type == tarfile.XGLTYPE:
            archive.global_metadata_bytes += size
            if archive.global_metadata_bytes > MAX_TAR_GLOBAL_METADATA_BYTES:
                raise ConfigError("TAR global metadata exceeds its size limit")
        archive.metadata_depth += 1
        try:
            if archive.metadata_depth > MAX_TAR_METADATA_NESTING:
                raise ConfigError("TAR metadata headers are nested too deeply")
            return super()._proc_member(archive)
        finally:
            archive.metadata_depth -= 1

    def _reject_sparse(self, *args):
        raise ConfigError("Sparse TAR members are not supported")

    # Sparse maps are parsed by tarfile before a caller can check member.size.
    _proc_sparse = _reject_sparse
    _proc_gnusparse_00 = _reject_sparse
    _proc_gnusparse_01 = _reject_sparse
    _proc_gnusparse_10 = _reject_sparse


class _LimitedXzStream(_DecompressReader):
    def __init__(self, filename, source=None):
        self._owned_source = None
        if source is None:
            source = self._owned_source = open(filename, "rb")
        super().__init__(
            source, lzma.LZMADecompressor,
            format=lzma.FORMAT_AUTO, memlimit=DECODER_MEMORY_LIMIT,
        )

    def close(self):
        try:
            super().close()
        finally:
            if self._owned_source is not None:
                self._owned_source.close()

    def read(self, size=-1):
        try:
            return super().read(size)
        except lzma.LZMAError as exc:
            if "Memory usage limit exceeded" in str(exc):
                raise ConfigError("TAR XZ decoder memory limit exceeded") from exc
            raise


class _BoundedTarFile(tarfile.TarFile):
    def __init__(self, *args, max_members: int, max_bytes: int | None, **kwargs):
        self.max_members = max_members
        self.max_bytes = max_bytes
        self.member_count = 0
        self.declared_bytes = 0
        self.metadata_bytes = 0
        self.metadata_records = 0
        self.global_metadata_bytes = 0
        self.metadata_depth = 0
        super().__init__(*args, tarinfo=_BoundedTarInfo, **kwargs)

    @classmethod
    def xzopen(cls, name, mode="r", fileobj=None, **kwargs):
        source = io.BufferedReader(_LimitedXzStream(name, fileobj))
        try:
            archive = cls.taropen(name, mode, source, **kwargs)
        except (lzma.LZMAError, EOFError) as exc:
            source.close()
            raise tarfile.ReadError("not an XZ archive") from exc
        except BaseException:
            source.close()
            raise
        archive._extfileobj = False
        return archive

    @classmethod
    def zstopen(cls, name, mode="r", fileobj=None, **kwargs):
        return super().zstopen(
            name, mode, fileobj,
            options={_ZSTD.DecompressionParameter.window_log_max: DECODER_MEMORY_LIMIT.bit_length() - 1},
            **kwargs,
        )

    def next(self):
        cached = self.firstmember is not None
        member = super().next()
        # CPython before 3.13 has no streaming flag to disable this list.
        self.members.clear()
        if member is None or cached:
            return member
        self.member_count += 1
        if self.member_count > self.max_members:
            raise ConfigError(f"Archive contains more than {self.max_members} files or directory entries")
        if member.size < 0:
            raise ConfigError("TAR member has an invalid size")
        self.declared_bytes += member.size
        if self.max_bytes is not None and self.declared_bytes > self.max_bytes:
            raise ConfigError(f"Archive expands beyond {self.max_bytes} bytes")
        return member


def open_bounded_tar(
    path: Path,
    *,
    mode: str = "r:*",
    max_members: int = MAX_ARCHIVE_MEMBERS,
    max_bytes: int | None = MAX_ARCHIVE_BYTES,
) -> tarfile.TarFile:
    """Open for forward iteration and extractfile(member); do not use name lookups."""
    if max_members < 1 or (max_bytes is not None and max_bytes < 1):
        raise ConfigError("TAR limits must be positive")
    if mode not in {"r", "r:*", "r:", "r:gz", "r:bz2", "r:xz", "r:zst"}:
        raise ConfigError("TAR mode must use a bounded read decoder")
    return _BoundedTarFile.open(path, mode, max_members=min(max_members, MAX_ARCHIVE_MEMBERS), max_bytes=max_bytes)


def _extract_tar(
    archive: tarfile.TarFile,
    target_dir: Path,
    budget: dict[str, int],
    max_nodes: int,
    max_bytes: int | None,
) -> None:
    for member in archive:
        destination = _safe_destination(target_dir, member.name)
        if member.issym() or member.islnk():
            raise ConfigError(f"Archive contains a link: {member.name}")
        _reserve_nodes(target_dir, destination, budget, max_nodes)
        if member.isdir():
            destination.mkdir(parents=True, exist_ok=True)
            continue
        if not member.isfile():
            raise ConfigError(f"Archive contains an unsupported member type: {member.name}")
        _check_member_size(member.name, member.size, budget, max_bytes)
        source = archive.extractfile(member)
        if source is None:
            raise ConfigError(f"Could not read archive member: {member.name}")
        with source:
            _copy_member(source, destination, budget, max_bytes)


def _extract_gzip(
    path: Path,
    target_dir: Path,
    budget: dict[str, int],
    max_nodes: int,
    max_bytes: int | None,
) -> None:
    output_name = path.name[:-3] if path.name.lower().endswith(".gz") else f"{path.name}.out"
    destination = _safe_destination(target_dir, output_name)
    _reserve_nodes(target_dir, destination, budget, max_nodes)
    with gzip.open(path, "rb") as source:
        _copy_member(source, destination, budget, max_bytes)
