"""Verify the publisher proof preserved by the managed data updater."""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import threading
from pathlib import Path

_verified: dict[tuple, bool] = {}
_cache_lock = threading.Lock()
_DATA_KEYS = {"DATASET_DATE", "NVD_INDEX", "NVD_DATASET_DATE", "NVD_SHA256", "KEV_CATALOG", "KEV_DATASET_DATE", "KEV_SHA256",
              "ALIAS_INDEX", "ALIAS_SHA256", "EPSS_SNAPSHOT", "EPSS_SHA256", "EPSS_DATASET_DATE", "INTELLIGENCE_INDEX", "INTELLIGENCE_SHA256",
              "GRYPE_DB_SCHEMA", "GRYPE_DATASET_DATE"}


def _stat(path: Path) -> tuple:
    value = path.stat()
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_mode)


def _metadata(path: Path) -> dict:
    if path.stat().st_size > 65536:
        raise ValueError("approved metadata exceeds size limit")
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            key = key.strip()
            if key in values:
                raise ValueError("duplicate approved metadata key")
            values[key] = value.strip().strip('"').strip("'")
    return values


def verify_approved_release(release: Path) -> None:
    """Caller holds .release.lock SH. Cache only unchanged immutable file identities.

    Every read checks proof/key/metadata and every manifest file's device, inode,
    size, mtime, ctime and mode. Changed identities invalidate the complete proof.
    Trusted backend writers are the only writers to this read-only mount.
    """
    key = Path(os.environ.get("KODA_DATA_UPDATE_VERIFY_KEY", "/run/secrets/tracker-data-update-verify.pub"))
    metadata = release / "approved-metadata.env"
    manifest = release / "approved-manifest.sha256"
    signature = release / "approved-manifest.sha256.sig"
    runtime = release / "metadata.env"
    proofs = (key, metadata, manifest, signature, runtime)
    if any(not p.is_file() or p.is_symlink() for p in proofs):
        raise ValueError("approved data proof or registered verification public key is missing")
    if manifest.stat().st_size > 16 * 1024 * 1024 or key.stat().st_size > 65536 or signature.stat().st_size > 65536:
        raise ValueError("approved data proof exceeds size limit")
    if b"PRIVATE KEY" in key.read_bytes():
        raise ValueError("a private signing key is not a verification public-key file")
    entries = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) != 2 or not re.fullmatch(r"[a-fA-F0-9]{64}", parts[0]):
            raise ValueError("invalid approved manifest entry")
        digest, name = parts; name = name.removeprefix("./")
        if not name or name.startswith("/") or "\\" in name or any(p in {"", ".", ".."} for p in name.split("/")) or name in entries:
            raise ValueError("unsafe or duplicate approved manifest path")
        path = metadata if name == "metadata.env" else release / name
        if not path.resolve().is_relative_to(release) or not path.is_file() or any(p.is_symlink() for p in (path, *path.parents) if p != release and p.is_relative_to(release)):
            raise ValueError("approved manifest source is missing or unsafe")
        entries[name] = (digest.lower(), path)
    if "metadata.env" not in entries or not any(name.startswith("grype-db/") for name in entries):
        raise ValueError("approved unified manifest lacks metadata or Grype data")
    allowed = set(entries) | {"approved-metadata.env", "approved-manifest.sha256", "approved-manifest.sha256.sig", "manifest.sha256"}
    for path in release.rglob("*"):
        if path.is_symlink() or (path.is_file() and path.relative_to(release).as_posix() not in allowed):
            raise ValueError("unapproved file or symlink in managed vulnerability release")
    approved, actual = _metadata(metadata), _metadata(runtime)
    if approved.get("DATASET_TYPE") != "unified" or {k: v for k,v in approved.items() if k in _DATA_KEYS} != {k: v for k,v in actual.items() if k in _DATA_KEYS}:
        raise ValueError("runtime data metadata differs from approved unified source")
    paths = tuple(dict.fromkeys((*proofs, *(entry[1] for entry in entries.values()))))
    identities = tuple((str(p), _stat(p)) for p in paths)
    cache_key = (str(release), identities)
    with _cache_lock:
        if cache_key in _verified:
            return
    try:
        result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(key), "-signature", str(signature), str(manifest)],
                                capture_output=True, timeout=30, check=False)
    except subprocess.SubprocessError as exc:
        raise ValueError("approved data signature verification did not complete") from exc
    if result.returncode:
        raise ValueError("approved data signature verification failed")
    for digest, path in entries.values():
        before = _stat(path)
        checksum = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                checksum.update(chunk)
        if checksum.hexdigest() != digest or before != _stat(path):
            raise ValueError("approved vulnerability source changed or failed checksum")
    if identities != tuple((str(p), _stat(p)) for p in paths):
        raise ValueError("approved data changed during verification")
    with _cache_lock:
        if len(_verified) >= 8:
            _verified.pop(next(iter(_verified)))
        _verified[cache_key] = True
