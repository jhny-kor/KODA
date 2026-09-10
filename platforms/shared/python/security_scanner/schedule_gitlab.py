"""Lease-scoped GitLab source collector used by the isolated schedule worker.

The portal keeps GitLab credentials and resolves the configured ref.  The
worker receives only a streamed archive for the leased run, then scans and
deletes that archive with the rest of the job directory.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import shutil
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Callable

from .schedule_api import API_PREFIX, _OPENER
from .schedule_transport import RemoteFile, RemoteLimitError, RemotePermanentError, RemoteTransientError, RemoteTransportError, _safe_relative_path


class GitLabCollector:
    """Download one authenticated GitLab archive and expose safe files."""

    def __init__(self, client, job: dict, *, cache_dir: Path, sleep: Callable[[float], None] = time.sleep):
        self.client = client
        self.job = job
        self.cache_dir = Path(cache_dir)
        self.sleep = sleep
        self._archive: Path | None = None
        self._files: dict[str, RemoteFile] = {}
        self._member_root = ""
        self.hashes: dict[str, str] = {}

    def reset(self) -> None:
        """Remove partial GitLab materialization before a retry."""
        self._archive = None
        self._files.clear()
        self.hashes.clear()
        for path in (self.cache_dir / "gitlab-source.tar.gz", self.cache_dir / "gitlab-files"):
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)

    def _payload(self, target: dict) -> dict:
        return {"schedule_run_id": self.job["schedule_run_id"], "lease_token": self.job["lease_token"]}

    def _download_archive(self, target: dict, *, cancel=None) -> Path:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        path = self.cache_dir / "gitlab-source.tar.gz"
        payload = json.dumps(self._payload(target), separators=(",", ":")).encode()
        request = urllib.request.Request(
            self.client.base_url + API_PREFIX + "/gitlab-archive", data=payload,
            method="POST", headers={"Authorization": f"Bearer {self.client.token}",
                                    "Content-Type": "application/json", "Accept": "application/gzip"})
        maximum = int(target.get("max_bytes", 0) or 0)
        if maximum <= 0:
            raise ValueError("GitLab scheduled source max_bytes is required")
        try:
            response = _OPENER.open(request, timeout=min(30, max(1, int(target.get("timeout_seconds", 300)))))
        except urllib.error.HTTPError as exc:
            try:
                exc.close()
            finally:
                if exc.code in {408, 429} or exc.code >= 500:
                    raise RemoteTransientError("GitLab source archive temporarily unavailable") from exc
                raise RemotePermanentError("GitLab source archive request rejected") from exc
        except (OSError, TimeoutError) as exc:
            raise RemoteTransientError("GitLab source archive unavailable") from exc
        written = 0
        started = time.monotonic()
        rate = max(1, int(target.get("transfer_rate_bytes_per_sec", 5 * 1024 * 1024)))
        try:
            with path.open("wb") as output:
                while True:
                    if cancel and cancel():
                        raise InterruptedError("scheduled collection cancelled")
                    block = response.read(64 * 1024)
                    if not block:
                        break
                    written += len(block)
                    if written > maximum:
                        raise RemoteLimitError("GitLab source archive exceeds transfer limit")
                    if shutil.disk_usage(self.cache_dir).free < int(target.get("min_free_bytes", 0) or 0) + len(block):
                        raise RemoteLimitError("local disk free-space limit exceeded")
                    output.write(block)
                    while (delay := written / rate - (time.monotonic() - started)) > 0:
                        if cancel and cancel():
                            raise InterruptedError("scheduled collection cancelled")
                        self.sleep(min(delay, .25))
            if written == 0:
                raise RemoteTransportError("empty GitLab source archive")
            return path
        except (http.client.HTTPException, ConnectionError, TimeoutError) as exc:
            path.unlink(missing_ok=True)
            raise RemoteTransientError("GitLab source stream interrupted") from exc
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        finally:
            response.close()

    def list_files(self, target: dict, *, cancel=None) -> list[RemoteFile]:
        self._archive = self._download_archive(target, cancel=cancel)
        selected_dir = str(target.get("source_gitlab_directory") or "").strip("/")
        excludes = target.get("exclude_paths", [])
        files: list[RemoteFile] = []
        extracted = self.cache_dir / "gitlab-files"
        max_files = int(target.get("max_files", 200_000))
        max_bytes = int(target.get("max_bytes", 0))
        expanded = 0
        entries = 0
        entry_limit = min(1_000_000, max(max_files + 1024, max_files * 2))
        prefix = None
        root = None
        selected_seen = False
        self.hashes = {}
        with tarfile.open(self._archive, mode="r|gz") as archive:
            for member in archive:
                if cancel and cancel():
                    raise InterruptedError("scheduled collection cancelled")
                entries += 1
                if entries > entry_limit:
                    raise RemoteLimitError("GitLab archive entry count limit exceeded")
                name = str(member.name)
                if not name or name.startswith("/") or "\\" in name:
                    raise RemoteTransportError("invalid GitLab archive member path")
                parts = PurePosixPath(name).parts
                if ".." in parts:
                    raise RemoteTransportError("invalid GitLab archive member path")
                if prefix is None:
                    prefix = parts[0] + "/"
                    root = prefix + (selected_dir + "/" if selected_dir else "")
                size = int(member.size)
                if size < 0 or size > max_bytes - expanded:
                    raise RemoteLimitError("GitLab expanded archive exceeds collection limit")
                expanded += size
                if not member.isfile():
                    if member.issym() or member.islnk():
                        raise RemoteTransportError("GitLab archive links are not allowed")
                    continue
                if root is None or not name.startswith(root):
                    continue
                selected_seen = True
                relative = name[len(root):]
                if not relative or relative.endswith("/"):
                    continue
                _safe_relative_path(relative)
                if any(str(x).strip("/") and (relative == str(x).strip("/") or relative.startswith(str(x).strip("/") + "/")) for x in excludes):
                    continue
                if len(files) >= max_files:
                    raise RemoteLimitError("GitLab source file count limit exceeded")
                destination = extracted / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if shutil.disk_usage(self.cache_dir).free < int(target.get("min_free_bytes", 0) or 0) + size:
                    raise RemoteLimitError("local disk free-space limit exceeded")
                if destination.is_symlink():
                    raise RemoteTransportError("GitLab extraction path is a symlink")
                stream = archive.extractfile(member)
                if stream is None:
                    raise RemoteTransportError("GitLab archive member is unreadable")
                with destination.open("xb") as output:
                    digest = hashlib.sha256()
                    while True:
                        if cancel and cancel():
                            raise InterruptedError("scheduled collection cancelled")
                        block = stream.read(64 * 1024)
                        if not block:
                            break
                        output.write(block)
                        digest.update(block)
                self.hashes[relative] = digest.hexdigest()
                files.append(RemoteFile(relative, size, float(member.mtime)))
        if selected_dir and root is not None and not selected_seen:
            # A configured directory that does not exist must be visible as a failure.
            raise RemotePermanentError("GitLab source directory is empty or missing")
        files.sort(key=lambda item: item.relative_path)
        self._files = {item.relative_path: item for item in files}
        return files

    def fetch(self, target: dict, remote_file: RemoteFile, destination: Path, *, cancel=None) -> str:
        if self._archive is None or remote_file.relative_path not in self._files:
            raise RemoteTransportError("GitLab archive manifest is unavailable")
        destination.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        written = 0
        try:
            cached = self.cache_dir / "gitlab-files" / remote_file.relative_path
            if not cached.is_file() or cached.is_symlink() or cached.stat().st_size != remote_file.size:
                raise RemoteTransportError("GitLab extracted member is unavailable")
            if remote_file.size > int(target.get("remaining_bytes", target["max_bytes"])):
                raise RemoteLimitError("GitLab copy exceeds remaining byte limit")
            if shutil.disk_usage(self.cache_dir).free < int(target.get("min_free_bytes", 0)) + remote_file.size:
                raise RemoteLimitError("local disk free-space limit exceeded")
            with cached.open("rb") as stream, destination.open("wb") as output:
                while True:
                    if cancel and cancel():
                        raise InterruptedError("scheduled collection cancelled")
                    block = stream.read(64 * 1024)
                    if not block:
                        break
                    written += len(block)
                    output.write(block)
                    digest.update(block)
            if written != remote_file.size:
                raise RemoteTransportError("GitLab archive member size changed")
            return digest.hexdigest()
        except BaseException:
            destination.unlink(missing_ok=True)
            raise


__all__ = ["GitLabCollector"]
