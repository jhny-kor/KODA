"""Bounded, read-only OpenSSH transport for scheduled inspections.

The scheduler owns orchestration. This module sends a fixed collection helper
and bounds the remote output written to the caller supplied destination.
"""
from __future__ import annotations

import hashlib
import os
import re
import select
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass
from importlib.resources import files as package_files
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, Protocol


class RemoteTransportError(RuntimeError):
    """A remote connection or protocol failure."""


class RemoteTransientError(RemoteTransportError):
    """A transport explicitly identified a retryable network/server response."""


class RemotePermanentError(RemoteTransportError):
    """An authentication, host-key, or path error that should not retry."""


class RemoteLimitError(RemoteTransportError):
    """A configured manifest or transfer limit was exceeded."""


@dataclass(frozen=True)
class RemoteFile:
    relative_path: str
    size: int
    mtime: float
    sha256: str = ""


class RemoteCollector(Protocol):
    def list_files(self, target: dict) -> list[RemoteFile]: ...

    def fetch(self, target: dict, remote_file: RemoteFile, destination: Path) -> str: ...


_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:-]*\Z")
_USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\Z")
_REMOTE_HELPER = package_files(__package__).joinpath("_schedule_ssh_remote.py").read_text(encoding="utf-8")
_REMOTE_PYTHON = (
    "command -v python3 >/dev/null 2>&1 || { "
    "printf '%s\\n' 'scheduled source collection requires Python 3.7 or later' >&2; exit 125; }; "
)
_STDERR_LIMIT = 64 * 1024
_PERMANENT = (
    "permission denied", "authentication failed", "host key verification failed",
    "remote host identification has changed", "could not resolve hostname",
    "no such file or directory", "not a directory", "bad configuration option",
)


def _remote_name(target: dict) -> str:
    username, host = str(target.get("username", "")), str(target.get("host", ""))
    if not _USER.fullmatch(username) or not _HOST.fullmatch(host):
        raise ValueError("invalid SSH host or account")
    return f"{username}@{host}"


def _ssh_options(target: dict, *, scp: bool = False) -> list[str]:
    key, known = str(target.get("ssh_key_ref", "")), str(target.get("known_hosts_file", ""))
    try:
        port = int(target.get("port", 22))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid SSH port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("invalid SSH port")
    if (not key or not known or not Path(key).expanduser().is_absolute()
            or not Path(known).expanduser().is_absolute()
            or any(c in key + known for c in "\x00\r\n")):
        raise ValueError("SSH key and known-hosts paths are required")
    return [
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known}", "-i", key,
        "-o", "ConnectTimeout=30", ("-P" if scp else "-p"), str(port),
    ]


def _safe_relative_path(path: str) -> str:
    if not path or path.startswith("/") or any(ord(char) < 32 for char in path):
        raise RemoteTransportError("invalid remote file path")
    parts = PurePosixPath(path).parts
    if ".." in parts or any(part in {"", "."} for part in parts):
        raise RemoteTransportError("invalid remote file path")
    return path


def _validate_remote_root(root: str) -> str:
    if not root.startswith("/") or any(ord(char) < 32 for char in root):
        raise ValueError("remote directory must be an absolute path")
    if ".." in root.split("/"):
        raise ValueError("remote directory must not contain parent components")
    return root


def _collection_command(target: dict, operation: str, *arguments: str) -> list[str]:
    root = _validate_remote_root(str(target.get("remote_directory", "")))
    remote_command = _REMOTE_PYTHON + shlex.join(
        ["exec", "python3", "-I", "-S", "-c", _REMOTE_HELPER, operation, root, *arguments]
    )
    return ["ssh", *_ssh_options(target), _remote_name(target), remote_command]


def _retain_stderr(diagnostics: bytearray, chunk: bytes) -> None:
    diagnostics.extend(chunk[:_STDERR_LIMIT - len(diagnostics)])


def _excluded(path: str, patterns: Iterable[str]) -> bool:
    normalized = path.strip("/")
    for raw in patterns:
        pattern = str(raw).strip().strip("/")
        if pattern and (normalized == pattern or normalized.startswith(pattern + "/")
                        or PurePosixPath(normalized).match(pattern)):
            return True
    return False


def _retryable_remote_error(error: BaseException) -> bool:
    if isinstance(error, RemoteTransientError):
        return True
    message = str(getattr(error, "stderr", "") or error).lower()
    if isinstance(error, (RemoteLimitError, RemotePermanentError, ValueError, InterruptedError)):
        return False
    if any(marker in message for marker in _PERMANENT):
        return False
    return isinstance(error, (OSError, TimeoutError, RuntimeError, subprocess.SubprocessError, RemoteTransportError)) and (
        not message or any(marker in message for marker in
                           ("connection reset", "connection timed out", "connection refused",
                            "network is unreachable", "broken pipe", "lost connection", "try again"))
    )


class OpenSSHCollector:
    """Streaming OpenSSH collector with hard count, byte, and time limits."""

    def __init__(
        self,
        *,
        popen: Callable[..., subprocess.Popen] | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ):
        self._popen = popen or subprocess.Popen
        self._clock = clock
        self._sleep = sleeper

    @staticmethod
    def _timeout(target: dict) -> float:
        return max(1.0, float(target.get("timeout_seconds", 21_600)))

    @staticmethod
    def _manifest_limit(target: dict) -> int:
        configured = int(target.get("manifest_max_bytes", 0) or 0)
        # A hard ceiling prevents a hostile directory from consuming memory.
        return max(4096, min(configured or 16 * 1024 * 1024, 64 * 1024 * 1024))

    def _start(self, command: list[str]) -> subprocess.Popen:
        return self._popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True)

    @staticmethod
    def _stop(process: subprocess.Popen) -> None:
        try:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except (OSError, ProcessLookupError):
                    try:
                        process.terminate()
                    except OSError:
                        pass
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (OSError, ProcessLookupError):
                        try:
                            process.kill()
                        except OSError:
                            pass
                    process.wait(timeout=2)
        finally:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()

    def _read(self, process: subprocess.Popen, diagnostics: bytearray, *, limit: int, timeout: float,
              cancel: Callable[[], bool] | None = None,
              on_chunk: Callable[[bytes], None] | None = None,
              retain: bool = True) -> bytes:
        output = bytearray()
        deadline = self._clock() + timeout
        stream = process.stdout
        error_stream = process.stderr
        assert stream is not None
        streams = [stream]
        if error_stream is not None:
            streams.append(error_stream)
        try:
            while streams:
                if cancel and cancel():
                    raise InterruptedError("scheduled collection cancelled")
                remaining = deadline - self._clock()
                if remaining <= 0:
                    raise TimeoutError("remote collection timed out")
                ready, _, _ = select.select(streams, [], [], min(remaining, 0.25))
                if not ready:
                    continue
                for ready_stream in ready:
                    chunk = os.read(ready_stream.fileno(), 64 * 1024)
                    if ready_stream is stream:
                        if not chunk:
                            streams.remove(stream)
                        else:
                            if retain:
                                output.extend(chunk)
                            if on_chunk:
                                on_chunk(chunk)
                            if retain and len(output) > limit:
                                raise RemoteLimitError("remote manifest output limit exceeded")
                    elif chunk:
                        _retain_stderr(diagnostics, chunk)
                    else:
                        streams.remove(ready_stream)
            return bytes(output)
        except BaseException:
            self._stop(process)
            raise

    def _finish(self, process: subprocess.Popen, diagnostics: bytearray) -> None:
        code = process.wait(timeout=2)
        if code:
            message = diagnostics.decode("utf-8", "replace")[:1000].strip() or f"ssh exited {code}"
            if code == 125 or any(marker in message.lower() for marker in _PERMANENT):
                raise RemotePermanentError(message)
            raise RemoteTransportError(message)

    def test_connection(self, target: dict) -> None:
        process = self._start(["ssh", *_ssh_options(target), _remote_name(target), "true"])
        diagnostics = bytearray()
        try:
            self._read(process, diagnostics, limit=4096, timeout=self._timeout(target))
            self._finish(process, diagnostics)
        finally:
            self._stop(process)

    def list_files(self, target: dict, *, cancel: Callable[[], bool] | None = None) -> list[RemoteFile]:
        excludes = [str(item).strip().strip("/") for item in target.get("exclude_paths", []) if str(item).strip()]
        command = _collection_command(target, "list", *excludes)
        max_files = int(target.get("max_files", 200_000))
        files: list[RemoteFile] = []

        def parse(line: bytes) -> None:
            parts = line.split(b"\t")
            if len(parts) != 3:
                raise RemoteTransportError("unsupported remote filename")
            path = _safe_relative_path(parts[0].decode("utf-8", "surrogateescape"))
            if _excluded(path, excludes):
                return
            try:
                size, mtime = int(parts[1]), float(parts[2])
            except ValueError as exc:
                raise RemoteTransportError("invalid remote manifest entry") from exc
            if size < 0:
                raise RemoteTransportError("invalid remote file size")
            files.append(RemoteFile(path, size, mtime))
            if len(files) > max_files:
                raise RemoteLimitError("remote file count limit exceeded")

        partial = bytearray()
        def consume(chunk: bytes) -> None:
            partial.extend(chunk)
            if len(partial) > self._manifest_limit(target):
                raise RemoteLimitError("remote manifest line limit exceeded")
            while b"\n" in partial:
                line, _, rest = partial.partition(b"\n")
                partial[:] = rest
                parse(line.rstrip(b"\r"))

        process = self._start(command)
        diagnostics = bytearray()
        try:
            self._read(process, diagnostics, limit=self._manifest_limit(target), timeout=self._timeout(target),
                       cancel=cancel, on_chunk=consume, retain=False)
            self._finish(process, diagnostics)
            if partial:
                parse(bytes(partial).rstrip(b"\r"))
        finally:
            self._stop(process)
        files.sort(key=lambda item: item.relative_path)
        return files

    def fetch(self, target: dict, remote_file: RemoteFile, destination: Path,
              *, cancel: Callable[[], bool] | None = None) -> str:
        relative = _safe_relative_path(remote_file.relative_path)
        if remote_file.size < 0:
            raise ValueError("invalid remote file size")
        command = _collection_command(target, "fetch", relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        process = self._start(command)
        diagnostics = bytearray()
        digest = hashlib.sha256()
        written = 0
        rate = int(target.get("transfer_rate_bytes_per_sec", os.environ.get("KODA_SCHEDULE_RATE_BYTES", 5 * 1024 * 1024)))
        rate = max(1, rate)
        started = self._clock()
        budget = min(remote_file.size, int(target.get("remaining_bytes", target.get("max_bytes", remote_file.size))))
        reserve = int(target.get("min_free_bytes", 0) or 0)
        try:
            stream = process.stdout
            error_stream = process.stderr
            assert stream is not None
            streams = [stream]
            if error_stream is not None:
                streams.append(error_stream)
            with destination.open("wb") as output:
                deadline = self._clock() + self._timeout(target)
                while streams:
                    if cancel and cancel():
                        raise InterruptedError("scheduled collection cancelled")
                    remaining = deadline - self._clock()
                    if remaining <= 0:
                        raise TimeoutError("remote file transfer timed out")
                    ready, _, _ = select.select(streams, [], [], min(remaining, 0.25))
                    if not ready:
                        continue
                    for ready_stream in ready:
                        chunk = os.read(ready_stream.fileno(), 64 * 1024)
                        if ready_stream is not stream:
                            if chunk:
                                _retain_stderr(diagnostics, chunk)
                            else:
                                streams.remove(ready_stream)
                            continue
                        if not chunk:
                            streams.remove(stream)
                            continue
                        written += len(chunk)
                        if written > budget:
                            raise RemoteLimitError("remote file exceeded transfer budget")
                        available = target.get("available_bytes")
                        if callable(available):
                            available = available()
                        if available is not None and int(available) < len(chunk) + reserve:
                            raise RemoteLimitError("local disk free-space limit exceeded")
                        output.write(chunk)
                        digest.update(chunk)
                        while True:
                            delay = written / rate - (self._clock() - started)
                            if delay <= 0:
                                break
                            if cancel and cancel():
                                raise InterruptedError("scheduled collection cancelled")
                            if deadline - self._clock() <= 0:
                                raise TimeoutError("remote file transfer timed out")
                            self._sleep(min(delay, 0.25))
            self._finish(process, diagnostics)
            if written != remote_file.size:
                raise RemoteTransportError(f"remote file size changed: expected {remote_file.size}, got {written}")
            return digest.hexdigest()
        except BaseException:
            self._stop(process)
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        finally:
            self._stop(process)


__all__ = ["RemoteFile", "RemoteCollector", "OpenSSHCollector", "RemoteTransportError",
           "RemotePermanentError", "RemoteLimitError", "_retryable_remote_error"]
