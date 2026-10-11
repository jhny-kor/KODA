from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

MAX_SYFT_STDOUT_BYTES = 32 * 1024 * 1024
MAX_SYFT_STDERR_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class SyftResult:
    payload: dict[str, object] | None
    version: str
    warning: str
    fatal: bool


def run_syft(target: Path, binary: Path | None, timeout: float) -> SyftResult:
    if binary is None:
        return SyftResult(None, "", "Syft is not configured; using the built-in Java inventory.", False)
    validation = _validate_binary(binary)
    if validation:
        return SyftResult(None, "", validation, True)
    version_result = _run(binary, ("--version",), timeout, {})
    version = version_result.stdout.strip() if version_result.returncode == 0 else ""
    if version_result.returncode != 0:
        version_warning = f"Syft version check failed: {version_result.stderr.strip() or 'unknown error'}"
    else:
        version_warning = ""
    source = f"file:{target}" if target.is_file() else f"dir:{target}"
    scan = _run(binary, (source, "-o", "cyclonedx-json@1.6"), timeout, {})
    if scan.returncode != 0:
        warning = f"Syft failed; using the built-in Java inventory: {scan.stderr.strip() or 'unknown error'}"
        return SyftResult(None, version, warning, True)
    try:
        payload = json.loads(scan.stdout)
    except json.JSONDecodeError as exc:
        return SyftResult(None, version, f"Syft returned invalid JSON: {exc}", True)
    if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
        return SyftResult(None, version, "Syft returned an invalid CycloneDX document.", True)
    if "components" not in payload:
        payload["components"] = []
    elif not isinstance(payload.get("components"), list):
        return SyftResult(None, version, "Syft returned an invalid CycloneDX document.", True)
    return SyftResult(payload, version, version_warning, False)


def _validate_binary(binary: Path) -> str:
    if not binary.is_file():
        return f"Syft executable not found: {binary}"
    if not os.access(binary, os.X_OK):
        return f"Syft executable is not executable: {binary}"
    return ""


def _run(binary: Path, arguments: tuple[str, ...], timeout: float, extra_env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(extra_env)
    command = [str(binary), *arguments]
    process = None
    readers: list[threading.Thread] = []
    stopped = threading.Event()
    chunks: queue.Queue[tuple[int, bytes | OSError]] = queue.Queue(maxsize=16)

    def read_stream(stream, index: int) -> None:
        def publish(chunk: bytes | OSError) -> None:
            while not stopped.is_set():
                try:
                    chunks.put((index, chunk), timeout=0.05)
                    return
                except queue.Full:
                    continue

        try:
            while not stopped.is_set():
                chunk = stream.read(65_536)
                publish(chunk)
                if not chunk:
                    return
        except OSError as exc:
            publish(exc)
        finally:
            stream.close()

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, bufsize=0)
        assert process.stdout is not None and process.stderr is not None
        output, errors = bytearray(), bytearray()
        buffers = (output, errors)
        limits = (MAX_SYFT_STDOUT_BYTES, MAX_SYFT_STDERR_BYTES)
        deadline = time.monotonic() + timeout
        # Windows selectors cannot monitor process pipes. Drain both streams
        # concurrently, with a bounded queue so a noisy tool cannot fill memory.
        for index, stream in enumerate((process.stdout, process.stderr)):
            reader = threading.Thread(target=read_stream, args=(stream, index), daemon=True)
            readers.append(reader)
            reader.start()
        remaining_streams = 2
        while remaining_streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            index, chunk = chunks.get(timeout=remaining)
            if isinstance(chunk, OSError):
                raise chunk
            if not chunk:
                remaining_streams -= 1
                continue
            if len(buffers[index]) + len(chunk) > limits[index]:
                return subprocess.CompletedProcess(command, 125, "", "Syft output byte limit exceeded")
            buffers[index].extend(chunk)
        # EOF does not mean the process exited; it still shares the same deadline.
        returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
        return subprocess.CompletedProcess(command, returncode, output.decode("utf-8", "replace"), errors.decode("utf-8", "replace"))
    except (subprocess.TimeoutExpired, queue.Empty):
        return subprocess.CompletedProcess(command, 124, "", f"timed out after {timeout:g}s")
    except FileNotFoundError:
        return subprocess.CompletedProcess(command, 127, "", f"executable not found: {binary}")
    except PermissionError:
        return subprocess.CompletedProcess(command, 126, "", f"permission denied: {binary}")
    except OSError as exc:
        return subprocess.CompletedProcess(command, 125, "", str(exc))
    finally:
        stopped.set()
        if process is not None and process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
            process.wait()
        for reader in readers:
            reader.join(timeout=1)
