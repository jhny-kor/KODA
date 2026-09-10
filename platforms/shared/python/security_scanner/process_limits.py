"""Resource and lifetime limits for the dedicated scheduled analyzer process."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import resource
import signal
import sys
import time


def apply_limits(settings: dict) -> dict:
    """Apply requested soft limits inside the deployment's hard ceilings."""
    cpus = int(settings.get("cpu_limit", settings.get("cpus", 1)))
    memory = int(settings.get("memory_limit_bytes", settings.get("memory_bytes", 4 * 1024**3)))
    if cpus < 1 or memory < 256 * 1024**2:
        raise ValueError("invalid scheduled analyzer resource limits")
    effective = {"cpus": cpus, "memory_bytes": memory, "enforced": sys.platform == "linux"}
    if sys.platform != "linux":
        return effective
    cpu_ceiling = float(cpus)
    try:
        quota, period = Path('/sys/fs/cgroup/cpu.max').read_text().split()
        if quota != 'max':
            cpu_ceiling = min(cpu_ceiling, int(quota) / int(period))
    except (OSError, ValueError):
        pass
    try:
        ceiling = Path('/sys/fs/cgroup/memory.max').read_text().strip()
        if ceiling != 'max':
            memory = min(memory, int(ceiling))
    except (OSError, ValueError):
        pass
    available = sorted(os.sched_getaffinity(0))
    selected = available[:cpus]
    os.sched_setaffinity(0, selected)
    _, hard = resource.getrlimit(resource.RLIMIT_AS)
    memory = memory if hard == resource.RLIM_INFINITY else min(memory, hard)
    resource.setrlimit(resource.RLIMIT_AS, (memory, hard))
    effective.update(cpus=min(len(selected), cpu_ceiling), memory_bytes=memory)
    return effective


def bind_parent_lifetime(parent_pid: int) -> None:
    """Called before threads/tools in an analyzer started with its own session.

    Linux kills the analyzer when its worker dies. A tiny group watchdog also
    removes grandchildren after analyzer SIGKILL (PDEATHSIG isn't inherited).
    """
    if os.getpgrp() != os.getpid():
        raise RuntimeError("scheduled analyzer requires a dedicated process group")
    if os.getppid() != parent_pid:
        os.killpg(os.getpgrp(), signal.SIGKILL)
    if sys.platform == "linux":
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        if os.getppid() != parent_pid:
            os.killpg(os.getpgrp(), signal.SIGKILL)
    analyzer_pid, group = os.getpid(), os.getpgrp()
    watchdog = os.fork()
    if watchdog == 0:
        try:
            # This child must not keep worker locks, network pipes, or source
            # descriptors alive. Only the lifetime check and group ID are needed.
            cap = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            os.closerange(0, min(int(cap), 1048576))
            while os.getppid() == analyzer_pid:
                try:
                    os.kill(parent_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(.2)
            os.killpg(group, signal.SIGKILL)
        finally:
            os._exit(0)
