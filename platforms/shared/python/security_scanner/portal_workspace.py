"""Private per-run extraction directories; cleanup never follows links."""
from __future__ import annotations

import fcntl
import logging
import os
import shutil
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path

log = logging.getLogger(__name__)


@contextmanager
def extraction_workspace(root: Path, run_id: str):
    run_id = str(uuid.UUID(run_id))
    if root.is_symlink():
        raise ValueError('portal work root must not be a symbolic link')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix=f'koda-portal-{run_id}-', dir=root) as directory:
        path = Path(directory)
        with (path / '.owner.lock').open('a') as lock:
            os.fchmod(lock.fileno(), 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX)
            (path / 'owner.json').write_text(f'{{"run_id":"{run_id}"}}\n', encoding='utf-8')
            yield path


def cleanup_workspaces(root: Path, run_id: str | None = None) -> list[str]:
    """Called by the execution owner, or after its child exits.

    Legacy random workspace names are reclaimed at startup under the DB worker
    lock. Current workspaces also hold their own lock, including direct scans.
    Symlinks and unrelated entries are always preserved.
    """
    if not root.exists() or root.is_symlink():
        return []
    prefix = f'koda-portal-{uuid.UUID(run_id)}-' if run_id else 'koda-portal-'
    errors = []
    for path in root.iterdir():
        if not path.name.startswith(prefix) or path.is_symlink() or not path.is_dir():
            continue
        try:
            descriptor = os.open(path / '.owner.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'a') as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                shutil.rmtree(path)
        except OSError as exc:
            errors.append(f'{path.name}: {exc}')
            log.error('Portal workspace cleanup failed: %s: %s', path.name, exc)
    return errors
