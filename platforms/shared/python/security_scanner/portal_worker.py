"""Portal worker supervision and durable publication requests.

The web and workers share the existing private portal data mount. Scan children
never perform publication. Only one execution owner may claim manual work.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from .portal_store import PortalStore, TERMINAL_RUN_STATUSES
from .portal_workspace import cleanup_workspaces

log = logging.getLogger(__name__)


def data_root(store: PortalStore | str | Path) -> Path:
    database = store.path if isinstance(store, PortalStore) else store
    return Path(os.environ.get('KODA_PORTAL_DATA_DIR') or Path(database).parent)


def heartbeat_path(store: PortalStore | str | Path, role: str) -> Path:
    return data_root(store) / f'portal-{role}-heartbeat.json'


def worker_healthy(store: PortalStore | str | Path, role: str) -> bool:
    try:
        record = json.loads(heartbeat_path(store, role).read_text(encoding='utf-8'))
        # monotonic values are shared by containers on this host and immune to
        # wall-clock changes. A host reboot invalidates the recorded PID epoch.
        age = time.monotonic() - float(record['monotonic'])
        return record['role'] == role and record.get('ready') is True and 0 <= age <= 15
    except (OSError, ValueError, KeyError, TypeError):
        return False


def write_heartbeat(store: PortalStore, role: str, ready: bool = True) -> None:
    path = heartbeat_path(store, role)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump({'role': role, 'ready': ready, 'monotonic': time.monotonic(), 'pid': os.getpid()}, stream)
    os.replace(temporary, path)


class ExternalWorkerProxy:
    """Web-side availability check; the DB is the durable enqueue operation."""
    def __init__(self, store: PortalStore):
        self.store = store

    @property
    def available(self):
        return worker_healthy(self.store, 'scan')

    def enqueue(self, run_id):
        # A worker exit between acceptance and this call must not turn an
        # already-persisted request into an HTTP error and a duplicate retry.
        pass

    def close(self):
        pass


def run_state(store: PortalStore, run_id: str) -> dict:
    with store._db() as db:
        row = db.execute('SELECT status,cancel_requested,input_id,snapshot_json FROM scan_runs WHERE run_id=?', (run_id,)).fetchone()
    if row is None:
        raise KeyError('run not found')
    return dict(row)


def work_root_for_run(store: PortalStore, run_id: str) -> Path:
    state = run_state(store, run_id)
    source = store.input(state['input_id'])
    path = Path(source['path'])
    return path.parent / 'extracted' if json.loads(state['snapshot_json']).get('source_type') == 'scheduled_server' else path.parent.parent / 'work'


def terminate_group(process: subprocess.Popen, grace: float = 3) -> None:
    def send(signum):
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            pass
        except PermissionError:
            # An exited leader alone does not prove its descendants are gone.
            # Accept a signal/exit race only after the entire group disappears.
            if process.poll() is not None:
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    return
            raise

    send(signal.SIGTERM)
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    # Also removes children after a leader exits on TERM.
    send(signal.SIGKILL)
    process.wait()


class ScanSupervisor:
    def __init__(self, store: PortalStore, stop_event=None, *, timeout=None, grace=None, command_factory=None):
        self.store = store
        self.stop_event = stop_event or threading.Event()
        self.timeout = float(timeout if timeout is not None else os.environ.get('KODA_SCAN_TIMEOUT_SECONDS', '21600'))
        self.grace = float(grace if grace is not None else os.environ.get('KODA_SCAN_TERMINATE_GRACE_SECONDS', '3'))
        if self.timeout <= 0 or not 0 <= self.grace <= 10:
            raise ValueError('invalid portal analyzer timeout/grace')
        self.command_factory = command_factory

    def execute(self, run_id: str) -> bool:
        if self.stop_event.is_set() or not self.store.mark_run_running(run_id):
            return False
        work_root = data_root(self.store) / 'work'
        process = None
        reason = ''
        try:
            work_root = work_root_for_run(self.store, run_id)
            command = (self.command_factory(run_id) if self.command_factory else [
                sys.executable, '-m', 'security_scanner.portal_worker', '--db', self.store.path,
                '--analyze-run', run_id, '--parent', str(os.getpid()),
            ])
            process = subprocess.Popen(command, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + self.timeout
            while process.poll() is None:
                state = run_state(self.store, run_id)
                if state['cancel_requested']:
                    reason = 'cancelled'
                    break
                if self.stop_event.is_set():
                    reason = 'shutdown'
                    break
                if time.monotonic() >= deadline:
                    reason = 'timeout'
                    break
                self.stop_event.wait(.2)
            if not reason and process.returncode:
                reason = f'analyzer exited {process.returncode}'
        except Exception as exc:
            reason = f'analyzer supervisor failed: {exc}'
        finally:
            if process is not None:
                try:
                    terminate_group(process, self.grace)
                except OSError as exc:
                    # Do not erase files or release the execution slot while a
                    # child may still use them. The worker must exit; startup
                    # recovery checks workspace ownership before requeuing.
                    self.stop_event.set()
                    error = f'analyzer termination failed: {exc}'[:2000]
                    with self.store._db() as db:
                        db.execute("UPDATE scan_runs SET error=? WHERE run_id=? AND status IN ('running','cancelling')", (error, run_id))
                    self.store.record_audit('portal-worker', 'scan.termination_failed', {'run_id': run_id, 'error': error})
                    raise OSError('portal analyzer termination incomplete') from exc
            errors = cleanup_workspaces(work_root, run_id)
            state = run_state(self.store, run_id)
            if errors:
                log.error('Run %s cleanup incomplete: %s', run_id, errors)
            if state['status'] not in TERMINAL_RUN_STATUSES:
                if reason == 'shutdown' and not state['cancel_requested']:
                    # Keep its original input and position for a later owner.
                    with self.store._db() as db:
                        db.execute("UPDATE scan_runs SET status='queued',stage='queued',progress=0 WHERE run_id=? AND status='running' AND cancel_requested=0", (run_id,))
                else:
                    self.store.complete_run(run_id, error=reason or 'analyzer exited without a result')
            if errors:
                self.store.record_audit('portal-worker', 'scan.workspace_cleanup_failed', {'run_id': run_id, 'errors': errors})
                # Do not accumulate more copies when the filesystem cannot
                # reclaim this one. Restart recovery must clear the workspace.
                raise OSError('portal workspace cleanup incomplete')
        return True


def ensure_delivery_queue(store: PortalStore) -> None:
    with store._db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS portal_delivery_jobs(
            job_id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL,
            kind TEXT NOT NULL, retry INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'queued', error TEXT,
            FOREIGN KEY(run_id) REFERENCES scan_runs(run_id))""")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_portal_delivery_active ON portal_delivery_jobs(run_id,kind) WHERE status IN ('queued','running')")


def enqueue_delivery(store: PortalStore, kind: str, run_id: str, *, retry: bool = False) -> dict:
    if kind not in {'tracker', 'gitlab_result', 'issues'}:
        raise ValueError('invalid publication kind')
    if run_state(store, run_id)['status'] != 'completed':
        raise ValueError('completed run required for publication')
    if retry:
        current = store.gitlab_issue_delivery(run_id) if kind == 'issues' else store.tracker_delivery(run_id)
        status = (current or {}).get('gitlab_result_status' if kind == 'gitlab_result' else 'status')
        allowed = {'failed', 'partial'} if kind == 'issues' else ({'failed', 'pending'} if kind == 'gitlab_result' else {'failed'})
        if status not in allowed:
            raise ValueError('publication is not retryable')
    ensure_delivery_queue(store)
    with store._db() as db:
        db.execute("INSERT OR IGNORE INTO portal_delivery_jobs(run_id,kind,retry) VALUES(?,?,?)", (run_id, kind, int(retry)))
        row = db.execute("SELECT job_id,status FROM portal_delivery_jobs WHERE run_id=? AND kind=? AND status IN ('queued','running')", (run_id, kind)).fetchone()
    return {'job_id': row['job_id'], 'status': row['status'], 'run_id': run_id, 'kind': kind}


def next_publication(store: PortalStore) -> tuple[str, str, bool, int | None] | None:
    """Already-completed scans are a durable outbox; retries have explicit jobs."""
    with store._db() as db:
        row = db.execute("SELECT * FROM portal_delivery_jobs WHERE status='queued' ORDER BY job_id LIMIT 1").fetchone()
        if row:
            return row['kind'], row['run_id'], bool(row['retry']), row['job_id']
        row = db.execute("""SELECT d.run_id FROM tracker_deliveries d JOIN scan_runs r USING(run_id)
            WHERE d.status='pending' AND r.status='completed' AND r.deleted_at IS NULL
            AND r.run_id NOT IN (SELECT run_id FROM schedule_runs WHERE run_id IS NOT NULL)
            ORDER BY r.created_at LIMIT 1""").fetchone()
        if row:
            return 'tracker', row[0], False, None
        row = db.execute("""SELECT d.run_id FROM gitlab_issue_deliveries d JOIN scan_runs r USING(run_id)
            WHERE d.status='pending' AND r.status='completed' AND r.deleted_at IS NULL
            AND r.run_id NOT IN (SELECT run_id FROM schedule_runs WHERE run_id IS NOT NULL)
            ORDER BY r.created_at LIMIT 1""").fetchone()
        if row:
            return 'issues', row[0], False, None
        row = db.execute("""SELECT d.run_id FROM tracker_deliveries d JOIN scan_runs r USING(run_id)
            WHERE d.gitlab_result_status='pending' AND d.status='completed' AND r.status='completed' AND r.deleted_at IS NULL
            AND r.run_id NOT IN (SELECT run_id FROM schedule_runs WHERE run_id IS NOT NULL)
            ORDER BY r.created_at LIMIT 1""").fetchone()
        if row:
            return 'gitlab_result', row[0], False, None
    return None


def process_publication(store: PortalStore, job) -> None:
    from .linux_portal import _run_delivery
    kind, run_id, retry, job_id = job
    if job_id:
        with store._db() as db:
            db.execute("UPDATE portal_delivery_jobs SET status='running' WHERE job_id=?", (job_id,))
    error = None
    try:
        current = store.gitlab_issue_delivery(run_id) if kind == 'issues' else store.tracker_delivery(run_id)
        status = (current or {}).get('gitlab_result_status' if kind == 'gitlab_result' else 'status')
        # A prior worker may have committed the remote acknowledgement before
        # committing this job. Sending rows are reset to pending by its owner.
        if status != 'completed':
            published = _run_delivery(store, kind, run_id, retry=retry and status != 'pending')
            status_key = 'gitlab_result_status' if kind == 'gitlab_result' else 'status'
            published_status = published.get(status_key, published.get('status'))
            if published_status not in {'completed', 'skipped'}:
                error_key = 'gitlab_result_error' if kind == 'gitlab_result' else 'error'
                error = str(published.get(error_key) or f'publication {published_status or "incomplete"}')[:1000]
    except Exception as exc:
        error = str(exc)[:1000]
        log.warning('Run %s %s publication failed: %s', run_id, kind, exc)
    if job_id:
        with store._db() as db:
            db.execute("UPDATE portal_delivery_jobs SET status=?,error=? WHERE job_id=?", ('failed' if error else 'completed', error, job_id))


def recover_scheduled_publications(store: PortalStore) -> None:
    # The external delivery owner replaces the web-side schedule tick thread.
    with store._db() as db:
        for table, column in (('tracker_deliveries', 'status'), ('tracker_deliveries', 'gitlab_result_status'),
                              ('gitlab_issue_deliveries', 'status')):
            db.execute(f"UPDATE {table} SET {column}='pending' WHERE {column}='sending' AND run_id IN (SELECT run_id FROM schedule_runs)")


def process_scheduled_publications(store: PortalStore) -> None:
    from .schedule_worker import ScheduleRunner
    # Reuse the cleanup gate, retry delays and schedule status projection.
    ScheduleRunner(store).retry_deliveries()
    store.prune_schedule_runs(90)
    with store._db() as db:
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schedule_api_receipts'").fetchone():
            db.execute("DELETE FROM schedule_api_receipts WHERE schedule_run_id NOT IN (SELECT schedule_run_id FROM schedule_runs)")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', default=os.environ.get('KODA_PORTAL_DB', 'koda-portal.sqlite3'))
    parser.add_argument('--role', choices=('scan', 'delivery'), default=os.environ.get('KODA_PORTAL_WORKER_ROLE', 'scan'))
    parser.add_argument('--healthcheck', action='store_true')
    parser.add_argument('--analyze-run')
    parser.add_argument('--parent', type=int)
    args = parser.parse_args(argv)
    if args.analyze_run:
        if not args.parent:
            parser.error('--analyze-run requires --parent')
        from .process_limits import bind_parent_lifetime, apply_limits
        bind_parent_lifetime(args.parent)
        apply_limits({'cpu_limit': int(os.environ.get('KODA_SCAN_CPU_LIMIT', '1')),
                      'memory_limit_bytes': int(os.environ.get('KODA_SCAN_MEMORY_BYTES', str(4 * 1024**3)))})
        store = PortalStore(args.db)
        from .linux_portal import _run_scan
        _run_scan(store, args.analyze_run, claimed=True, deliver=False)
        return 0
    if args.healthcheck:
        return 0 if worker_healthy(args.db, args.role) else 1
    store = PortalStore(args.db)
    from .linux_portal import _PortalWorker
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    worker = _PortalWorker(store, role=args.role, isolated=True)
    try:
        while not stop.wait(.25):
            if not worker.available:
                return 1
    finally:
        worker.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
