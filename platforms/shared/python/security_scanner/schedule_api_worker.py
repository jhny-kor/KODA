"""Isolated schedule worker: only results cross the authenticated portal API."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

from .schedule_api import API_PREFIX, ScheduleApiClient, ScheduleApiError
from .schedule_transport import OpenSSHCollector, RemoteFile, _retryable_remote_error


def _save(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, ensure_ascii=False, allow_nan=False)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


class ApiScheduleRunner:
    def __init__(self, client=None, *, work_dir=None, state_dir=None, worker_id=None, collector=None, sleep=time.sleep):
        self.client = client or ScheduleApiClient()
        self.state_dir = Path(state_dir or os.environ.get('KODA_SCHEDULE_STATE_DIR', '/var/lib/koda-schedule'))
        self.work_dir = Path(work_dir or os.environ.get('KODA_SCHEDULE_WORK_DIR', str(self.state_dir / 'work')))
        for directory in (self.state_dir, self.work_dir):
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
        identity = self.state_dir / 'worker-id.json'
        if worker_id:
            self.worker_id = worker_id
        elif identity.exists():
            self.worker_id = json.loads(identity.read_text())['worker_id']
        else:
            self.worker_id = uuid.uuid4().hex
            _save(identity, {'worker_id': self.worker_id})
        self.active = self.state_dir / 'active.json'
        self.outbox = self.state_dir / 'outbox.json'
        self.collector = collector or OpenSSHCollector()
        self.sleep = sleep
        self.settings = {}

    def _api(self, action, job=None, **fields):
        payload = ({'schedule_run_id': job['schedule_run_id'], 'lease_token': job['lease_token']} if job else {})
        return self.client.request('POST', API_PREFIX + '/' + action, payload | fields)

    def _clean(self):
        for path in self.work_dir.iterdir():
            if path.is_symlink() or not path.is_dir():
                path.unlink()
            else:
                shutil.rmtree(path)
        if any(self.work_dir.iterdir()):
            raise OSError('scheduled source cleanup incomplete')

    def recover(self):
        """No new collection until cleanup and the durable outbox are acknowledged."""
        record = json.loads(self.outbox.read_text()) if self.outbox.exists() else None
        job = record['job'] if record else json.loads(self.active.read_text()) if self.active.exists() else None
        if not job:
            self._clean()
            return None
        try:
            self._clean()
        except OSError as exc:
            self._api('cleanup', job, success=False, error=str(exc)[:1000])
            return {'status': 'cleanup_failed'}
        if record and 'result' in record:
            try:
                self._api('persist', job, result=record['result'], manifest=record['manifest'], counts=record['counts'])
            except ScheduleApiError as exc:
                if exc.status not in {409, 413, 422}:
                    raise
                failure = {'error': str(exc), 'cancelled': exc.status == 409, 'retryable': False}
                _save(self.outbox, {'job': job, 'failure': failure})
                self._api('fail', job, **failure)
        elif not job.get('run_id'):
            failure = record.get('failure') if record else None
            self._api('fail', job, **(failure or {'error': 'Worker restarted before result persistence; recollecting', 'cancelled': False, 'retryable': True}))
        value = self._api('cleanup', job, success=True, error='')
        self.outbox.unlink(missing_ok=True)
        self.active.unlink(missing_ok=True)
        self._api('tick')
        return value

    def _heartbeat(self, job, deadline):
        if time.monotonic() >= deadline:
            raise TimeoutError('scheduled directory deadline exceeded')
        state = self._api('heartbeat', job)
        if state['cancel_requested']:
            raise InterruptedError('scheduled scan cancelled')
        return state

    def _retry(self, operation, job, deadline):
        for attempt in range(4):
            try:
                return operation()
            except Exception as exc:
                if attempt == 3 or not _retryable_remote_error(exc) or isinstance(exc, InterruptedError):
                    raise
                until = time.monotonic() + (60, 300, 900)[attempt]
                if until >= deadline:
                    raise TimeoutError('scheduled retry exceeds directory deadline') from exc
                while time.monotonic() < until:
                    self._heartbeat(job, deadline)
                    self.sleep(min(1, until - time.monotonic()))

    def _analyze(self, source, root, context, job, deadline):
        _save(root / 'context.json', context)
        process = subprocess.Popen([sys.executable, '-m', 'security_scanner.schedule_api_worker',
                                    '--analyze', str(source), '--context', str(root / 'context.json'),
                                    '--result', str(root / 'result.json'), '--parent', str(os.getpid())], start_new_session=True)
        try:
            while process.poll() is None:
                self._heartbeat(job, deadline)
                self.sleep(1)
            if process.returncode:
                raise RuntimeError(f'scheduled analyzer exited {process.returncode}')
            result_path = root / 'result.json'
            if result_path.stat().st_size > 32 * 1024 * 1024:
                raise ValueError('scheduled result exceeds API result size limit')
            return json.loads(result_path.read_text())
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()

    def run_once(self):
        if self.active.exists() or self.outbox.exists():
            return self.recover()
        self._clean()
        self._api('tick')
        response = self._api('next', worker_id=self.worker_id)
        self.settings = response['settings']
        job = response.get('job')
        if not job:
            return None
        _save(self.active, job)
        # A lease returned after local state loss is cleaned/requeued; already
        # persisted results must never be silently replaced by a new analysis.
        if job.get('stage') in {'persisted', 'failed', 'cancelled', 'recollect'}:
            return self.recover()
        target = dict(job['target'])
        target['disabled_rules'] = sorted(set(target['disabled_rules']) | set(job['policy']['disabled_rules']))
        target['transfer_rate_bytes_per_sec'] = self.settings['rate_bytes_per_sec']
        target['min_free_bytes'] = self.settings['min_free_bytes']
        root = self.work_dir / ('koda-schedule-' + job['schedule_run_id'])
        source = root / 'files'
        source.mkdir(parents=True)
        deadline = time.monotonic() + int(target['timeout_seconds'])
        last_check = [0, None]
        def cancelled():
            if time.monotonic() - last_check[0] > 1:
                last_check[:] = [time.monotonic(), self._heartbeat(job, deadline)]
            return False
        def current_target():
            self._heartbeat(job, deadline)
            return target | {'timeout_seconds': max(.01, deadline - time.monotonic())}
        try:
            if shutil.disk_usage(self.work_dir).free < target['max_bytes'] * 3 + self.settings['min_free_bytes']:
                raise OSError('insufficient scheduled disk space')
            collector = self.collector
            if target.get('source_kind') == 'gitlab':
                from .schedule_gitlab import GitLabCollector
                collector = GitLabCollector(self.client, job, cache_dir=root, sleep=self.sleep)
            def collect_files():
                if target.get('source_kind') == 'gitlab' and hasattr(collector, 'reset'):
                    collector.reset()
                return collector.list_files(current_target(), cancel=cancelled)
            files = self._retry(collect_files, job, deadline)
            baseline = job['baseline']
            source_hashes = getattr(collector, 'hashes', {})
            changed = [item for item in files if job['mode'] == 'full' or item.relative_path not in baseline or
                       (target.get('source_kind') == 'gitlab' and source_hashes.get(item.relative_path) != baseline[item.relative_path].get('sha256')) or
                       (target.get('source_kind') != 'gitlab' and (item.size != baseline[item.relative_path]['size'] or item.mtime != baseline[item.relative_path]['mtime']))]
            deleted = sorted(set(baseline) - {item.relative_path for item in files})
            from .schedule_worker import ScheduleRunner
            selected = {item.relative_path: item for item in changed}
            if job['mode'] == 'changed' and target['scan_scope'] in {'all', 'library'}:
                selected.update({item.relative_path: item for item in files if ScheduleRunner._dependency_manifest(item)})
            if len(files) > target['max_files'] or sum(item.size for item in selected.values()) > target['max_bytes']:
                raise ValueError('scheduled collection limit exceeded')
            hashes, remaining = {}, target['max_bytes']
            for item in selected.values():
                if item.size > remaining or shutil.disk_usage(self.work_dir).free < item.size + self.settings['min_free_bytes']:
                    raise OSError('scheduled collection disk or byte limit exceeded')
                destination = source / item.relative_path
                self._retry(lambda: collector.fetch(current_target() | {'remaining_bytes': remaining}, item, destination, cancel=cancelled), job, deadline)
                hashes[item.relative_path] = _hash(destination)
                remaining -= destination.stat().st_size
            while True:
                state = self._heartbeat(job, deadline)
                if not state['manual_busy'] and state['settings']['enabled']:
                    self.settings = state['settings']
                    break
                self.sleep(1)
            result = self._analyze(source, root, {'target': target, 'settings': self.settings}, job, deadline)
            self._heartbeat(job, deadline)
            manifest = [{'relative_path': f.relative_path, 'size': f.size, 'mtime': f.mtime,
                         'sha256': hashes.get(f.relative_path) or baseline.get(f.relative_path, {}).get('sha256', '')} for f in files]
            counts = {'files_total': len(files), 'changed_files': len(changed) + len(deleted),
                      'changed_paths': [f.relative_path for f in changed] + deleted}
            record = {'job': job, 'result': result, 'manifest': manifest, 'counts': counts}
            _save(self.outbox, record)
            self._api('persist', job, result=result, manifest=manifest, counts=counts)
        except Exception as exc:
            if not self.outbox.exists():
                _save(self.outbox, {'job': job, 'failure': {'error': str(exc)[:1000],
                      'cancelled': isinstance(exc, InterruptedError), 'retryable': isinstance(exc, (ScheduleApiError, OSError)) and not isinstance(exc, (InterruptedError, TimeoutError))}})
        finally:
            # Even API failure cannot retain original files. The result-only
            # outbox is fsynced first and can be submitted on the next tick.
            try:
                self._clean()
            except OSError as exc:
                try:
                    self._api('cleanup', job, success=False, error=str(exc)[:1000])
                except ScheduleApiError:
                    pass
        return self.recover()

    def run_forever(self):
        while True:
            try:
                processed = self.run_once()
            except (ScheduleApiError, OSError):
                processed = None
            self.sleep(max(1, self.settings.get('gap_seconds', 30)) if processed else 60)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--analyze', required=True)
    parser.add_argument('--context', required=True)
    parser.add_argument('--result', required=True)
    parser.add_argument('--parent', type=int, required=True)
    args = parser.parse_args()
    from .process_limits import apply_limits, bind_parent_lifetime
    bind_parent_lifetime(args.parent)
    context = json.loads(Path(args.context).read_text())
    # Engine temporary files belong to the same cleanup boundary as sources.
    import tempfile
    temporary = Path(args.context).parent / 'tmp'
    temporary.mkdir(mode=0o700, exist_ok=True)
    tempfile.tempdir = str(temporary)
    os.environ['TMPDIR'] = str(temporary)
    effective = apply_limits(context['settings'])
    from .server import scan_directory_payload
    from .linux_portal import _analysis_stages
    target = context['target']
    result = scan_directory_payload(args.analyze, language='ko', standard=target['standard'],
                                   standard_category=target['standard_category'], disabled_rules=tuple(target['disabled_rules']),
                                   allow_file=True, display_path=(target.get('remote_directory') or target.get('source_gitlab_directory') or 'GitLab source'), scan_scope=target['scan_scope'],
                                   enable_local_vulnerabilities=target['scan_scope'] in {'all', 'library'}, cve_only=target['scan_scope'] == 'library')
    result['findings'] = result.get('findings_by_language', {}).get('ko', [])
    result['analysis_stages'] = _analysis_stages(result, target['scan_scope'])
    result['analysis_overall'] = 'partial' if any(s['status'] in {'failed', 'warning'} for s in result['analysis_stages'].values()) else 'completed'
    result['scheduled_resources'] = effective
    _save(Path(args.result), result)


if __name__ == '__main__':
    main()
