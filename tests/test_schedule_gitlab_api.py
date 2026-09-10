import io
import tarfile
import unittest
from unittest.mock import patch

import test_schedule_api as api_tests
from security_scanner.schedule_api import API_PREFIX, ScheduleApiError
from security_scanner.portal_integrations import _gitlab_scan_report


class Archive(io.BytesIO):
    headers = {'Content-Type': 'application/gzip'}


class GitLabScheduleApiTests(unittest.TestCase):
    setUp = api_tests.ScheduleApiTests.setUp
    tearDown = api_tests.ScheduleApiTests.tearDown
    next = api_tests.ScheduleApiTests.next
    runner = api_tests.ScheduleApiTests.runner

    def prepare_gitlab(self):
        mapping = self.store.set_gitlab_repositories(self.project, [{
            'gitlab_project_id': 7, 'path_with_namespace': 'team/app', 'name': 'app',
            'default_branch': 'main', 'tracker_service_id': 'svc', 'tracker_environment_id': 'env',
            'tracker_token_ref': 'private-ref',
        }])[0]
        self.target = self.store.save_schedule_target(self.target | {
            'source_kind': 'gitlab', 'source_gitlab_mapping_id': mapping['mapping_id'],
            'source_gitlab_ref': 'main', 'source_gitlab_directory': '/src', 'max_bytes': 1024 * 1024,
        })
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w:gz') as tar:
            for path, content in [('app-sha/src/app.py', b'print(1)\n'), ('app-sha/other.py', b'excluded')]:
                member = tarfile.TarInfo(path)
                member.size = len(content)
                tar.addfile(member, io.BytesIO(content))
        return raw.getvalue()

    def test_gitlab_http_collection_analysis_persist_and_cleanup(self):
        raw = self.prepare_gitlab()
        with patch('security_scanner.schedule_gitlab_proxy.resolve_gitlab_ref', return_value='a' * 40) as resolve, \
             patch('security_scanner.schedule_gitlab_proxy._gitlab_open', side_effect=lambda *a, **k: Archive(raw)):
            runner = self.runner()
            result = runner.run_once()
        self.assertEqual(result['status'], 'completed', result)
        self.assertFalse(list(runner.work_dir.iterdir()))
        self.assertEqual(list((self.root / 'inputs').iterdir()), [])
        self.assertEqual(list(self.store.baseline_schedule_files(self.target['target_id'])), ['app.py'])
        run = self.store.run(result['run_id'])
        self.assertEqual(run['snapshot']['source_gitlab_commit_sha'], 'a' * 40)
        self.assertEqual(_gitlab_scan_report(run, '', {})['source']['type'], 'scheduled_gitlab')
        self.assertEqual(resolve.call_args.args[1:3], ('branch', 'main'))
        self.store.begin_schedule_run(self.target['target_id'], '2026-09-10', 'changed', self.target['config_version'])
        # A different commit timestamp with identical content is not a change.
        modified = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as before, tarfile.open(fileobj=modified, mode='w:gz') as after:
            for member in before:
                member.mtime = 123456
                after.addfile(member, before.extractfile(member))
        with patch('security_scanner.schedule_gitlab_proxy.resolve_gitlab_ref', return_value='b' * 40), \
             patch('security_scanner.schedule_gitlab_proxy._gitlab_open', side_effect=lambda *a, **k: Archive(modified.getvalue())):
            delta = runner.run_once()
        self.assertEqual(delta['mode'], 'changed')
        self.assertEqual(delta['changed_files'], 0)
        self.assertEqual(delta['status'], 'completed')
        self.assertFalse(list(runner.work_dir.iterdir()))

    def test_archive_rejects_wrong_lease_and_arbitrary_source(self):
        self.prepare_gitlab()
        job = self.next()
        with patch('security_scanner.schedule_gitlab_proxy._gitlab_open') as upstream:
            for payload, status in [({'schedule_run_id': job['schedule_run_id'], 'lease_token': 'bad'}, 403),
                                    ({'schedule_run_id': job['schedule_run_id'], 'lease_token': job['lease_token'], 'source_gitlab_mapping_id': 'other'}, 422)]:
                with self.assertRaises(ScheduleApiError) as caught:
                    self.client.request('POST', API_PREFIX + '/gitlab-archive', payload)
                self.assertEqual(caught.exception.status, status)
            upstream.assert_not_called()
