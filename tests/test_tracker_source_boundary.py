import io
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

import test_linux_portal as portal_tests
from security_scanner.linux_portal import _deliver_tracker, _deliver_gitlab_result
from security_scanner.portal_integrations import send_tracker_sbom, IntegrationError, _gitlab_scan_report


class TrackerSourceBoundaryTests(unittest.TestCase):
    setUp = portal_tests.LinuxPortalStoreTests.setUp
    tearDown = portal_tests.LinuxPortalStoreTests.tearDown
    gitlab_run = portal_tests.LinuxPortalStoreTests.gitlab_run

    def test_source_only_skips_tracker_and_preserves_gitlab_with_retry(self):
        run = self.gitlab_run([{'category': 'code', 'title': 'source-only-marker'}])
        with patch('security_scanner.linux_portal.send_tracker_sbom') as send, \
             patch('security_scanner.linux_portal.fetch_tracker_result') as fetch, \
             patch('security_scanner.linux_portal.publish_tracker_result', side_effect=[OSError('GitLab down'), {'mergeRequestUrl': 'https://gitlab/mr/1'}]) as publish:
            result = _deliver_tracker(self.store, run['run_id'])
            self.assertEqual(result['status'], 'skipped')
            self.assertEqual(result['gitlab_result_status'], 'failed')
            result = _deliver_gitlab_result(self.store, run['run_id'], retry=True)
            self.assertEqual(result['gitlab_result_status'], 'completed')
            _deliver_tracker(self.store, run['run_id'], retry=True)
            send.assert_not_called()
            fetch.assert_not_called()
            self.assertEqual(publish.call_count, 2)
            self.assertEqual(result['attempts'], 0)
        self.assertIn('source-only-marker', json.dumps(_gitlab_scan_report(run, '', {})))

    def test_low_level_source_sender_blocks_before_reading_credentials(self):
        with patch('security_scanner.portal_integrations._secret') as secret, \
             patch('security_scanner.portal_integrations.build_opener') as opener:
            with self.assertRaises(IntegrationError):
                send_tracker_sbom({}, {'snapshot': {'scan_scope': 'source'}})
            secret.assert_not_called()
            opener.assert_not_called()

    def test_combined_scan_posts_sbom_only_not_source_findings(self):
        run = self.gitlab_run([{'category': 'code', 'title': 'source-only-marker', 'evidence': 'private-source-code'}], scope='all')
        mapping = self.store.gitlab_repositories(self.project)[0]
        token_dir = Path(self.tmp.name) / 'tokens'
        token_dir.mkdir()
        (token_dir / 'demo.token').write_text('test-token')
        opener = Mock()
        opener.open.return_value = io.BytesIO(b'{"runId":"tracker-library"}')
        with patch.dict(os.environ, {'KODA_TRACKER_URL': 'http://tracker.invalid', 'KODA_TRACKER_TOKEN_DIR': str(token_dir)}), \
             patch('security_scanner.portal_integrations.build_opener', return_value=opener):
            self.assertEqual(send_tracker_sbom(mapping, run), 'tracker-library')
        body = opener.open.call_args.args[0].data
        self.assertIn(b'koda.cdx.json', body)
        self.assertIn(b'components', body)
        self.assertNotIn(b'source-only-marker', body)
        self.assertNotIn(b'private-source-code', body)


class ScheduledTrackerSourceBoundaryTests(unittest.TestCase):
    import test_schedule_worker as fixture
    setUp = fixture.ScheduleWorkerTests.setUp
    tearDown = fixture.ScheduleWorkerTests.tearDown
    runner = fixture.ScheduleWorkerTests.runner
    mapped_target = fixture.ScheduleWorkerTests.mapped_target

    def test_scheduled_source_skips_tracker_after_cleanup(self):
        runner, target = self.runner(), self.mapped_target()
        def analyze(run_id, deadline):
            self.store.mark_run_running(run_id)
            self.store.complete_run(run_id, result={'findings': [], 'sbom': {'components': []}})
        def publish(*args, **kwargs):
            self.assertFalse(list(runner.work_dir.iterdir()))
            return {'mergeRequestUrl': 'https://gitlab/mr/1'}
        with patch.object(runner, '_analyze', side_effect=analyze), \
             patch('security_scanner.linux_portal.send_tracker_sbom') as send, \
             patch('security_scanner.linux_portal.fetch_tracker_result') as fetch, \
             patch('security_scanner.linux_portal.publish_tracker_result', side_effect=publish):
            result = runner.run_target(target, scheduled_for='2026-09-07')
            runner.retry_deliveries()
        self.assertEqual(result['cleanup_status'], 'completed')
        self.assertEqual(self.store.tracker_delivery(result['run_id'])['status'], 'skipped')
        self.assertEqual(self.store.tracker_delivery(result['run_id'])['gitlab_result_status'], 'completed')
        send.assert_not_called()
        fetch.assert_not_called()
