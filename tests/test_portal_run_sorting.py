"""Run ownership and server-side ordering apply before pagination."""
import tempfile
import unittest
import uuid
from pathlib import Path

from security_scanner.portal_store import PortalStore


class RunSortingTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.store = PortalStore(self.root / 'portal.sqlite')
        self.actor = str(uuid.uuid4())
        self.other = str(uuid.uuid4())
        # Equal display names must never conflate ownership.
        for actor in (self.actor, self.other):
            self.store.ensure_subject(actor, 'same-name')
            self.store.set_subject(actor, status='enabled', system_admin=True)
        self.project = self.store.create_project('Zulu', self.actor)
        self.second = self.store.create_project('Alpha', self.actor)
        target = self.root / 'input.py'
        target.write_text('print(1)')
        self.input_ids = {project: self.store.add_input(project, target.name, target, self.actor)
                          for project in (self.project, self.second)}

    def run_row(self, actor, project=None):
        project = project or self.project
        return self.store.create_scan(actor, project, self.input_ids[project], 'local', 'all', 'source')

    def test_owner_is_exact_and_filtered_before_count_and_pages(self):
        rows = [self.run_row(self.actor), self.run_row(self.other), self.run_row(self.actor)]
        page = self.store.paginate_runs([self.project], requested_by=self.actor,
                                        sort_by='round_number', sort_order='asc', page_size=1, page=2)
        self.assertEqual(page['total'], 2)
        self.assertEqual([r['run_id'] for r in page['items']], [rows[2]['run_id']])
        # The filter can only narrow the supplied accessible project set.
        self.assertEqual(self.store.paginate_runs([self.second], requested_by=self.actor)['total'], 0)
        self.assertEqual(self.store.paginate_runs([self.project], requested_by='missing')['total'], 0)

    def test_global_sort_precedes_pagination_and_does_not_group_by_project(self):
        zulu = self.run_row(self.actor)
        alpha = self.run_row(self.actor, self.second)
        projects = [self.project, self.second]
        for order, expected in [('asc', [alpha, zulu]), ('desc', [zulu, alpha])]:
            pages = [self.store.paginate_runs(projects, sort_by='project', sort_order=order,
                                              page_size=1, page=index)['items'][0]['run_id']
                     for index in (1, 2)]
            self.assertEqual(pages, [row['run_id'] for row in expected])
        for key in ('round_number', 'project', 'source', 'requested_by', 'scope', 'standard', 'status', 'created_at'):
            self.assertEqual(self.store.paginate_runs(projects, sort_by=key)['total'], 2)

    def test_multiple_sort_priorities_and_directions_apply_across_pages(self):
        zulu_first = self.run_row(self.actor)
        alpha_first = self.run_row(self.actor, self.second)
        zulu_second = self.run_row(self.actor)
        alpha_second = self.run_row(self.actor, self.second)
        projects = [self.project, self.second]
        expected = [alpha_second, alpha_first, zulu_second, zulu_first]
        actual = [self.store.paginate_runs(projects, sort_by='project,round_number',
                                          sort_order='asc,desc', page_size=1, page=page)['items'][0]['run_id']
                  for page in range(1, 5)]
        self.assertEqual(actual, [row['run_id'] for row in expected])
        # Reversing priority changes the global order, not just the current page.
        expected = [zulu_second, alpha_second, zulu_first, alpha_first]
        listing = self.store.paginate_runs(projects, sort_by='round_number,project', sort_order='desc,desc')
        self.assertEqual([row['run_id'] for row in listing['items']], [row['run_id'] for row in expected])
        keys = 'round_number,project,source,requested_by,scope,standard,status,created_at'
        self.assertEqual(self.store.paginate_runs(projects, sort_by=keys,
                                                 sort_order=','.join(['asc'] * 8))['total'], 4)
        self.assertEqual(self.store._runs_order('', 'desc'), 'r.created_at DESC,r.round_number DESC,r.run_id')

    def test_scheduled_multiple_sort_priorities_apply_before_paging(self):
        expected_by_project = {}
        for project in (self.project, self.second):
            target = self.store.save_schedule_target({
                'project_id': project, 'name': 'server', 'host': 'server.internal', 'username': 'scan',
                'ssh_key_ref': '/run/koda/ssh/key', 'known_hosts_file': '/run/koda/ssh/known_hosts',
                'remote_directory': '/srv/app', 'scan_scope': 'source', 'enabled': True,
            }, self.actor)
            expected_by_project[project] = [
                self.store.begin_schedule_run(target['target_id'], day, 'full', target['config_version'])['schedule_run_id']
                for day in ('2026-10-21', '2026-10-20')
            ]
        projects = [self.project, self.second]
        actual = [self.store.paginate_schedule_runs(projects, sort_by='project,round_number',
                                                    sort_order='asc,desc', page_size=1, page=page)['items'][0]['schedule_run_id']
                  for page in range(1, 5)]
        self.assertEqual(actual, expected_by_project[self.second] + expected_by_project[self.project])
        listing = self.store.paginate_schedule_runs(projects, sort_by='round_number,project', sort_order='asc,desc')
        self.assertEqual([row['schedule_run_id'] for row in listing['items']], [
            expected_by_project[self.project][1], expected_by_project[self.second][1],
            expected_by_project[self.project][0], expected_by_project[self.second][0],
        ])

    def test_sort_input_is_validated_even_for_empty_access(self):
        for method in (self.store.paginate_runs, self.store.paginate_schedule_runs):
            for ids in ([], [self.project]):
                for options in (
                    {'sort_by': 'created_at; DROP TABLE scan_runs'}, {'sort_order': 'DESC;--'},
                    {'sort_by': 'project,status', 'sort_order': 'asc'},
                    {'sort_by': 'project', 'sort_order': 'asc,desc'},
                    {'sort_by': 'project,project', 'sort_order': 'asc,desc'},
                    {'sort_by': 'project,unknown', 'sort_order': 'asc,desc'},
                    {'sort_by': 'project,status', 'sort_order': 'asc,desc;--'},
                    {'sort_by': 'project,', 'sort_order': 'asc,desc'},
                    {'sort_by': '', 'sort_order': 'asc,desc'},
                    {'sort_by': ','.join(['project'] * 9), 'sort_order': ','.join(['asc'] * 9)},
                ):
                    with self.assertRaises(ValueError):
                        method(ids, **options)

    def test_scheduled_owner_is_execution_actor_not_target_creator(self):
        target = self.store.save_schedule_target({
            'project_id': self.project, 'name': 'server', 'host': 'server.internal', 'username': 'scan',
            'ssh_key_ref': '/run/koda/ssh/key', 'known_hosts_file': '/run/koda/ssh/known_hosts',
            'remote_directory': '/srv/app', 'scan_scope': 'source', 'enabled': True,
        }, self.actor)
        scheduled = []
        for day in ('2026-10-21', '2026-10-20'):
            record = self.store.begin_schedule_run(target['target_id'], day, 'full', target['config_version'])
            self.store.create_scheduled_scan(self.project, self.input_ids[self.project], 'local', 'all', 'source', {
                'source_type': 'scheduled_server', 'schedule_run_id': record['schedule_run_id'],
                'schedule_target_id': target['target_id'], 'scheduled_for': day,
            })
            scheduled.append(record)
        projects = [self.project]
        self.assertEqual(self.store.paginate_schedule_runs(projects, requested_by=self.actor)['total'], 0)
        self.assertEqual(self.store.paginate_schedule_runs(projects, requested_by='schedule-worker')['total'], 2)
        page = self.store.paginate_schedule_runs(projects, sort_by='round_number', sort_order='asc', page_size=1)
        self.assertEqual(page['items'][0]['schedule_run_id'], scheduled[1]['schedule_run_id'])
        for key in ('round_number', 'project', 'source', 'requested_by', 'scope', 'standard', 'status', 'created_at'):
            self.assertEqual(self.store.paginate_schedule_runs(projects, sort_by=key)['total'], 2)
        # Queued schedule runs without a scan execution do not belong to a user.
        self.store.begin_schedule_run(target['target_id'], '2026-10-22', 'full', target['config_version'])
        self.assertEqual(self.store.paginate_schedule_runs(projects)['total'], 3)
        self.assertEqual(self.store.paginate_schedule_runs(projects, requested_by=self.actor)['total'], 0)


if __name__ == '__main__':
    unittest.main()
