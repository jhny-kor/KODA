import datetime as dt
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_scanner.schedule_timing import KST, due_slot
from security_scanner.schedule_api import _ensure, _next
from security_scanner.schedule_settings import save_settings
from security_scanner.portal_store import PortalStore


class ScheduleTimingTests(unittest.TestCase):
    def test_daily_weekly_hourly_boundaries_and_timezone(self):
        now = dt.datetime(2026, 9, 9, 3, 29, tzinfo=dt.timezone.utc)
        self.assertIsNone(due_slot({'schedule_time': '12:30'}, now))
        now += dt.timedelta(minutes=1)
        self.assertEqual(due_slot({'schedule_time': '12:30'}, now), '2026-09-09T12:30+09:00')
        weekly = dict(schedule_frequency='weekly', schedule_time='12:30', schedule_weekdays=[0, 4])
        self.assertIsNone(due_slot(weekly, now))
        weekly['schedule_weekdays'] = [2]
        self.assertEqual(due_slot(weekly, now), '2026-09-09T12:30+09:00')
        hourly = dict(schedule_frequency='hourly', schedule_time='01:15', schedule_interval_hours=4)
        self.assertEqual(due_slot(hourly, now), '2026-09-09T09:15+09:00')
        self.assertEqual(due_slot({}, now), '2026-09-09')

    def test_new_or_edited_target_does_not_backfill(self):
        now = dt.datetime(2026, 9, 9, 14, tzinfo=KST)
        self.assertIsNone(due_slot({'updated_at': '2026-09-09T03:00:00+00:00'}, now))

    def test_independent_targets_and_duplicate_polling(self):
        with tempfile.TemporaryDirectory() as root:
            store = PortalStore(Path(root) / 'portal.sqlite3')
            project = store.create_project('timing')
            base = dict(project_id=project, name='morning', host='example.internal', username='scan',
                        ssh_key_ref='/run/key', known_hosts_file='/run/hosts', remote_directory='/srv/app', enabled=True)
            first = store.save_schedule_target(base)
            second = store.save_schedule_target(base | {'name': 'afternoon', 'schedule_time': '15:00'})
            with store._db() as db:
                db.execute("UPDATE schedule_targets SET updated_at='2026-09-01T00:00:00+00:00'")
            save_settings(store, {'enabled': True})
            _ensure(store)
            class Clock(dt.datetime):
                @classmethod
                def now(cls, tz=None):
                    return cls(2026, 9, 9, 14, tzinfo=KST)
            with patch('security_scanner.schedule_api.dt.datetime', Clock):
                job = _next(store, 'test')['job']
                self.assertEqual(job['target']['target_id'], first['target_id'])
                self.assertEqual(_next(store, 'test')['job']['schedule_run_id'], job['schedule_run_id'])
                self.assertIsNone(_next(store, 'other')['job'])
            self.assertEqual(len(store.list_schedule_runs()), 1)
            self.assertEqual(store.list_schedule_runs(second['target_id']), [])


if __name__ == '__main__':
    unittest.main()
