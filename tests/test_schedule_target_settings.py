import tempfile
import unittest
from pathlib import Path

from security_scanner.portal_store import PortalStore


class ScheduleTargetSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PortalStore(Path(self.tmp.name) / "portal.db")
        self.project = self.store.create_project("demo", project_id="p-1")

    def tearDown(self):
        self.tmp.cleanup()

    def test_existing_server_defaults_are_preserved(self):
        target = self.store.save_schedule_target({
            "project_id": self.project, "name": "server", "host": "server.internal",
            "username": "scanner", "ssh_key_ref": "/run/koda/key",
            "known_hosts_file": "/run/koda/known_hosts", "remote_directory": "/srv/app",
        })
        self.assertEqual(target["source_kind"], "server")
        self.assertEqual(target["schedule_frequency"], "daily")
        self.assertEqual(target["schedule_time"], "01:00")
        self.assertEqual(target["schedule_weekdays"], list(range(7)))

    def test_weekly_and_hourly_schedule_fields_are_validated_and_saved(self):
        weekly = self.store.save_schedule_target({
            "project_id": self.project, "name": "weekly", "host": "h", "username": "u",
            "ssh_key_ref": "/k", "known_hosts_file": "/kh", "remote_directory": "/src",
            "schedule_frequency": "weekly", "schedule_time": "23:30", "schedule_weekdays": [0, 6],
        })
        self.assertEqual(weekly["schedule_weekdays"], [0, 6])
        hourly = self.store.save_schedule_target({
            "project_id": self.project, "name": "hourly", "host": "h", "username": "u",
            "ssh_key_ref": "/k", "known_hosts_file": "/kh", "remote_directory": "/src",
            "schedule_frequency": "hourly", "schedule_interval_hours": 6,
        })
        self.assertEqual(hourly["schedule_interval_hours"], 6)
        with self.assertRaisesRegex(ValueError, "schedule time"):
            self.store.save_schedule_target({
                "project_id": self.project, "name": "bad", "host": "h", "username": "u",
                "ssh_key_ref": "/k", "known_hosts_file": "/kh", "remote_directory": "/src",
                "schedule_time": "25:00",
            })

    def test_gitlab_source_requires_mapping_ref_and_directory(self):
        with self.assertRaisesRegex(ValueError, "GitLab schedule source"):
            self.store.save_schedule_target({
                "project_id": self.project, "name": "gitlab", "source_kind": "gitlab",
            })

    def test_gitlab_source_round_trips_and_rejects_cross_project_mapping(self):
        with self.store._db() as db:
            db.execute("INSERT INTO projects(project_id,name,created_at) VALUES(?,?,?)", ("p-2", "other", "now"))
            db.execute(
                "INSERT INTO gitlab_repositories(mapping_id,project_id,gitlab_project_id,path_with_namespace,name,default_branch,tracker_service_id,tracker_environment_id,tracker_token_ref,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                ("map-1", self.project, 101, "org/app", "app", "main", "svc", "env", "ref", "now", "now"),
            )
            db.execute(
                "INSERT INTO gitlab_repositories(mapping_id,project_id,gitlab_project_id,path_with_namespace,name,default_branch,tracker_service_id,tracker_environment_id,tracker_token_ref,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                ("map-2", "p-2", 102, "org/other", "other", "main", "svc2", "env2", "ref2", "now", "now"),
            )
        target = self.store.save_schedule_target({
            "project_id": self.project, "name": "gitlab", "source_kind": "gitlab",
            "source_gitlab_mapping_id": "map-1", "source_gitlab_ref_type": "branch",
            "source_gitlab_ref": "", "source_gitlab_directory": "/src/",
        })
        self.assertEqual(target["source_gitlab_ref"], "main")
        self.assertEqual(target["source_gitlab_directory"], "src")
        self.assertEqual(self.store.schedule_target(target["target_id"])["source_gitlab_ref_type"], "branch")
        with self.assertRaisesRegex(ValueError, "does not belong"):
            self.store.save_schedule_target({
                "project_id": self.project, "name": "bad-gitlab", "source_kind": "gitlab",
                "source_gitlab_mapping_id": "map-2", "source_gitlab_ref_type": "tag",
                "source_gitlab_ref": "v1", "source_gitlab_directory": "/",
            })


if __name__ == "__main__":
    unittest.main()
