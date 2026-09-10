"""Reusable server accounts remain project-bound across changes and restarts."""
import tempfile
import unittest
from pathlib import Path

from security_scanner.portal_store import PortalStore


class ServerConnectionTests(unittest.TestCase):
    def test_mapping_binding_updates_and_in_use_guards(self):
        with tempfile.TemporaryDirectory() as root:
            store = PortalStore(Path(root)/'db')
            project = store.create_project('mapped')
            other = store.create_project('unmapped')
            config = dict(name='sample', host='sample.invalid', port=22, username='reader',
                          ssh_key_ref='/run/koda/ssh/key', known_hosts_file='/run/koda/ssh/known_hosts', project_ids=[project])
            c = store.save_server_connection(config)
            target_config = dict(project_id=project, name='daily', server_connection_id=c['connection_id'], remote_directory='/srv/source')
            target = store.save_schedule_target(target_config)
            self.assertEqual(target['host'], 'sample.invalid')
            with self.assertRaisesRegex(ValueError, 'GitLab targets'):
                store.save_schedule_target({**target_config, 'source_kind':'gitlab'})
            with self.assertRaises((ValueError, PermissionError, KeyError)):
                store.save_schedule_target({**target_config, 'project_id':other})
            # Editing a connection without project_ids must not silently unmap it.
            updated = store.save_server_connection({**{k:v for k,v in config.items() if k != 'project_ids'}, 'connection_id': c['connection_id'], 'host':'new.invalid'})
            self.assertEqual(updated['project_ids'], [project])
            saved = PortalStore(store.path).list_schedule_targets()[0]
            self.assertEqual(saved['host'], 'new.invalid')
            self.assertGreater(saved['config_version'], target['config_version'])
            for update in ({'enabled':False}, {'project_ids':[]}):
                with self.assertRaises(ValueError):
                    store.save_server_connection({**config, 'connection_id':c['connection_id'], **update})
            with self.assertRaises(ValueError):
                store.remove_server_connection(c['connection_id'])
            self.assertTrue(store.server_connection(c['connection_id'])['enabled'])
            self.assertEqual(store.server_connection(c['connection_id'])['project_ids'], [project])

    def test_disabled_connection_cannot_be_bound(self):
        with tempfile.TemporaryDirectory() as root:
            store=PortalStore(Path(root)/'db')
            project=store.create_project('demo')
            c=store.save_server_connection(dict(name='sample',host='sample.invalid',username='reader',ssh_key_ref='/key',known_hosts_file='/known',project_ids=[project]))
            store.remove_server_connection(c['connection_id'])
            with self.assertRaises((KeyError, ValueError, PermissionError)):
                store.save_schedule_target(dict(project_id=project,name='no',server_connection_id=c['connection_id'],remote_directory='/srv'))


if __name__=='__main__': unittest.main()
