"""Execute release scripts with a stateful Docker double (no real deployment)."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == 'linux', 'release installer targets Linux')
class ScheduledReleaseInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.release = self.root / 'release'
        scripts = Path(__file__).resolve().parents[1] / 'platforms/linux/scheduled-release'
        self.release.mkdir()
        for name in ('apply.sh', 'rollback.sh'):
            shutil.copy2(scripts / name, self.release / name)
        (self.release / 'contract').mkdir()
        (self.release / 'preflight.py').write_text('print("compatibility=passed (test double)")\n')
        (self.release / 'images.tar').write_bytes(b'test images')
        self.refs = ['local/koda-scheduled:20260910-ui1', 'local/koda-tracker-api-scheduled:20260910-ui1', 'local/koda-tracker-web-scheduled:20260910-ui1']
        self.new = {ref: 'sha256:' + str(i + 1) * 64 for i, ref in enumerate(self.refs)}
        (self.release / 'image-inventory.json').write_text(json.dumps([{'reference': ref, 'id': ident, 'platform': 'linux/amd64'} for ref, ident in self.new.items()]))
        self.prefix = self.root / 'suite'
        for name in ('tracker', 'data/koda-portal', 'koda'):
            (self.prefix / name).mkdir(parents=True)
        self.env_file = self.prefix / 'tracker/.env'
        self.env_file.write_text('PRESERVE_EXISTING_SECRET=test-only\n')
        (self.prefix / 'koda/image-ref.txt').write_text('old/koda:current\n')
        self.connection = sqlite3.connect(self.prefix / 'data/koda-portal/portal.sqlite3')
        self.connection.execute('PRAGMA journal_mode=WAL')
        self.connection.execute('CREATE TABLE preserve(value TEXT)')
        self.connection.execute("INSERT INTO preserve VALUES('committed-in-WAL')")
        self.connection.commit()
        launcher = '#!/bin/sh\nprintf "launcher %s CPU=%s MEMORY=%s\\n" "$*" "$KODA_CPUS" "$KODA_MEMORY" >> "$EVENTS"\n'
        for base in (self.prefix, self.release / 'launchers'):
            base.mkdir(exist_ok=True)
            for name in ('koda-suite', 'koda-docker'):
                path = (base / name) if base != self.prefix or name == 'koda-suite' else self.prefix / 'koda/koda-docker'
                path.write_text(launcher)
                path.chmod(0o755)
        self.old = {'old/koda:current': 'old-koda-id', 'old/web:current': 'old-web-id', 'old/api:current': 'old-api-id'}
        self.state = self.root / 'state.json'
        self.state.write_text(json.dumps(self.old))
        binary = self.root / 'bin'
        binary.mkdir()
        uname = binary / 'uname'
        uname.write_text('#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo x86_64;; esac\n')
        uname.chmod(0o755)
        flock = binary / 'flock'
        flock.write_text('#!/bin/sh\nexit 0\n')
        flock.chmod(0o755)
        docker = binary / 'docker'
        docker.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
a=sys.argv[1:]; state=pathlib.Path(os.environ['STATE']); values=json.loads(state.read_text())
with open(os.environ['EVENTS'],'a') as f: f.write('docker '+repr(a)+'\\n')
if a[0]=='inspect':
 print(json.dumps({'NanoCpus':3000000000,'Memory':2147483648,'PidsLimit':128}))
elif a[:2]==['image','inspect']:
 if a[2] not in values: sys.exit(1)
 print('amd64' if '{{.Architecture}}' in a else values[a[2]] if '{{.Id}}' in a else '{}')
elif a[0]=='load':
 values.update(json.loads(os.environ['NEW'])); state.write_text(json.dumps(values))
elif a[0]=='tag':
 if os.environ.get('FAIL_TAG') and a[1]=='local/koda-tracker-web-scheduled:20260910-ui1': sys.exit(1)
 values[a[2]]=values[a[1]]; state.write_text(json.dumps(values))
elif a[0]=='compose':
 if 'config' in a: print(json.dumps({'services':{'portal-web':{'image':'old/web:current'},'portal-api':{'image':'old/api:current'},'portal-worker':{'image':'old/api:current'}}}))
 elif 'exec' in a:
  if os.environ.get('FAIL_BACKUP'): sys.exit(1)
  print('-- private database backup')
elif a[0] not in ('ps','stop'): sys.exit(2)
''')
        docker.chmod(0o755)
        self.env = os.environ | {'PATH': str(binary) + ':' + os.environ['PATH'], 'STATE': str(self.state), 'NEW': json.dumps(self.new), 'EVENTS': str(self.root / 'events')}
        manifest = ''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + str(p.relative_to(self.release)) + '\n' for p in sorted(self.release.rglob('*')) if p.is_file())
        (self.release / 'manifest.sha256').write_text(manifest)

    def tearDown(self):
        self.connection.close()
        self.tmp.cleanup()

    def run_script(self, name, **env):
        return subprocess.run(['bash', str(self.release / name), '--prefix', str(self.prefix)], env=self.env | env, capture_output=True, text=True)

    def test_apply_and_rollback_preserve_shared_image_refs_and_wal(self):
        result = self.run_script('apply.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        backup = Path((self.prefix / '.koda-scheduled-last-backup').read_text().strip())
        self.assertEqual(len((backup / 'old-image-refs.txt').read_text().splitlines()), 3)
        with sqlite3.connect(next((backup / 'sqlite').iterdir())) as db:
            self.assertEqual(db.execute('SELECT value FROM preserve').fetchone()[0], 'committed-in-WAL')
        self.assertEqual((backup / 'tracker.pg_dump.sql').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.env_file.read_text(), 'PRESERVE_EXISTING_SECRET=test-only\n')
        events = (self.root / 'events').read_text()
        self.assertIn('CPU=3.0 MEMORY=2147483648b', events)
        self.assertLess(events.index("'load'"), events.index("'stop'"))
        self.assertNotIn("'down'", events)
        self.assertNotIn("'--force-recreate', 'postgres'", events)
        result = self.run_script('rollback.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        current = json.loads(self.state.read_text())
        self.assertEqual({ref: current[ref] for ref in self.old}, self.old)

    def test_backup_failure_never_changes_images(self):
        result = self.run_script('apply.sh', FAIL_BACKUP='1')
        self.assertNotEqual(result.returncode, 0)
        state = json.loads(self.state.read_text())
        self.assertEqual({ref: state[ref] for ref in self.old}, self.old)
        self.assertEqual(state['local/koda-scheduled:20260910-ui1'], self.new['local/koda-scheduled:20260910-ui1'])
        self.assertFalse((self.prefix / '.koda-scheduled-last-backup').exists())

    def test_partial_retag_has_usable_rollback(self):
        result = self.run_script('apply.sh', FAIL_TAG='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.prefix / '.koda-scheduled-last-backup').exists())
        result = self.run_script('rollback.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        current = json.loads(self.state.read_text())
        self.assertEqual({ref: current[ref] for ref in self.old}, self.old)

    def test_digest_failure_keeps_services_running(self):
        changed = self.new | {self.refs[0]: 'sha256:' + 'f' * 64}
        result = self.run_script('apply.sh', NEW=json.dumps(changed))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('loaded image digest mismatch', result.stderr)
        self.assertNotIn("'stop'", (self.root / 'events').read_text())

    def test_containerd_build_id_is_accepted(self):
        inventory = self.release / 'image-inventory.json'
        items = json.loads(inventory.read_text())
        for item in items:
            item['source_image_id'] = item['id']
            item['id'] = 'sha256:' + 'f' * 64
        inventory.write_text(json.dumps(items))
        manifest = self.release / 'manifest.sha256'
        manifest.write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + str(p.relative_to(self.release)) + '\n' for p in sorted(self.release.rglob('*')) if p.is_file() and p != manifest))
        result = self.run_script('apply.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
