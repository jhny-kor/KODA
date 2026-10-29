"""Exercise real Suite/launcher wiring with Compose environment precedence."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_portal_worker_packaging import DOCKER_STUB


ROOT = Path(__file__).resolve().parents[1]
PROVISIONING = 'KODA_TRACKER_PROVISIONING_TOKEN_FILE'
TOKEN_DIR = 'KODA_TRACKER_TOKEN_DIR'

COMPOSE_STUB = r'''
if command == 'compose':
    env_file = pathlib.Path(args[args.index('--env-file') + 1])
    values = dict(line.split('=', 1) for line in env_file.read_text().splitlines() if '=' in line)
    effective = {key: os.environ.get(key, values.get(key, '')) for key in
                 ('KODA_TRACKER_PROVISIONING_TOKEN_FILE', 'KODA_TRACKER_TOKEN_DIR')}
    pathlib.Path(os.environ['COMPOSE_CAPTURE']).write_text(json.dumps(effective))
    if not effective['KODA_TRACKER_PROVISIONING_TOKEN_FILE']:
        print('invalid spec: :/run/secrets/koda-tracker-provisioning:ro: empty section between colons', file=sys.stderr)
        finish(1)
    finish()
'''


class SuiteProvisioningEnvironmentTests(unittest.TestCase):
    def exercise(self, inherited):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            prefix = root / 'installed suite'
            for directory in ('tracker', 'config', 'koda'):
                (prefix / directory).mkdir(parents=True)
            token = prefix / 'config/koda-tracker-provisioning.token'
            token.write_text('existing-private-fixture-token-' + 'x' * 48 + '\n')
            token.chmod(0o444)
            expected_hash = hashlib.sha256(token.read_bytes()).hexdigest()
            env_file = prefix / 'tracker/.env'
            env_file.write_text(PROVISIONING + '=\n' + TOKEN_DIR + '=\nKODA_TRACKER_URL=http://tracker-gateway:8080\n')
            wrapper = prefix / 'koda/koda-docker'
            wrapper.write_bytes((ROOT / 'platforms/linux/docker/koda-docker.sh').read_bytes())
            wrapper.chmod(0o755)
            (prefix / 'koda/image-ref.txt').write_text('local/koda:test\n')
            functions = root / 'suite-functions.sh'
            functions.write_text((ROOT / 'platforms/linux/suite/koda-suite').read_text().split('\ncase "${1:-}" in')[0])
            binary = root / 'bin'
            binary.mkdir()
            docker = binary / 'docker'
            docker.write_text(DOCKER_STUB.replace("if command == 'run':", COMPOSE_STUB + "\nif command == 'run':"))
            docker.chmod(0o755)
            state = root / 'docker-state.json'
            state.write_text(json.dumps({'containers': {}, 'networks': []}))
            capture = root / 'compose-env.json'
            environment = {key: value for key, value in os.environ.items() if not key.startswith(('KODA_', 'TRACKER_', 'VULN_DATA_'))}
            environment.update(PATH=str(binary) + os.pathsep + os.environ['PATH'],
                               DOCKER_STATE=str(state), DOCKER_LOG=str(root / 'docker.jsonl'), COMPOSE_CAPTURE=str(capture))
            if inherited is not None:
                for key in (PROVISIONING, TOKEN_DIR):
                    environment[key] = ''
            if inherited == 'custom':
                custom = root / 'custom private'
                custom.mkdir(mode=0o700)
                custom_token = custom / 'provisioning.token'
                custom_token.write_text('existing-custom-fixture-' + 'y' * 48)
                custom_directory = custom / 'tokens'
                custom_directory.mkdir()
                environment.update({PROVISIONING: str(custom_token), TOKEN_DIR: str(custom_directory)})
            program = '''source "$1"
prefix="$2"
start_dashboard "$prefix"
suite_compose "$prefix" up -d --no-build --pull never
'''
            result = subprocess.run(['bash', '-c', program, '_', str(functions), str(prefix)],
                                    env=environment, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            configured = dict(line.split('=', 1) for line in env_file.read_text().splitlines() if '=' in line)
            effective = json.loads(capture.read_text())
            expected_file = environment[PROVISIONING] if inherited == 'custom' else configured[PROVISIONING]
            expected_directory = environment[TOKEN_DIR] if inherited == 'custom' else configured[TOKEN_DIR]
            self.assertEqual(effective[PROVISIONING], expected_file)
            self.assertEqual(effective[TOKEN_DIR], expected_directory)
            self.assertTrue(Path(configured[PROVISIONING]).is_file())
            self.assertEqual(hashlib.sha256(token.read_bytes()).hexdigest(), expected_hash)
            self.assertEqual(token.stat().st_mode & 0o777, 0o444)
            containers = json.loads(state.read_text())['containers']
            self.assertEqual(set(containers), {'koda-dashboard', 'koda-scan-worker', 'koda-delivery-worker'})
            for name in ('koda-dashboard', 'koda-delivery-worker'):
                args = containers[name]['args']
                self.assertIn(expected_file + ':/run/secrets/koda-tracker-provisioning:ro', args)
                self.assertIn(expected_directory + ':/run/koda/tracker-tokens:rw', args)
                self.assertIn(PROVISIONING + '=/run/secrets/koda-tracker-provisioning', args)
            scan = containers['koda-scan-worker']['args']
            self.assertEqual(scan[scan.index('--network') + 1], 'none')
            self.assertFalse(any('koda-tracker-provisioning' in item or 'tracker-tokens' in item for item in scan))
            # Repeated starts must reuse the persisted secret, even when the
            # caller still exports its original empty optional variables.
            again = subprocess.run(['bash', '-c', program, '_', str(functions), str(prefix)],
                                   env=environment, text=True, capture_output=True)
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertEqual(hashlib.sha256(token.read_bytes()).hexdigest(), expected_hash)

    def test_exported_empty_optional_paths_use_generated_values_for_all_consumers(self):
        self.exercise('empty')

    def test_unset_optional_paths_still_use_generated_values(self):
        self.exercise(None)

    def test_nonempty_existing_environment_override_remains_consistent(self):
        self.exercise('custom')


if __name__ == '__main__':
    unittest.main()
