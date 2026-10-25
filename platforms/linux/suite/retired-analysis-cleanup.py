#!/usr/bin/env python3
"""Remove the retired analysis service from a verified KODA installation.

Only cleanup identifiers remain here. No installation, integration or retry
support is provided. The resource plan is checked completely before mutation.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

SERVICES = {'dtrack-apiserver', 'dtrack-frontend'}
ENV_PREFIXES = ('DTRACK_', 'TRACKER_DEPENDENCY_TRACK_', 'DEPENDENCY_TRACK_', 'KODA_INCLUDE_DEPENDENCY_TRACK')
RETIRED_FILES = (
    'tests/integration/test_dtrack_live.py', 'source/tests/integration/test_dtrack_live.py',
    'scripts/configure-dtrack-key.sh', 'scripts/verify-dtrack-connection.sh', 'scripts/verify-migration-runtime.py',
    'scripts/verify-complete-runtime.py', 'scripts/verify-java-regex-runtime.py', 'scripts/verify-literal-runtime.py',
    'apps/api/koda_tracker/dtrack.py', 'apps/api/koda_tracker/migration.py', 'apps/api/koda_tracker/migration_models.py',
    'apps/api/koda_tracker/migration_api.py',
    'source/apps/api/koda_tracker/dtrack.py', 'source/apps/api/koda_tracker/migration.py', 'source/apps/api/koda_tracker/migration_models.py',
    'source/apps/api/koda_tracker/migration_api.py',
    'docs/verification-complete-20261018-ko.md', 'docs/verification-java-regex-20261018-ko.md', 'docs/verification-literal-20261018-ko.md',
)


def read_env(path):
    result = {}
    if not path or not Path(path).is_file(): return result
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)', line)
        if match:
            key, value = match.groups()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'": value = value[1:-1]
            result[key] = value
    return result


class Cleaner:
    def __init__(self, values, *, runner=subprocess.run):
        self.values, self.runner = values, runner
        self.project = values.get('COMPOSE_PROJECT_NAME', 'koda-sbom')
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}', self.project): raise ValueError('invalid Compose project name')

    def docker(self, *args, data=None, optional=False):
        process = self.runner(['docker', *args], input=data, text=True, capture_output=True, timeout=180, check=False)
        if process.returncode and optional and any(value in (process.stderr or '').lower() for value in ('no such', 'not found', 'does not exist')):
            return None
        if process.returncode:
            # Avoid echoing environment values, SQL or database diagnostics.
            raise ValueError('retired-service cleanup command failed: ' + ' '.join(args[:2]))
        return process.stdout

    def inspect(self, kind, name):
        raw = self.docker(kind, 'inspect', name, optional=True)
        if raw is None: return None
        data = json.loads(raw)
        if not isinstance(data, list) or len(data) != 1: raise ValueError('invalid Docker inventory')
        return data[0]

    def plan(self):
        raw = self.docker('ps', '-a', '-q', '--filter', 'label=com.docker.compose.project=' + self.project)
        selected, images = [], set()
        # Previous installs can leave only their configured image tags behind.
        protected_refs = {self.values.get(key, '').split('@', 1)[0] for key in ('POSTGRES_IMAGE', 'GRYPE_IMAGE', 'NGINX_IMAGE', 'PORTAL_API_IMAGE', 'PORTAL_WEB_IMAGE', 'PORTAL_WORKER_IMAGE')}
        for key in ('DTRACK_APISERVER_IMAGE', 'DTRACK_FRONTEND_IMAGE'):
            reference = self.values.get(key)
            if not reference:
                continue
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,1023}', reference) or reference.split('@', 1)[0] in protected_refs:
                raise ValueError('invalid or protected retired image reference')
            item = self.inspect('image', reference)
            if item and item.get('Id'):
                images.add(item['Id'])
        for identifier in raw.split():
            item = self.inspect('container', identifier)
            labels = (item or {}).get('Config', {}).get('Labels') or {}
            if labels.get('com.docker.compose.project') != self.project: raise ValueError('container project ownership mismatch')
            if labels.get('com.docker.compose.service') in SERVICES:
                selected.append(identifier)
                if item.get('Image'): images.add(item['Image'])
        for service in SERVICES:
            item = self.inspect('container', self.project + '-' + service)
            if item:
                labels = item.get('Config', {}).get('Labels') or {}
                if labels.get('com.docker.compose.project') != self.project or labels.get('com.docker.compose.service') != service:
                    raise ValueError('refusing a foreign container using a retired service name')
                if item['Id'] not in selected: selected.append(item['Id'])
                if item.get('Image'): images.add(item['Image'])
        volumes = []
        candidates = {self.values.get('DTRACK_DATA_VOLUME_NAME', 'koda-sbom-dtrack-data'), self.project + '-dtrack-data'}
        raw = self.docker('volume', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + self.project)
        candidates.update(raw.split())
        protected = {self.values.get(key, default) for key, default in (
            ('POSTGRES_DATA_VOLUME_NAME', 'koda-sbom-postgres-data'), ('TRACKER_ARTIFACTS_VOLUME_NAME', 'koda-sbom-tracker-artifacts'),
            ('VULN_DATA_VOLUME_NAME', 'koda-sbom-vuln-data'), ('DATA_UPDATES_VOLUME_NAME', 'koda-sbom-data-updates'), ('BACKUP_VOLUME_NAME', 'koda-sbom-backups'))}
        for name in candidates:
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,254}', name): raise ValueError('invalid retired volume name')
            item = self.inspect('volume', name)
            if not item: continue
            labels = item.get('Labels') or {}
            logical = labels.get('com.docker.compose.volume')
            if logical != 'dtrack-data':
                if name in {self.values.get('DTRACK_DATA_VOLUME_NAME'), self.project + '-dtrack-data', 'koda-sbom-dtrack-data'}:
                    raise ValueError('refusing a volume without retired-service ownership')
                continue
            if name in protected or labels.get('com.docker.compose.project') != self.project:
                raise ValueError('refusing a protected or foreign volume')
            users = self.docker('ps', '-a', '-q', '--filter', 'volume=' + name).split()
            if set(users) - set(selected): raise ValueError('retired volume is shared by another container')
            volumes.append(name)
        return selected, sorted(set(volumes)), sorted(images)

    def resources(self):
        selected, volumes, images = self.plan()
        # Stop old native writers while the install replaces app/schema contracts.
        raw = self.docker('ps', '-a', '-q', '--filter', 'label=com.docker.compose.project=' + self.project)
        for identifier in raw.split():
            item = self.inspect('container', identifier)
            labels = (item or {}).get('Config', {}).get('Labels') or {}
            if labels.get('com.docker.compose.project') != self.project: raise ValueError('writer ownership mismatch')
            if labels.get('com.docker.compose.service') in {'portal-api', 'portal-worker', 'portal-project-sync', 'portal-data-updater'}:
                self.docker('stop', '--time', '30', identifier)
        for identifier in selected: self.docker('rm', '-f', identifier)
        for name in volumes: self.docker('volume', 'rm', name)
        removed_images = 0
        for identifier in images:
            # Never force removal of an image used by any other installation.
            if self.docker('ps', '-a', '-q', '--filter', 'ancestor=' + identifier).strip(): continue
            item = self.inspect('image', identifier)
            if not item: continue
            approved = {self.values.get(key, '').split('@', 1)[0] for key in ('DTRACK_APISERVER_IMAGE', 'DTRACK_FRONTEND_IMAGE')}
            removable = [tag for tag in item.get('RepoTags') or [] if tag in approved or re.match(r'^(?:docker.io/)?dependencytrack/(?:apiserver|frontend)(?::|@)', tag)]
            for tag in removable: self.docker('image', 'rm', tag)
            # An unrelated local alias is not an authorization to remove it.
            removed_images += bool(removable)
        return {'containers': len(selected), 'volumes': len(volumes), 'images': removed_images}

    def database(self):
        db = self.values.get('DTRACK_DB_NAME', 'dtrack')
        role = self.values.get('DTRACK_DB_USER', 'dtrack')
        admin = self.values.get('POSTGRES_SUPERUSER', 'postgres')
        protected = {'postgres', 'template0', 'template1', self.values.get('TRACKER_DB_NAME', 'sbom_tracker'), self.values.get('TRACKER_DB_USER', 'sbom_tracker'), admin}
        if any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', value) for value in (db, role, admin)) or db in protected or role in protected:
            raise ValueError('refusing protected or invalid database identity')
        name = self.project + '-postgres'
        item = self.inspect('container', name)
        if not item: raise ValueError('PostgreSQL must be started before database cleanup')
        labels = item.get('Config', {}).get('Labels') or {}
        if labels.get('com.docker.compose.project') != self.project or labels.get('com.docker.compose.service') != 'postgres':
            raise ValueError('PostgreSQL ownership mismatch')
        args = ('exec', '-i', name, 'psql', '-X', '-q', '-t', '-A', '-v', 'ON_ERROR_STOP=1', '-v', 'retired_db=' + db, '-v', 'retired_role=' + role, '-U', admin, '-d', 'postgres', '-f', '-')
        state = self.docker(*args, data="""SELECT json_build_object('exists', EXISTS(SELECT 1 FROM pg_database WHERE datname=:'retired_db'), 'owned', EXISTS(SELECT 1 FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE d.datname=:'retired_db' AND r.rolname=:'retired_role'), 'other', EXISTS(SELECT 1 FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE r.rolname=:'retired_role' AND d.datname<>:'retired_db'));
""")
        state = json.loads(state.strip())
        if state['exists'] and not state['owned'] or state['other']:
            raise ValueError('retired database role is shared or ownership differs')
        self.docker(*args, data="""SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=:'retired_db' AND pid<>pg_backend_pid();
SELECT format('DROP DATABASE %I', datname) FROM pg_database WHERE datname=:'retired_db'
\\gexec
SELECT format('DROP ROLE %I', rolname) FROM pg_roles WHERE rolname=:'retired_role'
\\gexec
""")
        return {'databaseRemoved': state['exists']}


def scrub_env(path):
    path = Path(path)
    if not path.is_file(): return
    original = path.read_text(encoding='utf-8')
    lines = original.splitlines(keepends=True)
    kept = []
    for line in lines:
        match = re.match(r'\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=', line)
        if match and match[1].startswith(ENV_PREFIXES): continue
        kept.append(line)
    if ''.join(kept) != original:
        descriptor, temporary = tempfile.mkstemp(prefix='.env-clean-', dir=path.parent)
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8') as handle: handle.write(''.join(kept))
            os.chmod(temporary, path.stat().st_mode & 0o777)
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)


def files(install_dir, values):
    root = Path(install_dir).resolve(strict=True)
    if root == Path('/') or root == Path.home(): raise ValueError('unsafe install directory')
    for relative in RETIRED_FILES:
        target = root / relative
        if target.is_symlink(): raise ValueError('refusing a symlink in retired file path')
        if target.exists():
            if not target.resolve().is_relative_to(root): raise ValueError('unsafe retired file path')
            target.unlink()
    for name in ('.env', 'koda-suite.env'):
        target = root / name
        if target.is_symlink(): raise ValueError('refusing symlink environment file')
        scrub_env(target)
    image_refs = {value for key, value in values.items() if key in {'DTRACK_APISERVER_IMAGE', 'DTRACK_FRONTEND_IMAGE'}}
    image_names = {re.sub(r'[/@:\s]', '_', value) + '.tar' for value in image_refs}
    directory = root / 'images'
    if directory.is_dir() and not directory.is_symlink():
        for target in directory.iterdir():
            if target.name in image_names or re.fullmatch(r'(?:docker.io_)?dependencytrack_(?:apiserver|frontend)[A-Za-z0-9_.-]*\.tar', target.name):
                if target.is_file() or target.is_symlink(): target.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, required=True)
    parser.add_argument('--install-dir', type=Path)
    parser.add_argument('--phase', choices=['resources', 'database', 'files'], required=True)
    args = parser.parse_args()
    values = read_env(args.env_file)
    try:
        if args.phase == 'files':
            if args.install_dir is None: parser.error('--install-dir required')
            files(args.install_dir, values)
            result = {'retiredFilesRemoved': True}
        else:
            cleaner = Cleaner(values)
            result = cleaner.resources() if args.phase == 'resources' else cleaner.database()
        print(json.dumps(result))
    except (ValueError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        parser.exit(2, 'Retired-service cleanup stopped: ownership, inventory or command verification failed. No foreign resources are removed.\n')


if __name__ == '__main__': main()
