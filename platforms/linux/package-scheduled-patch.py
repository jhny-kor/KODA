#!/usr/bin/env python3
"""Package already-built scheduled inspection images for an existing offline Suite."""
import argparse
import datetime
import hashlib
import json
import shutil
import subprocess
import tarfile
from pathlib import Path


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--tracker-repo', type=Path, required=True)
    parser.add_argument('--revision', default='20260914-ui-data1')
    parser.add_argument('--image-tag', default='20260914-ui-data1')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    name = f'koda-scheduled-offline-patch-x86_64-{args.revision}'
    args.output_dir.mkdir(parents=True, exist_ok=True)
    stage = args.output_dir / name
    stage.mkdir()  # Existing releases are never silently overwritten.
    shutil.copytree(repo / 'platforms/linux/scheduled-release', stage, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.DS_Store', '._*', '.omc'))
    if (repo / 'platforms/linux/update-release').is_dir():
        shutil.copytree(repo / 'platforms/linux/update-release', stage / 'build')
    launchers = stage / 'launchers'
    launchers.mkdir()
    for source, dest in [('platforms/linux/suite/koda-suite', 'koda-suite'),
                         ('platforms/linux/docker/koda-docker.sh', 'koda-docker')]:
        shutil.copy2(repo / source, launchers / dest)
        (launchers / dest).chmod(0o755)
    refs = [f'local/koda-scheduled:{args.image_tag}',
            f'local/koda-tracker-api-scheduled:{args.image_tag}',
            f'local/koda-tracker-web-scheduled:{args.image_tag}']
    inventory = []
    for ref in refs:
        item = json.loads(command('docker', 'image', 'inspect', ref))[0]
        if (item['Os'], item['Architecture']) != ('linux', 'amd64'):
            raise ValueError('release image must be linux/amd64: ' + ref)
        inventory.append({'reference': ref, 'id': item['Id'], 'platform': 'linux/amd64', 'size': item['Size']})
    (stage / 'image-inventory.json').write_text(json.dumps(inventory, indent=2) + '\n')
    sources = stage / 'source'
    shutil.copytree(repo / 'platforms/shared/python/security_scanner', sources / 'koda/security_scanner',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.DS_Store', '._*', '.omc'))
    shutil.copytree(args.tracker_repo / 'apps/api/koda_tracker', sources / 'tracker/koda_tracker',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.DS_Store', '._*', '.omc'))
    for directory in ('src', 'public'):
        shutil.copytree(args.tracker_repo / 'apps/web' / directory, sources / 'tracker/web' / directory,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.DS_Store', '._*', '.omc'))
    for file in ('package.json', 'package-lock.json', 'vite.config.ts', 'tsconfig.json', 'Dockerfile', 'nginx.conf'):
        path = args.tracker_repo / 'apps/web' / file
        if path.is_file():
            shutil.copy2(path, sources / 'tracker/web' / file)
    # The patch applies the reviewed Compose data-updater migration while
    # retaining the installed .env and named volumes.
    migration = stage / 'migration' / 'tracker'
    migration.mkdir(parents=True)
    for relative in ('compose.yaml', 'compose.airgap.yaml', 'compose.integration.yaml'):
        source = (repo / 'platforms/linux/suite/compose.integration.yaml') if relative == 'compose.integration.yaml' else args.tracker_repo / relative
        if source.is_file():
            shutil.copy2(source, migration / relative)
    gateway = repo / 'platforms/linux/suite/gateway.conf.template'
    if gateway.is_file():
        (migration / 'gateway').mkdir()
        shutil.copy2(gateway, migration / 'gateway/gateway.conf.template')
    for source, relative in (
        (args.tracker_repo / 'scripts/build-data-update.py', 'scripts/build-data-update.py'),
        (args.tracker_repo / 'scripts/nvd-alias-index.py', 'scripts/nvd-alias-index.py'),
        (repo / 'platforms/linux/package-offline.sh', 'koda/platforms/linux/package-offline.sh'),
    ):
        if source.is_file():
            destination = stage / 'external-tools' / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
    shutil.copy2(args.tracker_repo / 'apps/api/pyproject.toml', sources / 'tracker/pyproject.toml')
    for directory, project in ((repo, 'koda'), (args.tracker_repo, 'tracker')):
        for file in ('LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md'):
            if (directory / file).exists():
                shutil.copy2(directory / file, stage / (project + '-' + file))
    implementation_doc = repo / 'docs/schedule-implementation-2026-09-08.md'
    if implementation_doc.is_file():
        shutil.copy2(implementation_doc, stage / 'implementation-verification.ko.md')
    delivery_doc = repo / 'docs/linux-update-2026-09-14.md'
    if delivery_doc.is_file():
        shutil.copy2(delivery_doc, stage / 'linux-update.ko.md')
    verification = repo / '.build/linux-update/delivery-verification.json'
    if verification.is_file():
        shutil.copy2(verification, stage / 'verification.json')
    shutil.copy2(Path(__file__), stage / 'package-scheduled-patch.py')
    provenance = {'built_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'source_kind': 'working-tree-snapshot', 'target_platform': 'linux/amd64',
                  'base_suite': '0.1.1-20260902 with compatible 20260906/07 patches',
                  'vulnerability_data_refreshed': False, 'data_update_uploads': 'grype-db,vuln-data',
                  'koda_grype_db_built': '2026-09-10T06:30:24Z',
                  'tracker_web_vite_demo_mode': False,
                  'repositories': {key: {'head': command('git', '-C', str(path), 'rev-parse', 'HEAD'),
                                          'dirty': bool(command('git', '-C', str(path), 'status', '--porcelain'))}
                                   for key, path in [('koda', repo), ('tracker', args.tracker_repo)]}}
    (stage / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    subprocess.run(['docker', 'save', '-o', str(stage / 'images.tar'), *refs], check=True)
    # Docker 27 classic storage identifies the config; containerd may identify the index.
    with tarfile.open(stage / 'images.tar') as archive:
        manifests = json.load(archive.extractfile('manifest.json'))
        for item in inventory:
            matches = [m for m in manifests if item['reference'] in (m.get('RepoTags') or [])]
            if len(matches) != 1:
                raise ValueError('image archive reference is not unique: ' + item['reference'])
            config = archive.extractfile(matches[0]['Config']).read()
            item['source_image_id'] = item['id']
            item['id'] = 'sha256:' + hashlib.sha256(config).hexdigest()
    (stage / 'image-inventory.json').write_text(json.dumps(inventory, indent=2) + '\n')
    entries = []
    for path in sorted(stage.rglob('*')):
        if path.is_file():
            entries.append(f'{digest(path)}  {path.relative_to(stage).as_posix()}\n')
    (stage / 'manifest.sha256').write_text(''.join(entries))
    output = args.output_dir / (name + '.tar.gz')
    with tarfile.open(output, 'w:gz', compresslevel=1) as archive:
        archive.add(stage, arcname=name)
    checksum = digest(output)
    output.with_suffix(output.suffix + '.sha256').write_text(f'{checksum}  {output.name}\n')
    print(output)
    print('SHA256 ' + checksum)


if __name__ == '__main__':
    main()
