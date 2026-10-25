#!/usr/bin/env python3
"""Package already-built scheduled inspection images for an existing offline Suite."""
import argparse
import datetime
import hashlib
import json
import re
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
    parser.add_argument('--image-tag', '--source-image-tag', dest='image_tag', default='20260914-ui-data1', help='existing built-image tag; preserved unless output alias is explicit')
    parser.add_argument('--output-image-tag', help='explicit package alias only; original build timestamp/labels stay unchanged')
    args = parser.parse_args()
    for value in (args.image_tag, args.output_image_tag):
        if value is not None and not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', value):
            raise ValueError('invalid Docker tag')
    cleanup_helper = args.tracker_repo / 'scripts/remove-retired-analysis.py'
    if not cleanup_helper.is_file() or cleanup_helper.is_symlink():
        raise ValueError('Tracker native release cleanup helper is missing or unsafe')
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
        relative = 'koda/koda-docker' if dest == 'koda-docker' else dest
        shutil.copy2(repo / source, stage / 'contract' / relative)
    refs = [f'local/koda-scheduled:{args.image_tag}',
            f'local/koda-tracker-api-scheduled:{args.image_tag}',
            f'local/koda-tracker-web-scheduled:{args.image_tag}']
    inventory = []
    for ref in refs:
        item = json.loads(command('docker', 'image', 'inspect', ref))[0]
        if (item['Os'], item['Architecture']) != ('linux', 'amd64'):
            raise ValueError('release image must be linux/amd64: ' + ref)
        output_ref = ref.rsplit(':', 1)[0] + ':' + args.output_image_tag if args.output_image_tag else ref
        if output_ref != ref:
            command('docker', 'tag', ref, output_ref)
        labels = item.get('Config', {}).get('Labels') or {}
        inventory.append({'reference': output_ref, 'source_reference': ref, 'id': item['Id'],
                          'platform': 'linux/amd64', 'size': item['Size'],
                          'image_created': labels.get('org.opencontainers.image.created') or item.get('Created'),
                          'image_revision': labels.get('org.opencontainers.image.revision'),
                          'image_version': labels.get('org.opencontainers.image.version'),
                          'tag_is_package_alias': output_ref != ref})
    refs = [item['reference'] for item in inventory]
    (stage / 'image-inventory.json').write_text(json.dumps(inventory, indent=2) + '\n')
    sources = stage / 'source'
    shutil.copytree(repo / 'platforms/shared/python/security_scanner', sources / 'koda/security_scanner',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.DS_Store', '._*', '.omc'))
    shutil.copytree(args.tracker_repo / 'apps/api/koda_tracker', sources / 'tracker/koda_tracker',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.DS_Store', '._*', '.omc'))
    backend_hashes = {str(path.relative_to(sources / 'tracker/koda_tracker')): digest(path)
                      for path in sorted((sources / 'tracker/koda_tracker').rglob('*.py'))}
    (stage / 'contract/tracker-backend-sha256.json').write_text(json.dumps(backend_hashes, indent=2) + '\n')
    for directory in ('src', 'public'):
        shutil.copytree(args.tracker_repo / 'apps/web' / directory, sources / 'tracker/web' / directory,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.DS_Store', '._*', '.omc'))
    for file in ('package.json', 'package-lock.json', 'vite.config.ts', 'tsconfig.json', 'Dockerfile', 'nginx.conf'):
        path = args.tracker_repo / 'apps/web' / file
        if path.is_file():
            shutil.copy2(path, sources / 'tracker/web' / file)
    # Native-only contracts are generated from these exact source trees.
    # Old external-analysis installations must use the full installer first.
    migration = stage / 'migration' / 'tracker'
    migration.mkdir(parents=True)
    for relative in ('compose.yaml', 'compose.airgap.yaml', 'compose.integration.yaml'):
        source = (repo / 'platforms/linux/suite/compose.integration.yaml') if relative == 'compose.integration.yaml' else args.tracker_repo / relative
        if source.is_file():
            shutil.copy2(source, migration / relative)
            shutil.copy2(source, stage / 'contract/tracker' / relative)
    gateway = repo / 'platforms/linux/suite/gateway.conf.template'
    if gateway.is_file():
        (migration / 'gateway').mkdir()
        shutil.copy2(gateway, migration / 'gateway/gateway.conf.template')
        shutil.copy2(gateway, stage / 'contract/tracker/gateway/gateway.conf.template')
    for source, relative in (
        (args.tracker_repo / 'scripts/build-data-update.py', 'scripts/build-data-update.py'),
        (args.tracker_repo / 'scripts/nvd-alias-index.py', 'scripts/nvd-alias-index.py'),
        (cleanup_helper, 'tracker/scripts/remove-retired-analysis.py'),
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
    # Host-local and historical verification assets are not evidence for a new
    # package and must not be automatically republished with it.
    (stage / 'source-image-check.json').write_text(json.dumps({
        'status': 'not_verified', 'reason': 'source/image parity requires release-specific verification'
    }, indent=2) + '\n')
    shutil.copy2(Path(__file__), stage / 'package-scheduled-patch.py')
    provenance = {'packaged_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'source_kind': 'working-tree-snapshot', 'target_platform': 'linux/amd64',
                  'base_suite': 'native-two-product-contract',
                  'vulnerability_data_refreshed': False, 'source_image_tag': args.image_tag, 'output_image_tag': args.output_image_tag or args.image_tag,
                  'image_build_dates_are_preserved': True, 'data_update_uploads': 'grype-db,vuln-data',
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
