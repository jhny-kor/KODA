#!/usr/bin/env python3
"""Accept the specifically reviewed LDAP Compose variant without changing the Suite."""
import argparse
import hashlib
from pathlib import Path
import shutil

BASE = '8197b98b892a4a3bb2fd90210b3f14e94c49343a1a4a3e5dd4fda39e273202bb'
LDAP = '15d8984d641aa385873c9fbd26fd0d8ec11617c03b8d87decd71d4bfc4765b78'
REL = 'contract/tracker/compose.yaml'


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def reviewed_variants(baseline):
    """Return the exact LDAP additions reviewed for the supported release."""
    variants = set()
    for indent in ('      ', '        '):
        for before, after in (('', '\n'), ('\n', '')):
            candidate = baseline.replace(
                '    restart: unless-stopped\n\n  portal-worker:',
                '      - ldap-egress\n    restart: unless-stopped\n    dns:\n'
                + indent + '- 10.95.58.206\n' + indent + '- 10.95.58.207\n\n  portal-worker:', 1)
            candidate = candidate.replace('\nvolumes:\n', before
                + '  ldap-egress:\n    name: ${COMPOSE_PROJECT_NAME:-koda-sbom}-ldap-egress\n'
                + after + 'volumes:\n', 1)
            variants.add(candidate.encode())
    return variants


def apply(release, prefix):
    installed = prefix / 'tracker/compose.yaml'
    installed_hash = digest(installed)
    contract, manifest = release / REL, release / 'manifest.sha256'
    old_manifest = manifest.read_text()
    # Verify the complete original release before changing its compatibility contract.
    for line in old_manifest.splitlines():
        expected, name = line.split('  ', 1)
        path = (release / name).resolve()
        if release.resolve() not in path.parents or digest(path) != expected:
            raise ValueError('release checksum mismatch: ' + name)
    if digest(contract) == installed_hash and (release / 'ldap-compat-backup/compose.yaml').is_file():
        print('LDAP compatibility already applied; rerun preflight.py')
        return
    if digest(contract) != BASE or old_manifest.count(BASE + '  ' + REL + '\n') != 1:
        raise ValueError('unsupported release contract; no files changed')
    baseline = contract.read_text()
    reviewed = installed.read_bytes()
    # Permit only the pictured additions, with the two valid DNS list indents
    # and a blank line on either side of the added network definition.
    if reviewed not in reviewed_variants(baseline):
        raise ValueError('installed compose.yaml has changes outside the reviewed LDAP additions; no files changed')
    backup = release / 'ldap-compat-backup'
    backup.mkdir()  # Never overwrite a previous backup.
    shutil.copy2(contract, backup / 'compose.yaml')
    shutil.copy2(manifest, backup / 'manifest.sha256')
    if digest(installed) != installed_hash:
        raise ValueError('installed file changed during verification')
    contract.write_bytes(reviewed)
    manifest.write_text(old_manifest.replace(BASE + '  ' + REL + '\n', installed_hash + '  ' + REL + '\n'))
    print('LDAP compatibility applied to release files only. Suite files and containers unchanged.')
    print('Next: python3 preflight.py --prefix ' + str(prefix))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=Path, default=Path.cwd())
    parser.add_argument('--prefix', type=Path, required=True)
    args = parser.parse_args()
    try:
        apply(args.release, args.prefix)
    except (OSError, ValueError) as error:
        parser.exit(2, 'error: ' + str(error) + '\n')
