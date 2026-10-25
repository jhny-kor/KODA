#!/usr/bin/env python3
"""Build identities are assigned at build time, never at archive assembly time."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile

TAG = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}')

def build_identity(repo, version, *, image='', tag='', at=None):
    revision = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    if not re.fullmatch(r'[0-9a-f]{40,64}', revision):
        raise ValueError('a valid Git revision is required for an image build')
    dirty = bool(subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain', '--untracked-files=all'], text=True).strip())
    at = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    created = at.strftime('%Y-%m-%dT%H:%M:%SZ')
    tag = tag or f'{version}-{at:%Y%m%dT%H%M%SZ}-{revision[:12]}' + ('-dirty' if dirty else '')
    image = image or 'koda-offline:' + tag
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]*', image) or '@' in image:
        raise ValueError('a tagged image reference is required')
    last = image.rsplit('/', 1)[-1]
    if ':' not in last:
        image += ':' + tag
    actual_tag = image.rsplit(':', 1)[-1]
    if not TAG.fullmatch(actual_tag):
        raise ValueError('invalid Docker image tag')
    return dict(image=image, tag=actual_tag, created=created, revision=revision, dirty=str(dirty).lower())

def source_hashes(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc' and p.name != '.DS_Store'}

def verify_source_bundle(bundle, root_name, source):
    prefix = root_name + '/app/security_scanner/'
    with tarfile.open(bundle, 'r:gz') as archive:
        actual = {}
        for entry in archive.getmembers():
            if entry.name.startswith(prefix) and entry.isfile():
                name = entry.name[len(prefix):]
                if '__pycache__' in name.split('/') or name.endswith('.pyc') or Path(name).name == '.DS_Store':
                    continue
                if name in actual:
                    raise ValueError('duplicate source file in offline bundle')
                actual[name] = hashlib.sha256(archive.extractfile(entry).read()).hexdigest()
    if actual != source_hashes(Path(source)):
        raise ValueError('offline source bundle differs from current source; rebuild it with --refresh')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    stamp = sub.add_parser('stamp')
    stamp.add_argument('--repo', type=Path, required=True); stamp.add_argument('--version', required=True)
    stamp.add_argument('--image', default=''); stamp.add_argument('--tag', default='')
    verify = sub.add_parser('verify-source')
    verify.add_argument('--bundle', required=True); verify.add_argument('--root-name', required=True); verify.add_argument('--source', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'stamp':
            value = build_identity(args.repo, args.version, image=args.image, tag=args.tag)
            print('\t'.join(value[key] for key in ('image', 'tag', 'created', 'revision', 'dirty')))
        else:
            verify_source_bundle(args.bundle, args.root_name, args.source)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(2, str(exc) + '\n')

if __name__ == '__main__': main()
