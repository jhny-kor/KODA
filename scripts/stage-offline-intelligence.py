#!/usr/bin/env python3
"""Validate an approved local supplemental snapshot before packaging its files."""
import argparse
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'platforms/shared/python'))
from security_scanner.offline_intelligence import load_intelligence


def stage(source, destination):
    source, destination = Path(source).resolve(strict=True), Path(destination)
    document = load_intelligence(source.parent, source.name)
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.intelligence-', dir=destination) as temporary:
        staged = Path(temporary)
        for dataset in document['datasets'].values():
            for origin in dataset['sources']:
                relative = Path(origin['sourceFile'])
                target = staged / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source.parent / relative, target)
        shutil.copyfile(source, staged / 'intelligence.json')
        # Validate copied bytes too. Derived record freshness is never serialized.
        load_intelligence(staged)
        old_sources = destination / 'intelligence-sources'
        backup = staged / '.previous-sources'
        if old_sources.is_symlink():
            raise ValueError('packaging source directory must not be a symlink')
        if old_sources.exists():
            old_sources.replace(backup)
        try:
            if (staged / 'intelligence-sources').is_dir():
                (staged / 'intelligence-sources').replace(old_sources)
            (staged / 'intelligence.json').replace(destination / 'intelligence.json')
        except BaseException:
            if old_sources.exists():
                shutil.rmtree(old_sources)
            if backup.exists():
                backup.replace(old_sources)
            raise
    return len(document['datasets'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source')
    parser.add_argument('destination')
    args = parser.parse_args()
    try:
        print(f'Staged {stage(args.source, args.destination)} supplemental datasets')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f'Invalid offline intelligence: {exc}\n')
