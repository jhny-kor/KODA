import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('build_identity', ROOT/'platforms/linux/docker/build_identity.py')
identity = importlib.util.module_from_spec(spec); spec.loader.exec_module(identity)

class LinuxImageTagTests(unittest.TestCase):
    def test_build_clock_revision_dirty_and_explicit_overrides(self):
        at = datetime(2026, 10, 19, 12, 34, 56, tzinfo=timezone.utc)
        with patch.object(identity.subprocess, 'check_output', side_effect=['a'*40, ' M code.py']):
            value = identity.build_identity(ROOT, '1.2', at=at)
        self.assertEqual(value['tag'], '1.2-20261019T123456Z-aaaaaaaaaaaa-dirty')
        self.assertEqual(value['created'], '2026-10-19T12:34:56Z')
        with patch.object(identity.subprocess, 'check_output', side_effect=['a'*40, '']):
            value = identity.build_identity(ROOT, '1.2', image='registry.example:5000/koda:approved', at=at)
        self.assertEqual(value['image'], 'registry.example:5000/koda:approved')
        self.assertEqual(value['tag'], 'approved')

    def test_cached_source_mismatch_cannot_receive_current_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source=root/'source'; source.mkdir(); (source/'a.py').write_text('new')
            bundle=root/'source.tar.gz'
            with tarfile.open(bundle,'w:gz') as out:
                raw=b'old'; item=tarfile.TarInfo('bundle/app/security_scanner/a.py'); item.size=len(raw); out.addfile(item,io.BytesIO(raw))
            with self.assertRaisesRegex(ValueError, '--refresh'):
                identity.verify_source_bundle(bundle,'bundle',source)

    def test_mock_actual_build_propagates_one_identity_to_labels_and_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'bin'; binary.mkdir(); dist=root/'dist'; dist.mkdir(); log=root/'docker.jsonl'
            version=re.search(r'^version = "([^"]+)"', (ROOT/'platforms/shared/python/pyproject.toml').read_text(), re.M)[1]
            bundle_name='koda-linux-x86_64-'+version
            with tarfile.open(dist/(bundle_name+'.tar.gz'),'w:gz') as out:
                for name in identity.source_hashes(ROOT/'platforms/shared/python/security_scanner'):
                    out.add(ROOT/'platforms/shared/python/security_scanner'/name,arcname=bundle_name+'/app/security_scanner/'+name)
                raw=b'syft=1\ngrype=1\n'; item=tarfile.TarInfo(bundle_name+'/versions.txt'); item.size=len(raw);out.addfile(item,io.BytesIO(raw))
            docker=binary/'docker'
            docker.write_text('''#!/usr/bin/env python3
import sys,json,os
from pathlib import Path
a=sys.argv[1:]
with open(os.environ['IMAGE_TEST_LOG'],'a') as f:f.write(json.dumps(a)+'\\n')
if a[:2]==['image','inspect']:print('python@sha256:'+'a'*64)
if a[:2]==['image','save']:Path(a[a.index('--output')+1]).write_bytes(b'mocked-built-image')
if a and a[0]=='run' and '/opt/koda/tools/grype' in a and 'db' in a:raise SystemExit(23)
''');docker.chmod(0o755)
            env=os.environ | {'PATH':str(binary)+os.pathsep+os.environ['PATH'],'IMAGE_TEST_LOG':str(log),'KODA_LINUX_DIST_DIR':str(dist),'KODA_SUITE_ALLOW_DIRTY':'1'}
            for key in ('KODA_IMAGE','KODA_DOCKER_IMAGE','KODA_DOCKER_IMAGE_TAG'):env.pop(key,None)
            result=subprocess.run(['bash',str(ROOT/'platforms/linux/package-docker-offline.sh')],env=env,text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            calls=[json.loads(line) for line in log.read_text().splitlines()]
            build=next(call for call in calls if call[:2]==['buildx','build'])
            image=build[build.index('-t')+1]
            labels=dict(build[i+1].split('=',1) for i,v in enumerate(build) if v=='--label')
            self.assertRegex(image,r'^koda-offline:'+re.escape(version)+r'-\d{8}T\d{6}Z-[0-9a-f]{12}(?:-dirty)?$')
            with tarfile.open(dist/('koda-docker-offline-x86_64-'+version+'.tar.gz')) as archive:
                base=archive.getnames()[0]
                self.assertEqual(archive.extractfile(base+'/image-ref.txt').read().decode().strip(),image)
                versions=dict(line.split('=',1) for line in archive.extractfile(base+'/versions.txt').read().decode().splitlines() if '=' in line)
                self.assertEqual(versions['docker_image'],image)
                self.assertEqual(versions['docker_image_built_at'],labels['org.opencontainers.image.created'])
                self.assertEqual(versions['docker_image_tag'],labels['org.opencontainers.image.version'])
                self.assertEqual(versions['git_revision'],labels['org.opencontainers.image.revision'])
            self.assertTrue(any(call[:2]==['image','save'] and call[-1]==image for call in calls))
            grype_smokes=[call for call in calls if call[0]=='run' and '/opt/koda/tools/grype' in call]
            self.assertEqual(len(grype_smokes),1)
            self.assertEqual(grype_smokes[0][-1],'version')
            self.assertIn('--read-only',grype_smokes[0])
            self.assertEqual(grype_smokes[0][grype_smokes[0].index('--network')+1],'none')


class ManagedDataInstallerSmokeTests(unittest.TestCase):
    def exercise(self, fail_version=False):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); binary=root/'bin'; binary.mkdir(); bundle=root/'bundle'; bundle.mkdir(); prefix=root/'installed'
            (bundle/'image').mkdir()
            files={'install.sh':(ROOT/'platforms/linux/docker/install.sh').read_bytes(),
                   'koda-docker.sh':b'#!/bin/sh\nexit 0\n','image-ref.txt':b'local/koda:test\n',
                   'versions.txt':b'product=fixture\n','README.md':b'fixture\n','image/koda-offline-amd64.tar':b'fixture-image'}
            for name,content in files.items():(bundle/name).write_bytes(content)
            (bundle/'manifest.sha256').write_text(''.join(hashlib.sha256(content).hexdigest()+'  '+name+'\n' for name,content in files.items()))
            log=root/'docker.jsonl'
            (binary/'uname').write_text('#!/bin/sh\nprintf "x86_64\\n"\n'); (binary/'uname').chmod(0o755)
            docker=binary/'docker'
            docker.write_text('''#!/usr/bin/env python3
import json,os,sys
a=sys.argv[1:]
with open(os.environ['IMAGE_TEST_LOG'],'a') as f:f.write(json.dumps(a)+'\\n')
if a and a[0]=='info' and '--format' in a:print(os.environ['IMAGE_TEST_ROOT'])
if a[:2]==['image','inspect'] and '--format' in a:
    fmt=a[a.index('--format')+1]
    print('amd64' if '.Architecture' in fmt else 'true' if 'io.koda.offline' in fmt else 'fixture')
if a and a[0]=='run' and '/opt/koda/tools/grype' in a:
    if a[-1]!='version' or os.environ.get('FAIL_GRYPE_VERSION')=='1':raise SystemExit(23)
'''); docker.chmod(0o755)
            env=os.environ | {'PATH':str(binary)+os.pathsep+os.environ['PATH'],'IMAGE_TEST_LOG':str(log),'IMAGE_TEST_ROOT':str(root),'FAIL_GRYPE_VERSION':'1' if fail_version else '0'}
            result=subprocess.run(['bash',str(bundle/'install.sh'),'--prefix',str(prefix)],env=env,text=True,capture_output=True)
            calls=[json.loads(line) for line in log.read_text().splitlines()]
            return result,calls,(prefix/'koda-docker').is_file()

    def test_install_accepts_binary_without_embedded_database_and_keeps_offline_sandbox(self):
        result,calls,installed=self.exercise()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertTrue(installed)
        grype=next(call for call in calls if call[0]=='run' and '/opt/koda/tools/grype' in call)
        self.assertEqual(grype[-1],'version')
        self.assertEqual(grype[grype.index('--network')+1],'none')
        self.assertIn('--read-only',grype)
        self.assertIn('no-new-privileges',grype)

    def test_install_stops_before_wrapper_install_when_binary_version_fails(self):
        result,_,installed=self.exercise(True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('smoke test failed: grype version',result.stderr)
        self.assertFalse(installed)

class SuiteDatedPatchTests(unittest.TestCase):
    def exercise(self, changed_repository=False):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); release=root/'release'; prefix=root/'installed'; events=root/'events'
            for directory in (release/'tracker/config', release/'tracker/scripts', release/'tracker/images', prefix/'tracker'):
                directory.mkdir(parents=True)
            (prefix/'metadata.env').write_text('SUITE_VERSION=test\n')
            (release/'tracker/metadata.env').write_text('IMAGE_BUILT_AT=2026-10-19T12:34:56Z\nIMAGE_REVISION=abc123\n')
            old={'PORTAL_IMAGE_TAG':'old','PORTAL_WEB_IMAGE':'local/web','PORTAL_API_IMAGE':'local/api','PORTAL_WORKER_IMAGE':'local/worker'}
            new={**old,'PORTAL_IMAGE_TAG':'20261019T123456Z-abc123'}
            if changed_repository:new['PORTAL_API_IMAGE']='foreign/api'
            (prefix/'tracker/.env').write_text('PRESERVE_SECRET=test-only\n'+''.join(k+'='+v+'\n' for k,v in old.items()))
            (release/'tracker/config/release-images.env').write_text(''.join(k+'='+v+'\n' for k,v in new.items()))
            (release/'tracker/config/.env.example').write_text('')
            # A local test double for the separately verified Tracker allow4key helper.
            (release/'tracker/scripts/release-images.sh').write_text('apply_release_images(){ grep -v "^PORTAL_" "$2" > "$2.next"; cat "$1" >> "$2.next"; mv "$2.next" "$2"; }\n')
            for key in ('PORTAL_WEB_IMAGE','PORTAL_API_IMAGE','PORTAL_WORKER_IMAGE'):
                ref=new[key]+':'+new['PORTAL_IMAGE_TAG']
                (release/'tracker/images'/(re.sub(r'[/:@]','_',ref)+'.tar')).write_bytes(b'fixture')
            functions=root/'functions.sh'
            functions.write_text((ROOT/'platforms/linux/suite/koda-suite').read_text().split('\ncase "${1:-}" in')[0])
            # Function arguments have their own positional parameters; store event path globally.
            program='''source "$1"
install_tmp="$2"
events="$4"
docker(){ printf '%s\\n' "$*" >> "$events"; if [[ "$1" == load ]]; then echo 'Loaded image ID: sha256:fixture'; else echo amd64; fi; }
services=()
patch_tracker_application "$3" portal-web
printf 'SERVICES=%s\\n' "${services[*]}"
'''
            result=subprocess.run(['bash','-c',program,'_',str(functions),str(release),str(prefix),str(events)],capture_output=True,text=True)
            return result, events.read_text() if events.exists() else '', (prefix/'tracker/.env').read_text(), (prefix/'metadata.env').read_text()

    def test_new_shared_tag_loads_all_images_and_updates_all_application_services(self):
        result,events,env,metadata=self.exercise()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(sum(line.startswith('load ') for line in events.splitlines()),3)
        self.assertIn('SERVICES=portal-web portal-api portal-worker portal-data-updater portal-metadata-collector',result.stdout)
        self.assertIn('PORTAL_IMAGE_TAG=20261019T123456Z-abc123',env)
        self.assertIn('PRESERVE_SECRET=test-only',env)
        self.assertIn('TRACKER_IMAGE_BUILT_AT=2026-10-19T12:34:56Z',metadata)

    def test_second_image_repository_change_is_rejected_before_any_load(self):
        result,events,env,_=self.exercise(True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('image reference changed',result.stderr)
        self.assertEqual(events,'')
        self.assertIn('PORTAL_IMAGE_TAG=old',env)
