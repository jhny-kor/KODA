"""Application-only bundles must never fetch or carry vulnerability data."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from test_linux_selected_db_packaging import ROOT, SelectedGrypeDatabasePackagingTests


class AppOnlyPackagingTests(unittest.TestCase):
    def test_native_bundle_excludes_data_and_retains_renderer_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script, assets, env = SelectedGrypeDatabasePackagingTests().fixture(root, versions="vulnerability_data=absent\ngrype_db=absent\n")
            before = {p.relative_to(assets): p.read_bytes() for p in assets.rglob('*') if p.is_file()}
            result = subprocess.run(['/bin/bash', str(script), '--without-vulnerability-data'], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(before, {p.relative_to(assets): p.read_bytes() for p in assets.rglob('*') if p.is_file()})
            with tarfile.open(root / 'dist/koda-linux-x86_64-0.1.0.tar.gz') as archive:
                base = 'koda-linux-x86_64-0.1.0/'
                names = archive.getnames()
                self.assertFalse(any('/grype-db/' in n or '/vuln-data/' in n for n in names))
                self.assertIn(base+'app/render-wheels/playwright-fixture.whl', names)
                self.assertIn(base+'ms-playwright/chromium-fixture/chrome', names)
                manifest = archive.extractfile(base+'manifest.sha256').read().decode()
                self.assertIn('versions.txt', manifest)
                for line in manifest.splitlines():
                    expected, relative = line.split(maxsplit=1)
                    self.assertEqual(hashlib.sha256(archive.extractfile(base+relative).read()).hexdigest(), expected)

    def test_offline_downloader_requests_tools_only_and_preserves_data_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); binary = root/'bin'; binary.mkdir(); fixtures = root/'fixtures'; fixtures.mkdir()
            for name, version in [('syft','1.46.0'),('grype','0.115.0')]:
                filename = f'{name}_{version}_linux_amd64.tar.gz'
                with tarfile.open(fixtures/filename, 'w:gz') as archive:
                    content=b'#!/bin/sh\nexit 0\n'; member=tarfile.TarInfo(name); member.size=len(content); archive.addfile(member,io.BytesIO(content))
                (fixtures/f'{name}_{version}_checksums.txt').write_text(hashlib.sha256((fixtures/filename).read_bytes()).hexdigest()+'  '+filename+'\n')
            (binary/'curl').write_text(f'#!{sys.executable}\n'+'''import os,sys,shutil
from pathlib import Path
args=sys.argv[1:]; url=args[-1]; dest=args[args.index('-o')+1]
with open(os.environ['REQUEST_LOG'],'a') as stream: stream.write(url+'\\n')
shutil.copyfile(Path(os.environ['FIXTURES'])/url.rsplit('/',1)[-1],dest)
''')
            (binary/'uname').write_text('#!/bin/sh\necho Linux\n')
            (binary/'bash').write_text('#!/bin/sh\nprintf "%s" "$KODA_WITHOUT_VULNERABILITY_DATA" > "$MODE_LOG"\n')
            for file in binary.iterdir(): file.chmod(0o755)
            cache=root/'cache'; sentinel=cache/'assets/vuln-data/keep'; sentinel.parent.mkdir(parents=True); sentinel.write_text('existing approved data')
            env=os.environ|{'PATH':str(binary)+os.pathsep+os.environ['PATH'],'FIXTURES':str(fixtures),'REQUEST_LOG':str(root/'requests'),'MODE_LOG':str(root/'mode'),'KODA_OFFLINE_CACHE_DIR':str(cache),'KODA_LINUX_DIST_DIR':str(root/'dist')}
            result=subprocess.run(['/bin/bash',str(ROOT/'platforms/linux/package-offline.sh'),'--without-vulnerability-data'],env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            requests=(root/'requests').read_text().splitlines(); self.assertEqual(len(requests),4)
            self.assertTrue(all('github.com/anchore/' in url for url in requests))
            self.assertEqual((root/'mode').read_text(),'1')
            self.assertEqual(sentinel.read_text(),'existing approved data')
            assets=cache/'assets-app-only'; self.assertFalse((assets/'vuln-data').exists()); self.assertFalse((assets/'grype-db').exists())
            self.assertIn('vulnerability_data=absent',(assets/'versions.txt').read_text())
            for flag in ['--data-cache-only','--vuln-data-only']:
                result=subprocess.run(['/bin/bash',str(ROOT/'platforms/linux/package-offline.sh'),'--without-vulnerability-data',flag],env=env,capture_output=True,text=True)
                self.assertEqual(result.returncode,2)
            self.assertEqual(len((root/'requests').read_text().splitlines()),4)
