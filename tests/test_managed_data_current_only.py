import fcntl
import subprocess
import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from security_scanner import data_release as data
from security_scanner.grype_adapter import inspect_grype, run_grype
from security_scanner.offline_vuln_data import load_offline_data
from security_scanner.offline_epss import enrich_records as epss_enrich
from security_scanner.intelligence_enrichment import load_document, enrich_records


class ManagedCurrentOnlyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {'KODA_VULN_DATA_ROOT': str(self.root), 'KODA_REQUIRE_MANAGED_DATA': '0',
                                         'GRYPE_DB_CACHE_DIR': str(self.root / 'legacy'),
                                         'KODA_NVD_DATA': str(self.root / 'legacy.json'),
                                         'KODA_EPSS_DATA': str(self.root / 'legacy.csv'),
                                         'KODA_INTELLIGENCE_DATA': str(self.root / 'legacy.json'),
                                         'KODA_DATA_UPDATE_VERIFY_KEY': str(self.root / 'verify.pub')})
        self.env.start(); self.addCleanup(self.env.stop)
        self.binary = self.root / 'grype'
        self.binary.write_text('#!/bin/sh\nexit 0\n'); self.binary.chmod(0o755)
        (self.root / '.release.lock').write_text('')

    def activate(self, state='active'):
        release = self.root / 'releases' / 'approved-1'
        release.mkdir(parents=True)
        (release / 'grype-db' / '6').mkdir(parents=True)
        (release / 'grype-db' / '6' / 'vulnerability.db').write_bytes(b'approved-database')
        (release / 'metadata.env').write_text('BUNDLE_VERSION=approved-1\nDATASET_TYPE=composite\n')
        (release / 'approved-metadata.env').write_text('BUNDLE_VERSION=approved-1\nDATASET_TYPE=unified\n')
        manifest=release/'approved-manifest.sha256'
        manifest.write_text(hashlib.sha256((release/'approved-metadata.env').read_bytes()).hexdigest()+'  metadata.env\n'+hashlib.sha256((release/'grype-db/6/vulnerability.db').read_bytes()).hexdigest()+'  grype-db/6/vulnerability.db\n')
        subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:1024','-out',str(self.root/'private.pem')],check=True,capture_output=True)
        subprocess.run(['openssl','pkey','-in',str(self.root/'private.pem'),'-pubout','-out',str(self.root/'verify.pub')],check=True,capture_output=True)
        subprocess.run(['openssl','dgst','-sha256','-sign',str(self.root/'private.pem'),'-out',str(release/'approved-manifest.sha256.sig'),str(manifest)],check=True,capture_output=True)
        (self.root / 'current').symlink_to('releases/approved-1')
        self.marker(state)
        return release

    def marker(self, state):
        (self.root / '.managed.json').write_text(json.dumps({'format': 'koda-managed-vulnerability-data-v1',
                                                           'state': state, 'currentVersion': 'approved-1'}))

    def test_missing_current_never_launches_grype_or_reads_legacy_feeds(self):
        with patch('security_scanner.grype_adapter.subprocess.run') as execute:
            result = run_grype(self.root / 'sbom.json', self.binary, 1)
            self.assertTrue(result.fatal)
            self.assertFalse(inspect_grype(self.binary)['available'])
            execute.assert_not_called()
        with data.pinned_release():
            self.assertEqual(data.vulnerability_paths(), (None, None))
            self.assertIsNone(data.epss_path()); self.assertIsNone(data.intelligence_path())
            self.assertEqual(data.release_metadata()['status'], 'unavailable')
        result = load_offline_data(self.root / 'legacy.json', self.root / 'kev.json', ['CVE-2026-12345'])
        self.assertTrue(result.fatal)

    def test_active_release_overrides_legacy_env_and_keeps_read_only_lease(self):
        release = self.activate()
        with data.pinned_release():
            self.assertEqual(data.grype_cache_dir(), release.resolve() / 'grype-db')
            with (self.root / '.release.lock').open('rb') as writer:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch('security_scanner.grype_adapter.subprocess.run') as execute:
                execute.return_value.returncode = 0
                execute.return_value.stdout = '{}'
                execute.return_value.stderr = ''
                inspect_grype(self.binary)
                self.assertEqual(execute.call_args.kwargs['env']['GRYPE_DB_CACHE_DIR'], str(release.resolve() / 'grype-db'))
        with (self.root / '.release.lock').open('rb') as writer:
            fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_purged_marker_survives_current_and_old_cache_resurrection(self):
        self.activate('purged')
        with data.pinned_release():
            self.assertIsNone(data.grype_cache_dir())
            self.assertEqual(data.release_metadata()['status'], 'unavailable')
        self.assertTrue((self.root / 'current').exists())
        with patch('security_scanner.grype_adapter.subprocess.run') as execute:
            self.assertTrue(run_grype(self.root / 'bom', self.binary, 1).fatal)
            execute.assert_not_called()

    def test_marker_mismatch_and_exclusive_writer_are_unavailable(self):
        self.activate()
        payload=json.loads((self.root/'.managed.json').read_text());payload['currentVersion']='other'
        (self.root/'.managed.json').write_text(json.dumps(payload))
        self.assertTrue(data.data_unavailable_reason())
        self.marker('active')
        with (self.root / '.release.lock').open('rb') as writer:
            fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertTrue(data.data_unavailable_reason())

    def test_explicit_epss_path_and_supplied_old_intelligence_cannot_bypass_purge(self):
        self.activate('purged')
        with patch('security_scanner.offline_epss.load_snapshot', side_effect=AssertionError('legacy snapshot')):
            result=epss_enrich([{'id':'CVE-2026-12345','epss_score':.99}], self.root/'old.csv')
        self.assertNotIn('epss_score', result[0])
        self.assertFalse(result[0]['epss_policy_eligible'])
        self.assertEqual(load_document(self.root/'old.json')[1], 'missing')
        result=enrich_records([{'id':'CVE-2026-12345'}], document={'datasets':{'vulnrichment':{}}})
        self.assertEqual(result[0]['offline_intelligence']['status'],'missing')

    def test_missing_data_still_writes_sbom_and_report_counts_are_unknown(self):
        from security_scanner.java_vulnerability_scan import JavaScanOptions, run_java_scan
        archive=self.root/'app.jar'
        with zipfile.ZipFile(archive,'w') as z:
            z.writestr('META-INF/maven/example/demo/pom.properties','groupId=example\nartifactId=demo\nversion=1.0\n')
        output=self.root/'reports'
        result=run_java_scan(JavaScanOptions(target=archive,output_dir=output,builtin_only=True,grype_bin=self.binary))
        self.assertEqual(result.exit_code,2)
        self.assertTrue((output/'server-sbom.cdx.json').is_file())
        payload=json.loads((output/'server-vulnerabilities.json').read_text())
        self.assertIsNone(payload['summary']['unique_vulnerability_count'])
        self.assertEqual(payload['summary']['vulnerability_comparison_status'],'unavailable')
        self.assertIn('점검 불가',(output/'server-library-report.html').read_text())
        self.assertTrue(result.components)

    def test_cached_approval_detects_changed_db_metadata_and_unknown_files(self):
        release=self.activate()
        with patch('security_scanner.approved_release.subprocess.run', wraps=subprocess.run) as verify:
            self.assertEqual(data.data_unavailable_reason(),'')
            self.assertEqual(data.data_unavailable_reason(),'')
            self.assertEqual(verify.call_count,1)
            db=release/'grype-db/6/vulnerability.db'
            db.write_bytes(b'modified-data')
            self.assertTrue(data.data_unavailable_reason())
            self.assertEqual(verify.call_count,2)
        db.write_bytes(b'approved-database')
        self.assertEqual(data.data_unavailable_reason(),'')
        (release/'grype-db/6/unapproved.db').write_bytes(b'extra')
        self.assertTrue(data.data_unavailable_reason())

    def test_missing_proof_or_registered_key_blocks_current(self):
        release=self.activate()
        (self.root/'verify.pub').unlink()
        self.assertTrue(data.data_unavailable_reason())
        self.assertTrue((self.root/'current').is_dir())
        (release/'approved-manifest.sha256.sig').unlink()
        self.assertTrue(data.data_unavailable_reason())

    def test_runtime_metadata_cannot_select_an_unapproved_fallback(self):
        release=self.activate()
        self.assertEqual(data.data_unavailable_reason(),'')
        with (release/'metadata.env').open('a') as file:
            file.write('EPSS_SNAPSHOT=old.csv\n')
        self.assertTrue(data.data_unavailable_reason())
        with data.pinned_release():
            self.assertIsNone(data.epss_path())

    def test_private_key_is_never_a_registered_public_verification_key(self):
        self.activate()
        (self.root/'verify.pub').write_bytes((self.root/'verify.pub').read_bytes()+(self.root/'private.pem').read_bytes())
        self.assertTrue(data.data_unavailable_reason())

    def test_portal_stage_keeps_unknown_count_instead_of_zero(self):
        from security_scanner.linux_portal import _analysis_stages
        result={'scan':{'local_vulnerability':{'status':'failed','comparison_available':False,'matched_vulnerabilities':None}}}
        self.assertIsNone(_analysis_stages(result)['library']['matched_vulnerabilities'])

    def test_linux_direct_module_is_strict_even_without_launcher_and_with_zero_flag(self):
        with patch.dict(os.environ, {'KODA_VULN_DATA_ROOT':'','KODA_REQUIRE_MANAGED_DATA':'0'}), patch.object(data,'DEFAULT_ROOT',self.root), patch.object(data.sys,'platform','linux'):
            self.assertTrue(data.managed_data_required())
            self.assertEqual(data.vulnerability_paths(),(None,None))
            self.assertTrue(data.data_unavailable_reason())

    def test_mac_explicit_local_development_workflow_without_managed_root_is_preserved(self):
        with patch.dict(os.environ, {'KODA_VULN_DATA_ROOT':'','KODA_REQUIRE_MANAGED_DATA':'0'}), patch.object(data,'DEFAULT_ROOT',self.root), patch.object(data.sys,'platform','darwin'):
            self.assertFalse(data.managed_data_required())
            self.assertEqual(data.epss_path(),self.root/'legacy.csv')


if __name__ == '__main__':
    unittest.main()
