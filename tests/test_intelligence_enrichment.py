import copy
import json
import unittest
from types import SimpleNamespace
import os
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch

from security_scanner.intelligence_enrichment import enrich_records, evidence_html
from security_scanner.eol_data import query_cycle_eol

AT = datetime(2026, 10, 19, tzinfo=timezone.utc)
CVE = 'CVE-2021-44228'
PURL = 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'


def document(kind, values, day='2026-10-19'):
    return {'format': 'koda-offline-intelligence-v1', 'snapshotSha256': 'a' * 64,
            'datasets': {kind: {'sources': [{'id': 'source', 'sourceUrl': 'https://example.org/data', 'dataDate': day, 'maxAgeDays': 7}],
                                'records': [{'sourceId': 'source', **row} for row in values]}}}


class EnrichmentTests(unittest.TestCase):
    def setUp(self):
        # Explicit local-file development fixtures; Linux production defaults
        # are exercised independently by test_managed_data_current_only.
        local_profile = patch("security_scanner.data_release.sys", SimpleNamespace(platform="darwin"))
        local_profile.start()
        self.addCleanup(local_profile.stop)

    def test_nested_scan_pins_same_release_even_after_activation_changes(self):
        from security_scanner.data_release import pinned_release, intelligence_path
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for version in ('one', 'two'):
                release = base / 'releases' / version
                release.mkdir(parents=True)
                (release / 'metadata.env').write_text('INTELLIGENCE_INDEX=intelligence.json\n')
                (release / 'intelligence.json').write_text('{}')
            (base / 'current').symlink_to(base / 'releases/one', target_is_directory=True)
            (base / '.release.lock').write_text('')
            (base / '.managed.json').write_text(json.dumps({'format':'koda-managed-vulnerability-data-v1','state':'active','currentVersion':'one'}))
            with patch.dict(os.environ, {'KODA_VULN_DATA_ROOT': directory}), patch('security_scanner.approved_release.verify_approved_release'):
                with pinned_release():
                    (base / 'current').unlink()
                    (base / 'current').symlink_to(base / 'releases/two', target_is_directory=True)
                    (base / '.managed.json').write_text(json.dumps({'format':'koda-managed-vulnerability-data-v1','state':'active','currentVersion':'two'}))
                    with pinned_release():
                        self.assertEqual(intelligence_path().parent.name, 'one')
                with pinned_release():
                    self.assertEqual(intelligence_path().parent.name, 'two')

    def test_ssvc_advisory_inheritance_does_not_change_verdict(self):
        original = [{'component_purl': PURL, 'cve_ids': [CVE], 'severity': 'low', 'advisories': [{'cve_ids': [CVE]}]}]
        before = copy.deepcopy(original)
        with patch('socket.create_connection', side_effect=AssertionError('egress')):
            result = enrich_records(original, document=document('vulnrichment', [{'cve': CVE, 'exploitation': 'active', 'automatable': 'yes', 'technicalImpact': 'total'}]), at=AT)
        self.assertEqual(original, before)
        self.assertEqual(result[0]['severity'], 'low')
        self.assertTrue(result[0]['offline_intelligence']['ssvcSuggestions'][0]['requiresReview'])
        self.assertEqual(result[0]['advisories'][0]['offline_intelligence']['evidence'][0]['kind'], 'vulnrichment')

    def test_stale_data_is_observed_not_ssvc_input(self):
        result = enrich_records([{'cve_ids': [CVE]}], document=document('vulnrichment', [{'cve': CVE, 'exploitation': 'active'}], '2026-09-01'), at=AT)[0]
        self.assertNotIn('ssvcSuggestions', result['offline_intelligence'])
        self.assertEqual(result['offline_intelligence']['evidence'][0]['source']['status'], 'stale')

    def test_unified_epss_appears_in_existing_report_fields(self):
        doc = document('epss', [{'cve': CVE, 'epss': .9, 'percentile': .99, 'date': '2026-10-19', 'modelVersion': 'v4'}])
        result = enrich_records([{'id': CVE, 'epss_status': 'missing'}], document=doc, at=AT)[0]
        self.assertEqual(result['epss_score'], .9)
        self.assertTrue(result['epss_policy_eligible'])
        invalid = enrich_records([{'id': CVE, 'epss_status': 'invalid'}], document=doc, at=AT)[0]
        self.assertNotIn('epss_score', invalid)
        doc['datasets']['epss']['sources'][0].update(dataDate='2026-10-01', maxAgeDays=30)
        doc['datasets']['epss']['records'][0]['date'] = '2026-10-01'
        stale = enrich_records([{'id': CVE}], document=doc, at=AT)[0]
        self.assertEqual(stale['epss_score'], .9)
        self.assertFalse(stale['epss_policy_eligible'])

    def test_supplier_statement_requires_exact_product(self):
        doc = document('vex', [{'cve': CVE, 'purl': PURL, 'status': 'not_affected'}])
        result = enrich_records([{'id': CVE, 'purl': PURL, 'severity': 'critical'}, {'id': CVE, 'purl': PURL + '-other'}], document=doc, at=AT)
        self.assertEqual(len(result[0]['offline_intelligence']['evidence']), 1)
        self.assertEqual(result[0]['severity'], 'critical')
        self.assertEqual(result[1]['offline_intelligence']['evidence'], [])

    def test_lifecycle_uses_purl_identity_and_cycle_boundaries(self):
        doc = document('lifecycle', [{'product': 'python', 'cycle': '3.1', 'identifiers': [{'type': 'purl', 'id': 'pkg:generic/python'}], 'isEol': True}])
        results = enrich_records([{'purl': 'pkg:generic/python@3.1.2', 'version': '3.1.2'}, {'purl': 'pkg:generic/python@3.10.1', 'version': '3.10.1'}, {'name': 'python', 'version': '3.1.2'}], document=doc, at=AT)
        self.assertEqual([len(row['offline_intelligence']['evidence']) for row in results], [1, 0, 0])

    def test_cwe_numeric_ids_and_spdx_identifiers(self):
        cwe = enrich_records([{'cwe_ids': ['CWE-79']}], document=document('cwe', [{'id': 79, 'name': 'XSS'}]), at=AT)[0]
        self.assertEqual(len(cwe['offline_intelligence']['evidence']), 1)
        license_row = enrich_records([{'licenses': [{'license': {'id': 'MIT'}}]}], document=document('spdx', [{'id': 'MIT', 'name': 'MIT License'}]), at=AT)[0]
        self.assertEqual(len(license_row['offline_intelligence']['evidence']), 1)

    def test_oval_does_not_claim_evaluation_from_cve_only(self):
        result = enrich_records([{'id': CVE}], document=document('ubuntu-oval', [{'id': 'oval:1', 'cves': [CVE]}]), at=AT)[0]
        self.assertEqual(result['offline_intelligence']['evidence'][0]['assessment'], 'unknown')

    def test_html_escapes_untrusted_source_content(self):
        result = enrich_records([{'licenses': ['MIT']}], document=document('spdx', [{'id': 'MIT', 'name': '<script>alert(1)</script>'}]), at=AT)[0]
        output = evidence_html(result)
        self.assertNotIn('<script>', output)
        self.assertIn('&lt;script&gt;', output)

    def test_eol_prefers_local_and_never_calls_external_in_offline_mode(self):
        doc = document('lifecycle', [{'product': 'python', 'cycle': '3.9', 'eolDate': '2025-10-31', 'latestVersion': '3.9.25'}])
        with patch('security_scanner.intelligence_enrichment.load_document', return_value=(doc, 'available', '')), patch('security_scanner.network_policy.offline_mode', return_value=True), patch('security_scanner.eol_data._fetch', side_effect=AssertionError('external')):
            result, warnings = query_cycle_eol('python', '3.9', today=AT.date())
        self.assertTrue(result.is_eol)
        self.assertEqual(result.latest, '3.9.25')

    def test_eol_missing_does_not_look_safe(self):
        with patch('security_scanner.intelligence_enrichment.load_document', return_value=(None, 'missing', '')), patch('security_scanner.network_policy.offline_mode', return_value=True), patch('security_scanner.eol_data._fetch', side_effect=AssertionError('external')):
            result, warnings = query_cycle_eol('python', '3.9')
        self.assertIsNone(result)
        self.assertTrue(warnings)
