import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from security_scanner import offline_intelligence as parser
from security_scanner.intelligence_enrichment import enrich_records, load_document, evidence_html

AT = datetime(2026, 10, 19, tzinfo=timezone.utc)
CVE = 'CVE-2026-12345'


def snapshot(root):
    root.mkdir(parents=True)
    raw = json.dumps({'cveMetadata': {'cveId': CVE}, 'containers': {'adp': [{'providerMetadata': {'shortName': 'CISA-ADP'}, 'metrics': [{'other': {'type': 'ssvc', 'content': {'version': '2.0.3', 'timestamp': AT.isoformat(), 'role': 'CISA Coordinator', 'options': [{'Exploitation': 'active'}, {'Automatable': 'yes'}, {'Technical Impact': 'total'}]}}}]}]}}).encode()
    digest = hashlib.sha256(raw).hexdigest()
    name = f'intelligence-sources/{digest}.bin'
    (root / 'intelligence-sources').mkdir()
    (root / name).write_bytes(raw)
    source = {'id': 'cisa', 'sourceUrl': 'https://github.com/cisagov/vulnrichment', 'dataDate': '2026-10-19', 'fetchedAt': AT.isoformat(), 'sourceFile': name}
    doc = {'format': parser.FORMAT, 'createdAt': AT.isoformat(), 'datasets': {'vulnrichment': parser.normalize_source('vulnrichment', raw, source)}}
    path = root / 'intelligence.json'
    path.write_text(json.dumps(doc))
    return path, name


class TransferTests(unittest.TestCase):
    def setUp(self):
        # Explicit local-file development fixtures; Linux production defaults
        # are exercised independently by test_managed_data_current_only.
        local_profile = patch("security_scanner.data_release.sys", SimpleNamespace(platform="darwin"))
        local_profile.start()
        self.addCleanup(local_profile.stop)

    def test_local_original_proof_roundtrip_and_saved_report_survives_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            path, name = snapshot(Path(directory) / 'source')
            with patch('socket.create_connection', side_effect=AssertionError('egress')):
                doc, state, error = load_document(path, at=AT)
                self.assertEqual((state, error), ('available', ''))
                result = enrich_records([{'id': CVE, 'severity': 'medium'}], path, at=AT)
            original = evidence_html(result[0])
            path.unlink()
            (path.parent / name).unlink()
            self.assertEqual(evidence_html(result[0]), original)
            self.assertTrue(result[0]['offline_intelligence']['snapshotSha256'])
            self.assertEqual(result[0]['severity'], 'medium')

    def test_stager_validates_before_replacing_existing_assets(self):
        spec = importlib.util.spec_from_file_location('stage_intelligence', Path(__file__).parents[1] / 'scripts/stage-offline-intelligence.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            path, name = snapshot(Path(directory) / 'source')
            target = Path(directory) / 'packaged'
            self.assertEqual(module.stage(path, target), 1)
            self.assertEqual(parser.load_intelligence(target, at=AT)['datasets']['vulnrichment']['records'][0]['exploitation'], 'active')
            before = (target / 'intelligence.json').read_bytes()
            original_replace = Path.replace
            def fail_index_replace(file, destination):
                if file.name == 'intelligence.json' and Path(destination) == target / 'intelligence.json':
                    raise OSError('injected packaging disk failure')
                return original_replace(file, destination)
            with patch.object(Path, 'replace', fail_index_replace):
                with self.assertRaisesRegex(OSError, 'disk failure'):
                    module.stage(path, target)
            self.assertEqual((target / 'intelligence.json').read_bytes(), before)
            self.assertEqual(parser.load_intelligence(target, at=AT)['datasets']['vulnrichment']['records'][0]['exploitation'], 'active')
            (path.parent / name).write_bytes(b'corrupt')
            with self.assertRaises(ValueError):
                module.stage(path, target)
            self.assertEqual((target / 'intelligence.json').read_bytes(), before)

    def test_tampered_normalized_record_and_escaping_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _ = snapshot(Path(directory) / 'source')
            doc = json.loads(path.read_text())
            doc['datasets']['vulnrichment']['records'][0]['exploitation'] = 'none'
            path.write_text(json.dumps(doc))
            self.assertEqual(load_document(path, at=AT)[1], 'invalid')
            with patch.dict(os.environ, {'KODA_VULN_DATA_ROOT': directory}):
                from security_scanner.data_release import pinned_release, release_metadata
                with pinned_release():
                    self.assertEqual(release_metadata()["status"], "unavailable")
