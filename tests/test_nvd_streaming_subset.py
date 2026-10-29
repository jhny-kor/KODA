"""NVD consumers keep selected records without reading a full JSON document."""
from contextlib import contextmanager
import builtins
import gzip
import json
from pathlib import Path
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch

from security_scanner import offline_vuln_data as data


APP = "cpe:2.3:a:example:widget:1.2:*:*:*:*:*:*:*"
OTHER = "cpe:2.3:a:other:product:*:*:*:*:*:*:*:*"
OS = "cpe:2.3:o:example:server:8:*:*:*:*:*:*:*"


class CheckedReads:
    def __init__(self, stream):
        self.stream = stream

    def __enter__(self):
        self.stream.__enter__()
        return self

    def __exit__(self, *args):
        return self.stream.__exit__(*args)

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def read(self, size=-1):
        if size < 0:
            raise AssertionError("whole-document read is forbidden")
        return self.stream.read(size)

    def readline(self, size=-1):
        if size < 0:
            raise AssertionError("unbounded line read is forbidden")
        return self.stream.readline(size)


@contextmanager
def bounded_reads(source):
    original_open = Path.open
    original_builtin = builtins.open
    original_gzip = gzip.open

    def path_open(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)
        return CheckedReads(stream) if path == source else stream

    def gzip_open(path, *args, **kwargs):
        stream = original_gzip(path, *args, **kwargs)
        return CheckedReads(stream) if Path(path) == source else stream

    def builtin_open(path, *args, **kwargs):
        stream = original_builtin(path, *args, **kwargs)
        return CheckedReads(stream) if not isinstance(path, int) and Path(path) == source else stream

    with patch.object(Path, "open", path_open), patch.object(gzip, "open", gzip_open), patch.object(builtins, "open", builtin_open):
        yield


class NvdStreamingSubsetTests(unittest.TestCase):
    def test_compact_and_official_feeds_retain_only_requested_cves_without_full_reads(self):
        expected = {"id": "CVE-2026-12345", "description": "selected 😃", "configurations": [{"nodes": []}]}
        for compressed in (False, True):
            for compact in (False, True):
                with self.subTest(compressed=compressed, compact=compact), tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / ("nvd.json.gz" if compressed else "nvd.json")
                    unrelated = {"id": "CVE-2026-99999", "description": "x" * 200_000}
                    records = {expected["id"]: expected, unrelated["id"]: unrelated} if compact else [{"cve": expected}, {"cve": unrelated}]
                    raw = json.dumps({"timestamp": "2026-10-29", "aliases": {"GHSA-AAAA-BBBB-CCCC": expected["id"]}, "vulnerabilities": records}, ensure_ascii=False).encode()
                    path.write_bytes(gzip.compress(raw) if compressed else raw)
                    with bounded_reads(path):
                        result = data.load_offline_data(path, None, ["cve-2026-12345"])
                    self.assertFalse(result.fatal)
                    self.assertEqual(set(result.nvd), {expected["id"]})
                    self.assertEqual(result.nvd[expected["id"]]["configurations"], expected["configurations"])
                    self.assertEqual(result.data_as_of, "2026-10-29")
                    self.assertEqual(result.sources[0].metadata["applicabilityRecords"], 1)
                    self.assertEqual(result.sources[0].metadata["legacyDetailsOnly"], 1)

    def test_empty_requested_ids_still_validate_data_without_retaining_all_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nvd.json"
            path.write_text(json.dumps({"vulnerabilities": {"CVE-2026-12345": {"description": "details"}}}))
            with bounded_reads(path):
                result = data.load_offline_data(path, None, [])
            self.assertFalse(result.fatal)
            self.assertTrue(result.loaded("nvd"))
            self.assertEqual(result.nvd, {})
            path.write_text('{"vulnerabilities":[{"id":"CVE-2026-12345"}]')
            with bounded_reads(path):
                invalid = data.load_offline_data(path, None, [])
            self.assertTrue(invalid.fatal)
            self.assertFalse(invalid.loaded("nvd"))

    def test_cpe_subset_keeps_full_environment_tree_and_global_unknowns(self):
        record = {"id": "CVE-2026-12345", "configurations": [{"operator": "AND", "nodes": [
            {"cpeMatch": [{"criteria": APP, "vulnerable": True, "versionEndExcluding": "2"}]},
            {"cpeMatch": [{"criteria": OS, "vulnerable": False}]},
        ]}]}
        unrelated = {"id": "CVE-2026-99999", "configurations": [{"cpeMatch": [{"criteria": OTHER, "vulnerable": True}]}]}
        legacy = {"id": "CVE-2026-54321", "description": "no applicability tree"}
        malformed = {"id": "CVE-2026-67890", "configurations": [{"nodes": "invalid"}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nvd.json"
            path.write_text(json.dumps({"vulnerabilities": {r["id"]: r for r in (record, unrelated, legacy, malformed)}}))
            with bounded_reads(path):
                result = data.load_offline_cpe_data(path, None, [APP])
            self.assertFalse(result.fatal)
            self.assertEqual(set(result.nvd), {record["id"], legacy["id"], malformed["id"]})
            self.assertEqual(result.nvd[record["id"]]["configurations"], record["configurations"])
            self.assertEqual(result.sources[0].metadata["applicabilityRecords"], 3)
            self.assertEqual(result.sources[0].metadata["legacyDetailsOnly"], 1)

    def test_compact_keys_duplicate_members_and_multiple_files_keep_last_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "one.json"
            path.write_text('{"vulnerabilities":{"CVE-2026-12345":{"id":"wrong","description":"old","configurations":[{}]},"CVE-2026-12345":{"id":"wrong","description":"new"}}}')
            with bounded_reads(path):
                result = data.load_offline_data(path, None, ["CVE-2026-12345"])
            self.assertEqual(result.nvd["CVE-2026-12345"]["description"], "new")
            self.assertEqual(result.nvd["CVE-2026-12345"]["id"], "CVE-2026-12345")
            self.assertEqual(result.sources[0].metadata["applicabilityRecords"], 0)
            self.assertEqual(result.sources[0].metadata["legacyDetailsOnly"], 1)
            (root / "two.json").write_text('{"vulnerabilities":[{"cve":{"id":"CVE-2026-12345","description":"last file"}}]}')
            result = data.load_offline_data(root, None, ["CVE-2026-12345"])
            self.assertEqual(result.nvd["CVE-2026-12345"]["description"], "last file")

    def test_missing_empty_root_legacy_and_malformed_json_contracts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nvd.json"
            for raw, expected_fatal, expected_id in (
                ('{}', False, None),
                ('{"CVE_Items":[{"cve":{"CVE_data_meta":{"ID":"CVE-2026-12345"}}}]}', False, 'CVE-2026-12345'),
                ('{"vulnerabilities":null,"CVE_Items":[{"id":"CVE-2026-12345"}]}', False, None),
                ('{"vulnerabilities":[],"vulnerabilities":[{"id":"CVE-2026-12345"}]}', False, 'CVE-2026-12345'),
                ('[]', True, None),
                ('{"vulnerabilities":[]} trailing', True, None),
            ):
                with self.subTest(raw=raw):
                    path.write_text(raw)
                    with bounded_reads(path):
                        result = data.load_offline_data(path, None, ['CVE-2026-12345'])
                    self.assertEqual(result.fatal, expected_fatal)
                    if not expected_fatal:
                        self.assertEqual(set(result.nvd), {expected_id} if expected_id else set())
            missing = data.load_offline_data(Path(tmp) / "missing.json", None, [])
            self.assertTrue(missing.fatal)

    def test_explicit_all_records_and_large_unrelated_corpus_keep_selection_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nvd.json"
            path.write_text('{"vulnerabilities":[{"id":"CVE-2026-12345"},{"id":"CVE-2026-54321"}]}')
            warnings = []
            all_records, _, _, fatal = data._load_nvd(path, None, warnings)
            self.assertFalse(fatal)
            self.assertEqual(set(all_records), {"CVE-2026-12345", "CVE-2026-54321"})
            with path.open('w', encoding='utf-8') as stream:
                stream.write('{"vulnerabilities":[')
                for index in range(20_000):
                    if index:
                        stream.write(',')
                    stream.write(json.dumps({'id': f'CVE-2026-{10000 + index}', 'description': 'padding' * 300 + '😃'}, ensure_ascii=False))
                stream.write(']}')
            self.assertGreater(path.stat().st_size, 40 * 1024 * 1024)
            tracemalloc.start()
            try:
                selected = data.load_offline_data(path, None, ['CVE-2026-12345'])
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            self.assertEqual(set(selected.nvd), {'CVE-2026-12345'})
            self.assertLess(peak, 16 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
