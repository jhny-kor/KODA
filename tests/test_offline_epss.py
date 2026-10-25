import copy
import gzip
import hashlib
import os
import tempfile
import unittest
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from security_scanner import offline_epss


AT = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
CVE = "CVE-2021-44228"
OTHER = "CVE-2024-12345"


def csv_bytes(day="2026-10-19", rows=None):
    return (f"#model_version:v2025.03.14,score_date:{day}T00:00:00+0000\n"
            "cve,epss,percentile\n" + (rows if rows is not None else f"{CVE},0.94,0.99\n")).encode()


class OfflineEpssTests(unittest.TestCase):
    def setUp(self):
        # Explicit local-file development fixtures; Linux production defaults
        # are exercised independently by test_managed_data_current_only.
        local_profile = patch("security_scanner.data_release.sys", SimpleNamespace(platform="darwin"))
        local_profile.start()
        self.addCleanup(local_profile.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "epss.csv.gz"

    def write(self, raw):
        self.path.write_bytes(raw)
        return self.path

    def test_fresh_gzip_enriches_record_and_nested_advisory_without_network(self):
        raw = gzip.compress(csv_bytes(), mtime=0)
        self.write(raw)
        original = [{"vulnerability_id": CVE, "severity": "medium", "advisories": [{"cve_ids": [CVE]}]}]
        before = copy.deepcopy(original)
        with patch("urllib.request.urlopen", side_effect=AssertionError("unexpected HTTP")), patch("socket.create_connection", side_effect=AssertionError("unexpected socket")):
            result = offline_epss.enrich_records(original, self.path, at=AT)
        record = result[0]
        self.assertEqual(record["epss_score"], .94)
        self.assertEqual(record["epss_date"], "2026-10-19")
        self.assertEqual(record["epss_status"], "fresh")
        self.assertTrue(record["epss_policy_eligible"])
        self.assertEqual(record["epss_source"]["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(record["epss_source"]["model_version"], "v2025.03.14")
        self.assertEqual(record["advisories"][0]["epss_score"], .94)
        self.assertEqual(original, before)
        self.assertEqual(record["severity"], "medium")

    def test_past_score_remains_observed_and_cannot_drive_current_policy(self):
        self.write(csv_bytes(day="2026-09-01"))
        record = offline_epss.enrich_records([{"cve_ids": [CVE]}], self.path, at=AT)[0]
        self.assertEqual((record["epss_score"], record["epss_date"], record["epss_status"]), (.94, "2026-09-01", "stale"))
        self.assertFalse(record["epss_policy_eligible"])
        self.assertEqual(record["epss_source"]["age_days"], 48)

    def test_age_configuration_and_missing_score_are_separate(self):
        self.write(csv_bytes(day="2026-10-12"))
        self.assertTrue(offline_epss.enrich_records([{"id": CVE}], self.path, at=AT, max_age_days=7)[0]["epss_policy_eligible"])
        self.assertFalse(offline_epss.enrich_records([{"id": CVE}], self.path, at=AT, max_age_days=6)[0]["epss_policy_eligible"])
        missing = offline_epss.enrich_records([{"id": OTHER}], self.path, at=AT)[0]
        self.assertEqual(missing["epss_status"], "missing")
        self.assertNotIn("epss_score", missing)

    def test_aliases_and_multiple_cves_preserve_all_evidence_and_choose_highest(self):
        self.write(csv_bytes(rows=f"{CVE},.2,.9\n{OTHER},.8,.99\n"))
        record = offline_epss.enrich_records([{"id": "GHSA-example", "aliases": [OTHER, CVE]}], self.path, at=AT)[0]
        self.assertEqual(record["epss_cve"], OTHER)
        self.assertEqual(record["epss_score"], .8)
        self.assertEqual(len(record["epss_records"]), 2)
        source, scores = offline_epss.load_snapshot(self.path, {CVE}, at=AT)
        self.assertEqual(source["record_count"], 2)
        self.assertEqual(set(scores), {CVE})

    def test_duplicate_or_invalid_unrequested_row_rejects_whole_file_and_clears_old_evidence(self):
        for tail in (f"{OTHER},.2,.3\n{OTHER},.2,.3\n", f"{OTHER},nan,.3\n", f"{OTHER},.2\n"):
            with self.subTest(tail=tail):
                self.write(csv_bytes(rows=f"{CVE},.9,.99\n" + tail))
                record = offline_epss.enrich_records([{"id": CVE, "epss_score": .1, "epss_date": "2020-01-01"}], self.path, at=AT)[0]
                self.assertEqual(record["epss_status"], "invalid")
                self.assertNotIn("epss_score", record)
                self.assertFalse(record["epss_policy_eligible"])

    def test_pinned_release_path_is_used_and_missing_file_is_not_zero(self):
        self.write(csv_bytes())
        with patch("security_scanner.data_release.epss_path", return_value=self.path, create=True) as resolver:
            self.assertEqual(offline_epss.enrich_records([{"id": CVE}], at=AT)[0]["epss_score"], .94)
            resolver.assert_called_once_with()
        missing = offline_epss.enrich_records([{"id": CVE}], self.path.with_name("missing.csv"), at=AT)[0]
        self.assertEqual(missing["epss_status"], "missing")
        self.assertNotIn("epss_score", missing)
        self.assertEqual(offline_epss.enrich_records([{"id": "GHSA-example"}], self.path, at=AT)[0]["epss_status"], "not_applicable")

    def test_future_source_date_corrupt_gzip_and_expanded_size_are_rejected(self):
        for raw in (csv_bytes(day="2026-10-25"), b"\x1f\x8bcorrupt", csv_bytes(rows="")):
            self.write(raw)
            self.assertEqual(offline_epss.enrich_records([{"id": CVE}], self.path, at=AT)[0]["epss_status"], "invalid")
        self.write(gzip.compress(csv_bytes()))
        with patch.object(offline_epss, "MAX_EXPANDED_BYTES", 20):
            self.assertEqual(offline_epss.enrich_records([{"id": CVE}], self.path, at=AT)[0]["epss_status"], "invalid")

    def test_invalid_policy_configuration_does_not_silently_use_a_score(self):
        self.write(csv_bytes())
        for days in (True, -1, 366, "bad"):
            with self.subTest(days=days):
                result = offline_epss.enrich_records([{"id": CVE}], self.path, at=AT, max_age_days=days)[0]
                self.assertEqual(result["epss_status"], "invalid")
                self.assertNotIn("epss_score", result)


if __name__ == "__main__":
    unittest.main()
