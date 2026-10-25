from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "platforms/shared/python"))
from security_scanner.offline_cpe import GLOBAL_PRODUCT, MAX_DEPTH, MAX_NODES, evaluate, product_key, candidate_index
from security_scanner.cpe_lookup import query_offline_cpe_vulnerabilities


APP = "cpe:2.3:a:acme:widget:1.2.0:*:*:*:*:*:*:*"
OS = "cpe:2.3:o:acme:server:8.0:*:*:*:*:*:*:*"


def leaf(**kwargs):
    return {"criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", "vulnerable": True, **kwargs}


def config(*matches, operator="OR", **kwargs):
    return [{"nodes": [{"operator": operator, "cpeMatch": list(matches), **kwargs}]}]


class OfflineCpeTests(unittest.TestCase):
    def setUp(self):
        # Explicit local-file development fixtures; Linux production defaults
        # are exercised independently by test_managed_data_current_only.
        local_profile = patch("security_scanner.data_release.sys", SimpleNamespace(platform="darwin"))
        local_profile.start()
        self.addCleanup(local_profile.stop)

    def test_numeric_bounds_and_exact_product(self):
        tree = config(leaf(versionStartIncluding="1.2", versionEndExcluding="2.0"))
        self.assertEqual(evaluate(tree, [APP]).status, "affected")
        self.assertEqual(evaluate(tree, [APP.replace("1.2.0", "2.0")]).status, "not_affected")
        self.assertEqual(evaluate(tree, [APP.replace("acme:widget", "other:widget")]).status, "unknown")
        self.assertEqual(candidate_index({"CVE-2026-1234": {"configurations": tree}})[("a", "acme", "widget")], {"CVE-2026-1234"})

    def test_escaped_separator_and_literal_wildcard(self):
        actual = r"cpe:2.3:a:acme:widget\:pro:1.2:*:*:*:*:*:*:*"
        self.assertEqual(product_key(actual), ("a", "acme", "widget:pro"))
        self.assertEqual(evaluate(config(leaf(criteria=actual)), [actual]).status, "affected")
        star = r"cpe:2.3:a:acme:widget\*:1.2:*:*:*:*:*:*:*"
        self.assertEqual(product_key(star)[2], "widget*")
        self.assertEqual(evaluate(config(leaf(criteria=star)), [star]).status, "affected")
        with self.assertRaises(ValueError):
            product_key(star + "\\")

    def test_environment_and_negation_are_not_flattened(self):
        environment = leaf(criteria=OS, vulnerable=False)
        tree = config(leaf(versionEndExcluding="2"), environment, operator="AND")
        self.assertEqual(evaluate(tree, [APP]).status, "unknown")
        result = evaluate(tree, [APP, OS])
        self.assertEqual(result.status, "affected")
        self.assertEqual(result.matched_cpes, (APP,))
        self.assertEqual(evaluate(tree, [APP, OS.replace("8.0", "9.0")]).status, "not_affected")
        negated = [{"operator": "AND", "nodes": [{"cpeMatch": [leaf()]}, {"negate": True, "cpeMatch": [environment]}]}]
        self.assertEqual(evaluate(negated, [APP]).status, "unknown")
        self.assertEqual(evaluate(negated, [APP, OS]).status, "not_affected")
        self.assertEqual(evaluate(negated, [APP], complete_inventory=True).status, "affected")

    def test_unknown_and_environment_only_never_emit_vulnerabilities(self):
        for conditions in (None, [], config(leaf(vulnerable=False)), config(leaf(), negate=True), config(leaf(), operator="XOR")):
            self.assertEqual(evaluate(conditions, [APP]).matched_cpes, ())
        self.assertEqual(evaluate(config(leaf(versionEndIncluding="1.2.0")), [APP.replace("1.2.0", "1.2rc1")]).status, "unknown")
        self.assertEqual(evaluate(config(leaf()), [APP.replace("1.2.0", "*")]).status, "unknown")

    def test_wildcard_criteria_match_concrete_identity_but_not_ambiguous_inventory(self):
        conditions = config(leaf(criteria="cpe:2.3:*:acme:wid*:*:*:*:*:*:*:*:*", versionEndExcluding="2"))
        self.assertEqual(evaluate(conditions, [APP]).status, "affected")
        self.assertEqual(evaluate(conditions, [APP.replace("acme", "different")]).status, "unknown")
        self.assertEqual(evaluate(conditions, [APP.replace("widget", "*")]).status, "unknown")

    def test_index_never_silently_discards_deep_complex_or_malformed_records(self):
        deep = {"cpeMatch": [leaf()]}
        for _ in range(MAX_DEPTH + 1):
            deep = {"nodes": [deep]}
        conditions = ([deep], [{"operator": "OR", "cpeMatch": [leaf()] * (MAX_NODES + 1)}],
                      [{"operator": [], "cpeMatch": [leaf()]}], [{"nodes": "bad"}])
        for malformed in conditions:
            issues = {}
            index = candidate_index({"normal": {"configurations": config(leaf())}, "omitted": {"configurations": malformed}}, issues=issues)
            self.assertIn("normal", index[product_key(APP)])
            self.assertIn("omitted", index[GLOBAL_PRODUCT])
            self.assertIn("omitted", issues)

    def test_nested_or_exposes_only_satisfied_vulnerable_branches(self):
        different = APP.replace("widget", "other")
        tree = [{"nodes": [{"operator": "OR", "children": [{"cpeMatch": [leaf()]}, {"operator": "AND", "cpeMatch": [leaf(criteria=different), leaf(criteria=OS, vulnerable=False)]}]}]}]
        self.assertEqual(evaluate(tree, [APP, different]).matched_cpes, (APP,))

    def test_local_raw_and_compact_feeds_without_network(self):
        record = {"id": "CVE-2026-12345", "configurations": config(leaf(versionEndExcluding="2")), "description": "Example"}
        with TemporaryDirectory() as root, patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")):
            path = Path(root) / "nvd.json"
            for payload in ({"vulnerabilities": [{"cve": record}]}, {"vulnerabilities": {record["id"]: record}}):
                path.write_text(json.dumps(payload))
                findings, warnings, summary = query_offline_cpe_vulnerabilities([APP], nvd_source=path)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["cve"], record["id"])
                self.assertEqual(summary["status"], "completed")
                self.assertEqual(summary["unknownCves"], 0)
            path.write_text(json.dumps({"vulnerabilities": {record["id"]: {"id": record["id"], "cpe": [APP]}}}))
            findings, _, _ = query_offline_cpe_vulnerabilities([APP], nvd_source=path)
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
