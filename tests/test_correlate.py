from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner import correlate


class CorrelateTests(unittest.TestCase):
    def setUp(self):
        self.src = Path(tempfile.mkdtemp()) / "app.py"
        self.src.write_text(
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n"
            "\n"
            '@app.route("/users/<int:uid>")\n'
            "def user(uid):\n"
            '    cur.execute("SELECT * FROM u WHERE id = " + request.args["id"])\n'
            "\n"
            '@app.get("/ping")\n'
            "def ping():\n"
            '    os.system("ping " + request.args["h"])\n',
            encoding="utf-8",
        )

    def _code(self, rule, line):
        return {"rule_id": rule, "path": str(self.src), "line": line}

    def test_same_weakness_same_endpoint(self):
        result = correlate.correlate(
            [self._code("code.sql-dynamic-query", 6)],
            [{"rule_id": "web.sql-injection-error-verified", "path": "https://app.test/users/42?id=1"}],
        )
        self.assertEqual(result["summary"]["corroborated"], 1)
        item = result["corroborated"][0]
        self.assertEqual(item["weakness"], "SQL injection")
        self.assertTrue(item["same_endpoint"])
        self.assertEqual(item["endpoints"][0]["route"], "/users/<int:uid>")

    def test_same_weakness_different_endpoint(self):
        result = correlate.correlate(
            [self._code("code.command-injection", 10)],
            [{"rule_id": "web.command-injection-time-blind", "path": "https://app.test/other?x=1"}],
        )
        self.assertEqual(result["summary"]["corroborated"], 1)
        self.assertFalse(result["corroborated"][0]["same_endpoint"])

    def test_static_only_and_dynamic_only(self):
        result = correlate.correlate(
            [self._code("code.sql-dynamic-query", 6)],
            [{"rule_id": "web.ssrf-cloud-metadata", "path": "https://app.test/fetch?url=x"}],
        )
        self.assertEqual(result["summary"], {"corroborated": 0, "same_endpoint": 0, "static_only": 1, "dynamic_only": 1})
        self.assertEqual(result["static_only"][0]["weakness"], "SQL injection")
        self.assertEqual(result["dynamic_only"][0]["weakness"], "SSRF")

    def test_unreadable_source_still_correlates_by_weakness(self):
        result = correlate.correlate(
            [{"rule_id": "code.path-traversal", "path": "/nonexistent/x.py", "line": 3}],
            [{"rule_id": "web.path-traversal-lfi", "path": "https://app.test/read?f=a"}],
        )
        self.assertEqual(result["summary"]["corroborated"], 1)
        self.assertFalse(result["corroborated"][0]["same_endpoint"])

    def test_collapsed_scheme_from_web_report_still_matches_endpoint(self):
        # Real web-scan JSON stores the URL as a Path, collapsing "//" -> "/".
        result = correlate.correlate(
            [self._code("code.sql-dynamic-query", 6)],
            [{"rule_id": "web.sql-injection-error-verified", "path": "http:/127.0.0.1:8765/users/42?id=1"}],
        )
        item = result["corroborated"][0]
        self.assertTrue(item["same_endpoint"])
        self.assertEqual(item["web"], ["http://127.0.0.1:8765/users/42?id=1"])

    def test_route_matching_rules(self):
        self.assertTrue(correlate._route_matches("/users/<int:uid>", "/users/42"))
        self.assertTrue(correlate._route_matches("/items/{item_id}", "/items/abc"))
        self.assertTrue(correlate._route_matches("/a/:id", "/a/7"))
        self.assertFalse(correlate._route_matches("/users/<uid>", "/users/42/extra"))
        self.assertFalse(correlate._route_matches("/users", "/accounts"))

    def test_markdown_lists_sections(self):
        result = correlate.correlate(
            [self._code("code.sql-dynamic-query", 6)],
            [{"rule_id": "web.sql-injection-time-blind", "path": "https://app.test/users/1"}],
        )
        text = correlate.render_markdown(result, language="en")
        self.assertIn("Corroborated (fix first)", text)
        self.assertIn("same endpoint", text)


if __name__ == "__main__":
    unittest.main()
