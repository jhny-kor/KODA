import json
from unittest import TestCase
from unittest.mock import patch

from security_scanner.har_review import review_har


class HarReviewTests(TestCase):
    def test_recorded_evidence_omits_raw_request_and_response_values(self):
        request = {
            "method": "POST",
            "url": "https://person:private@example.test/account/private-path?session=private-query",
            "headers": [{"name": "Authorization", "value": "private-header"}],
            "postData": {"text": "private-request-body"},
        }
        response = {
            "status": 200,
            "headers": [
                {"name": "Content-Type", "value": "text/html; charset=utf-8"},
                {"name": "Set-Cookie", "value": "private-cookie-name=private-cookie-value"},
                {"name": "Server", "value": "private-server 1.0"},
            ],
            "content": {"text": "private-response-body"},
        }
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS query")):
            result = review_har(json.dumps({"log": {"entries": [
                {"request": request, "response": response},
                {"request": request, "response": {"status": 0, "headers": []}},
            ]}}).encode())
        self.assertEqual(result["responses_reviewed"], 1)
        self.assertEqual(result["request_methods"], {"POST": 2})
        self.assertEqual(result["credential_header_observations"], {"requests": 2, "write_requests": 2, "over_http": []})
        rules = {row["rule_id"]: row for row in result["findings"]}
        self.assertEqual(rules["web.missing-csp"]["entries"], [1])
        self.assertEqual(rules["web.cookie-missing-httponly"]["origin"], "https://example.test")
        self.assertIn("web.server-version-disclosure", rules)
        self.assertNotIn("private", json.dumps(result))

    def test_reports_plain_http_credential_headers_with_no_response(self):
        raw = {"log": {"entries": [
            {"request": {"method": "PUT", "url": "http://example.test/private-path",
                         "headers": [{"name": "COOKIE", "value": "private-cookie"}]}},
            {"request": {"method": "GET", "url": "http://example.test",
                         "headers": [{"name": "Authorization", "value": ""}]}},
        ]}}
        result = review_har(json.dumps(raw).encode())
        self.assertEqual(result["status"], "NO_RESPONSES")
        self.assertEqual(result["credential_header_observations"], {
            "requests": 1, "write_requests": 1, "over_http": [{"origin": "http://example.test", "entries": [1]}],
        })
        self.assertNotIn("private", json.dumps(result))

    def test_missing_response_headers_and_malformed_har(self):
        result = review_har(b'{"log":{"entries":[{"request":{"method":"GET","url":"https://example.test"}}]}}')
        self.assertEqual(result["status"], "NO_RESPONSES")
        self.assertEqual(result["findings"], [])
        with self.assertRaisesRegex(ValueError, "log.entries"):
            review_har(b'{"log":{"entries":{}}}')
