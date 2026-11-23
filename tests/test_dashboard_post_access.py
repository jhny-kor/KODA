from __future__ import annotations

import http.client
import io
import json
import sys
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.server import create_dashboard_server


class _DashboardServerCase(unittest.TestCase):
    local_only = False

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = create_dashboard_server(port=0, local_only=cls.local_only)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"
        response = cls.request("GET", "/api/health")
        cls.session = response.getheader("X-KODA-Session")
        response.read()
        assert cls.session

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    @classmethod
    def request(cls, method: str, path: str, body: str | bytes | None = None, headers: dict[str, str] | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", cls.server.server_port)
        connection.request(method, path, body=body, headers=headers or {})
        return connection.getresponse()


class DashboardPostAccessTests(_DashboardServerCase):
    def test_every_dashboard_post_rejects_cross_origin(self) -> None:
        paths = (
            "/api/scan", "/api/scan-upload", "/api/web-scan", "/api/zap-scan",
            "/api/select-directory", "/api/prevention-kit", "/api/export", "/api/desktop-projects",
        )
        for path in paths:
            with self.subTest(path=path):
                response = self.request("POST", path, body="{}", headers={
                    "Content-Type": "text/plain", "Origin": "https://attacker.example",
                    "X-KODA-Session": self.session,
                })
                self.assertEqual(response.status, 403)
                response.read()

    def test_same_origin_session_json_keeps_directory_picker_working(self) -> None:
        with patch("security_scanner.server.select_directory", return_value="/tmp/selected") as picker:
            response = self.request("POST", "/api/select-directory", json.dumps({"current_path": "/tmp"}), {
                "Content-Type": "application/json; charset=utf-8",
                "Origin": self.origin,
                "X-KODA-Session": self.session,
            })
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read())["path"], "/tmp/selected")
            picker.assert_called_once_with("/tmp")

    def test_missing_session_simple_content_type_and_dns_rebinding_are_rejected(self) -> None:
        cases = (
            ({"Content-Type": "application/json", "Origin": self.origin}, 403),
            ({"Content-Type": "text/plain", "Origin": self.origin, "X-KODA-Session": self.session}, 415),
            ({"Content-Type": "application/json", "Origin": self.origin.replace("http:", "https:"),
              "X-KODA-Session": self.session}, 403),
            ({"Content-Type": "application/json", "Host": f"attacker.example:{self.server.server_port}",
              "Origin": f"http://attacker.example:{self.server.server_port}", "X-KODA-Session": self.session}, 403),
        )
        with patch("security_scanner.server.select_directory", return_value="/tmp/selected") as picker:
            for headers, expected in cases:
                with self.subTest(headers=headers):
                    response = self.request("POST", "/api/select-directory", "{}", headers)
                    self.assertEqual(response.status, expected)
                    response.read()
            picker.assert_not_called()

    def test_cross_origin_preflight_is_rejected(self) -> None:
        response = self.request("OPTIONS", "/api/scan", headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "POST",
        })
        self.assertEqual(response.status, 403)
        response.read()


class LocalOnlyDashboardTests(_DashboardServerCase):
    local_only = True

    @classmethod
    def setUpClass(cls) -> None:
        with patch("security_scanner.server.platform.system", return_value="Darwin"):
            super().setUpClass()

    def test_local_dashboard_rejects_other_hosts_and_live_operations(self) -> None:
        with self.assertRaises(ValueError):
            create_dashboard_server(host="0.0.0.0", port=0, local_only=True)
        response = self.request("GET", "/api/health", headers={"Host": "unknown.test"})
        self.assertEqual(response.status, 403)
        self.assertIsNone(response.getheader("X-KODA-Session"))
        response.read()
        response = self.request("GET", "/", headers={"Origin": "http://127.0.0.1:9999"})
        self.assertIsNone(response.getheader("Access-Control-Allow-Origin"))
        self.assertEqual(response.getheader("X-Frame-Options"), "DENY")
        self.assertIn(b'<body class="local-only">', response.read())
        for path in ("/api/web-scan", "/api/zap-scan", "/api/web-audit/plan", "/api/web-audit/approve", "/api/web-audit/run"):
            with self.subTest(path=path):
                response = self.request("POST", path, "{}", {
                    "Content-Type": "application/json", "Origin": self.origin, "X-KODA-Session": self.session,
                })
                self.assertEqual(response.status, 404)
                response.read()

    def test_local_scan_ignores_online_enrichment(self) -> None:
        with patch("security_scanner.server.scan_directory_payload", return_value={}) as scan:
            response = self.request("POST", "/api/scan", json.dumps({
                "path": "/tmp/selected", "enable_osv": True,
            }), {
                "Content-Type": "application/json", "Origin": self.origin, "X-KODA-Session": self.session,
            })
            self.assertEqual(response.status, 200)
            response.read()
            self.assertFalse(scan.call_args.kwargs["enable_osv"])

    def test_local_dashboard_reserves_child_stdout_for_startup(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            response = self.request("GET", "/api/health")
            self.assertEqual(response.status, 200)
            response.read()
        self.assertEqual(output.getvalue(), "")

    def test_har_review_only_accepts_authenticated_local_uploads(self) -> None:
        response = self.request("GET", "/har-review")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Cache-Control"), "no-store")
        self.assertIn(b"/api/har-review", response.read())
        recording = b'{"log":{"entries":[]}}'
        headers = {"Content-Type": "application/octet-stream", "Origin": self.origin}
        response = self.request("POST", "/api/har-review", recording, headers)
        self.assertEqual(response.status, 403)
        response.read()
        headers["X-KODA-Session"] = self.session
        response = self.request("POST", "/api/har-review", recording, headers)
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.read())["status"], "NO_RESPONSES")

    def test_tcp_listener_inventory_requires_local_dashboard_session(self) -> None:
        response = self.request("GET", "/local-listeners")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Cache-Control"), "no-store")
        self.assertIn(b"/api/local-listeners", response.read())
        payload = {"platform": "macos", "status": "completed", "listeners": [], "warnings": []}
        with patch("security_scanner.local_listeners.collect_local_listeners", return_value=payload) as collect:
            response = self.request("POST", "/api/local-listeners", headers={"Origin": self.origin})
            self.assertEqual(response.status, 403)
            response.read()
            collect.assert_not_called()
            response = self.request("POST", "/api/local-listeners", headers={
                "Origin": self.origin, "X-KODA-Session": self.session,
            })
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read()), payload)
            collect.assert_called_once_with()

    def test_certificate_review_uses_bounded_local_upload_only(self) -> None:
        response = self.request("GET", "/crypto-review")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Cache-Control"), "no-store")
        self.assertIn(b"/api/tls-cert-review", response.read())
        payload = {"validity": "VALID"}
        headers = {"Content-Type": "application/octet-stream", "Origin": self.origin}
        with patch("security_scanner.certificate_review.review_certificate", return_value=payload) as review:
            response = self.request("POST", "/api/tls-cert-review", b"recorded-certificate", headers)
            self.assertEqual(response.status, 403)
            response.read()
            review.assert_not_called()
            headers["X-KODA-Session"] = self.session
            response = self.request("POST", "/api/tls-cert-review", b"recorded-certificate", headers)
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read()), payload)
            review.assert_called_once_with(b"recorded-certificate")

    def test_app_sandbox_reports_its_own_listener_when_os_inventory_is_unavailable(self) -> None:
        payload = {"platform": "macos", "status": "unavailable", "listeners": [], "warnings": []}
        with patch("security_scanner.local_listeners.collect_local_listeners", return_value=payload):
            response = self.request("POST", "/api/local-listeners", headers={
                "Origin": self.origin, "X-KODA-Session": self.session,
            })
            self.assertEqual(response.status, 200)
            report = json.loads(response.read())
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["listeners"], [
            {"address": "127.0.0.1", "port": self.server.server_port, "family": "IPv4", "binding": "loopback"},
        ])


if __name__ == "__main__":
    unittest.main()
