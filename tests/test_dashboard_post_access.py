from __future__ import annotations

import http.client
import json
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.server import create_dashboard_server


class DashboardPostAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = create_dashboard_server(port=0)
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

    def test_every_dashboard_post_rejects_cross_origin(self) -> None:
        paths = (
            "/api/scan", "/api/scan-upload", "/api/web-scan", "/api/zap-scan",
            "/api/select-directory", "/api/prevention-kit", "/api/export",
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


if __name__ == "__main__":
    unittest.main()
