from __future__ import annotations

import http.server
import socket
import socketserver
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner import netprobe


class PortScanTests(unittest.TestCase):
    def test_open_port_is_reported(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            findings = netprobe.port_scan("127.0.0.1", ports={port: "test"}, timeout=1.0)
            self.assertTrue([f for f in findings if f.rule_id == "net.port-exposed"])
        finally:
            listener.close()

    def test_closed_port_is_quiet(self):
        # Bind then close to get a port nothing listens on.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        findings = netprobe.port_scan("127.0.0.1", ports={port: "test"}, timeout=0.5)
        self.assertEqual(findings, [])


class DefaultCredentialTests(unittest.TestCase):
    def _server(self):
        class Basic(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                auth = self.headers.get("Authorization", "")
                import base64 as _b64
                ok = False
                if auth.startswith("Basic "):
                    try:
                        user, _, pw = _b64.b64decode(auth[6:]).decode().partition(":")
                        ok = (user, pw) == ("admin", "admin")
                    except Exception:
                        ok = False
                if ok:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"welcome")
                else:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="admin"')
                    self.end_headers()
                    self.wfile.write(b"auth required")

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Basic)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def test_default_credentials_detected_when_authorized(self):
        server = self._server()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/admin"
            findings = netprobe.default_credential_check(url, timeout=5.0, authorize=True)
            self.assertTrue([f for f in findings if f.rule_id == "net.default-credentials"])
        finally:
            server.shutdown()
            server.server_close()

    def test_no_check_without_authorization(self):
        server = self._server()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/admin"
            self.assertEqual(netprobe.default_credential_check(url, authorize=False), [])
        finally:
            server.shutdown()
            server.server_close()


class ActiveTlsTests(unittest.TestCase):
    def test_non_tls_port_is_handled_gracefully(self):
        # A plain HTTP port is not TLS; the probe must return cleanly, not raise.
        server = socketserver.TCPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            findings = netprobe.active_tls_probe("127.0.0.1", server.server_address[1], timeout=2.0)
            self.assertIsInstance(findings, list)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
