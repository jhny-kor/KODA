from __future__ import annotations

import http.server
import socket
import socketserver
import sys
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner import netprobe


class HttpProbeBoundaryTests(unittest.TestCase):
    def test_non_http_targets_are_rejected_before_io(self):
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "private.txt"
            private.write_text("private probe data", encoding="utf-8")
            targets = (private.as_uri(), "ftp://127.0.0.1/private.txt",
                       "data:text/plain,private", "http://127.0.0.1:invalid/",
                       "http:///missing-host", "http://127.0.0.1/\nprivate")
            for url in targets:
                with self.subTest(url=url), \
                        patch("builtins.open", side_effect=AssertionError("local file I/O")) as file_io, \
                        patch("socket.create_connection", side_effect=AssertionError("network I/O")) as network_io:
                    with self.assertRaises(urllib.error.URLError):
                        netprobe._http_open(url, timeout=1.0)
                    self.assertEqual(netprobe.default_credential_check(url, authorize=True), [])
                    file_io.assert_not_called()
                    network_io.assert_not_called()

    def test_http_redirects_work_but_cannot_read_files_or_use_ftp(self):
        destinations = {}
        user_agents = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                user_agents.append(self.headers.get("User-Agent", ""))
                if self.path in destinations:
                    self.send_response(302)
                    self.send_header("Location", destinations[self.path])
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"HTTP probe response")

            def log_message(self, *args):
                pass

        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "private.txt"
            private.write_text("private probe data", encoding="utf-8")
            destinations.update({"/file": private.as_uri(), "/ftp": "ftp://127.0.0.1/private.txt",
                                 "/http": "/probe"})
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                with netprobe._http_open(base + "/http", timeout=2.0) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), b"HTTP probe response")
                for path in ("/file", "/ftp"):
                    with self.subTest(path=path), \
                            patch("urllib.request.FileHandler.file_open", side_effect=AssertionError("local file read")) as file_io, \
                            patch("urllib.request.FTPHandler.ftp_open", side_effect=AssertionError("FTP request")) as ftp_io:
                        with self.assertRaises(urllib.error.URLError):
                            netprobe._http_open(base + path, timeout=2.0)
                        file_io.assert_not_called()
                        ftp_io.assert_not_called()
                self.assertTrue(user_agents)
                self.assertTrue(all(agent.startswith("Python-urllib/") for agent in user_agents))
            finally:
                server.shutdown()
                server.server_close()


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


class ServiceAuthTests(unittest.TestCase):
    def test_redis_without_auth_is_flagged(self):
        class RedisHandler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(64)  # PING
                self.request.sendall(b"+PONG\r\n")
                self.request.recv(64)  # INFO server
                self.request.sendall(b"# Server\r\nredis_version:7.0.0\r\n")

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), RedisHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            findings = netprobe._redis_unauth("127.0.0.1", 2.0, port=server.server_address[1])
            self.assertTrue([f for f in findings if f.rule_id == "net.redis-unauth"])
        finally:
            server.shutdown()
            server.server_close()

    def test_redis_with_auth_is_quiet(self):
        class NoAuth(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(64)
                self.request.sendall(b"-NOAUTH Authentication required.\r\n")

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), NoAuth)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            self.assertEqual(netprobe._redis_unauth("127.0.0.1", 2.0, port=server.server_address[1]), [])
        finally:
            server.shutdown()
            server.server_close()

    def test_http_service_unauth_detected(self):
        class ESHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"cluster_name":"prod","version":{}}')

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), ESHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            findings = netprobe._http_unauth("127.0.0.1", server.server_address[1], "/", "elasticsearch", "cluster_name", 2.0)
            self.assertTrue([f for f in findings if f.rule_id == "net.elasticsearch-unauth"])
        finally:
            server.shutdown()
            server.server_close()


class MongoUnauthTests(unittest.TestCase):
    def _server(self, reply_body: bytes):
        import struct

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(4096)
                self.request.sendall(struct.pack("<i", 4 + len(reply_body)) + reply_body)

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def test_unauth_mongo_flagged(self):
        server = self._server(b"\x00" * 16 + b"databases\x00payload")
        try:
            findings = netprobe._mongodb_unauth("127.0.0.1", 3.0, port=server.server_address[1])
            self.assertTrue([f for f in findings if f.rule_id == "net.mongodb-unauth"])
        finally:
            server.shutdown()
            server.server_close()

    def test_auth_required_mongo_quiet(self):
        server = self._server(b"\x00" * 16 + b"command listDatabases requires authentication")
        try:
            self.assertEqual(netprobe._mongodb_unauth("127.0.0.1", 3.0, port=server.server_address[1]), [])
        finally:
            server.shutdown()
            server.server_close()


class TriageOnWebFindingsTests(unittest.TestCase):
    def test_web_finding_is_triaged_via_injected_backend(self):
        from security_scanner.ai import provider, triage
        from security_scanner.models import Finding

        finding = Finding(
            rule_id="net.default-credentials", category="web", severity="high",
            title="Default credentials accepted", path=Path("http://h/admin"),
            target="http://h/admin", evidence="published default 'admin:admin' was accepted",
        )

        def fake_complete(prompt, *, system, json_mode, model, timeout_seconds):
            verdict = "likely_true" if "exploitable" in system.lower() or "true" in system.lower() else "likely_true"
            return provider.LLMResult(
                text='{"verdict": "' + verdict + '", "confidence": 0.9, "reason": "test"}',
                backend="test", sent_externally=False,
            )

        triaged, warnings = triage.triage_findings([finding], complete=fake_complete)
        self.assertEqual(triaged[0].triage_verdict, "likely_true")
        self.assertEqual(warnings, [])


if __name__ == "__main__":
    unittest.main()
