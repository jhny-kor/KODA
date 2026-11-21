"""End-to-end coverage for KODA's intrusive web active-scan detectors.

Spins up a localhost-only, deliberately-vulnerable fixture server and runs the
real ``web.active_probe`` / ``web.crawl_web`` against it, asserting the expected
rule_ids fire. Covers the deeper tier the passive/reflected checks skip:
time-blind SQLi, time-blind + OOB OS command injection, blind SSRF (OOB),
cloud-metadata SSRF, and stored (second-order) XSS.

All traffic stays on 127.0.0.1 and all payloads are benign (sleep/callback
markers only, no destructive actions). The fixture is test scaffolding, not a
product component. Slow: the time-blind detectors issue real delayed requests,
so the two injection cases take a few seconds each.
"""
from __future__ import annotations

import re
import sys
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner import web  # noqa: E402

# Parse the sleep seconds out of whatever SQL/shell delay payload the scanner sent.
_SLEEP_RE = re.compile(r"(?:sleep[\s(]+|pg_sleep\(|DELAY '0:0:)(\d+)", re.IGNORECASE)
# Pull the callback URL out of an injected `; curl http://collector/token` payload.
_CURL_RE = re.compile(r"(?:curl|wget[\s\-qO]*)\s+(https?://[^\s`)'\"]+)", re.IGNORECASE)
# Canned cloud-metadata responses keyed by the SSRF target host.
_META = {
    "169.254.169.254": "ami-id\ninstance-id\nhostname\niam/",
    "metadata.google.internal": "service-accounts\nmachine-type\nzone",
}


def _sleep_seconds(value: str) -> int:
    m = _SLEEP_RE.search(value)
    return int(m.group(1)) if m else 0


class _VulnHandler(BaseHTTPRequestHandler):
    """Deliberately-vulnerable endpoints, one per detector under test."""

    store: list[str] = []  # shared guestbook, for stored/second-order XSS

    def log_message(self, *args: object) -> None:  # keep test output quiet
        pass

    def _html(self, body: str, status: int = 200) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        q = parse_qs(parsed.query, keep_blank_values=True)

        def first(name: str) -> str:
            return q.get(name, [""])[0]

        if parsed.path == "/tsqli":  # time-blind SQLi: delay tracks the payload
            time.sleep(_sleep_seconds(first("id")))
            return self._html("ok")

        if parsed.path == "/tcmd":  # OS command injection: time-blind + OOB curl
            value = first("host")
            time.sleep(_sleep_seconds(value))
            m = _CURL_RE.search(value)
            if m:
                try:
                    urllib.request.urlopen(m.group(1), timeout=2).read()
                except Exception:
                    pass
            return self._html("ok")

        if parsed.path == "/ssrf":  # blind SSRF (OOB) + cloud-metadata SSRF
            target = first("url")
            host = urlparse(target).hostname or ""
            if host in _META:
                return self._html(_META[host])
            if target.startswith("http"):
                try:
                    urllib.request.urlopen(target, timeout=2).read()
                except Exception:
                    pass
            return self._html("fetched")

        # Stored-XSS guestbook: list -> form -> render stored entries unencoded.
        if parsed.path == "/":
            return self._html('<a href="/guestbook">guestbook</a>')
        if parsed.path == "/guestbook":
            return self._html(
                '<a href="/recent">recent</a>'
                '<form action="/post" method="post"><input name="comment"></form>'
            )
        if parsed.path == "/recent":
            return self._html("<div>" + "".join(f"<p>{e}</p>" for e in self.store) + "</div>")
        return self._html("not found", 404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/post":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", "replace")
            value = parse_qs(body, keep_blank_values=True).get("comment", [""])[0]
            self.store.append(value)  # stored raw -> second-order XSS on /recent
            return self._html("saved")
        return self._html("not found", 404)


class WebActiveDetectionTest(unittest.TestCase):
    def setUp(self) -> None:
        _VulnHandler.store = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnHandler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.collector = web.OobCollector("127.0.0.1")
        # active_probe expects a policy-bound, redirect-disabled opener.
        self.opener = web._no_redirect_opener(web.build_auth_opener())

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.collector.close()

    def _probe(self, path: str) -> set[str]:
        findings = web.active_probe(
            self.base + path, self.opener, {}, 5.0, self.base,
            oob_host=self.collector.public_host,
            oob_confirmed=self.collector.confirmed,
            intrusive=True,
        )
        return {f.rule_id for f in findings}

    def test_time_blind_sqli(self) -> None:
        self.assertIn("web.sql-injection-time-blind", self._probe("/tsqli?id=1"))

    def test_command_injection_time_blind_and_oob(self) -> None:
        fired = self._probe("/tcmd?host=a")
        self.assertIn("web.command-injection-time-blind", fired)
        self.assertIn("web.command-injection-oob", fired)

    def test_ssrf_oob_and_cloud_metadata(self) -> None:
        fired = self._probe("/ssrf?url=http://x")
        self.assertIn("web.ssrf-oob-verified", fired)
        self.assertIn("web.ssrf-cloud-metadata", fired)

    def test_stored_xss_via_crawl(self) -> None:
        findings, _warnings, _pages = web.crawl_web(
            self.base + "/", timeout=5.0, max_pages=20, max_depth=3, delay=0.0,
            opener=web.build_auth_opener(), active=True, intrusive=True,
            allowed_origins=[self.base],
        )
        self.assertIn("web.stored-xss", {f.rule_id for f in findings})


if __name__ == "__main__":
    unittest.main()
