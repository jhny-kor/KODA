from __future__ import annotations

import http.server
import socketserver
import sys
import threading
import time
import types
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner import web
from security_scanner.models import Finding
from security_scanner.web_audit import NetworkContext, build_approval_request, validate_profile


class LinkAndHostTests(unittest.TestCase):
    def test_extract_links_absolutizes_and_strips_fragments(self):
        body = b'<a href="/a">a</a><a href="b.html">b</a><a href="#top">t</a><a href="http://x.io/z">z</a>'
        links = web._extract_links("http://site.test/dir/index.html", body)
        self.assertIn("http://site.test/a", links)
        self.assertIn("http://site.test/dir/b.html", links)
        self.assertIn("http://x.io/z", links)
        # Fragment-only link resolves to the base page without the fragment.
        self.assertIn("http://site.test/dir/index.html", links)
        self.assertFalse(any("#" in link for link in links))

    def test_extract_links_accepts_str_and_bytes(self):
        # Rendered DOM arrives as str (Playwright page.content()); raw fetch as bytes.
        html = '<a href="/a">a</a>'
        self.assertEqual(
            web._extract_links("http://site.test/", html),
            web._extract_links("http://site.test/", html.encode()),
        )
        self.assertIn("http://site.test/a", web._extract_links("http://site.test/", html))

    def test_static_asset_filter(self):
        for asset in ("http://s.test/a.js", "http://s.test/x.WOFF2", "http://s.test/i.png?v=2", "http://s.test/b.css"):
            self.assertTrue(web._is_static_asset(asset), asset)
        for route in ("http://s.test/help", "http://s.test/api/users", "http://s.test/"):
            self.assertFalse(web._is_static_asset(route), route)

    def test_route_literal_extraction_and_noise(self):
        js = 'x=["/help","/api/users"];a="/_next/skip";b="/logo.png";c="/node_modules/y";d="/"'
        keep = {m for m in web._ROUTE_LITERAL_RE.findall(js) if m != "/" and not web._ROUTE_NOISE_RE.search(m)}
        self.assertEqual(keep, {"/help", "/api/users"})

    def test_extract_links_also_collects_script_srcs(self):
        parser = web._parse_html("http://s.test/", '<a href="/x">a</a><script src="/app.js"></script>')
        self.assertIsNotNone(parser)
        self.assertEqual(parser.scripts, ["/app.js"])

    def test_js_secret_scan_redacts(self):
        aws_access_key = "AK" + "IA" + "IOSFODNN7EXAMPLE"
        text = f'var k="{aws_access_key}"; var ok="/route";'
        findings = web._scan_text_for_secrets(text, "http://s.test/app.js", "s.test")
        self.assertEqual([f.rule_id for f in findings], ["web.js-secret.aws-access-key"])
        self.assertNotIn(aws_access_key, findings[0].evidence)  # redacted
        self.assertIn("...", findings[0].evidence)

    def test_js_secret_scan_skips_placeholder(self):
        # A placeholder-looking generic value should not fire.
        text = 'password = "changeme"'
        self.assertEqual(web._scan_text_for_secrets(text, "http://s.test/a.js", "s.test"), [])

    def test_asset_fetch_failure_is_counted(self):
        with patch("security_scanner.web._read_asset", return_value=None):
            routes, findings, failed, limited = web._scan_assets(
                "http://s.test/", '<script src="/app.js"></script>', web.build_auth_opener(), {}, 1,
                set(), 20, "s.test", extract_routes=True, scan_secrets=True,
            )
        self.assertEqual((routes, findings, failed, limited), (set(), [], 1, False))

    def test_analyze_body_tier2(self):
        html = ('<script src="http://cdn.x/a.js"></script>'
                '<link rel="stylesheet" href="https://other.test/b.css">'
                '<form method="post"><input type="password" name="pw"></form>')
        rules = {f.rule_id for f in web.analyze_body("https://site.test/", html, target="site.test")}
        self.assertIn("web.mixed-content", rules)
        self.assertIn("web.subresource-integrity-missing", rules)
        self.assertIn("web.form-missing-csrf-token", rules)

    def test_analyze_body_token_and_password_over_http(self):
        with_token = web.analyze_body("https://s/", '<form method=post><input name=xsrf type=hidden></form>', target="s")
        self.assertNotIn("web.form-missing-csrf-token", {f.rule_id for f in with_token})
        http_pw = web.analyze_body("http://s/", '<form method=post><input type=password></form>', target="s")
        self.assertIn("web.password-input-over-http", {f.rule_id for f in http_pw})

    def test_weak_csp_and_hsts(self):
        weak = {f.rule_id for f in web.analyze_response(
            "https://s/",
            [("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' *"),
             ("Strict-Transport-Security", "max-age=100")],
            target="s")}
        self.assertIn("web.weak-csp", weak)
        self.assertIn("web.weak-hsts", weak)
        strong = {f.rule_id for f in web.analyze_response(
            "https://s/",
            [("Content-Security-Policy", "default-src 'self'; object-src 'none'; script-src 'self'"),
             ("Strict-Transport-Security", "max-age=31536000; includeSubDomains")],
            target="s")}
        self.assertNotIn("web.weak-csp", strong)
        self.assertNotIn("web.weak-hsts", strong)

    def test_opener_cookies_bridges_jar(self):
        opener = web.build_auth_opener()
        # Seed the jar as a form login would, then confirm it converts for Playwright.
        import http.cookiejar
        for handler in opener.handlers:
            jar = getattr(handler, "cookiejar", None)
            if jar is not None:
                jar.set_cookie(http.cookiejar.Cookie(
                    0, "sid", "ok", None, False, "site.test", False, False,
                    "/", True, False, None, False, None, None, {}))
        cookies = web._opener_cookies(opener)
        self.assertEqual(cookies, [{"name": "sid", "value": "ok", "domain": "site.test", "path": "/", "secure": False}])

    def test_merge_browser_cookies_reverse_sync(self):
        opener = web.build_auth_opener()
        web._merge_browser_cookies(opener, [
            {"name": "sid", "value": "ROTATED", "domain": "site.test", "path": "/", "secure": True, "httpOnly": True},
        ])
        self.assertEqual(
            web._opener_cookies(opener),
            [{"name": "sid", "value": "ROTATED", "domain": "site.test", "path": "/", "secure": True}],
        )

    def test_with_query_param_replaces(self):
        import urllib.parse
        parsed = urllib.parse.urlparse("http://s/x?a=1&b=2")
        out = web._with_query_param(parsed, "a", "PAYLOAD")
        self.assertIn("a=PAYLOAD", out)
        self.assertIn("b=2", out)

    def test_sql_error_signature(self):
        self.assertTrue(web._SQL_ERROR_RE.search("You have an error in your SQL syntax near"))
        self.assertTrue(web._SQL_ERROR_RE.search("ORA-00933: something"))
        self.assertFalse(web._SQL_ERROR_RE.search("a normal page with no db error"))

    def test_access_control_helpers(self):
        self.assertTrue(web._looks_like_login('<form><input type="password"></form>'))
        self.assertTrue(web._looks_like_login("<form>please sign in</form>"))
        self.assertFalse(web._looks_like_login("<html>user dashboard, balance 500</html>"))

    def test_responses_equivalent_structural(self):
        # Same data, only a per-request CSRF token differs -> still equivalent
        # (raw length comparison could miss this on short bodies).
        a = '<form><input name="csrf" value="AAAAAAAAAAAAAAAAAAAAAAAAAAAA1"><p>Alice Kim balance 500</p></form>'
        b = '<form><input name="csrf" value="BBBBBBBBBBBBBBBBBBBBBBBBBBBB2"><p>Alice Kim balance 500</p></form>'
        self.assertTrue(web._responses_equivalent(a, b))
        # Two different accounts' data of similar length -> NOT equivalent
        # (the old 15%-length heuristic would have called these a match).
        c = "<html><p>Alice Kim, account 1001, balance 500</p></html>"
        d = "<html><p>Bob Lee, account 2002, balance 999</p></html>"
        self.assertFalse(web._responses_equivalent(c, d))
        # JSON: same keys+values but different volatile token -> equivalent
        j1 = '{"user":"alice","role":"admin","token":"xyz111","updated_at":"2024-01-01T00:00:00"}'
        j2 = '{"role":"admin","user":"alice","token":"zzz999","updated_at":"2025-09-09T09:09:09"}'
        self.assertTrue(web._responses_equivalent(j1, j2))
        # JSON: different user values -> NOT equivalent
        j3 = '{"user":"bob","role":"user"}'
        self.assertFalse(web._responses_equivalent(j1, j3))

    def test_api_spec_openapi_har_postman(self):
        import json
        from security_scanner import api_spec
        openapi = json.dumps({"openapi": "3.0.0", "servers": [{"url": "https://a.test/v1"}],
                              "paths": {"/u/{id}": {"get": {"parameters": [{"in": "path", "name": "id"}]}, "post": {}}}})
        urls, warns = api_spec.parse_api_spec(openapi, "https://a.test")
        self.assertEqual(urls, ["https://a.test/v1/u/1"])
        self.assertTrue(any("non-GET" in w for w in warns))
        har = json.dumps({"log": {"entries": [{"request": {"method": "GET", "url": "https://a.test/z"}}]}})
        self.assertEqual(api_spec.parse_api_spec(har, "https://a.test")[0], ["https://a.test/z"])

    def test_forms_parser_skips_login_and_file(self):
        parser = web._FormsParser()
        parser.feed('<form method="post"><input name="q" type="text"><input name="pw" type="password"></form>'
                    '<form><input name="s" type="search"></form>')
        self.assertTrue(parser.forms[0]["has_password"])
        self.assertFalse(parser.forms[1]["has_password"])
        self.assertIn("q", parser.forms[0]["fields"])

    def test_origin(self):
        self.assertEqual(web._origin("https://h.test:8443/a/b?x=1"), "https://h.test:8443")

    def test_same_host(self):
        self.assertTrue(web._same_host("http://site.test/a", "http://site.test/b"))
        self.assertFalse(web._same_host("http://site.test/a", "http://other.test/b"))
        # Different scheme but same netloc counts as same host.
        self.assertTrue(web._same_host("http://site.test/a", "https://site.test/b"))
        self.assertFalse(web._same_host("http://site.test/a", "ftp://site.test/b"))


class DedupeTests(unittest.TestCase):
    def test_repeats_collapse_with_count(self):
        def make(url):
            return Finding(
                rule_id="web.missing-csp",
                category="web",
                severity="medium",
                title="x",
                path=Path(url),
                target="site.test",
            )

        deduped = web._dedupe_findings([make("/a"), make("/b"), make("/c")])
        self.assertEqual(len(deduped), 1)
        # Evidence now lists the actual affected URLs, not just a count.
        self.assertIn("affected URLs:", deduped[0].evidence)
        for path in ("/a", "/b", "/c"):
            self.assertIn(path, deduped[0].evidence)

    def test_distinct_rules_kept(self):
        a = Finding("web.missing-csp", "web", "medium", "x", Path("/a"), target="site.test")
        b = Finding("web.missing-hsts", "web", "medium", "y", Path("/a"), target="site.test")
        self.assertEqual(len(web._dedupe_findings([a, b])), 2)


class _Site(http.server.BaseHTTPRequestHandler):
    """Static site: /, /a, /b link internally; /secret needs a session cookie."""

    def log_message(self, *args):  # silence test output
        pass

    def _html(self, body: bytes, status: int = 200, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        for key, value in (headers or []):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self._html(b'<a href="/a">a</a><a href="/b">b</a><a href="/private">private</a><a href="https://ext.io/x">e</a>')
        elif self.path == "/a":
            self._html(b'<a href="/b">b</a>')
        elif self.path == "/b":
            self._html(b"leaf")
        elif self.path == "/login":
            self._html(
                b'<form method="post" action="/do-login">'
                b'<input type="hidden" name="csrf" value="tok">'
                b'<input name="username"><input type="password" name="password"></form>'
            )
        elif self.path == "/secret":
            if "session=ok" in self.headers.get("Cookie", ""):
                self._html(b"<html>secret</html>")
            else:
                self._html(b"denied", status=403)
        elif self.path == "/private":
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
        else:
            self._html(b"not found", status=404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        if "username=admin" in body and "password=pw" in body and "csrf=tok" in body:
            self._html(b"", status=302, headers=[("Set-Cookie", "session=ok"), ("Location", "/secret")])
        else:
            self._html(b"bad login")


class LiveCrawlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = socketserver.TCPServer(("127.0.0.1", 0), _Site)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_crawl_visits_same_host_pages_only(self):
        page_results = []
        _findings, _warnings, pages = web.crawl_web(self.base + "/", delay=0, page_results=page_results)
        self.assertEqual(pages, 3)
        private = next(item for item in page_results if item["requested_url"] == self.base + "/private")
        self.assertEqual(private["final_url"], self.base + "/login")
        self.assertEqual(private["skip_reason"], "redirected to login page; protected content was not scanned")

    def test_max_pages_caps_crawl(self):
        _findings, warnings, pages = web.crawl_web(self.base + "/", max_pages=2, max_depth=3, delay=0)
        self.assertEqual(pages, 2)
        self.assertTrue(any("max_pages=2" in warning for warning in warnings))

    def test_response_body_read_obeys_wall_clock_budget(self):
        class SlowBody:
            headers = {"Content-Type": "text/html"}

            def read1(self, _amount):
                return b"x"

            read = read1

        with patch("security_scanner.web.time.monotonic", side_effect=[0.0, 0.04, 0.08]):
            with self.assertRaises(TimeoutError):
                web._read_safe_body(SlowBody(), 10, timeout=0.05)

    def test_response_body_over_limit_fails_closed(self):
        class OversizedBody:
            def __init__(self):
                self.remaining = 11

            def read1(self, amount):
                size = min(amount, self.remaining)
                self.remaining -= size
                return b"x" * size

            read = read1

        with self.assertRaises(web.ResponseBodyLimitError):
            web._read_bounded_body(OversizedBody(), 10, timeout=1)

    def test_check_web_is_single_page(self):
        findings, warnings = web.check_web(self.base + "/")
        # Same result set as a one-page crawl (regression guard).
        c_findings, c_warnings, pages = web.crawl_web(self.base + "/", max_pages=1, delay=0)
        self.assertEqual(pages, 1)
        self.assertEqual([f.rule_id for f in findings], [f.rule_id for f in c_findings])

    def test_form_login_then_reach_protected_page(self):
        opener = web.build_auth_opener()
        warnings, _findings = web.login(opener, self.base + "/login", "admin", "pw")
        self.assertEqual(warnings, [])
        _findings, _warnings, pages = web.crawl_web(self.base + "/secret", opener=opener, max_pages=1, delay=0)
        self.assertEqual(pages, 1)  # 200, not 403

    def test_cookie_injection_reaches_protected_page(self):
        _findings, _warnings, pages = web.crawl_web(
            self.base + "/secret", extra_headers={"Cookie": "session=ok"}, max_pages=1, delay=0
        )
        self.assertEqual(pages, 1)

    def test_bad_login_warns_but_does_not_raise(self):
        opener = web.build_auth_opener()
        warnings, _findings = web.login(opener, self.base + "/login", "admin", "wrong")
        self.assertTrue(warnings)  # no session cookie set -> warning

    def test_crawl_records_login_redirect_as_uncovered_page(self):
        page_results = []
        _findings, _warnings, pages = web.crawl_web(
            self.base + "/private", delay=0, page_results=page_results
        )
        self.assertEqual(pages, 0)
        self.assertEqual(len(page_results), 1)
        self.assertEqual(page_results[0]["requested_url"], self.base + "/private")
        self.assertEqual(page_results[0]["final_url"], self.base + "/login")
        self.assertEqual(page_results[0]["auth_state"], "login-page")
        self.assertIn("protected", page_results[0]["skip_reason"])

    def test_web_payload_marks_web_results_and_keeps_raw_counts(self):
        from security_scanner.server import web_scan_payload

        payload = web_scan_payload(self.base + "/private", delay=0)
        self.assertEqual(payload["scan"]["kind"], "web")
        self.assertEqual(payload["summary"]["raw_finding_count"], len(payload["findings_by_language"]["en"]))
        self.assertEqual(payload["summary"]["displayed_finding_count"], len(payload["findings_by_language"]["en"]))
        self.assertEqual(payload["page_results"][0]["auth_state"], "login-page")

    def test_web_payload_confirms_authenticated_content_after_login(self):
        from security_scanner.server import web_scan_payload

        payload = web_scan_payload(
            self.base + "/secret",
            delay=0,
            auth={"login_url": self.base + "/login", "username": "admin", "password": "pw"},
        )
        self.assertEqual(payload["auth"]["status"], "authenticated")
        self.assertEqual(payload["page_results"][0]["auth_state"], "authenticated")

    def test_web_payload_forwards_intrusive_exploit_tier(self):
        import json as _json
        from security_scanner.server import web_scan_payload

        class Templater(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                value = (parse_qs(urlparse(self.path).query).get("name") or [""])[0]
                body = value.replace("{{31337-1}}", "31336").replace("{{1337*1337}}", "1787569")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Templater)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/p?name=x"
            payload = web_scan_payload(url, delay=0, timeout=5, active=True, intrusive=True, exploit=True)
            self.assertIn("web.ssti-exploited", _json.dumps(payload))
        finally:
            server.shutdown()
            server.server_close()

    def test_cross_account_structural_detection(self):
        # A server that serves the SAME record to any cookie (broken object-level
        # auth) but varies only a per-request CSRF token — structural comparison
        # must still flag it; a raw-length check could be thrown by the token.
        class Idor(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                token = self.headers.get("Cookie", "x")[:8].ljust(8, "z")
                body = (
                    f'<html><input name="csrf" value="{token}CSRFTOKENVALUE1234567">'
                    "<p>Record 42: Alice Kim, balance 500</p></html>"
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Idor)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/"
            findings, _warnings, _pages = web.crawl_web(
                base, max_pages=1, delay=0,
                extra_headers={"Cookie": "session=acct1"},
                secondary_headers={"Cookie": "session=acct2"},
            )
            rule_ids = {finding.rule_id for finding in findings}
            self.assertIn("web.broken-access-control-cross-account", rule_ids)
        finally:
            server.shutdown()
            server.server_close()

    def test_bundle_passive_and_perhost_checks(self):
        import base64
        import json as _json

        def _jwt(header, payload):
            def enc(data):
                return base64.urlsafe_b64encode(_json.dumps(data).encode()).rstrip(b"=").decode()
            return f"{enc(header)}.{enc(payload)}."

        alg_none = _jwt({"alg": "none", "typ": "JWT"}, {"sub": "1"})

        class Bundle(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                host = self.headers.get("Host", "")
                body = f"<html>Traceback (most recent call last): boom. Host={host}</html>".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Set-Cookie", f"session={alg_none}; Path=/")
                self.end_headers()
                self.wfile.write(body)

            def do_OPTIONS(self):
                self.send_response(204)
                self.send_header("Allow", "GET, POST, TRACE, PUT")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Bundle)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/"
            findings, _warnings, _pages = web.crawl_web(base, max_pages=1, delay=0)
            rule_ids = {finding.rule_id for finding in findings}
            for rid in (
                "web.error-stack-trace", "web.jwt-alg-none",
                "web.http-trace-enabled", "web.http-methods-exposed", "web.host-header-injection",
            ):
                self.assertIn(rid, rule_ids)
        finally:
            server.shutdown()
            server.server_close()

    def test_lfi_path_traversal_active(self):
        class Reader(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                value = (parse_qs(urlparse(self.path).query).get("file") or [""])[0]
                body = b"root:x:0:0:root:/root:/bin/bash\n" if "etc/passwd" in value else b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Reader)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/read?file=readme"
            findings, _warnings, _pages = web.crawl_web(base, max_pages=1, delay=0, active=True)
            rule_ids = {finding.rule_id for finding in findings}
            self.assertIn("web.path-traversal-lfi", rule_ids)
        finally:
            server.shutdown()
            server.server_close()

    def test_ssti_active(self):
        class Templater(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                value = (parse_qs(urlparse(self.path).query).get("name") or [""])[0]
                # Evaluate the {{...}} expression like a vulnerable template engine.
                body = value.replace("{{1337*1337}}", "1787569").replace("{{31337-1}}", "31336").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Templater)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/p?name=x"
            findings, _w, _p = web.crawl_web(base, max_pages=1, delay=0, active=True)
            self.assertIn("web.ssti-verified", {f.rule_id for f in findings})
        finally:
            server.shutdown()
            server.server_close()

    def test_ssti_evaluated_requires_eval_not_echo(self):
        self.assertTrue(web._ssti_evaluated("result is 1787569"))
        # Literal payload echoed back (not evaluated) must not trigger.
        self.assertFalse(web._ssti_evaluated("you sent {{1337*1337}}"))
        self.assertFalse(web._ssti_evaluated("nothing here"))

    def test_ssti_confirmation_rejects_static_result_and_single_expression(self):
        calls = []

        def static_page(value):
            calls.append(value)
            return "static page contains 1787569 and 31336"

        self.assertEqual(web._ssti_findings(static_page, "http://example.test", "test", "param 'q'"), [])
        self.assertIn("{{31337-1}}", calls)

        def one_expression(value):
            return value.replace("{{1337*1337}}", "1787569")

        self.assertEqual(web._ssti_findings(one_expression, "http://example.test", "test", "param 'q'"), [])

    def test_ssti_dollar_brace_engine(self):
        class Templater(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                value = (parse_qs(urlparse(self.path).query).get("name") or [""])[0]
                # Only ${...} evaluates here (Freemarker/EL-style), not {{...}}.
                body = value.replace("${1337*1337}", "1787569").replace("${31337-1}", "31336").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Templater)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/p?name=x"
            findings, _w, _p = web.crawl_web(base, max_pages=1, delay=0, active=True)
            self.assertIn("web.ssti-verified", {f.rule_id for f in findings})
        finally:
            server.shutdown()
            server.server_close()

    def test_ssti_thymeleaf_star_brace_engine(self):
        class Templater(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                value = (parse_qs(urlparse(self.path).query).get("name") or [""])[0]
                body = value.replace("*{1337*1337}", "1787569").replace("*{31337-1}", "31336")  # only *{...} evaluates
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Templater)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/p?name=x"
            findings, _w, _p = web.crawl_web(base, max_pages=1, delay=0, active=True)
            self.assertIn("web.ssti-verified", {f.rule_id for f in findings})
        finally:
            server.shutdown()
            server.server_close()

    def test_ssti_razor_engine(self):
        class Templater(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                value = (parse_qs(urlparse(self.path).query).get("name") or [""])[0]
                body = value.replace("@(1337*1337)", "1787569").replace("@(31337-1)", "31336")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Templater)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/p?name=x"
            findings, _w, _p = web.crawl_web(base, max_pages=1, delay=0, active=True)
            self.assertIn("web.ssti-verified", {f.rule_id for f in findings})
        finally:
            server.shutdown()
            server.server_close()

    def test_xss_js_context(self):
        class JsCtx(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                q = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
                q = q.replace("<", "&lt;").replace(">", "&gt;")  # HTML-escapes angle brackets only
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(f"<html><script>var x = '{q}';</script></html>".encode())

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), JsCtx)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/p?q=1"
            findings, _w, _p = web.crawl_web(base, max_pages=1, delay=0, active=True)
            self.assertIn("web.xss-js-context", {f.rule_id for f in findings})
        finally:
            server.shutdown()
            server.server_close()

    def test_crlf_injection(self):
        class Crlf(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                q = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
                self.send_response(200)
                self.send_header("X-Echo", q)  # vulnerable: unsanitized value into a header
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Crlf)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/p?q=1"
            findings, _w, _p = web.crawl_web(base, max_pages=1, delay=0, active=True)
            self.assertIn("web.crlf-injection", {f.rule_id for f in findings})
        finally:
            server.shutdown()
            server.server_close()

    def test_stored_xss_cross_page(self):
        stored = {"v": ""}

        class App(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import urlparse
                if urlparse(self.path).path == "/b":
                    html = f"<html>comment: {stored['v']}</html>"  # reflects stored value raw
                else:
                    html = ("<html><a href='/b'>b</a>"
                            "<form method='post' action='/save'><input name='c'></form></html>")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(html.encode())

            def do_POST(self):
                from urllib.parse import parse_qs
                n = int(self.headers.get("Content-Length", "0"))
                stored["v"] = (parse_qs(self.rfile.read(n).decode()).get("c") or [""])[0]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), App)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/"
            findings, _w, _p = web.crawl_web(base, max_pages=5, max_depth=1, delay=0, timeout=5,
                                             active=True, intrusive=True)
            self.assertIn("web.stored-xss", {f.rule_id for f in findings})
        finally:
            server.shutdown()
            server.server_close()

    def test_delay_confirms_accepts_consistent_delay(self):
        # Response time scales with the requested delay across all samples.
        self.assertTrue(web._delay_confirms(lambda sec: 0.05 + sec, big=3, small=1))

    def test_delay_confirms_rejects_one_off_spike(self):
        # base, hi(spike), lo(scales), hi2(spike gone) -> re-confirmation rejects it.
        samples = iter([0.0, 3.0, 1.0, 0.0])
        self.assertFalse(web._delay_confirms(lambda sec: next(samples), big=3, small=1))

    def test_delay_confirms_rejects_uniformly_slow(self):
        # Every request is slow but does not scale with the delay -> not injectable.
        self.assertFalse(web._delay_confirms(lambda sec: 5.0, big=3, small=1))

    def test_exploit_sqli_extracts_db_identity(self):
        class SqlLeak(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                value = (parse_qs(urlparse(self.path).query).get("id") or [""])[0]
                # Vulnerable: extractvalue leaks version() in the XPATH error body.
                body = "XPATH syntax error: '~5.7.42-log~'" if "extractvalue" in value else "ok"
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), SqlLeak)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/q?id=1"
            findings, _w, _p = web.crawl_web(base, max_pages=1, delay=0, timeout=5,
                                             active=True, intrusive=True, exploit=True)
            hit = [f for f in findings if f.rule_id == "web.sql-injection-exploited"]
            self.assertTrue(hit)
            self.assertIn("5.7.42-log", hit[0].evidence)
        finally:
            server.shutdown()
            server.server_close()

    def test_exploit_command_injection_runs_id(self):
        import re as _re

        class ShellRun(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                value = (parse_qs(urlparse(self.path).query).get("host") or [""])[0]
                if _re.search(r"(;|\||&|\$\(|`)\s*id", value):  # vulnerable: runs injected `id`
                    body = "uid=0(root) gid=0(root) groups=0(root)"
                else:
                    body = "pong"
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), ShellRun)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/ping?host=a"
            findings, _w, _p = web.crawl_web(base, max_pages=1, delay=0, timeout=5,
                                             active=True, intrusive=True, exploit=True)
            hit = [f for f in findings if f.rule_id == "web.command-injection-exploited"]
            self.assertTrue(hit)
            self.assertIn("uid=0(root)", hit[0].evidence)
        finally:
            server.shutdown()
            server.server_close()

    def test_jwt_weak_hmac_secret_detected(self):
        import base64 as _b64
        import hashlib
        import hmac
        import json as _json

        def jwt(secret: str) -> str:
            def part(obj):
                return _b64.urlsafe_b64encode(_json.dumps(obj).encode()).rstrip(b"=").decode()
            header = part({"alg": "HS256", "typ": "JWT"})
            payload = part({"sub": "1", "exp": 9999999999})
            signing = f"{header}.{payload}".encode()
            sig = _b64.urlsafe_b64encode(hmac.new(secret.encode(), signing, hashlib.sha256).digest()).rstrip(b"=").decode()
            return f"{header}.{payload}.{sig}"

        weak = web._jwt_findings("http://h/", [f"session={jwt('secret')}; HttpOnly"], target="h")
        self.assertIn("web.jwt-weak-secret", {f.rule_id for f in weak})
        strong = web._jwt_findings("http://h/", [f"session={jwt('N9x!q2Lr8vZ_k3Pw7tB1sEoYhGfDmJc')}; HttpOnly"], target="h")
        self.assertNotIn("web.jwt-weak-secret", {f.rule_id for f in strong})

    def test_ssrf_cloud_metadata_inband(self):
        class Fetcher(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                target_url = (parse_qs(urlparse(self.path).query).get("url") or [""])[0]
                # Vulnerable: server fetches the URL and reflects metadata content.
                body = "instance-id: i-0abc\nami-id: ami-123" if "169.254.169.254" in target_url else "ok"
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Fetcher)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/f?url=x"
            findings, _w, _p = web.crawl_web(base, max_pages=1, delay=0, timeout=5, active=True)
            self.assertIn("web.ssrf-cloud-metadata", {f.rule_id for f in findings})
        finally:
            server.shutdown()
            server.server_close()

    def test_exploit_ssti_arbitrary_expression(self):
        class Templater(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                value = (parse_qs(urlparse(self.path).query).get("name") or [""])[0]
                body = value.replace("{{31337-1}}", "31336").replace("{{1337*1337}}", "1787569")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Templater)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/p?name=x"
            findings, _w, _p = web.crawl_web(base, max_pages=1, delay=0, timeout=5,
                                             active=True, intrusive=True, exploit=True)
            self.assertIn("web.ssti-exploited", {f.rule_id for f in findings})
        finally:
            server.shutdown()
            server.server_close()

    def test_redact_masks_credentials(self):
        red = web._redact("Set-Cookie: session=abc; version 5.7 token=deadbeefdeadbeefdeadbeefdeadbeef1234")
        self.assertNotIn("abc", red)
        self.assertIn("[REDACTED]", red)

    def test_header_injection_reflected(self):
        class Echoer(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                ref = self.headers.get("Referer", "")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(f"<p>from {ref}</p>".encode())

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Echoer)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/p?q=1"
            findings, _w, _p = web.crawl_web(base, max_pages=1, delay=0, active=True)
            hit = [f for f in findings if f.rule_id == "web.reflected-xss-verified" and "header" in f.evidence]
            self.assertTrue(hit, "expected a header-reflected XSS finding")
        finally:
            server.shutdown()
            server.server_close()

    def test_json_active_probe_reflects_and_errors(self):
        class Api(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                import json as _json
                length = int(self.headers.get("Content-Length", "0"))
                data = _json.loads(self.rfile.read(length) or b"{}")
                q = str(data.get("q", ""))
                body = "SQL syntax error near" if q.endswith("'") else f"<i>{q}</i>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Api)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/api"
            findings = web.json_active_probe(
                url, {"q": "hello"}, web.build_auth_opener(), {}, 5.0, "api"
            )
            ids = {f.rule_id for f in findings}
            self.assertIn("web.reflected-xss-verified", ids)
            self.assertIn("web.sql-injection-error-verified", ids)
        finally:
            server.shutdown()
            server.server_close()

    def test_oob_ssrf_fires_only_with_collector(self):
        seen = []

        class Fetcher(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                seen.append((parse_qs(urlparse(self.path).query).get("url") or [""])[0])
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Fetcher)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/f?url=x"
            opener = web.build_auth_opener()
            # No collector wired: nothing sent, no finding.
            self.assertEqual(web.active_probe(url, opener, {}, 5.0, "f"), [])
            before = len(seen)
            # Collector confirms the token it received in the subdomain.
            tokens = []
            findings = web.active_probe(
                url, opener, {}, 5.0, "f",
                oob_host="oob.example",
                oob_confirmed=lambda t: tokens.append(t) or any(t in s for s in seen[before:]),
            )
            self.assertIn("web.ssrf-oob-verified", {f.rule_id for f in findings})
        finally:
            server.shutdown()
            server.server_close()

    def test_intrusive_time_based_sqli(self):
        import re as _re

        class SleepySql(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                value = (parse_qs(urlparse(self.path).query).get("id") or [""])[0]
                m = _re.search(r"SLEEP\((\d+)\)", value)  # SQL sleep, case-sensitive
                if m:
                    time.sleep(int(m.group(1)))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), SleepySql)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/q?id=1"
            findings, _w, _p = web.crawl_web(base, max_pages=1, delay=0, timeout=5, active=True, intrusive=True)
            self.assertIn("web.sql-injection-time-blind", {f.rule_id for f in findings})
        finally:
            server.shutdown()
            server.server_close()

    def test_intrusive_command_injection_time(self):
        import re as _re

        class SleepyShell(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                value = (parse_qs(urlparse(self.path).query).get("host") or [""])[0]
                m = _re.search(r"sleep (\d+)", value)  # shell sleep (space), not SQL SLEEP(n)
                if m:
                    time.sleep(int(m.group(1)))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"pong")

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), SleepyShell)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/ping?host=a"
            findings, _w, _p = web.crawl_web(base, max_pages=1, delay=0, timeout=5, active=True, intrusive=True)
            self.assertIn("web.command-injection-time-blind", {f.rule_id for f in findings})
        finally:
            server.shutdown()
            server.server_close()

    def test_intrusive_not_run_without_flag(self):
        class SleepySql(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), SleepySql)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/q?id=1"
            # active but NOT intrusive: no timing payloads sent.
            findings, _w, _p = web.crawl_web(base, max_pages=1, delay=0, timeout=5, active=True)
            ids = {f.rule_id for f in findings}
            self.assertNotIn("web.sql-injection-time-blind", ids)
            self.assertNotIn("web.command-injection-time-blind", ids)
        finally:
            server.shutdown()
            server.server_close()

    def test_parse_api_spec_json_bodies(self):
        from security_scanner.api_spec import parse_api_spec_json_bodies
        spec = (
            '{"openapi":"3.0.0","servers":[{"url":"https://a.test"}],"paths":'
            '{"/users":{"post":{"requestBody":{"content":{"application/json":'
            '{"schema":{"properties":{"name":{"type":"string"},"age":{"type":"integer"}}}}}}}},'
            '"/ping":{"get":{}}}}'
        )
        bodies = parse_api_spec_json_bodies(spec, "https://a.test")
        self.assertEqual(len(bodies), 1)
        method, url, skeleton = bodies[0]
        self.assertEqual(method, "POST")
        self.assertEqual(url, "https://a.test/users")
        self.assertEqual(skeleton, {"name": "test", "age": 1})

    def test_intrusive_json_endpoint_fuzz(self):
        class JsonApi(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                import json as _json
                n = int(self.headers.get("Content-Length", "0"))
                data = _json.loads(self.rfile.read(n) or b"{}")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(f"<b>{data.get('name', '')}</b>".encode())

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), JsonApi)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            host = f"http://127.0.0.1:{server.server_address[1]}"
            findings, _w, _p = web.crawl_web(
                host + "/", max_pages=1, delay=0, timeout=5, active=True, intrusive=True,
                json_endpoints=[("POST", host + "/users", {"name": "x"})],
            )
            self.assertIn("web.reflected-xss-verified", {f.rule_id for f in findings})
        finally:
            server.shutdown()
            server.server_close()

    def test_intrusive_form_field_sqli(self):
        import re as _re

        class SleepyForm(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<form method='post' action='/s'><input name='q'></form>")

            def do_POST(self):
                from urllib.parse import parse_qs
                n = int(self.headers.get("Content-Length", "0"))
                q = (parse_qs(self.rfile.read(n).decode()).get("q") or [""])[0]
                m = _re.search(r"SLEEP\((\d+)\)", q)
                if m:
                    time.sleep(int(m.group(1)))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), SleepyForm)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/"
            findings, _w, _p = web.crawl_web(base, max_pages=1, delay=0, timeout=5, active=True, intrusive=True)
            self.assertIn("web.sql-injection-time-blind", {f.rule_id for f in findings})
        finally:
            server.shutdown()
            server.server_close()

    def test_oob_collector_confirms_ssrf(self):
        import urllib.request as _req

        collector = web.OobCollector("127.0.0.1", port=0)

        class Fetcher(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                target_url = (parse_qs(urlparse(self.path).query).get("url") or [""])[0]
                if target_url.startswith("http://"):
                    try:  # vulnerable: server fetches a caller-controlled URL (SSRF)
                        _req.urlopen(target_url, timeout=2).read()
                    except Exception:
                        pass
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Fetcher)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/f?url=x"
            findings, _w, _p = web.crawl_web(
                base, max_pages=1, delay=0, timeout=5, active=True, intrusive=True,
                oob_host=collector.public_host, oob_confirmed=collector.confirmed,
            )
            self.assertIn("web.ssrf-oob-verified", {f.rule_id for f in findings})
        finally:
            server.shutdown()
            server.server_close()
            collector.close()

    def test_authenticated_intrusive_scan_uses_session(self):
        import re as _re

        class AuthApp(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from http.cookies import SimpleCookie
                cookie = SimpleCookie(self.headers.get("Cookie", ""))
                authed = cookie["sid"].value == "good" if "sid" in cookie else False
                from urllib.parse import parse_qs, urlparse
                value = (parse_qs(urlparse(self.path).query).get("id") or [""])[0]
                if authed:  # timing bug only reachable behind the session
                    m = _re.search(r"SLEEP\((\d+)\)", value)
                    if m:
                        time.sleep(int(m.group(1)))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok" if authed else b"login")

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), AuthApp)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/acct?id=1"
            findings, _w, _p = web.crawl_web(
                base, max_pages=1, delay=0, timeout=5, active=True, intrusive=True,
                extra_headers={"Cookie": "sid=good"},
            )
            self.assertIn("web.sql-injection-time-blind", {f.rule_id for f in findings})
        finally:
            server.shutdown()
            server.server_close()

    def test_cors_dynamic_origin_reflection(self):
        class Reflector(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                origin = self.headers.get("Origin")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                if origin:  # echo any request Origin back (the misconfiguration)
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Access-Control-Allow-Credentials", "true")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Reflector)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}/"
            findings, _warnings, _pages = web.crawl_web(base, max_pages=1, delay=0)
            rule_ids = {finding.rule_id for finding in findings}
            self.assertIn("web.cors-origin-reflection-credentials", rule_ids)
            self.assertIn("web.cors-null-origin", rule_ids)
        finally:
            server.shutdown()
            server.server_close()

    def test_cors_probe_quiet_when_no_cors(self):
        # A server that never emits CORS headers must not produce CORS findings.
        findings, _warnings, _pages = web.crawl_web(self.base + "/b", max_pages=1, delay=0)
        rule_ids = {finding.rule_id for finding in findings}
        self.assertNotIn("web.cors-origin-reflection", rule_ids)
        self.assertNotIn("web.cors-origin-reflection-credentials", rule_ids)
        self.assertNotIn("web.cors-null-origin", rule_ids)

    def test_cross_origin_redirect_never_receives_credentials(self):
        received = {}

        class Receiver(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received["cookie"] = self.headers.get("Cookie")
                received["authorization"] = self.headers.get("Authorization")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()

            def log_message(self, *args):
                pass

        receiver = socketserver.TCPServer(("127.0.0.1", 0), Receiver)
        receiver_thread = threading.Thread(target=receiver.serve_forever, daemon=True)
        receiver_thread.start()
        destination = f"http://127.0.0.1:{receiver.server_address[1]}/"

        class Redirector(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", destination)
                self.end_headers()

            def log_message(self, *args):
                pass

        redirector = socketserver.TCPServer(("127.0.0.1", 0), Redirector)
        redirector_thread = threading.Thread(target=redirector.serve_forever, daemon=True)
        redirector_thread.start()
        try:
            source = f"http://127.0.0.1:{redirector.server_address[1]}/"
            _findings, _warnings, pages = web.crawl_web(
                source,
                delay=0,
                extra_headers={"Cookie": "session=TOPSECRET", "Authorization": "Bearer TOPSECRET"},
                allowed_origins=(destination,),
            )
            self.assertEqual(pages, 1)
            self.assertIsNone(received["cookie"])
            self.assertIsNone(received["authorization"])
        finally:
            redirector.shutdown()
            redirector.server_close()
            receiver.shutdown()
            receiver.server_close()


class SecondaryRequestBoundaryTests(unittest.TestCase):
    def test_direct_discovery_scopes_headers_and_cookie_jar_to_seed_origin(self):
        received = []

        class Receiver(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received.append((self.path, self.headers.get("Authorization"), self.headers.get("Cookie")))
                body = (f'<urlset><url><loc>{destination}/page</loc></url></urlset>'
                        if self.path == "/sitemap.xml" else "<html>other page</html>")
                self.send_response(200)
                self.send_header("Content-Type", "application/xml" if self.path == "/sitemap.xml" else "text/html")
                self.end_headers()
                self.wfile.write(body.encode())

            def do_POST(self):
                received.append((self.path, self.headers.get("Authorization"), self.headers.get("Cookie")))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_args):
                pass

        receiver = socketserver.TCPServer(("127.0.0.1", 0), Receiver)
        destination = f"http://127.0.0.1:{receiver.server_address[1]}"

        class Source(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain" if self.path == "/robots.txt" else "text/html")
                if self.path == "/":
                    self.send_header("Set-Cookie", "session=TOPSECRET; Path=/")
                self.end_headers()
                body = (f"Sitemap: {destination}/sitemap.xml" if self.path == "/robots.txt"
                        else f'<form action="{destination}/submit" method="post"><input name="q" value="x"></form>')
                self.wfile.write(body.encode())

            def log_message(self, *_args):
                pass

        source = socketserver.TCPServer(("127.0.0.1", 0), Source)
        threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (receiver, source)]
        for thread in threads:
            thread.start()
        try:
            web.crawl_web(f"http://127.0.0.1:{source.server_address[1]}/", opener=web.build_auth_opener(),
                          allowed_origins=(destination,), extra_headers={"Authorization": "Bearer TOPSECRET"},
                          ingest_sitemap=True, active=True, delay=0, max_pages=2)
            self.assertTrue(any(path == "/sitemap.xml" for path, _, _ in received))
            self.assertTrue(any(path == "/page" for path, _, _ in received))
            self.assertTrue(any(path == "/submit" for path, _, _ in received))
            self.assertTrue(all(not auth and not cookie for _, auth, cookie in received))
        finally:
            for server in (receiver, source):
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join()

    def test_approved_default_port_matches_implicit_port_and_case(self):
        self.assertTrue(web._safe_secondary_url(
            "https://app.example/login", "https://APP.EXAMPLE:443/submit", {"https://app.example:443"},
        ))
        self.assertTrue(web._safe_secondary_url(
            "http://app.example/login", "http://APP.EXAMPLE:80/next", {"http://app.example:80"},
        ))
        self.assertFalse(web._safe_secondary_url(
            "https://app.example/login", "http://app.example:80/submit", {"http://app.example:80"},
        ))

    def test_non_loopback_http_login_is_rejected_before_loading_page(self):
        class NoNetwork:
            def open(self, *_args, **_kwargs):
                raise AssertionError("insecure login was fetched")

        result = {}
        with patch.object(web, "_no_redirect_opener", return_value=NoNetwork()):
            warnings, _ = web.login(web.build_auth_opener(), "http://public.example/login", "alice", "secret",
                                    result=result)
        self.assertTrue(any("requires HTTPS" in warning for warning in warnings))
        self.assertEqual(result["status"], "failed")

    @classmethod
    def setUpClass(cls):
        cls.received = []
        cls.source_auth = []

        class Receiver(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                cls.received.append(("GET", self.path, dict(self.headers)))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"<html>receiver</html>")

            def do_POST(self):
                cls.received.append(("POST", self.path, dict(self.headers)))
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        cls.receiver = socketserver.TCPServer(("127.0.0.1", 0), Receiver)
        cls.receiver_base = f"http://127.0.0.1:{cls.receiver.server_address[1]}"
        cls.receiver_thread = threading.Thread(target=cls.receiver.serve_forever, daemon=True)
        cls.receiver_thread.start()

        class Source(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path in {"/robots.txt", "/sitemap.xml"}:
                    body = (f"Sitemap: {cls.receiver_base}/outside.xml" if self.path == "/robots.txt"
                            else f"<sitemapindex><loc>{cls.receiver_base}/nested.xml</loc></sitemapindex>").encode()
                elif self.path == "/login":
                    body = (f'<form method="post" action="{cls.receiver_base}/steal">'
                            '<input name="username"><input name="password" type="password"></form>').encode()
                elif self.path == "/forms":
                    body = (f'<form method="post" action="{cls.receiver_base}/form">'
                            '<input name="q" type="text"></form>').encode()
                elif self.path == "/compare":
                    auth = self.headers.get("Authorization")
                    cls.source_auth.append(auth)
                    if auth != "Bearer primary":
                        self.send_response(302)
                        self.send_header("Location", cls.receiver_base + "/compare-redirect")
                        self.end_headers()
                        return
                    body = b"<html>private content</html>"
                elif self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", cls.receiver_base + "/redirected")
                    self.end_headers()
                    return
                else:
                    body = b"<html>ordinary page</html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        cls.source = socketserver.TCPServer(("127.0.0.1", 0), Source)
        cls.source_base = f"http://127.0.0.1:{cls.source.server_address[1]}"
        cls.source_thread = threading.Thread(target=cls.source.serve_forever, daemon=True)
        cls.source_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.source.shutdown()
        cls.source.server_close()
        cls.source_thread.join()
        cls.receiver.shutdown()
        cls.receiver.server_close()
        cls.receiver_thread.join()

    def setUp(self):
        self.received.clear()
        self.source_auth.clear()

    def test_sitemap_and_active_form_never_request_unapproved_origin(self):
        web.crawl_web(self.source_base + "/forms", max_pages=1, delay=0, ingest_sitemap=True,
                      active=True, extra_headers={"Authorization": "Bearer primary"})
        self.assertEqual(self.received, [])

    def test_login_form_action_rejects_cross_origin_credentials(self):
        result = {}
        warnings, _ = web.login(web.build_auth_opener(), self.source_base + "/login", "alice", "secret", result=result)
        self.assertTrue(any("form action" in warning for warning in warnings))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.received, [])

    def test_explicit_login_request_url_requires_approved_origin(self):
        destination = self.receiver_base + "/explicit-login"
        warnings, _ = web.login(web.build_auth_opener(), self.source_base + "/login", "alice", "secret",
                                request_url=destination)
        self.assertTrue(any("form action" in warning for warning in warnings))
        self.assertEqual(self.received, [])

        web.login(web.build_auth_opener(), self.source_base + "/login", "alice", "secret",
                  request_url=destination, allowed_origins=(self.receiver_base,))
        self.assertEqual([(method, path) for method, path, _ in self.received], [("POST", "/explicit-login")])

    def test_explicit_approved_http_login_action_requires_loopback(self):
        destination = "http://public.example/submit"
        warnings, _ = web.login(web.build_auth_opener(), self.source_base + "/login", "alice", "secret",
                                request_url=destination, allowed_origins=("http://public.example:80",))
        self.assertTrue(any("form action requires HTTPS" in warning for warning in warnings))
        self.assertEqual(self.received, [])

    def test_comparison_headers_do_not_inherit_primary_or_follow_redirect(self):
        web.crawl_web(self.source_base + "/compare", max_pages=1, delay=0,
                      extra_headers={"Authorization": "Bearer primary", "X-API-Key": "primary-key"},
                      compare_unauth=True, secondary_headers={"Authorization": "Bearer second"})
        self.assertIn("Bearer primary", self.source_auth)
        self.assertIn(None, self.source_auth)
        self.assertIn("Bearer second", self.source_auth)
        self.assertEqual(self.received, [])

    def test_approved_redirect_strips_custom_auth_header(self):
        web.crawl_web(self.source_base + "/redirect", max_pages=1, delay=0,
                      allowed_origins=(self.receiver_base,),
                      extra_headers={"Authorization": "Bearer primary", "X-API-Key": "primary-key"})
        redirected = next(headers for method, path, headers in self.received if path == "/redirected")
        self.assertNotIn("Authorization", redirected)
        self.assertNotIn("X-Api-Key", redirected)

    def test_custom_redirecting_opener_is_made_safe(self):
        web.crawl_web(self.source_base + "/redirect", max_pages=1, delay=0,
                      opener=urllib.request.build_opener(), allowed_origins=(self.receiver_base,),
                      extra_headers={"Authorization": "Bearer primary"})
        redirected = next(headers for method, path, headers in self.received if path == "/redirected")
        self.assertNotIn("Authorization", redirected)

    def test_pinned_render_fetch_stops_before_redirect(self):
        class Network:
            limits = {"max_response_bytes": 4096}

            def build_opener(self):
                return urllib.request.build_opener()

            def remaining_timeout(self):
                return 2

        network = Network()
        request = types.SimpleNamespace(
            url=self.source_base + "/redirect", method="GET", post_data_buffer=None,
            all_headers=lambda: {"Authorization": "Bearer primary"},
        )
        self.assertIsNone(web._pinned_render_response(network, request, {}, 2))
        self.assertEqual(self.received, [])

        request.url = self.source_base + "/forms"
        status, _headers, body = web._pinned_render_response(network, request, {}, 2)
        self.assertEqual(status, 200)
        self.assertIn(b"<form", body)

    def test_pinned_render_fetch_uses_approved_network_context(self):
        profile = validate_profile({
            "schema_version": 1,
            "target": {"environment": "fixture", "origins": [self.source_base],
                       "include_paths": ["/"], "scopes": ["passive"]},
            "limits": {"requests": 5, "timeout_seconds": 10},
            "accounts": {}, "auth": {}, "resources": [], "scenarios": [],
            "oast": {}, "applicability": {},
        })
        network = NetworkContext(profile, build_approval_request(profile))
        request = types.SimpleNamespace(
            url=self.source_base + "/forms", method="GET", post_data_buffer=None,
            all_headers=lambda: {"Accept": "text/html"},
        )
        status, _headers, body = web._pinned_render_response(network, request, {}, 2)
        self.assertEqual(status, 200)
        self.assertIn(b"<form", body)
        self.assertEqual(network.request_count, 1)

    def test_https_asset_downgrade_is_not_requested(self):
        class NoNetwork:
            def open(self, *_args, **_kwargs):
                raise AssertionError("downgraded asset was fetched")

        routes, findings, failed, limited = web._scan_assets(
            "https://example.test/page", '<script src="http://example.test/app.js"></script>',
            NoNetwork(), {"Authorization": "Bearer primary"}, 1.0, set(), 20, "example.test",
            extract_routes=True, scan_secrets=False,
            allowed_origins={"https://example.test", "http://example.test"},
        )
        self.assertEqual((routes, findings, failed, limited), (set(), [], 0, False))


if __name__ == "__main__":
    unittest.main()
