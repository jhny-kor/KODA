#!/usr/bin/env python3
"""Run the production Swift web auditor against local, deterministic HTTP fixtures.

No external host is scanned. The harness uses the same sources as the macOS app,
so request policy, audit coverage and report exports are tested together.
"""

from __future__ import annotations

import json
import html
import re
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


SOURCE_DIR = Path(__file__).resolve().parents[1] / "app/KODA/KODA"
SOURCES = ["NativeWebAuditModels.swift", "NativeWebAuditTransport.swift",
           "NativeWebAuditRules.swift", "NativeWebAuditAPI.swift", "NativeWebAuditor.swift"]
SECRET = "KODA_FIXTURE_PRIVATE_BEARER_39f2a674"
HARNESS = r'''
import Foundation

@main struct WebAuditHarness {
    static func main() async {
        do {
            let profile = try WebAuditProfile.load(data: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1])))
            let output = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
            let spec: Data? = CommandLine.arguments.count > 3 && CommandLine.arguments[3] != "-"
                ? try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[3])) : nil
            let task = Task { try await NativeWebAuditor.run(profile: profile, apiSpecData: spec) }
            if CommandLine.arguments.count > 4 {
                let trigger = CommandLine.arguments[4]
                Task {
                    if let milliseconds = UInt64(trigger) {
                        try? await Task.sleep(nanoseconds: milliseconds * 1_000_000)
                    } else {
                        while !FileManager.default.fileExists(atPath: trigger) {
                            try? await Task.sleep(nanoseconds: 5_000_000)
                        }
                    }
                    task.cancel()
                }
            }
            let report = try await task.value
            _ = try WebAuditReportWriter.write(report: report, to: output)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            print(String(decoding: try encoder.encode(report), as: UTF8.self))
        } catch {
            let data = try! JSONSerialization.data(withJSONObject: ["error": error.localizedDescription])
            print(String(decoding: data, as: UTF8.self))
            exit(2)
        }
    }
}
'''


class FixtureState:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with self.lock:
            self.mode = "normal"
            self.requests = []
            self.items = 0
            self.trap_url = ""
            self.cancel_signal = ""

    def record(self, handler, body):
        with self.lock:
            self.requests.append({"method": handler.command, "path": handler.path,
                                  "authorization": handler.headers.get("Authorization", ""),
                                  "cookie": handler.headers.get("Cookie", ""),
                                  "body": body.decode("utf-8", "replace")})


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def do_HEAD(self):
        self.dispatch()

    def do_GET(self):
        self.dispatch()

    def do_OPTIONS(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch()

    def do_PUT(self):
        self.dispatch()

    def do_DELETE(self):
        self.dispatch()

    def reply(self, status=200, text="ok", headers=None):
        payload = text.encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.close_connection = True

    def dispatch(self):
        state = self.server.state
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size) if size else b""
        state.record(self, body)
        path = urlsplit(self.path).path
        query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        if state.mode == "trap":
            self.reply(text="redirect target")
        elif path == "/redirect":
            self.reply(302, "redirect", {"Location": state.trap_url + "/caught"})
        elif path == "/slow":
            if state.cancel_signal:
                Path(state.cancel_signal).touch()
            time.sleep(0.8)
            self.reply(text="slow fixture")
        elif path == "/large":
            self.reply(text="x" * 100_000)
        elif path == "/login":
            actor = self.headers.get("Authorization", "")
            self.reply(200 if actor == "Bearer user-a" else 403, "signed in" if actor == "Bearer user-a" else "denied",
                       {"Set-Cookie": "audit_actor=user-a; Path=/; HttpOnly; SameSite=Strict"} if actor == "Bearer user-a" else {})
        elif path == "/cookie-private":
            permitted = "audit_actor=user-a" in self.headers.get("Cookie", "")
            self.reply(200 if permitted else 403, "private cookie data" if permitted else "denied")
        elif path == "/login-fallback":
            actor = self.headers.get("Authorization", "")
            self.reply(text="owner A" if actor == "Bearer user-a" else "<html><form>Please sign in</form></html>")
        elif path.startswith("/api/soft/"):
            self.reply(text="APP_KEY=fixture-public-template DB_PASSWORD=fixture-template")
        elif path == "/.env" and state.mode == "envexposure":
            self.reply(text="APP_KEY=fixture-app DB_PASSWORD=fixture-password")
        elif path == "/private":
            actor = self.headers.get("Authorization", "")
            permitted = actor in ("Bearer user-a", "Bearer admin") or state.mode == "broken-auth"
            self.reply(200 if permitted else 403, "owner A" if permitted else "forbidden")
        elif path in ("/vulnerable", "/strict"):
            value = query.get("q", [""])[0]
            if path == "/strict":
                self.reply(text="<html><body>" + html.escape(value) + "</body></html>")
            elif value.startswith("https://example.invalid/"):
                self.reply(302, "redirect", {"Location": value})
            elif "\r\nX-Koda-Audit: " in value:
                self.reply(text="fixture", headers={"X-Koda-Audit": value.split("X-Koda-Audit: ", 1)[1]})
            elif "'" in value:
                self.reply(500, "SQLSTATE[42000] fixture input error")
            else:
                computed = re.sub(r"\{\{(\d{1,4})\*(\d{1,4})\}\}",
                                  lambda match: str(int(match[1]) * int(match[2])), value)
                self.reply(text="<html><body>" + computed + "</body></html>")
        elif path == "/marker":
            self.reply(text="KODA_CONFIRMED_FIXTURE_MARKER")
        elif path == "/leak":
            self.reply(text="LEAK " + self.headers.get("Authorization", ""))
        elif path == "/api/search":
            q = query.get("q", [""])[0]
            self.reply(200 if 2 <= len(q) <= 4 else 400, json.dumps({"query": q}))
        elif path == "/api/items" and self.command == "POST":
            try:
                value = json.loads(body)
            except (ValueError, UnicodeDecodeError):
                value = {}
            if not isinstance(value, dict):
                value = {}
            if isinstance(value.get("name"), str) and 2 <= len(value["name"]) <= 8:
                with state.lock:
                    state.items += 1
                self.reply(201, '{"id":1}')
            else:
                self.reply(400, '{"error":"invalid name"}')
        elif path == "/api/items/all" and self.command == "DELETE":
            if state.mode == "cleanup-failure":
                self.reply(500, "fixture cleanup failure")
            else:
                with state.lock:
                    state.items = 0
                self.reply(200, "cleaned")
        elif path == "/" or path == "/normal":
            self.reply(text="<!doctype html><html><body>fixture home</body></html>")
        elif state.mode == "soft404":
            self.reply(text="<!doctype html><html><body>Please sign in to continue</body></html>")
        else:
            self.reply(404, "fixture not found")


class NativeWebAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="koda-native-web-audit-tests-")
        cls.root = Path(cls.workspace.name)
        harness = cls.root / "Harness.swift"
        harness.write_text(HARNESS, encoding="utf-8")
        cls.binary = cls.root / "web-audit-harness"
        command = ["swiftc", "-swift-version", "6"] + [str(SOURCE_DIR / name) for name in SOURCES]
        subprocess.run(command + [str(harness), "-o", str(cls.binary)], check=True,
                       text=True, timeout=90)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.server.daemon_threads = True
        cls.server.state = FixtureState()
        cls.trap = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.trap.daemon_threads = True
        cls.trap.state = FixtureState()
        cls.trap.state.mode = "trap"
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.trap_url = f"http://127.0.0.1:{cls.trap.server_port}"
        cls.threads = [threading.Thread(target=server.serve_forever, daemon=True)
                       for server in (cls.server, cls.trap)]
        for thread in cls.threads:
            thread.start()

    @classmethod
    def tearDownClass(cls):
        for server in (cls.server, cls.trap):
            server.shutdown()
            server.server_close()
        cls.workspace.cleanup()

    def setUp(self):
        self.server.state.reset()
        self.trap.state.reset()
        self.trap.state.mode = "trap"
        self.server.state.trap_url = self.trap_url

    def profile(self, **updates):
        result = {"target": self.url, "authorized": True,
                  "limits": {"maxRequests": 100, "maxDuration": 20, "requestsPerSecond": 20,
                             "requestTimeout": 2, "maxResponseBytes": 200_000,
                             "maxUploadBytes": 10_000, "maxPages": 2, "maxDepth": 1}}
        result.update(updates)
        return result

    def audit(self, profile, spec=None, cancel_ms=None, cancel_on_slow=False, expect_error=False):
        directory = Path(tempfile.mkdtemp(prefix="run-", dir=self.root))
        profile_path = directory / "profile.json"
        profile_path.write_text(json.dumps(profile), encoding="utf-8")
        spec_path = "-"
        if spec is not None:
            spec_file = directory / "openapi.json"
            spec_file.write_text(json.dumps(spec), encoding="utf-8")
            spec_path = str(spec_file)
        args = [str(self.binary), str(profile_path), str(directory), spec_path]
        if cancel_on_slow:
            signal = directory / "cancel.signal"
            self.server.state.cancel_signal = str(signal)
            args.append(str(signal))
        elif cancel_ms is not None:
            args.append(str(cancel_ms))
        process = subprocess.run(args, capture_output=True, text=True, timeout=30,
                                 env={**os.environ, "KODA_WEB_TEST_TOKEN": "Bearer " + SECRET})
        lines = [line for line in process.stdout.splitlines() if line.strip()]
        self.assertTrue(lines, process.stderr)
        value = json.loads(lines[-1])
        if expect_error:
            self.assertNotEqual(process.returncode, 0, value)
            self.assertIn("error", value)
            return value, directory
        self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
        self.assertEqual(value["engine"], "koda-swift-web-audit")
        for name in ("audit.json", "audit.md", "audit.html"):
            self.assertTrue((directory / name).is_file(), name)
        return value, directory

    @unittest.skipUnless(os.environ.get("KODA_TEST_APP_BINARY"),
                         "set KODA_TEST_APP_BINARY to verify the built macOS .app executable")
    def test_built_macos_app_executes_the_same_audit_and_exports_evidence(self):
        binary = Path(os.environ["KODA_TEST_APP_BINARY"]).expanduser().resolve()
        self.assertTrue(binary.is_file(), binary)
        self.assertTrue(os.access(binary, os.X_OK), binary)
        for mode, expected_exit in (("normal", 0), ("envexposure", 1), ("budget", 2)):
            with self.subTest(mode=mode, executable=str(binary)):
                self.server.state.reset()
                self.server.state.mode = mode
                profile = self.profile()
                if mode == "budget":
                    profile["limits"]["maxRequests"] = 1
                directory = Path(tempfile.mkdtemp(prefix="app-run-", dir=self.root))
                profile_path = directory / "profile.json"
                profile_path.write_text(json.dumps(profile), encoding="utf-8")
                process = subprocess.run([str(binary)], capture_output=True, text=True, timeout=45,
                                         env={**os.environ, "KODA_WEB_AUDIT_PROFILE": str(profile_path),
                                              "KODA_WEB_AUDIT_OUTPUT_DIR": str(directory)})
                self.assertEqual(process.returncode, expected_exit, process.stdout + process.stderr)
                output = directory / "KODA-web-audit"
                for name in ("audit.json", "audit.html", "audit.md"):
                    self.assertTrue((output / name).is_file(), process.stdout + process.stderr)
                report = json.loads((output / "audit.json").read_text(encoding="utf-8"))
                self.assertEqual(report["engine"], "koda-swift-web-audit")
                self.assertEqual(len(report["controls"]), 21)
                self.assertGreater(report["metrics"]["requests"], 0)
                evidence_ids = {item["evidenceID"] for item in report["observations"]}
                self.assertTrue(evidence_ids, report)
                self.assertTrue(all(set(item["evidenceIDs"]).issubset(evidence_ids)
                                    for item in report["controls"]), report)
                if mode == "envexposure":
                    self.assertTrue(report["completed"], report)
                    self.assertTrue(any(item["ruleID"] == "builtin.dotenv" and item["status"] == "VULNERABLE"
                                        for item in report["observations"]), report)
                elif mode == "budget":
                    self.assertFalse(report["completed"], report)
                    self.assertTrue(report["warnings"], report)
                    self.assertFalse(any(item["status"] == "PASS" for item in report["controls"]), report)
                else:
                    self.assertTrue(report["completed"], report)
                    self.assertTrue(any(item["ruleID"] == "passive.http" for item in report["observations"]), report)

    def test_unconfigured_controls_are_not_false_passes(self):
        report, _ = self.audit(self.profile())
        self.assertEqual(len(report["controls"]), 21)
        self.assertEqual(len({item["controlID"] for item in report["controls"]}), 21)
        self.assertFalse(any(item["status"] == "PASS" for item in report["controls"]), report["controls"])
        self.assertGreater(report["metrics"]["requests"], 0)
        self.assertTrue(report["completed"], report["warnings"])
        evidence_ids = {item["evidenceID"] for item in report["observations"]}
        self.assertTrue(evidence_ids)
        self.assertTrue(all(set(item["evidenceIDs"]).issubset(evidence_ids) for item in report["controls"]))

    def test_custom_rule_preserves_identity_without_self_confirming(self):
        rule = {"id": "fixture.marker", "title": "Fixture marker", "controlID": "web.information-disclosure",
                "path": "/marker", "bodyContains": ["KODA_CONFIRMED_FIXTURE_MARKER"], "confirmed": True}
        report, _ = self.audit(self.profile(rules=[rule]))
        matches = [item for item in report["observations"] if item["ruleID"] == "fixture.marker"]
        self.assertEqual(len(matches), 1, report)
        self.assertEqual(matches[0]["status"], "NEEDS_REVIEW")
        self.assertIn("/marker", matches[0]["endpoint"])

    def test_scoped_custom_rule_runs_without_out_of_scope_builtin_requests(self):
        rule = {"id": "fixture.scoped-home", "title": "Scoped fixture home",
                "controlID": "web.information-disclosure", "path": "/normal",
                "bodyContains": ["fixture home"], "confirmed": True}
        report, _ = self.audit(self.profile(target=self.url + "/normal", includePaths=["/normal"], rules=[rule]))
        matches = [item for item in report["observations"] if item["ruleID"] == rule["id"]]
        self.assertEqual(len(matches), 1, report)
        self.assertEqual(matches[0]["status"], "NEEDS_REVIEW", report)
        self.assertTrue(report["completed"], report)
        paths = [urlsplit(item["path"]).path for item in self.server.state.requests]
        self.assertTrue(paths)
        self.assertTrue(all(path == "/normal" for path in paths), paths)
        self.assertFalse(any(path.startswith(("/.git", "/.env", "/debug")) for path in paths), paths)

    def test_builtin_exposure_rule_requires_differentiated_missing_paths(self):
        self.server.state.mode = "envexposure"
        report, _ = self.audit(self.profile())
        matches = [item for item in report["observations"] if item["ruleID"] == "builtin.dotenv"]
        self.assertEqual(len(matches), 1, report)
        self.assertEqual(matches[0]["status"], "VULNERABLE", report)

    def test_real_http_differential_probes_find_only_fixture_signals(self):
        report, _ = self.audit(self.profile(target=self.url + "/vulnerable?q=sample", active=True))
        observations = {item["ruleID"]: item for item in report["observations"]}
        for rule in ("active.ssti", "active.crlf", "active.redirect"):
            self.assertEqual(observations.get(rule, {}).get("status"), "VULNERABLE", report)
        for rule in ("active.reflection", "active.sql-error"):
            self.assertEqual(observations.get(rule, {}).get("status"), "NEEDS_REVIEW", report)
        normal, _ = self.audit(self.profile(target=self.url + "/strict?q=sample", active=True))
        self.assertFalse(any(item["ruleID"].startswith("active.") for item in normal["observations"]), normal)

    def test_soft404_does_not_become_confirmed_sensitive_path_exposure(self):
        self.server.state.mode = "soft404"
        report, _ = self.audit(self.profile())
        confirmed = [item for item in report["observations"]
                     if item["status"] == "VULNERABLE" and item["controlID"] in
                     ("web.admin-exposure", "web.information-disclosure", "web.file-download")]
        self.assertEqual(confirmed, [], report)

    def test_auth_matrix_requires_matching_actor_expectations(self):
        resource = {"id": "owner-a", "path": "/private", "controlID": "web.authorization",
                    "expectations": {"anonymous": {"statusCodes": [403]},
                                     "user-a": {"statusCodes": [200], "bodyContains": "owner A"},
                                     "user-b": {"statusCodes": [403]},
                                     "admin": {"statusCodes": [200], "bodyContains": "owner A"}}}
        accounts = [{"id": value, "headers": {"Authorization": "Bearer " + value}}
                    for value in ("user-a", "user-b", "admin")]
        report, _ = self.audit(self.profile(accounts=accounts, resources=[resource]))
        control = next(item for item in report["controls"] if item["controlID"] == "web.authorization")
        self.assertEqual(control["status"], "PASS", report)
        self.server.state.mode = "broken-auth"
        broken, _ = self.audit(self.profile(accounts=accounts, resources=[resource]))
        control = next(item for item in broken["controls"] if item["controlID"] == "web.authorization")
        self.assertEqual(control["status"], "VULNERABLE", broken)
        self.assertTrue(any(item["controlID"] == "web.authorization" for item in broken["observations"]))

    def test_login_fallback_and_unmarked_success_are_not_confirmed_bypasses(self):
        accounts = [{"id": "user-a", "headers": {"Authorization": "Bearer user-a"}}]
        resource = {"id": "fallback", "path": "/login-fallback", "controlID": "web.authorization",
                    "expectations": {"anonymous": {"statusCodes": [403]},
                                     "user-a": {"statusCodes": [200], "bodyContains": "owner A"}}}
        report, _ = self.audit(self.profile(accounts=accounts, resources=[resource]))
        related = [item for item in report["observations"] if item["ruleID"] == "web.matrix.fallback"]
        self.assertTrue(related, report)
        self.assertTrue(all(item["status"] == "NEEDS_REVIEW" for item in related), report)
        self.server.state.mode = "broken-auth"
        resource["path"] = "/private"
        resource["expectations"]["user-a"] = {"statusCodes": [200]}
        unmarked, _ = self.audit(self.profile(accounts=accounts, resources=[resource]))
        related = [item for item in unmarked["observations"] if item["ruleID"] == "web.matrix.fallback"]
        self.assertTrue(related, unmarked)
        self.assertTrue(all(item["status"] == "NEEDS_REVIEW" for item in related), unmarked)

    def test_route_specific_soft404_cannot_confirm_a_marker_rule(self):
        rule = {"id": "fixture.route-soft404", "title": "Soft404 environment fixture",
                "controlID": "web.information-disclosure", "path": "/api/soft/.env",
                "bodyContains": ["APP_KEY=", "DB_PASSWORD="], "confirmed": True}
        report, _ = self.audit(self.profile(rules=[rule]))
        related = [item for item in report["observations"] if item["ruleID"] == rule["id"]]
        self.assertTrue(related, report)
        self.assertTrue(all(item["status"] == "NEEDS_REVIEW" for item in related), report)
        self.assertTrue(any(urlsplit(item["path"]).path == rule["path"]
                            for item in self.server.state.requests))

    def test_cancelled_stateful_scenario_still_executes_reserved_cleanup(self):
        scenario = {"id": "create-and-cancel", "controlID": "web.process-validation",
                    "steps": [{"path": "/api/items", "method": "POST", "body": '{"name":"test"}',
                               "expectedStatusCodes": [201]},
                              {"path": "/slow", "expectedStatusCodes": [200]}],
                    "cleanup": [{"path": "/api/items/all", "method": "DELETE", "expectedStatusCodes": [200]}]}
        report, _ = self.audit(self.profile(active=True, allowStateChanges=True,
                                            allowedMethods=["GET", "HEAD", "OPTIONS", "POST", "DELETE"],
                                            scenarios=[scenario]), cancel_on_slow=True)
        calls = self.server.state.requests
        self.assertTrue(any(item["method"] == "POST" and item["path"] == "/api/items" for item in calls))
        self.assertTrue(any(item["path"] == "/slow" for item in calls))
        self.assertTrue(any(item["method"] == "DELETE" and item["path"] == "/api/items/all" for item in calls), report)
        self.assertEqual(self.server.state.items, 0, report)
        self.assertFalse(report["completed"], report)
        self.assertFalse(any(item["status"] == "PASS" for item in report["controls"]), report)

    def test_api_cleanup_http_failure_is_reported(self):
        self.server.state.mode = "cleanup-failure"
        profile = self.profile(active=True, allowStateChanges=True,
                               allowedMethods=["GET", "HEAD", "OPTIONS", "POST", "DELETE"],
                               apiWriteCleanup=[{"path": "/api/items/all", "method": "DELETE", "expectedStatusCodes": [200]}])
        report, _ = self.audit(profile, spec=self.api_spec(write=True))
        self.assertGreater(self.server.state.items, 0)
        self.assertFalse(report["completed"], report)
        self.assertTrue(any("정리" in value for value in report["warnings"]), report["warnings"])
        self.assertFalse(any(item["status"] == "PASS" for item in report["controls"]), report)

    def test_account_cookie_sessions_are_persistent_and_isolated(self):
        resources = [{"id": "sign-in", "path": "/login", "controlID": "web.session-management",
                      "expectations": {"user-a": {"statusCodes": [200], "bodyContains": "signed in"}}},
                     {"id": "cookie-access", "path": "/cookie-private", "controlID": "web.authorization",
                      "expectations": {"anonymous": {"statusCodes": [403]},
                                       "user-a": {"statusCodes": [200], "bodyContains": "private cookie data"}}}]
        report, _ = self.audit(self.profile(accounts=[{"id": "user-a", "headers": {"Authorization": "Bearer user-a"}}],
                                            resources=resources))
        controls = {item["controlID"]: item["status"] for item in report["controls"]}
        self.assertEqual(controls["web.session-management"], "PASS", report)
        self.assertEqual(controls["web.authorization"], "PASS", report)
        calls = [item for item in self.server.state.requests if item["path"] == "/cookie-private"]
        self.assertEqual(len(calls), 2)
        self.assertEqual([item["cookie"] for item in calls if not item["authorization"]], [""])
        self.assertTrue(any("audit_actor=user-a" in item["cookie"] for item in calls if item["authorization"]))

    def test_cross_origin_redirect_never_forwards_credentials(self):
        report, _ = self.audit(self.profile(target=self.url + "/redirect",
                                            headers={"Authorization": "Bearer " + SECRET,
                                                     "Cookie": "session=" + SECRET}))
        self.assertEqual(self.trap.state.requests, [])
        self.assertGreater(report["metrics"]["requests"], 0)

    def test_request_budget_marks_report_incomplete(self):
        profile = self.profile()
        profile["limits"]["maxRequests"] = 1
        report, _ = self.audit(profile)
        self.assertFalse(report["completed"], report)
        self.assertLessEqual(len(self.server.state.requests), 1)
        self.assertLessEqual(report["metrics"]["requests"], 1)
        self.assertTrue(report["warnings"])
        self.assertFalse(any(item["status"] == "PASS" for item in report["controls"]))

    def test_cancellation_stops_request_pipeline(self):
        report, _ = self.audit(self.profile(target=self.url + "/slow"), cancel_ms=80)
        self.assertFalse(report["completed"], report)
        self.assertLessEqual(len(self.server.state.requests), 2)
        self.assertTrue(report["warnings"])

    def test_oversized_response_is_an_explicit_incomplete_result(self):
        profile = self.profile(target=self.url + "/large")
        profile["limits"]["maxResponseBytes"] = 1024
        report, _ = self.audit(profile)
        self.assertFalse(report["completed"], report)
        self.assertTrue(report["warnings"])

    def test_invalid_profiles_and_rules_are_rejected_before_network(self):
        cases = [self.profile(authorized=False), self.profile(target="file:///etc/passwd"),
                 self.profile(includePaths=["//outside.example"]),
                 self.profile(rules=[{"id": "bad", "title": "bad", "controlID": "web.unknown",
                                      "path": "/marker", "bodyContains": ["fixture"]}]),
                 self.profile(headers={"Host": "outside.example"}),
                 self.profile(resources=[{"id": "typo", "path": "/private", "expectations": {
                     "anonymous": {"statusCodes": [403], "bodyContain": "forbidden"}}}]),
                 self.profile(resources=[{"id": "empty-oracle", "path": "/private", "expectations": {}}]),
                 self.profile(scenarios=[{"id": "empty-scenario", "steps": []}])]
        for profile in cases:
            with self.subTest(profile=profile):
                self.server.state.requests.clear()
                self.audit(profile, expect_error=True)
                self.assertEqual(self.server.state.requests, [])

    def test_export_redacts_credentials_and_escapes_html(self):
        rule = {"id": "fixture.leak", "title": "<script>alert(1)</script>",
                "controlID": "web.information-disclosure", "path": "/leak", "bodyContains": ["LEAK"]}
        report, directory = self.audit(self.profile(headers={"Authorization": "${ENV:KODA_WEB_TEST_TOKEN}"},
                                                     rules=[rule]))
        self.assertTrue(any(item["authorization"] == "Bearer " + SECRET for item in self.server.state.requests))
        for name in ("audit.json", "audit.md", "audit.html"):
            self.assertNotIn(SECRET, (directory / name).read_text(), name)
        self.assertNotIn(SECRET, json.dumps(report))
        self.assertNotIn("<script>alert(1)</script>", (directory / "audit.html").read_text())

    def api_spec(self, write=False):
        paths = {"/api/search": {"get": {"parameters": [{"name": "q", "in": "query", "required": True,
                                                         "schema": {"type": "string", "minLength": 2, "maxLength": 4}}],
                                          "responses": {"200": {"description": "valid"}, "400": {"description": "invalid"}}}}}
        if write:
            paths["/api/items"] = {"post": {"requestBody": {"required": True, "content": {"application/json": {
                "schema": {"type": "object", "required": ["name"], "properties": {
                    "name": {"type": "string", "minLength": 2, "maxLength": 8}}}}}},
                "responses": {"201": {"description": "created"}, "400": {"description": "invalid"}}}}
        return {"openapi": "3.0.3", "info": {"title": "Fixture", "version": "1"},
                "servers": [{"url": self.url}], "paths": paths}

    def test_openapi_generates_valid_and_invalid_get_inputs(self):
        report, _ = self.audit(self.profile(active=True), spec=self.api_spec())
        calls = [item for item in self.server.state.requests if urlsplit(item["path"]).path == "/api/search"]
        values = [parse_qs(urlsplit(item["path"]).query, keep_blank_values=True).get("q", [""])[0]
                  for item in calls]
        self.assertTrue(any(2 <= len(value) <= 4 for value in values), calls)
        self.assertTrue(any(not 2 <= len(value) <= 4 for value in values), calls)
        self.assertFalse(any("transport failed" in value for value in report["warnings"]), report["warnings"])

    def test_openapi_passive_profile_sends_only_the_valid_baseline(self):
        report, _ = self.audit(self.profile(active=False), spec=self.api_spec())
        calls = [item for item in self.server.state.requests if urlsplit(item["path"]).path == "/api/search"]
        values = [parse_qs(urlsplit(item["path"]).query, keep_blank_values=True).get("q", [""])[0]
                  for item in calls]
        self.assertEqual(len(values), 1, calls)
        self.assertTrue(all(2 <= len(value) <= 4 for value in values), calls)
        self.assertFalse(any("transport failed" in value for value in report["warnings"]), report["warnings"])

    def test_external_openapi_references_are_never_fetched(self):
        for variant in ("server", "reference"):
            spec = self.api_spec()
            if variant == "server":
                spec["servers"] = [{"url": self.trap_url}]
            else:
                spec["components"] = {"schemas": {"External": {"$ref": self.trap_url + "/schema.json"}}}
            with self.subTest(spec=spec):
                report, _ = self.audit(self.profile(active=True), spec=spec)
                self.assertFalse(report["completed"])
                self.assertTrue(report["warnings"])
                self.assertEqual(self.trap.state.requests, [])

    def test_openapi_writes_require_cleanup_and_leave_no_fixture_state(self):
        profile = self.profile(active=True, allowStateChanges=True, allowedMethods=["GET", "HEAD", "OPTIONS", "POST", "DELETE"])
        self.audit(profile, spec=self.api_spec(write=True))
        self.assertFalse(any(item["method"] == "POST" for item in self.server.state.requests))
        self.server.state.requests.clear()
        profile["apiWriteCleanup"] = [{"path": "/api/items/all", "method": "DELETE", "expectedStatusCodes": [200]}]
        report, _ = self.audit(profile, spec=self.api_spec(write=True))
        self.assertTrue(any(item["method"] == "POST" for item in self.server.state.requests), report)
        self.assertTrue(any(item["method"] == "DELETE" and item["path"] == "/api/items/all"
                            for item in self.server.state.requests), report)
        self.assertEqual(self.server.state.items, 0)
        self.assertFalse(any("transport failed" in value for value in report["warnings"]), report["warnings"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
