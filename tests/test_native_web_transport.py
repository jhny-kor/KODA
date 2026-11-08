"""Compile the shipping Swift transport and exercise real loopback HTTP boundaries."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
SWIFT = ROOT / 'platforms/macos/app/KODA/KODA'

HARNESS = r'''
import Foundation
@main struct Harness {
    static func main() async throws {
        let base = CommandLine.arguments[1]
        func profile() -> WebAuditProfile {
            var p = WebAuditProfile(target: base)
            p.authorized = true
            p.limits.requestsPerSecond = 20
            p.limits.requestTimeout = 2
            return p
        }
        func req(_ path: String, method: String = "GET", body: Data? = nil) -> WebAuditRequest {
            WebAuditRequest(url: URL(string: base + path)!, method: method, body: body)
        }
        func check(_ condition: Bool, _ label: String) throws {
            if !condition { throw NSError(domain: label, code: 1) }
        }
        var p = profile()
        p.headers = ["Authorization": "${ENV:KODA_TRANSPORT_TEST_SECRET}"]
        p.accounts = [WebAuditAccount(id: "second", headers: ["Authorization": "Bearer second"])]
        let transport = try WebAuditTransport(profile: p)
        let primary = try await transport.send(req("/identity"), actor: "primary")
        try check(primary.text.contains("Bearer fixture-secret"), "primary env header")
        _ = try await transport.send(req("/set-cookie"), actor: "primary")
        let cookie = try await transport.send(req("/identity"), actor: "primary")
        try check(cookie.text.contains("session=primary"), "primary cookie")
        let anonymous = try await transport.send(req("/identity"))
        try check(!anonymous.text.contains("fixture-secret") && !anonymous.text.contains("session="), "anonymous isolation")
        let second = try await transport.send(req("/identity"), actor: "second")
        try check(second.text.contains("Bearer second") && !second.text.contains("session="), "second isolation")
        let redirect = try await transport.send(req("/redirect"), actor: "primary")
        try check(redirect.status == 302, "redirect returned")
        let before = await transport.snapshot()
        let invalid = ["http://localhost:" + String(URL(string: base)!.port!) + "/identity", base + "/%252e%252e/identity", base + "/x%2fy", base + "/logout/child"]
        for url in invalid {
            do { _ = try await transport.send(WebAuditRequest(url: URL(string: url)!)); throw NSError(domain: "policy accepted", code: 1) }
            catch is WebAuditError { }
        }
        do { _ = try await transport.send(req("/identity"), actor: "missing"); throw NSError(domain: "actor accepted", code: 1) } catch is WebAuditError { }
        do { _ = try await transport.send(req("/identity", method: "POST")); throw NSError(domain: "write accepted", code: 1) } catch is WebAuditError { }
        let after = await transport.snapshot()
        try check(before.requests == after.requests && after.blocked >= 6, "blocked before network")
        await transport.shutdown()
        do { _ = try await transport.send(req("/identity")); throw NSError(domain: "shutdown accepted", code: 1) } catch is WebAuditError { }

        p = profile(); p.allowedMethods.append("POST"); p.allowStateChanges = true
        let inactive = try WebAuditTransport(profile: p)
        do { _ = try await inactive.send(req("/identity", method: "POST")); throw NSError(domain: "inactive write accepted", code: 1) } catch is WebAuditError { }
        await inactive.shutdown()

        p = profile(); p.includePaths = ["/scope"]
        let scoped = try WebAuditTransport(profile: p)
        _ = try await scoped.send(req("/scope/ok"))
        do { _ = try await scoped.send(req("/scope-escape")); throw NSError(domain: "segment accepted", code: 1) } catch is WebAuditError { }
        await scoped.shutdown()

        p = profile(); p.allowedMethods.append("POST"); p.active = true; p.allowStateChanges = true; p.limits.maxUploadBytes = 3
        let writing = try WebAuditTransport(profile: p)
        let posted = try await writing.send(req("/identity", method: "POST", body: Data("ok".utf8)))
        try check(posted.status == 200, "explicit write")
        do { _ = try await writing.send(req("/identity", method: "POST", body: Data("large".utf8))); throw NSError(domain: "upload accepted", code: 1) } catch is WebAuditError { }
        await writing.shutdown()

        p = profile(); p.limits.maxRequests = 2
        let bounded = try WebAuditTransport(profile: p)
        let successes = await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<8 { group.addTask { do { _ = try await bounded.send(req("/identity")); return true } catch { return false } } }
            var count = 0; for await ok in group { if ok { count += 1 } }; return count
        }
        try check(successes == 2, "concurrent request budget")
        await bounded.shutdown()

        p = profile(); p.limits.maxRequests = 3
        p.apiWriteCleanup = [WebAuditStep(path: "/identity")]
        let reserved = try WebAuditTransport(profile: p)
        _ = try await reserved.send(req("/identity"))
        _ = try await reserved.send(req("/identity"))
        do { _ = try await reserved.send(req("/identity")); throw NSError(domain: "cleanup reserve spent", code: 1) } catch is WebAuditError { }
        let cleaned = try await Task.detached { try await reserved.sendCleanup(req("/identity")) }.value
        try check(cleaned.status == 200, "reserved cleanup request succeeds")
        let reservedMetrics = await reserved.snapshot()
        try check(reservedMetrics.requests == 3, "cleanup counted in total")
        await reserved.shutdown()

        p = profile(); p.apiWriteCleanup = [WebAuditStep(path: "/identity")]
        let cancelledAudit = try WebAuditTransport(profile: p)
        _ = try await cancelledAudit.send(req("/set-cookie"), actor: "primary")
        let pending = Task { try await cancelledAudit.send(req("/slow"), actor: "primary") }
        try await Task.sleep(nanoseconds: 100_000_000); pending.cancel()
        do { _ = try await pending.value; throw NSError(domain: "cancel ignored", code: 1) } catch is CancellationError { }
        let cancellationCleanup = try await Task.detached { try await cancelledAudit.sendCleanup(req("/identity"), actor: "primary") }.value
        try check(cancellationCleanup.text.contains("session=primary"), "cancel cleanup preserves actor cookie")
        await cancelledAudit.shutdown()

        p = profile(); p.limits.maxDuration = 0.4; p.apiWriteCleanup = [WebAuditStep(path: "/identity")]
        let timeReserved = try WebAuditTransport(profile: p)
        do { _ = try await timeReserved.send(req("/slow")); throw NSError(domain: "normal deadline ignored", code: 1) } catch is WebAuditError { }
        let timeCleanup = try await Task.detached { try await timeReserved.sendCleanup(req("/identity")) }.value
        try check(timeCleanup.status == 200, "reserved cleanup duration succeeds")
        await timeReserved.shutdown()

        p = profile(); p.limits.maxRequests = 1; p.apiWriteCleanup = [WebAuditStep(path: "/identity")]
        do { _ = try WebAuditTransport(profile: p); throw NSError(domain: "cleanup budget accepted", code: 1) } catch is WebAuditError { }

        p = profile(); p.limits.maxResponseBytes = 128
        let capped = try WebAuditTransport(profile: p)
        for path in ["/large", "/stream"] {
            do { _ = try await capped.send(req(path)); throw NSError(domain: "response cap accepted", code: 1) }
            catch WebAuditError.responseTooLarge { }
        }
        await capped.shutdown()

        p = profile(); p.limits.maxDuration = 0.2
        let deadline = try WebAuditTransport(profile: p)
        let start = Date()
        do { _ = try await deadline.send(req("/slow")); throw NSError(domain: "deadline accepted", code: 1) } catch is WebAuditError { }
        try check(Date().timeIntervalSince(start) < 1, "hard duration deadline")
        await deadline.shutdown()

        p = profile(); p.limits.requestsPerSecond = 10
        let rate = try WebAuditTransport(profile: p)
        let rateStart = Date()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<3 { group.addTask { _ = try? await rate.send(req("/identity")) } }
        }
        try check(Date().timeIntervalSince(rateStart) >= 0.18, "global rate reservation")
        await rate.shutdown()
        let cancellationTransport = try WebAuditTransport(profile: profile())
        let cancellationStarted = Date()
        let cancelled = Task { try await cancellationTransport.send(req("/slow")) }
        try await Task.sleep(nanoseconds: 50_000_000); cancelled.cancel()
        do { _ = try await cancelled.value; throw NSError(domain: "cancellation accepted", code: 1) } catch is CancellationError { }
        try check(Date().timeIntervalSince(cancellationStarted) < 0.8, "active request cancellation")
        await cancellationTransport.shutdown()

        for invalidType in 0..<12 {
            p = profile()
            switch invalidType {
            case 0: p.accounts = [WebAuditAccount(id: "anonymous")]
            case 1: p.allowedMethods = ["get"]
            case 2: p.limits.requestsPerSecond = .infinity
            case 3: p.resources = [WebAuditResource(id: "x", path: "/x", controlID: "unknown")]
            case 4: p.scenarios = [WebAuditScenario(id: "x", steps: [WebAuditStep(path: "/", expectedStatusCodes: [])])]
            case 5: p.rules = [WebAuditHTTPRule(id: "empty", title: "empty", controlID: "web.xss", path: "/")]
            case 6: p.resources = [WebAuditResource(id: "empty", path: "/")]
            case 7: p.scenarios = [WebAuditScenario(id: "empty", steps: [])]
            case 8: p.scenarios = Array(repeating: WebAuditScenario(id: "duplicate", steps: [WebAuditStep(path: "/")]), count: 2)
            case 9: p.scenarios = [WebAuditScenario(id: "bad\n", steps: [WebAuditStep(path: "/")])]
            case 10: p.rules = [WebAuditHTTPRule(id: "builtin.shadow", title: "shadow", controlID: "web.xss", path: "/", bodyContains: ["match"])]
            default: p.accounts = Array(repeating: WebAuditAccount(id: "too-many"), count: 21)
            }
            do { _ = try WebAuditTransport(profile: p); throw NSError(domain: "invalid profile accepted", code: 1) } catch is WebAuditError { }
        }
        p = profile(); p.target = "http://192.0.2.1/"; p.headers = ["Content-Type": "application/json", "Accept": "application/json"]
        let ordinaryHTTP = try WebAuditTransport(profile: p)
        await ordinaryHTTP.shutdown()
        p = profile(); p.target = "http://192.0.2.1/"; p.headers = ["Authorization": "Bearer fixture-secret"]
        do { _ = try WebAuditTransport(profile: p); throw NSError(domain: "insecure credentials accepted", code: 1) } catch is WebAuditError { }
        print("transport-fixture-ok")
    }
}
'''


class Handler(BaseHTTPRequestHandler):
    seen = []
    def log_message(self, *_args):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.do_GET()

    def do_GET(self):
        self.seen.append(self.path)
        if self.path == '/slow':
            time.sleep(1.2)
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', self.server.redirect_to)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if self.path == '/large':
            body = b'x' * 1024
        else:
            body = json.dumps(dict(self.headers)).encode()
        self.send_response(200)
        if self.path == '/set-cookie':
            self.send_header('Set-Cookie', 'session=primary; Path=/; HttpOnly')
        if self.path != '/stream':
            self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            if self.path == '/stream':
                for _ in range(500):
                    self.wfile.write(b'x' * 64)
                    self.wfile.flush()
                    time.sleep(.002)
            else:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


@unittest.skipUnless(shutil.which('swiftc') and os.uname().sysname == 'Darwin', 'macOS Swift required')
class NativeWebTransportTests(unittest.TestCase):
    def test_app_store_compile_boundary(self):
        source = r'''import Foundation
@main struct Check {
    static func main() async throws {
        var p = WebAuditProfile(target: "http://127.0.0.1/")
        p.authorized = true; p.allowedMethods = ["GET", "HEAD"]
        let transport = try WebAuditTransport(profile: p)
        do {
            _ = try await transport.send(WebAuditRequest(url: URL(string: p.target)!, method: "OPTIONS"))
            throw NSError(domain: "App Store write accepted", code: 1)
        } catch is WebAuditError { }
        await transport.shutdown()
        p.active = true
        do { _ = try WebAuditTransport(profile: p); throw NSError(domain: "App Store active accepted", code: 1) }
        catch is WebAuditError { }
        print("app-store-boundary-ok")
    }
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            harness = Path(tmp) / 'main.swift'; harness.write_text(source)
            executable = Path(tmp) / 'appstore'
            build = subprocess.run(['swiftc', '-swift-version', '6', '-D', 'KODA_APP_STORE', '-parse-as-library',
                                    str(SWIFT / 'NativeWebAuditModels.swift'), str(SWIFT / 'NativeWebAuditTransport.swift'),
                                    str(harness), '-o', str(executable)], capture_output=True, text=True, timeout=90)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('app-store-boundary-ok', result.stdout)

    def test_production_transport_boundaries(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        other = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.redirect_to = f'http://127.0.0.1:{other.server_port}/must-not-follow'
        threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (server, other)]
        for thread in threads:
            thread.start()
        Handler.seen = []
        try:
            with tempfile.TemporaryDirectory() as tmp:
                harness = Path(tmp) / 'main.swift'
                harness.write_text(HARNESS)
                executable = Path(tmp) / 'transport'
                build = subprocess.run(['swiftc', '-swift-version', '5', '-parse-as-library',
                                        str(SWIFT / 'NativeWebAuditModels.swift'), str(SWIFT / 'NativeWebAuditTransport.swift'),
                                        str(harness), '-o', str(executable)], capture_output=True, text=True, timeout=90)
                self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
                env = dict(os.environ, KODA_TRANSPORT_TEST_SECRET='Bearer fixture-secret')
                result = subprocess.run([str(executable), f'http://127.0.0.1:{server.server_port}'],
                                        env=env, capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('transport-fixture-ok', result.stdout)
                self.assertNotIn('/must-not-follow', Handler.seen)
                self.assertNotIn('/logout/child', Handler.seen)
                self.assertNotIn('/scope-escape', Handler.seen)
        finally:
            for item in (server, other):
                item.shutdown()
                item.server_close()
