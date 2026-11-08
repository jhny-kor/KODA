"""Compile and exercise native Swift web rules/API planning without network traffic."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "platforms/macos/app/KODA/KODA"

HARNESS = r'''
import Foundation
actor WebAuditTransport {
    let mode: String
    var calls = 0
    init(_ mode: String) { self.mode = mode }
    func send(_ request: WebAuditRequest, actor: String = "anonymous") async throws -> WebAuditResponse {
        precondition(actor == "primary")
        calls += 1
        let value = URLComponents(url: request.url, resolvingAgainstBaseURL: false)?.queryItems?.first?.value ?? ""
        var body = value, headers = ["Content-Type": "text/html"], status = 200
        if mode == "static-error" { body = "SQLSTATE[42000]" }
        if mode == "sql" && value.hasSuffix("'") { body = "SQLSTATE[42000]" }
        if mode == "ssti" {
            body = body.replacingOccurrences(of: "{{713*719}}", with: String(713*719)).replacingOccurrences(of: "{{727*733}}", with: String(727*733))
        }
        if mode == "crlf" && value.hasPrefix("\r\nX-Koda-Audit: ") { headers["X-Koda-Audit"] = String(value.dropFirst("\r\nX-Koda-Audit: ".count)) }
        if mode == "redirect" && value.hasPrefix("https://example.invalid/") { headers["Location"] = value; status = 302 }
        return WebAuditResponse(url: request.url, status: status, headers: headers, body: Data(body.utf8), elapsed: 0)
    }
}
@main struct Runner {
    static func main() async throws {
        let selected = CommandLine.arguments[1]
        let origin = URL(string: "https://local.invalid")!
        func load(_ source: String, writes: Bool = false) throws -> WebAuditAPIPlan {
            try NativeWebAuditAPI.load(data: Data(source.utf8), baseURL: origin, allowedStateChanges: writes)
        }
        func rejected(_ source: String) -> Bool { do { _ = try load(source); return false } catch { return true } }
        switch selected {
        case "passive":
            let response = WebAuditResponse(url: origin, status: 200, headers: ["Content-Type":"text/html", "Access-Control-Allow-Origin":"*", "Set-Cookie":"session=secret"], body: Data("<title>Index of /</title>Parent Directory".utf8), elapsed: 0)
            let result = NativeWebAuditRules.inspect(response: response)
            precondition(result.contains { $0.ruleID == "passive.directory-index" })
            precondition(result.contains { $0.ruleID == "passive.cookie-flags" })
            precondition(result.allSatisfy { $0.status == .needsReview })
            precondition(!result.contains { $0.evidence.contains("secret") })
        case "api":
            let source = ##"{"openapi":"3.0.3","servers":[{"url":"/api"}],"paths":{"/items/{id}":{"parameters":[{"in":"path","name":"id","schema":{"type":"integer"}}],"get":{"parameters":[{"in":"query","name":"q","required":true,"schema":{"type":"string","minLength":2,"maxLength":4}}]},"post":{}}}}"##
            let result = try load(source)
            precondition(result.requests.count == 3)
            precondition(result.invalidRequestIndices == Set([1,2]))
            precondition(result.requests.allSatisfy { $0.method == "GET" && $0.url.host == origin.host })
            precondition(result.requests[0].url.path == "/api/items/1")
            let q = URLComponents(url: result.requests[0].url, resolvingAgainstBaseURL: false)!.queryItems!.first!.value!
            precondition((2...4).contains(q.count))
            precondition(result.requests[1].url.query == "q=")
            precondition(result.requests[2].url.query == nil || result.requests[2].url.query == "")
            precondition(result.warnings.contains { $0.contains("POST") })
        case "api-reject":
            precondition(rejected(##"{"openapi":"3.0.3","servers":[{"url":"https://evil.invalid"}],"paths":{}}"##))
            precondition(rejected(##"{"openapi":"3.0.3","paths":{},"components":{"schemas":{"x":{"$ref":"https://evil.invalid/x"}}}}"##))
            precondition(rejected("openapi: 3.0.3\npaths: {}"))
            precondition(rejected(##"{"swagger":"2.0","host":"evil.invalid","paths":{}}"##))
            precondition(rejected(##"{"openapi":"3.0.3","servers":[{"url":"//evil.invalid"}],"paths":{}}"##))
        case "api-write":
            let source = ##"{"openapi":"3.0.3","paths":{"/items":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Item"}}}}},"delete":{}}},"components":{"schemas":{"Item":{"type":"object","properties":{"name":{"type":"string","minLength":2,"maxLength":8}}}}}}"##
            let readonly = try load(source)
            precondition(readonly.requests.isEmpty)
            let result = try load(source, writes: true)
            precondition(result.requests.count == 2)
            precondition(result.requests.allSatisfy { $0.method == "POST" })
            let body = try JSONSerialization.jsonObject(with: result.requests[0].body!) as! [String:String]
            precondition((2...8).contains(body["name"]!.count))
            precondition(result.requests[1].body == Data("{".utf8))
        case "swagger":
            let source = ##"{"swagger":"2.0","host":"local.invalid","schemes":["https"],"basePath":"/v2","paths":{"/x":{"get":{"parameters":[{"in":"query","name":"n","type":"integer","minimum":5,"maximum":8}]}}}}"##
            let result = try load(source)
            precondition(result.requests[0].url.path == "/v2/x")
            precondition(result.requests[0].url.query == "n=5")
        case "bounds":
            var paths: [String:Any] = [:]
            for i in 0..<100 { paths["/x\(i)"] = ["get": [:]] }
            let data = try JSONSerialization.data(withJSONObject: ["openapi":"3.0.3", "paths":paths])
            let result = try NativeWebAuditAPI.load(data: data, baseURL: origin, allowedStateChanges: false)
            precondition(result.requests.count == 40)
        case "api-500":
            let response = WebAuditResponse(url: origin, status: 500, headers: [:], body: Data(), elapsed: 0)
            precondition(NativeWebAuditRules.inspectAPI(response: response).first!.status == .needsReview)
            let accepted = WebAuditResponse(url: origin, status: 200, headers: [:], body: Data(), elapsed: 0)
            precondition(NativeWebAuditRules.inspectAPI(response: accepted).isEmpty)
            precondition(NativeWebAuditRules.inspectAPI(response: accepted, isNegative: true).first!.status == .needsReview)
        case "response-schema":
            let source = ##"{"openapi":"3.0.3","paths":{"/item":{"get":{"responses":{"200":{"$ref":"#/components/responses/Item"},"404":{"description":"missing"}}}}},"components":{"responses":{"Item":{"description":"ok","content":{"application/json":{"schema":{"type":"object","required":["name","meta"],"properties":{"name":{"type":"string"},"meta":{"$ref":"#/components/schemas/Meta"}}}}}}},"schemas":{"Meta":{"type":"object","required":["count"],"properties":{"count":{"type":"integer"}}}}}}"##
            let result = try load(source)
            let expectation = result.responseExpectations[0]!
            func findings(_ body: String, status: Int = 200) -> [WebAuditObservation] {
                NativeWebAuditRules.inspectAPI(response: WebAuditResponse(url: origin, status: status, headers: [:], body: Data(body.utf8), elapsed: 0), expectation: expectation)
            }
            precondition(findings(#"{"name":"ok","meta":{"count":1}}"#).isEmpty)
            precondition(findings(#"{"name":"ok","meta":{"count":true}}"#).first!.status == .needsReview)
            precondition(findings(#"{"name":"ok"}"#).first!.ruleID == "api.response-contract")
            precondition(findings("not JSON").first!.ruleID == "api.response-contract")
            precondition(findings("", status: 404).isEmpty)
            precondition(findings("", status: 418).first!.evidence.contains("418"))
        case "swagger-response":
            let source = ##"{"swagger":"2.0","paths":{"/x":{"get":{"responses":{"2XX":{"schema":{"type":"array","items":{"$ref":"#/definitions/X"}}},"default":{"description":"other"}}}}},"definitions":{"X":{"type":"object","required":["n"],"properties":{"n":{"type":"number"}}}}}"##
            let result = try load(source)
            let e = result.responseExpectations[0]!
            func response(_ body: String, status: Int = 201) -> WebAuditResponse { WebAuditResponse(url: origin, status: status, headers: [:], body: Data(body.utf8), elapsed: 0) }
            precondition(NativeWebAuditAPI.responseViolations(response(#"[{"n":1.5}]"#), expectation: e).isEmpty)
            precondition(!NativeWebAuditAPI.responseViolations(response(#"[{"n":"wrong"}]"#), expectation: e).isEmpty)
            precondition(NativeWebAuditAPI.responseViolations(response("", status: 418), expectation: e).isEmpty)
        case "form":
            let source = ##"{"openapi":"3.0.3","paths":{"/items":{"post":{"requestBody":{"content":{"application/x-www-form-urlencoded":{"schema":{"type":"object","required":["name"],"properties":{"name":{"type":"string","minLength":2,"maxLength":4}}}}}},"responses":{"200":{"description":"ok"}}}}}}"##
            let readonly = try load(source)
            precondition(readonly.requests.isEmpty)
            let result = try load(source, writes: true)
            precondition(result.requests.count == 2)
            precondition(result.requests[0].headers["Content-Type"] == "application/x-www-form-urlencoded")
            precondition(String(decoding: result.requests[0].body!, as: UTF8.self) == "name=aaaa")
            precondition(String(decoding: result.requests[1].body!, as: UTF8.self) == "name=")
            precondition(result.invalidRequestIndices == Set([1]))
            precondition(result.responseExpectations[1] != nil)
        case "swagger-form":
            let source = ##"{"swagger":"2.0","consumes":["application/x-www-form-urlencoded"],"paths":{"/x":{"post":{"parameters":[{"in":"formData","name":"count","type":"integer","required":true}],"responses":{"200":{"description":"ok"}}}}}}"##
            let result = try load(source, writes: true)
            precondition(String(decoding: result.requests[0].body!, as: UTF8.self) == "count=1")
            precondition(String(decoding: result.requests[1].body!, as: UTF8.self) == "count=koda-invalid-type")
        case "unsupported-response":
            let source = ##"{"openapi":"3.0.3","paths":{"/x":{"get":{"responses":{"200":{"content":{"application/json":{"schema":{"oneOf":[{"type":"string"},{"type":"integer"}]}}}}}}}}}"##
            let result = try load(source)
            precondition(result.responseExpectations[0]!.schemas.isEmpty)
            precondition(result.warnings.contains { $0.contains("합성") })
        case "inactive":
            let transport = WebAuditTransport("ssti")
            let result = await NativeWebAuditRules.probe(url: URL(string:"https://local.invalid/?q=normal")!, transport: transport, active: false)
            precondition(result.observations.isEmpty)
            let count = await transport.calls
            precondition(count == 0)
        default:
            let transport = WebAuditTransport(selected)
            let result = await NativeWebAuditRules.probe(url: URL(string:"https://local.invalid/?q=normal")!, transport: transport, active: true)
            precondition(result.warnings.isEmpty)
            switch selected {
            case "ssti": precondition(result.observations.contains { $0.ruleID == "active.ssti" && $0.status == .vulnerable })
            case "crlf": precondition(result.observations.contains { $0.ruleID == "active.crlf" && $0.status == .vulnerable })
            case "redirect": precondition(result.observations.contains { $0.ruleID == "active.redirect" && $0.status == .vulnerable })
            case "sql": precondition(result.observations.contains { $0.ruleID == "active.sql-error" && $0.status == .needsReview })
            case "static-error": precondition(!result.observations.contains { $0.ruleID == "active.sql-error" })
            default:
                precondition(result.observations.contains { $0.ruleID == "active.reflection" && $0.status == .needsReview })
                precondition(!result.observations.contains { $0.status == .vulnerable })
            }
            let count = await transport.calls
            precondition(count == 8)
        }
        print("PASS \(selected)")
    }
}
'''

@unittest.skipUnless(shutil.which("swiftc"), "Swift compiler unavailable")
class NativeWebRulesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="koda-native-rules-")
        work = Path(cls.tmp.name)
        (work / "Main.swift").write_text(HARNESS)
        cls.binary = work / "verify"
        result = subprocess.run(["swiftc", "-parse-as-library", str(SOURCES / "NativeWebAuditModels.swift"), str(SOURCES / "NativeWebAuditRules.swift"), str(SOURCES / "NativeWebAuditAPI.swift"), str(work / "Main.swift"), "-o", str(cls.binary)], capture_output=True, text=True)
        if result.returncode: raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_rules_and_api_contracts(self):
        for case in ("passive", "api", "api-reject", "api-write", "swagger", "bounds", "api-500", "response-schema", "swagger-response", "form", "swagger-form", "unsupported-response", "inactive", "ssti", "crlf", "redirect", "sql", "static-error", "reflect"):
            with self.subTest(case=case):
                result = subprocess.run([str(self.binary), case], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("PASS", result.stdout)

if __name__ == "__main__":
    unittest.main()
