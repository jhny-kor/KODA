import Foundation
import CryptoKit

enum WebAuditStatus: String, Codable, Sendable {
    case vulnerable = "VULNERABLE", pass = "PASS", needsReview = "NEEDS_REVIEW"
    case unsupported = "UNSUPPORTED", notApplicable = "NOT_APPLICABLE", notScanned = "NOT_SCANNED"
}

struct WebAuditLimits: Codable, Sendable {
    var maxRequests = 300
    var maxDuration: Double = 120
    var requestsPerSecond: Double = 5
    var requestTimeout: Double = 10
    var maxResponseBytes = 524_288
    var maxUploadBytes = 262_144
    var maxPages = 30
    var maxDepth = 3
}

struct WebAuditAccount: Codable, Sendable {
    var id: String
    var headers: [String: String] = [:]
}

struct WebAuditExpectation: Codable, Sendable {
    var statusCodes: [Int]
    var bodyContains: String? = nil
}

struct WebAuditResource: Codable, Sendable {
    var id: String
    var path: String
    var method = "GET"
    var controlID = "web.authorization"
    var expectations: [String: WebAuditExpectation] = [:]
}

struct WebAuditStep: Codable, Sendable {
    var path: String
    var method = "GET"
    var actor = "anonymous"
    var body: String? = nil
    var expectedStatusCodes: [Int] = [200]
    var bodyContains: String? = nil
}

struct WebAuditScenario: Codable, Sendable {
    var id: String
    var controlID = "web.process-validation"
    var steps: [WebAuditStep]
    var cleanup: [WebAuditStep] = []
}

/// Deliberately small, data-only HTTP rule format. This is not a Nuclei YAML interpreter.
struct WebAuditHTTPRule: Codable, Sendable {
    var id: String
    var title: String
    var controlID: String
    var severity = "medium"
    var path: String
    var statusCodes: [Int] = [200]
    var bodyContains: [String] = []
    var headerContains: [String: String] = [:]
    var confirmed = false
}

struct WebAuditProfile: Codable, Sendable {
    var schemaVersion = 1
    var target: String
    var authorized = false
    var active = false
    var allowStateChanges = false
    var includePaths = ["/"]
    var excludePaths = ["/logout", "/signout"]
    #if KODA_APP_STORE
    var allowedMethods = ["GET", "HEAD"]
    #else
    var allowedMethods = ["GET", "HEAD", "OPTIONS"]
    #endif
    var limits = WebAuditLimits()
    /// Credentials may use ${ENV:NAME}; exported reports never include these values.
    var headers: [String: String] = [:]
    var accounts: [WebAuditAccount] = []
    var resources: [WebAuditResource] = []
    var scenarios: [WebAuditScenario] = []
    var apiSpecPath: String? = nil
    var apiWriteCleanup: [WebAuditStep] = []
    var rules: [WebAuditHTTPRule] = []

    static func load(data: Data) throws -> WebAuditProfile {
        guard data.count <= 2_097_152,
              let input = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let target = input["target"] as? String else { throw WebAuditError.invalidProfile("target is required") }
        let encoder = JSONEncoder()
        let defaults = try JSONSerialization.jsonObject(with: encoder.encode(WebAuditProfile(target: target))) as! [String: Any]
        var merged = defaults.merging(input) { _, supplied in supplied }
        guard Set(input.keys).isSubset(of: Set(defaults.keys).union(["apiSpecPath"])) else {
            throw WebAuditError.invalidProfile("unknown profile field")
        }
        if let supplied = input["limits"] as? [String: Any], let base = defaults["limits"] as? [String: Any] {
            guard Set(supplied.keys).isSubset(of: Set(base.keys)) else { throw WebAuditError.invalidProfile("unknown limit") }
            merged["limits"] = base.merging(supplied) { _, value in value }
        }
        func record<T: Encodable>(_ value: Any, defaults: T, required: [String], extra: [String] = []) throws -> [String: Any] {
            guard let fields = value as? [String: Any], required.allSatisfy({ fields[$0] != nil }),
                  let base = try JSONSerialization.jsonObject(with: encoder.encode(defaults)) as? [String: Any],
                  Set(fields.keys).isSubset(of: Set(base.keys).union(extra)) else { throw WebAuditError.invalidProfile("invalid nested record") }
            return base.merging(fields) { _, supplied in supplied }
        }
        if let items = input["accounts"] as? [Any] {
            merged["accounts"] = try items.map { try record($0, defaults: WebAuditAccount(id: ""), required: ["id"]) }
        }
        if let items = input["resources"] as? [Any] {
            merged["resources"] = try items.map { item in
                var value = try record(item, defaults: WebAuditResource(id: "", path: ""), required: ["id", "path"])
                guard let expectations = value["expectations"] as? [String: Any] else { throw WebAuditError.invalidProfile("invalid expectations") }
                value["expectations"] = try expectations.mapValues {
                    try record($0, defaults: WebAuditExpectation(statusCodes: []), required: ["statusCodes"], extra: ["bodyContains"])
                }
                return value
            }
        }
        func steps(_ value: Any?) throws -> [[String: Any]] {
            guard let items = value as? [Any] else { throw WebAuditError.invalidProfile("steps must be an array") }
            return try items.map { try record($0, defaults: WebAuditStep(path: ""), required: ["path"], extra: ["body", "bodyContains"]) }
        }
        if let items = input["scenarios"] as? [Any] {
            merged["scenarios"] = try items.map { item in
                var value = try record(item, defaults: WebAuditScenario(id: "", steps: []), required: ["id", "steps"])
                value["steps"] = try steps(value["steps"]); value["cleanup"] = try steps(value["cleanup"])
                return value
            }
        }
        if input["apiWriteCleanup"] != nil { merged["apiWriteCleanup"] = try steps(input["apiWriteCleanup"]) }
        if let items = input["rules"] as? [Any] {
            merged["rules"] = try items.map { try record($0, defaults: WebAuditHTTPRule(id: "", title: "", controlID: "", path: ""), required: ["id", "title", "controlID", "path"]) }
        }
        return try JSONDecoder().decode(Self.self, from: JSONSerialization.data(withJSONObject: merged))
    }

    func encoded() throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }
}

struct WebAuditRequest: Sendable {
    var url: URL
    var method = "GET"
    var headers: [String: String] = [:]
    var body: Data? = nil
}

struct WebAuditResponse: Sendable {
    var url: URL
    var status: Int
    var headers: [String: String]
    var body: Data
    var elapsed: Double
    var text: String { String(decoding: body, as: UTF8.self) }
    func header(_ name: String) -> String { headers.first { $0.key.lowercased() == name.lowercased() }?.value ?? "" }
}

struct WebAuditMetrics: Codable, Sendable {
    var requests = 0
    var blocked = 0
    var receivedBytes = 0
    var elapsed: Double = 0
}

struct WebAuditObservation: Codable, Sendable, Hashable {
    var ruleID: String
    var controlID: String
    var title: String
    var severity = "medium"
    var status: WebAuditStatus = .needsReview
    var endpoint: String
    var method = "GET"
    var evidence: String
    var recommendation = "응답 증거와 서비스의 기대 동작을 확인하세요."
    var cwe: String = ""
    var evidenceID: String {
        String(SHA256.hash(data: Data("\(ruleID)|\(method)|\(endpoint)|\(evidence)".utf8)).map { String(format: "%02x", $0) }.joined().prefix(20))
    }
    func encode(to encoder: Encoder) throws {
        enum Key: String, CodingKey { case ruleID, controlID, title, severity, status, endpoint, method, evidence, recommendation, cwe, evidenceID }
        var box = encoder.container(keyedBy: Key.self)
        try box.encode(ruleID, forKey: .ruleID); try box.encode(controlID, forKey: .controlID)
        try box.encode(title, forKey: .title); try box.encode(severity, forKey: .severity)
        try box.encode(status, forKey: .status); try box.encode(endpoint, forKey: .endpoint)
        try box.encode(method, forKey: .method); try box.encode(evidence, forKey: .evidence)
        try box.encode(recommendation, forKey: .recommendation); try box.encode(cwe, forKey: .cwe)
        try box.encode(evidenceID, forKey: .evidenceID)
    }
}

struct WebAuditControlResult: Codable, Sendable {
    var controlID: String
    var title: String
    var status: WebAuditStatus
    var reason: String
    var evidenceIDs: [String] = []
}

struct WebAuditReport: Codable, Sendable {
    var schemaVersion = 1
    var engine = "koda-swift-web-audit"
    var engineVersion = "1.0"
    var generatedAt = Date()
    var target: String
    var profileHash: String
    var completed: Bool
    var metrics: WebAuditMetrics
    var observations: [WebAuditObservation]
    var controls: [WebAuditControlResult]
    var warnings: [String]
}

enum WebAuditError: Error, LocalizedError {
    case invalidProfile(String), blocked(String), budget(String), responseTooLarge, invalidResponse
    var errorDescription: String? {
        switch self {
        case .invalidProfile(let message): return "웹 프로필 오류: \(message)"
        case .blocked(let message): return "웹 요청 차단: \(message)"
        case .budget(let message): return "웹 점검 한도: \(message)"
        case .responseTooLarge: return "응답 크기 한도 초과"
        case .invalidResponse: return "HTTP 응답을 확인할 수 없습니다."
        }
    }
}

enum WebAuditCatalog {
    static let controls: [(String, String)] = [
        ("web.code-injection", "코드 삽입"), ("web.ssrf", "SSRF"), ("web.file-download", "파일 다운로드"),
        ("web.sql-injection", "SQL 삽입"), ("web.session-management", "세션 관리"),
        ("web.directory-indexing", "디렉터리 인덱싱"), ("web.password-policy", "비밀번호 정책"),
        ("web.plaintext-transmission", "평문 전송"), ("web.error-pages", "오류 페이지"),
        ("web.authentication", "인증"), ("web.cookie-tampering", "쿠키 변조"),
        ("web.information-disclosure", "정보 노출"), ("web.authorization", "권한 부여"),
        ("web.admin-exposure", "관리자 페이지 노출"), ("web.xss", "XSS"),
        ("web.password-recovery", "비밀번호 복구"), ("web.automated-attacks", "자동화 공격"),
        ("web.csrf", "CSRF"), ("web.process-validation", "절차 검증"),
        ("web.http-methods", "HTTP 메서드"), ("web.file-upload", "파일 업로드")
    ]
}
