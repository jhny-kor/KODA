import Foundation

/// Conservative signals: absence of a header is configuration evidence, never proof of exploitation.
enum NativeWebAuditRules {
    /// The runner must compare these responses with a random missing-path control before confirming.
    static let builtinRules: [WebAuditHTTPRule] = [
        WebAuditHTTPRule(id: "builtin.git-config", title: "Git 저장소 설정 노출", controlID: "web.information-disclosure", severity: "high", path: "/.git/config", bodyContains: ["[core]", "repositoryformatversion"], confirmed: true),
        WebAuditHTTPRule(id: "builtin.dotenv", title: "환경 설정 파일 노출", controlID: "web.information-disclosure", severity: "high", path: "/.env", bodyContains: ["APP_KEY=", "DB_PASSWORD="], confirmed: true),
        WebAuditHTTPRule(id: "builtin.debug-vars", title: "디버그 런타임 정보 노출", controlID: "web.information-disclosure", path: "/debug/vars", bodyContains: ["\"cmdline\":", "\"memstats\":"], confirmed: true),
        WebAuditHTTPRule(id: "builtin.git-head", title: "Git 저장소 HEAD 노출", controlID: "web.information-disclosure", severity: "high", path: "/.git/HEAD", bodyContains: ["ref: refs/"], confirmed: true),
        WebAuditHTTPRule(id: "builtin.aws-credentials", title: "AWS 자격증명 파일 노출", controlID: "web.information-disclosure", severity: "critical", path: "/.aws/credentials", bodyContains: ["aws_access_key_id"], confirmed: true),
        WebAuditHTTPRule(id: "builtin.npmrc", title: "npm 인증 설정 노출", controlID: "web.information-disclosure", severity: "high", path: "/.npmrc", bodyContains: ["_authToken"], confirmed: true),
        WebAuditHTTPRule(id: "builtin.actuator-env", title: "Spring Actuator 환경 정보 노출", controlID: "web.information-disclosure", severity: "high", path: "/actuator/env", bodyContains: ["propertySources"], confirmed: true),
        WebAuditHTTPRule(id: "builtin.server-status", title: "Apache 서버 상태 페이지 노출", controlID: "web.information-disclosure", path: "/server-status", bodyContains: ["Apache Server Status"], confirmed: true),
        WebAuditHTTPRule(id: "builtin.phpinfo", title: "phpinfo 페이지 노출", controlID: "web.information-disclosure", path: "/phpinfo.php", bodyContains: ["PHP Version", "phpinfo()"], confirmed: true),
        // An API description is often public by design: evidence for review, never a confirmed finding.
        WebAuditHTTPRule(id: "builtin.openapi", title: "API 명세 공개", controlID: "web.information-disclosure", severity: "low", path: "/openapi.json", bodyContains: ["\"openapi\"", "\"paths\""]),
        WebAuditHTTPRule(id: "builtin.swagger", title: "Swagger API 명세 공개", controlID: "web.information-disclosure", severity: "low", path: "/swagger.json", bodyContains: ["\"swagger\"", "\"paths\""])
    ]

    static func inspect(response: WebAuditResponse) -> [WebAuditObservation] {
        var output: [WebAuditObservation] = []
        func add(_ id: String, _ control: String, _ title: String, _ evidence: String, severity: String = "low", status: WebAuditStatus = .needsReview, cwe: String = "") {
            output.append(WebAuditObservation(ruleID: id, controlID: control, title: title, severity: severity, status: status, endpoint: response.url.absoluteString, evidence: evidence, cwe: cwe))
        }
        let html = response.header("content-type").lowercased().contains("text/html")
        if response.url.scheme == "http" {
            add("passive.http", "web.plaintext-transmission", "평문 HTTP 응답", "HTTP 응답을 관측했습니다. 민감정보 전달 여부를 확인하세요.")
        }
        // Page-protection headers matter on rendered pages, not on redirect hops.
        if html && (200..<300).contains(response.status) {
            if response.header("content-security-policy").isEmpty {
                add("passive.csp", "web.xss", "Content-Security-Policy 미관측", "HTML 응답에 CSP 헤더가 없습니다. XSS 발생을 입증하지 않습니다.")
            }
            if response.header("x-content-type-options").lowercased() != "nosniff" {
                add("passive.nosniff", "web.information-disclosure", "MIME 추측 방어 헤더 확인 필요", "X-Content-Type-Options: nosniff가 관측되지 않았습니다.")
            }
            if response.header("x-frame-options").isEmpty, !response.header("content-security-policy").lowercased().contains("frame-ancestors") {
                add("passive.frame-protection", "web.plaintext-transmission", "클릭재킹 방어 헤더 미관측", "X-Frame-Options 또는 CSP frame-ancestors가 관측되지 않았습니다.", cwe: "CWE-1021")
            }
        }
        let server = response.header("server")
        if server.contains(where: \.isNumber) {
            add("passive.server-version", "web.information-disclosure", "Server 헤더 버전 노출", "Server: \(server.prefix(120))", cwe: "CWE-200")
        }
        let poweredBy = response.header("x-powered-by")
        if !poweredBy.isEmpty {
            add("passive.x-powered-by", "web.information-disclosure", "X-Powered-By 기술 스택 노출", "X-Powered-By: \(poweredBy.prefix(120))", cwe: "CWE-200")
        }
        if response.url.scheme == "https", response.header("strict-transport-security").isEmpty {
            add("passive.hsts", "web.plaintext-transmission", "HSTS 미관측", "HTTPS 응답에 HSTS 헤더가 없습니다. 배포 경로와 정책을 확인하세요.")
        }
        let cookie = response.header("set-cookie")
        if !cookie.isEmpty {
            // Header dictionaries may combine cookies; report a review signal without guessing cookie boundaries.
            let lower = cookie.lowercased()
            if !lower.contains("httponly") || (response.url.scheme == "https" && !lower.contains("secure")) || !lower.contains("samesite=") {
                add("passive.cookie-flags", "web.session-management", "쿠키 보호 속성 확인 필요", "Set-Cookie 보호 속성이 일부 미관측되었습니다. 쿠키 값은 저장하지 않습니다.")
            }
        }
        if response.header("access-control-allow-origin") == "*" {
            if response.header("access-control-allow-credentials").lowercased() == "true" {
                add("passive.cors-credentials", "web.authorization", "와일드카드 CORS와 자격증명 동시 허용", "Access-Control-Allow-Origin: *와 Allow-Credentials: true가 함께 관측되었습니다.", severity: "high", cwe: "CWE-942")
            } else {
                add("passive.cors", "web.information-disclosure", "와일드카드 CORS 확인 필요", "Access-Control-Allow-Origin: * 관측. 공개 리소스 여부와 자격증명 정책을 확인하세요.")
            }
        }
        if matches(response.text, #"(?i)(Traceback \(most recent call last\)|Fatal error:|java\.lang\.[A-Za-z]+Exception|SQLSTATE\[[A-Z0-9]+\])"#) {
            add("passive.error-detail", "web.error-pages", "상세 오류 문자열 노출 가능성", "응답에 스택 또는 데이터베이스 오류 형식이 있습니다. 실제 오류 화면인지 확인하세요.", severity: "medium")
        }
        if html && matches(response.text, #"(?is)<title>\s*Index of /[^<]*</title>"#) && matches(response.text, #"(?i)(Parent Directory|\?C=N;O=D)"#) {
            add("passive.directory-index", "web.directory-indexing", "디렉터리 목록 형식 관측", "Index of 제목 및 디렉터리 목록 링크 형식이 함께 관측되었습니다.", severity: "medium")
        }
        // JWTs may be samples or public data. Only decode bounded header candidates; never retain tokens.
        let tokenPattern = #"eyJ[A-Za-z0-9_-]{1,1024}\.[A-Za-z0-9_-]{1,4096}\.([A-Za-z0-9_-]{0,4096})"#
        if let regex = try? NSRegularExpression(pattern: tokenPattern) {
            let text = String(response.text.prefix(65_536))
            for match in regex.matches(in: text, range: NSRange(text.startIndex..., in: text)).prefix(8) {
                guard let range = Range(match.range, in: text), let first = text[range].split(separator: ".", omittingEmptySubsequences: false).first else { continue }
                var header = String(first).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
                header += String(repeating: "=", count: (4 - header.count % 4) % 4)
                if let data = Data(base64Encoded: header), let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any], (object["alg"] as? String)?.lowercased() == "none" {
                    add("passive.jwt-none", "web.session-management", "서명 없는 JWT 형식 확인 필요", "alg=none인 JWT 형식이 응답에 있습니다. 서버의 수락 여부는 검증하지 않았습니다.", severity: "medium")
                    break
                }
            }
        }
        return output
    }

    static func inspectAPI(response: WebAuditResponse, isNegative: Bool = false, expectation: WebAuditAPIResponseExpectation? = nil) -> [WebAuditObservation] {
        var output: [WebAuditObservation] = []
        if isNegative, (200..<300).contains(response.status) {
            output.append(WebAuditObservation(ruleID: "api.invalid-input-accepted", controlID: "web.process-validation", title: "API 경계 밖 입력에 정상 응답", severity: "low", status: .needsReview, endpoint: response.url.absoluteString, evidence: "정의된 입력 제약을 위반한 표본에 HTTP \(response.status) 응답을 관측했습니다. 서버 정규화/선택 필드 정책과 비교해야 하며 보안 취약점으로 확정하지 않습니다."))
        }
        if response.status >= 500 {
            output.append(WebAuditObservation(ruleID: "api.server-error", controlID: "web.error-pages", title: "API 입력에 서버 오류 응답", severity: "low", status: .needsReview, endpoint: response.url.absoluteString, evidence: "HTTP \(response.status). 견고성 신호이며 보안 취약점으로 확정하지 않습니다."))
        }
        if let expectation {
            let violations = NativeWebAuditAPI.responseViolations(response, expectation: expectation)
            if !violations.isEmpty {
                output.append(WebAuditObservation(ruleID: "api.response-contract", controlID: "web.process-validation", title: "API 응답 계약 확인 필요", severity: "low", status: .needsReview, endpoint: response.url.absoluteString, evidence: violations.joined(separator: "; ") + ". 제한된 required/type/상태 검사 결과이며 보안 취약점으로 확정하지 않습니다."))
            }
        }
        return output
    }

    /// One request shape to fuzz: GET fields travel in the query, POST fields in a form body.
    struct ProbeTarget: Sendable {
        var url: URL
        var method = "GET"
        var fields: [URLQueryItem]
        var testable: [Int]
        var source: String
        /// Recorded per-request headers (e.g. X-CSRF-Token) and, for JSON APIs, the original body to vary.
        var headers: [String: String] = [:]
        var jsonTemplate: Data? = nil
        /// Same path, method and fuzzed names are probed once per audit.
        var signature: String {
            "\(method) \(url.path) " + testable.map { fields[$0].name }.sorted().joined(separator: ",")
        }
    }

    /// Existing query parameters, first three fuzzed.
    static func queryTarget(_ url: URL) -> ProbeTarget? {
        guard let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems, !items.isEmpty else { return nil }
        return ProbeTarget(url: url, fields: items, testable: Array(items.indices.prefix(3)), source: "query")
    }

    /// Fields of HTML forms. Login (password) and upload (file) forms are never submitted.
    static func formTargets(html: String, page: URL) -> [ProbeTarget] {
        let attr = { (tag: String, name: String) -> String? in
            guard let regex = try? NSRegularExpression(pattern: "(?i)\\b\(name)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))"),
                  let match = regex.firstMatch(in: tag, range: NSRange(tag.startIndex..., in: tag)) else { return nil }
            for group in 1...3 { if let range = Range(match.range(at: group), in: tag) { return String(tag[range]) } }
            return nil
        }
        guard let formRegex = try? NSRegularExpression(pattern: "(?is)<form\\b([^>]*)>(.*?)</form>"),
              let fieldRegex = try? NSRegularExpression(pattern: "(?i)<(input|textarea|select)\\b[^>]*>") else { return [] }
        var output: [ProbeTarget] = []
        for form in formRegex.matches(in: html, range: NSRange(html.startIndex..., in: html)).prefix(5) {
            guard let headRange = Range(form.range(at: 1), in: html), let bodyRange = Range(form.range(at: 2), in: html) else { continue }
            let head = String(html[headRange]), body = String(html[bodyRange])
            let action = attr(head, "action").map { $0.replacingOccurrences(of: "&amp;", with: "&") } ?? ""
            guard let resolved = URL(string: action, relativeTo: page)?.absoluteURL,
                  var parts = URLComponents(url: resolved, resolvingAgainstBaseURL: false) else { continue }
            let existing = parts.queryItems ?? []
            parts.query = nil; parts.fragment = nil
            guard let endpoint = parts.url else { continue }
            var fields: [URLQueryItem] = [], testable: [Int] = [], skip = false
            for match in fieldRegex.matches(in: body, range: NSRange(body.startIndex..., in: body)) {
                guard let range = Range(match.range, in: body) else { continue }
                let tag = String(body[range])
                let type = (attr(tag, "type") ?? (tag.lowercased().hasPrefix("<textarea") ? "textarea" : "text")).lowercased()
                if ["password", "file"].contains(type) { skip = true; break }
                guard let name = attr(tag, "name"), !name.isEmpty,
                      !["submit", "button", "image", "reset"].contains(type) else { continue }
                if ["text", "search", "email", "url", "textarea", "tel", ""].contains(type) { testable.append(fields.count) }
                let value = attr(tag, "value") ?? ""
                fields.append(URLQueryItem(name: name, value: value.isEmpty ? "test" : value))
            }
            guard !skip, !testable.isEmpty else { continue }
            let method = (attr(head, "method") ?? "get").uppercased() == "POST" ? "POST" : "GET"
            if method == "GET" { fields = existing + fields; testable = testable.map { $0 + existing.count } }
            output.append(ProbeTarget(url: endpoint, method: method, fields: fields, testable: Array(testable.prefix(3)), source: "form"))
        }
        return output
    }

    private static let commonParams = ["id", "q", "query", "search", "s", "keyword", "page", "name", "user", "email",
        "url", "redirect", "next", "return", "callback", "file", "path", "template", "view", "lang", "debug",
        "format", "sort", "filter", "category", "type"]

    /// Query names the page reflects although no link exposed them: one request, one marker per name.
    static func discoverParameters(page: URL, html: String, transport: WebAuditTransport) async throws -> ProbeTarget? {
        guard var parts = URLComponents(url: page, resolvingAgainstBaseURL: false) else { return nil }
        let existing = parts.queryItems ?? []
        var mined: [String] = []
        for pattern in [#"[?&]([A-Za-z_][\w-]{0,30})="#, #"searchParams\s*\.\s*get\(\s*["']([A-Za-z_][\w-]{0,30})["']"#] {
            guard let regex = try? NSRegularExpression(pattern: pattern) else { continue }
            for match in regex.matches(in: html, range: NSRange(html.startIndex..., in: html)) {
                if let range = Range(match.range(at: 1), in: html) { mined.append(String(html[range])) }
            }
        }
        var seen = Set(existing.map(\.name))
        let names = (mined + commonParams).filter { seen.insert($0).inserted }.prefix(30)
        guard !names.isEmpty else { return nil }
        let token = UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(6).lowercased()
        let markers = names.enumerated().map { URLQueryItem(name: $0.element, value: "kd\(token)\($0.offset)z") }
        parts.percentEncodedQuery = formEncode(existing + markers)
        guard let url = parts.url else { return nil }
        let text = try await transport.send(WebAuditRequest(url: url), actor: "primary").text
        let found = markers.filter { text.contains($0.value ?? "\u{0}") }.prefix(3).map { URLQueryItem(name: $0.name, value: "1") }
        guard !found.isEmpty else { return nil }
        return ProbeTarget(url: page, fields: existing + found, testable: Array(existing.count..<(existing.count + found.count)), source: "discovered")
    }

    /// Strict application/x-www-form-urlencoded: payload characters such as & = + ' never change field boundaries.
    static func formEncode(_ items: [URLQueryItem]) -> String {
        var allowed = CharacterSet.alphanumerics; allowed.insert(charactersIn: "-._~")
        func encode(_ value: String) -> String { value.addingPercentEncoding(withAllowedCharacters: allowed) ?? "" }
        return items.map { encode($0.name) + "=" + encode($0.value ?? "") }.joined(separator: "&")
    }

    /// One unauthenticated request with a foreign Origin; reflection plus credentials lets any site read the response.
    static func probeCORS(url: URL, transport: WebAuditTransport) async throws -> [WebAuditObservation] {
        let origin = "https://koda-cors-probe.example"
        let response = try await transport.send(WebAuditRequest(url: url, headers: ["Origin": origin]), actor: "anonymous")
        guard response.header("access-control-allow-origin") == origin else { return [] }
        let credentials = response.header("access-control-allow-credentials").lowercased() == "true"
        return [WebAuditObservation(ruleID: credentials ? "active.cors-reflection-credentials" : "active.cors-reflection",
            controlID: "web.authorization", title: credentials ? "임의 Origin 반사 + 자격증명 허용 CORS" : "임의 Origin 반사 CORS",
            severity: credentials ? "high" : "medium", status: credentials ? .vulnerable : .needsReview, endpoint: url.absoluteString,
            evidence: "Origin: \(origin) 요청에 Access-Control-Allow-Origin이 그대로 반사되었습니다" + (credentials ? " (Allow-Credentials: true)." : "."),
            recommendation: "Origin을 엄격한 허용 목록과 비교하고, 자격증명을 허용할 때 요청 Origin을 그대로 반사하지 마세요.", cwe: "CWE-942")]
    }

    /// Normalized-content equivalence for boolean comparisons; token multiset Dice coefficient >= 0.9.
    static func equivalent(_ a: String, _ b: String) -> Bool {
        func tokens(_ text: String) -> [Substring: Int] {
            let cleaned = text.replacingOccurrences(of: #"(?i)<input[^>]*\b(csrf|xsrf|token|nonce)[^>]*>|\b[A-Fa-f0-9]{24,}\b|\b[A-Za-z0-9+/_-]{32,}={0,2}"#, with: "", options: .regularExpression).lowercased()
            return cleaned.split(whereSeparator: { !$0.isLetter && !$0.isNumber }).reduce(into: [:]) { $0[$1, default: 0] += 1 }
        }
        let x = tokens(a), y = tokens(b)
        if x == y { return true }
        let total = x.values.reduce(0, +) + y.values.reduce(0, +)
        guard total > 0 else { return true }
        let shared = x.reduce(0) { $0 + min($1.value, y[$1.key] ?? 0) }
        return Double(2 * shared) / Double(total) >= 0.9
    }

    static func probe(_ target: ProbeTarget, transport: WebAuditTransport) async -> (observations: [WebAuditObservation], warnings: [String]) {
        var output: [WebAuditObservation] = [], warnings: [String] = []
        let items = target.fields
        let nonce = "koda" + UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(16)
        func request(_ fields: [URLQueryItem]) throws -> WebAuditRequest {
            if target.method == "POST" {
                if let template = target.jsonTemplate, var object = try JSONSerialization.jsonObject(with: template) as? [String: Any] {
                    for field in fields { object[field.name] = field.value ?? "" }
                    return WebAuditRequest(url: target.url, method: "POST", headers: target.headers.merging(["Content-Type": "application/json"]) { $1 },
                                           body: try JSONSerialization.data(withJSONObject: object))
                }
                return WebAuditRequest(url: target.url, method: "POST", headers: target.headers.merging(["Content-Type": "application/x-www-form-urlencoded"]) { $1 },
                                       body: Data(formEncode(fields).utf8))
            }
            guard var parts = URLComponents(url: target.url, resolvingAgainstBaseURL: false) else { throw WebAuditError.invalidProfile("query URL") }
            parts.percentEncodedQuery = formEncode(fields)
            guard let url = parts.url else { throw WebAuditError.invalidProfile("query URL") }
            return WebAuditRequest(url: url, headers: target.headers)
        }
        func send(_ index: Int, _ value: String) async throws -> WebAuditResponse {
            var changed = items; changed[index] = URLQueryItem(name: items[index].name, value: value)
            return try await transport.send(request(changed), actor: "primary")
        }
        let endpoint = target.method == "POST" ? target.url.absoluteString : ((try? request(items))?.url.absoluteString ?? target.url.absoluteString)
        func add(_ id: String, _ control: String, _ title: String, _ evidence: String, confirmed: Bool = false, severity: String = "medium", cwe: String = "") {
            output.append(WebAuditObservation(ruleID: id, controlID: control, title: title, severity: severity, status: confirmed ? .vulnerable : .needsReview, endpoint: endpoint, method: target.method, evidence: evidence, cwe: cwe))
        }
        do {
            let baseline = try await transport.send(request(items), actor: "primary")
            for index in target.testable {
                let field = "\(["form": "폼 필드", "har": "HAR 요청 필드"][target.source] ?? "매개변수") \(items[index].name)"
                let original = items[index].value ?? ""
                let control = try await send(index, String(nonce))
                let reflection = "<koda-audit data-marker=\"\(nonce)\">"
                let xss = try await send(index, reflection)
                if xss.text.contains(reflection), !baseline.text.contains(reflection), !control.text.contains(reflection) {
                    add("active.reflection", "web.xss", "HTML 형태 입력 반사", "\(field)에서 고유 입력이 인코딩 없이 반사되었습니다. 스크립트 실행은 검증하지 않았습니다.")
                }
                let sql = try await send(index, "\(nonce)'")
                let sqlPattern = #"(?i)(SQLSTATE\[[A-Z0-9]+\]|you have an error in your SQL syntax|unterminated quoted string|quoted string not properly terminated|Unclosed quotation mark|syntax error at or near|ORA-0[0-9]{4}|PG::SyntaxError|SQLite3::|sqlite3?\.(OperationalError|DatabaseError)|Microsoft OLE DB Provider|ODBC SQL Server Driver)"#
                if matches(sql.text, sqlPattern), !matches(baseline.text, sqlPattern), !matches(control.text, sqlPattern) {
                    add("active.sql-error", "web.sql-injection", "SQL 오류 차등 반응", "\(field)의 따옴표 입력에서만 DB 오류 형식을 관측했습니다. SQL 실행을 확정하지 않습니다.", cwe: "CWE-89")
                } else if equivalent(baseline.text, try await send(index, original).text) {
                    // Boolean blind: the true condition keeps the stable page, the false one changes it, and the change reproduces.
                    func stripped(_ text: String, _ value: String) -> String {
                        [value, value.replacingOccurrences(of: "'", with: "&#39;"), value.replacingOccurrences(of: "'", with: "&#x27;")]
                            .reduce(text) { $0.replacingOccurrences(of: $1, with: "") }
                    }
                    for (yes, no) in [("' AND '1'='1", "' AND '1'='2"), (" AND 1=1", " AND 1=2"), ("' AND 1=1-- -", "' AND 1=2-- -")] {
                        let truthy = try await send(index, original + yes)
                        guard equivalent(stripped(truthy.text, original + yes), baseline.text) else { continue }
                        let falsy = try await send(index, original + no)
                        guard !equivalent(stripped(falsy.text, original + no), baseline.text) else { continue }
                        let repeated = try await send(index, original + no)
                        if !equivalent(stripped(repeated.text, original + no), baseline.text) {
                            add("active.sql-boolean-blind", "web.sql-injection", "참/거짓 조건에 따른 응답 차이(Blind SQL 삽입)",
                                "\(field): '\(yes.trimmingCharacters(in: .whitespaces))'는 정상 응답을 유지하고 '\(no.trimmingCharacters(in: .whitespaces))'는 응답을 바꿨습니다(재현 확인).",
                                confirmed: true, severity: "high", cwe: "CWE-89")
                            break
                        }
                    }
                }
                let lfiPattern = #"root:[^:\n]*:0:0:|\bfor 16-bit app support\b"#
                let lfi = try await send(index, "../../../../../../../../etc/passwd")
                if matches(lfi.text, lfiPattern), !matches(baseline.text, lfiPattern), !matches(control.text, lfiPattern) {
                    add("active.path-traversal", "web.file-download", "경로 조작으로 시스템 파일 노출",
                        "\(field)의 상위 경로 입력에 /etc/passwd 형식 내용이 응답되었습니다. 내용은 저장하지 않았습니다.", confirmed: true, severity: "high", cwe: "CWE-22")
                }
                let first = try await send(index, "\(nonce){{713*719}}\(nonce)")
                let second = try await send(index, "\(nonce){{727*733}}\(nonce)")
                let firstResult = "\(nonce)\(713*719)\(nonce)", secondResult = "\(nonce)\(727*733)\(nonce)"
                if first.text.contains(firstResult), second.text.contains(secondResult),
                   !baseline.text.contains(firstResult), !baseline.text.contains(secondResult),
                   !control.text.contains(firstResult), !control.text.contains(secondResult) {
                    add("active.ssti", "web.code-injection", "템플릿 산술식 평가", "서로 다른 두 산술식의 계산 결과가 고유 경계 표식과 함께 관측되고 정상 대조 응답에는 없습니다.", confirmed: true)
                }
                let crlf = try await send(index, "\r\nX-Koda-Audit: \(nonce)")
                if crlf.header("x-koda-audit") == nonce, baseline.header("x-koda-audit").isEmpty, control.header("x-koda-audit").isEmpty {
                    add("active.crlf", "web.information-disclosure", "응답 헤더 삽입", "CRLF 입력의 고유 X-Koda-Audit 표식이 응답 헤더로 분리되었습니다.", confirmed: true)
                }
                let destination = "https://example.invalid/\(nonce)"
                let redirect = try await send(index, destination)
                if (300..<400).contains(redirect.status), redirect.header("location") == destination,
                   baseline.header("location") != destination, control.header("location") != destination {
                    add("active.redirect", "web.process-validation", "외부 URL 리다이렉트", "\(field): 외부 표식 URL이 Location에 그대로 반영되었습니다. 대상 URL로 이동하지 않았습니다.", confirmed: true)
                }
            }
        } catch { warnings.append("능동 검사 일부 중단: \(error.localizedDescription)") }
        return (output, warnings)
    }

    private static func matches(_ text: String, _ pattern: String) -> Bool {
        text.range(of: pattern, options: .regularExpression) != nil
    }
}
