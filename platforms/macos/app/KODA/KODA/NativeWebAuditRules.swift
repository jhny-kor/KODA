import Foundation

/// Conservative signals: absence of a header is configuration evidence, never proof of exploitation.
enum NativeWebAuditRules {
    /// The runner must compare these responses with a random missing-path control before confirming.
    static let builtinRules: [WebAuditHTTPRule] = [
        WebAuditHTTPRule(id: "builtin.git-config", title: "Git 저장소 설정 노출", controlID: "web.information-disclosure", severity: "high", path: "/.git/config", bodyContains: ["[core]", "repositoryformatversion"], confirmed: true),
        WebAuditHTTPRule(id: "builtin.dotenv", title: "환경 설정 파일 노출", controlID: "web.information-disclosure", severity: "high", path: "/.env", bodyContains: ["APP_KEY=", "DB_PASSWORD="], confirmed: true),
        WebAuditHTTPRule(id: "builtin.debug-vars", title: "디버그 런타임 정보 노출", controlID: "web.information-disclosure", path: "/debug/vars", bodyContains: ["\"cmdline\":", "\"memstats\":"], confirmed: true)
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
        if html && response.status < 400 {
            if response.header("content-security-policy").isEmpty {
                add("passive.csp", "web.xss", "Content-Security-Policy 미관측", "HTML 응답에 CSP 헤더가 없습니다. XSS 발생을 입증하지 않습니다.")
            }
            if response.header("x-content-type-options").lowercased() != "nosniff" {
                add("passive.nosniff", "web.information-disclosure", "MIME 추측 방어 헤더 확인 필요", "X-Content-Type-Options: nosniff가 관측되지 않았습니다.")
            }
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
            add("passive.cors", "web.information-disclosure", "와일드카드 CORS 확인 필요", "Access-Control-Allow-Origin: * 관측. 공개 리소스 여부와 자격증명 정책을 확인하세요.")
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

    static func probe(url: URL, transport: WebAuditTransport, active: Bool) async -> (observations: [WebAuditObservation], warnings: [String]) {
        guard active else { return ([], []) }
        var output: [WebAuditObservation] = [], warnings: [String] = []
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false), let items = components.queryItems, !items.isEmpty else {
            return ([], ["능동 매개변수 검사는 기존 query parameter가 있는 URL에서만 수행합니다."])
        }
        let nonce = "koda" + UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(16)
        func send(_ index: Int, _ value: String) async throws -> WebAuditResponse {
            var changed = items; changed[index] = URLQueryItem(name: items[index].name, value: value)
            components.queryItems = changed
            guard let target = components.url else { throw WebAuditError.invalidProfile("query URL") }
            return try await transport.send(WebAuditRequest(url: target), actor: "primary")
        }
        func add(_ id: String, _ control: String, _ title: String, _ evidence: String, confirmed: Bool = false) {
            output.append(WebAuditObservation(ruleID: id, controlID: control, title: title, severity: "medium", status: confirmed ? .vulnerable : .needsReview, endpoint: url.absoluteString, evidence: evidence))
        }
        do {
            let baseline = try await transport.send(WebAuditRequest(url: url), actor: "primary")
            for index in items.indices.prefix(2) {
                let control = try await send(index, String(nonce))
                let reflection = "<koda-audit data-marker=\"\(nonce)\">"
                let xss = try await send(index, reflection)
                if xss.text.contains(reflection), !baseline.text.contains(reflection), !control.text.contains(reflection) {
                    add("active.reflection", "web.xss", "HTML 형태 입력 반사", "매개변수 \(items[index].name)에서 고유 입력이 인코딩 없이 반사되었습니다. 스크립트 실행은 검증하지 않았습니다.")
                }
                let sql = try await send(index, "\(nonce)'")
                let sqlPattern = #"(?i)(SQLSTATE\[[A-Z0-9]+\]|you have an error in your SQL syntax|unterminated quoted string|ORA-0[0-9]{4}|sqlite3?\.(OperationalError|DatabaseError))"#
                if matches(sql.text, sqlPattern), !matches(baseline.text, sqlPattern), !matches(control.text, sqlPattern) {
                    add("active.sql-error", "web.sql-injection", "SQL 오류 차등 반응", "매개변수 \(items[index].name)의 따옴표 입력에서만 DB 오류 형식을 관측했습니다. SQL 실행을 확정하지 않습니다.")
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
                    add("active.redirect", "web.process-validation", "외부 URL 리다이렉트", "외부 표식 URL이 Location에 그대로 반영되었습니다. 대상 URL로 이동하지 않았습니다.", confirmed: true)
                }
            }
        } catch { warnings.append("능동 검사 일부 중단: \(error.localizedDescription)") }
        return (output, warnings)
    }

    private static func matches(_ text: String, _ pattern: String) -> Bool {
        text.range(of: pattern, options: .regularExpression) != nil
    }
}
