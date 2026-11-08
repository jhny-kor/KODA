import Foundation
import CryptoKit

/// Native macOS audit coordinator. Every network operation goes through one budgeted transport.
enum NativeWebAuditor {
    static func run(profile: WebAuditProfile, apiSpecData: Data? = nil,
                    progress: (@Sendable (String) -> Void)? = nil) async throws -> WebAuditReport {
        let transport = try WebAuditTransport(profile: profile)
        var observations: [WebAuditObservation] = []
        var warnings: [String] = []
        var passed = Set<String>()
        var completed = true
        var queue: [(URL, Int)] = []
        var visited = Set<String>()
        guard let base = URL(string: profile.target) else { throw WebAuditError.invalidProfile("invalid URL") }
        queue.append((base, 0))
        let redactor = WebAuditRedactor(profile: profile)
        let profileHash = SHA256.hash(data: try profile.encoded()).map { String(format: "%02x", $0) }.joined()

        func note(_ error: Error, context: String) {
            completed = false
            // Transport errors may contain URLs or credentials supplied by an untrusted target.
            warnings.append(redactor.clean("\(context): \(error.localizedDescription)"))
        }

        // A matched HTTP response is evidence, never proof that an entire control is safe.
        while !queue.isEmpty && visited.count < profile.limits.maxPages {
            if Task.isCancelled { completed = false; warnings.append("점검이 취소되었습니다."); break }
            let (url, depth) = queue.removeFirst()
            guard visited.insert(url.absoluteString).inserted else { continue }
            progress?("웹 경로 점검 \(visited.count): \(redactor.clean(url.absoluteString))")
            do {
                let response = try await transport.send(WebAuditRequest(url: url), actor: "primary")
                observations += NativeWebAuditRules.inspect(response: response)
                if profile.active {
                    let result = await NativeWebAuditRules.probe(url: url, transport: transport, active: true)
                    observations += result.observations
                    if !result.warnings.isEmpty { completed = false; warnings += result.warnings }
                }
                if response.header("content-type").lowercased().contains("html") {
                    let discovered = links(in: response.text, relativeTo: url).filter { withinScope($0, profile: profile) && !visited.contains($0.absoluteString) }
                    if depth < profile.limits.maxDepth {
                        for link in discovered {
                            if queue.count < profile.limits.maxPages * 4 { queue.append((link, depth + 1)) }
                            else { completed = false; warnings.append("발견 경로 대기열 한도에 도달했습니다."); break }
                        }
                    } else if !discovered.isEmpty {
                        completed = false; warnings.append("크롤 깊이 한도로 일부 발견 경로를 점검하지 못했습니다.")
                    }
                }
            } catch { note(error, context: "경로 점검 중단"); break }
        }
        if !queue.isEmpty { completed = false; warnings.append("페이지·깊이 한도로 일부 발견 경로를 점검하지 못했습니다.") }

        if !Task.isCancelled {
            // Reviewed data-only rules. A randomized control prevents SPA fallback/soft-404 matches.
            let rules = NativeWebAuditRules.builtinRules.map { (true, $0) } + profile.rules.map { (false, $0) }
            for (isBuiltin, rule) in rules {
                do {
                    guard let url = URL(string: rule.path, relativeTo: base)?.absoluteURL else {
                        throw WebAuditError.invalidProfile("rule path")
                    }
                    if isBuiltin && !withinScope(url, profile: profile) { continue }
                    let response = try await transport.send(WebAuditRequest(url: url), actor: "primary")
                    guard matches(rule, response) else { continue }
                    var differentiated = false
                    if isBuiltin {
                        let controlURL = url.deletingLastPathComponent().appendingPathComponent("koda-missing-\(UUID().uuidString)")
                        do {
                            let control = try await transport.send(WebAuditRequest(url: controlURL), actor: "primary")
                            differentiated = !matches(rule, control) && response.body != control.body
                        } catch { note(error, context: "노출 규칙 대조 요청 미완료") }
                    }
                    observations.append(WebAuditObservation(ruleID: rule.id, controlID: rule.controlID,
                        title: rule.title, severity: rule.severity,
                        status: isBuiltin && rule.confirmed && differentiated ? .vulnerable : .needsReview,
                        endpoint: url.absoluteString,
                        evidence: "HTTP \(response.status); rule \(rule.id); negative control \(differentiated ? "different" : "not differentiated"); SHA256 \(digest(response.body))"))
                } catch { note(error, context: "규칙 점검 중단"); break }
            }
        }

        if let apiSpecData, !Task.isCancelled {
            progress?("OpenAPI 입력 검사")
            do {
                let allowWrites = profile.active && profile.allowStateChanges && !profile.apiWriteCleanup.isEmpty
                let plan = try NativeWebAuditAPI.load(data: apiSpecData, baseURL: base, allowedStateChanges: allowWrites)
                warnings += plan.warnings
                if !plan.warnings.isEmpty { completed = false }
                for (index, request) in plan.requests.enumerated() {
                    if !profile.active && plan.invalidRequestIndices.contains(index) { continue }
                    do {
                        let response = try await transport.send(request, actor: "primary")
                        observations += NativeWebAuditRules.inspect(response: response)
                        observations += NativeWebAuditRules.inspectAPI(response: response,
                            isNegative: plan.invalidRequestIndices.contains(index), expectation: plan.responseExpectations[index])
                    } catch { note(error, context: "API 검사 중단"); break }
                }
                if allowWrites {
                    for step in profile.apiWriteCleanup {
                        do {
                            let response = try await executeCleanup(step, base: base, transport: transport)
                            if !satisfies(step, response) { completed = false; warnings.append("API 테스트 데이터 정리 응답 검증 실패") }
                        }
                        catch { note(error, context: "API 테스트 데이터 정리 미완료") }
                    }
                }
            } catch { note(error, context: "API 명세를 검사하지 못했습니다") }
        }

        // Account x resource matrix with explicit status/body oracles, including expected denials.
        for resource in profile.resources {
            if Task.isCancelled { completed = false; break }
            var allMatched = !resource.expectations.isEmpty
            var resourceObservations: [WebAuditObservation] = []
            for actor in resource.expectations.keys.sorted() {
                guard let expectation = resource.expectations[actor],
                      let url = URL(string: resource.path, relativeTo: base)?.absoluteURL else { continue }
                do {
                    let response = try await transport.send(WebAuditRequest(url: url, method: resource.method), actor: actor)
                    let matched = expectation.statusCodes.contains(response.status) &&
                        (expectation.bodyContains.map { response.text.contains($0) } ?? true)
                    allMatched = allMatched && matched
                    if !matched {
                        let deniedExpected = !expectation.statusCodes.isEmpty && expectation.statusCodes.allSatisfy { [401, 403, 404].contains($0) }
                        // A login page may return 200. Require a declared protected-content marker
                        // from an allowed actor before treating a denied actor's response as proof.
                        let protectedMarkers = resource.expectations.values.filter {
                            $0.statusCodes.contains(where: { (200..<300).contains($0) })
                        }.compactMap(\.bodyContains).filter { !$0.isEmpty }
                        let unauthorizedSuccess = deniedExpected && (200..<300).contains(response.status) &&
                            protectedMarkers.contains(where: { response.text.contains($0) })
                        resourceObservations.append(WebAuditObservation(ruleID: "web.matrix.\(resource.id)",
                            controlID: resource.controlID, title: "계정별 접근 기대 결과 불일치", severity: "high",
                            status: unauthorizedSuccess ? .vulnerable : .needsReview, endpoint: url.absoluteString,
                            method: resource.method, evidence: "actor=\(actor), expected=\(expectation.statusCodes), actual=\(response.status); explicit oracle"))
                    }
                } catch { allMatched = false; note(error, context: "권한 행렬 미점검 \(resource.id)/\(actor)") }
            }
            observations += resourceObservations
            if allMatched { passed.insert(resource.controlID) }
        }

        for scenario in profile.scenarios {
            if Task.isCancelled { completed = false; break }
            progress?("시나리오: \(scenario.id)")
            var matched = !scenario.steps.isEmpty
            let stateChanging = scenario.steps.contains { !["GET", "HEAD", "OPTIONS"].contains($0.method.uppercased()) }
            if stateChanging && (!profile.active || !profile.allowStateChanges || scenario.cleanup.isEmpty) {
                completed = false; warnings.append("\(scenario.id): 상태 변경 승인 또는 정리 절차가 없어 실행하지 않았습니다."); continue
            }
            for step in scenario.steps {
                do {
                    let response = try await execute(step, base: base, transport: transport)
                    if !satisfies(step, response) {
                        matched = false
                        observations.append(WebAuditObservation(ruleID: "web.scenario.\(scenario.id)", controlID: scenario.controlID,
                            title: "업무 시나리오 기대 결과 불일치", endpoint: response.url.absoluteString, method: step.method,
                            evidence: "scenario=\(scenario.id), actor=\(step.actor), expected=\(step.expectedStatusCodes), actual=\(response.status)"))
                    }
                } catch { matched = false; note(error, context: "시나리오 중단 \(scenario.id)"); break }
            }
            for step in scenario.cleanup {
                do {
                    let response = try await executeCleanup(step, base: base, transport: transport)
                    if !satisfies(step, response) { matched = false; completed = false; warnings.append("\(scenario.id): 정리 응답 검증 실패") }
                } catch { matched = false; note(error, context: "테스트 데이터 정리 미완료 \(scenario.id)") }
            }
            if matched { passed.insert(scenario.controlID) }
        }
        if Task.isCancelled { completed = false; warnings.append("취소 후 미실행 항목은 안전 판정에 포함하지 않습니다.") }
        let metrics = await transport.snapshot()
        await transport.shutdown()
        observations = Array(Set(observations.map { redactor.clean($0) })).sorted {
            ($0.controlID, $0.ruleID, $0.endpoint) < ($1.controlID, $1.ruleID, $1.endpoint)
        }
        let controls = WebAuditCatalog.controls.map { id, title -> WebAuditControlResult in
            let related = observations.filter { $0.controlID == id }
            let status: WebAuditStatus
            let reason: String
            if related.contains(where: { $0.status == .vulnerable }) { status = .vulnerable; reason = "응답·대조 또는 명시적 권한 oracle에서 취약 증거 확인" }
            else if !related.isEmpty { status = .needsReview; reason = "자동 탐지 후보의 실제 보안 영향을 확인해야 합니다." }
            else if passed.contains(id) { status = completed ? .pass : .needsReview; reason = completed ? "선언한 시나리오·기대 응답만 검증 완료. 항목 전체의 안전을 보장하지 않습니다." : "실행 공백이 있어 완료 판정 보류" }
            else { status = .notScanned; reason = "이 항목을 판정할 명시적 시나리오·충분한 증거가 없습니다." }
            return WebAuditControlResult(controlID: id, title: title, status: status, reason: reason, evidenceIDs: related.map(\.evidenceID))
        }
        return WebAuditReport(target: redactor.clean(profile.target), profileHash: profileHash, completed: completed,
                              metrics: metrics, observations: observations, controls: controls,
                              warnings: Array(Set(warnings.map { redactor.clean($0) })).sorted())
    }

    private static func execute(_ step: WebAuditStep, base: URL, transport: WebAuditTransport) async throws -> WebAuditResponse {
        guard let url = URL(string: step.path, relativeTo: base)?.absoluteURL else { throw WebAuditError.invalidProfile("step path") }
        return try await transport.send(WebAuditRequest(url: url, method: step.method,
            headers: step.body == nil ? [:] : ["Content-Type": "application/json"], body: step.body.map { Data($0.utf8) }), actor: step.actor)
    }
    private static func executeCleanup(_ step: WebAuditStep, base: URL, transport: WebAuditTransport) async throws -> WebAuditResponse {
        guard let url = URL(string: step.path, relativeTo: base)?.absoluteURL else { throw WebAuditError.invalidProfile("cleanup path") }
        let request = WebAuditRequest(url: url, method: step.method,
            headers: step.body == nil ? [:] : ["Content-Type": "application/json"], body: step.body.map { Data($0.utf8) })
        // Cleanup has reserved request/time budgets and remains bounded after operator cancellation.
        return try await Task.detached { try await transport.sendCleanup(request, actor: step.actor) }.value
    }
    private static func satisfies(_ step: WebAuditStep, _ response: WebAuditResponse) -> Bool {
        step.expectedStatusCodes.contains(response.status) && (step.bodyContains.map { response.text.contains($0) } ?? true)
    }
    private static func matches(_ rule: WebAuditHTTPRule, _ response: WebAuditResponse) -> Bool {
        !rule.bodyContains.isEmpty || !rule.headerContains.isEmpty ?
            rule.statusCodes.contains(response.status) && rule.bodyContains.allSatisfy { response.text.contains($0) } &&
            rule.headerContains.allSatisfy { response.header($0.key).lowercased().contains($0.value.lowercased()) } : false
    }
    private static func links(in html: String, relativeTo base: URL) -> [URL] {
        guard let regex = try? NSRegularExpression(pattern: "(?i)(?:href|src)\\s*=\\s*[\"']([^\"'#]+)[\"']") else { return [] }
        return regex.matches(in: html, range: NSRange(html.startIndex..., in: html)).compactMap { match in
            guard let range = Range(match.range(at: 1), in: html), let url = URL(string: String(html[range]), relativeTo: base)?.absoluteURL,
                  url.scheme == base.scheme, url.host?.lowercased() == base.host?.lowercased(), url.port == base.port,
                  !["png", "jpg", "svg", "css", "woff", "ico", "mp4"].contains(url.pathExtension.lowercased()) else { return nil }
            var parts = URLComponents(url: url, resolvingAgainstBaseURL: true); parts?.fragment = nil
            return parts?.url
        }
    }
    private static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private static func withinScope(_ url: URL, profile: WebAuditProfile) -> Bool {
        guard let base = URL(string: profile.target), WebAuditTransport.origin(url) == WebAuditTransport.origin(base) else { return false }
        func includes(_ prefix: String) -> Bool {
            prefix == "/" || url.path == prefix || url.path.hasPrefix(prefix.hasSuffix("/") ? prefix : prefix + "/")
        }
        return profile.includePaths.contains(where: includes) && !profile.excludePaths.contains(where: includes)
    }
}

struct WebAuditRedactor {
    private var secrets: [String] = []
    init(profile: WebAuditProfile) {
        let headers = Array(profile.headers.values) + profile.accounts.flatMap { Array($0.headers.values) }
        for value in headers {
            if value.hasPrefix("${ENV:"), value.hasSuffix("}") {
                let key = String(value.dropFirst(6).dropLast())
                if let resolved = ProcessInfo.processInfo.environment[key], !resolved.isEmpty { secrets.append(resolved) }
            } else if !value.isEmpty { secrets.append(value) }
        }
    }
    func clean(_ value: String) -> String {
        var result = String(value.prefix(4096))
        for secret in secrets where secret.count >= 4 { result = result.replacingOccurrences(of: secret, with: "[REDACTED]") }
        for pattern in ["(?i)(bearer\\s+)[A-Za-z0-9._~+/-]+=*", "(?i)((?:password|passwd|token|secret|api[_-]?key|authorization|cookie)=)[^&\\s<>\\\"]+",
                        "-----BEGIN [^-]*PRIVATE KEY-----[\\s\\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)"] {
            if let regex = try? NSRegularExpression(pattern: pattern) {
                result = regex.stringByReplacingMatches(in: result, range: NSRange(result.startIndex..., in: result), withTemplate: "[REDACTED]")
            }
        }
        return result
    }
    func clean(_ item: WebAuditObservation) -> WebAuditObservation {
        var output = item
        output.endpoint = clean(item.endpoint); output.evidence = clean(item.evidence)
        output.title = clean(item.title); output.recommendation = clean(item.recommendation)
        output.ruleID = clean(item.ruleID); output.cwe = clean(item.cwe)
        return output
    }
}

enum WebAuditReportWriter {
    @discardableResult static func write(report: WebAuditReport, to directory: URL) throws -> URL {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try encoder.encode(report).write(to: directory.appendingPathComponent("audit.json"), options: .atomic)
        var markdown = "# KODA Swift 웹 정밀 점검\n\n대상: \(md(report.target))\n\n실행: \(report.completed ? "완료" : "미완료 / 확인 필요") · 요청 \(report.metrics.requests)건 · \(String(format: "%.1f", report.metrics.elapsed))초\n\n"
        markdown += "PASS는 선언한 시나리오 범위의 기대 응답을 의미합니다. 미점검 항목은 안전으로 간주하지 않습니다.\n\n| 항목 | 판정 | 근거 |\n|---|---|---|\n"
        for control in report.controls { markdown += "| \(md(control.title)) | \(control.status.rawValue) | \(md(control.reason)) |\n" }
        for item in report.observations {
            markdown += "\n## \(md(item.title)) [\(item.status.rawValue)]\n\n규칙: \(md(item.ruleID)) · 증거: \(item.evidenceID)\n\n\(md(item.method)) \(md(item.endpoint))\n\n\(md(item.evidence))\n\n\(md(item.recommendation))\n"
        }
        markdown += "\n## 실행 공백\n\n" + (report.warnings.isEmpty ? "없음\n" : report.warnings.map { "- \(md($0))" }.joined(separator: "\n"))
        try markdown.write(to: directory.appendingPathComponent("audit.md"), atomically: true, encoding: .utf8)
        let rows = report.controls.map { "<tr><td>\(escape($0.title))</td><td>\(escape($0.status.rawValue))</td><td>\(escape($0.reason))</td></tr>" }.joined()
        let details = report.observations.map {
            "<article><h2>\(escape($0.title))</h2><p>\(escape($0.status.rawValue)) · \(escape($0.ruleID)) · \(escape($0.evidenceID))</p><code>\(escape($0.method)) \(escape($0.endpoint))</code><pre>\(escape($0.evidence))</pre><p>\(escape($0.recommendation))</p></article>"
        }.joined()
        let html = """
        <!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>KODA Swift 웹 점검</title>
        <style>body{font:15px system-ui;max-width:1100px;margin:36px auto;padding:0 24px;color:#172335;background:#f5f7fa}table{border-collapse:collapse;width:100%;background:white}td,th{padding:12px;text-align:left;border-bottom:1px solid #dce3ed}article{padding:20px;background:white;margin-top:16px;border-radius:12px}pre,code{white-space:pre-wrap;overflow-wrap:anywhere}.warning{color:#924d00}</style>
        <h1>KODA Swift 웹 정밀 점검</h1><p>\(escape(report.target))</p><p>실행 \(report.completed ? "완료" : "미완료 / 확인 필요") · 요청 \(report.metrics.requests)건 · \(String(format: "%.1f", report.metrics.elapsed))초</p>
        <p>PASS는 선언한 시나리오 범위에서만 유효합니다. 미점검 항목은 안전 판정이 아닙니다.</p>
        <table><tr><th>점검 항목</th><th>판정</th><th>범위·근거</th></tr>\(rows)</table>\(details)<h2>실행 공백</h2><ul class="warning">\(report.warnings.map { "<li>\(escape($0))</li>" }.joined())</ul></html>
        """
        let destination = directory.appendingPathComponent("audit.html")
        try html.write(to: destination, atomically: true, encoding: .utf8)
        return destination
    }
    private static func escape(_ value: String) -> String {
        value.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }
    private static func md(_ value: String) -> String {
        var output = escape(value).replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\r", with: " ")
        for character in ["\\", "`", "*", "_", "[", "]", "(", ")", "#", "|", "!"] {
            output = output.replacingOccurrences(of: character, with: "\\" + character)
        }
        return output
    }
}
