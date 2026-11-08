import Foundation

private final class WebAuditNoRedirect: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

/// One policy and budget boundary for all native HTTP strategies. Cookies never use shared storage.
actor WebAuditTransport {
    private let profile: WebAuditProfile
    private let targetOrigin: String
    private let cleanupRequests: Int
    private let cleanupSeconds: Double
    private let started = ProcessInfo.processInfo.systemUptime
    private var nextSlot: Double = 0
    private var metrics = WebAuditMetrics()
    private var sessions: [String: URLSession] = [:]
    private var cookies: [String: [HTTPCookie]] = [:]
    private var stopped = false
    private let actorHeaders: [String: [String: String]]

    nonisolated static func origin(_ url: URL) -> String {
        guard let scheme = url.scheme?.lowercased(), let host = url.host?.lowercased(),
              ["http", "https"].contains(scheme) else { return "" }
        return "\(scheme)://\(host):\(url.port ?? (scheme == "https" ? 443 : 80))"
    }

    init(profile: WebAuditProfile) throws {
        guard profile.schemaVersion == 1, profile.authorized,
              let target = URL(string: profile.target), !Self.origin(target).isEmpty,
              target.user == nil, target.password == nil, target.fragment == nil,
              !profile.includePaths.isEmpty else { throw WebAuditError.invalidProfile("authorized HTTP target required") }
        #if KODA_APP_STORE
        guard !profile.active, !profile.allowStateChanges,
              profile.allowedMethods.allSatisfy({ ["GET", "HEAD"].contains($0) }) else {
            throw WebAuditError.invalidProfile("App Store distribution permits read-only profiles")
        }
        #endif
        let l = profile.limits
        guard (1...5000).contains(l.maxRequests), l.maxDuration.isFinite, (0.05...3600).contains(l.maxDuration),
              l.requestsPerSecond.isFinite, (0.1...20).contains(l.requestsPerSecond),
              l.requestTimeout.isFinite, (0.01...120).contains(l.requestTimeout),
              (1...8_388_608).contains(l.maxResponseBytes), (0...5_242_880).contains(l.maxUploadBytes),
              (1...1000).contains(l.maxPages), (0...20).contains(l.maxDepth) else {
            throw WebAuditError.invalidProfile("invalid limits")
        }
        guard profile.resources.count <= 100, profile.scenarios.count <= 100,
              profile.accounts.count <= 20, profile.rules.count <= 100,
              Set(profile.resources.map { $0.id }).count == profile.resources.count,
              Set(profile.scenarios.map { $0.id }).count == profile.scenarios.count else {
            throw WebAuditError.invalidProfile("profile collection limit or duplicate identifier")
        }
        let cleanupCount = profile.apiWriteCleanup.count + profile.scenarios.reduce(0) { $0 + $1.cleanup.count }
        let reservedSeconds = cleanupCount == 0 ? 0 : min(30, l.maxDuration * 0.25)
        guard cleanupCount <= 100, cleanupCount < l.maxRequests,
              cleanupCount == 0 || reservedSeconds >= Double(cleanupCount) / l.requestsPerSecond + 0.05 else {
            throw WebAuditError.invalidProfile("insufficient cleanup budget")
        }
        let supported: Set<String> = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
        guard !profile.allowedMethods.isEmpty, Set(profile.allowedMethods).count == profile.allowedMethods.count,
              profile.allowedMethods.allSatisfy({ supported.contains($0) }) else { throw WebAuditError.invalidProfile("invalid methods") }
        for path in profile.includePaths + profile.excludePaths { try Self.validatePath(path) }
        let targetPath = URLComponents(url: target, resolvingAgainstBaseURL: false)?.percentEncodedPath ?? "/"
        try Self.validatePath(targetPath.isEmpty ? "/" : targetPath)
        var headers: [String: [String: String]] = ["anonymous": [:], "primary": try Self.resolveHeaders(profile.headers)]
        for account in profile.accounts {
            guard account.id.range(of: "^[A-Za-z][A-Za-z0-9_-]{0,63}$", options: .regularExpression) != nil,
                  headers[account.id] == nil else { throw WebAuditError.invalidProfile("invalid or duplicate actor") }
            headers[account.id] = try Self.resolveHeaders(account.headers)
        }
        let controls = Set(WebAuditCatalog.controls.map { $0.0 })
        func step(_ value: WebAuditStep) throws {
            try Self.validatePath(value.path)
            guard headers[value.actor] != nil, !value.expectedStatusCodes.isEmpty,
                  value.expectedStatusCodes.allSatisfy({ (100...599).contains($0) }),
                  (value.bodyContains == nil || !value.bodyContains!.isEmpty),
                  (value.body?.utf8.count ?? 0) <= l.maxUploadBytes,
                  profile.allowedMethods.contains(value.method),
                  (["GET", "HEAD", "OPTIONS"].contains(value.method) || (profile.active && profile.allowStateChanges)) else {
                throw WebAuditError.invalidProfile("invalid step actor or method")
            }
        }
        for resource in profile.resources {
            try Self.validatePath(resource.path)
            guard Self.identifier(resource.id), !resource.expectations.isEmpty,
                  controls.contains(resource.controlID), profile.allowedMethods.contains(resource.method),
                  ["GET", "HEAD", "OPTIONS"].contains(resource.method),
                  resource.expectations.keys.allSatisfy({ headers[$0] != nil }),
                  resource.expectations.values.allSatisfy({ !$0.statusCodes.isEmpty && $0.statusCodes.allSatisfy { (100...599).contains($0) } && ($0.bodyContains == nil || !$0.bodyContains!.isEmpty) }) else { throw WebAuditError.invalidProfile("invalid resource") }
        }
        for scenario in profile.scenarios {
            guard Self.identifier(scenario.id), !scenario.steps.isEmpty, controls.contains(scenario.controlID) else { throw WebAuditError.invalidProfile("unknown control") }
            for value in scenario.steps + scenario.cleanup { try step(value) }
        }
        for value in profile.apiWriteCleanup { try step(value) }
        guard Set(profile.rules.map { $0.id }).count == profile.rules.count else { throw WebAuditError.invalidProfile("duplicate rule") }
        for rule in profile.rules {
            try Self.validatePath(rule.path)
            guard controls.contains(rule.controlID), Self.identifier(rule.id), !rule.id.hasPrefix("builtin."),
                  !rule.title.isEmpty, rule.title.count <= 256,
                  ["info", "low", "medium", "high", "critical"].contains(rule.severity),
                  (!rule.bodyContains.isEmpty || !rule.headerContains.isEmpty),
                  rule.statusCodes.allSatisfy({ (100...599).contains($0) }),
                  rule.bodyContains.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 4096 }),
                  rule.headerContains.allSatisfy({ !$0.key.isEmpty && !$0.value.isEmpty && $0.value.utf8.count <= 4096 }) else {
                throw WebAuditError.invalidProfile("invalid rule")
            }
        }
        if target.scheme?.lowercased() != "https" && !Self.loopback(target) && headers.values.contains(where: { Self.hasCredentials($0) }) {
            throw WebAuditError.invalidProfile("credentials require HTTPS")
        }
        self.profile = profile
        self.targetOrigin = Self.origin(target)
        self.actorHeaders = headers
        self.cleanupRequests = cleanupCount
        self.cleanupSeconds = reservedSeconds
    }

    func snapshot() -> WebAuditMetrics {
        var result = metrics
        result.elapsed = ProcessInfo.processInfo.systemUptime - started
        return result
    }

    func shutdown() {
        stopped = true
        for session in sessions.values { session.invalidateAndCancel() }
        sessions.removeAll(); cookies.removeAll()
    }

    func send(_ request: WebAuditRequest, actor: String = "anonymous") async throws -> WebAuditResponse {
        do { return try await perform(request, actor: actor, isCleanup: false) }
        catch { metrics.blocked += 1; throw error }
    }

    /// Call from a separate, bounded Task when the initiating task was cancelled. Identities and
    /// cookies remain shared with this audit; cleanup cannot exceed the original total envelope.
    func sendCleanup(_ request: WebAuditRequest, actor: String = "anonymous") async throws -> WebAuditResponse {
        do { return try await perform(request, actor: actor, isCleanup: true) }
        catch { metrics.blocked += 1; throw error }
    }

    private func perform(_ input: WebAuditRequest, actor: String, isCleanup: Bool) async throws -> WebAuditResponse {
        try Task.checkCancellation()
        guard !stopped else { throw WebAuditError.blocked("transport stopped") }
        guard let identityHeaders = actorHeaders[actor] else { throw WebAuditError.blocked("unknown actor") }
        guard Self.origin(input.url) == targetOrigin, input.url.user == nil, input.url.password == nil,
              input.url.fragment == nil else { throw WebAuditError.blocked("origin mismatch") }
        let encoded = URLComponents(url: input.url, resolvingAgainstBaseURL: false)?.percentEncodedPath ?? "/"
        try Self.validatePath(encoded.isEmpty ? "/" : encoded)
        let path = input.url.path.isEmpty ? "/" : input.url.path
        guard profile.includePaths.contains(where: { Self.contains($0, path) }),
              !profile.excludePaths.contains(where: { Self.contains($0, path) }) else { throw WebAuditError.blocked("path outside profile") }
        let method = input.method
        #if KODA_APP_STORE
        guard ["GET", "HEAD"].contains(method) else { throw WebAuditError.blocked("read-only distribution") }
        #endif
        guard profile.allowedMethods.contains(method),
              (["GET", "HEAD", "OPTIONS"].contains(method) || (profile.active && profile.allowStateChanges)) else {
            throw WebAuditError.blocked("method outside profile")
        }
        guard (input.body?.count ?? 0) <= profile.limits.maxUploadBytes else { throw WebAuditError.budget("upload") }
        var headers = identityHeaders
        for (key, value) in try Self.resolveHeaders(input.headers) { headers[key] = value }
        // Anonymous requests cannot accidentally acquire the primary identity's headers or cookies.
        if Self.hasCredentials(headers) && input.url.scheme?.lowercased() != "https" && !Self.loopback(input.url) {
            throw WebAuditError.blocked("credentials require HTTPS")
        }
        let now = ProcessInfo.processInfo.systemUptime
        let deadline = started + profile.limits.maxDuration - (isCleanup ? 0 : cleanupSeconds)
        let requestLimit = profile.limits.maxRequests - (isCleanup ? 0 : cleanupRequests)
        guard now < deadline, metrics.requests < requestLimit else { throw WebAuditError.budget("requests or duration") }
        let slot = max(now, nextSlot)
        guard slot < deadline else { throw WebAuditError.budget("duration") }
        // Reserve both counters before the first suspension: concurrent callers cannot overspend.
        metrics.requests += 1
        nextSlot = slot + 1 / profile.limits.requestsPerSecond
        if slot > now { try await Task.sleep(nanoseconds: UInt64((slot - now) * 1_000_000_000)) }
        try Task.checkCancellation()
        guard !stopped else { throw WebAuditError.blocked("transport stopped") }
        let remaining = deadline - ProcessInfo.processInfo.systemUptime
        guard remaining > 0 else { throw WebAuditError.budget("duration") }
        let session: URLSession
        if let existing = sessions[actor] { session = existing }
        else {
            let config = URLSessionConfiguration.ephemeral
            config.httpCookieStorage = nil; config.httpShouldSetCookies = false
            config.urlCredentialStorage = nil; config.requestCachePolicy = .reloadIgnoringLocalCacheData
            config.httpMaximumConnectionsPerHost = 1
            session = URLSession(configuration: config, delegate: WebAuditNoRedirect(), delegateQueue: nil)
            sessions[actor] = session
        }
        var request = URLRequest(url: input.url)
        request.httpMethod = method; request.httpBody = input.body
        request.timeoutInterval = min(profile.limits.requestTimeout, remaining)
        for (key, value) in headers { request.setValue(value, forHTTPHeaderField: key) }
        let currentCookies = (cookies[actor] ?? []).filter { cookie in
            (cookie.expiresDate == nil || cookie.expiresDate! > Date()) && (!cookie.isSecure || input.url.scheme == "https") && Self.contains(cookie.path, path)
        }
        if !currentCookies.isEmpty && input.url.scheme?.lowercased() != "https" && !Self.loopback(input.url) {
            throw WebAuditError.blocked("session cookies require HTTPS")
        }
        if !currentCookies.isEmpty && request.value(forHTTPHeaderField: "Cookie") == nil {
            request.setValue(HTTPCookie.requestHeaderFields(with: currentCookies)["Cookie"], forHTTPHeaderField: "Cookie")
        }
        let begun = ProcessInfo.processInfo.systemUptime
        let cap = profile.limits.maxResponseBytes
        let outgoingRequest = request
        let requestDeadline = min(remaining, profile.limits.requestTimeout)
        let response: WebAuditResponse
        do {
            response = try await withThrowingTaskGroup(of: WebAuditResponse.self) { group in
                group.addTask {
                    let (bytes, raw) = try await session.bytes(for: outgoingRequest)
                    guard let http = raw as? HTTPURLResponse else { throw WebAuditError.invalidResponse }
                    if http.expectedContentLength > Int64(cap) { throw WebAuditError.responseTooLarge }
                    var body = Data()
                    for try await byte in bytes {
                        try Task.checkCancellation()
                        guard body.count < cap else { throw WebAuditError.responseTooLarge }
                        body.append(byte)
                    }
                    var fields: [String: String] = [:]
                    for (key, value) in http.allHeaderFields { fields[String(describing: key)] = String(describing: value) }
                    return WebAuditResponse(url: input.url, status: http.statusCode, headers: fields, body: body,
                                            elapsed: ProcessInfo.processInfo.systemUptime - begun)
                }
                group.addTask {
                    try await Task.sleep(nanoseconds: UInt64(requestDeadline * 1_000_000_000))
                    throw WebAuditError.budget("request deadline")
                }
                defer { group.cancelAll() }
                guard let first = try await group.next() else { throw WebAuditError.invalidResponse }
                return first
            }
        } catch is CancellationError { throw CancellationError() }
        catch let error as WebAuditError { throw error }
        catch {
            if Task.isCancelled { throw CancellationError() }
            throw WebAuditError.blocked("HTTP transport failed")
        }
        metrics.receivedBytes += response.body.count
        let incoming = HTTPCookie.cookies(withResponseHeaderFields: response.headers, for: input.url)
        var jar = cookies[actor] ?? []
        for cookie in incoming where cookie.domain.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased() == input.url.host?.lowercased() {
            jar.removeAll { $0.name == cookie.name && $0.path == cookie.path }
            jar.append(cookie)
        }
        cookies[actor] = jar
        return response
    }

    private nonisolated static func identifier(_ value: String) -> Bool {
        guard let matched = value.range(of: "^[A-Za-z][A-Za-z0-9_.-]{0,127}$", options: .regularExpression) else { return false }
        return matched == value.startIndex..<value.endIndex
    }
    private nonisolated static func hasCredentials(_ headers: [String: String]) -> Bool {
        let ordinary: Set<String> = ["accept", "accept-language", "accept-encoding", "user-agent", "content-type", "cache-control", "pragma"]
        return headers.keys.contains { !ordinary.contains($0.lowercased()) }
    }
    private nonisolated static func loopback(_ url: URL) -> Bool {
        ["localhost", "127.0.0.1", "::1", "[::1]"].contains(url.host?.lowercased() ?? "")
    }
    private nonisolated static func contains(_ prefix: String, _ path: String) -> Bool {
        prefix == "/" || path == prefix || path.hasPrefix(prefix.hasSuffix("/") ? prefix : prefix + "/")
    }
    private nonisolated static func validatePath(_ raw: String) throws {
        guard raw.utf8.count <= 2048, raw.hasPrefix("/"), !raw.hasPrefix("//"), !raw.contains("?"), !raw.contains("#") else { throw WebAuditError.blocked("invalid path") }
        var path = raw
        for _ in 0..<4 {
            guard !path.contains("\\"), !path.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }),
                  !path.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0 == "." || $0 == ".." }) else {
                throw WebAuditError.blocked("invalid path")
            }
            guard let decoded = path.removingPercentEncoding else { throw WebAuditError.blocked("invalid encoding") }
            if decoded == path { return }
            // Encoded separators change path boundaries and are rejected rather than normalized.
            guard !path.lowercased().contains("%2f"), !path.lowercased().contains("%5c") else { throw WebAuditError.blocked("encoded separator") }
            path = decoded
        }
        throw WebAuditError.blocked("nested encoding")
    }
    private nonisolated static func resolveHeaders(_ source: [String: String]) throws -> [String: String] {
        var result: [String: String] = [:]
        let forbidden: Set<String> = ["host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "proxy-connection", "upgrade", "expect"]
        for (key, original) in source {
            guard key.range(of: "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$", options: .regularExpression) != nil,
                  !forbidden.contains(key.lowercased()) else { throw WebAuditError.invalidProfile("invalid header") }
            var value = original
            if original.hasPrefix("${ENV:") {
                guard original.hasSuffix("}"), original.dropFirst(6).dropLast().range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) != nil,
                      let resolved = ProcessInfo.processInfo.environment[String(original.dropFirst(6).dropLast())], !resolved.isEmpty else {
                    throw WebAuditError.invalidProfile("missing credential reference")
                }
                value = resolved
            }
            guard !value.contains("\r"), !value.contains("\n"), !value.contains("\0") else { throw WebAuditError.invalidProfile("invalid header value") }
            guard !result.keys.contains(where: { $0.caseInsensitiveCompare(key) == .orderedSame }) else { throw WebAuditError.invalidProfile("duplicate header") }
            result[key.lowercased()] = value
        }
        return result
    }
}
