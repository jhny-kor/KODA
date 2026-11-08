import Foundation
import CoreFoundation

struct WebAuditAPIResponseExpectation: Sendable {
    var documentedStatuses: Set<String>
    /// Bounded, locally resolved JSON schema subsets keyed by HTTP status / 2XX / default.
    var schemas: [String: Data]
}

struct WebAuditAPIPlan: Sendable {
    var requests: [WebAuditRequest]
    var responseExpectations: [Int: WebAuditAPIResponseExpectation]
    var invalidRequestIndices: Set<Int>
    var warnings: [String]
}

/// A bounded JSON subset, not a full OpenAPI validator. No external fetches or executable examples.
/// Parameter/server structure follows https://spec.openapis.org/oas/v3.0.3.html and /oas/v2.0.html.
enum NativeWebAuditAPI {
    static func load(data: Data, baseURL: URL, allowedStateChanges: Bool) throws -> WebAuditAPIPlan {
        guard data.count <= 2_097_152 else { throw WebAuditError.invalidProfile("API 정의는 2 MiB 이하만 지원합니다.") }
        guard let document = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw WebAuditError.invalidProfile("OpenAPI/Swagger JSON만 지원합니다. YAML은 지원하지 않습니다.")
        }
        let v3 = (document["openapi"] as? String)?.hasPrefix("3.") == true
        guard v3 || document["swagger"] as? String == "2.0" else { throw WebAuditError.invalidProfile("OpenAPI 3 또는 Swagger 2 JSON이 필요합니다.") }
        guard ["http", "https"].contains(baseURL.scheme?.lowercased() ?? ""), baseURL.host != nil, baseURL.user == nil, baseURL.password == nil else {
            throw WebAuditError.invalidProfile("API 기준 URL이 올바르지 않습니다.")
        }
        var count = 0
        try validateTree(document, baseURL: baseURL, count: &count, depth: 0)
        var server = baseURL
        if v3, let servers = document["servers"] as? [[String: Any]], let first = servers.first {
            server = try serverURL(first, baseURL: baseURL)
        } else if !v3 {
            if let host = document["host"] as? String {
                let schemes = document["schemes"] as? [String] ?? [baseURL.scheme ?? "https"]
                guard !schemes.isEmpty else { throw WebAuditError.invalidProfile("Swagger schemes가 비어 있습니다.") }
                for scheme in schemes {
                    guard let candidate = URL(string: "\(scheme)://\(host)"), sameOrigin(candidate, baseURL) else {
                        throw WebAuditError.invalidProfile("외부 Swagger host/scheme은 허용하지 않습니다.")
                    }
                }
            }
            if let basePath = document["basePath"] as? String {
                guard basePath.hasPrefix("/"), !basePath.contains("?"), !basePath.contains("#") else { throw WebAuditError.invalidProfile("Swagger basePath 오류") }
                var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false)!
                components.path = basePath; components.query = nil; components.fragment = nil
                guard let candidate = components.url else { throw WebAuditError.invalidProfile("Swagger basePath 오류") }
                server = candidate
            }
        }
        guard let paths = document["paths"] as? [String: Any] else { throw WebAuditError.invalidProfile("API paths가 필요합니다.") }
        var requests: [WebAuditRequest] = [], warnings: [String] = [], operations = 0
        var invalidRequestIndices: Set<Int> = []
        var responseExpectations: [Int: WebAuditAPIResponseExpectation] = [:]
        let methods = ["get", "head", "options", "post", "put", "patch", "delete"]
        for path in paths.keys.sorted() {
            guard operations < 40 else { warnings.append("API operation 40개 한도를 적용했습니다."); break }
            guard path.hasPrefix("/"), !path.hasPrefix("//"), !path.contains("?"), !path.contains("#"), !path.contains("\\"), let rawPath = paths[path] as? [String: Any] else {
                throw WebAuditError.invalidProfile("API path 형식 오류: \(path)")
            }
            let pathItem = try resolve(rawPath, document: document, depth: 0)
            for method in methods {
                guard operations < 40, let operation = pathItem[method] as? [String: Any] else { continue }
                guard method == "get" || allowedStateChanges else {
                    warnings.append("기본 GET 전용 정책으로 \(method.uppercased()) \(path) 제외")
                    continue
                }
                // Destructive endpoint semantics cannot be inferred from an API schema.
                if method == "delete" { warnings.append("삭제 operation은 자동 생성하지 않습니다: \(path)"); continue }
                var operationServer = server
                if let servers = operation["servers"] as? [[String: Any]], let first = servers.first { operationServer = try serverURL(first, baseURL: baseURL) }
                else if let servers = pathItem["servers"] as? [[String: Any]], let first = servers.first { operationServer = try serverURL(first, baseURL: baseURL) }
                let inherited = pathItem["parameters"] as? [[String: Any]] ?? []
                let own = operation["parameters"] as? [[String: Any]] ?? []
                var parameters: [String: [String: Any]] = [:]
                for raw in (inherited + own).prefix(64) {
                    let parameter = try resolve(raw, document: document, depth: 0)
                    guard let name = parameter["name"] as? String, let location = parameter["in"] as? String, name.count <= 128 else { continue }
                    parameters[location + ":" + name] = parameter
                }
                var rendered = path, query: [URLQueryItem] = [], headers: [String: String] = [:], body: Data?
                var negativeQuery: [URLQueryItem]?
                var formFields: [String: [String: Any]] = [:]
                var negativeBody: Data?
                var unsupportedFile = false
                for key in parameters.keys.sorted() {
                    let p = parameters[key]!, name = p["name"] as! String, location = p["in"] as! String
                    let schema = try resolve((p["schema"] as? [String: Any]) ?? p, document: document, depth: 0)
                    if location == "path" {
                        if rendered.range(of: #"\{[^{}]+\}"#, options: .regularExpression) != nil { warnings.append("스키마에 선언되지 않은 path parameter를 고정 표본으로 대체합니다: \(path)") }
                rendered = rendered.replacingOccurrences(of: "{\(name)}", with: pathValue(schema))
                    } else if location == "query" {
                        query.append(URLQueryItem(name: name, value: stringValue(schema)))
                        if negativeQuery == nil, let invalid = invalidString(schema) {
                            negativeQuery = [URLQueryItem(name: name, value: invalid)]
                        }
                    } else if location == "body", allowedStateChanges {
                        body = try jsonBody(schema, document: document)
                        headers["Content-Type"] = "application/json"
                    } else if location == "header" || location == "cookie" {
                        warnings.append("인증/헤더/쿠키 parameter는 자동 생성하지 않습니다: \(name)")
                    } else if location == "formData", allowedStateChanges {
                        guard (schema["type"] as? String) != "file" else { warnings.append("파일 업로드 formData operation은 제외합니다: \(path)"); unsupportedFile = true; continue }
                        formFields[name] = schema
                    }
                }
                if unsupportedFile { continue }
                if !formFields.isEmpty {
                    let consumes = operation["consumes"] as? [String] ?? document["consumes"] as? [String] ?? []
                    guard consumes.contains("application/x-www-form-urlencoded") else { warnings.append("Swagger formData는 urlencoded만 지원합니다: \(path)"); continue }
                    let form = try formBody(formFields, required: Set(formFields.filter { ($0.value["required"] as? Bool) == true }.keys))
                    body = form.body; negativeBody = form.negative; headers["Content-Type"] = "application/x-www-form-urlencoded"
                }
                // Unspecified path parameters get safe, fixed placeholders rather than remote examples.
                if rendered.range(of: #"\{[^{}]+\}"#, options: .regularExpression) != nil { warnings.append("스키마에 선언되지 않은 path parameter를 고정 표본으로 대체합니다: \(path)") }
                rendered = rendered.replacingOccurrences(of: #"\{[^{}]+\}"#, with: "koda-sample", options: .regularExpression)
                if rendered.contains("{") || rendered.contains("}") { throw WebAuditError.invalidProfile("해결하지 못한 path parameter") }
                if allowedStateChanges, ["post", "put", "patch"].contains(method), let rawBody = operation["requestBody"] as? [String: Any] {
                    let requestBody = try resolve(rawBody, document: document, depth: 0)
                    if let content = requestBody["content"] as? [String: Any], let media = content["application/json"] as? [String: Any], let schema = media["schema"] as? [String: Any] {
                        body = try jsonBody(schema, document: document); headers["Content-Type"] = "application/json"
                    } else if let content = requestBody["content"] as? [String: Any], let media = content["application/x-www-form-urlencoded"] as? [String: Any], let rawSchema = media["schema"] as? [String: Any] {
                        guard media["encoding"] == nil else { warnings.append("사용자 encoding이 있는 form body는 지원하지 않습니다: \(path)"); continue }
                        let schema = try resolve(rawSchema, document: document, depth: 0)
                        guard schema["allOf"] == nil, schema["anyOf"] == nil, schema["oneOf"] == nil else { throw WebAuditError.invalidProfile("합성 form schema 미지원") }
                        let properties = schema["properties"] as? [String: [String: Any]] ?? [:]
                        guard properties.count <= 8 else { throw WebAuditError.invalidProfile("urlencoded property 수 한도 초과") }
                        var fields: [String: [String: Any]] = [:]
                        for name in properties.keys.sorted().prefix(8) { fields[name] = try resolve(properties[name]!, document: document, depth: 0) }
                        let form = try formBody(fields, required: Set(schema["required"] as? [String] ?? []))
                        body = form.body; negativeBody = form.negative; headers["Content-Type"] = "application/x-www-form-urlencoded"
                    } else { warnings.append("JSON/urlencoded 외 requestBody는 지원하지 않습니다: \(path)"); continue }
                }
                guard var components = URLComponents(url: operationServer, resolvingAgainstBaseURL: false) else { continue }
                let prefix = components.path == "/" ? "" : components.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                components.path = (prefix.isEmpty ? "" : "/" + prefix) + rendered
                components.queryItems = query.isEmpty ? nil : query; components.fragment = nil
                guard let url = components.url, sameOrigin(url, baseURL) else { throw WebAuditError.invalidProfile("API 요청이 기준 origin을 벗어납니다.") }
                let startIndex = requests.count
                requests.append(WebAuditRequest(url: url, method: method.uppercased(), headers: headers, body: body)); operations += 1
                // One bounded type-error request and one missing-required-query request per operation.
                if let invalid = negativeQuery?.first {
                    var altered = query; if let i = altered.firstIndex(where: { $0.name == invalid.name }) { altered[i] = invalid }
                    components.queryItems = altered
                    if let negativeURL = components.url {
                        invalidRequestIndices.insert(requests.count)
                        requests.append(WebAuditRequest(url: negativeURL, method: method.uppercased(), headers: headers, body: body))
                    }
                }
                let requiredNames = Set(parameters.values.filter { ($0["in"] as? String) == "query" && ($0["required"] as? Bool) == true }.compactMap { $0["name"] as? String })
                if !requiredNames.isEmpty {
                    components.queryItems = query.filter { !requiredNames.contains($0.name) }
                    if let negativeURL = components.url {
                        invalidRequestIndices.insert(requests.count)
                        requests.append(WebAuditRequest(url: negativeURL, method: method.uppercased(), headers: headers, body: body))
                    }
                }
                if body != nil {
                    if headers["Content-Type"] == "application/json" { negativeBody = Data("{".utf8) }
                    if let invalidBody = negativeBody, invalidBody != body {
                        invalidRequestIndices.insert(requests.count)
                        requests.append(WebAuditRequest(url: url, method: method.uppercased(), headers: headers, body: invalidBody))
                    }
                    warnings.append("요청 body는 제한된 표본입니다. 전체 스키마 적합성 및 cleanup은 별도 검증이 필요합니다.")
                }
                let expectation = try responseExpectation(operation, document: document, warnings: &warnings)
                for index in startIndex..<requests.count { responseExpectations[index] = expectation }

            }
        }
        if requests.isEmpty { warnings.append("실행 가능한 API 요청이 없습니다.") }
        warnings.append("응답 스키마는 required/type 및 배열 앞 8개·속성 32개·깊이 4만 검사합니다. enum/format/pattern/합성 스키마 전체 검증은 지원하지 않습니다.")
        warnings.append("JSON 스키마 부분집합만 지원합니다. YAML·외부 $ref·파일 업로드·GraphQL·보안 의미/권한 자동 추론은 지원하지 않습니다.")
        if requests.count > 120 { warnings.append("API 요청 120개 한도를 적용했습니다.") }
        return WebAuditAPIPlan(requests: Array(requests.prefix(120)), responseExpectations: responseExpectations.filter { $0.key < 120 }, invalidRequestIndices: Set(invalidRequestIndices.filter { $0 < 120 }), warnings: Array(Set(warnings)).sorted())
    }

    private static func formBody(_ fields: [String: [String: Any]], required: Set<String>) throws -> (body: Data, negative: Data?) {
        guard fields.count <= 8, fields.values.allSatisfy({ ["string", "integer", "number", "boolean"].contains($0["type"] as? String ?? "string") }) else {
            throw WebAuditError.invalidProfile("urlencoded 표본은 최대 8개 scalar property만 지원합니다.")
        }
        func encode(_ items: [URLQueryItem]) -> Data {
            var components = URLComponents(); components.queryItems = items
            // URL query permits '+', while a form parser interprets it as a space.
            return Data((components.percentEncodedQuery ?? "").replacingOccurrences(of: "+", with: "%2B").utf8)
        }
        let items = fields.keys.sorted().map { URLQueryItem(name: $0, value: stringValue(fields[$0]!)) }
        var negative: Data?
        if let key = fields.keys.sorted().first(where: { invalidString(fields[$0]!) != nil }) {
            negative = encode(items.map { $0.name == key ? URLQueryItem(name: key, value: invalidString(fields[key]!)) : $0 })
        } else if let key = required.sorted().first(where: { fields[$0] != nil }) {
            negative = encode(items.filter { $0.name != key })
        }
        return (encode(items), negative)
    }

    private static func responseExpectation(_ operation: [String: Any], document: [String: Any], warnings: inout [String]) throws -> WebAuditAPIResponseExpectation {
        let responses = operation["responses"] as? [String: [String: Any]] ?? [:]
        var schemas: [String: Data] = [:]
        let statuses = Set(responses.keys.filter { $0 == "default" || $0.range(of: #"^[1-5]([0-9]{2}|[xX]{2})$"#, options: .regularExpression) != nil }.map { $0 == "default" ? $0 : $0.uppercased() })
        for key in responses.keys.sorted() {
            let response = try resolve(responses[key]!, document: document, depth: 0)
            var raw = response["schema"] as? [String: Any]
            if let content = response["content"] as? [String: Any] {
                if let name = content.keys.sorted().first(where: { $0 == "application/json" || $0.hasSuffix("+json") }), let media = content[name] as? [String: Any] {
                    raw = media["schema"] as? [String: Any]
                }
            } else if raw != nil {
                let produces = operation["produces"] as? [String] ?? document["produces"] as? [String] ?? ["application/json"]
                if !produces.contains(where: { $0 == "application/json" || $0.hasSuffix("+json") }) { raw = nil }
            }
            if let raw {
                do {
                    let schema = try responseSchema(raw, document: document, depth: 0)
                    schemas[key == "default" ? key : key.uppercased()] = try JSONSerialization.data(withJSONObject: schema)
                } catch { warnings.append("응답 schema 일부를 검사하지 못합니다 (\(key)): \(error.localizedDescription)") }
            }
        }
        if statuses.isEmpty { warnings.append("문서화된 API 응답 상태가 없어 상태 계약을 검사하지 못합니다.") }
        return WebAuditAPIResponseExpectation(documentedStatuses: statuses, schemas: schemas)
    }

    private static func responseSchema(_ raw: [String: Any], document: [String: Any], depth: Int) throws -> [String: Any] {
        guard depth < 4 else { throw WebAuditError.invalidProfile("응답 schema 깊이 한도 초과") }
        let schema = try resolve(raw, document: document, depth: 0)
        guard schema["allOf"] == nil, schema["oneOf"] == nil, schema["anyOf"] == nil, schema["not"] == nil else { throw WebAuditError.invalidProfile("합성 응답 schema 미지원") }
        var bounded: [String: Any] = [:]
        for key in ["type", "nullable"] { bounded[key] = schema[key] }
        if let required = schema["required"] as? [String] {
            guard required.count <= 32 else { throw WebAuditError.invalidProfile("응답 required 속성 한도 초과") }
            bounded["required"] = required
        }
        if let properties = schema["properties"] as? [String: [String: Any]] {
            guard properties.count <= 32 else { throw WebAuditError.invalidProfile("응답 property 수 한도 초과") }
            var result: [String: Any] = [:]
            for key in properties.keys.sorted() { result[key] = try responseSchema(properties[key]!, document: document, depth: depth + 1) }
            bounded["properties"] = result
        }
        if let items = schema["items"] as? [String: Any] { bounded["items"] = try responseSchema(items, document: document, depth: depth + 1) }
        return bounded
    }

    static func responseViolations(_ response: WebAuditResponse, expectation: WebAuditAPIResponseExpectation) -> [String] {
        let status = String(response.status), group = "\(response.status / 100)XX"
        var output: [String] = []
        if !expectation.documentedStatuses.isEmpty, !expectation.documentedStatuses.contains(status), !expectation.documentedStatuses.contains(group), !expectation.documentedStatuses.contains("default") {
            output.append("문서화되지 않은 응답 상태 HTTP \(response.status)")
        }
        guard (200..<300).contains(response.status), let data = expectation.schemas[status] ?? expectation.schemas[group] ?? expectation.schemas["default"],
              let schema = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return output }
        guard let value = try? JSONSerialization.jsonObject(with: response.body, options: [.fragmentsAllowed]) else {
            output.append("JSON schema가 지정된 2xx 응답을 JSON으로 해석하지 못함"); return output
        }
        return output + validateResponse(value, schema: schema, path: "$", depth: 0)
    }

    private static func validateResponse(_ value: Any, schema: [String: Any], path: String, depth: Int) -> [String] {
        guard depth < 4 else { return [] }
        let declared = (schema["type"] as? String).map { [$0] } ?? schema["type"] as? [String] ?? []
        if value is NSNull, (schema["nullable"] as? Bool == true || declared.contains("null")) { return [] }
        func matches(_ type: String) -> Bool {
            switch type {
            case "null": return value is NSNull
            case "string": return value is String
            case "object": return value is [String: Any]
            case "array": return value is [Any]
            case "boolean": return (value as? NSNumber).map { CFGetTypeID($0) == CFBooleanGetTypeID() } ?? false
            case "integer", "number":
                guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return false }
                return type == "number" || (n.doubleValue.isFinite && n.doubleValue.rounded() == n.doubleValue)
            default: return true
            }
        }
        if !declared.isEmpty, !declared.contains(where: matches) { return ["\(path) 응답 type 불일치"] }
        var output: [String] = []
        if let object = value as? [String: Any] {
            let required = schema["required"] as? [String] ?? []
            if required.contains(where: { object[$0] == nil }) { output.append("\(path) 응답 required property 누락") }
            if let properties = schema["properties"] as? [String: [String: Any]] {
                for key in properties.keys.sorted().prefix(32) {
                    if let child = object[key] { output += validateResponse(child, schema: properties[key]!, path: "\(path).property", depth: depth + 1) }
                }
            }
        } else if let array = value as? [Any], let items = schema["items"] as? [String: Any] {
            for child in array.prefix(8) { output += validateResponse(child, schema: items, path: "\(path)[]", depth: depth + 1) }
        }
        return Array(output.prefix(16))
    }

    private static func sameOrigin(_ a: URL, _ b: URL) -> Bool {
        func port(_ u: URL) -> Int { u.port ?? (u.scheme?.lowercased() == "https" ? 443 : 80) }
        return a.scheme?.lowercased() == b.scheme?.lowercased() && a.host?.lowercased() == b.host?.lowercased() && port(a) == port(b) && a.user == nil && a.password == nil
    }
    private static func serverURL(_ server: [String: Any], baseURL: URL) throws -> URL {
        guard let raw = server["url"] as? String, !raw.contains("{"), !raw.hasPrefix("//"),
              let candidate = URL(string: raw, relativeTo: baseURL)?.absoluteURL,
              sameOrigin(candidate, baseURL), candidate.query == nil, candidate.fragment == nil else {
            throw WebAuditError.invalidProfile("외부/변수형 API server URL은 허용하지 않습니다.")
        }
        return candidate
    }
    private static func validateTree(_ value: Any, baseURL: URL, count: inout Int, depth: Int) throws {
        count += 1
        guard count <= 40_000, depth <= 40 else { throw WebAuditError.invalidProfile("API 정의 구조 한도 초과") }
        if let object = value as? [String: Any] {
            if let ref = object["$ref"] as? String, !ref.hasPrefix("#/") { throw WebAuditError.invalidProfile("외부 $ref는 지원하지 않습니다.") }
            if let servers = object["servers"] as? [[String: Any]] { for server in servers { _ = try serverURL(server, baseURL: baseURL) } }
            for child in object.values { try validateTree(child, baseURL: baseURL, count: &count, depth: depth + 1) }
        } else if let array = value as? [Any] { for child in array { try validateTree(child, baseURL: baseURL, count: &count, depth: depth + 1) } }
    }
    private static func resolve(_ object: [String: Any], document: [String: Any], depth: Int) throws -> [String: Any] {
        guard depth < 8 else { throw WebAuditError.invalidProfile("순환 또는 과도한 $ref") }
        guard let ref = object["$ref"] as? String else { return object }
        guard ref.hasPrefix("#/") else { throw WebAuditError.invalidProfile("외부 $ref는 지원하지 않습니다.") }
        var value: Any = document
        for segment in ref.dropFirst(2).split(separator: "/", omittingEmptySubsequences: false) {
            let key = String(segment).replacingOccurrences(of: "~1", with: "/").replacingOccurrences(of: "~0", with: "~")
            guard let next = (value as? [String: Any])?[key] else { throw WebAuditError.invalidProfile("해결하지 못한 $ref") }
            value = next
        }
        guard let target = value as? [String: Any] else { throw WebAuditError.invalidProfile("$ref 대상 형식 오류") }
        return try resolve(target, document: document, depth: depth + 1)
    }
    private static func stringValue(_ schema: [String: Any]) -> String {
        switch schema["type"] as? String {
        case "integer", "number":
            let minimum = (schema["minimum"] as? NSNumber)?.doubleValue ?? 1
            let maximum = (schema["maximum"] as? NSNumber)?.doubleValue ?? max(minimum, 1)
            guard minimum.isFinite, maximum.isFinite, minimum <= maximum else { return "1" }
            let value = min(max(1, minimum), maximum)
            if (schema["type"] as? String) == "integer" { return String(format: "%.0f", value.rounded(.up)) }
            return String(value)
        case "boolean": return "true"
        default:
            let minimum = max(0, min(256, schema["minLength"] as? Int ?? 1))
            let maximum = max(0, min(256, schema["maxLength"] as? Int ?? 16))
            let size = min(maximum, max(minimum, min(11, maximum)))
            return String(repeating: "a", count: size)
        }
    }
    private static func invalidString(_ schema: [String: Any]) -> String? {
        if ["integer", "number", "boolean"].contains(schema["type"] as? String ?? "") { return "koda-invalid-type" }
        if let minimum = schema["minLength"] as? Int, minimum > 0 { return "" }
        if let maximum = schema["maxLength"] as? Int, (0...256).contains(maximum) { return String(repeating: "x", count: maximum + 1) }
        return nil
    }
    private static func pathValue(_ schema: [String: Any]) -> String { stringValue(schema) }
    private static func jsonBody(_ schema: [String: Any], document: [String: Any]) throws -> Data {
        let value = try sample(schema, document: document, depth: 0)
        let data = try JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed, .sortedKeys])
        guard data.count <= 16_384 else { throw WebAuditError.invalidProfile("API JSON body 한도 초과") }
        return data
    }
    private static func sample(_ raw: [String: Any], document: [String: Any], depth: Int) throws -> Any {
        guard depth < 4 else { throw WebAuditError.invalidProfile("API JSON schema 표본 깊이 한도 초과") }
        let schema = try resolve(raw, document: document, depth: 0)
        if schema["oneOf"] != nil || schema["anyOf"] != nil || schema["allOf"] != nil { throw WebAuditError.invalidProfile("합성 JSON schema 표본은 지원하지 않습니다.") }
        switch schema["type"] as? String ?? (schema["properties"] == nil ? "string" : "object") {
        case "integer", "number": return Double(stringValue(schema)) ?? 1
        case "boolean": return true
        case "array": return [try sample(schema["items"] as? [String: Any] ?? [:], document: document, depth: depth + 1)]
        case "object":
            let properties = schema["properties"] as? [String: [String: Any]] ?? [:]
            var result: [String: Any] = [:]
            for key in properties.keys.sorted().prefix(8) { result[String(key.prefix(128))] = try sample(properties[key]!, document: document, depth: depth + 1) }
            return result
        default: return stringValue(schema)
        }
    }
}
