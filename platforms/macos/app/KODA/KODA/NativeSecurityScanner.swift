import zlib
import AppKit
import CoreText
import Foundation

struct NativeFinding: Hashable {
    let ruleID: String
    let severity: String
    let category: String
    let title: String
    let path: String
    let line: Int?
    var evidence: String
    let recommendation: String
    // Optional reachability label for dependency findings: "" / "reachable" / "unreachable" / "unknown".
    var reachable: String = ""
    // Source regex matches are review candidates unless a context analyzer
    // explicitly confirms a source-to-sink path.
    var verificationStatus: String = "confirmed"
    var verificationNote: String = ""
    // Optional AI triage labels (see NativeAITriage). Severity is never derived from these.
    var triageVerdict: String = ""
    var triageConfidence: Double? = nil
    var triageNote: String = ""
}

struct NativeScanResult {
    let findings: [NativeFinding]
    let warnings: [String]
    let targetCount: Int
    let scannedFileCount: Int
    let generatedAt: Date

    var riskScore: Int {
        findings.reduce(0) { total, finding in
            guard finding.verificationStatus == "confirmed" else { return total }
            return total + Self.score(for: finding.severity)
        }
    }

    static func score(for severity: String) -> Int {
        switch severity {
        case "critical": return 100
        case "high": return 40
        case "medium": return 10
        case "low": return 3
        default: return 1
        }
    }
}

enum NativeScanError: Error, LocalizedError {
    case unsafeArchivePath(String)
    case unsupportedArchive(String)
    case corruptArchive(String)
    case compressionFailed(String)
    case archiveLimit(String)

    var errorDescription: String? {
        switch self {
        case .unsafeArchivePath(let path):
            return "압축파일에 안전하지 않은 경로가 있습니다: \(path)"
        case .unsupportedArchive(let path):
            return "지원하지 않는 압축 형식입니다: \(path)"
        case .corruptArchive(let path):
            return "압축파일을 읽을 수 없습니다: \(path)"
        case .compressionFailed(let path):
            return "압축 해제에 실패했습니다: \(path)"
        case .archiveLimit(let path):
            return "압축파일 처리 한도를 초과했습니다: \(path)"
        }
    }
}

private struct NativeIgnoreRule {
    let rule: String
    let path: String
    let until: String

    func matches(_ finding: NativeFinding, targetName: String) -> Bool {
        if isExpired {
            return false
        }
        if rule != "*" && rule != finding.ruleID && rule != finding.category {
            return false
        }
        let relativePath = finding.path.hasPrefix("\(targetName)/")
            ? String(finding.path.dropFirst(targetName.count + 1))
            : finding.path
        return globMatches(path, relativePath) || globMatches(path, URL(fileURLWithPath: relativePath).lastPathComponent)
    }

    private var isExpired: Bool {
        guard !until.isEmpty else { return false }
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        guard let expiry = formatter.date(from: until) else {
            return false
        }
        return expiry < Calendar.current.startOfDay(for: Date())
    }

    private func globMatches(_ pattern: String, _ value: String) -> Bool {
        let regex = "^" + NSRegularExpression.escapedPattern(for: pattern)
            .replacingOccurrences(of: "\\*\\*", with: ".*")
            .replacingOccurrences(of: "\\*", with: "[^/]*")
            .replacingOccurrences(of: "\\?", with: ".") + "$"
        return value.range(of: regex, options: .regularExpression) != nil
    }
}

private enum NativeIgnoreRules {
    static func load(from root: URL) -> [NativeIgnoreRule] {
        for filename in ["koda-ignore.yml", ".koda-ignore.yml"] {
            let file = root.appendingPathComponent(filename)
            if let text = try? String(contentsOf: file, encoding: .utf8) {
                return parse(text)
            }
        }
        return []
    }

    private static func parse(_ text: String) -> [NativeIgnoreRule] {
        var rules: [NativeIgnoreRule] = []
        var current: [String: String] = [:]

        for rawLine in text.components(separatedBy: .newlines) {
            let stripped = rawLine.components(separatedBy: "#").first?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if stripped.isEmpty || stripped == "ignore:" {
                continue
            }
            if stripped.hasPrefix("- ") {
                appendRule(current, to: &rules)
                current = [:]
                let rest = String(stripped.dropFirst(2)).trimmingCharacters(in: .whitespaces)
                assign(rest, to: &current)
            } else {
                assign(stripped, to: &current)
            }
        }
        appendRule(current, to: &rules)
        return rules
    }

    private static func assign(_ line: String, to current: inout [String: String]) {
        guard let separator = line.firstIndex(of: ":") else {
            return
        }
        let key = line[..<separator].trimmingCharacters(in: .whitespaces)
        let value = line[line.index(after: separator)...]
            .trimmingCharacters(in: .whitespaces)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        current[key] = value
    }

    private static func appendRule(_ current: [String: String], to rules: inout [NativeIgnoreRule]) {
        guard !current.isEmpty else {
            return
        }
        rules.append(
            NativeIgnoreRule(
                rule: current["rule"] ?? current["rule_id"] ?? "*",
                path: current["path"] ?? "*",
                until: current["until"] ?? ""
            )
        )
    }
}

final class NativeSecurityScanner {
    private let fileManager: FileManager
    private let maxFileSize = 524_288
    private let maxArchiveInputBytes = 256 * 1024 * 1024
    private let maxArchiveMemberBytes = 256 * 1024 * 1024
    private let maxArchiveExpandedBytes = 512 * 1024 * 1024
    private let maxArchiveEntries = 10_000
    private let maxArchiveDepth = 5
    private struct ArchiveBudget {
        var expandedBytes = 0
        var entries = 0
    }
    private let excludedDirectoryNames: Set<String> = [
        ".git",
        ".hg",
        ".svn",
        ".build",
        ".cache",
        ".mypy_cache",
        ".next",
        ".omx",
        ".playwright-cli",
        ".pytest_cache",
        ".terraform",
        ".venv",
        "DerivedData",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "output",
        "reports",
        "target",
        "venv",
    ]

    init(fileManager: FileManager = .default) {
        self.fileManager = fileManager
    }

    func scan(targets: [URL], screenQualityOnly: Bool = false) throws -> NativeScanResult {
        let temporaryRoot = fileManager.temporaryDirectory.appendingPathComponent("KODA-native-scan-\(UUID().uuidString)")
        try fileManager.createDirectory(at: temporaryRoot, withIntermediateDirectories: true)
        defer {
            try? fileManager.removeItem(at: temporaryRoot)
        }

        var findings: [NativeFinding] = []
        var warnings: [String] = []
        var scannedFileCount = 0
        var archiveBudget = ArchiveBudget()

        for target in targets {
            let resolvedTarget = target.standardizedFileURL
            guard fileManager.fileExists(atPath: resolvedTarget.path) else {
                warnings.append("대상이 존재하지 않습니다: \(resolvedTarget.path)")
                continue
            }

            let targetName = resolvedTarget.lastPathComponent.isEmpty ? resolvedTarget.path : resolvedTarget.lastPathComponent
            let findingStartIndex = findings.count
            if isArchive(resolvedTarget) {
                do {
                    let extractedRoot = try extractArchive(resolvedTarget, under: temporaryRoot, budget: &archiveBudget, depth: 1)
                    var scannedFileURLs: [URL] = []
                    scanDirectory(
                        extractedRoot,
                        targetName: targetName,
                        originalRoot: extractedRoot,
                        screenQualityOnly: screenQualityOnly,
                        findings: &findings,
                        warnings: &warnings,
                        scannedFileCount: &scannedFileCount,
                        scannedFileURLs: &scannedFileURLs,
                        archiveBudget: &archiveBudget,
                        archiveDepth: 1
                    )
                    if !screenQualityOnly {
                        appendFindings(checkPrevention(root: extractedRoot, files: scannedFileURLs), targetName: targetName, findings: &findings)
                    }
                } catch {
                    warnings.append(error.localizedDescription)
                }
                let ignored = applyIgnoreRules(to: &findings, startingAt: findingStartIndex, root: resolvedTarget.deletingLastPathComponent(), targetName: targetName)
                if ignored > 0 {
                    warnings.append("예외 파일(koda-ignore.yml)로 \(ignored)건 제외: \(targetName)")
                }
                continue
            }

            if isDirectory(resolvedTarget) {
                var scannedFileURLs: [URL] = []
                scanDirectory(
                    resolvedTarget,
                    targetName: targetName,
                    originalRoot: resolvedTarget,
                    screenQualityOnly: screenQualityOnly,
                    findings: &findings,
                    warnings: &warnings,
                    scannedFileCount: &scannedFileCount,
                    scannedFileURLs: &scannedFileURLs,
                    archiveBudget: &archiveBudget,
                    archiveDepth: 0
                )
                if !screenQualityOnly {
                    appendFindings(checkPrevention(root: resolvedTarget, files: scannedFileURLs), targetName: targetName, findings: &findings)
                }
            } else {
                scanFile(
                    resolvedTarget,
                    targetName: targetName,
                    root: resolvedTarget.deletingLastPathComponent(),
                    screenQualityOnly: screenQualityOnly,
                    findings: &findings,
                    scannedFileCount: &scannedFileCount
                )
            }
            let ignoreRoot = isDirectory(resolvedTarget) ? resolvedTarget : resolvedTarget.deletingLastPathComponent()
            let ignored = applyIgnoreRules(to: &findings, startingAt: findingStartIndex, root: ignoreRoot, targetName: targetName)
            if ignored > 0 {
                warnings.append("예외 파일(koda-ignore.yml)로 \(ignored)건 제외: \(targetName)")
            }
        }

        let disabledRules = KodaRuleSettings.disabledIDs()
        return NativeScanResult(
            findings: findings
                .filter { disabledRules.isEmpty || !disabledRules.contains($0.ruleID) }
                .sorted { left, right in
                    let leftRank = severityRank(left.severity)
                    let rightRank = severityRank(right.severity)
                    if leftRank != rightRank { return leftRank > rightRank }
                    if left.path != right.path { return left.path < right.path }
                    return (left.line ?? 0) < (right.line ?? 0)
                },
            warnings: warnings,
            targetCount: targets.count,
            scannedFileCount: scannedFileCount,
            generatedAt: Date()
        )
    }

    // MARK: - Host (endpoint) posture

    /// Read-only macOS endpoint security posture checks (no file targets).
    /// Mirrors the Python `host-scan` posture checks. Each probe degrades to a
    /// warning if its command is unavailable so one failure never aborts the run.
    func scanHost() -> NativeScanResult {
        if Self.isSandboxed {
            let findings = [
                Self.hostFinding(
                    "host.macos.sandbox-limited", "info",
                    "App Store 앱에서는 호스트 보안 상태를 자동 확정하지 않습니다",
                    resource: "macos/sandbox",
                    evidence: "App Sandbox 활성 — 시스템 명령 결과를 PASS/FAIL 근거로 사용하지 않음",
                    recommendation: "각 항목의 '해당 설정 열기'에서 현재 값을 직접 확인하세요."
                ),
            ] + Self.sandboxUnverifiedFindings()
            return NativeScanResult(
                findings: findings,
                warnings: ["App Sandbox에서는 시스템 보안 상태를 신뢰성 있게 조회할 수 없어 모든 호스트 항목을 미확인으로 표시했습니다."],
                targetCount: 1,
                scannedFileCount: 0,
                generatedAt: Date()
            )
        }

        var posture: [NativeFinding] = []
        var warnings: [String] = []

        // Core posture (A/C/E)
        posture.append(contentsOf: Self.checkSystemIntegrityProtection(warnings: &warnings))
        posture.append(contentsOf: Self.checkFileVault(warnings: &warnings))
        posture.append(contentsOf: Self.checkGatekeeper(warnings: &warnings))
        posture.append(contentsOf: Self.checkApplicationFirewall(warnings: &warnings))
        posture.append(contentsOf: Self.checkFirewallStealthMode(warnings: &warnings))
        posture.append(contentsOf: Self.checkAutomaticSecurityUpdates(warnings: &warnings))
        // Account & lock controls (D)
        posture.append(contentsOf: Self.checkAutomaticLogin(warnings: &warnings))
        posture.append(contentsOf: Self.checkGuestAccount(warnings: &warnings))
        posture.append(contentsOf: Self.checkScreenLock(warnings: &warnings))

        var findings: [NativeFinding] = []

        // #3 Posture drift: compare against the saved baseline before overwriting it.
        let drift = Self.driftFindings(current: posture)

        findings.append(contentsOf: drift)
        findings.append(contentsOf: posture)
        Self.saveBaseline(posture)

        return NativeScanResult(
            findings: findings.sorted { left, right in
                let leftRank = severityRank(left.severity)
                let rightRank = severityRank(right.severity)
                if leftRank != rightRank { return leftRank > rightRank }
                return left.path < right.path
            },
            warnings: warnings,
            targetCount: 1,
            scannedFileCount: 0,
            generatedAt: Date()
        )
    }

    static var isSandboxed: Bool {
        ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] != nil
    }

    private static func hostFinding(
        _ ruleID: String,
        _ severity: String,
        _ title: String,
        resource: String,
        evidence: String = "",
        recommendation: String = ""
    ) -> NativeFinding {
        return NativeFinding(
            ruleID: ruleID,
            severity: severity,
            category: "host",
            title: title,
            path: resource,
            line: nil,
            evidence: evidence,
            recommendation: recommendation
        )
    }

    private static func unverifiedHostFinding(
        _ ruleID: String,
        _ title: String,
        resource: String,
        recommendation: String
    ) -> NativeFinding {
        var finding = hostFinding(
            ruleID,
            "info",
            title,
            resource: resource,
            evidence: "App Sandbox에서 시스템 상태를 신뢰성 있게 조회할 수 없어 판정하지 않았습니다.",
            recommendation: recommendation
        )
        finding.verificationStatus = "unverified"
        finding.verificationNote = "App Sandbox 제한"
        return finding
    }

    private static func sandboxUnverifiedFindings() -> [NativeFinding] {
        [
            unverifiedHostFinding(
                "host.macos.filevault-unverified",
                "FileVault 디스크 암호화 상태 미확인",
                resource: "macos/filevault",
                recommendation: "시스템 설정 > 개인정보 보호 및 보안 > FileVault에서 현재 상태를 확인하세요."
            ),
            unverifiedHostFinding(
                "host.macos.sip-unverified",
                "시스템 무결성 보호(SIP) 상태 미확인",
                resource: "macos/system-integrity-protection",
                recommendation: "터미널에서 csrutil status로 확인하세요. 변경이 필요하면 macOS 복구 모드에서 조치해야 합니다."
            ),
            unverifiedHostFinding(
                "host.macos.gatekeeper-unverified",
                "Gatekeeper 상태 미확인",
                resource: "macos/gatekeeper",
                recommendation: "시스템 설정 > 개인정보 보호 및 보안 > 보안에서 허용된 앱 출처를 확인하세요."
            ),
            unverifiedHostFinding(
                "host.macos.firewall-unverified",
                "응용프로그램 방화벽 상태 미확인",
                resource: "macos/application-firewall",
                recommendation: "시스템 설정 > 네트워크 > 방화벽에서 현재 상태를 확인하세요."
            ),
            unverifiedHostFinding(
                "host.macos.firewall-stealth-unverified",
                "방화벽 스텔스 모드 상태 미확인",
                resource: "macos/firewall-stealth-mode",
                recommendation: "시스템 설정 > 네트워크 > 방화벽 > 옵션에서 스텔스 모드를 확인하세요."
            ),
            unverifiedHostFinding(
                "host.macos.auto-security-updates-unverified",
                "자동 업데이트 상태 미확인",
                resource: "macos/automatic-security-updates",
                recommendation: "시스템 설정 > 일반 > 소프트웨어 업데이트 > 자동 업데이트와 개인정보 보호 및 보안 > 백그라운드 보안 개선을 확인하세요."
            ),
            unverifiedHostFinding(
                "host.macos.auto-login-unverified",
                "자동 로그인 상태 미확인",
                resource: "macos/automatic-login",
                recommendation: "시스템 설정 > 사용자 및 그룹 > 자동 로그인에서 '끔'인지 확인하세요. FileVault가 켜져 있으면 자동 로그인은 비활성화됩니다."
            ),
            unverifiedHostFinding(
                "host.macos.guest-account-unverified",
                "게스트 계정 상태 미확인",
                resource: "macos/guest-account",
                recommendation: "시스템 설정 > 사용자 및 그룹 > 게스트 사용자에서 로그인을 허용하지 않도록 설정하세요."
            ),
            unverifiedHostFinding(
                "host.macos.screen-lock-unverified",
                "화면 잠금 암호 요구 상태 미확인",
                resource: "macos/screen-lock",
                recommendation: "시스템 설정 > 잠금 화면 > 화면 보호기 시작 또는 디스플레이 꺼짐 후 암호 요구를 '즉시'로 설정하세요."
            ),
        ]
    }

    /// Run a read-only command and capture its successful output. Failed commands
    /// are never returned as posture evidence.
    private static func runReadOnlyCommand(_ executablePath: String, _ arguments: [String]) -> String? {
        guard FileManager.default.isExecutableFile(atPath: executablePath) else { return nil }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executablePath)
        process.arguments = arguments
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        do {
            try process.run()
        } catch {
            return nil
        }
        let outData = stdout.fileHandleForReading.readDataToEndOfFile()
        let errData = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let out = (String(data: outData, encoding: .utf8) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let err = (String(data: errData, encoding: .utf8) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        return acceptedCommandOutput(stdout: out, stderr: err, terminationStatus: process.terminationStatus)
    }

    static func acceptedCommandOutput(stdout: String, stderr: String, terminationStatus: Int32) -> String? {
        guard terminationStatus == 0 else { return nil }
        let output = stdout.isEmpty ? stderr : stdout
        return output.isEmpty ? nil : output
    }

    private static func checkSystemIntegrityProtection(warnings: inout [String]) -> [NativeFinding] {
        guard let output = runReadOnlyCommand("/usr/bin/csrutil", ["status"]) else {
            warnings.append("SIP 상태를 확인할 수 없습니다.")
            return []
        }
        let lowered = output.lowercased()
        if lowered.contains("system integrity protection status: enabled") {
            return [hostFinding("host.macos.sip-enabled", "info", "시스템 무결성 보호(SIP)가 켜져 있습니다", resource: "macos/system-integrity-protection", evidence: output)]
        }
        if lowered.contains("system integrity protection status: disabled") {
            return [hostFinding(
                "host.macos.sip-disabled", "high", "시스템 무결성 보호(SIP)가 꺼져 있습니다",
                resource: "macos/system-integrity-protection", evidence: output,
                recommendation: "macOS 복구 모드에서 'csrutil enable'을 실행한 뒤 재부팅하세요. 시스템 설정에서는 변경할 수 없습니다."
            )]
        }
        warnings.append("SIP 응답을 해석할 수 없습니다: \(output)")
        return []
    }

    private static func checkFileVault(warnings: inout [String]) -> [NativeFinding] {
        guard let output = runReadOnlyCommand("/usr/bin/fdesetup", ["status"]) else {
            warnings.append("FileVault 상태를 확인할 수 없습니다.")
            return []
        }
        let lowered = output.lowercased()
        if lowered.contains("filevault is on") {
            return [hostFinding("host.macos.filevault-on", "info", "FileVault 디스크 암호화가 켜져 있습니다", resource: "macos/filevault", evidence: output)]
        }
        if lowered.contains("filevault is off") {
            return [hostFinding(
                "host.macos.filevault-off", "high", "FileVault 디스크 암호화가 꺼져 있습니다",
                resource: "macos/filevault", evidence: output,
                recommendation: "시스템 설정 > 개인정보 보호 및 보안 > FileVault에서 켜고 복구 키를 안전하게 보관하세요."
            )]
        }
        warnings.append("FileVault 응답을 해석할 수 없습니다: \(output)")
        return []
    }

    private static func checkGatekeeper(warnings: inout [String]) -> [NativeFinding] {
        guard let output = runReadOnlyCommand("/usr/sbin/spctl", ["--status"]) else {
            warnings.append("Gatekeeper 상태를 확인할 수 없습니다.")
            return []
        }
        let lowered = output.lowercased()
        if lowered.contains("assessments enabled") {
            return [hostFinding("host.macos.gatekeeper-enabled", "info", "Gatekeeper 검사가 켜져 있습니다", resource: "macos/gatekeeper", evidence: output)]
        }
        if lowered.contains("assessments disabled") {
            return [hostFinding(
                "host.macos.gatekeeper-disabled", "high", "Gatekeeper 검사가 꺼져 있습니다",
                resource: "macos/gatekeeper", evidence: output,
                recommendation: "시스템 설정 > 개인정보 보호 및 보안 > 보안에서 허용된 앱 출처를 확인하세요. macOS 15 이상에서는 MDM 구성 프로파일로 관리할 수 있습니다."
            )]
        }
        warnings.append("Gatekeeper 응답을 해석할 수 없습니다: \(output)")
        return []
    }

    private static func checkApplicationFirewall(warnings: inout [String]) -> [NativeFinding] {
        guard let output = runReadOnlyCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]) else {
            warnings.append("응용프로그램 방화벽 상태를 확인할 수 없습니다.")
            return []
        }
        let lowered = output.lowercased()
        if lowered.contains("state = 1") || lowered.contains("state = 2") {
            return [hostFinding("host.macos.firewall-enabled", "info", "응용프로그램 방화벽이 켜져 있습니다", resource: "macos/application-firewall", evidence: output)]
        }
        if lowered.contains("state = 0") {
            return [hostFinding(
                "host.macos.firewall-disabled", "medium", "응용프로그램 방화벽이 꺼져 있습니다",
                resource: "macos/application-firewall", evidence: output,
                recommendation: "시스템 설정 > 네트워크 > 방화벽에서 방화벽을 켜세요."
            )]
        }
        warnings.append("응용프로그램 방화벽 응답을 해석할 수 없습니다: \(output)")
        return []
    }

    private static func checkFirewallStealthMode(warnings: inout [String]) -> [NativeFinding] {
        guard let output = runReadOnlyCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getstealthmode"]) else {
            warnings.append("방화벽 스텔스 모드 상태를 확인할 수 없습니다.")
            return []
        }
        let lowered = output.lowercased()
        if lowered.contains("stealth mode is on") {
            return [hostFinding("host.macos.firewall-stealth-enabled", "info", "방화벽 스텔스 모드가 켜져 있습니다", resource: "macos/firewall-stealth-mode", evidence: output)]
        }
        if lowered.contains("stealth mode is off") {
            return [hostFinding(
                "host.macos.firewall-stealth-disabled", "low", "방화벽 스텔스 모드가 꺼져 있습니다",
                resource: "macos/firewall-stealth-mode", evidence: output,
                recommendation: "시스템 설정 > 네트워크 > 방화벽 > 옵션에서 스텔스 모드를 켜세요."
            )]
        }
        warnings.append("방화벽 스텔스 모드 응답을 해석할 수 없습니다: \(output)")
        return []
    }

    private static func checkAutomaticSecurityUpdates(warnings: inout [String]) -> [NativeFinding] {
        let domain = "/Library/Preferences/com.apple.SoftwareUpdate"
        let scheduled = runReadOnlyCommand("/usr/sbin/softwareupdate", ["--schedule"])
        let scheduledState: Bool?
        if scheduled?.lowercased().contains("turned on") == true {
            scheduledState = true
        } else if scheduled?.lowercased().contains("turned off") == true {
            scheduledState = false
        } else {
            scheduledState = nil
        }

        let keys = ["AutomaticDownload", "AutomaticallyInstallMacOSUpdates", "ConfigDataInstall", "CriticalUpdateInstall"]
        var states: [(String, Bool?)] = [("AutomaticCheckEnabled", scheduledState)]
        for key in keys {
            let raw = runReadOnlyCommand("/usr/bin/defaults", ["read", domain, key])?.lowercased()
            let state: Bool?
            switch raw {
            case "1", "true", "yes": state = true
            case "0", "false", "no": state = false
            default: state = nil
            }
            states.append((key, state))
        }

        let evidence = states.map { "\($0.0)=\($0.1.map { $0 ? "1" : "0" } ?? "unverified")" }.joined(separator: ", ")
        let disabled = states.compactMap { $0.1 == false ? $0.0 : nil }
        let unverified = states.compactMap { $0.1 == nil ? $0.0 : nil }
        if disabled.isEmpty && unverified.isEmpty {
            return [hostFinding("host.macos.auto-security-updates-enabled", "info", "CIS 자동 업데이트 설정이 모두 켜져 있습니다", resource: "macos/automatic-security-updates", evidence: evidence)]
        }
        if disabled.isEmpty {
            warnings.append("일부 자동 업데이트 설정을 확인할 수 없습니다: \(unverified.joined(separator: ", "))")
            return []
        }

        let labels = [
            "AutomaticCheckEnabled": "업데이트 자동 확인",
            "AutomaticDownload": "새 업데이트 다운로드",
            "AutomaticallyInstallMacOSUpdates": "macOS 업데이트 설치",
            "ConfigDataInstall": "시스템 데이터 파일 설치",
            "CriticalUpdateInstall": "보안 업데이트 설치",
        ]
        let disabledLabels = disabled.map { labels[$0] ?? $0 }.joined(separator: ", ")
        return [hostFinding(
            "host.macos.auto-security-updates-disabled", "medium", "일부 자동 업데이트 옵션이 꺼져 있습니다",
            resource: "macos/automatic-security-updates", evidence: evidence,
            recommendation: "시스템 설정 > 일반 > 소프트웨어 업데이트 > 자동 업데이트에서 다음 항목을 켜세요: \(disabledLabels). macOS 26에서는 개인정보 보호 및 보안 > 백그라운드 보안 개선의 자동 설치도 확인하세요."
        )]
    }

    // MARK: - Account & lock controls (#1)

    private static func checkAutomaticLogin(warnings: inout [String]) -> [NativeFinding] {
        guard let output = runReadOnlyCommand("/usr/sbin/sysadminctl", ["-autologin", "status"]) else {
            warnings.append("자동 로그인 상태를 확인할 수 없습니다.")
            return []
        }
        let lowered = output.lowercased()
        if lowered.contains("automatic login is disabled") {
            return [hostFinding("host.macos.auto-login-disabled", "info", "자동 로그인이 꺼져 있습니다", resource: "macos/automatic-login", evidence: output)]
        }
        if lowered.contains("automatic login is enabled") {
            return [hostFinding(
                "host.macos.auto-login-enabled", "high",
                "자동 로그인이 켜져 있습니다",
                resource: "macos/automatic-login", evidence: output,
                recommendation: "시스템 설정 > 사용자 및 그룹 > 자동 로그인을 '끔'으로 설정하세요. 분실 또는 도난 시 잠금 없이 접근될 수 있습니다."
            )]
        }
        warnings.append("자동 로그인 응답을 해석할 수 없습니다: \(output)")
        return []
    }

    private static func checkGuestAccount(warnings: inout [String]) -> [NativeFinding] {
        guard let output = runReadOnlyCommand("/usr/sbin/sysadminctl", ["-guestAccount", "status"]) else {
            warnings.append("게스트 계정 상태를 확인할 수 없습니다.")
            return []
        }
        let lowered = output.lowercased()
        if lowered.contains("guest account") && lowered.contains("disabled") {
            return [hostFinding("host.macos.guest-account-disabled", "info", "게스트 계정이 비활성화되어 있습니다", resource: "macos/guest-account", evidence: output)]
        }
        if lowered.contains("guest account") && lowered.contains("enabled") {
            return [hostFinding(
                "host.macos.guest-account-enabled", "medium",
                "게스트 계정이 활성화되어 있습니다",
                resource: "macos/guest-account", evidence: output,
                recommendation: "시스템 설정 > 사용자 및 그룹 > 게스트 사용자에서 이 컴퓨터 로그인을 허용하지 않도록 설정하세요."
            )]
        }
        warnings.append("게스트 계정 응답을 해석할 수 없습니다: \(output)")
        return []
    }

    private static func checkScreenLock(warnings: inout [String]) -> [NativeFinding] {
        guard let output = runReadOnlyCommand("/usr/sbin/sysadminctl", ["-screenLock", "status"]) else {
            warnings.append("화면 잠금 비밀번호 설정을 확인할 수 없습니다.")
            return []
        }
        let lowered = output.lowercased()
        let marker = "screenlock delay is "
        var delaySeconds: Double?
        if let range = lowered.range(of: marker) {
            let suffix = lowered[range.upperBound...]
            if let token = suffix.split(whereSeparator: { $0.isWhitespace }).first {
                let number = String(token).trimmingCharacters(in: CharacterSet(charactersIn: "0123456789.-").inverted)
                delaySeconds = Double(number)
            }
        }
        let isImmediate = lowered.contains("screenlock delay is immediate")
        let isOff = lowered.contains("screenlock is off") || lowered.contains("screenlock disabled")
        if isImmediate || delaySeconds.map({ $0 >= 0 && $0 <= 5 }) == true {
            return [hostFinding("host.macos.screen-lock-enabled", "info", "화면 잠금 후 즉시 비밀번호를 요구합니다", resource: "macos/screen-lock", evidence: output)]
        }
        if isOff || delaySeconds.map({ $0 > 5 }) == true {
            return [hostFinding(
                "host.macos.screen-lock-disabled", "medium",
                "잠금 후 비밀번호 요구가 꺼져 있거나 5초를 초과합니다",
                resource: "macos/screen-lock", evidence: output,
                recommendation: "시스템 설정 > 잠금 화면에서 '화면 보호기 시작 또는 디스플레이 꺼짐 후 암호 요구'를 '즉시'로 설정하세요."
            )]
        }
        warnings.append("화면 잠금 응답을 해석할 수 없습니다: \(output)")
        return []
    }

    // MARK: - Posture drift (#3)

    private static var baselineURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser
        return base.appendingPathComponent("KODA", isDirectory: true).appendingPathComponent("host-posture-baseline-v2.json")
    }

    /// Map of resource identifier -> severity from the previous host scan.
    private static func loadBaseline() -> [String: String] {
        guard let data = try? Data(contentsOf: baselineURL),
              let map = try? JSONDecoder().decode([String: String].self, from: data) else {
            return [:]
        }
        return map
    }

    private static func saveBaseline(_ findings: [NativeFinding]) {
        var map: [String: String] = [:]
        for finding in findings { map[finding.path] = finding.severity }
        guard let data = try? JSONEncoder().encode(map) else { return }
        try? FileManager.default.createDirectory(at: baselineURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: baselineURL, options: .atomic)
    }

    /// Emit findings when a control regressed (was passing, now failing) or
    /// improved since the last scan, so users notice posture changes over time.
    private static func driftFindings(current: [NativeFinding]) -> [NativeFinding] {
        let baseline = loadBaseline()
        guard !baseline.isEmpty else { return [] }
        var drift: [NativeFinding] = []
        for finding in current {
            guard let previous = baseline[finding.path] else { continue }
            let wasProblem = previous != "info"
            let isProblem = finding.severity != "info"
            if !wasProblem && isProblem {
                drift.append(hostFinding(
                    "host.drift.regressed", "high",
                    "보안 상태 악화 감지: \(finding.title)",
                    resource: "drift/\(finding.path)",
                    evidence: "이전: 양호(\(previous)) → 현재: \(finding.severity)",
                    recommendation: "최근 변경으로 이 항목이 약화되었습니다. 즉시 점검하세요. (\(finding.recommendation))"
                ))
            } else if wasProblem && !isProblem {
                drift.append(hostFinding(
                    "host.drift.improved", "info",
                    "보안 상태 개선 감지: \(finding.title)",
                    resource: "drift/\(finding.path)",
                    evidence: "이전: \(previous) → 현재: 양호"
                ))
            }
        }
        return drift
    }

    func writeHTMLReport(_ result: NativeScanResult, to output: URL, language: AppLanguage = .ko) throws {
        try renderHTML(result, language: language).write(to: output, atomically: true, encoding: .utf8)
    }

    func writeMarkdownReport(_ result: NativeScanResult, to output: URL, language: AppLanguage = .ko) throws {
        try renderMarkdown(result, language: language).write(to: output, atomically: true, encoding: .utf8)
    }

    func markdownReport(_ result: NativeScanResult, language: AppLanguage = .ko) -> String {
        renderMarkdown(result, language: language)
    }

    func writePDFReport(_ result: NativeScanResult, to output: URL, language: AppLanguage = .ko) throws {
        let pageRect = CGRect(x: 0, y: 0, width: 595, height: 842)
        let data = NSMutableData()
        var mediaBox = pageRect
        guard let consumer = CGDataConsumer(data: data as CFMutableData),
              let context = CGContext(consumer: consumer, mediaBox: &mediaBox, nil) else {
            throw CocoaError(.fileWriteUnknown)
        }

        context.beginPDFPage(nil)
        drawPDFSummaryPage(result, language: language, context: context, pageRect: pageRect)
        context.endPDFPage()
        drawPDFFindingTablePages(result, language: language, context: context, pageRect: pageRect)

        context.closePDF()
        try data.write(to: output, options: .atomic)
    }

    private func drawPDFSummaryPage(
        _ result: NativeScanResult,
        language: AppLanguage,
        context: CGContext,
        pageRect: CGRect
    ) {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let generated = formatter.string(from: result.generatedAt)
        let severityCounts = Dictionary(grouping: result.findings, by: \.severity).mapValues(\.count)

        context.setFillColor(pdfColor(245, 247, 251).cgColor)
        context.fill(pageRect)

        let headerRect = topRect(x: 0, y: 0, width: pageRect.width, height: 112, pageRect: pageRect)
        context.setFillColor(pdfColor(11, 18, 32).cgColor)
        context.fill(headerRect)

        drawPDFText(
            reportLabel("pageTitle", language: language),
            in: topRect(x: 42, y: 28, width: pageRect.width - 84, height: 34, pageRect: pageRect),
            context: context,
            font: .systemFont(ofSize: 24, weight: .bold),
            color: .white
        )
        drawPDFText(
            "\(reportLabel("generatedAt", language: language)) \(generated) | \(reportLabel("targets", language: language)) \(result.targetCount) | \(reportLabel("scannedFiles", language: language)) \(result.scannedFileCount)",
            in: topRect(x: 42, y: 67, width: pageRect.width - 84, height: 22, pageRect: pageRect),
            context: context,
            font: .systemFont(ofSize: 10.5, weight: .regular),
            color: pdfColor(203, 213, 225)
        )

        let cardTop = CGFloat(138)
        let cardGap = CGFloat(12)
        let cardWidth = (pageRect.width - 84 - cardGap * 3) / 4
        let cards: [(String, String, NSColor)] = [
            (reportLabel("riskScore", language: language), "\(result.riskScore)", pdfColor(194, 65, 12)),
            (reportLabel("criticalHigh", language: language), "\((severityCounts["critical"] ?? 0) + (severityCounts["high"] ?? 0))", pdfColor(153, 27, 27)),
            (severityLabel("medium", language: language), "\(severityCounts["medium"] ?? 0)", pdfColor(180, 83, 9)),
            (reportLabel("lowInfo", language: language), "\((severityCounts["low"] ?? 0) + (severityCounts["info"] ?? 0))", pdfColor(37, 99, 235)),
        ]

        for (index, card) in cards.enumerated() {
            let x = CGFloat(42) + CGFloat(index) * (cardWidth + cardGap)
            let rect = topRect(x: x, y: cardTop, width: cardWidth, height: 88, pageRect: pageRect)
            drawPDFRoundedRect(rect, fill: .white, stroke: pdfColor(216, 222, 233), context: context)
            drawPDFText(
                card.0,
                in: topRect(x: x + 14, y: cardTop + 13, width: cardWidth - 28, height: 18, pageRect: pageRect),
                context: context,
                font: .systemFont(ofSize: 9.5, weight: .bold),
                color: pdfColor(102, 112, 133)
            )
            drawPDFText(
                card.1,
                in: topRect(x: x + 14, y: cardTop + 38, width: cardWidth - 28, height: 36, pageRect: pageRect),
                context: context,
                font: .systemFont(ofSize: 26, weight: .heavy),
                color: card.2
            )
        }

        let formulaRect = topRect(x: 42, y: 252, width: pageRect.width - 84, height: 82, pageRect: pageRect)
        drawPDFRoundedRect(formulaRect, fill: .white, stroke: pdfColor(216, 222, 233), context: context)
        drawPDFText(
            reportLabel("riskFormula", language: language),
            in: topRect(x: 58, y: 267, width: pageRect.width - 116, height: 18, pageRect: pageRect),
            context: context,
            font: .systemFont(ofSize: 11, weight: .bold),
            color: pdfColor(102, 112, 133)
        )
        drawPDFText(
            riskFormula(language: language),
            in: topRect(x: 58, y: 292, width: pageRect.width - 116, height: 28, pageRect: pageRect),
            context: context,
            font: .systemFont(ofSize: 10.5, weight: .regular),
            color: pdfColor(17, 24, 39),
            lineSpacing: 3
        )

        let chartTop = CGFloat(360)
        let chartRect = topRect(x: 42, y: chartTop, width: pageRect.width - 84, height: 210, pageRect: pageRect)
        drawPDFRoundedRect(chartRect, fill: .white, stroke: pdfColor(216, 222, 233), context: context)
        drawPDFText(
            reportLabel("severityDistribution", language: language),
            in: topRect(x: 58, y: chartTop + 16, width: pageRect.width - 116, height: 20, pageRect: pageRect),
            context: context,
            font: .systemFont(ofSize: 12, weight: .bold),
            color: pdfColor(17, 24, 39)
        )
        drawPDFSeverityBars(severityCounts, language: language, top: chartTop + 48, context: context, pageRect: pageRect)

        if !result.warnings.isEmpty {
            let warningSummary = result.warnings.prefix(4).map { "- \(warningText($0, language: language))" }.joined(separator: "\n")
            let warningRect = topRect(x: 42, y: 596, width: pageRect.width - 84, height: 96, pageRect: pageRect)
            drawPDFRoundedRect(warningRect, fill: pdfColor(255, 251, 235), stroke: pdfColor(251, 191, 36), context: context)
            drawPDFText(
                reportLabel("warnings", language: language),
                in: topRect(x: 58, y: 612, width: pageRect.width - 116, height: 18, pageRect: pageRect),
                context: context,
                font: .systemFont(ofSize: 11, weight: .bold),
                color: pdfColor(146, 64, 14)
            )
            drawPDFText(
                warningSummary,
                in: topRect(x: 58, y: 637, width: pageRect.width - 116, height: 42, pageRect: pageRect),
                context: context,
                font: .systemFont(ofSize: 9.5, weight: .regular),
                color: pdfColor(120, 53, 15),
                lineSpacing: 3
            )
        }
    }

    private func drawPDFFindingTablePages(
        _ result: NativeScanResult,
        language: AppLanguage,
        context: CGContext,
        pageRect: CGRect
    ) {
        let marginX = CGFloat(42)
        let tableWidth = pageRect.width - marginX * 2
        let columns: [(String, CGFloat)] = [
            (reportLabel("severity", language: language), 72),
            (reportLabel("finding", language: language), 158),
            (reportLabel("path", language: language), 132),
            (reportLabel("evidenceAction", language: language), tableWidth - 72 - 158 - 132),
        ]
        let headerHeight = CGFloat(30)
        let footerY = pageRect.height - 46
        var y = CGFloat(0)

        func beginTablePage() {
            context.beginPDFPage(nil)
            context.setFillColor(pdfColor(245, 247, 251).cgColor)
            context.fill(pageRect)
            drawPDFText(
                reportLabel("findings", language: language),
                in: topRect(x: 42, y: 34, width: pageRect.width - 84, height: 24, pageRect: pageRect),
                context: context,
                font: .systemFont(ofSize: 16, weight: .bold),
                color: pdfColor(17, 24, 39)
            )
            drawPDFText(
                "\(reportLabel("findings", language: language)) \(result.findings.count) | \(reportLabel("riskScore", language: language)) \(result.riskScore)",
                in: topRect(x: 42, y: 60, width: pageRect.width - 84, height: 18, pageRect: pageRect),
                context: context,
                font: .systemFont(ofSize: 9.5, weight: .regular),
                color: pdfColor(102, 112, 133)
            )
            y = 92
            drawPDFTableHeader(columns: columns, x: marginX, y: y, width: tableWidth, height: headerHeight, context: context, pageRect: pageRect)
            y += headerHeight
        }

        beginTablePage()

        if result.findings.isEmpty {
            let rowRect = topRect(x: marginX, y: y, width: tableWidth, height: 52, pageRect: pageRect)
            drawPDFRoundedRect(rowRect, fill: .white, stroke: pdfColor(216, 222, 233), context: context, cornerRadius: 0)
            drawPDFTableCell(
                reportLabel("noFindings", language: language),
                x: marginX,
                y: y,
                width: tableWidth,
                height: 52,
                context: context,
                pageRect: pageRect,
                font: .systemFont(ofSize: 10, weight: .regular),
                color: pdfColor(17, 24, 39)
            )
            context.endPDFPage()
            return
        }

        for (index, finding) in result.findings.enumerated() {
            let rowHeight = pdfFindingRowHeight(finding, language: language, columns: columns)
            if y + rowHeight > footerY {
                context.endPDFPage()
                beginTablePage()
            }
            drawPDFFindingRow(
                finding,
                rowIndex: index,
                columns: columns,
                x: marginX,
                y: y,
                height: rowHeight,
                language: language,
                context: context,
                pageRect: pageRect
            )
            y += rowHeight
        }
        context.endPDFPage()
    }

    private func renderPDFFindingText(_ result: NativeScanResult, language: AppLanguage) -> String {
        let warnings = result.warnings.isEmpty
            ? ""
            : "\n\(reportLabel("warnings", language: language))\n"
                + result.warnings.map { "- \(warningText($0, language: language))" }.joined(separator: "\n")
                + "\n\n"
        let findings = result.findings.isEmpty
            ? reportLabel("noFindings", language: language)
            : result.findings.enumerated().map { index, finding in
                """
                \(index + 1). [\(severityLabel(finding.severity, language: language))] [\(verificationLabel(finding, language: language))] \(findingTitle(finding, language: language))
                   Rule: \(finding.ruleID)
                   \(reportLabel("category", language: language)): \(categoryLabel(finding.category, language: language))
                   \(reportLabel("path", language: language)): \(finding.path)\(finding.line.map { ":\($0)" } ?? "")
                   \(reportLabel("evidence", language: language)): \(finding.evidence)
                   \(reportLabel("recommendation", language: language)): \(findingRecommendation(finding, language: language))
                """
            }.joined(separator: "\n\n")

        return "\(warnings)\(findings)"
    }

    private func drawPDFTableHeader(
        columns: [(String, CGFloat)],
        x: CGFloat,
        y: CGFloat,
        width: CGFloat,
        height: CGFloat,
        context: CGContext,
        pageRect: CGRect
    ) {
        drawPDFRoundedRect(
            topRect(x: x, y: y, width: width, height: height, pageRect: pageRect),
            fill: pdfColor(248, 250, 252),
            stroke: pdfColor(216, 222, 233),
            context: context,
            cornerRadius: 0
        )
        var currentX = x
        for column in columns {
            drawPDFTableCell(
                column.0,
                x: currentX,
                y: y,
                width: column.1,
                height: height,
                context: context,
                pageRect: pageRect,
                font: .systemFont(ofSize: 8.8, weight: .bold),
                color: pdfColor(102, 112, 133),
                drawBorder: true
            )
            currentX += column.1
        }
    }

    private func drawPDFFindingRow(
        _ finding: NativeFinding,
        rowIndex: Int,
        columns: [(String, CGFloat)],
        x: CGFloat,
        y: CGFloat,
        height: CGFloat,
        language: AppLanguage,
        context: CGContext,
        pageRect: CGRect
    ) {
        let rowFill = rowIndex.isMultiple(of: 2) ? NSColor.white : pdfColor(250, 252, 255)
        let rowWidth = columns.reduce(CGFloat(0)) { partial, column in partial + column.1 }
        drawPDFRoundedRect(topRect(x: x, y: y, width: rowWidth, height: height, pageRect: pageRect), fill: rowFill, stroke: pdfColor(216, 222, 233), context: context, cornerRadius: 0)

        var currentX = x
        let severityRect = topRect(x: currentX + 8, y: y + 12, width: columns[0].1 - 16, height: 21, pageRect: pageRect)
        drawPDFRoundedRect(severityRect, fill: pdfSeverityColor(finding.severity), stroke: pdfSeverityColor(finding.severity), context: context, cornerRadius: 10.5)
        drawPDFText(
            severityLabel(finding.severity, language: language),
            in: severityRect.insetBy(dx: 4, dy: 4),
            context: context,
            font: .systemFont(ofSize: 7.8, weight: .heavy),
            color: .white,
            lineSpacing: 1
        )
        drawPDFCellBorder(x: currentX, y: y, width: columns[0].1, height: height, context: context, pageRect: pageRect)
        currentX += columns[0].1

        drawPDFTableCell(
            pdfTrimmed(
                """
                \(findingTitle(finding, language: language))
                \(finding.ruleID)
                \(categoryLabel(finding.category, language: language))
                """,
                limit: 220
            ),
            x: currentX,
            y: y,
            width: columns[1].1,
            height: height,
            context: context,
            pageRect: pageRect,
            font: .systemFont(ofSize: 8.7, weight: .regular),
            color: pdfColor(17, 24, 39),
            drawBorder: true
        )
        currentX += columns[1].1

        let location = "\(finding.path)\(finding.line.map { ":\($0)" } ?? "")"
        drawPDFTableCell(
            pdfTrimmed(location, limit: 180),
            x: currentX,
            y: y,
            width: columns[2].1,
            height: height,
            context: context,
            pageRect: pageRect,
            font: .monospacedSystemFont(ofSize: 8.2, weight: .regular),
            color: pdfColor(71, 84, 103),
            drawBorder: true
        )
        currentX += columns[2].1

        drawPDFTableCell(
            pdfTrimmed(
                """
                \(reportLabel("evidence", language: language)): \(finding.evidence)
                \(reportLabel("recommendation", language: language)): \(findingRecommendation(finding, language: language))
                """,
                limit: 300
            ),
            x: currentX,
            y: y,
            width: columns[3].1,
            height: height,
            context: context,
            pageRect: pageRect,
            font: .systemFont(ofSize: 8.2, weight: .regular),
            color: pdfColor(17, 24, 39),
            drawBorder: true
        )
    }

    private func drawPDFTableCell(
        _ text: String,
        x: CGFloat,
        y: CGFloat,
        width: CGFloat,
        height: CGFloat,
        context: CGContext,
        pageRect: CGRect,
        font: NSFont,
        color: NSColor,
        drawBorder: Bool = false
    ) {
        if drawBorder {
            drawPDFCellBorder(x: x, y: y, width: width, height: height, context: context, pageRect: pageRect)
        }
        drawPDFText(
            text,
            in: topRect(x: x + 7, y: y + 7, width: max(1, width - 14), height: max(1, height - 14), pageRect: pageRect),
            context: context,
            font: font,
            color: color,
            lineSpacing: 2.4
        )
    }

    private func drawPDFCellBorder(
        x: CGFloat,
        y: CGFloat,
        width: CGFloat,
        height: CGFloat,
        context: CGContext,
        pageRect: CGRect
    ) {
        let rect = topRect(x: x, y: y, width: width, height: height, pageRect: pageRect)
        context.setStrokeColor(pdfColor(216, 222, 233).cgColor)
        context.setLineWidth(0.7)
        context.stroke(rect)
    }

    private func pdfFindingRowHeight(
        _ finding: NativeFinding,
        language: AppLanguage,
        columns: [(String, CGFloat)]
    ) -> CGFloat {
        let titleLines = pdfEstimatedLineCount("\(findingTitle(finding, language: language)) \(finding.ruleID) \(categoryLabel(finding.category, language: language))", width: columns[1].1 - 14)
        let locationLines = pdfEstimatedLineCount("\(finding.path)\(finding.line.map { ":\($0)" } ?? "")", width: columns[2].1 - 14, averageCharacterWidth: 4.8)
        let actionLines = pdfEstimatedLineCount("\(finding.evidence) \(findingRecommendation(finding, language: language))", width: columns[3].1 - 14)
        let lineCount = max(titleLines, locationLines, actionLines)
        return min(132, max(72, CGFloat(lineCount) * 11 + 22))
    }

    private func pdfEstimatedLineCount(_ text: String, width: CGFloat, averageCharacterWidth: CGFloat = 5.2) -> Int {
        let usableCharacters = max(10, Int(width / averageCharacterWidth))
        let lines = text.components(separatedBy: .newlines).reduce(0) { partial, line in
            partial + max(1, Int(ceil(Double(line.count) / Double(usableCharacters))))
        }
        return max(lines, 1)
    }

    private func pdfTrimmed(_ text: String, limit: Int) -> String {
        let normalized = text
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: "\n")
        guard normalized.count > limit else {
            return normalized
        }
        return String(normalized.prefix(max(0, limit - 1))) + "..."
    }

    private func drawPDFSeverityBars(
        _ counts: [String: Int],
        language: AppLanguage,
        top: CGFloat,
        context: CGContext,
        pageRect: CGRect
    ) {
        let entries = ["critical", "high", "medium", "low", "info"]
        let maximum = max(entries.map { counts[$0] ?? 0 }.max() ?? 0, 1)

        for (index, severity) in entries.enumerated() {
            let y = top + CGFloat(index) * 31
            let count = counts[severity] ?? 0
            let ratio = CGFloat(count) / CGFloat(maximum)

            drawPDFText(
                severityLabel(severity, language: language),
                in: topRect(x: 58, y: y, width: 76, height: 18, pageRect: pageRect),
                context: context,
                font: .systemFont(ofSize: 10, weight: .bold),
                color: pdfColor(102, 112, 133)
            )

            let trackRect = topRect(x: 136, y: y + 4, width: pageRect.width - 236, height: 11, pageRect: pageRect)
            drawPDFRoundedRect(trackRect, fill: pdfColor(233, 238, 245), stroke: pdfColor(233, 238, 245), context: context, cornerRadius: 5.5)
            if count > 0 {
                let fillRect = CGRect(x: trackRect.minX, y: trackRect.minY, width: max(8, trackRect.width * ratio), height: trackRect.height)
                drawPDFRoundedRect(fillRect, fill: pdfSeverityColor(severity), stroke: pdfSeverityColor(severity), context: context, cornerRadius: 5.5)
            }

            drawPDFText(
                "\(count)",
                in: topRect(x: pageRect.width - 86, y: y, width: 44, height: 18, pageRect: pageRect),
                context: context,
                font: .systemFont(ofSize: 10, weight: .heavy),
                color: pdfColor(17, 24, 39)
            )
        }
    }

    private func drawPDFText(
        _ text: String,
        in rect: CGRect,
        context: CGContext,
        font: NSFont,
        color: NSColor,
        lineSpacing: CGFloat = 2
    ) {
        let paragraph = NSMutableParagraphStyle()
        paragraph.lineSpacing = lineSpacing
        paragraph.lineBreakMode = .byWordWrapping
        let attributed = NSAttributedString(
            string: text,
            attributes: [
                .font: font,
                .foregroundColor: color,
                .paragraphStyle: paragraph,
            ]
        )
        let framesetter = CTFramesetterCreateWithAttributedString(attributed)
        let path = CGPath(rect: rect, transform: nil)
        let frame = CTFramesetterCreateFrame(framesetter, CFRange(location: 0, length: attributed.length), path, nil)
        context.saveGState()
        context.textMatrix = .identity
        CTFrameDraw(frame, context)
        context.restoreGState()
    }

    private func drawPDFRoundedRect(
        _ rect: CGRect,
        fill: NSColor,
        stroke: NSColor,
        context: CGContext,
        cornerRadius: CGFloat = 9
    ) {
        let path = CGPath(roundedRect: rect, cornerWidth: cornerRadius, cornerHeight: cornerRadius, transform: nil)
        context.setFillColor(fill.cgColor)
        context.addPath(path)
        context.fillPath()
        context.setStrokeColor(stroke.cgColor)
        context.setLineWidth(1)
        context.addPath(path)
        context.strokePath()
    }

    private func topRect(x: CGFloat, y: CGFloat, width: CGFloat, height: CGFloat, pageRect: CGRect) -> CGRect {
        CGRect(x: x, y: pageRect.height - y - height, width: width, height: height)
    }

    private func pdfColor(_ red: CGFloat, _ green: CGFloat, _ blue: CGFloat, _ alpha: CGFloat = 1) -> NSColor {
        NSColor(calibratedRed: red / 255, green: green / 255, blue: blue / 255, alpha: alpha)
    }

    private func pdfSeverityColor(_ severity: String) -> NSColor {
        switch severity {
        case "critical": return pdfColor(127, 29, 29)
        case "high": return pdfColor(180, 35, 24)
        case "medium": return pdfColor(183, 121, 31)
        case "low": return pdfColor(37, 99, 235)
        default: return pdfColor(71, 84, 103)
        }
    }

    private func scanDirectory(
        _ root: URL,
        targetName: String,
        originalRoot: URL,
        screenQualityOnly: Bool,
        findings: inout [NativeFinding],
        warnings: inout [String],
        scannedFileCount: inout Int,
        scannedFileURLs: inout [URL],
        archiveBudget: inout ArchiveBudget,
        archiveDepth: Int
    ) {
        guard let enumerator = fileManager.enumerator(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey, .fileSizeKey],
            options: [.skipsPackageDescendants]
        ) else {
            warnings.append("디렉터리를 열 수 없습니다: \(root.path)")
            return
        }

        while let item = enumerator.nextObject() as? URL {
            if isDirectory(item) {
                if excludedDirectoryNames.contains(item.lastPathComponent) {
                    enumerator.skipDescendants()
                }
                continue
            }

            if isArchive(item) {
                do {
                    let extractedRoot = try extractArchive(item, under: fileManager.temporaryDirectory, budget: &archiveBudget, depth: archiveDepth + 1)
                    defer { try? fileManager.removeItem(at: extractedRoot) }
                    scanDirectory(
                        extractedRoot,
                        targetName: targetName,
                        originalRoot: extractedRoot,
                        screenQualityOnly: screenQualityOnly,
                        findings: &findings,
                        warnings: &warnings,
                        scannedFileCount: &scannedFileCount,
                        scannedFileURLs: &scannedFileURLs,
                        archiveBudget: &archiveBudget,
                        archiveDepth: archiveDepth + 1
                    )
                } catch {
                    warnings.append(error.localizedDescription)
                }
                continue
            }

            scannedFileURLs.append(item)
            scanFile(
                item,
                targetName: targetName,
                root: originalRoot,
                screenQualityOnly: screenQualityOnly,
                findings: &findings,
                scannedFileCount: &scannedFileCount
            )
        }
    }

    private func scanFile(
        _ file: URL,
        targetName: String,
        root: URL,
        screenQualityOnly: Bool,
        findings: inout [NativeFinding],
        scannedFileCount: inout Int
    ) {
        let displayPath = relativePath(file, root: root)
        var localFindings = screenQualityOnly ? [] : checkFileMetadata(file: file, displayPath: displayPath)

        guard let lines = readTextLines(file) else {
            appendFindings(localFindings, targetName: targetName, findings: &findings)
            return
        }

        scannedFileCount += 1
        if screenQualityOnly {
            localFindings += checkScreenQuality(lines: lines, file: file, displayPath: displayPath)
        } else {
            localFindings +=
                checkSecrets(lines: lines, file: file, displayPath: displayPath)
                + checkDependencies(lines: lines, file: file, root: root, displayPath: displayPath)
                + checkConfiguration(lines: lines, file: file, displayPath: displayPath)
                + checkCode(lines: lines, file: file, displayPath: displayPath)
        }

        appendFindings(localFindings, targetName: targetName, findings: &findings)
    }

    private func appendFindings(_ localFindings: [NativeFinding], targetName: String, findings: inout [NativeFinding]) {
        findings.append(contentsOf: localFindings.map { finding in
            NativeFinding(
                ruleID: finding.ruleID,
                severity: finding.severity,
                category: finding.category,
                title: finding.title,
                path: "\(targetName)/\(finding.path)",
                line: finding.line,
                evidence: finding.evidence,
                recommendation: finding.recommendation,
                reachable: finding.reachable,
                verificationStatus: finding.verificationStatus,
                verificationNote: finding.verificationNote,
                triageVerdict: finding.triageVerdict,
                triageConfidence: finding.triageConfidence,
                triageNote: finding.triageNote
            )
        })
    }

    private func applyIgnoreRules(to findings: inout [NativeFinding], startingAt startIndex: Int, root: URL, targetName: String) -> Int {
        let rules = NativeIgnoreRules.load(from: root)
        guard !rules.isEmpty, startIndex < findings.count else {
            return 0
        }

        let prefix = Array(findings[..<startIndex])
        let scoped = Array(findings[startIndex...])
        let kept = scoped.filter { finding in
            !rules.contains { rule in
                rule.matches(finding, targetName: targetName)
            }
        }
        findings = prefix + kept
        return scoped.count - kept.count
    }

    private func checkFileMetadata(file: URL, displayPath: String) -> [NativeFinding] {
        let name = file.lastPathComponent
        let suffix = file.pathExtension.lowercased()
        let privateKeyNames: Set<String> = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]
        let privateKeySuffixes: Set<String> = ["pem", "p12", "pfx", "key"]

        if privateKeyNames.contains(name) || privateKeySuffixes.contains(suffix) {
            return [
                finding(
                    "config.private-key-like-file",
                    "high",
                    "configuration",
                    "개인 키로 보이는 파일이 프로젝트에 포함됨",
                    displayPath,
                    nil,
                    name,
                    "개인 키 파일은 비밀 저장소로 이동하고 실제 키였다면 즉시 교체하세요."
                )
            ]
        }

        return []
    }

    private func checkSecrets(lines: [String], file: URL, displayPath: String) -> [NativeFinding] {
        var findings: [NativeFinding] = []
        for (index, line) in lines.enumerated() {
            let lineNumber = index + 1
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            let isComment = trimmed.hasPrefix("//") || trimmed.hasPrefix("#") || trimmed.hasPrefix("/*") || trimmed.hasPrefix("*")
            if line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") {
                findings.append(finding("secret.private-key", "critical", "secrets", "개인 키가 파일에 포함됨", displayPath, lineNumber, line, "개인 키를 즉시 폐기하고 안전한 비밀 관리 저장소로 이동하세요."))
            }
            if matches(#"\b(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b"#, line) {
                findings.append(finding("secret.aws-access-key", "high", "secrets", "AWS Access Key로 보이는 값 발견", displayPath, lineNumber, redact(line), "키를 폐기하고 IAM 권한 범위와 사용 이력을 확인하세요."))
            }
            if matches(#"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b"#, line) {
                findings.append(finding("secret.github-token", "high", "secrets", "GitHub 토큰으로 보이는 값 발견", displayPath, lineNumber, redact(line), "토큰을 폐기하고 GitHub secret 저장소 또는 OS 비밀 저장소를 사용하세요."))
            }
            if matches(#"sk-[A-Za-z0-9_\-]{20,}"#, line) {
                findings.append(finding("secret.openai-key", "high", "secrets", "API 키로 보이는 값 발견", displayPath, lineNumber, redact(line), "키를 폐기하고 환경변수 또는 비밀 관리 저장소를 사용하세요."))
            }
            if matches(#"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"#, line) {
                findings.append(finding("secret.slack-token", "high", "secrets", "Slack 토큰으로 보이는 값 발견", displayPath, lineNumber, redact(line), "토큰을 폐기하고 Slack 앱 권한과 사용 이력을 확인하세요."))
            }
            if matches(#"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{12,}"#, line),
               !isComment,
               !matches(#"(?i)(getenv|process\.env|os\.environ|config\.get|placeholder|example)"#, line) {
                findings.append(finding("secret.generic-assignment", "medium", "secrets", "하드코딩된 비밀값 의심 대입", displayPath, lineNumber, redact(line), "코드에 값을 직접 두지 말고 런타임 비밀 주입을 사용하세요.", verificationStatus: "needs_review"))
            }
            if isComment,
               matches(#"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{8,}"#, line),
               !matches(#"(?i)(placeholder|example|sample|dummy|redacted|your[_-])"#, line) {
                findings.append(finding("secret.sensitive-comment", "medium", "secrets", "주석에 중요정보가 포함된 것으로 보임", displayPath, lineNumber, redact(line), "주석에서 자격증명과 내부 중요정보를 제거하고 실제 값이었다면 즉시 교체하세요.", verificationStatus: "needs_review"))
            }
        }
        return findings
    }

    private func checkDependencies(lines: [String], file: URL, root: URL, displayPath: String) -> [NativeFinding] {
        var findings: [NativeFinding] = []
        let name = file.lastPathComponent
        if name == "requirements.txt" {
            for (index, rawLine) in lines.enumerated() {
                let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
                if line.isEmpty || line.hasPrefix("#") || line.contains("==") || line.contains("@") {
                    continue
                }
                if line.hasPrefix("http://") || line.contains(" http://") {
                    findings.append(finding("dependency.python-insecure-url", "high", "dependencies", "Python 의존성이 안전하지 않은 HTTP에서 내려받아짐", displayPath, index + 1, line, "HTTPS 또는 신뢰할 수 있는 패키지 저장소를 사용하세요."))
                }
                if matches(#"^[A-Za-z0-9_.\-]+([<>=!~]=?)?.*"#, line) {
                    findings.append(finding("dependency.python-unpinned-requirement", "low", "dependencies", "고정되지 않은 Python 의존성", displayPath, index + 1, line, "정확한 버전을 고정하고 정기적으로 취약점 조회를 수행하세요."))
                }
            }
        }

        if name == "package.json" {
            let lockfiles = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"]
            let text = lines.joined(separator: "\n")
            if let data = text.data(using: .utf8) {
                do {
                    let object = try JSONSerialization.jsonObject(with: data)
                    if let package = object as? [String: Any] {
                        let dependencySections = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]
                        let hasDependencies = dependencySections.contains { section in
                            guard let dependencies = package[section] as? [String: Any] else { return false }
                            return !dependencies.isEmpty
                        }

                        if hasDependencies, !lockfiles.contains(where: { fileManager.fileExists(atPath: file.deletingLastPathComponent().appendingPathComponent($0).path) }) {
                            findings.append(finding("dependency.node-missing-lockfile", "medium", "dependencies", "Node lockfile 누락", displayPath, nil, "package.json", "lockfile을 커밋해 재현 가능한 설치를 보장하세요."))
                        }

                        for section in dependencySections {
                            guard let dependencies = package[section] as? [String: Any] else { continue }
                            for (packageName, rawVersion) in dependencies {
                                guard let version = rawVersion as? String else { continue }
                                let lineNumber = lineNumberContaining(packageName, in: lines)
                                if ["*", "latest", "x"].contains(version.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()) || version.hasPrefix(">=") {
                                    findings.append(finding("dependency.node-unbounded-version", "medium", "dependencies", "제한 없는 Node 의존성 버전", displayPath, lineNumber, "\(packageName): \(version)", "검증된 버전 범위나 lockfile을 사용하세요."))
                                }
                                if version.hasPrefix("http://") || version.contains(" http://") {
                                    findings.append(finding("dependency.node-insecure-url", "high", "dependencies", "Node 의존성이 안전하지 않은 HTTP에서 내려받아짐", displayPath, lineNumber, "\(packageName): \(version)", "HTTPS 또는 신뢰할 수 있는 패키지 저장소를 사용하세요."))
                                }
                            }
                        }

                        if let scripts = package["scripts"] as? [String: Any] {
                            for (scriptName, rawCommand) in scripts {
                                guard let command = rawCommand as? String else { continue }
                                if matches(#"(?i)\b(curl|wget)\b.+\|\s*(sh|bash|zsh|python|ruby|node)\b"#, command) {
                                    findings.append(finding("dependency.remote-shell-script", "high", "dependencies", "패키지 스크립트가 원격 콘텐츠를 즉시 실행함", displayPath, lineNumberContaining(scriptName, in: lines), "\(scriptName): \(command)", "설치 스크립트를 vendoring하거나 체크섬/서명을 검증하세요."))
                                }
                            }
                        }
                    }
                } catch {
                    findings.append(finding("dependency.package-json-invalid", "medium", "dependencies", "package.json 문법 오류", displayPath, nil, String(describing: error), "의존성 도구가 안정적으로 검사할 수 있도록 package.json 문법을 수정하세요."))
                }
            }
        }

        if name == "pyproject.toml" {
            for (index, line) in lines.enumerated() {
                if matches(#"=\s*['"]\*['"]"#, line) {
                    findings.append(finding("dependency.python-wildcard-version", "medium", "dependencies", "Python 의존성 wildcard 버전", displayPath, index + 1, line, "검증된 버전 범위나 lockfile을 사용하세요."))
                }
            }
        }

        if name == "Dockerfile" {
            for (index, line) in lines.enumerated() {
                if matches(#"(?i)(curl|wget).*\|\s*(sh|bash)"#, line) {
                    findings.append(finding("dependency.docker-remote-shell", "high", "dependencies", "Docker 빌드가 원격 스크립트를 즉시 실행함", displayPath, index + 1, line, "다운로드 검증과 체크섬 확인 후 실행하세요."))
                }
                if matches(#"(?i)^FROM\s+\S+:latest\b"#, line) || matches(#"(?i)^FROM\s+[^:@\s]+(?:\s+AS\s+\S+)?$"#, line) {
                    findings.append(finding("dependency.docker-unpinned-base", "medium", "dependencies", "Docker base image가 고정되지 않음", displayPath, index + 1, line, "검토된 태그나 digest로 base image를 고정하세요."))
                }
            }
        }

        _ = root
        return findings
    }

    private func checkConfiguration(lines: [String], file: URL, displayPath: String) -> [NativeFinding] {
        var findings: [NativeFinding] = []
        let name = file.lastPathComponent
        if isRealEnvironmentFile(name) {
            findings.append(finding("config.env-file-present", "medium", "configuration", "환경 파일이 프로젝트에 포함됨", displayPath, nil, name, "비밀값 포함 여부를 확인하고 저장소에서 제외하세요."))
        }

        var dockerHasUserDirective = false
        for (index, line) in lines.enumerated() {
            let lowered = line.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if matches(#"(?i)\bDEBUG\s*[:=]\s*(true|1|yes)\b"#, line) {
                findings.append(finding("config.debug-enabled", "medium", "configuration", "디버그 설정 활성화", displayPath, index + 1, line, "운영 빌드에서 디버그 설정을 비활성화하세요."))
            }
            if shouldCheckDevelopmentEnvironment(file) && matches(#"(?i)\b(NODE_ENV|FLASK_ENV|APP_ENV)\b\s*[:=]\s*['"]?development['"]?"#, line) {
                findings.append(finding("config.development-environment", "low", "configuration", "개발 환경 플래그가 설정됨", displayPath, index + 1, line, "배포 설정과 로컬 개발 설정을 분리하세요."))
            }
            if looksLikeKubernetesManifest(file) {
                if lowered == "privileged: true" {
                    findings.append(finding("config.k8s-privileged-container", "high", "configuration", "Kubernetes 컨테이너가 privileged 모드를 사용함", displayPath, index + 1, line, "privileged 모드를 제거하고 필요한 capability만 명시하세요."))
                }
                if lowered == "allowprivilegeescalation: true" {
                    findings.append(finding("config.k8s-allow-privilege-escalation", "medium", "configuration", "Kubernetes 컨테이너가 권한 상승을 허용함", displayPath, index + 1, line, "필요하지 않다면 allowPrivilegeEscalation: false를 설정하세요."))
                }
                if lowered == "hostnetwork: true" {
                    findings.append(finding("config.k8s-host-network", "medium", "configuration", "Kubernetes workload가 host network를 사용함", displayPath, index + 1, line, "Pod 네트워크와 Service/NetworkPolicy를 우선 사용하세요."))
                }
                if lowered == "hostpath:" || lowered.hasSuffix(" hostpath:") || lowered.hasSuffix("- hostpath:") {
                    findings.append(finding("config.k8s-hostpath-volume", "medium", "configuration", "Kubernetes workload가 hostPath 볼륨을 마운트함", displayPath, index + 1, line, "가능하면 PersistentVolume으로 대체하고 예외 사유를 문서화하세요."))
                }
                if lowered == "runasnonroot: false" {
                    findings.append(finding("config.k8s-run-as-root", "medium", "configuration", "Kubernetes workload가 root 실행을 허용함", displayPath, index + 1, line, "runAsNonRoot: true와 비root 런타임 사용자를 설정하세요."))
                }
                if lowered == "automountserviceaccounttoken: true" {
                    findings.append(finding("config.k8s-service-account-token", "low", "configuration", "Kubernetes service account token 자동 마운트", displayPath, index + 1, line, "Kubernetes API 접근이 필요하지 않다면 automountServiceAccountToken: false를 설정하세요."))
                }
                if lowered == "seccompprofile: unconfined" || lowered == "type: unconfined" {
                    findings.append(finding("config.k8s-seccomp-unconfined", "medium", "configuration", "Kubernetes seccomp가 unconfined로 설정됨", displayPath, index + 1, line, "검토된 예외가 없다면 RuntimeDefault seccomp profile을 사용하세요."))
                }
                if matches(#"(?i)^\s*-\s*(SYS_ADMIN|NET_ADMIN)\s*$"#, line) || matches(#"(?i)\badd\s*:\s*\[.*(SYS_ADMIN|NET_ADMIN)"#, line) {
                    findings.append(finding("config.k8s-dangerous-capability", "medium", "configuration", "Kubernetes workload에 광범위한 capability가 추가됨", displayPath, index + 1, line, "기본적으로 capability를 모두 drop하고 필요한 최소 capability만 검토 후 추가하세요."))
                }
                if matches(#"(?i)^-?\s*image:"#, lowered) && (lowered.contains(":latest") || matches(#"(?i)^-?\s*image:\s*[^:@\s]+$"#, lowered)) {
                    findings.append(finding("config.k8s-unpinned-image", "medium", "configuration", "Kubernetes 이미지가 고정되지 않음", displayPath, index + 1, line, "검토된 버전 태그나 immutable digest로 이미지를 고정하세요."))
                }
            }
            if ["tf", "tfvars"].contains(file.pathExtension.lowercased()) {
                if matches(#"(?i)\bacl\s*=\s*"(public-read|public-read-write|website)""#, line) {
                    findings.append(finding("config.terraform-public-storage", "high", "configuration", "Terraform 저장소 ACL이 public으로 설정됨", displayPath, index + 1, line, "private ACL을 기본값으로 두고 공개 정책은 별도 검토하세요."))
                }
                if matches(#"(?i)\b(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b"#, line) {
                    findings.append(finding("config.terraform-public-access-block-disabled", "medium", "configuration", "Terraform public access block이 비활성화됨", displayPath, index + 1, line, "public access block 통제를 유지하세요."))
                }
                if lowered.contains("0.0.0.0/0") && nearbyAdminPort(lines: lines, index: index) {
                    findings.append(finding("config.terraform-open-admin-port", "high", "configuration", "Terraform 보안그룹이 관리자 포트를 인터넷에 공개함", displayPath, index + 1, line, "관리자 포트는 VPN, bastion, 승인된 CIDR로 제한하세요."))
                }
                if lowered.contains("0.0.0.0/0") && !nearbyAdminPort(lines: lines, index: index) {
                    findings.append(finding("config.terraform-public-ingress", "medium", "configuration", "Terraform 보안그룹이 public ingress를 허용함", displayPath, index + 1, line, "소스 CIDR을 의도한 클라이언트로 제한하거나 승인된 edge/load balancer 통제로 앞단을 제한하세요."))
                }
                if matches(#"(?i)\b(actions?|not_actions?)\s*=\s*(\[\s*)?"\*""#, line) {
                    findings.append(finding("config.terraform-wildcard-iam-action", "medium", "configuration", "Terraform IAM 정책이 wildcard action을 허용함", displayPath, index + 1, line, "필요한 최소 action만 명시하세요."))
                }
                if matches(#"(?i)\b(principals?|identifiers?|principal|identifier)\s*=\s*(\[\s*)?"\*""#, line) {
                    findings.append(finding("config.terraform-wildcard-principal", "high", "configuration", "Terraform IAM 정책이 wildcard principal을 허용함", displayPath, index + 1, line, "승인된 계정, 역할, 서비스 주체로 principal을 제한하세요."))
                }
                if matches(#"(?i)\b(encrypted|enable_server_side_encryption|storage_encrypted)\s*=\s*false\b"#, line) {
                    findings.append(finding("config.terraform-unencrypted-storage", "medium", "configuration", "Terraform 저장소 암호화가 꺼져 있음", displayPath, index + 1, line, "저장 시 암호화를 활성화하고 서비스별 예외는 문서화하세요."))
                }
                if matches(#"(?i)\boutput\s+"[^"]*(secret|password|token|key)[^"]*""#, line) || matches(#"(?i)\bsensitive\s*=\s*false\b"#, line) {
                    findings.append(finding("config.terraform-sensitive-output", "medium", "configuration", "Terraform output이 민감값을 노출할 수 있음", displayPath, index + 1, line, "민감 output에는 sensitive = true를 설정하고 원시 자격증명 출력을 피하세요."))
                }
            }
            if looksLikeGitHubWorkflow(file) {
                if lowered.hasPrefix("pull_request_target:") {
                    findings.append(finding("config.github-pull-request-target", "medium", "configuration", "GitHub Actions가 pull_request_target을 사용함", displayPath, index + 1, line, "비신뢰 PR 코드는 pull_request에서 실행하고 권한 작업과 분리하세요."))
                }
                if (lowered.hasPrefix("run:") || lowered.hasPrefix("- run:")) && lowered.contains("${{ github.event.") {
                    findings.append(finding("config.github-untrusted-event-in-run", "medium", "configuration", "GitHub Actions run 단계에 이벤트 데이터가 직접 삽입됨", displayPath, index + 1, line, "이벤트 값은 환경변수로 전달하고 셸 사용 전에 검증하세요."))
                }
            }
            if isComposeFile(name) && matches(#"(?i)\bprivileged\s*:\s*true\b"#, line) {
                findings.append(finding("config.compose-privileged", "high", "configuration", "권한 상승 컨테이너 설정", displayPath, index + 1, line, "컨테이너 privileged 모드를 제거하고 필요한 capability만 부여하세요."))
            }
            if isComposeFile(name) && matches(#"(?i)^\s*network_mode\s*:\s*host\s*$"#, line) {
                findings.append(finding("config.compose-host-network", "medium", "configuration", "Compose 서비스가 host network를 사용함", displayPath, index + 1, line, "필요한 포트만 명시적으로 매핑하세요."))
            }
            if isComposeFile(name) && line.lowercased().contains("/var/run/docker.sock") {
                findings.append(finding("config.compose-docker-sock", "high", "configuration", "Compose 서비스가 Docker socket을 마운트함", displayPath, index + 1, line, "Docker socket 마운트를 피하거나 제한된 프록시를 사용하세요."))
            }
            if isComposeFile(name) && (matches(#"(?i)\b(cap_add|capabilities)\s*:"#, line) || matches(#"(?i)^\s*-\s*(SYS_ADMIN|NET_ADMIN)\s*$"#, line)) {
                findings.append(finding("config.compose-dangerous-capability", "medium", "configuration", "Compose 서비스가 광범위한 Linux capability를 부여함", displayPath, index + 1, line, "SYS_ADMIN/NET_ADMIN 같은 광범위 권한을 제거하고 필요한 capability만 부여하세요."))
            }
            if isComposeFile(name) && matches(#"(?i)^\s*pid\s*:\s*host\s*$"#, line) {
                findings.append(finding("config.compose-host-pid", "medium", "configuration", "Compose 서비스가 host PID namespace를 사용함", displayPath, index + 1, line, "host PID 접근이 꼭 필요한 경우가 아니면 기본 PID namespace를 사용하세요."))
            }
            if isComposeFile(name) && matches(#"(?i)\b[A-Z0-9_]*(PASSWORD|TOKEN|SECRET|API_KEY|ACCESS_KEY)[A-Z0-9_]*\s*="#, line) {
                findings.append(finding("config.compose-secret-in-environment", "medium", "configuration", "Compose 환경값에 비밀값이 직접 포함됨", displayPath, index + 1, line, "민감값은 secret manager 또는 런타임 주입으로 옮기고 compose에는 placeholder만 남기세요."))
            }
            if name == "Dockerfile" {
                if matches(#"(?i)^USER\s+"#, line) {
                    dockerHasUserDirective = true
                    if matches(#"(?i)^USER\s+(0|root)\s*$"#, line) {
                        findings.append(finding("config.docker-root-user", "medium", "configuration", "Docker image가 root로 실행됨", displayPath, index + 1, line, "런타임 단계에서 최소 권한 사용자로 실행하세요."))
                    }
                }
                if matches(#"(?i)^ADD\s+http://"#, line) {
                    findings.append(finding("config.docker-add-http", "medium", "configuration", "Dockerfile ADD가 HTTP를 사용함", displayPath, index + 1, line, "HTTPS와 체크섬 검증을 사용하세요."))
                }
            }
            if name == "AndroidManifest.xml" {
                if lowered.contains("android:debuggable=\"true\"") {
                    findings.append(finding("config.android-debuggable", "high", "configuration", "Android 앱이 debuggable로 설정됨", displayPath, index + 1, line, "릴리스 빌드에서는 android:debuggable을 비활성화하세요."))
                }
                if lowered.contains("android:allowbackup=\"true\"") {
                    findings.append(finding("config.android-allow-backup", "medium", "configuration", "Android 백업이 허용됨", displayPath, index + 1, line, "민감 앱은 백업을 비활성화하거나 백업 제외 규칙을 명확히 설정하세요."))
                }
                if lowered.contains("android:usescleartexttraffic=\"true\"") {
                    findings.append(finding("config.android-cleartext-traffic", "high", "configuration", "Android cleartext traffic이 허용됨", displayPath, index + 1, line, "HTTPS를 기본으로 강제하고 예외는 network security config로 제한하세요."))
                }
                if lowered.contains("android:exported=\"true\"") {
                    findings.append(finding("config.android-exported-component", "medium", "configuration", "Android component가 exported로 설정됨", displayPath, index + 1, line, "의도한 진입점만 export하고 민감 component에는 permission을 요구하세요."))
                }
            }
            if name == "Info.plist" {
                let text = lines.joined(separator: "\n")
                if line.contains("NSAllowsArbitraryLoads") && plistKeyTrue(text, key: "NSAllowsArbitraryLoads") {
                    findings.append(finding("config.ios-ats-arbitrary-loads", "high", "configuration", "iOS ATS가 임의 네트워크 로드를 허용함", displayPath, index + 1, "NSAllowsArbitraryLoads", "ATS를 유지하고 예외는 검토된 도메인으로 제한하세요."))
                }
                if line.contains("UIFileSharingEnabled") && plistKeyTrue(text, key: "UIFileSharingEnabled") {
                    findings.append(finding("config.ios-file-sharing-enabled", "medium", "configuration", "iOS 파일 공유가 활성화됨", displayPath, index + 1, "UIFileSharingEnabled", "민감 문서가 아니라는 근거가 없다면 파일 공유를 비활성화하세요."))
                }
                if line.contains("LSSupportsOpeningDocumentsInPlace") && plistKeyTrue(text, key: "LSSupportsOpeningDocumentsInPlace") {
                    findings.append(finding("config.ios-open-documents-in-place", "low", "configuration", "iOS 문서 제자리 열기가 활성화됨", displayPath, index + 1, "LSSupportsOpeningDocumentsInPlace", "문서 provider 흐름과 민감 파일 처리 범위를 검토하세요."))
                }
            }
        }

        if name == "Dockerfile", !dockerHasUserDirective {
            findings.append(finding("config.docker-no-user", "low", "configuration", "Dockerfile에 비root USER가 없음", displayPath, nil, name, "런타임 단계에 비root USER를 추가하세요."))
        }
        return findings
    }

    private func isComposeFile(_ name: String) -> Bool {
        ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"].contains(name)
    }

    private func looksLikeKubernetesManifest(_ file: URL) -> Bool {
        let lowerName = file.lastPathComponent.lowercased()
        if ["deployment.yml", "deployment.yaml", "pod.yml", "pod.yaml", "daemonset.yml", "daemonset.yaml", "statefulset.yml", "statefulset.yaml"].contains(lowerName) {
            return true
        }
        guard ["yaml", "yml"].contains(file.pathExtension.lowercased()) else {
            return false
        }
        let lowerPath = file.path.lowercased()
        return lowerPath.contains("/k8s/") || lowerPath.contains("/kubernetes/") || lowerPath.contains("/manifests/") || lowerPath.contains("/helm/")
    }

    private func looksLikeGitHubWorkflow(_ file: URL) -> Bool {
        let lowerPath = file.path.lowercased()
        return lowerPath.contains("/.github/workflows/") && ["yml", "yaml"].contains(file.pathExtension.lowercased())
    }

    private func nearbyAdminPort(lines: [String], index: Int) -> Bool {
        let lower = max(0, index - 7)
        let upper = min(lines.count, index + 8)
        let window = lines[lower..<upper].joined(separator: "\n").lowercased()
        return matches(#"\b(from_port|to_port|port)\s*=\s*(22|3389)\b"#, window)
    }

    private func plistKeyTrue(_ text: String, key: String) -> Bool {
        let escapedKey = NSRegularExpression.escapedPattern(for: key)
        return matches(#"<key>\s*\#(escapedKey)\s*</key>\s*<true\s*/>"#, text)
            || matches(#"\#(escapedKey)\s*=\s*(true|YES|1)"#, text)
    }

    private func isRealEnvironmentFile(_ name: String) -> Bool {
        let lower = name.lowercased()
        if lower.hasSuffix(".example") || lower.hasSuffix(".sample") || lower.hasSuffix(".template") {
            return false
        }
        return lower == ".env" || lower.hasPrefix(".env.")
    }

    private func shouldCheckDevelopmentEnvironment(_ file: URL) -> Bool {
        let name = file.lastPathComponent
        let lower = name.lowercased()
        if lower.hasSuffix(".example") || lower.hasSuffix(".sample") || lower.hasSuffix(".template") {
            return false
        }
        if lower.hasPrefix(".env") {
            return true
        }
        if ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"].contains(name) {
            return true
        }
        return [".cfg", ".conf", ".config", ".env", ".ini", ".json", ".properties", ".toml", ".yaml", ".yml"].contains(file.pathExtension.isEmpty ? "" : ".\(file.pathExtension.lowercased())")
    }

    /// Remote, attacker-supplied input. `req`/`request` must be *dereferenced*:
    /// the bare word also appears in `urllib.request` and in ordinary prose.
    private static let remoteSource = #"(?:\b(?:req|request)\s*(?:\.|\[)|\bctx\s*(?:\.\s*(?:request|req|query|params|body|headers|cookies)\b|\[)|\$_(?:GET|POST|REQUEST|FILES)\b|\blocation\.(?:hash|search|href)\b)"#

    /// Bounded so `passed`, `bypass`, `tokenize` and `cache_token` are not
    /// secrets, while the compound names that really do carry credentials match.
    private static let sensitiveName = #"\b(?:pass(?:word)?|passwd|pwd|secret|credentials?|authorization|(?:access|refresh|auth|id|bearer|csrf|xsrf|session)[_-]?tokens?|tokens?|api[_-]?keys?|secret[_-]?keys?|private[_-]?keys?|session[_-]?ids?|sessions?|cookies?)\b"#

    private static let slashCommentSuffixes: Set<String> = [
        "c", "cc", "cpp", "cs", "cxx", "go", "h", "hpp", "java", "js",
        "jsx", "kt", "php", "rs", "swift", "ts", "tsx", "vue"
    ]
    private static let hashCommentSuffixes: Set<String> = ["conf", "config", "php", "properties", "py", "rb"]
    private static let htmlCommentSuffixes: Set<String> = ["html", "htm", "jsp", "jspx", "vue", "xml"]
    private static let tripleQuoteSuffixes: Set<String> = ["py"]
    private static let backtickStringSuffixes: Set<String> = ["go", "js", "jsx", "ts", "tsx", "vue"]

    private func hasPrefix(_ needle: [Character], _ characters: [Character], at index: Int) -> Bool {
        guard index >= 0, index + needle.count <= characters.count else { return false }
        for offset in 0..<needle.count where characters[index + offset] != needle[offset] {
            return false
        }
        return true
    }

    private func matchIndex(_ needle: [Character], _ characters: [Character], from start: Int) -> Int? {
        guard !needle.isEmpty else { return nil }
        var index = max(0, start)
        while index + needle.count <= characters.count {
            if hasPrefix(needle, characters, at: index) { return index }
            index += 1
        }
        return nil
    }

    /// Returns the file with comments removed, keeping line numbers aligned.
    ///
    /// Every source rule runs against this view instead of the raw line, so
    /// commented-out code, block comments and multi-line docstrings are never
    /// reported as live findings. String *contents* are preserved because rules
    /// such as dynamic-SQL detection need the literal text; only multi-line
    /// string bodies are dropped, since a rule cannot tell prose from code there.
    private func codeView(lines: [String], suffix: String) -> [String] {
        var lineTokens: [[Character]] = []
        if Self.slashCommentSuffixes.contains(suffix) { lineTokens.append(Array("//")) }
        if Self.hashCommentSuffixes.contains(suffix) { lineTokens.append(Array("#")) }
        let blockOpen = Array("/*")
        let blockClose = Array("*/")
        let htmlOpen = Array("<!--")
        let htmlClose = Array("-->")
        let hasBlockComment = Self.slashCommentSuffixes.contains(suffix)
        let hasHTMLComment = Self.htmlCommentSuffixes.contains(suffix)
        let triples: [[Character]] = Self.tripleQuoteSuffixes.contains(suffix)
            ? [Array("\"\"\""), Array("'''")]
            : []
        var quotes: Set<Character> = ["\"", "'"]
        if Self.backtickStringSuffixes.contains(suffix) { quotes.insert("`") }
        guard !lineTokens.isEmpty || hasBlockComment || hasHTMLComment else { return lines }

        var stripped: [String] = []
        stripped.reserveCapacity(lines.count)
        var openBlock: [Character]?
        var openTriple: [Character]?

        for rawLine in lines {
            let characters = Array(rawLine)
            var output = ""
            // Single-quote strings never span lines in these languages, so quote
            // state resets per line or one stray apostrophe blinds the rest.
            var quote: Character?
            var escaped = false
            var index = 0
            while index < characters.count {
                if let triple = openTriple {
                    guard let end = matchIndex(triple, characters, from: index) else { break }
                    index = end + triple.count
                    openTriple = nil
                    continue
                }
                if let close = openBlock {
                    guard let end = matchIndex(close, characters, from: index) else { break }
                    index = end + close.count
                    openBlock = nil
                    continue
                }
                let current = characters[index]
                if let active = quote {
                    output.append(current)
                    if escaped {
                        escaped = false
                    } else if current == "\\" {
                        escaped = true
                    } else if current == active {
                        quote = nil
                    }
                    index += 1
                    continue
                }
                if let triple = triples.first(where: { hasPrefix($0, characters, at: index) }) {
                    if let end = matchIndex(triple, characters, from: index + triple.count) {
                        // Opened and closed on one line: an ordinary string literal.
                        output.append(String(characters[index..<(end + triple.count)]))
                        index = end + triple.count
                        continue
                    }
                    openTriple = triple
                    break
                }
                if lineTokens.contains(where: { hasPrefix($0, characters, at: index) }) {
                    break
                }
                if hasBlockComment, hasPrefix(blockOpen, characters, at: index) {
                    if let end = matchIndex(blockClose, characters, from: index + blockOpen.count) {
                        index = end + blockClose.count
                        continue
                    }
                    openBlock = blockClose
                    break
                }
                if hasHTMLComment, hasPrefix(htmlOpen, characters, at: index) {
                    if let end = matchIndex(htmlClose, characters, from: index + htmlOpen.count) {
                        index = end + htmlClose.count
                        continue
                    }
                    openBlock = htmlClose
                    break
                }
                if quotes.contains(current) {
                    quote = current
                    output.append(current)
                    index += 1
                    continue
                }
                output.append(current)
                index += 1
            }
            stripped.append(output)
        }
        return stripped
    }

    private func checkJavaNullPointerDereference(lines: [String], codeLines: [String], file: URL, displayPath: String) -> [NativeFinding] {
        guard ["java", "kt"].contains(file.pathExtension.lowercased()) else { return [] }

        func captureGroups(_ pattern: String, _ text: String) -> [String]? {
            guard let expression = try? NSRegularExpression(pattern: pattern) else { return nil }
            let range = NSRange(text.startIndex..<text.endIndex, in: text)
            guard let match = expression.firstMatch(in: text, range: range) else { return nil }
            return (1..<match.numberOfRanges).map { index in
                guard let swiftRange = Range(match.range(at: index), in: text) else { return "" }
                return String(text[swiftRange])
            }
        }

        func guardExits(_ start: Int) -> Bool {
            if !codeLines[start].contains("{") {
                return matches(#"\b(return|throw)\b"#, codeLines[start])
            }
            var depth = 0
            var sawBlock = false
            for index in start..<min(codeLines.count, start + 7) {
                let line = codeLines[index]
                if line.contains("{") { sawBlock = true }
                depth += line.filter { $0 == "{" }.count - line.filter { $0 == "}" }.count
                if matches(#"\b(return|throw)\b"#, line) { return true }
                if sawBlock && index > start && depth <= 0 { break }
            }
            return false
        }

        let assignmentPattern = #"^\s*(?:(?:final|var|val)\s+)?(?:[A-Za-z_$][\w$<>\[\].,?]*\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*;?\s*$"#
        let mapPattern = #"\b(?:Map|HashMap|ConcurrentHashMap|SortedMap|NavigableMap)\s*<[^;=]+>\s*([A-Za-z_$][\w$]*)"#
        let nullableCallPattern = #"(?i)(?:\brequest\s*\.\s*getParameter|\bSystem\s*\.\s*(?:getenv|getProperty)|\b(?:[A-Za-z_$][\w$]*(?:Map|Cache|Repository|Repo|Dao)|map|cache|users|items|records)\s*\.\s*(?:get|findBy\w*|lookup\w*))\s*\([^;]*?\)"#
        let nullSafePattern = #"(?i)\.(?:orElseThrow|orElseGet|orElse|ifPresent|isPresent)\s*\(|\bObjects\s*\.\s*requireNonNull\s*\("#
        var definitelyNull = Set<String>()
        var possiblyNull = Set<String>()
        var nullableReceivers = Set<String>()
        var nonnullScopes: [(name: String, depth: Int)] = []
        var nonnullNextStatement: [String: Int] = [:]
        var braceDepth = 0
        var findings: [NativeFinding] = []
        var seenLines = Set<Int>()

        for index in codeLines.indices {
            let stripped = codeLines[index].trimmingCharacters(in: .whitespacesAndNewlines)
            if stripped.isEmpty { continue }

            nonnullNextStatement = nonnullNextStatement.filter { $0.value >= index }
            if matches(#"\belse\b"#, stripped) { nonnullScopes.removeAll() }
            nonnullScopes = nonnullScopes.filter { braceDepth >= $0.depth }
            if let receiver = firstCapture(mapPattern, in: stripped) { nullableReceivers.insert(receiver) }

            var nonnullOnLine: String?
            let positiveGuard = firstCapture(#"\bif\s*\(\s*([A-Za-z_$][\w$]*)\s*!=\s*null\s*\)"#, in: stripped)
                ?? firstCapture(#"\bif\s*\(\s*null\s*!=\s*([A-Za-z_$][\w$]*)\s*\)"#, in: stripped)
            if let name = positiveGuard {
                if stripped.contains("{") {
                    nonnullScopes.append((name, braceDepth + 1))
                } else if let next = codeLines.indices.dropFirst(index + 1).first(where: {
                    !codeLines[$0].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                }) {
                    nonnullNextStatement[name] = next
                } else {
                    nonnullOnLine = name
                }
            }

            if let required = firstCapture(#"\bObjects\s*\.\s*requireNonNull\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*;"#, in: stripped) {
                definitelyNull.remove(required)
                possiblyNull.remove(required)
            }

            let nullGuard = firstCapture(#"\bif\s*\(\s*([A-Za-z_$][\w$]*)\s*==\s*null\s*\)"#, in: stripped)
                ?? firstCapture(#"\bif\s*\(\s*null\s*==\s*([A-Za-z_$][\w$]*)\s*\)"#, in: stripped)
            if let name = nullGuard, guardExits(index) {
                definitelyNull.remove(name)
                possiblyNull.remove(name)
                braceDepth += stripped.filter { $0 == "{" }.count - stripped.filter { $0 == "}" }.count
                continue
            }

            for name in definitelyNull.union(possiblyNull).sorted() {
                let escaped = NSRegularExpression.escapedPattern(for: name)
                guard matches("\\b\(escaped)\\s*\\.(?!\\s*class\\b)", stripped) else { continue }
                if name == nonnullOnLine || nonnullNextStatement[name] == index || nonnullScopes.contains(where: { $0.name == name }) { continue }
                if matches(nullSafePattern, stripped) { continue }
                let lineNumber = index + 1
                guard !seenLines.contains(lineNumber) else { continue }
                let confirmed = definitelyNull.contains(name)
                findings.append(finding(
                    "code.null-pointer-dereference", "medium", "code", "Null 포인터 역참조 가능성",
                    displayPath, lineNumber, lines[index],
                    "null 여부를 확인한 뒤 참조하고, nullable 조회 결과는 Objects.requireNonNull 또는 Optional.orElseThrow 등으로 명시적으로 처리하세요.",
                    verificationStatus: confirmed ? "confirmed" : "needs_review"
                ))
                seenLines.insert(lineNumber)
            }

            let typedMapChain = nullableReceivers.contains { receiver in
                let escaped = NSRegularExpression.escapedPattern(for: receiver)
                return matches("\\b\(escaped)\\s*\\.\\s*get\\s*\\([^;]*?\\)\\s*\\.\\s*[A-Za-z_$]", stripped)
            }
            if (matches(nullableCallPattern, stripped) || typedMapChain)
                && matches(#"\)\s*\.\s*[A-Za-z_$]"#, stripped)
                && !matches(nullSafePattern, stripped) {
                let lineNumber = index + 1
                if !seenLines.contains(lineNumber) {
                    findings.append(finding(
                        "code.null-pointer-dereference", "medium", "code", "Null 포인터 역참조 가능성",
                        displayPath, lineNumber, lines[index],
                        "nullable 조회 결과를 즉시 참조하지 말고 null 또는 값 부재 경로를 명시적으로 처리하세요."
                    ))
                    seenLines.insert(lineNumber)
                }
            }

            if let groups = captureGroups(assignmentPattern, stripped), groups.count == 2 {
                let name = groups[0]
                let expression = groups[1].trimmingCharacters(in: .whitespacesAndNewlines)
                    .trimmingCharacters(in: CharacterSet(charactersIn: ";"))
                let typedMapLookup = nullableReceivers.contains { receiver in
                    let escaped = NSRegularExpression.escapedPattern(for: receiver)
                    return matches("\\b\(escaped)\\s*\\.\\s*get\\s*\\(", expression)
                }
                if expression == "null" || definitelyNull.contains(expression) {
                    definitelyNull.insert(name)
                    possiblyNull.remove(name)
                } else if possiblyNull.contains(expression)
                    || ((matches(nullableCallPattern, expression) || typedMapLookup) && !matches(nullSafePattern, expression)) {
                    definitelyNull.remove(name)
                    possiblyNull.insert(name)
                } else {
                    definitelyNull.remove(name)
                    possiblyNull.remove(name)
                }
            }

            braceDepth += stripped.filter { $0 == "{" }.count - stripped.filter { $0 == "}" }.count
        }
        return findings.sorted {
            if $0.verificationStatus != $1.verificationStatus {
                return $0.verificationStatus == "confirmed"
            }
            return ($0.line ?? 0) < ($1.line ?? 0)
        }.prefix(5).map { $0 }
    }

    private func checkJavaDocumentBuilderXXE(lines: [String], codeLines: [String], file: URL, displayPath: String) -> [NativeFinding] {
        guard ["java", "kt"].contains(file.pathExtension.lowercased()) else { return [] }

        let factoryPattern = #"(?i)\b(?:DocumentBuilderFactory\s+)?([A-Za-z_$][\w$]*)\s*=\s*DocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)"#
        var findings: [NativeFinding] = []

        for factoryIndex in codeLines.indices {
            guard let factory = firstCapture(factoryPattern, in: codeLines[factoryIndex]) else { continue }
            let escapedFactory = NSRegularExpression.escapedPattern(for: factory)
            let nextFactoryIndex = codeLines.indices.first {
                $0 > factoryIndex && firstCapture(factoryPattern, in: codeLines[$0]) != nil
            } ?? codeLines.endIndex
            let builderPattern = "(?i)\\b(?:DocumentBuilder\\s+)?([A-Za-z_$][\\w$]*)\\s*=\\s*\(escapedFactory)\\s*\\.\\s*newDocumentBuilder\\s*\\(\\s*\\)"

            var builderIndex: Int?
            var builder: String?
            if factoryIndex + 1 < nextFactoryIndex {
                for index in (factoryIndex + 1)..<nextFactoryIndex {
                    if let capture = firstCapture(builderPattern, in: codeLines[index]) {
                        builderIndex = index
                        builder = capture
                        break
                    }
                }
            }
            guard let builderIndex, let builder else { continue }

            let escapedBuilder = NSRegularExpression.escapedPattern(for: builder)
            let parsePattern = "(?i)\\b\(escapedBuilder)\\s*\\.\\s*parse\\s*\\((.*)"
            var parseIndex: Int?
            if builderIndex + 1 < nextFactoryIndex {
                for index in (builderIndex + 1)..<nextFactoryIndex {
                    guard let argument = firstCapture(parsePattern, in: codeLines[index]) else { continue }
                    if matches(#"(?i)\b(request|req|body|payload|input|stream|reader|upload|xml)\w*\b|getInputStream\s*\(|getReader\s*\("#, argument) {
                        parseIndex = index
                        break
                    }
                }
            }
            guard let parseIndex else { continue }

            let configuration = codeLines[(factoryIndex + 1)..<builderIndex].joined(separator: "\n")
            if javaXMLFactoryIsHardened(factory: escapedFactory, configuration: configuration) {
                continue
            }

            findings.append(finding(
                "code.xml-external-entity",
                "high",
                "code",
                "XML 외부 엔티티 처리가 허용될 수 있음",
                displayPath,
                parseIndex + 1,
                lines[parseIndex],
                "newDocumentBuilder() 호출 전에 DOCTYPE 또는 외부 엔티티 처리를 차단하고, 설정 예외 발생 시 파싱을 중단하세요.",
                verificationStatus: "confirmed"
            ))
            if findings.count >= 5 { break }
        }
        return findings
    }

    private func javaXMLFactoryIsHardened(factory: String, configuration: String) -> Bool {
        let ignoredConfigurationFailure = #"(?is)catch\s*\([^)]*(ParserConfigurationException|SAXNotRecognizedException|SAXNotSupportedException)[^)]*\)\s*\{((?:(?!\bthrow\b|\breturn\b).)*)\}"#
        if matches(ignoredConfigurationFailure, configuration) { return false }

        func lastBooleanCall(_ method: String) -> Bool? {
            captures("(?i)\\b\(factory)\\s*\\.\\s*\(method)\\s*\\(\\s*(true|false)\\s*\\)", in: configuration)
                .last
                .map { $0.lowercased() == "true" }
        }

        func lastFeatureBoolean(_ uri: String) -> Bool? {
            let escapedURI = NSRegularExpression.escapedPattern(for: uri)
            return captures("(?i)\\b\(factory)\\s*\\.\\s*setFeature\\s*\\(\\s*[\"']\(escapedURI)[\"']\\s*,\\s*(true|false)\\s*\\)", in: configuration)
                .last
                .map { $0.lowercased() == "true" }
        }

        let doctype = lastFeatureBoolean("http://apache.org/xml/features/disallow-doctype-decl")
        if doctype == true { return true }

        let externalGeneral = lastFeatureBoolean("http://xml.org/sax/features/external-general-entities")
        let externalParameter = lastFeatureBoolean("http://xml.org/sax/features/external-parameter-entities")
        let externalDTD = lastFeatureBoolean("http://apache.org/xml/features/nonvalidating/load-external-dtd")
        let xinclude = lastBooleanCall("setXIncludeAware")
        let entityExpansion = lastBooleanCall("setExpandEntityReferences")
        return externalGeneral == false
            && externalParameter == false
            && externalDTD == false
            && xinclude == false
            && entityExpansion == false
    }

    private func openDepth(_ text: String) -> Int {
        var depth = 0
        var quote: Character?
        var escaped = false
        for character in text {
            if let active = quote {
                if escaped {
                    escaped = false
                } else if character == "\\" {
                    escaped = true
                } else if character == active {
                    quote = nil
                }
                continue
            }
            if character == "\"" || character == "'" || character == "`" {
                quote = character
            } else if character == "(" || character == "[" {
                depth += 1
            } else if character == ")" || character == "]" {
                depth -= 1
            }
        }
        return depth
    }

    /// Joins argument lists that continue onto following lines.
    ///
    /// A statement split over several lines is still one statement, and matching
    /// each fragment alone is exactly the single-line reading this scanner
    /// avoids. A line ending in `{` opens a block rather than an argument list,
    /// so a route handler is never merged into its own declaration.
    private func logicalLines(_ codeLines: [String]) -> [String] {
        let maxContinuationLines = 4
        var joined: [String] = []
        joined.reserveCapacity(codeLines.count)
        for (index, line) in codeLines.enumerated() {
            var text = line
            if !line.trimmingCharacters(in: .whitespaces).hasSuffix("{") {
                var cursor = index
                while openDepth(text) > 0,
                      cursor + 1 < codeLines.count,
                      cursor - index < maxContinuationLines {
                    cursor += 1
                    text += " " + codeLines[cursor].trimmingCharacters(in: .whitespaces)
                }
            }
            joined.append(text)
        }
        return joined
    }

    private func startsFunctionScope(_ line: String, suffix: String) -> Bool {
        let source = line.trimmingCharacters(in: .whitespaces)
        guard !source.isEmpty else { return false }
        switch suffix {
        case "py":
            return matches(#"^(?:async\s+)?def\s+[A-Za-z_]\w*\s*\("#, source)
        case "rb":
            return matches(#"^def\s+(?:self\.)?[A-Za-z_]\w*[!?=]?"#, source)
        case "go":
            return matches(#"^func\s+(?:\([^)]*\)\s*)?[A-Za-z_]\w*\s*\("#, source)
        case "swift":
            return matches(#"^(?:[\w@]+\s+)*func\s+[A-Za-z_]\w*\s*\("#, source)
        case "js", "jsx", "ts", "tsx":
            return matches(#"^(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\("#, source)
                || matches(#"^(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=.*=>\s*\{"#, source)
                || matches(#"^(?:async\s+)?[A-Za-z_$][\w$]*\s*\([^;{}]*\)\s*\{"#, source)
        case "php":
            return matches(#"(?i)^(?:public\s+|protected\s+|private\s+|static\s+)*function\s+\w+\s*\("#, source)
        case "java", "kt", "cs", "c", "cc", "cpp", "cxx", "h", "hpp":
            guard let name = firstCapture(
                #"^(?:(?:public|private|protected|internal|static|final|abstract|synchronized|native|default|open|override|virtual|inline|constexpr|extern|friend)\s+)*(?:<[^>]+>\s+)?(?:[\w$:.<>,?\[\]*&]+\s+)?([A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?:throws\s+[^\{]+)?\{"#,
                in: source
            ) else { return false }
            return !["if", "for", "while", "switch", "catch", "try", "synchronized"].contains(name)
        default:
            return false
        }
    }

    /// Returns the argument text of a call whose name ends at `callEnd`, or nil
    /// when the sink is not a call (an `innerHTML` assignment, say) so the
    /// caller can fall back to line scope.
    private func callArguments(_ line: String, callEnd: Int) -> String? {
        let characters = Array(line)
        var cursor = callEnd
        while cursor < characters.count, characters[cursor].isWhitespace { cursor += 1 }
        guard cursor < characters.count, characters[cursor] == "(" else { return nil }
        var depth = 0
        var quote: Character?
        var escaped = false
        var index = cursor
        while index < characters.count {
            let current = characters[index]
            if let active = quote {
                if escaped {
                    escaped = false
                } else if current == "\\" {
                    escaped = true
                } else if current == active {
                    quote = nil
                }
            } else if current == "\"" || current == "'" || current == "`" {
                quote = current
            } else if current == "(" {
                depth += 1
            } else if current == ")" {
                depth -= 1
                if depth == 0 {
                    return String(characters[(cursor + 1)..<index])
                }
            }
            index += 1
        }
        // Unbalanced (the call continues on the next line): treat the rest as args.
        return String(characters[(cursor + 1)...])
    }

    private func checkContextualSourceFlows(lines: [String], codeLines: [String], displayPath: String, suffix: String) -> [NativeFinding] {
        // Remote input only. `ctx` needs a request-shaped member: a bare `ctx.`
        // also matches a canvas 2D context, a crypto context, and most other
        // graphics or codec handles. Operator input (`sys.argv`, `input()`) is
        // deliberately absent: reading the file named on your own command line
        // is what a CLI is for, so it raises a candidate but never confirms.
        let untrusted = #"(?i)(?:\b(?:req|request)\s*(?:\.|\[)|\bctx\s*(?:\.\s*(?:request|req|query|params|body|headers|cookies)\b|\[)|\$_(?:GET|POST|REQUEST|FILES)\b|\blocation\.(?:hash|search|href)\b)"#
        let requestBody = #"(?i)\b(?:req|request)\s*\.\s*(?:body|data|json|POST|form|params|query|values)\b"#
        let sanitizer = #"(?i)\b(DOMPurify\.sanitize|sanitizeHtml|escapeHtml|html\.escape|encodeForHTML|secure_filename|basename|realpath|canonicalPath|allowlist|allowed_hosts?|validate(?:Url|Path|Host|Redirect|Input)|escapeLdap|encodeForLDAP|stripCrLf|sanitizeHeader)\s*\([^)]*\)"#
        let assignmentName = #"^\s*(?:(?:const|let|var|final)\s+)?(?:[A-Za-z_$][\w$<>\[\].,?]*\s+)?([A-Za-z_$][\w$]*)\s*(?::[^=]+)?="#
        let sqlCallNames = #"execute|executemany|executescript|executeQuery|executeUpdate|executeLargeUpdate|executeBatch|addBatch|query|raw|prepareStatement|createQuery|createNativeQuery|createSQLQuery|batchUpdate|SqlCommand|ExecuteReader|ExecuteScalar|ExecuteNonQuery|ExecuteReaderAsync|ExecuteScalarAsync|ExecuteNonQueryAsync|ExecuteSqlRaw|ExecuteSqlRawAsync|ExecuteSqlCommand|FromSqlRaw|FromSqlRawAsync|SqlQueryRaw|mysqli_query|mysqli_real_query|mysqli_multi_query|mysqli_prepare|mysqli_execute_query|mysqli_stmt_execute|pg_query|pg_send_query|pg_query_params"#
        let sqlSink = #"(?i)(?:\b(?:"# + sqlCallNames + #")\b(?=\s*\()|(?:->|::)\s*(?:query|exec|prepare|execute)\b(?=\s*\()|\b(?:jdbcTemplate|namedParameterJdbcTemplate)\s*\.\s*update\b(?=\s*\()|\.\s*CommandText\b(?=\s*(?:\+?=)))"#
        let sqlSinkTokens = ["execute", "query", "raw", "prepare", "commandtext", "sqlcommand", "batch", "jdbc"]
        let sinks: [(String, String, String, String, String)] = [
            ("code.sql-dynamic-query", sqlSink, "high", "동적 SQL 쿼리 구성", "파라미터 바인딩 또는 ORM 안전 API를 사용하세요."),
            ("code.xss-dom-sink", #"(?i)\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML)\b"#, "high", "DOM XSS 위험 sink", "신뢰할 수 없는 입력을 HTML로 직접 삽입하지 말고 escaping 또는 textContent를 사용하세요."),
            ("code.command-injection", #"(?i)\b(os\.system|os\.popen|subprocess\.(run|call|Popen|check_output)|child_process\.(exec|execSync)|shell_exec|passthru|Runtime\.getRuntime\(\)\.exec)\s*\("#, "high", "명령어 삽입 위험", "쉘 실행을 피하고 고정 인자 배열과 허용목록을 사용하세요."),
            // Bare `open(` or an explicit filesystem module only: `self.parent.open()`
            // in a URL opener is not a file API.
            ("code.path-traversal", #"(?i)(?<![.\w])open\s*\(|\b(?:os|io|codecs|shutil|aiofiles)\.open\s*\(|\b(send_file|FileResponse|readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\("#, "medium", "경로 조작 위험", "입력 경로를 정규화하고 허용된 루트 내부인지 검증하세요."),
            ("code.eval-user-input", #"(?i)\b(eval|exec|(?-i:Function)|instance_eval|class_eval)\s*\("#, "high", "eval 계열 API에 사용자 입력이 연결됨", "동적 코드 실행을 제거하고 허용목록 기반 분기로 대체하세요."),
            // Timers only execute code when their first argument is a string.
            ("code.eval-user-input", #"(?i)\b(setTimeout|setInterval)\s*\(\s*["'`]"#, "high", "eval 계열 API에 사용자 입력이 연결됨", "동적 코드 실행을 제거하고 허용목록 기반 분기로 대체하세요."),
            ("code.ssrf-user-url", #"(?i)\b(requests\.(get|post|put|patch|delete|request)|httpx\.(get|post|put|patch|delete|request)|urllib\.request\.urlopen|axios\.(get|post|put|patch|delete)|fetch|http\.get|https\.get)\b"#, "high", "사용자 입력 URL 요청으로 인한 SSRF 위험", "허용된 호스트만 요청하고 사설망 대역 접근을 차단하세요."),
            ("code.open-redirect-user-input", #"(?i)\b(sendRedirect|redirect|(res|response|ctx)\.redirect)\s*\("#, "medium", "사용자 입력 기반 Open Redirect", "리다이렉트 대상은 내부 경로 허용목록에 매핑하세요."),
            ("code.ldap-injection", #"(?i)\b(ldap([_-]?(client|connection|template))?|dirContext)\s*\.\s*(search|search_s|search_ext)\s*\("#, "high", "LDAP 필터 삽입 위험", "LDAP 필터 메타문자를 이스케이프하거나 파라미터화된 API를 사용하세요."),
            ("code.http-response-splitting", #"(?i)\b(setHeader|addHeader|set_header|writeHead)\s*\("#, "medium", "HTTP 응답 분할 위험", "헤더 값의 CR/LF를 거부하고 허용 형식만 사용하세요."),
            ("code.unsafe-deserialization", #"(?i)\b(pickle\.loads?|yaml\.load|ObjectInputStream|BinaryFormatter|unserialize|Marshal\.load|readObject)\b"#, "high", "신뢰할 수 없는 데이터 역직렬화", "안전 파서를 사용하고 신뢰할 수 없는 객체 역직렬화를 금지하세요."),
            ("code.unrestricted-file-upload", #"(?i)\b(move_uploaded_file|save|writeFile|writeFileSync)\s*\("#, "medium", "검증되지 않은 업로드 저장", "파일 형식과 크기를 검증하고 서버측 파일명을 생성하세요."),
            ("code.api-mass-assignment", #"(?i)\b(create|update|assign|save|insert|merge)\s*\("#, "medium", "API 요청 데이터의 mass assignment", "허용 필드만 명시적으로 매핑하세요."),
            ("code.format-string-user-input", #"(?i)\b(printf|vprintf|syslog|fprintf|String\.format)\s*\("#, "high", "사용자 제어 포맷 문자열", "상수 포맷 문자열을 사용하고 동적 값은 별도 인자로 전달하세요.")
        ]
        var tainted = Set<String>()
        var safePreparedStatements = Set<String>()
        var findings: [NativeFinding] = []
        var seen = Set<String>()

        func withoutSanitizers(_ text: String) -> String {
            guard let regex = try? NSRegularExpression(pattern: sanitizer) else { return text }
            let range = NSRange(text.startIndex..<text.endIndex, in: text)
            return regex.stringByReplacingMatches(in: text, range: range, withTemplate: " ")
        }

        func containsTaintedName(_ text: String) -> Bool {
            tainted.contains { name in
                let escaped = NSRegularExpression.escapedPattern(for: name)
                let pattern = name.hasPrefix("$")
                    ? "(?i)(?<![\\w$])\(escaped)(?![\\w$])"
                    : "(?i)\\b\(escaped)\\b"
                return matches(pattern, text)
            }
        }

        func hasUnsanitizedTaint(_ text: String) -> Bool {
            let remaining = withoutSanitizers(text)
            guard matches(untrusted, remaining) || containsTaintedName(remaining) else { return false }
            let masked = maskLiteralProse(remaining, keepPHPVariables: suffix == "php")
            return matches(untrusted, masked) || containsTaintedName(masked)
        }

        for (index, rawLine) in codeLines.enumerated() {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("//") || line.hasPrefix("#") || line.hasPrefix("/*") || line.hasPrefix("*") {
                continue
            }
            if let name = firstCapture(assignmentName, in: line), let equals = line.firstIndex(of: "=") {
                let expression = String(line[line.index(after: equals)...])
                let expressionIsTainted = hasUnsanitizedTaint(expression)
                let isSafePreparedStatement = suffix == "php" && expression.localizedCaseInsensitiveContains("prepare") && matches(
                        #"(?i)(?:\b(?:prepareStatement|mysqli_prepare)\b|(?:->|::)\s*prepare\b)\s*\([^;\n]*["'][^"']*(?:\?|%s|:\w+|@\w+|\$\d+)[^"']*["']"#,
                    expression
                ) && !expressionIsTainted
                if isSafePreparedStatement {
                    safePreparedStatements.insert(name)
                } else {
                    safePreparedStatements.remove(name)
                }
                if expressionIsTainted {
                    tainted.insert(name)
                } else {
                    tainted.remove(name)
                }
            }

            guard hasUnsanitizedTaint(line) else { continue }
            for (ruleID, sink, severity, title, recommendation) in sinks {
                if ruleID == "code.sql-dynamic-query" {
                    let lowered = line.lowercased()
                    guard sqlSinkTokens.contains(where: lowered.contains) else {
                        continue
                    }
                }
                guard matches(sink, line) else { continue }
                // Taint anywhere on the line is not enough for a call sink: the
                // untrusted value has to be an argument of that call, otherwise
                // `ctx.save()` beside unrelated request handling reads as a flow.
                if let callEnd = matchEnd(sink, line), let arguments = callArguments(line, callEnd: callEnd) {
                    guard hasUnsanitizedTaint(arguments) else { continue }
                }
                if ruleID == "code.sql-dynamic-query" {
                    let inlineBinding = matches(
                        #"(?i)(?:\b(?:"# + sqlCallNames + #")\b|(?:->|::)\s*(?:query|exec|prepare|execute)\b|\b(?:jdbcTemplate|namedParameterJdbcTemplate)\s*\.\s*update\b)\s*\(\s*[furb]*["'][^"']*(?:\?|%s|:\w+|@\w+|\$\d+)[^"']*["']\s*,"#,
                        line
                    ) || matches(#"(?i)\bmysqli_execute_query\s*\(\s*[^,]+,\s*["'][^"']*\?[^"']*["']\s*,"#, line)
                        || matches(#"(?i)\bpg_query_params\s*\(\s*[^,]+,\s*["'][^"']*\$\d+[^"']*["']\s*,"#, line)
                    let methodReceiver = firstCapture(
                        #"(?i)(\$?[A-Za-z_][\w$]*)\s*(?:->|\.)\s*(?:execute|executeQuery|executeUpdate|executeLargeUpdate|executeBatch|ExecuteReader|ExecuteScalar|ExecuteNonQuery|ExecuteReaderAsync|ExecuteScalarAsync|ExecuteNonQueryAsync)\s*\("#,
                        in: line
                    )
                    let functionReceiver = firstCapture(
                        #"(?i)\bmysqli_stmt_execute\s*\(\s*(\$?[A-Za-z_][\w$]*)"#,
                        in: line
                    )
                    if inlineBinding
                        || methodReceiver.map({ safePreparedStatements.contains($0) }) == true
                        || functionReceiver.map({ safePreparedStatements.contains($0) }) == true {
                        continue
                    }
                }
                if ruleID == "code.command-injection" && matches(#"(?i)subprocess\.(run|call|Popen|check_output)\s*\(\s*\["#, line) && !matches(#"(?i)shell\s*=\s*True"#, line) {
                    continue
                }
                if ruleID == "code.unsafe-deserialization" && matches(#"(?i)yaml\.load\s*\([^\n]*(Loader\s*=\s*yaml\.SafeLoader|SafeLoader)"#, line) {
                    continue
                }
                // Mass assignment is about binding a whole request body onto a
                // model, not about any call that happens to mention the request.
                if ruleID == "code.api-mass-assignment" && !matches(requestBody, line) {
                    continue
                }
                let key = "\(ruleID):\(index + 1)"
                guard seen.insert(key).inserted else { continue }
                findings.append(finding(
                    ruleID,
                    severity,
                    "code",
                    title,
                    displayPath,
                    index + 1,
                    lines[index],
                    recommendation,
                    verificationStatus: "confirmed"
                ))
                break
            }
        }
        return findings
    }

    private func preferConfirmedFindings(_ findings: [NativeFinding]) -> [NativeFinding] {
        var result: [NativeFinding] = []
        for finding in findings {
            if let index = result.firstIndex(where: { $0.ruleID == finding.ruleID && $0.line == finding.line && $0.path == finding.path }) {
                if result[index].verificationStatus != "confirmed" && finding.verificationStatus == "confirmed" {
                    result[index] = finding
                }
            } else {
                result.append(finding)
            }
        }
        let selected = Set(Dictionary(grouping: result, by: \.ruleID).values.flatMap { group in
            group.sorted {
                if $0.verificationStatus != $1.verificationStatus {
                    return $0.verificationStatus == "confirmed"
                }
                return ($0.line ?? 0) < ($1.line ?? 0)
            }.prefix(5)
        })
        return result.filter { selected.contains($0) }
    }

    /// Drops prose inside string literals, keeping interpolations and labelled
    /// keys, so a sensitive *word* in an English log message is not read as
    /// sensitive *data* reaching the log.
    private func maskLiteralProse(_ line: String, keepPHPVariables: Bool = false) -> String {
        guard let literals = try? NSRegularExpression(pattern: #"(['"`])(?:\\.|(?!\1).)*?\1"#),
              // Only interpolations stay. A bare label inside a literal is prose:
              // `"shlex: token="` is a debug caption, not a credential in a log.
              let keep = try? NSRegularExpression(pattern: #"\$\{[^}]*\}|\{[^{}]*\}"#),
              let phpVariable = try? NSRegularExpression(pattern: #"(?<!\\)\$[A-Za-z_]\w*"#) else {
            return line
        }
        var output = line
        let range = NSRange(line.startIndex..<line.endIndex, in: line)
        for match in literals.matches(in: line, range: range).reversed() {
            guard let literalRange = Range(match.range, in: line) else { continue }
            let literal = String(line[literalRange])
            let literalNSRange = NSRange(literal.startIndex..<literal.endIndex, in: literal)
            var kept = keep.matches(in: literal, range: literalNSRange).compactMap { item -> String? in
                guard let keptRange = Range(item.range, in: literal) else { return nil }
                return String(literal[keptRange])
            }
            if keepPHPVariables && literal.first != "'" {
                kept += phpVariable.matches(in: literal, range: literalNSRange).compactMap { item -> String? in
                    guard let keptRange = Range(item.range, in: literal) else { return nil }
                    return String(literal[keptRange])
                }
            }
            output.replaceSubrange(literalRange, with: "\"\(kept.joined(separator: " "))\"")
        }
        return output
    }

    private func checkCode(lines: [String], file: URL, displayPath: String) -> [NativeFinding] {
        if ["js", "mjs", "cjs"].contains(file.pathExtension.lowercased()) {
            let normalizedPath = "/" + displayPath.lowercased()
                .replacingOccurrences(of: "-", with: "_")
                .trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/"
            let banner = lines.prefix(5).joined(separator: "\n")
            let isVendoredPath = normalizedPath.contains("/vendor/")
                || normalizedPath.contains("/vendors/")
                || normalizedPath.contains("/thirdparty/")
                || normalizedPath.contains("/third_party/")
                || normalizedPath.contains("/node_modules/")
            let hasLibraryBanner = matches(#"(?i)\b(jquery|jsrender|datepicker|lodash|bootstrap|angular|react|vue|moment)\b[^\n]{0,100}\bv?\d+(?:\.\d+)+"#, banner)
            let isVersionedLibraryFile = matches(#"(?i)^(jquery|lodash|bootstrap|angular|react(?:\.production)?|vue(?:\.runtime)?|moment|jsrender|datepicker)[._-]?v?\d+(?:\.\d+)*(?:\.min)?\.(?:js|mjs|cjs)$"#, file.lastPathComponent)
            let isNamedLibraryFile = matches(#"(?i)^(jquery|lodash|bootstrap|angular|react(?:\.production)?|vue(?:\.runtime)?|moment|jsrender|datepicker)(?:\.min)?\.(?:js|mjs|cjs)$"#, file.lastPathComponent)
            if isVersionedLibraryFile || (isNamedLibraryFile && (isVendoredPath || hasLibraryBanner)) {
                return []
            }
        }
        // Every rule below reads the whole-file code view, not the raw line, so a
        // single line is never judged out of its file context.
        let codeLines = codeView(lines: lines, suffix: file.pathExtension.lowercased())
        let statements = logicalLines(codeLines)
        var findings = checkJavaDocumentBuilderXXE(lines: lines, codeLines: codeLines, file: file, displayPath: displayPath)
        findings += checkJavaNullPointerDereference(lines: lines, codeLines: codeLines, file: file, displayPath: displayPath)
        findings += checkContextualSourceFlows(
            lines: lines,
            codeLines: statements,
            displayPath: displayPath,
            suffix: file.pathExtension.lowercased()
        )
        let document = codeLines.joined(separator: "\n")
        let suffix = file.pathExtension.lowercased()
        var safeDateFormatValuesBeforeLine = Array(repeating: Set<String>(), count: statements.count)
        if ["java", "kt"].contains(suffix)
            && matches(#"\bimport\s+devonframe\.util\.DateUtil\s*;?"#, document) {
            var safeDateFormatValues = Set<String>()
            for (index, statement) in statements.enumerated() {
                if startsFunctionScope(statement, suffix: suffix) {
                    safeDateFormatValues.removeAll()
                }
                safeDateFormatValuesBeforeLine[index] = safeDateFormatValues
                if let written = firstCapture(#"(?<![\w$])([A-Za-z_$][\w$]*)\s*(?:(?:<<|>>|[+\-*/%&|^])?=(?!=))"#, in: statement) {
                    safeDateFormatValues.remove(written)
                }
                if let name = firstCapture(#"\b([A-Za-z_$][\w$]*)\s*=\s*DateUtil\.getDate\s*\(\s*[\"'][^\"'%]+[\"']\s*\)"#, in: statement) {
                    safeDateFormatValues.insert(name)
                }
                if let name = firstCapture(#"\b([A-Za-z_$][\w$]*)\s*=\s*DateUtil\.(?:getNextMonthDate|getPrevDate)\s*\("#, in: statement),
                   let source = firstCapture(#"DateUtil\.(?:getNextMonthDate|getPrevDate)\s*\(\s*([A-Za-z_$][\w$]*)\s*,"#, in: statement),
                   safeDateFormatValues.contains(source) {
                    safeDateFormatValues.insert(name)
                }
            }
        }
        if ["java", "kt"].contains(suffix) {
            var acquired: [String: Int] = [:]
            var released = Set<String>()
            func appendUnreleasedResources() {
                for (name, index) in acquired where !released.contains(name) {
                    let nearby = statements[max(0, index - 1)...min(statements.count - 1, index + 1)].joined(separator: "\n")
                    if !matches(#"\btry\s*\([^)]*\b"# + NSRegularExpression.escapedPattern(for: name) + #"\b"#, nearby) {
                        findings.append(finding("code.improper-resource-release", "medium", "code", "자원 해제 누락 가능성", displayPath, index + 1, lines[index], "모든 경로에서 자원을 닫거나 try-with-resources를 사용하세요."))
                    }
                }
            }
            for (index, statement) in statements.enumerated() {
                if startsFunctionScope(statement, suffix: suffix) {
                    appendUnreleasedResources()
                    acquired.removeAll()
                    released.removeAll()
                }
                if let name = firstCapture(#"\b([A-Za-z_$][\w$]*)\s*=\s*[^;]*(?:getConnection|prepareStatement|createStatement|new\s+(?:File)?InputStream|Files\.newInputStream)"#, in: statement) {
                    acquired[name] = index
                    released.remove(name)
                }
                for name in acquired.keys where matches(#"\b"# + NSRegularExpression.escapedPattern(for: name) + #"\s*\.\s*(?:close|release)\s*\("#, statement) {
                    released.insert(name)
                }
            }
            appendUnreleasedResources()
        }
        if ["c", "cc", "cpp", "cxx", "h", "hpp"].contains(suffix) {
            var freed: [String: Int] = [:]
            var uninitialized = Set<String>()
            for (index, statement) in statements.enumerated() {
                if startsFunctionScope(statement, suffix: suffix) {
                    freed.removeAll()
                    uninitialized.removeAll()
                }
                if let name = firstCapture(#"\b(?:int|char|float|double|long|short|size_t)\s+([A-Za-z_]\w*)\s*;"#, in: statement) {
                    uninitialized.insert(name)
                    continue
                }
                if let name = firstCapture(#"\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)\s*;"#, in: statement) {
                    freed[name] = index
                    continue
                }
                for name in Array(uninitialized) {
                    let escaped = NSRegularExpression.escapedPattern(for: name)
                    if matches(#"\b"# + escaped + #"\s*="# , statement) {
                        uninitialized.remove(name)
                    } else if matches(#"\b(?:return|printf|fprintf|assert)\b[^;]*\b"# + escaped + #"\b|\b"# + escaped + #"\b\s*[+\-*/;,)\]]"#, statement) {
                        findings.append(finding("code.uninitialized-variable", "high", "code", "초기화되지 않은 변수 사용 가능성", displayPath, index + 1, lines[index], "지역 변수를 모든 제어 흐름에서 읽기 전에 초기화하세요."))
                        uninitialized.remove(name)
                    }
                }
                for name in Array(freed.keys) {
                    let escaped = NSRegularExpression.escapedPattern(for: name)
                    if matches(#"\b"# + escaped + #"\s*="# , statement) {
                        freed.removeValue(forKey: name)
                    } else if matches(#"\b"# + escaped + #"\b"#, statement) {
                        findings.append(finding("code.use-after-free", "high", "code", "해제된 자원 사용 가능성", displayPath, index + 1, lines[index], "free 이후 포인터를 사용하지 말고 NULL로 초기화하거나 새 자원으로 재할당하세요."))
                        freed.removeValue(forKey: name)
                    }
                }
            }
        }
        var dnsNames = Set<String>()
        for (index, statement) in statements.enumerated() {
            if startsFunctionScope(statement, suffix: suffix) {
                dnsNames.removeAll()
            }
            if let written = firstCapture(#"(?<![\w$])([A-Za-z_$][\w$]*)\s*(?:(?:<<|>>|[+\-*/%&|^])?=(?!=))"#, in: statement) {
                dnsNames.remove(written)
            }
            if let name = firstCapture(#"\b([A-Za-z_]\w*)\s*=\s*[^;]*(?:gethostbyname|getaddrinfo|gethostbyaddr|getnameinfo|socket\.gethost|dns\.lookup|InetAddress\.getByName)"#, in: statement) {
                dnsNames.insert(name)
            }
            if matches(#"(?i)\b(?:auth|authoriz|allow|permit|trust|trusted|is_internal|role|admin|principal)\w*\b"#, statement),
               matches(#"(?:==|!=|\bin\b|\.equals\s*\(|\.contains\s*\()"#, statement),
               dnsNames.contains(where: { matches(#"\b"# + NSRegularExpression.escapedPattern(for: $0) + #"\b"#, statement) }) {
                findings.append(finding("code.dns-security-decision", "medium", "code", "DNS 결과를 사용한 보안결정 가능성", displayPath, index + 1, lines[index], "DNS 이름 대신 인증된 식별자와 인증서 검증을 사용하세요."))
            }
        }
        let hasAuthEntry = matches(#"(?im)(?:@(?:\w+\.)?(?:post|route)\s*\([^\n]*(?:login|sign[_-]?in|authenticate|token)|\b(?:app|router|server)\.(?:post|use)\s*\([^\n]*(?:login|sign[_-]?in|authenticate|token)|\b(?:def|function|public|private|protected)\s+\w*(?:login|signin|authenticate|issueToken)\w*)"#, document)
        let hasAuthSink = matches(#"(?i)\b(?:authenticate|verifyPassword|check_password|issueToken|create_access_token|authenticationManager\.authenticate)\s*\("#, document)
        let hasAuthAttemptProtection = matches(#"(?i)\b(?:express-rate-limit|rateLimit|RateLimiter|SlowAPIMiddleware|limiter\.limit|Bucket4j|failedAttempts?|loginAttempts?|lockAccount|lockedUntil|accountLocked|captcha|mfa|2fa|otp|webauthn)\b"#, document)
        if hasAuthEntry && hasAuthSink && !hasAuthAttemptProtection,
           let index = statements.firstIndex(where: { matches(#"(?i)(?:login|sign[_-]?in|authenticate|token)"#, $0) }) {
            findings.append(finding("code.auth-attempt-protection-missing", "medium", "code", "반복 인증시도 제한 기능 부재 가능성", displayPath, index + 1, lines[index], "로그인 흐름에 인증 전용 속도 제한, 실패 횟수, 잠금 또는 추가 인증을 적용하세요."))
        }
        let hasRateLimit = matches(#"(?i)\b(express-rate-limit|rateLimit\s*\(|RateLimiter|SlowAPIMiddleware|@\w*limiter\.limit|Bucket4j|resilience4j.*ratelimit)"#, document)
        let hasGlobalAuth = matches(#"(?i)\b(app|router|server)\.use\s*\([^\n]*(authenticate|authorize|requireAuth|requireAdmin)|\b(SecurityFilterChain|OncePerRequestFilter|AuthMiddleware|AuthorizationMiddleware)\b"#, document)
        let sanitizerOnLine = #"(?i)\b(DOMPurify\.sanitize|sanitizeHtml|escapeHtml|html\.escape|encodeForHTML|secure_filename|Path\.GetFileName|basename|realpath|canonicalPath|allowlist|allowed_hosts?|validate(?:Url|Path|Host|Redirect|Input)|escapeLdap|encodeForLDAP|stripCrLf|sanitizeHeader)\b"#
        for (index, line) in statements.enumerated() {
            let lineNumber = index + 1
            let rawLine = lines[index]
            if line.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { continue }
            let nearby = codeLines[max(0, index - 5)...min(codeLines.count - 1, index + 5)].joined(separator: "\n")
            let hasSanitizer = matches(sanitizerOnLine, line)
            if !hasSanitizer && matches(#"(?i)\.innerHTML\s*=.*(location|document\.URL|request|params)"#, line) {
                findings.append(finding("code.xss-dom-sink", "high", "code", "DOM XSS 위험 sink", displayPath, lineNumber, rawLine, "신뢰할 수 없는 입력을 HTML로 직접 삽입하지 말고 escaping 또는 textContent를 사용하세요."))
            }
            if (matches(#"(?i)(?:execute|executemany|executescript|executeQuery|executeUpdate|executeLargeUpdate|addBatch|query|raw|prepareStatement|createQuery|createNativeQuery|createSQLQuery|batchUpdate|SqlCommand|ExecuteSqlRaw|ExecuteSqlRawAsync|ExecuteSqlCommand|FromSqlRaw|FromSqlRawAsync|SqlQueryRaw|mysqli_(?:query|real_query|multi_query|prepare)|(?:->|::)\s*(?:query|exec|prepare)|(?:jdbcTemplate|namedParameterJdbcTemplate)\s*\.\s*update)\s*\(.*(SELECT|INSERT|UPDATE|DELETE|MERGE).*(\+|f"|%\s|\.\s*\$)"#, line)
                || matches(#"(?i)\.\s*CommandText\s*(?:\+?=).*(SELECT|INSERT|UPDATE|DELETE|MERGE|WHERE).*(\+|f"|%\s)"#, line))
                && !matches(#"(?i)(?:\b(?:execute|executemany|query|prepareStatement|createQuery|createNativeQuery|createSQLQuery|batchUpdate|SqlCommand|ExecuteSqlRaw|ExecuteSqlRawAsync|ExecuteSqlCommand|FromSqlRaw|FromSqlRawAsync|SqlQueryRaw)\b|(?:->|::)\s*(?:query|exec|prepare)|(?:jdbcTemplate|namedParameterJdbcTemplate)\s*\.\s*update)\s*\(\s*[furb]*[\"'][^\"']*(\?|%s|:\w+|@\w+|\$\d+)[^\"']*[\"']\s*,"#, line) {
                findings.append(finding("code.sql-dynamic-query", "high", "code", "동적 SQL 쿼리 구성", displayPath, lineNumber, rawLine, "파라미터 바인딩 또는 ORM 안전 API를 사용하세요."))
            }
            if matches(#"(?i)(os\.system|subprocess\.[A-Za-z_]+|exec\().*(shell\s*=\s*True|\+|request|params)"#, line)
                && !(matches(#"(?i)subprocess\.(run|call|Popen|check_output)\s*\(\s*\["#, line) && !matches(#"(?i)shell\s*=\s*True"#, line)) {
                findings.append(finding("code.command-injection", "high", "code", "명령어 삽입 위험", displayPath, lineNumber, rawLine, "쉘 실행을 피하고 인자를 배열로 전달하며 입력을 allowlist로 검증하세요."))
            }
            if !hasSanitizer && matches(#"(?i)\b(send_file|sendfile|readFile|readFileSync|createReadStream)\s*\(.*"# + Self.remoteSource, line) {
                findings.append(finding("code.path-traversal", "medium", "code", "경로 조작 위험", displayPath, lineNumber, rawLine, "사용자 입력 경로를 정규화하고 허용된 루트 내부인지 검증하세요."))
            }
            if matches(#"(?i)(@csrf_exempt|csrf\s*:\s*false|csrf\.disable|verify_csrf_token.*false|skip_before_action\s+:verify_authenticity_token|protect_from_forgery\s+except:)"#, line) {
                findings.append(finding("code.csrf-disabled", "medium", "code", "CSRF 보호가 비활성화된 것으로 보임", displayPath, lineNumber, rawLine, "브라우저 인증 기반 상태 변경 요청에는 CSRF 보호를 유지하세요."))
            }
            if matches(#"(?i)(@AllowAnonymous|@Public\(\)|permitAll\(\)|auth\s*:\s*false|AllowAny|permission_classes\s*=\s*\[\s*\]|skip_before_action\s+:authenticate)"#, line) {
                findings.append(finding("code.auth-disabled-endpoint", "medium", "code", "인증 또는 인가가 우회된 엔드포인트", displayPath, lineNumber, rawLine, "공개 의도가 명확한지 확인하고 민감 기능에는 권한 검사를 적용하세요."))
            }
            // `Function` stays case-sensitive (the JS `function` keyword is not a
            // sink) and timers only execute code when their first argument is a string.
            if matches(#"(?i)(?:\b(eval|exec|(?-i:Function)|instance_eval|class_eval)\s*\(|\b(setTimeout|setInterval)\s*\(\s*["'`]).*(req\.|request\.|\$_(GET|POST|REQUEST|FILES)|params|query|body|location\.|input\(|sys\.argv|ARGV)"#, line) {
                findings.append(finding("code.eval-user-input", "high", "code", "eval 계열 API에 사용자 입력이 연결됨", displayPath, lineNumber, rawLine, "동적 코드 실행을 제거하고 허용목록 기반 분기 처리로 대체하세요."))
            }
            if matches(#"(?i)(pickle\.loads|yaml\.load|ObjectInputStream|unserialize\()"#, line)
                && !matches(#"(?i)yaml\.load\s*\([^\n]*(Loader\s*=\s*yaml\.SafeLoader|SafeLoader)"#, line) {
                findings.append(finding("code.unsafe-deserialization", "high", "code", "위험한 역직렬화 사용", displayPath, lineNumber, rawLine, "신뢰할 수 없는 입력의 역직렬화를 금지하고 안전 로더를 사용하세요."))
            }
            if !hasSanitizer && matches(#"(?i)\b(requests|httpx|urllib\.request|axios|fetch|http\.get|https\.get|RestTemplate|WebClient).*(get|post|open|request|\().*(req\.|request\.|\$_(GET|POST|REQUEST|FILES)|params|query|body|location\.|input\(|sys\.argv|ARGV)"#, line) {
                findings.append(finding("code.ssrf-user-url", "high", "code", "사용자 입력 URL 요청으로 인한 SSRF 위험", displayPath, lineNumber, rawLine, "허용된 호스트만 요청하고 사설망 대역 접근을 차단하세요."))
            }
            if matches(#"(?i)(move_uploaded_file\s*\(\s*\$_FILES|\.save\s*\(.*(filename|originalname|req\.file)|multer\s*\(\s*\{\s*dest\s*:)"#, line) {
                findings.append(finding("code.unrestricted-file-upload", "medium", "code", "파일 업로드 제한이 부족할 수 있음", displayPath, lineNumber, rawLine, "확장자와 콘텐츠 유형을 검증하고 서버측 파일명을 생성하세요."))
            }
            if matches(#"(?i)\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\("#, line) {
                findings.append(finding("code.dangerous-c-buffer-api", "medium", "code", "위험한 C/C++ 버퍼 API 사용", displayPath, lineNumber, rawLine, "버퍼 크기를 검증하고 bounded API로 대체하세요."))
            }
            if matches(#"(?i)\b(express\.json|bodyParser\.json|express\.urlencoded|bodyParser\.urlencoded)\s*\(\s*\)"#, line) {
                findings.append(finding("code.unbounded-request-body", "low", "code", "요청 본문 크기 제한이 명시되지 않음", displayPath, lineNumber, rawLine, "요청 본문 크기 제한을 설정하고 과대 요청을 조기에 거부하세요."))
            }
            // Checked against the line with literal prose removed: "session
            // established" is an English message, not a session value in a log.
            if matches(#"(?i)(console\.(log|debug|info|warn|error)|logger\.(debug|info|warning|warn|error|exception)|logging\.(debug|info|warning|warn|error|exception)|print|System\.out\.println|NSLog|Log\.(d|i|w|e))\s*\(.*"# + Self.sensitiveName, maskLiteralProse(line)) {
                findings.append(finding("code.logging-sensitive-data", "medium", "code", "민감정보가 로그에 기록될 수 있음", displayPath, lineNumber, rawLine, "로그에서 민감값을 제거하거나 마스킹된 식별자만 기록하세요."))
            }
            if matches(#"(?i)(\bexcept\b[^:\n]*:\s*pass\b|\bcatch\s*(\([^)]*\))?\s*\{\s*\})"#, line) {
                findings.append(finding("code.empty-exception-handler", "low", "code", "예외가 조용히 무시되는 것으로 보임", displayPath, lineNumber, rawLine, "예상 예외를 명시적으로 처리하고 필요한 경우 보안 관련 실패를 기록하세요."))
            }
            if matches(#"(?i)(?:\bexcept\s*(?::|(?:Exception|BaseException)\b[^:]*:)|\bcatch\s*\(\s*(?:final\s+)?(?:Exception|Throwable|System\.Exception)\b|\brescue\s+Exception\b)"#, line) {
                findings.append(finding("code.broad-exception-handler", "low", "code", "과도하게 포괄적인 예외 처리", displayPath, lineNumber, rawLine, "예상 예외 형식을 구체적으로 처리하고 예상하지 못한 실패는 안전하게 재전파하세요."))
            }
            if matches(#"(?i)\b(printStackTrace|traceback\.print_exc|console\.trace)\s*\("#, line)
                && !matches(#"(?i)\b(if|guard)\b[^\n]*(DEBUG|development|isDev|devMode)"#, nearby) {
                findings.append(finding("code.stack-trace-exposure", "low", "code", "스택 트레이스 출력이 내부 정보를 노출할 수 있음", displayPath, lineNumber, rawLine, "중앙 오류 처리로 전달하고 사용자 노출 경로에서는 원본 스택을 숨기세요."))
            }
            if matches(#"(?i)(@\w+\.route|(?:app|router|routes|server)\.(?:get|post|put|patch|delete|use)|Route|path)\s*\(.*['"]/api/(?!v\d+(?:/|$))[^'"]+['"]"#, line) {
                findings.append(finding("code.unversioned-api-route", "low", "code", "API 라우트에 버전이 명시되지 않음", displayPath, lineNumber, rawLine, "공개 API에는 /api/v1 같은 명시적 버전 경로를 사용하세요."))
            }
            if matches(#"(?i)mktemp\s*\("#, line) {
                findings.append(finding("code.insecure-temp-file", "medium", "code", "불안전한 임시 파일 생성", displayPath, lineNumber, rawLine, "경쟁 조건을 피하기 위해 안전한 임시 파일 API를 사용하세요."))
            }
            if matches(#"(?i)(CORS|Access-Control-Allow-Origin).*(\*|origins\s*=\s*['\"]\*)"#, line) {
                findings.append(finding("code.wildcard-cors", "medium", "code", "와일드카드 CORS 설정", displayPath, lineNumber, rawLine, "허용 origin을 명시적으로 제한하세요."))
            }
            if matches(#"(?i)(host\s*=\s*['\"]0\.0\.0\.0|listen\([^)]*0\.0\.0\.0)"#, line) {
                findings.append(finding("code.public-bind-all-interfaces", "low", "code", "전체 인터페이스 바인딩", displayPath, lineNumber, rawLine, "개발 서버는 localhost에만 바인딩하세요."))
            }
            // `usedforsecurity=False` is the caller declaring this hash is not a
            // security control; `\b` would miss `file_checksum`, because `_` is
            // a word character.
            if matches(#"(?i)(md5|sha1)\s*\("#, line)
                && !matches(#"(?i)usedforsecurity\s*=\s*False"#, line)
                && !matches(#"(?i)\w*(checksum|etag|cache[_-]?key|content[_-]?hash|file[_-]?hash)\w*"#, nearby) {
                findings.append(finding("code.weak-hash", "medium", "code", "약한 해시 알고리즘 사용", displayPath, lineNumber, rawLine, "SHA-256 이상 또는 비밀번호에는 bcrypt/argon2를 사용하세요."))
            }
            if matches(#"(?i)(secure\s*:\s*false|httpOnly\s*:\s*false|SameSite\s*=\s*None)"#, line) {
                findings.append(finding("code.insecure-cookie-settings", "medium", "code", "쿠키/세션 보안 설정 약화", displayPath, lineNumber, rawLine, "Secure, HttpOnly, SameSite 속성을 적절히 설정하세요."))
            }
            if matches(#"(?i)\b(?:cookie|set-cookie)\b"#, line)
                && matches(#"(?i)\b(?:pass(?:word)?|passwd|pwd|secret|credentials?|authorization|jwt|(?:access|refresh|auth|id|bearer|csrf|xsrf|session)[_-]?tokens?|tokens?|api[_-]?keys?|secret[_-]?keys?|private[_-]?keys?|session[_-]?ids?|sessions?)\b"#, line)
                && matches(#"(?i)\b(?:max[_-]?age|expires?)\b"#, line) {
                findings.append(finding("code.persistent-sensitive-cookie", "medium", "code", "민감 값이 영속 쿠키에 저장될 수 있음", displayPath, lineNumber, rawLine, "민감 쿠키는 가능한 세션 범위로 제한하고 불투명하며 폐기 가능한 식별자만 저장하세요."))
            }
            if matches(#"(?i)(verify_signature\s*[:=]\s*False|verify\s*[:=]\s*false|jwt\.decode.*(verify\s*=\s*False|verify_signature.*False))"#, line) {
                findings.append(finding("code.jwt-verification-disabled", "high", "code", "JWT 서명 검증이 비활성화된 것으로 보임", displayPath, lineNumber, rawLine, "모든 JWT에 대해 서명, issuer, audience, 만료, 알고리즘 검증을 강제하세요."))
            }
            if matches(#"(?i)(algorithms?\s*[:=]\s*\[[^\]]*["']none["']|alg\s*[:=]\s*["']none["'])"#, line) {
                findings.append(finding("code.jwt-none-algorithm", "high", "code", "JWT none 알고리즘 허용 의심", displayPath, lineNumber, rawLine, "승인된 서명 알고리즘 allowlist만 허용하고 unsigned token은 거부하세요."))
            }
            if matches(#"(?i)(SESSION_COOKIE_AGE\s*=\s*([7-9]\d{5,}|[1-9]\d{6,})|maxAge\s*[:=]\s*([7-9]\d{8,}|[1-9]\d{9,})|expiresIn\s*[:=]\s*["'](365d|[2-9]\d{2,}d|[1-9]\d+y)["'])"#, line) {
                findings.append(finding("code.session-long-expiry", "low", "code", "세션 또는 토큰 만료 시간이 과도함", displayPath, lineNumber, rawLine, "짧은 access token, 회전되는 refresh token, 장기 세션 예외 문서를 사용하세요."))
            }
            if !hasGlobalAuth
                && !matches(#"(?i)\b(requireAuth|requireAdmin|authenticate|authorize|isAuthenticated|checkPermission)\b"#, line)
                && matches(#"(?i)((app|router|server)\.(get|post|put|patch|delete)\s*\(["'][^"']*/api/[^"']*(admin|user|account|payment|order|profile|secret|token)[^"']*["'][^\n]*\(?\s*(req|request|ctx)\s*\)?\s*=>)"#, line) {
                findings.append(finding("code.api-route-missing-auth", "medium", "code", "민감 API 라우트에 인증 가드가 보이지 않음", displayPath, lineNumber, rawLine, "민감 API handler 실행 전에 라우트 수준 인증과 객체/기능 권한 검사를 강제하세요."))
            }
            if matches(#"(?i)(\b(create|update|assign|save|insert|merge)\s*\([^\n]*\b(req|request)\s*\.\s*(body|data|json|POST|form|params|query|values)\b|\.\.\.\s*(req|request)\s*\.\s*body\b)"#, line) {
                findings.append(finding("code.api-mass-assignment", "medium", "code", "API 요청 body의 mass assignment 의심", displayPath, lineNumber, rawLine, "허용 필드만 명시적으로 매핑하고 예상하지 않은 속성은 저장 전에 거부하세요."))
            }
            if !hasRateLimit && matches(#"(?i)(express\s*\(\)|FastAPI\s*\(|new\s+Koa\s*\(|SpringApplication\.run)"#, line) {
                findings.append(finding("code.api-missing-rate-limit", "low", "code", "API rate limit 기준이 보이지 않음", displayPath, lineNumber, rawLine, "로그인, 가입, 검색, export, 고비용 API에 rate limit과 남용 방지 통제를 추가하세요."))
            }
            if matches(#"(?i)\b(requests\.(get|post|put|patch|delete)|httpx\.(get|post|put|patch|delete)|axios\.(get|post|put|patch|delete)|fetch)\s*\([^\n]*(https?://|url|endpoint)"#, line) && !matches(#"(?i)(timeout|signal|AbortController)\s*[:=]"#, nearby) {
                findings.append(finding("code.external-api-no-timeout", "low", "code", "외부 API 호출에 timeout이 보이지 않음", displayPath, lineNumber, rawLine, "외부 API 호출에 timeout, backoff 재시도, 목적지 allowlist를 적용하세요."))
            }
            if matches(#"(?i)(console\.(log|debug|info|warn|error)|logger\.(debug|info|warning|warn|error|exception)|logging\.(debug|info|warning|warn|error|exception)|print|System\.out\.println|NSLog|Log\.(d|i|w|e))\s*\(.*(email|phone|mobile|address|birth|dob|ssn|resident|rrn|jumin|주민|전화|주소|생년|card[_-]?number)"#, maskLiteralProse(line)) {
                findings.append(finding("code.pii-logging", "medium", "code", "개인정보 로깅 의심", displayPath, lineNumber, rawLine, "개인정보는 로그에서 제거하거나 마스킹하고 보관 기간과 접근 권한을 문서화하세요."))
            }
            if matches(#"(?i)Options\s+Indexes"#, line) {
                findings.append(finding("code.directory-listing-enabled", "medium", "code", "디렉터리 리스팅 활성화", displayPath, lineNumber, rawLine, "디렉터리 인덱싱을 비활성화하세요."))
            }
            if matches(#"(?i)WebDAV(Module| enabled| true)"#, line) {
                findings.append(finding("code.webdav-enabled", "medium", "code", "WebDAV 활성화 흔적", displayPath, lineNumber, rawLine, "필요하지 않은 WebDAV 기능을 비활성화하세요."))
            }
            if matches(#"(?i)\b(technote|zeroboard)\b"#, line) {
                findings.append(finding("code.legacy-board-software", "medium", "code", "레거시 게시판 소프트웨어 흔적", displayPath, lineNumber, rawLine, "컴포넌트 사용 여부를 확인하고 최신 버전으로 교체하거나 제거하세요."))
            }
            let handledJavaDocumentBuilder = ["java", "kt"].contains(file.pathExtension.lowercased()) && line.contains("DocumentBuilderFactory")
            if !handledJavaDocumentBuilder && matches(#"(?i)(resolve_entities\s*=\s*True|load_dtd\s*=\s*True|DocumentBuilderFactory|SAXParserFactory|XmlReaderSettings|XmlDocument)"#, line) {
                findings.append(finding("code.xml-external-entity", "high", "code", "XML 외부 엔티티 처리가 허용될 수 있음", displayPath, lineNumber, rawLine, "DTD와 외부 엔티티 해석을 비활성화한 안전한 XML parser 설정을 사용하세요."))
            }
            if !hasSanitizer && matches(#"(?i)(sendRedirect\s*\(.*request\.getParameter|(res|response|ctx)\.redirect\s*\(.*(req\.|request\.|params|query|body)|\bredirect\s*\(.*(request\.|req\.|params|query|body))"#, line) {
                findings.append(finding("code.open-redirect-user-input", "medium", "code", "사용자 입력 기반 Open Redirect 의심", displayPath, lineNumber, rawLine, "리다이렉트 대상은 내부 경로 허용목록에 매핑하고 외부 URL은 거부하세요."))
            }
            if matches(#"(?i)(<[A-Za-z][\w:-]*>.*(\+|%|\$\{).*(request|req\.|params|query|body|input))"#, line) {
                findings.append(finding("code.xml-injection", "medium", "code", "XML 문자열 삽입 의심", displayPath, lineNumber, rawLine, "문자열 연결 대신 XML serializer를 사용하고 입력을 XML 문맥에 맞게 인코딩하세요."))
            }
            if !hasSanitizer && matches(#"(?i)(LdapTemplate|DirContext|ldap\w*).*search.*(\+|\.format\(|f[\"'])"#, line) {
                findings.append(finding("code.ldap-injection", "high", "code", "LDAP 필터 삽입 의심", displayPath, lineNumber, rawLine, "LDAP 필터 메타문자를 이스케이프하거나 파라미터화된 API를 사용하세요."))
            }
            if !hasSanitizer && matches(#"(?i)\b(setHeader|addHeader|set_header|writeHead)\s*\(.*(request\.|req\.|params|query|body|input)"#, line) {
                findings.append(finding("code.http-response-splitting", "medium", "code", "HTTP 응답 분할 의심", displayPath, lineNumber, rawLine, "헤더 값의 CR/LF를 거부하고 허용 형식만 사용하세요."))
            }
            let formatConstant = firstCapture(#"\bString\.format\s*\(\s*([A-Z][A-Z0-9_]*)\s*[,)]"#, in: line)
            let hasFixedFormatDeclaration = formatConstant.map { name in
                matches(#"\b(?:static\s+)?final\s+String\s+"# + NSRegularExpression.escapedPattern(for: name) + #"\s*=\s*[\"']"#, document)
            } ?? false
            let formatVariable = firstCapture(#"\bString\.format\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]"#, in: line)
            let hasSafeDateFormatValue = formatVariable.map { safeDateFormatValuesBeforeLine[lineNumber - 1].contains($0) } ?? false
            if !hasFixedFormatDeclaration && !hasSafeDateFormatValue && matches(#"(?i)(\b(printf|vprintf|syslog)\s*\(\s*[A-Za-z_][\w>.\-\[\]]*\s*\)|\bString\.format\s*\(\s*[A-Za-z_][\w.\[\]]*\s*[,\)])"#, line) {
                findings.append(finding("code.format-string-user-input", "high", "code", "변수 기반 포맷 문자열 사용", displayPath, lineNumber, rawLine, "상수 포맷 문자열을 사용하고 동적 값은 별도 인자로 전달하세요."))
            }
            if matches(#"(?i)(\bRSA\b.{0,60}\b(512|768|1024)\b|\bKeyPairGenerator\b.*initialize\s*\(\s*(512|768|1024))"#, line) {
                findings.append(finding("code.insufficient-key-length", "medium", "code", "부족한 암호키 길이 의심", displayPath, lineNumber, rawLine, "RSA/DSA/DH는 최소 2048비트 또는 승인된 현대적 타원곡선 알고리즘을 사용하세요."))
            }
            if matches(#"(?i)\b(token|otp|nonce|salt|session[_-]?id|secret|password|api[_-]?key)\w*\s*[:=].*(Math\.random|new\s+Random\s*\(|random\.(random|randint|choice)|\brand\s*\()"#, line) {
                findings.append(finding("code.insecure-random-security-use", "medium", "code", "보안 용도에 비암호학적 난수 사용", displayPath, lineNumber, rawLine, "토큰·키·인증코드에는 CSPRNG를 사용하세요."))
            }
            if matches(#"(?i)(verify\s*=\s*False|rejectUnauthorized\s*[:=]\s*false|InsecureSkipVerify\s*:\s*true|check_hostname\s*=\s*False|ssl\.CERT_NONE)"#, line) {
                findings.append(finding("code.tls-certificate-verification-disabled", "high", "code", "TLS 인증서 검증 비활성화", displayPath, lineNumber, rawLine, "인증서와 호스트명 검증을 유지하고 올바른 신뢰 저장소를 구성하세요."))
            }
            // Either order: the credential can precede or follow the hash call.
            if matches(#"(?i)(\b(password|passwd|pwd|pin|credential)\w*\b.*\b(hashlib\.(md5|sha1|sha256)|MessageDigest\.getInstance|DigestUtils\.(md5|sha1|sha256)\w*|crypto\.createHash)\b|\b(hashlib\.(md5|sha1|sha256)|crypto\.createHash)\b.*\b(password|passwd|pwd|pin)\b)"#, line) {
                findings.append(finding("code.password-hash-without-salt", "medium", "code", "솔트 없는 비밀번호 해시 의심", displayPath, lineNumber, rawLine, "비밀번호는 고유 솔트를 적용하는 Argon2, bcrypt, scrypt 또는 PBKDF2로 저장하세요."))
            }
            if matches(#"(?i)\b(system|developer|prompt|messages?)\s*[:=].*(\+|f["']|`\$\{).*"# + Self.remoteSource, line) {
                findings.append(finding("code.llm-prompt-user-concat", "medium", "code", "LLM 프롬프트에 사용자 입력이 직접 결합됨", displayPath, lineNumber, rawLine, "시스템 지시는 고정하고 사용자 콘텐츠는 별도 메시지 필드로 분리하며 프롬프트 인젝션 테스트를 추가하세요."))
            }
            if matches(#"(?i)(tool_choice\s*[:=]\s*["']auto|function_call\s*[:=]\s*["']auto|tools\s*[:=]\s*\[[^\]]*(exec|shell|browser|http|file|database))"#, line) {
                findings.append(finding("code.llm-tool-unrestricted", "high", "code", "LLM 도구 호출 권한이 넓게 열려 있음", displayPath, lineNumber, rawLine, "작업별 도구 allowlist, 인자 검증, 부작용 확인, 도구 호출 로그를 적용하세요."))
            }
            if matches(#"(?i)(openai|anthropic|chat\.completions|responses\.create|generateContent).*(password|pwd|secret|token|api[_-]?key|authorization|credential|session|cookie)"#, line) {
                findings.append(finding("code.llm-sensitive-data-in-prompt", "medium", "code", "민감정보가 LLM 프롬프트로 전달될 수 있음", displayPath, lineNumber, rawLine, "LLM 호출 전 민감값을 제거하거나 마스킹하고 프롬프트가 로컬 신뢰 경계를 벗어나는지 문서화하세요."))
            }
        }
        return preferConfirmedFindings(findings)
    }

    private func checkScreenQuality(lines: [String], file: URL, displayPath: String) -> [NativeFinding] {
        let screenExtensions: Set<String> = ["html", "htm", "jsp", "jspx", "clx", "js", "vue", "jsx", "tsx"]
        let htmlExtensions: Set<String> = ["html", "htm", "jsp", "jspx"]
        let suffix = file.pathExtension.lowercased()
        guard screenExtensions.contains(suffix) else { return [] }

        let text = lines.joined(separator: "\n")
        let lowerText = text.lowercased()
        let labelTargets = Set(captures(#"(?i)<label\b[^>]*\bfor\s*=\s*['"]([^'"]+)['"]"#, in: text))
        var findings: [NativeFinding] = []

        if htmlExtensions.contains(suffix),
           lowerText.contains("<html"),
           !matches(#"(?i)<html\b[^>]*\blang\s*="#, text) {
            findings.append(finding(
                "screen.html-lang-missing",
                "medium",
                "screen_quality",
                "HTML language is not declared",
                displayPath,
                nil,
                "<html>",
                "Add a lang attribute to the html element."
            ))
        }
        if lowerText.contains("<head"),
           !lowerText.contains(#"name="viewport""#),
           !lowerText.contains(#"name='viewport'"#) {
            findings.append(finding(
                "screen.viewport-missing",
                "medium",
                "screen_quality",
                "Responsive viewport meta tag is missing",
                displayPath,
                nil,
                "<head>",
                "Add a viewport meta tag for responsive layouts."
            ))
        }

        for (index, line) in lines.enumerated() {
            let lineNumber = index + 1
            for tag in captures(#"(?i)(<img\b[^>]*>)"#, in: line) where !matches(#"(?i)\balt\s*="#, tag) {
                findings.append(finding(
                    "screen.image-alt-missing",
                    "medium",
                    "screen_quality",
                    "Image is missing alt text",
                    displayPath,
                    lineNumber,
                    tag,
                    "Add meaningful alt text or alt=\"\" for decorative images."
                ))
            }
            for tag in captures(#"(?i)(<input\b[^>]*>)"#, in: line) {
                let type = firstCapture(#"(?i)\btype\s*=\s*['"]?([^'"\s>]+)"#, in: tag)?.lowercased() ?? "text"
                if ["hidden", "submit", "button", "reset"].contains(type) { continue }
                let id = firstCapture(#"(?i)\bid\s*=\s*['"]([^'"]+)['"]"#, in: tag)
                let hasAccessibleName = matches(#"(?i)\baria-(label|labelledby)\s*="#, tag)
                    || matches(#"(?i)\btitle\s*="#, tag)
                    || id.map { labelTargets.contains($0) } == true
                if !hasAccessibleName {
                    findings.append(finding(
                        "screen.input-label-missing",
                        "medium",
                        "screen_quality",
                        "Input has no accessible label",
                        displayPath,
                        lineNumber,
                        tag,
                        "Connect the input to a label or add aria-label."
                    ))
                }
            }
            for tag in captures(#"(?i)(<button\b[^>]*>)"#, in: line) where !matches(#"(?i)\btype\s*="#, tag) {
                findings.append(finding(
                    "screen.button-type-missing",
                    "low",
                    "screen_quality",
                    "Button type is not explicit",
                    displayPath,
                    lineNumber,
                    tag,
                    "Set button type to button, submit, or reset."
                ))
            }
            for tag in captures(#"(?i)(<a\b[^>]*>)"#, in: line) {
                let href = firstCapture(#"(?i)\bhref\s*=\s*['"]([^'"]*)['"]"#, in: tag)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                if href.isEmpty || href == "#" || href.lowercased() == "javascript:void(0)" {
                    findings.append(finding(
                        "screen.link-target-empty",
                        "low",
                        "screen_quality",
                        "Link target is empty or placeholder",
                        displayPath,
                        lineNumber,
                        tag,
                        "Use a real href or a button for actions."
                    ))
                }
            }
            if matches(#"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['"][^'"]{6,}"#, line) {
                findings.append(finding(
                    "screen.sensitive-text-exposed",
                    "high",
                    "screen_quality",
                    "Screen source appears to expose sensitive text",
                    displayPath,
                    lineNumber,
                    redact(line),
                    "Remove secrets and sensitive values from client-rendered source."
                ))
            }
            if matches(#"(?i)(/var/(log|www|lib)|/etc/[A-Za-z0-9_.-]+|[A-Z]:\\(?:Users|Windows|Program Files)\\)"#, line) {
                findings.append(finding(
                    "screen.system-path-exposed",
                    "medium",
                    "screen_quality",
                    "Screen source exposes a system path",
                    displayPath,
                    lineNumber,
                    line,
                    "Replace internal system paths with user-safe messages."
                ))
            }
        }

        return findings
    }

    private func checkPrevention(root: URL, files: [URL]) -> [NativeFinding] {
        let relPaths = Set(files.map { relativePath($0, root: root) })
        let lowerRelPaths = Set(relPaths.map { $0.lowercased() })
        let basenames = Set(files.map(\.lastPathComponent))
        let lowerBasenames = Set(basenames.map { $0.lowercased() })
        let dependencyManifestNames: Set<String> = [
            "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
            "requirements.txt", "requirements.in", "pyproject.toml", "poetry.lock",
            "Pipfile", "Pipfile.lock", "Gemfile", "Gemfile.lock", "go.mod", "go.sum",
            "Cargo.toml", "Cargo.lock", "composer.json", "composer.lock", "pom.xml",
            "build.gradle", "build.gradle.kts",
        ]
        let sourceExtensions: Set<String> = ["py", "js", "ts", "tsx", "jsx", "java", "go", "rb", "php", "cs", "swift", "rs"]
        let securityPolicyPaths: Set<String> = ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"]
        let dependencyAutomationPaths: Set<String> = [
            ".github/dependabot.yml", ".github/dependabot.yaml", "dependabot.yml", "dependabot.yaml",
            "renovate.json", ".renovaterc", ".renovaterc.json", ".github/renovate.json",
        ]
        let preCommitGuidePaths: Set<String> = ["docs/security/pre_commit.md", "docs/security/pre-commit.md"]
        let repositorySecurityGuidePaths: Set<String> = ["docs/security/github_repository_security.md", "docs/security/repository_security.md"]
        let codeownersPaths: Set<String> = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"]
        let ssdfWorkflowPaths: Set<String> = ["docs/security/nist_ssdf_workflow.md", "docs/security/ssdf_workflow.md"]
        let secureByDesignPaths: Set<String> = ["docs/security/secure_by_design.md"]
        let threatModelPaths: Set<String> = ["docs/security/threat_model.md", "docs/security/threat-model.md"]
        let secretRotationPaths: Set<String> = ["docs/security/secret_rotation.md", "docs/security/secrets_rotation.md", "docs/security/secret-rotation.md"]
        let aiLLMSecurityPaths: Set<String> = ["docs/security/ai_llm_security.md", "docs/security/llm_security.md", "docs/security/ai-security.md"]
        let mobileSecurityPaths: Set<String> = ["docs/security/mobile_security.md", "docs/security/mobile-security.md"]
        let nistCSFProfilePaths: Set<String> = ["docs/security/nist_csf_2_profile.md", "docs/security/nist-csf-2-profile.md"]
        let cisaAttestationPaths: Set<String> = ["docs/security/cisa_secure_software_attestation.md", "docs/security/cisa-attestation.md"]
        let apiSecurityPaths: Set<String> = ["docs/security/api_security.md", "docs/security/api-security.md"]
        let scvsPlanPaths: Set<String> = ["docs/security/scvs_plan.md", "docs/security/owasp_scvs.md", "docs/security/software_component_verification.md"]
        let privacyDataMapPaths: Set<String> = ["docs/security/privacy_data_map.md", "docs/security/privacy-data-map.md", "docs/security/data_inventory.md"]
        let securityRoadmapPaths: Set<String> = ["docs/security/security_roadmap.md", "docs/security/security-roadmap.md"]
        let evidenceRegisterPaths: Set<String> = ["docs/security/evidence_register.md", "docs/security/security_evidence.md"]
        let securityHeadersPaths: Set<String> = ["docs/security/security_headers.md", "docs/security/security-headers.md"]
        let containerHardeningPaths: Set<String> = ["docs/security/container_hardening.md", "docs/security/container-hardening.md"]
        let cloudIACSecurityPaths: Set<String> = ["docs/security/cloud_iac_security.md", "docs/security/cloud-iac-security.md"]
        let releaseProvenanceWorkflowPaths: Set<String> = [".github/workflows/koda-release-provenance.yml", ".github/workflows/koda-release-provenance.yaml"]
        let envExampleNames: Set<String> = [".env.example", ".env.sample", ".env.template", ".env.local.example", ".env.development.example", ".env.production.example"]
        let hasDependencyManifest = !dependencyManifestNames.intersection(basenames).isEmpty
        let hasSourceCode = files.contains { sourceExtensions.contains($0.pathExtension.lowercased()) }
        let dockerfiles = files.filter { $0.lastPathComponent == "Dockerfile" || $0.lastPathComponent.hasPrefix("Dockerfile.") }
        let envFiles = files.filter { file in
            let name = file.lastPathComponent
            return name == ".env" || (name.hasPrefix(".env.") && !name.hasSuffix(".example") && !name.hasSuffix(".sample") && !name.hasSuffix(".template"))
        }
        let workflowFiles = files.filter { relativePath($0, root: root).hasPrefix(".github/workflows/") }
        let workflowTexts = workflowFiles.compactMap { readTextLines($0)?.joined(separator: "\n").lowercased() }
        let workflowText = workflowTexts.joined(separator: "\n")
        let hasAILLMCode = projectTextContains(files: files, keywords: ["openai", "anthropic", "langchain", "llamaindex", "chat.completions", "responses.create", "generatecontent", "tool_choice", "function_call"])
        let hasAPICode = projectTextContains(files: files, keywords: ["app.get(", "app.post(", "router.get(", "router.post(", "fastapi(", "@getmapping", "@postmapping", "/api/"])
        let hasMobileProject = looksLikeMobileProject(files: files, basenames: basenames, lowerRelPaths: lowerRelPaths)
        let hasCloudIAC = looksLikeCloudIAC(files: files, basenames: basenames, lowerRelPaths: lowerRelPaths)
        let k8sFiles = files.filter { looksLikeKubernetesManifest($0) }

        var findings: [NativeFinding] = []
        findings.append(contentsOf: ignoreFileFindings(root: root, files: files))
        if (hasSourceCode || hasDependencyManifest) && securityPolicyPaths.intersection(relPaths).isEmpty {
            findings.append(finding("prevention.security-policy-missing", "info", "prevention", "보안 정책 문서가 없음", ".", nil, "SECURITY.md 없음", "SECURITY.md에 신고 연락처, 지원 범위, 취약점 공개 기대사항을 작성하세요."))
        }
        if (hasSourceCode || hasDependencyManifest) && fileManager.fileExists(atPath: root.appendingPathComponent(".git").path) && !hasPreCommitHook(root: root) && preCommitGuidePaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.pre-commit-hook-missing", "low", "prevention", "커밋 전 보안 차단 훅이 없음", ".", nil, "KODA pre-commit hook 없음", "고위험 항목이 저장소에 들어오기 전에 차단되도록 KODA pre-commit hook을 설치하세요."))
        }
        if hasDependencyManifest && dependencyAutomationPaths.intersection(relPaths).isEmpty {
            findings.append(finding("prevention.dependency-update-automation-missing", "low", "prevention", "의존성 업데이트 자동화가 없음", ".", nil, "Dependabot/Renovate 설정 없음", "Dependabot 또는 Renovate를 추가해 의존성 업데이트와 취약점 알림을 자동화하세요."))
        }
        let hasGithubMetadata = workflowFiles.count > 0 || lowerRelPaths.contains { $0.hasPrefix(".github/") }
        if hasGithubMetadata && codeownersPaths.intersection(relPaths).isEmpty {
            findings.append(finding("prevention.codeowners-missing", "info", "prevention", "CODEOWNERS가 설정되지 않음", ".", nil, "CODEOWNERS 파일 없음", "보안 민감 경로에 책임 리뷰어가 지정되도록 CODEOWNERS를 추가하세요."))
        }
        if hasGithubMetadata && repositorySecurityGuidePaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.repository-security-settings-missing", "info", "prevention", "GitHub 저장소 보안 설정 문서가 없음", ".", nil, "브랜치 보호/secret scanning 체크리스트 없음", "브랜치 보호, 필수 리뷰, secret scanning, Dependabot alerts, Actions 최소 권한 설정을 문서화하고 활성화하세요."))
        }
        if (hasDependencyManifest || hasSourceCode) && !hasSecurityWorkflow(workflowFiles) {
            findings.append(finding("prevention.ci-security-scan-missing", "info", "prevention", "CI 보안 점검 워크플로가 없음", ".", nil, "보안 점검 workflow 없음", "KODA, CodeQL, Semgrep, OSV, Trivy, Gitleaks, ZAP baseline 같은 보안 점검을 CI에 추가하세요."))
        }
        if (hasSourceCode || hasDependencyManifest) && releaseProvenanceWorkflowPaths.intersection(lowerRelPaths).isEmpty && !containsAny(workflowText, ["slsa-framework", "slsa-github-generator", "sigstore", "cosign", "sign-blob", "attestation", "provenance"]) && !lowerRelPaths.contains("docs/security/slsa_sigstore.md") {
            findings.append(finding("prevention.release-provenance-automation-missing", "info", "prevention", "릴리스 서명 자동화가 준비되지 않음", ".", nil, "릴리스 provenance/signing workflow 없음", "CI에서 산출물을 빌드하고 provenance 생성, 서명, 체크섬 게시까지 수행하는 릴리스 workflow를 추가하세요."))
        }
        if !envFiles.isEmpty && !gitignoreIgnoresEnv(root: root) {
            findings.append(finding("prevention.env-not-gitignored", "low", "prevention", ".env 파일이 gitignore로 제외되지 않음", ".", nil, ".env 제외 패턴 없음", ".gitignore에 .env, .env.* 또는 동등한 제외 패턴을 추가하세요."))
        }
        if !envFiles.isEmpty && envExampleNames.intersection(basenames).isEmpty {
            findings.append(finding("prevention.env-example-missing", "low", "prevention", "정제된 환경 예시 파일이 없음", ".", nil, ".env.example 없음", "실제 값은 저장소 밖에 두고 필요한 키만 담은 .env.example 또는 .env.sample을 커밋하세요."))
        }
        if !dockerfiles.isEmpty && !basenames.contains(".dockerignore") {
            findings.append(finding("prevention.dockerignore-missing", "low", "prevention", ".dockerignore가 없음", ".", nil, "Dockerfile은 있으나 .dockerignore 없음", ".dockerignore를 추가해 비밀값, VCS 메타데이터, 빌드 산출물, 로컬 파일이 이미지 빌드에 포함되지 않게 하세요."))
        }
        if hasDependencyManifest && !hasSBOM(lowerRelPaths: lowerRelPaths, lowerBasenames: lowerBasenames) {
            findings.append(finding("prevention.sbom-missing", "info", "prevention", "SBOM 산출물이 없음", ".", nil, "의존성 매니페스트는 있으나 SBOM 없음", "릴리스 또는 CI 단계에서 CycloneDX나 SPDX SBOM을 생성하고 보관하세요."))
        }
        if (hasSourceCode || hasDependencyManifest) && !containsAny(workflowText, ["codeql", "semgrep", "sonar", "bandit", "brakeman", "gosec"]) {
            findings.append(finding("prevention.sast-workflow-missing", "info", "prevention", "SAST 워크플로가 없음", ".", nil, "CodeQL/Semgrep workflow 없음", "Pull request에서 코드 수준 보안 점검이 실행되도록 CodeQL 또는 Semgrep 같은 SAST workflow를 추가하세요."))
        }
        if (hasSourceCode || hasDependencyManifest) && ssdfWorkflowPaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.ssdf-workflow-missing", "info", "prevention", "NIST SSDF 워크플로 문서가 없음", ".", nil, "SSDF 체크리스트 없음", "설계, 구현, 검증, 릴리스, 취약점 대응 활동을 NIST SSDF 증적에 매핑하세요."))
        }
        if (hasSourceCode || hasDependencyManifest) && secureByDesignPaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.secure-by-design-program-missing", "info", "prevention", "Secure by Design 예방 계획이 없음", ".", nil, "Secure by Design 체크리스트 없음", "안전한 기본값, 고객 보안 결과 책임, 투명성, 제품 보안 지표를 추적하세요."))
        }
        if (hasSourceCode || hasDependencyManifest) && threatModelPaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.threat-model-missing", "info", "prevention", "위협 모델 문서가 없음", ".", nil, "위협 모델 없음", "신뢰 경계, 자산, 악용 시나리오, 보안 가정을 출시 전 문서화하세요."))
        }
        if (hasSourceCode || !envFiles.isEmpty) && secretRotationPaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.secret-rotation-runbook-missing", "info", "prevention", "비밀값 회전 절차 문서가 없음", ".", nil, "비밀값 회전 runbook 없음", "비밀값 노출 시 폐기, 회전, 감사, 재점검 절차를 문서화하세요."))
        }
        if hasAILLMCode && aiLLMSecurityPaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.ai-llm-security-plan-missing", "info", "prevention", "AI/LLM 보안 계획이 없음", ".", nil, "AI/LLM 사용 흔적은 있으나 보안 계획 없음", "프롬프트 인젝션 통제, 도구 경계, 민감정보 처리, 모델/제공자 목록, 적대적 테스트를 문서화하세요."))
        }
        if hasAPICode && apiSecurityPaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.api-security-plan-missing", "info", "prevention", "API 보안 계획이 없음", ".", nil, "API 라우트 또는 핸들러 감지", "API 목록, 객체/기능 권한, schema 검증, rate limit, 외부 API timeout/allowlist 기준을 문서화하세요."))
        }
        if hasMobileProject && mobileSecurityPaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.mobile-security-plan-missing", "info", "prevention", "모바일 보안 계획이 없음", ".", nil, "모바일 프로젝트 파일은 있으나 보안 계획 없음", "MASVS 범위, 플랫폼 설정, 저장소, 네트워크, 릴리스 서명, 기기 테스트 요구사항을 문서화하세요."))
        }
        if hasCloudIAC && cloudIACSecurityPaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.cloud-iac-security-plan-missing", "info", "prevention", "Cloud/IaC 보안 계획이 없음", ".", nil, "Cloud/IaC 파일 감지", "네트워크 노출, IAM 경계, 암호화, 컨테이너 runtime 하드닝, 배포 검토 기준을 문서화하세요."))
        }
        if !k8sFiles.isEmpty && !hasKubernetesNetworkPolicy(files: files) {
            findings.append(finding("prevention.k8s-network-policy-missing", "info", "prevention", "Kubernetes NetworkPolicy가 없음", ".", nil, "Kubernetes workload는 있으나 NetworkPolicy 없음", "NetworkPolicy를 추가하거나 다른 네트워크 격리 계층을 사용한다는 근거를 문서화하세요."))
        }
        if (hasSourceCode || hasDependencyManifest) && nistCSFProfilePaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.nist-csf-profile-missing", "info", "prevention", "NIST CSF 2.0 프로파일이 없음", ".", nil, "NIST CSF 2.0 프로파일 없음", "Govern, Identify, Protect, Detect, Respond, Recover 활동을 프로젝트 증적과 소유자에 매핑하세요."))
        }
        if hasDependencyManifest && scvsPlanPaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.scvs-plan-missing", "info", "prevention", "OWASP SCVS 구성요소 검증 계획이 없음", ".", nil, "의존성 매니페스트는 있으나 SCVS 계획 없음", "구성요소 인벤토리, SBOM, 빌드 환경, 패키지 관리, 분석, provenance 통제를 문서화하세요."))
        }
        if (hasSourceCode || !envFiles.isEmpty) && privacyDataMapPaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.privacy-data-map-missing", "info", "prevention", "개인정보 데이터 맵이 없음", ".", nil, "개인정보 data map 없음", "개인정보 항목, 목적, 저장 위치, 보관 기간, 공유, 로깅 제한을 기록하세요."))
        }
        if (hasSourceCode || hasDependencyManifest) && securityRoadmapPaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.security-roadmap-missing", "info", "prevention", "보안 로드맵이 없음", ".", nil, "보안 roadmap 없음", "보안 backlog, 담당자, 기한, 위험 수용 항목, 목표 성숙도를 한 곳에서 추적하세요."))
        }
        if (hasSourceCode || hasDependencyManifest) && evidenceRegisterPaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.evidence-register-missing", "info", "prevention", "보안 증적 보관대장이 없음", ".", nil, "증적 register 없음", "점검 리포트, SBOM, VEX, DAST, 위협모델, 승인 기록 위치와 담당자를 기록하세요."))
        }
        if looksLikeWebProject(files: files, basenames: basenames) && securityHeadersPaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.security-headers-guide-missing", "info", "prevention", "보안 헤더 기준 문서가 없음", ".", nil, "security headers baseline 없음", "CSP, HSTS, nosniff, Referrer-Policy, Permissions-Policy 기준과 예외를 정리하세요."))
        }
        if (!dockerfiles.isEmpty || !k8sFiles.isEmpty || basenames.contains("docker-compose.yml") || basenames.contains("docker-compose.yaml") || basenames.contains("compose.yml") || basenames.contains("compose.yaml")) && containerHardeningPaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.container-hardening-guide-missing", "info", "prevention", "컨테이너 하드닝 기준 문서가 없음", ".", nil, "컨테이너 배포 파일은 있으나 하드닝 기준 없음", "non-root, read-only filesystem, capability drop, image pinning, resource limit, runtime profile 기준을 문서화하세요."))
        }
        if (hasSourceCode || hasDependencyManifest) && cisaAttestationPaths.intersection(lowerRelPaths).isEmpty {
            findings.append(finding("prevention.cisa-attestation-missing", "info", "prevention", "CISA 보안 소프트웨어 개발 확인서 증적이 없음", ".", nil, "CISA 확인서 증적 체크리스트 없음", "SSDF 기반 개발, 의존성, 검증, 취약점 대응 증적을 확인서 제출 전 기록하세요."))
        }
        if (hasSourceCode || hasDependencyManifest) && !containsAny(workflowText, ["scorecard-action", "openssf/scorecard", "scorecard"]) {
            findings.append(finding("prevention.openssf-scorecard-missing", "info", "prevention", "OpenSSF Scorecard 워크플로가 없음", ".", nil, "OpenSSF Scorecard workflow 없음", "토큰 권한, 고정된 액션, SAST, 의존성 업데이트 자동화 상태를 추적하도록 OpenSSF Scorecard를 CI에 추가하세요."))
        }
        if !workflowFiles.isEmpty && !hasReadOnlyTokenPermissions(workflowText) {
            findings.append(finding("prevention.github-token-permissions-not-readonly", "low", "prevention", "GitHub Actions 토큰 권한이 읽기 전용으로 제한되지 않음", ".", nil, "permissions: contents: read 없음", "workflow 최상단에 permissions: contents: read를 설정하고 쓰기 권한은 필요한 job에만 별도로 부여하세요."))
        }
        let floatingActions = floatingGitHubActions(workflowTexts)
        if !floatingActions.isEmpty {
            findings.append(finding("prevention.github-actions-unpinned", "medium", "prevention", "GitHub Actions 참조가 mutable ref를 사용함", ".", nil, floatingActions.prefix(5).joined(separator: ", "), "외부 GitHub Actions는 검토한 버전 태그나 immutable commit SHA로 고정하세요."))
        }
        if (hasSourceCode || hasDependencyManifest) && !containsAny(workflowText, ["slsa", "sigstore", "cosign", "provenance", "attestation", "attest"]) && !lowerRelPaths.contains("docs/security/slsa_sigstore.md") {
            findings.append(finding("prevention.slsa-sigstore-missing", "info", "prevention", "릴리스 서명 또는 출처 증명이 없음", ".", nil, "SLSA/Sigstore workflow 없음", "릴리스 산출물에 Sigstore/cosign 서명 또는 SLSA provenance 생성을 추가하세요."))
        }
        if looksLikeWebProject(files: files, basenames: basenames) && !containsAny(workflowText, ["zap-baseline", "zaproxy", "owasp/zap", "ghcr.io/zaproxy"]) && !lowerRelPaths.contains("docs/security/zap_baseline.md") {
            findings.append(finding("prevention.zap-baseline-missing", "info", "prevention", "DAST baseline이 설정되지 않음", ".", nil, "OWASP ZAP workflow 없음", "권한이 있는 staging URL에 대해 OWASP ZAP baseline 점검 또는 DAST 인수인계 절차를 추가하세요."))
        }
        if hasDependencyManifest && !containsAny(workflowText, ["dependency-track", "/api/v1/bom"]) && !lowerRelPaths.contains("docs/security/dependency_track.md") {
            findings.append(finding("prevention.dependency-track-integration-missing", "info", "prevention", "Dependency-Track SBOM 업로드가 설정되지 않음", ".", nil, "Dependency-Track workflow 없음", "릴리스 SBOM을 Dependency-Track 또는 동등한 SBOM 분석 backend에 업로드하도록 자동화하세요."))
        }
        if hasDependencyManifest && !hasVEX(lowerRelPaths: lowerRelPaths, lowerBasenames: lowerBasenames) {
            findings.append(finding("prevention.vex-missing", "info", "prevention", "VEX 문서가 없음", ".", nil, "VEX 산출물 없음", "검토된 의존성 취약점에 대해 exploitable, fixed, not_affected 같은 VEX 결정을 문서화하세요."))
        }
        let binaries = binaryArtifacts(files: files, root: root)
        if !binaries.isEmpty {
            findings.append(finding("prevention.binary-artifact-committed", "low", "prevention", "바이너리 릴리스 산출물이 저장소에 포함됨", ".", nil, binaries.prefix(5).joined(separator: ", "), "의도적으로 vendoring한 파일이 아니라면 제거하고 필요한 경우 출처 증명, 체크섬, 서명을 함께 관리하세요."))
        }
        return findings
    }

    private func hasSecurityWorkflow(_ workflowFiles: [URL]) -> Bool {
        let keywords = [
            "sec-chk", "koda", "osv", "dependency-check", "dependency-track", "trivy",
            "grype", "snyk", "semgrep", "codeql", "gitleaks", "trufflehog", "zap",
            "bandit", "safety", "pip-audit", "npm audit",
        ]
        return workflowFiles.contains { file in
            guard let lines = readTextLines(file) else { return false }
            let text = lines.joined(separator: "\n").lowercased()
            return keywords.contains { text.contains($0) }
        }
    }

    private func projectTextContains(files: [URL], keywords: [String]) -> Bool {
        let suffixes: Set<String> = ["js", "jsx", "md", "py", "ts", "tsx", "txt"]
        for file in files where suffixes.contains(file.pathExtension.lowercased()) {
            guard let text = readTextLines(file)?.joined(separator: "\n").lowercased() else {
                continue
            }
            if keywords.contains(where: { text.contains($0) }) {
                return true
            }
        }
        return false
    }

    private func looksLikeMobileProject(files: [URL], basenames: Set<String>, lowerRelPaths: Set<String>) -> Bool {
        if basenames.contains("AndroidManifest.xml") {
            return true
        }
        if basenames.contains("Info.plist"), lowerRelPaths.contains(where: { $0.contains("/ios/") || $0.contains("/app/") || $0.contains("/mobile/") }) {
            return true
        }
        if lowerRelPaths.contains(where: { $0.hasSuffix(".xcodeproj/project.pbxproj") || $0.hasSuffix(".xcworkspace/contents.xcworkspacedata") }) {
            return true
        }
        for file in files where ["build.gradle", "build.gradle.kts"].contains(file.lastPathComponent) {
            let text = readTextLines(file)?.joined(separator: "\n").lowercased() ?? ""
            if text.contains("com.android.application") || text.contains("com.android.library") {
                return true
            }
        }
        return false
    }

    private func looksLikeCloudIAC(files: [URL], basenames: Set<String>, lowerRelPaths: Set<String>) -> Bool {
        if !Set(["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]).intersection(basenames).isEmpty {
            return true
        }
        if files.contains(where: { $0.lastPathComponent == "Dockerfile" || $0.lastPathComponent.hasPrefix("Dockerfile.") || ["tf", "tfvars"].contains($0.pathExtension.lowercased()) }) {
            return true
        }
        return lowerRelPaths.contains { rel in
            rel.contains("/k8s/") || rel.contains("/kubernetes/") || rel.contains("/helm/") || rel.contains("/terraform/") || rel.contains("/infra/")
        }
    }

    private func hasKubernetesNetworkPolicy(files: [URL]) -> Bool {
        for file in files where ["yaml", "yml"].contains(file.pathExtension.lowercased()) {
            if file.lastPathComponent.lowercased().contains("networkpolicy") {
                return true
            }
            let text = readTextLines(file)?.joined(separator: "\n").lowercased() ?? ""
            if text.contains("kind: networkpolicy") {
                return true
            }
        }
        return false
    }

    private func ignoreFileFindings(root: URL, files: [URL]) -> [NativeFinding] {
        var findings: [NativeFinding] = []
        for file in files where ["koda-ignore.yml", ".koda-ignore.yml"].contains(file.lastPathComponent) {
            guard let lines = readTextLines(file) else { continue }
            findings.append(contentsOf: inspectIgnoreFile(file, lines: lines, displayPath: relativePath(file, root: root)))
        }
        return findings
    }

    private func inspectIgnoreFile(_ file: URL, lines: [String], displayPath: String) -> [NativeFinding] {
        var findings: [NativeFinding] = []
        var current: [String: (String, Int)] = [:]
        let today = Calendar.current.startOfDay(for: Date())
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"

        func flush() {
            guard !current.isEmpty else { return }
            let line = current.values.map(\.1).min()
            let rule = current["rule"]?.0 ?? current["rule_id"]?.0 ?? "*"
            let path = current["path"]?.0 ?? "*"
            let evidence = "rule=\(rule), path=\(path)"
            if (current["reason"]?.0 ?? "").isEmpty {
                findings.append(finding("prevention.exception-reason-missing", "low", "prevention", "예외 항목에 사유가 없음", displayPath, line, evidence, "각 예외에 구체적인 reason을 기록하세요."))
            }
            if (current["owner"]?.0 ?? "").isEmpty {
                findings.append(finding("prevention.exception-owner-missing", "low", "prevention", "예외 항목에 담당자가 없음", displayPath, line, evidence, "각 예외에 담당 팀, 담당자, 또는 티켓 큐를 owner로 기록하세요."))
            }
            let until = current["until"]?.0 ?? ""
            if until.isEmpty {
                findings.append(finding("prevention.exception-expiry-missing", "medium", "prevention", "예외 항목에 만료일이 없음", displayPath, line, evidence, "until을 YYYY-MM-DD 형식으로 추가하고 만료 전에 재검토하세요."))
            } else if let expiry = formatter.date(from: until) {
                if expiry < today {
                    findings.append(finding("prevention.exception-expired", "medium", "prevention", "예외 항목이 만료됨", displayPath, current["until"]?.1, "\(evidence), until=\(until)", "근본 원인을 수정하거나 새 승인 사유와 만료일로 예외를 갱신하세요."))
                }
            } else {
                findings.append(finding("prevention.exception-expiry-missing", "medium", "prevention", "예외 항목 만료일 형식이 잘못됨", displayPath, current["until"]?.1, "\(evidence), until=\(until)", "until을 2099-12-31 같은 ISO 날짜 형식으로 작성하세요."))
            }
        }

        for (index, rawLine) in lines.enumerated() {
            var stripped = rawLine.components(separatedBy: "#").first?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if stripped.isEmpty || stripped == "ignore:" {
                continue
            }
            if stripped.hasPrefix("- ") {
                flush()
                current = [:]
                stripped = String(stripped.dropFirst(2)).trimmingCharacters(in: .whitespaces)
            }
            guard let separator = stripped.firstIndex(of: ":") else { continue }
            let key = String(stripped[..<separator]).trimmingCharacters(in: .whitespaces)
            let value = stripped[stripped.index(after: separator)...]
                .trimmingCharacters(in: .whitespaces)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            current[key] = (String(value), index + 1)
        }
        flush()
        return findings
    }

    private func hasPreCommitHook(root: URL) -> Bool {
        let hook = root.appendingPathComponent(".git/hooks/pre-commit")
        guard let text = readTextLines(hook)?.joined(separator: "\n").lowercased() else {
            return false
        }
        return text.contains("koda") || text.contains("security_scanner") || text.contains("local-security-scan")
    }

    private func gitignoreIgnoresEnv(root: URL) -> Bool {
        guard let lines = readTextLines(root.appendingPathComponent(".gitignore")) else { return false }
        let patterns = Set(lines.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty && !$0.hasPrefix("#") })
        let envPatterns: Set<String> = [".env", ".env*", ".env.*", "*.env", "**/.env", "**/.env.*"]
        return !patterns.intersection(envPatterns).isEmpty
    }

    private func hasSBOM(lowerRelPaths: Set<String>, lowerBasenames: Set<String>) -> Bool {
        let knownNames: Set<String> = ["sbom.cdx.json", "bom.json", "bom.xml", "cyclonedx.json", "cyclonedx.xml", "spdx.json", "spdx.xml"]
        if !knownNames.intersection(lowerBasenames).isEmpty {
            return true
        }
        return lowerRelPaths.contains { rel in
            (rel.contains("sbom") && (rel.hasSuffix(".json") || rel.hasSuffix(".xml")))
        }
    }

    private func hasVEX(lowerRelPaths: Set<String>, lowerBasenames: Set<String>) -> Bool {
        let knownNames: Set<String> = ["vex.json", "vex.cdx.json", "cyclonedx-vex.json", "openvex.json"]
        if !knownNames.intersection(lowerBasenames).isEmpty {
            return true
        }
        return lowerRelPaths.contains { rel in
            rel.contains("vex") && rel.hasSuffix(".json")
        }
    }

    private func containsAny(_ text: String, _ keywords: [String]) -> Bool {
        keywords.contains { text.contains($0) }
    }

    private func hasReadOnlyTokenPermissions(_ workflowText: String) -> Bool {
        if workflowText.contains("permissions: read-all") {
            return true
        }
        guard workflowText.contains("permissions:") else {
            return false
        }
        return workflowText.contains("contents: read") && !workflowText.contains("write-all")
    }

    private func floatingGitHubActions(_ workflowTexts: [String]) -> [String] {
        var floating: Set<String> = []
        for text in workflowTexts {
            for line in text.components(separatedBy: .newlines) {
                let stripped = line.trimmingCharacters(in: .whitespacesAndNewlines)
                let reference: String
                if stripped.hasPrefix("- uses:") {
                    reference = String(stripped.dropFirst("- uses:".count)).trimmingCharacters(in: CharacterSet(charactersIn: " \"'"))
                } else if stripped.hasPrefix("uses:") {
                    reference = String(stripped.dropFirst("uses:".count)).trimmingCharacters(in: CharacterSet(charactersIn: " \"'"))
                } else {
                    continue
                }
                if isFloatingActionReference(reference) {
                    floating.insert(reference)
                }
            }
        }
        return floating.sorted()
    }

    private func isFloatingActionReference(_ reference: String) -> Bool {
        if reference.hasPrefix("./") {
            return false
        }
        guard let marker = reference.lastIndex(of: "@") else {
            return true
        }
        let ref = reference[reference.index(after: marker)...].lowercased()
        return ["main", "master", "latest", "head"].contains(ref)
    }

    private func looksLikeWebProject(files: [URL], basenames: Set<String>) -> Bool {
        if !Set(["package.json", "vite.config.js", "next.config.js", "next.config.mjs"]).intersection(basenames).isEmpty {
            return true
        }
        let webExtensions: Set<String> = ["html", "jsx", "tsx", "php", "vue", "svelte"]
        let webConfigNames: Set<String> = ["nginx.conf", "httpd.conf", "apache2.conf", "web.config"]
        return files.contains { webExtensions.contains($0.pathExtension.lowercased()) || webConfigNames.contains($0.lastPathComponent.lowercased()) }
    }

    private func binaryArtifacts(files: [URL], root: URL) -> [String] {
        let suffixes: Set<String> = ["app", "apk", "dmg", "dll", "dylib", "ear", "exe", "msi", "pkg", "so", "war"]
        return files
            .filter { suffixes.contains($0.pathExtension.lowercased()) }
            .map { relativePath($0, root: root) }
            .sorted()
    }

    private func readTextLines(_ file: URL) -> [String]? {
        guard isTextCandidate(file) else { return nil }
        guard let values = try? file.resourceValues(forKeys: [.fileSizeKey]),
              let size = values.fileSize,
              size <= maxFileSize else {
            return nil
        }
        guard let data = try? Data(contentsOf: file, options: [.mappedIfSafe]) else {
            return nil
        }
        if data.prefix(4096).contains(0) {
            return nil
        }
        return String(decoding: data, as: UTF8.self).components(separatedBy: .newlines)
    }

    private func isTextCandidate(_ file: URL) -> Bool {
        let name = file.lastPathComponent
        let textNames: Set<String> = [
            ".env",
            ".env.local",
            ".env.production",
            ".env.development",
            ".gitignore",
            ".htaccess",
            ".npmrc",
            "Dockerfile",
            "Makefile",
            "requirements.txt",
        ]
        if textNames.contains(name) || name.hasPrefix(".env.") {
            return true
        }
        let textExtensions: Set<String> = [
            "bash", "c", "cc", "cfg", "conf", "config", "cpp", "cs", "css", "cxx", "env", "go",
            "h", "hcl", "hpp", "html", "ini", "java", "js", "json", "jsx", "kt", "m", "md", "php",
            "inc", "plist", "properties", "py", "rb", "rs", "sh", "sql", "swift", "toml", "ts", "tsx",
            "tf", "tfvars", "txt", "vue", "xml", "yaml", "yml", "zsh",
        ]
        return textExtensions.contains(file.pathExtension.lowercased())
    }

    private func extractArchive(_ archive: URL, under root: URL, budget: inout ArchiveBudget, depth: Int) throws -> URL {
        guard depth <= maxArchiveDepth else { throw NativeScanError.archiveLimit(archive.lastPathComponent) }
        let output = root.appendingPathComponent("\(archive.lastPathComponent)-\(UUID().uuidString)")
        try fileManager.createDirectory(at: output, withIntermediateDirectories: true)
        let startingBudget = budget
        var completed = false
        defer {
            if !completed {
                budget = startingBudget
                try? fileManager.removeItem(at: output)
            }
        }
        let lowerName = archive.lastPathComponent.lowercased()
        let handle = try FileHandle(forReadingFrom: archive)
        defer { try? handle.close() }
        var data = Data()
        while data.count <= maxArchiveInputBytes {
            let chunk = try handle.read(upToCount: min(1024 * 1024, maxArchiveInputBytes + 1 - data.count)) ?? Data()
            if chunk.isEmpty { break }
            data.append(chunk)
        }
        guard data.count <= maxArchiveInputBytes else { throw NativeScanError.archiveLimit(archive.lastPathComponent) }

        if lowerName.hasSuffix(".zip") || lowerName.hasSuffix(".jar") || lowerName.hasSuffix(".war") || lowerName.hasSuffix(".ear") {
            try extractZip(data, to: output, budget: &budget)
            completed = true
            return output
        }

        if lowerName.hasSuffix(".tar") {
            try extractTar(data, to: output, budget: &budget)
            completed = true
            return output
        }

        if lowerName.hasSuffix(".tar.gz") || lowerName.hasSuffix(".tgz") {
            try extractTar(try gunzip(data, sourceName: archive.lastPathComponent), to: output, budget: &budget)
            completed = true
            return output
        }

        if lowerName.hasSuffix(".gz") {
            let decompressed = try gunzip(data, sourceName: archive.lastPathComponent)
            try reserveArchiveBytes(decompressed.count, label: archive.lastPathComponent, budget: &budget)
            let fileName = String(archive.deletingPathExtension().lastPathComponent.prefix(120))
            try decompressed.write(to: safeDestination(root: output, memberName: fileName))
            completed = true
            return output
        }

        throw NativeScanError.unsupportedArchive(archive.lastPathComponent)
    }

    private func extractZip(_ data: Data, to output: URL, budget: inout ArchiveBudget) throws {
        var offset = 0
        while offset + 30 <= data.count {
            let signature = data.u32(offset)
            if signature == 0x0201_4B50 || signature == 0x0605_4B50 {
                break
            }
            guard signature == 0x0403_4B50 else {
                throw NativeScanError.corruptArchive("zip")
            }

            let flags = data.u16(offset + 6)
            let method = data.u16(offset + 8)
            let compressedSize = Int(data.u32(offset + 18))
            let uncompressedSize = Int(data.u32(offset + 22))
            let nameLength = Int(data.u16(offset + 26))
            let extraLength = Int(data.u16(offset + 28))
            let nameStart = offset + 30
            let dataStart = nameStart + nameLength + extraLength
            guard nameStart + nameLength <= data.count, dataStart + compressedSize <= data.count else {
                throw NativeScanError.corruptArchive("zip")
            }
            guard flags & 0x0008 == 0 else {
                throw NativeScanError.unsupportedArchive("zip data descriptor")
            }

            let nameData = data[nameStart..<nameStart + nameLength]
            guard let memberName = String(data: nameData, encoding: .utf8), !memberName.isEmpty else {
                throw NativeScanError.corruptArchive("zip filename")
            }
            try reserveArchiveEntry(memberName, budget: &budget)
            let destination = try safeDestination(root: output, memberName: memberName)
            if memberName.hasSuffix("/") {
                try fileManager.createDirectory(at: destination, withIntermediateDirectories: true)
            } else {
                guard uncompressedSize <= maxArchiveMemberBytes else { throw NativeScanError.archiveLimit(memberName) }
                try reserveArchiveBytes(uncompressedSize, label: memberName, budget: &budget)
                try fileManager.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
                let compressed = Data(data[dataStart..<dataStart + compressedSize])
                switch method {
                case 0:
                    guard compressed.count == uncompressedSize else { throw NativeScanError.corruptArchive(memberName) }
                    try compressed.write(to: destination)
                case 8:
                    try inflate(compressed, expectedSize: uncompressedSize, maxSize: uncompressedSize, label: memberName).write(to: destination)
                default:
                    throw NativeScanError.unsupportedArchive("zip method \(method)")
                }
            }
            offset = dataStart + compressedSize
        }
    }

    private func extractTar(_ data: Data, to output: URL, budget: inout ArchiveBudget) throws {
        var offset = 0
        while offset + 512 <= data.count {
            let block = data[offset..<offset + 512]
            if block.allSatisfy({ $0 == 0 }) {
                break
            }
            let name = tarString(data, offset: offset, length: 100)
            if name.isEmpty {
                break
            }
            try reserveArchiveEntry(name, budget: &budget)
            let sizeText = tarString(data, offset: offset + 124, length: 12)
            guard let size = Int(sizeText.trimmingCharacters(in: .whitespacesAndNewlines), radix: 8), size >= 0 else {
                throw NativeScanError.corruptArchive("tar size")
            }
            let typeFlag = data[offset + 156]
            let dataStart = offset + 512
            guard size <= data.count - dataStart else {
                throw NativeScanError.corruptArchive("tar")
            }
            let destination = try safeDestination(root: output, memberName: name)
            if typeFlag == 53 || name.hasSuffix("/") {
                try fileManager.createDirectory(at: destination, withIntermediateDirectories: true)
            } else if typeFlag == 0 || typeFlag == 48 {
                try reserveArchiveBytes(size, label: name, budget: &budget)
                try fileManager.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
                try Data(data[dataStart..<dataStart + size]).write(to: destination)
            }
            offset = dataStart + ((size + 511) / 512) * 512
        }
    }

    private func gunzip(_ data: Data, sourceName: String) throws -> Data {
        guard data.count > 18, data[0] == 0x1F, data[1] == 0x8B, data[2] == 8 else {
            throw NativeScanError.corruptArchive(sourceName)
        }
        let flags = data[3]
        var offset = 10
        if flags & 0x04 != 0 {
            guard offset + 2 <= data.count else { throw NativeScanError.corruptArchive(sourceName) }
            let extraLength = Int(data.u16(offset))
            offset += 2 + extraLength
        }
        if flags & 0x08 != 0 {
            while offset < data.count, data[offset] != 0 { offset += 1 }
            offset += 1
        }
        if flags & 0x10 != 0 {
            while offset < data.count, data[offset] != 0 { offset += 1 }
            offset += 1
        }
        if flags & 0x02 != 0 {
            offset += 2
        }
        guard offset < data.count - 8 else {
            throw NativeScanError.corruptArchive(sourceName)
        }
        let expectedSize = Int(data.u32(data.count - 4))
        return try inflate(Data(data[offset..<data.count - 8]), expectedSize: expectedSize, maxSize: maxArchiveMemberBytes, label: sourceName)
    }

    private func inflate(_ data: Data, expectedSize: Int, maxSize: Int, label: String) throws -> Data {
        guard expectedSize <= maxSize else { throw NativeScanError.archiveLimit(label) }
        guard !data.isEmpty else { throw NativeScanError.corruptArchive(label) }
        let capacity = 64 * 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
        defer { buffer.deallocate() }
        var stream = z_stream()
        guard inflateInit2_(&stream, -MAX_WBITS, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            throw NativeScanError.compressionFailed(label)
        }
        defer { inflateEnd(&stream) }

        return try data.withUnsafeBytes { source in
            stream.next_in = UnsafeMutablePointer(mutating: source.bindMemory(to: UInt8.self).baseAddress!)
            stream.avail_in = uInt(data.count)
            var output = Data()
            while true {
                let remainingInput = stream.avail_in
                let outputSize = min(capacity, maxSize - output.count + 1)
                stream.next_out = buffer
                stream.avail_out = uInt(outputSize)
                let status = zlib.inflate(&stream, Z_NO_FLUSH)
                let written = outputSize - Int(stream.avail_out)
                guard written <= maxSize - output.count else { throw NativeScanError.archiveLimit(label) }
                output.append(buffer, count: written)
                // STREAM_END distinguishes a valid empty DEFLATE stream from corrupt or
                // truncated input, which the buffer API reports as the same zero.
                if status == Z_STREAM_END {
                    guard stream.avail_in == 0, output.count == expectedSize else {
                        throw NativeScanError.corruptArchive(label)
                    }
                    return output
                }
                guard status == Z_OK,
                      written > 0 || stream.avail_in < remainingInput else {
                    throw NativeScanError.compressionFailed(label)
                }
            }
        }
    }

    private func reserveArchiveEntry(_ label: String, budget: inout ArchiveBudget) throws {
        guard budget.entries < maxArchiveEntries else { throw NativeScanError.archiveLimit(label) }
        budget.entries += 1
    }

    private func reserveArchiveBytes(_ count: Int, label: String, budget: inout ArchiveBudget) throws {
        guard count >= 0, count <= maxArchiveMemberBytes,
              budget.expandedBytes <= maxArchiveExpandedBytes - count else {
            throw NativeScanError.archiveLimit(label)
        }
        budget.expandedBytes += count
    }

    private func safeDestination(root: URL, memberName: String) throws -> URL {
        let parts = memberName.split(separator: "/").map(String.init).filter { !$0.isEmpty && $0 != "." }
        if parts.contains("..") {
            throw NativeScanError.unsafeArchivePath(memberName)
        }
        var destination = root
        for part in parts {
            destination.appendPathComponent(part)
        }
        let rootPath = root.standardizedFileURL.path
        let destinationPath = destination.standardizedFileURL.path
        guard destinationPath == rootPath || destinationPath.hasPrefix(rootPath + "/") else {
            throw NativeScanError.unsafeArchivePath(memberName)
        }
        return destination
    }

    private func isArchive(_ url: URL) -> Bool {
        let name = url.lastPathComponent.lowercased()
        return [".zip", ".jar", ".war", ".ear", ".tar", ".tar.gz", ".tgz", ".gz"].contains { name.hasSuffix($0) }
    }

    private func isDirectory(_ url: URL) -> Bool {
        (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true
    }

    private func relativePath(_ url: URL, root: URL) -> String {
        let rootPath = root.standardizedFileURL.path
        let path = url.standardizedFileURL.path
        if path.hasPrefix(rootPath + "/") {
            return String(path.dropFirst(rootPath.count + 1))
        }
        return url.lastPathComponent
    }

    private func finding(
        _ ruleID: String,
        _ severity: String,
        _ category: String,
        _ title: String,
        _ path: String,
        _ line: Int?,
        _ evidence: String,
        _ recommendation: String,
        verificationStatus: String? = nil
    ) -> NativeFinding {
        let resolvedStatus = verificationStatus ?? (category == "code" ? "needs_review" : "confirmed")
        return NativeFinding(
            ruleID: ruleID,
            severity: severity,
            category: category,
            title: title,
            path: path,
            line: line,
            evidence: String(evidence.trimmingCharacters(in: .whitespacesAndNewlines).prefix(220)),
            recommendation: recommendation,
            verificationStatus: resolvedStatus,
            verificationNote: resolvedStatus == "needs_review"
                ? "소스 파일 전체의 설정과 방어 패턴을 확인했지만 위험 흐름을 확정할 근거가 부족하여 추가 검토가 필요합니다."
                : ""
        )
    }

    private func severityRank(_ severity: String) -> Int {
        switch severity {
        case "critical": return 5
        case "high": return 4
        case "medium": return 3
        case "low": return 2
        default: return 1
        }
    }

    private func lineNumberContaining(_ needle: String, in lines: [String]) -> Int? {
        lines.firstIndex { $0.contains(needle) }.map { $0 + 1 }
    }
}

private func matches(_ pattern: String, _ text: String) -> Bool {
    NativeRegexCache.shared.matches(pattern, text)
}

private func captures(_ pattern: String, in text: String) -> [String] {
    NativeRegexCache.shared.captures(pattern, text)
}

private func firstCapture(_ pattern: String, in text: String) -> String? {
    captures(pattern, in: text).first
}

private func matchEnd(_ pattern: String, _ text: String) -> Int? {
    NativeRegexCache.shared.matchEnd(pattern, text)
}

private final class NativeRegexCache {
    static let shared = NativeRegexCache()

    private var cache: [String: NSRegularExpression] = [:]
    private let lock = NSLock()

    func matches(_ pattern: String, _ text: String) -> Bool {
        guard let regex = regex(for: pattern) else { return false }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        return regex.firstMatch(in: text, range: range) != nil
    }

    /// Character offset just past the first match, for slicing a call's arguments.
    func matchEnd(_ pattern: String, _ text: String) -> Int? {
        guard let regex = regex(for: pattern) else { return nil }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        guard let match = regex.firstMatch(in: text, range: range),
              let matched = Range(match.range, in: text) else {
            return nil
        }
        return text.distance(from: text.startIndex, to: matched.upperBound)
    }

    func captures(_ pattern: String, _ text: String) -> [String] {
        guard let regex = regex(for: pattern) else { return [] }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        return regex.matches(in: text, range: range).compactMap { match in
            guard match.numberOfRanges > 1,
                  let capturedRange = Range(match.range(at: 1), in: text) else {
                return nil
            }
            return String(text[capturedRange])
        }
    }

    private func regex(for pattern: String) -> NSRegularExpression? {
        lock.lock()
        if let cached = cache[pattern] {
            lock.unlock()
            return cached
        }
        lock.unlock()

        guard let compiled = try? NSRegularExpression(pattern: pattern) else {
            return nil
        }

        lock.lock()
        cache[pattern] = compiled
        lock.unlock()
        return compiled
    }
}

private func redact(_ line: String) -> String {
    line
        .replacingOccurrences(of: #"(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{12,}"#, with: "aws-[redacted]", options: .regularExpression)
        .replacingOccurrences(of: #"gh[pousr]_[A-Za-z0-9_]{8,}"#, with: "gh-[redacted]", options: .regularExpression)
        .replacingOccurrences(of: #"sk-[A-Za-z0-9_\-]{8,}"#, with: "sk-[redacted]", options: .regularExpression)
        .replacingOccurrences(of: #"xox[baprs]-[A-Za-z0-9-]{8,}"#, with: "xox-[redacted]", options: .regularExpression)
}

private func tarString(_ data: Data, offset: Int, length: Int) -> String {
    guard offset < data.count else { return "" }
    let end = min(offset + length, data.count)
    let bytes = data[offset..<end].prefix { $0 != 0 }
    return String(data: Data(bytes), encoding: .utf8) ?? ""
}

private extension Data {
    func u16(_ offset: Int) -> UInt16 {
        UInt16(self[offset]) | UInt16(self[offset + 1]) << 8
    }

    func u32(_ offset: Int) -> UInt32 {
        UInt32(self[offset])
            | UInt32(self[offset + 1]) << 8
            | UInt32(self[offset + 2]) << 16
            | UInt32(self[offset + 3]) << 24
    }
}

private extension NativeSecurityScanner {
    func renderHTML(_ result: NativeScanResult, language: AppLanguage) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let generated = formatter.string(from: result.generatedAt)
        let severityCounts = Dictionary(grouping: result.findings, by: \.severity).mapValues(\.count)
        let severityBars = renderSeverityBars(severityCounts, language: language)
        let rows = result.findings.map { finding in
            """
            <tr>
              <td><span class="badge \(finding.severity.htmlEscaped)">\(severityLabel(finding.severity, language: language))</span></td>
              <td><strong>\(findingTitle(finding, language: language).htmlEscaped)</strong><br><span>\(verificationLabel(finding, language: language).htmlEscaped)</span> · <code>\(finding.ruleID.htmlEscaped)</code> | \(categoryLabel(finding.category, language: language).htmlEscaped)</td>
              <td>\(finding.path.htmlEscaped)\(finding.line.map { ":\($0)" } ?? "")</td>
              <td><code>\(finding.evidence.htmlEscaped)</code><br><span>\(findingRecommendation(finding, language: language).htmlEscaped)</span></td>
            </tr>
            """
        }.joined(separator: "\n")
        let warnings = result.warnings.map { "<li>\(warningText($0, language: language).htmlEscaped)</li>" }.joined(separator: "\n")
        let pageTitle = reportLabel("pageTitle", language: language)

        return """
        <!doctype html>
        <html lang="\(language.rawValue)">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>\(pageTitle.htmlEscaped)</title>
          <style>
            :root { color-scheme: light dark; --ink:#111827; --muted:#667085; --line:#d8dee9; --bg:#f5f7fb; --card:#ffffff; --thead:#f8fafc; --code:#475467; --track:#e9eef5; --warning:#92400e; }
            @media (prefers-color-scheme: dark) {
              :root { --ink:#f8fafc; --muted:#a8b3c7; --line:#334155; --bg:#0f172a; --card:#111827; --thead:#172033; --code:#cbd5e1; --track:#263244; --warning:#fbbf24; }
            }
            html { background:var(--bg); }
            body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo",sans-serif; background:var(--bg); color:var(--ink); }
            header { background:#0b1220; color:white; padding:28px 36px; }
            main { padding:28px 36px 44px; }
            h1 { margin:0 0 8px; font-size:34px; }
            .meta { color:#cbd5e1; }
            .grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; margin:22px 0; }
            .card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:18px; }
            .label { color:var(--muted); font-weight:700; }
            .value { font-size:34px; font-weight:800; margin-top:8px; }
            .risk-panel { display:grid; grid-template-columns:1fr 1.2fr; gap:14px; margin:0 0 22px; }
            .risk-copy { color:var(--muted); line-height:1.55; margin:8px 0 0; }
            .bars { display:grid; gap:10px; }
            .bar-row { display:grid; grid-template-columns:72px 1fr 42px; align-items:center; gap:10px; }
            .bar-label { color:var(--muted); font-weight:700; }
            .bar-track { height:11px; border-radius:999px; background:var(--track); overflow:hidden; }
            .bar-fill { height:100%; border-radius:999px; min-width:0; }
            .bar-count { text-align:right; font-variant-numeric:tabular-nums; font-weight:800; }
            table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
            th,td { text-align:left; vertical-align:top; border-bottom:1px solid var(--line); padding:13px 14px; }
            th { color:var(--muted); background:var(--thead); font-size:13px; }
            code { color:var(--code); white-space:pre-wrap; word-break:break-word; }
            .badge { display:inline-block; min-width:68px; text-align:center; border-radius:999px; padding:7px 10px; font-weight:800; }
            .critical { background:#7f1d1d; color:white; }
            .high { background:#b42318; color:white; }
            .medium { background:#b7791f; color:white; }
            .low { background:#2563eb; color:white; }
            .info { background:#475467; color:white; }
            .warnings { margin:18px 0; color:var(--warning); }
            @media (max-width: 900px) { .grid,.risk-panel { grid-template-columns:1fr; } table { font-size:14px; } }
          </style>
        </head>
        <body>
          <header>
            <h1>\(pageTitle.htmlEscaped)</h1>
            <div class="meta">\(reportLabel("generatedAt", language: language).htmlEscaped) \(generated.htmlEscaped) | \(reportLabel("targets", language: language).htmlEscaped) \(result.targetCount) | \(reportLabel("scannedFiles", language: language).htmlEscaped) \(result.scannedFileCount)</div>
          </header>
          <main>
            <section class="grid">
              <div class="card"><div class="label">\(reportLabel("riskScore", language: language).htmlEscaped)</div><div class="value">\(result.riskScore)</div></div>
              <div class="card"><div class="label">\(reportLabel("criticalHigh", language: language).htmlEscaped)</div><div class="value">\((severityCounts["critical"] ?? 0) + (severityCounts["high"] ?? 0))</div></div>
              <div class="card"><div class="label">\(severityLabel("medium", language: language).htmlEscaped)</div><div class="value">\(severityCounts["medium"] ?? 0)</div></div>
              <div class="card"><div class="label">\(reportLabel("lowInfo", language: language).htmlEscaped)</div><div class="value">\((severityCounts["low"] ?? 0) + (severityCounts["info"] ?? 0))</div></div>
            </section>
            <section class="risk-panel">
              <div class="card">
                <div class="label">\(reportLabel("riskFormula", language: language).htmlEscaped)</div>
                <p class="risk-copy">\(riskFormula(language: language).htmlEscaped)</p>
              </div>
              <div class="card">
                <div class="label">\(reportLabel("severityDistribution", language: language).htmlEscaped)</div>
                <div class="bars">\(severityBars)</div>
              </div>
            </section>
            \(warnings.isEmpty ? "" : "<section class=\"warnings\"><strong>\(reportLabel("warnings", language: language).htmlEscaped)</strong><ul>\(warnings)</ul></section>")
            <table>
              <thead><tr><th>\(reportLabel("severity", language: language).htmlEscaped)</th><th>\(reportLabel("finding", language: language).htmlEscaped)</th><th>\(reportLabel("path", language: language).htmlEscaped)</th><th>\(reportLabel("evidenceAction", language: language).htmlEscaped)</th></tr></thead>
              <tbody>\(rows.isEmpty ? "<tr><td colspan=\"4\">\(reportLabel("noFindings", language: language).htmlEscaped)</td></tr>" : rows)</tbody>
            </table>
          </main>
        </body>
        </html>
        """
    }

    func renderMarkdown(_ result: NativeScanResult, language: AppLanguage) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let generated = formatter.string(from: result.generatedAt)
        let severityCounts = Dictionary(grouping: result.findings, by: \.severity).mapValues(\.count)
        let warningBlock = result.warnings.isEmpty
            ? ""
            : "\n## \(reportLabel("warnings", language: language))\n\n"
                + result.warnings.map { "- \(warningText($0, language: language))" }.joined(separator: "\n")
                + "\n"
        let rows = result.findings.map { finding in
            let columns = [
                severityLabel(finding.severity, language: language),
                "\(verificationLabel(finding, language: language)) · \(findingTitle(finding, language: language))",
                finding.ruleID,
                categoryLabel(finding.category, language: language),
                "\(finding.path)\(finding.line.map { ":\($0)" } ?? "")",
                finding.evidence,
                findingRecommendation(finding, language: language),
            ].map(\.markdownCellEscaped).joined(separator: " | ")
            return "| \(columns) |"
        }.joined(separator: "\n")
        let findingRows = rows.isEmpty
            ? "| \(reportLabel("noFindings", language: language).markdownCellEscaped) |  |  |  |  |  |  |"
            : rows

        return """
        # \(reportLabel("pageTitle", language: language))

        - \(reportLabel("generatedAt", language: language)): \(generated)
        - \(reportLabel("targets", language: language)): \(result.targetCount)
        - \(reportLabel("scannedFiles", language: language)): \(result.scannedFileCount)
        - \(reportLabel("riskScore", language: language)): \(result.riskScore)

        ## \(reportLabel("riskFormula", language: language))

        \(riskFormula(language: language))

        ## \(reportLabel("severityDistribution", language: language))

        - \(severityLabel("critical", language: language)): \(severityCounts["critical"] ?? 0)
        - \(severityLabel("high", language: language)): \(severityCounts["high"] ?? 0)
        - \(severityLabel("medium", language: language)): \(severityCounts["medium"] ?? 0)
        - \(severityLabel("low", language: language)): \(severityCounts["low"] ?? 0)
        - \(severityLabel("info", language: language)): \(severityCounts["info"] ?? 0)
        \(warningBlock)
        ## \(reportLabel("findings", language: language))

        | \(reportLabel("severity", language: language)) | \(reportLabel("finding", language: language)) | Rule | \(reportLabel("category", language: language)) | \(reportLabel("path", language: language)) | \(reportLabel("evidence", language: language)) | \(reportLabel("recommendation", language: language)) |
        | --- | --- | --- | --- | --- | --- | --- |
        \(findingRows)
        """
    }

    func renderPlainText(_ result: NativeScanResult, language: AppLanguage) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let generated = formatter.string(from: result.generatedAt)
        let severityCounts = Dictionary(grouping: result.findings, by: \.severity).mapValues(\.count)
        let warnings = result.warnings.isEmpty
            ? ""
            : "\n\(reportLabel("warnings", language: language))\n"
                + result.warnings.map { "- \(warningText($0, language: language))" }.joined(separator: "\n")
                + "\n"
        let findings = result.findings.isEmpty
            ? reportLabel("noFindings", language: language)
            : result.findings.enumerated().map { index, finding in
                """
                \(index + 1). [\(severityLabel(finding.severity, language: language))] [\(verificationLabel(finding, language: language))] \(findingTitle(finding, language: language))
                   Rule: \(finding.ruleID)
                   \(reportLabel("category", language: language)): \(categoryLabel(finding.category, language: language))
                   \(reportLabel("path", language: language)): \(finding.path)\(finding.line.map { ":\($0)" } ?? "")
                   \(reportLabel("evidence", language: language)): \(finding.evidence)
                   \(reportLabel("recommendation", language: language)): \(findingRecommendation(finding, language: language))
                """
            }.joined(separator: "\n\n")

        return """
        \(reportLabel("pageTitle", language: language))

        \(reportLabel("generatedAt", language: language)): \(generated)
        \(reportLabel("targets", language: language)): \(result.targetCount)
        \(reportLabel("scannedFiles", language: language)): \(result.scannedFileCount)
        \(reportLabel("riskScore", language: language)): \(result.riskScore)

        \(reportLabel("riskFormula", language: language))
        \(riskFormula(language: language))

        \(reportLabel("severityDistribution", language: language))
        \(severityLabel("critical", language: language)): \(severityCounts["critical"] ?? 0)
        \(severityLabel("high", language: language)): \(severityCounts["high"] ?? 0)
        \(severityLabel("medium", language: language)): \(severityCounts["medium"] ?? 0)
        \(severityLabel("low", language: language)): \(severityCounts["low"] ?? 0)
        \(severityLabel("info", language: language)): \(severityCounts["info"] ?? 0)
        \(warnings)
        \(reportLabel("findings", language: language))
        \(findings)
        """
    }

    func severityLabel(_ severity: String, language: AppLanguage) -> String {
        switch (language, severity) {
        case (.ko, "critical"): return "치명"
        case (.ko, "high"): return "높음"
        case (.ko, "medium"): return "중간"
        case (.ko, "low"): return "낮음"
        case (.ko, _): return "정보"
        case (.en, "critical"): return "Critical"
        case (.en, "high"): return "High"
        case (.en, "medium"): return "Medium"
        case (.en, "low"): return "Low"
        case (.en, _): return "Info"
        }
    }

    func verificationLabel(_ finding: NativeFinding, language: AppLanguage) -> String {
        switch finding.verificationStatus {
        case "needs_review":
            return language == .ko ? "검토 필요" : "Needs review"
        case "unverified":
            return language == .ko ? "미확인" : "Unverified"
        default:
            return language == .ko ? "문맥 확인" : "Context confirmed"
        }
    }

    func renderSeverityBars(_ counts: [String: Int], language: AppLanguage) -> String {
        let entries = [
            ("critical", severityLabel("critical", language: language), "#7f1d1d"),
            ("high", severityLabel("high", language: language), "#b42318"),
            ("medium", severityLabel("medium", language: language), "#b7791f"),
            ("low", severityLabel("low", language: language), "#2563eb"),
            ("info", severityLabel("info", language: language), "#475467"),
        ]
        let maximum = max(entries.map { counts[$0.0] ?? 0 }.max() ?? 0, 1)
        return entries.map { severity, label, color in
            let count = counts[severity] ?? 0
            let width = count == 0 ? 0 : max(3, Int((Double(count) / Double(maximum)) * 100))
            return """
            <div class="bar-row">
              <div class="bar-label">\(label)</div>
              <div class="bar-track"><div class="bar-fill" style="width:\(width)%; background:\(color);"></div></div>
              <div class="bar-count">\(count)</div>
            </div>
            """
        }.joined(separator: "\n")
    }

    func reportLabel(_ key: String, language: AppLanguage) -> String {
        let ko = [
            "pageTitle": "KODA 보안 점검 리포트",
            "generatedAt": "생성 시각",
            "targets": "점검 대상",
            "scannedFiles": "스캔 파일",
            "riskScore": "위험 점수",
            "criticalHigh": "치명/높음",
            "lowInfo": "낮음/정보",
            "riskFormula": "위험점수 계산",
            "severityDistribution": "위험군별 분포",
            "warnings": "경고",
            "severity": "심각도",
            "finding": "발견 항목",
            "findings": "발견 항목",
            "path": "경로",
            "category": "분류",
            "evidence": "근거",
            "recommendation": "조치",
            "evidenceAction": "근거 / 조치",
            "noFindings": "현재 활성화된 점검 범위에서 탐지된 항목이 없습니다. 전체 보안성을 보장하지 않습니다.",
        ]
        let en = [
            "pageTitle": "KODA Security Scan Report",
            "generatedAt": "Generated",
            "targets": "Targets",
            "scannedFiles": "Scanned Files",
            "riskScore": "Risk Score",
            "criticalHigh": "Critical/High",
            "lowInfo": "Low/Info",
            "riskFormula": "Risk Score Formula",
            "severityDistribution": "Severity Distribution",
            "warnings": "Warnings",
            "severity": "Severity",
            "finding": "Finding",
            "findings": "Findings",
            "path": "Path",
            "category": "Category",
            "evidence": "Evidence",
            "recommendation": "Recommendation",
            "evidenceAction": "Evidence / Action",
            "noFindings": "No findings were detected within the checks and pages covered by this scan. This does not guarantee that the target is free of vulnerabilities.",
        ]
        return (language == .ko ? ko : en)[key] ?? key
    }

    func riskFormula(language: AppLanguage) -> String {
        switch language {
        case .ko:
            return "위험 점수는 치명 100점, 높음 40점, 중간 10점, 낮음 3점, 정보 1점을 발견 항목별로 더한 값입니다."
        case .en:
            return "Risk score is the sum of each finding: critical 100, high 40, medium 10, low 3, and info 1."
        }
    }

    func categoryLabel(_ category: String, language: AppLanguage) -> String {
        switch (language, category) {
        case (.ko, "secrets"): return "비밀값"
        case (.ko, "dependencies"): return "의존성"
        case (.ko, "configuration"): return "설정"
        case (.ko, "code"): return "코드 패턴"
        case (.ko, "prevention"): return "예방 가드레일"
        case (.ko, "screen_quality"): return "화면 품질"
        case (.ko, "host"): return "호스트 보안 상태"
        case (.en, "secrets"): return "Secrets"
        case (.en, "dependencies"): return "Dependencies"
        case (.en, "configuration"): return "Configuration"
        case (.en, "code"): return "Code Pattern"
        case (.en, "prevention"): return "Prevention Guardrails"
        case (.en, "screen_quality"): return "Screen Quality"
        case (.en, "host"): return "Host Posture"
        default: return category
        }
    }

    func findingTitle(_ finding: NativeFinding, language: AppLanguage) -> String {
        guard language == .en else { return finding.title }
        switch finding.ruleID {
        case "secret.private-key": return "Private key embedded in a file"
        case "secret.aws-access-key": return "Possible AWS access key found"
        case "secret.github-token": return "Possible GitHub token found"
        case "secret.openai-key": return "Possible API key found"
        case "secret.slack-token": return "Possible Slack token found"
        case "secret.generic-assignment": return "Possible hard-coded secret assignment"
        case "screen.html-lang-missing": return "HTML language is not declared"
        case "screen.viewport-missing": return "Responsive viewport meta tag is missing"
        case "screen.image-alt-missing": return "Image is missing alt text"
        case "screen.input-label-missing": return "Input has no accessible label"
        case "screen.button-type-missing": return "Button type is not explicit"
        case "screen.link-target-empty": return "Link target is empty or placeholder"
        case "screen.sensitive-text-exposed": return "Screen source appears to expose sensitive text"
        case "screen.system-path-exposed": return "Screen source exposes a system path"
        case "prevention.security-policy-missing": return "Security policy is not documented"
        case "prevention.dependency-update-automation-missing": return "Dependency update automation is not configured"
        case "prevention.ci-security-scan-missing": return "CI security scan is not configured"
        case "prevention.pre-commit-hook-missing": return "Pre-commit security gate is not installed"
        case "prevention.codeowners-missing": return "CODEOWNERS is not configured"
        case "prevention.repository-security-settings-missing": return "GitHub repository security settings are not documented"
        case "prevention.release-provenance-automation-missing": return "Release signing automation is not prepared"
        case "prevention.ssdf-workflow-missing": return "NIST SSDF workflow is not documented"
        case "prevention.secure-by-design-program-missing": return "Secure by Design prevention plan is not documented"
        case "prevention.env-not-gitignored": return ".env files are not ignored"
        case "prevention.env-example-missing": return "Sanitized environment example is missing"
        case "prevention.dockerignore-missing": return ".dockerignore is missing"
        case "prevention.sbom-missing": return "SBOM artifact is not present"
        case "prevention.sast-workflow-missing": return "SAST workflow is not configured"
        case "prevention.openssf-scorecard-missing": return "OpenSSF Scorecard workflow is not configured"
        case "prevention.github-token-permissions-not-readonly": return "GitHub Actions token permissions are not read-only"
        case "prevention.github-actions-unpinned": return "GitHub Actions references are not tightly pinned"
        case "prevention.slsa-sigstore-missing": return "Release signing or provenance is not configured"
        case "prevention.zap-baseline-missing": return "DAST baseline is not configured"
        case "prevention.dependency-track-integration-missing": return "Dependency-Track SBOM upload is not configured"
        case "prevention.vex-missing": return "VEX document is not present"
        case "prevention.binary-artifact-committed": return "Binary release artifact is committed"
        case "prevention.threat-model-missing": return "Threat model is not documented"
        case "prevention.secret-rotation-runbook-missing": return "Secret rotation runbook is not documented"
        case "prevention.ai-llm-security-plan-missing": return "AI/LLM security plan is not documented"
        case "prevention.mobile-security-plan-missing": return "Mobile security plan is not documented"
        case "prevention.nist-csf-profile-missing": return "NIST CSF 2.0 profile is not documented"
        case "prevention.cisa-attestation-missing": return "CISA secure software attestation evidence is not documented"
        case "prevention.api-security-plan-missing": return "API security plan is not documented"
        case "prevention.scvs-plan-missing": return "OWASP SCVS component verification plan is not documented"
        case "prevention.privacy-data-map-missing": return "Privacy data map is not documented"
        case "prevention.security-roadmap-missing": return "Security roadmap is not documented"
        case "prevention.evidence-register-missing": return "Security evidence register is not documented"
        case "prevention.exception-reason-missing": return "KODA exception lacks a reason"
        case "prevention.exception-owner-missing": return "KODA exception lacks an owner"
        case "prevention.exception-expiry-missing": return "KODA exception lacks a valid expiry"
        case "prevention.exception-expired": return "KODA exception is expired"
        case "prevention.k8s-network-policy-missing": return "Kubernetes NetworkPolicy is not present"
        case "prevention.security-headers-guide-missing": return "Security headers baseline is not documented"
        case "prevention.container-hardening-guide-missing": return "Container hardening guide is not documented"
        case "prevention.cloud-iac-security-plan-missing": return "Cloud/IaC security baseline is not documented"
        case "dependency.package-json-invalid": return "Invalid package.json"
        case "dependency.node-insecure-url": return "Node dependency fetched over insecure HTTP"
        case "dependency.python-unpinned-requirement": return "Unpinned Python dependency"
        case "dependency.python-insecure-url": return "Python dependency fetched over insecure HTTP"
        case "dependency.python-wildcard-version": return "Wildcard Python dependency version"
        case "dependency.node-missing-lockfile": return "Node lockfile missing"
        case "dependency.node-unbounded-version": return "Unbounded Node dependency version"
        case "dependency.remote-shell-script": return "Package script executes remote content"
        case "dependency.docker-remote-shell": return "Docker build executes remote content"
        case "dependency.docker-unpinned-base": return "Docker base image is not pinned"
        case "config.env-file-present": return "Environment file present in project"
        case "config.private-key-like-file": return "Private-key-like file present"
        case "config.debug-enabled": return "Debug setting enabled"
        case "config.development-environment": return "Development environment flag present"
        case "config.docker-root-user": return "Docker image explicitly runs as root"
        case "config.docker-add-http": return "Dockerfile ADD fetches over HTTP"
        case "config.docker-no-user": return "Dockerfile does not set a non-root user"
        case "config.compose-privileged": return "Privileged container configuration"
        case "config.compose-host-network": return "Compose service uses host networking"
        case "config.compose-docker-sock": return "Compose service mounts the Docker socket"
        case "config.compose-dangerous-capability": return "Compose service grants broad Linux capabilities"
        case "config.compose-host-pid": return "Compose service uses the host PID namespace"
        case "config.compose-secret-in-environment": return "Compose environment appears to inline a secret"
        case "config.k8s-privileged-container": return "Kubernetes container enables privileged mode"
        case "config.k8s-allow-privilege-escalation": return "Kubernetes container allows privilege escalation"
        case "config.k8s-host-network": return "Kubernetes workload uses host networking"
        case "config.k8s-hostpath-volume": return "Kubernetes workload mounts a hostPath volume"
        case "config.k8s-run-as-root": return "Kubernetes workload allows root execution"
        case "config.k8s-service-account-token": return "Kubernetes service account token is auto-mounted"
        case "config.k8s-unpinned-image": return "Kubernetes image is not pinned"
        case "config.k8s-seccomp-unconfined": return "Kubernetes workload disables seccomp confinement"
        case "config.k8s-dangerous-capability": return "Kubernetes workload adds broad Linux capabilities"
        case "config.terraform-public-storage": return "Terraform storage ACL is public"
        case "config.terraform-public-access-block-disabled": return "Terraform public access block is disabled"
        case "config.terraform-open-admin-port": return "Terraform security group opens admin access to the internet"
        case "config.terraform-wildcard-iam-action": return "Terraform IAM policy allows wildcard actions"
        case "config.terraform-wildcard-principal": return "Terraform IAM policy allows wildcard principals"
        case "config.terraform-public-ingress": return "Terraform security group allows public ingress"
        case "config.terraform-unencrypted-storage": return "Terraform storage encryption appears disabled"
        case "config.terraform-sensitive-output": return "Terraform output may expose sensitive values"
        case "config.github-pull-request-target": return "GitHub Actions uses pull_request_target"
        case "config.github-untrusted-event-in-run": return "GitHub Actions run step interpolates untrusted event data"
        case "config.android-debuggable": return "Android app is debuggable"
        case "config.android-allow-backup": return "Android backup is allowed"
        case "config.android-cleartext-traffic": return "Android cleartext traffic is allowed"
        case "config.android-exported-component": return "Android component is exported"
        case "config.ios-ats-arbitrary-loads": return "iOS ATS allows arbitrary loads"
        case "config.ios-file-sharing-enabled": return "iOS file sharing is enabled"
        case "config.ios-open-documents-in-place": return "iOS open documents in place is enabled"
        case "code.xss-dom-sink": return "DOM XSS sink risk"
        case "code.sql-dynamic-query": return "Dynamic SQL query construction"
        case "code.command-injection": return "Command injection risk"
        case "code.path-traversal": return "Path traversal risk"
        case "code.csrf-disabled": return "CSRF protection appears disabled"
        case "code.auth-disabled-endpoint": return "Authentication or authorization appears disabled"
        case "code.eval-user-input": return "Eval-like API receives user input"
        case "code.unsafe-deserialization": return "Unsafe deserialization"
        case "code.ssrf-user-url": return "User-controlled URL fetch may cause SSRF"
        case "code.unrestricted-file-upload": return "File upload may be unrestricted"
        case "code.dangerous-c-buffer-api": return "Dangerous C/C++ buffer API"
        case "code.unbounded-request-body": return "Request body parser has no obvious size limit"
        case "code.logging-sensitive-data": return "Sensitive data may be written to logs"
        case "code.empty-exception-handler": return "Exception appears to be silently ignored"
        case "code.broad-exception-handler": return "Overly broad exception handler"
        case "code.stack-trace-exposure": return "Stack trace output may expose internals"
        case "code.unversioned-api-route": return "API route appears to be unversioned"
        case "code.insecure-temp-file": return "Insecure temporary file creation"
        case "code.wildcard-cors": return "Wildcard CORS configuration"
        case "code.public-bind-all-interfaces": return "Binds to all network interfaces"
        case "code.weak-hash": return "Weak hash algorithm"
        case "code.insecure-cookie-settings": return "Weak cookie/session security settings"
        case "code.persistent-sensitive-cookie": return "Sensitive value stored in a persistent cookie"
        case "code.jwt-verification-disabled": return "JWT signature verification appears disabled"
        case "code.jwt-none-algorithm": return "JWT none algorithm appears allowed"
        case "code.session-long-expiry": return "Session or token expiry appears excessive"
        case "code.api-route-missing-auth": return "Sensitive API route appears to lack an auth guard"
        case "code.api-mass-assignment": return "API handler appears to mass-assign request body data"
        case "code.api-missing-rate-limit": return "API server appears to lack rate limiting"
        case "code.auth-attempt-protection-missing": return "Authentication flow may lack repeated-attempt protection"
        case "code.external-api-no-timeout": return "External API call appears to omit a timeout"
        case "code.pii-logging": return "Personal data may be written to logs"
        case "code.directory-listing-enabled": return "Directory listing enabled"
        case "code.webdav-enabled": return "WebDAV enabled"
        case "code.legacy-board-software": return "Legacy bulletin-board software marker"
        case "code.xml-external-entity": return "XML parser may allow external entities"
        case "code.null-pointer-dereference": return "Possible null pointer dereference"
        case "code.improper-resource-release": return "Potential resource leak"
        case "code.use-after-free": return "Potential use after free"
        case "code.uninitialized-variable": return "Potential uninitialized variable use"
        case "code.dns-security-decision": return "DNS result used in a security decision"
        case "code.llm-prompt-user-concat": return "LLM prompt concatenates user-controlled input"
        case "code.llm-tool-unrestricted": return "LLM tool or function access is broad"
        case "code.llm-sensitive-data-in-prompt": return "Sensitive data may be sent to an LLM prompt"
        default: return finding.title
        }
    }

    func findingRecommendation(_ finding: NativeFinding, language: AppLanguage) -> String {
        guard language == .en else { return finding.recommendation }
        switch finding.ruleID {
        case "secret.private-key":
            return "Revoke the private key immediately and move it to a secure secrets manager."
        case "secret.aws-access-key":
            return "Revoke the key and review IAM permissions and recent usage."
        case "secret.github-token":
            return "Revoke the token and store it in GitHub secrets or an OS secret store."
        case "secret.openai-key":
            return "Revoke the key and use environment variables or a secrets manager."
        case "secret.slack-token":
            return "Revoke the token and review Slack app permissions and usage."
        case "secret.generic-assignment":
            return "Do not keep secret values in source code; inject them at runtime."
        case "screen.html-lang-missing":
            return "Add a lang attribute to the html element."
        case "screen.viewport-missing":
            return "Add a viewport meta tag for responsive layouts."
        case "screen.image-alt-missing":
            return "Add meaningful alt text or alt=\"\" for decorative images."
        case "screen.input-label-missing":
            return "Connect the input to a label or add aria-label."
        case "screen.button-type-missing":
            return "Set button type to button, submit, or reset."
        case "screen.link-target-empty":
            return "Use a real href or a button for actions."
        case "screen.sensitive-text-exposed":
            return "Remove secrets and sensitive values from client-rendered source."
        case "screen.system-path-exposed":
            return "Replace internal system paths with user-safe messages."
        case "prevention.security-policy-missing":
            return "Add SECURITY.md with supported versions, vulnerability reporting contact, and disclosure expectations."
        case "prevention.dependency-update-automation-missing":
            return "Add Dependabot or Renovate so vulnerable and outdated dependencies are surfaced continuously."
        case "prevention.ci-security-scan-missing":
            return "Add a CI job for KODA, CodeQL, Semgrep, OSV, Trivy, Gitleaks, ZAP baseline, or a similar security scanner."
        case "prevention.pre-commit-hook-missing":
            return "Install the KODA pre-commit hook so high-risk findings are blocked before entering Git history."
        case "prevention.codeowners-missing":
            return "Add CODEOWNERS so security-sensitive paths require review from accountable owners."
        case "prevention.repository-security-settings-missing":
            return "Document and enable branch protection, required reviews, secret scanning, Dependabot alerts, and least-privilege Actions settings."
        case "prevention.release-provenance-automation-missing":
            return "Add a release workflow that builds artifacts in CI, generates provenance, signs artifacts, and publishes checksums."
        case "prevention.ssdf-workflow-missing":
            return "Map design, implementation, verification, release, and vulnerability response activities to NIST SSDF evidence."
        case "prevention.secure-by-design-program-missing":
            return "Track secure defaults, customer-impact ownership, radical transparency, and product-security metrics as a product-level prevention program."
        case "prevention.env-not-gitignored":
            return "Add .env, .env.*, or an equivalent pattern to .gitignore before committing real environment files."
        case "prevention.env-example-missing":
            return "Commit a sanitized .env.example or .env.sample and keep real values outside the repository."
        case "prevention.dockerignore-missing":
            return "Add .dockerignore to keep secrets, VCS metadata, build output, and local files out of Docker build contexts."
        case "prevention.sbom-missing":
            return "Generate and retain a CycloneDX or SPDX SBOM for release builds or CI artifacts."
        case "prevention.sast-workflow-missing":
            return "Add a SAST workflow such as CodeQL or Semgrep so code-level security checks run on pull requests."
        case "prevention.openssf-scorecard-missing":
            return "Run OpenSSF Scorecard in CI to monitor token permissions, pinned actions, SAST, and dependency-update automation."
        case "prevention.github-token-permissions-not-readonly":
            return "Set top-level workflow permissions to contents: read and grant write permissions only to jobs that need them."
        case "prevention.github-actions-unpinned":
            return "Pin third-party GitHub Actions to immutable commit SHAs or reviewed version tags."
        case "prevention.slsa-sigstore-missing":
            return "Add Sigstore/cosign signing or SLSA provenance generation for release artifacts."
        case "prevention.zap-baseline-missing":
            return "For authorized staging URLs, add an OWASP ZAP baseline check or document the DAST handoff process."
        case "prevention.dependency-track-integration-missing":
            return "Upload release SBOMs to Dependency-Track or another SBOM analysis backend."
        case "prevention.vex-missing":
            return "Generate a VEX document for reviewed dependency vulnerabilities so exploitable, fixed, and not-affected decisions are traceable."
        case "prevention.binary-artifact-committed":
            return "Keep build artifacts out of source control unless they are intentionally vendored and covered by provenance, checksums, or signatures."
        case "prevention.threat-model-missing":
            return "Document trust boundaries, assets, abuse cases, and security assumptions before release."
        case "prevention.secret-rotation-runbook-missing":
            return "Document how to revoke, rotate, audit, and re-scan after any exposed credential."
        case "prevention.ai-llm-security-plan-missing":
            return "Document prompt-injection controls, tool boundaries, sensitive data handling, model/provider inventory, and adversarial tests."
        case "prevention.mobile-security-plan-missing":
            return "Document MASVS coverage, platform configuration, storage, network, release signing, and device-test requirements."
        case "prevention.nist-csf-profile-missing":
            return "Map Govern, Identify, Protect, Detect, Respond, and Recover activities to project evidence and owners."
        case "prevention.cisa-attestation-missing":
            return "Record SSDF-aligned development, dependency, verification, and vulnerability-response evidence before attesting."
        case "prevention.api-security-plan-missing":
            return "Document API inventory, object/function authorization, schema validation, rate limits, and external API controls."
        case "prevention.scvs-plan-missing":
            return "Document component inventory, SBOM, build environment, package management, component analysis, and provenance controls."
        case "prevention.privacy-data-map-missing":
            return "Record personal data fields, purposes, storage, retention, sharing, and logging restrictions."
        case "prevention.security-roadmap-missing":
            return "Track security backlog, owners, due dates, accepted risks, and target control maturity in one roadmap."
        case "prevention.evidence-register-missing":
            return "Keep links to scan reports, SBOM, VEX, DAST, threat models, attestations, and approvals for audit or release review."
        case "prevention.exception-reason-missing":
            return "Add a specific reason explaining why the finding is accepted or considered false positive."
        case "prevention.exception-owner-missing":
            return "Add an accountable owner for each exception."
        case "prevention.exception-expiry-missing":
            return "Add an ISO expiry date such as 2099-12-31 and review before extending it."
        case "prevention.exception-expired":
            return "Remove the exception, fix the underlying issue, or renew it with a fresh approval and reason."
        case "prevention.k8s-network-policy-missing":
            return "Add NetworkPolicies or document the alternative network isolation layer."
        case "prevention.security-headers-guide-missing":
            return "Document expected CSP, HSTS, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy settings."
        case "prevention.container-hardening-guide-missing":
            return "Document non-root users, read-only filesystems, dropped capabilities, image pinning, resource limits, and runtime profiles."
        case "prevention.cloud-iac-security-plan-missing":
            return "Document network exposure, IAM boundaries, encryption, Terraform state handling, and deployment review requirements."
        case "dependency.package-json-invalid":
            return "Fix package.json syntax so dependency tooling can inspect it reliably."
        case "dependency.node-insecure-url":
            return "Use HTTPS or a trusted package registry source."
        case "dependency.python-unpinned-requirement":
            return "Pin exact versions and run dependency vulnerability checks regularly."
        case "dependency.python-insecure-url":
            return "Use HTTPS or a trusted Python package index."
        case "dependency.python-wildcard-version":
            return "Use a reviewed version range or lockfile."
        case "dependency.node-missing-lockfile":
            return "Commit a lockfile to keep dependency installation reproducible."
        case "dependency.node-unbounded-version":
            return "Use verified version ranges or a lockfile."
        case "dependency.remote-shell-script":
            return "Vendor the installer or verify checksums and signatures before execution."
        case "dependency.docker-remote-shell":
            return "Verify downloaded artifacts and checksums before running them in builds."
        case "dependency.docker-unpinned-base":
            return "Pin to a reviewed tag or digest."
        case "config.env-file-present":
            return "Check for secrets and exclude this file from the repository."
        case "config.private-key-like-file":
            return "Move private keys to a secret store and rotate them if they were real."
        case "config.debug-enabled":
            return "Disable debug settings for production builds."
        case "config.development-environment":
            return "Separate local development configuration from deployment configuration."
        case "config.docker-root-user":
            return "Run runtime stages as a least-privileged user."
        case "config.docker-add-http":
            return "Use HTTPS and verify artifact checksums."
        case "config.docker-no-user":
            return "Add a non-root USER for runtime stages when possible."
        case "config.compose-privileged":
            return "Remove privileged mode and grant only required capabilities."
        case "config.compose-host-network":
            return "Use explicit port mappings unless host networking is required."
        case "config.compose-docker-sock":
            return "Avoid mounting the Docker socket or isolate it behind a purpose-built proxy."
        case "config.compose-dangerous-capability":
            return "Remove broad capabilities such as SYS_ADMIN or NET_ADMIN and grant only what is required."
        case "config.compose-host-pid":
            return "Use the default PID namespace unless host PID access is explicitly required."
        case "config.compose-secret-in-environment":
            return "Move sensitive values to a secret manager or runtime-only environment injection and keep only placeholders in compose files."
        case "config.k8s-privileged-container":
            return "Remove privileged mode and grant only the specific Linux capabilities that are required."
        case "config.k8s-allow-privilege-escalation":
            return "Set allowPrivilegeEscalation: false unless a documented workload requirement exists."
        case "config.k8s-host-network":
            return "Use pod networking and explicit Services or NetworkPolicies unless host networking is required."
        case "config.k8s-hostpath-volume":
            return "Replace hostPath with scoped PersistentVolumes or document why host access is unavoidable."
        case "config.k8s-run-as-root":
            return "Set runAsNonRoot: true and run containers with a non-root runtime user."
        case "config.k8s-service-account-token":
            return "Set automountServiceAccountToken: false when the workload does not need Kubernetes API access."
        case "config.k8s-unpinned-image":
            return "Pin images to reviewed version tags or immutable digests."
        case "config.k8s-seccomp-unconfined":
            return "Use RuntimeDefault seccomp profiles unless a reviewed workload exception exists."
        case "config.k8s-dangerous-capability":
            return "Drop all capabilities by default and add only the minimum reviewed capability needed."
        case "config.terraform-public-storage":
            return "Use private ACLs and explicit, reviewed public access policies only when required."
        case "config.terraform-public-access-block-disabled":
            return "Keep public access block controls enabled unless a documented public bucket design exists."
        case "config.terraform-open-admin-port":
            return "Restrict admin ports to VPN, bastion, or approved source CIDRs."
        case "config.terraform-wildcard-iam-action":
            return "List only the minimum IAM actions required and document any exception."
        case "config.terraform-wildcard-principal":
            return "Limit principals to approved accounts, roles, or service principals."
        case "config.terraform-public-ingress":
            return "Restrict source CIDRs to intended clients or front traffic through an approved load balancer or edge control."
        case "config.terraform-unencrypted-storage":
            return "Enable encryption at rest and document any service-specific exception."
        case "config.terraform-sensitive-output":
            return "Mark sensitive outputs with sensitive = true and avoid outputting raw credentials."
        case "config.github-pull-request-target":
            return "Use pull_request for untrusted code or strictly separate checkout/build steps from privileged operations."
        case "config.github-untrusted-event-in-run":
            return "Pass event values through environment variables and quote/validate them before shell use."
        case "config.android-debuggable":
            return "Disable android:debuggable for release builds and keep build-type settings separate."
        case "config.android-allow-backup":
            return "Disable backup for sensitive apps or define explicit backup exclusion rules."
        case "config.android-cleartext-traffic":
            return "Require HTTPS by default and scope any exception through network security configuration."
        case "config.android-exported-component":
            return "Export only intentional entry points and require permissions for sensitive components."
        case "config.ios-ats-arbitrary-loads":
            return "Keep ATS enabled and scope exceptions to reviewed domains."
        case "config.ios-file-sharing-enabled":
            return "Disable file sharing unless the exposed documents are intentionally user-accessible."
        case "config.ios-open-documents-in-place":
            return "Review document-provider flows and restrict sensitive file handling."
        case "code.xss-dom-sink":
            return "Do not inject untrusted input as HTML; escape it or use textContent."
        case "code.sql-dynamic-query":
            return "Use parameter binding or safe ORM APIs."
        case "code.command-injection":
            return "Avoid shell execution, pass arguments as arrays, and validate input with allowlists."
        case "code.path-traversal":
            return "Normalize user paths and verify they stay inside an allowed root."
        case "code.csrf-disabled":
            return "Keep CSRF protection enabled for browser-authenticated state-changing requests."
        case "code.auth-disabled-endpoint":
            return "Confirm the route is intentionally public and enforce authorization on sensitive operations."
        case "code.eval-user-input":
            return "Remove dynamic code execution or replace it with an allowlisted dispatch table."
        case "code.unsafe-deserialization":
            return "Do not deserialize untrusted input; use safe loaders."
        case "code.ssrf-user-url":
            return "Fetch only allowlisted hosts and block private network ranges."
        case "code.unrestricted-file-upload":
            return "Validate content type and extension, generate server-side filenames, and store uploads outside executable paths."
        case "code.dangerous-c-buffer-api":
            return "Use bounded alternatives and verify destination buffer sizes."
        case "code.unbounded-request-body":
            return "Set conservative request body limits and reject oversized requests early."
        case "code.logging-sensitive-data":
            return "Remove sensitive values from logs or record only redacted identifiers."
        case "code.empty-exception-handler":
            return "Handle expected exceptions explicitly and log security-relevant failures with sanitized context."
        case "code.broad-exception-handler":
            return "Catch expected exception types and fail closed or rethrow unexpected failures."
        case "code.stack-trace-exposure":
            return "Route exceptions through centralized error handling and avoid exposing raw stack traces."
        case "code.unversioned-api-route":
            return "Prefer explicit versioned routes such as /api/v1 for public APIs."
        case "code.insecure-temp-file":
            return "Use safe temporary-file APIs to avoid race conditions."
        case "code.wildcard-cors":
            return "Restrict allowed origins explicitly."
        case "code.public-bind-all-interfaces":
            return "Bind development servers to localhost only."
        case "code.weak-hash":
            return "Use SHA-256 or stronger; for passwords use bcrypt or argon2."
        case "code.insecure-cookie-settings":
            return "Set Secure, HttpOnly, and SameSite attributes appropriately."
        case "code.persistent-sensitive-cookie":
            return "Keep sensitive cookies session-scoped where possible and store only opaque, revocable identifiers."
        case "code.jwt-verification-disabled":
            return "Require signature, issuer, audience, expiry, and algorithm validation for every trusted JWT."
        case "code.jwt-none-algorithm":
            return "Use an explicit allowlist of approved signing algorithms and reject unsigned tokens."
        case "code.session-long-expiry":
            return "Use short-lived access tokens, rotate refresh tokens, and document any long-lived session exception."
        case "code.api-route-missing-auth":
            return "Require explicit route-level authentication and object/function authorization before sensitive API handlers run."
        case "code.api-mass-assignment":
            return "Map only allowed fields explicitly and reject unexpected object properties before persistence."
        case "code.api-missing-rate-limit":
            return "Add rate limits, request quotas, and abuse controls for login, signup, password reset, search, export, and high-cost API routes."
        case "code.auth-attempt-protection-missing":
            return "Apply authentication-specific throttling, failed-attempt controls, lockout, or step-up verification."
        case "code.external-api-no-timeout":
            return "Set conservative timeouts, retries with backoff, and allowlisted destinations for outbound API integrations."
        case "code.pii-logging":
            return "Redact personal data in logs, use event IDs instead of raw identifiers, and document retention limits."
        case "code.directory-listing-enabled":
            return "Disable directory indexing."
        case "code.webdav-enabled":
            return "Disable WebDAV unless it is explicitly required."
        case "code.legacy-board-software":
            return "Confirm the component is still used, then update, isolate, or remove it."
        case "code.xml-external-entity":
            return "Disable DTD and external entity resolution in XML parser configuration."
        case "code.null-pointer-dereference":
            return "Check for null before dereferencing and handle absent lookup results explicitly."
        case "code.improper-resource-release":
            return "Close or release acquired resources on every path."
        case "code.use-after-free":
            return "Do not use a pointer after free; reset or reassign it before reuse."
        case "code.uninitialized-variable":
            return "Initialize local variables before every read on all control-flow paths."
        case "code.dns-security-decision":
            return "Use authenticated identity and certificate validation instead of DNS identity for security decisions."
        case "code.llm-prompt-user-concat":
            return "Keep system and developer instructions fixed, separate user content into user-message fields, and add prompt-injection tests."
        case "code.llm-tool-unrestricted":
            return "Constrain tools by task, validate tool arguments, require confirmation for side effects, and log tool decisions."
        case "code.llm-sensitive-data-in-prompt":
            return "Redact sensitive values before LLM calls and document whether prompts leave the local trust boundary."
        default:
            return finding.recommendation
        }
    }

    func warningText(_ warning: String, language: AppLanguage) -> String {
        guard language == .en else { return warning }
        if warning.hasPrefix("대상이 존재하지 않습니다:") {
            return warning.replacingOccurrences(of: "대상이 존재하지 않습니다:", with: "Target does not exist:")
        }
        if warning.hasPrefix("디렉터리를 열 수 없습니다:") {
            return warning.replacingOccurrences(of: "디렉터리를 열 수 없습니다:", with: "Cannot open directory:")
        }
        if warning.hasPrefix("압축파일에 안전하지 않은 경로가 있습니다:") {
            return warning.replacingOccurrences(of: "압축파일에 안전하지 않은 경로가 있습니다:", with: "Archive contains an unsafe path:")
        }
        if warning.hasPrefix("지원하지 않는 압축 형식입니다:") {
            return warning.replacingOccurrences(of: "지원하지 않는 압축 형식입니다:", with: "Unsupported archive format:")
        }
        if warning.hasPrefix("압축파일을 읽을 수 없습니다:") {
            return warning.replacingOccurrences(of: "압축파일을 읽을 수 없습니다:", with: "Cannot read archive:")
        }
        if warning.hasPrefix("압축 해제에 실패했습니다:") {
            return warning.replacingOccurrences(of: "압축 해제에 실패했습니다:", with: "Archive extraction failed:")
        }
        if warning.hasPrefix("압축파일 처리 한도를 초과했습니다:") {
            return warning.replacingOccurrences(of: "압축파일 처리 한도를 초과했습니다:", with: "Archive processing limit exceeded:")
        }
        return warning
    }
}

private extension String {
    var htmlEscaped: String {
        replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }

    var markdownCellEscaped: String {
        replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "|", with: "\\|")
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
    }
}
