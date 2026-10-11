#!/usr/bin/env python3
"""Compile and run the production read-only AI triage service with deterministic doubles."""
from pathlib import Path
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[1] / 'app/KODA/KODA/NativeLocalAITriageReview.swift'
HARNESS = r'''
import Foundation

struct NativeFinding {
    let ruleID: String
    let severity: String
    let category: String
    let title: String
    let path: String
    let line: Int?
    let evidence: String
    let recommendation: String
    let verificationStatus: String
}
struct NativeScanResult {
    let findings: [NativeFinding]
    let warnings: [String]
    let scannedFileCount: Int
}
struct NativeSecurityScanner {
    func scan(targets: [URL]) throws -> NativeScanResult {
        let file = targets[0]
        let lines = try String(contentsOf: file, encoding: .utf8).components(separatedBy: .newlines)
        var findings: [NativeFinding] = []
        for (index, line) in lines.enumerated() {
            if line.contains("unsafe_call()") {
                findings.append(NativeFinding(ruleID: "code.unsafe", severity: "high", category: "code",
                    title: "unsafe", path: "\(file.lastPathComponent)/\(file.lastPathComponent)",
                    line: index + 1, evidence: line, recommendation: "review", verificationStatus: "needs_review"))
            }
            if line.contains("api_key =") {
                findings.append(NativeFinding(ruleID: "secret.key", severity: "high", category: "secrets",
                    title: "secret", path: "\(file.lastPathComponent)/\(file.lastPathComponent)",
                    line: index + 1, evidence: line, recommendation: "remove", verificationStatus: "confirmed"))
            }
        }
        return NativeScanResult(findings: findings, warnings: [], scannedFileCount: 1)
    }
}
struct LocalAIConfiguration { let response: String }
struct LocalAIClient {
    static var lastPrompt = ""
    func completeStreaming(configuration: LocalAIConfiguration, prompt: String, maxTokens: Int,
                           system: String, timeoutSeconds: TimeInterval) async throws -> String {
        precondition(maxTokens == 8192 && !system.isEmpty && timeoutSeconds == 1500)
        Self.lastPrompt = prompt
        return configuration.response
    }
}

@main struct Test {
    static func main() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("KODA-triage-harness-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let sourceURL = root.appendingPathComponent("sample.py")
        let original = "# distant private note\n" + String(repeating: "# spacer\n", count: 10)
            + "def run():\n    unsafe_call()\n# trailing\n"
        try original.write(to: sourceURL, atomically: true, encoding: .utf8)
        let finding = try NativeSecurityScanner().scan(targets: [sourceURL]).findings[0]
        let response = """
        {"assessment":"uncertain","evidence":"3행 호출 확인","uncertainty":"호출 경로 미확인","verification_steps":"입력과 호출처 확인"}
        """
        let review = try await NativeLocalAITriageReviewer.review(finding: finding, targets: [sourceURL],
            configuration: LocalAIConfiguration(response: response))
        precondition(review.assessment == .uncertain && review.evidence == "3행 호출 확인")
        precondition(review.sourceSnippet.contains("13:     unsafe_call()"))
        precondition(review.scannerVerdictNote.contains("변경되지"))
        precondition(LocalAIClient.lastPrompt.contains("<untrusted_source>"))
        precondition(!LocalAIClient.lastPrompt.contains("distant private note"))
        let sourceAfterReview = try String(contentsOf: sourceURL, encoding: .utf8)
        precondition(sourceAfterReview == original)

        do {
            _ = try await NativeLocalAITriageReviewer.review(finding: finding, targets: [sourceURL],
                configuration: LocalAIConfiguration(response: "could be safe"))
            fatalError("malformed response accepted")
        } catch NativeLocalAITriageReviewError.invalidResponse { }

        let secretSource = "api_key = \"secret123\"\n" + original
        try secretSource.write(to: sourceURL, atomically: true, encoding: .utf8)
        let secretFinding = try NativeSecurityScanner().scan(targets: [sourceURL]).findings.last!
        LocalAIClient.lastPrompt = ""
        do {
            _ = try await NativeLocalAITriageReviewer.review(finding: secretFinding, targets: [sourceURL],
                configuration: LocalAIConfiguration(response: response))
            fatalError("secret-bearing source sent")
        } catch NativeLocalAITriageReviewError.containsSecrets { }
        precondition(LocalAIClient.lastPrompt.isEmpty)

        try "def run():\n    safe_call()\n".write(to: sourceURL, atomically: true, encoding: .utf8)
        do {
            _ = try await NativeLocalAITriageReviewer.review(finding: finding, targets: [sourceURL],
                configuration: LocalAIConfiguration(response: response))
            fatalError("stale finding accepted")
        } catch NativeLocalAITriageReviewError.staleFinding { }

        let unsupported = NativeFinding(ruleID: "secret.key", severity: "high", category: "secrets",
            title: "secret", path: finding.path, line: finding.line, evidence: finding.evidence,
            recommendation: "remove", verificationStatus: "confirmed")
        do {
            _ = try await NativeLocalAITriageReviewer.review(finding: unsupported, targets: [sourceURL],
                configuration: LocalAIConfiguration(response: response))
            fatalError("unsupported finding accepted")
        } catch NativeLocalAITriageReviewError.unsupportedFinding { }

        let traversing = NativeFinding(ruleID: finding.ruleID, severity: finding.severity,
            category: finding.category, title: finding.title, path: "sample.py/../sample.py",
            line: finding.line, evidence: finding.evidence, recommendation: finding.recommendation,
            verificationStatus: finding.verificationStatus)
        do {
            _ = try await NativeLocalAITriageReviewer.review(finding: traversing, targets: [sourceURL],
                configuration: LocalAIConfiguration(response: response))
            fatalError("path traversal accepted")
        } catch NativeLocalAITriageReviewError.sourceNotFound { }

        print("NativeLocalAITriageReviewer tests passed")
    }
}
'''

with tempfile.TemporaryDirectory(prefix='koda-triage-tests-') as directory:
    directory = Path(directory)
    harness = directory / 'Harness.swift'
    harness.write_text(HARNESS)
    binary = directory / 'test'
    subprocess.run(['swiftc', str(SOURCE), str(harness), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
