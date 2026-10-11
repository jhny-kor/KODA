#!/usr/bin/env python3
"""Compile the production report service with a deterministic local-AI double."""

from pathlib import Path
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[1] / "app/KODA/KODA/NativeAIReport.swift"
HARNESS = r'''
import Foundation

struct NativeFinding {
    let ruleID: String
    let severity: String
    let category: String
    let path: String
    let evidence: String
    let verificationStatus: String
}
struct NativeScanResult {
    let findings: [NativeFinding]
    let warnings: [String]
    let targetCount: Int
    let scannedFileCount: Int
    let generatedAt: Date
    var riskScore: Int {
        findings.reduce(0) { $0 + ($1.verificationStatus == "confirmed" ? 40 : 0) }
    }
}
struct LocalAIConfiguration { let apiKey: String }
enum Fixture {
    static var response = ""
    static var prompt = ""
}
struct LocalAIClient {
    func completeStreaming(configuration: LocalAIConfiguration, prompt: String, maxTokens: Int,
                           system: String, timeoutSeconds: TimeInterval) async throws -> String {
        precondition(maxTokens == 8192 && timeoutSeconds == 1500 && !system.isEmpty)
        Fixture.prompt = prompt
        return Fixture.response
    }
}

@main struct Test {
    static func main() async throws {
        let privatePath = "/Users/alice/private/customer.py"
        let secret = "VERY_PRIVATE_TOKEN_0123456789"
        let finding = NativeFinding(ruleID: "code.command-injection", severity: "high", category: "code",
                                    path: privatePath, evidence: "password = " + secret,
                                    verificationStatus: "review_candidate")
        let result = NativeScanResult(findings: [finding], warnings: [secret], targetCount: 2,
                                      scannedFileCount: 9, generatedAt: Date(timeIntervalSince1970: 0))
        Fixture.response = """
        {"overview":"검토가 필요합니다.","findings":[{"index":1,"cause":"shell 문자열 결합 가능성을 검토하세요.","remediation":"인자를 분리하세요.","verificationPlan":"정상 입력 및 악의적 입력 테스트를 계획하세요.","uncertainty":"소스 증거가 제공되지 않았습니다."}]}
        """
        let report = try await NativeAIReportService.generate(result: result,
                                                               configuration: LocalAIConfiguration(apiKey: "MY_LOCAL_API_KEY"))
        precondition(report.includedFindingCount == 1 && report.omittedFindingCount == 0)
        precondition(report.markdown.contains("KODA 발견: 1건") && report.markdown.contains("KODA 위험점수: 0점"))
        precondition(report.markdown.contains("추가 검토 필요") && report.markdown.contains("미실행"))
        precondition(!Fixture.prompt.contains(privatePath) && !Fixture.prompt.contains(secret))
        precondition(!Fixture.prompt.contains("MY_LOCAL_API_KEY"))
        precondition(!report.markdown.contains(privatePath) && !report.markdown.contains(secret))

        Fixture.response = """
        {"overview":"# forged heading", "findings":[{"index":1,"cause":"# pass | [fake](http://x)","remediation":"do x","verificationPlan":"plan x","uncertainty":"unknown"}]}
        """
        let escaped = try await NativeAIReportService.generate(result: result,
                                                                configuration: LocalAIConfiguration(apiKey: ""))
        precondition(!escaped.markdown.contains("\n# forged heading"))
        precondition(escaped.markdown.contains("\\# pass \\| \\[fake\\]"))

        Fixture.response = """
        {"overview":"text","findings":[{"index":2,"cause":"x","remediation":"x","verificationPlan":"x","uncertainty":"x"}]}
        """
        do {
            _ = try await NativeAIReportService.generate(result: result,
                                                         configuration: LocalAIConfiguration(apiKey: ""))
            fatalError("mismatched index accepted")
        } catch NativeAIReportError.invalidNarrative { }

        Fixture.response = """
        {"overview":"테스트를 실행했습니다.","findings":[{"index":1,"cause":"x","remediation":"x","verificationPlan":"x","uncertainty":"x"}]}
        """
        do {
            _ = try await NativeAIReportService.generate(result: result,
                                                         configuration: LocalAIConfiguration(apiKey: ""))
            fatalError("false execution claim accepted")
        } catch NativeAIReportError.invalidNarrative { }

        let many = NativeScanResult(findings: Array(repeating: finding, count: 15), warnings: [],
                                    targetCount: 1, scannedFileCount: 1, generatedAt: Date())
        Fixture.response = "{\"overview\":\"bounded\",\"findings\":[" +
            (1...12).map { i in
                "{\"index\":\(i),\"cause\":\"x\",\"remediation\":\"x\",\"verificationPlan\":\"x\",\"uncertainty\":\"x\"}"
            }.joined(separator: ",") + "]}"
        let bounded = try await NativeAIReportService.generate(result: many,
                                                                configuration: LocalAIConfiguration(apiKey: ""))
        precondition(bounded.includedFindingCount == 12 && bounded.omittedFindingCount == 3)
        precondition(bounded.markdown.contains("나머지 3건"))

        let empty = NativeScanResult(findings: [], warnings: [], targetCount: 1,
                                     scannedFileCount: 1, generatedAt: Date())
        Fixture.prompt = ""
        let zero = try await NativeAIReportService.generate(result: empty,
                                                             configuration: LocalAIConfiguration(apiKey: ""))
        precondition(Fixture.prompt.isEmpty && zero.markdown.contains("안전성 보증을 뜻하지 않습니다"))
        print("NativeAIReport service tests passed")
    }
}
'''

with tempfile.TemporaryDirectory(prefix="koda-ai-report-tests-") as directory:
    root = Path(directory)
    harness = root / "Harness.swift"
    harness.write_text(HARNESS)
    binary = root / "test"
    subprocess.run(["swiftc", str(SOURCE), str(harness), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
