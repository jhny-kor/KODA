#!/usr/bin/env python3
"""Compile the production impact service with a deterministic local AI double."""
from pathlib import Path
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[1] / 'app/KODA/KODA/NativeLocalAIImpact.swift'
HARNESS = r'''
import Foundation

struct NativeFinding { let ruleID: String }
struct NativeLocalAIFixProposal {
    let finding: NativeFinding
    let sourceURL: URL
    let original: String
    let proposed: String
    let validationSummary: String
}
struct LocalAIConfiguration { let response: String }
struct LocalAIClient {
    func completeStreaming(configuration: LocalAIConfiguration, prompt: String, maxTokens: Int,
                           system: String, timeoutSeconds: TimeInterval) async throws -> String {
        precondition(maxTokens == 2048 && timeoutSeconds == 600)
        precondition(system.contains("Never claim functional equivalence"))
        precondition(!prompt.contains("supersecret123"), "secret sent to model")
        precondition(!prompt.contains("return user_input"), "source sent to model")
        return configuration.response
    }
}

@main struct Test {
    static func main() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("KODA-impact-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let sourceURL = root.appendingPathComponent("app.py")
        let original = "def run(user_input):\n    return user_input\n\ndef stable():\n    return 1\n"
        let proposed = "def run(user_input):\n    return escape(user_input)\n\ndef stable():\n    return 1\n"
        try original.write(to: sourceURL, atomically: true, encoding: .utf8)
        try "from app import run\n\ndef caller():\n    return run('test')\n".write(
            to: root.appendingPathComponent("caller.py"), atomically: true, encoding: .utf8)
        try "api_key = \"supersecret123\"\nrun('skip')\n".write(
            to: root.appendingPathComponent("secret.py"), atomically: true, encoding: .utf8)
        let outside = FileManager.default.temporaryDirectory.appendingPathComponent("KODA-outside-\(UUID().uuidString).py")
        try "run('outside')\n".write(to: outside, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: outside) }
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("linked.py"), withDestinationURL: outside)

        let proposal = NativeLocalAIFixProposal(finding: NativeFinding(ruleID: "code.sample"),
            sourceURL: sourceURL, original: original, proposed: proposed, validationSummary: "fixture")
        let evidence = try NativeLocalAIImpact.inspect(proposal: proposal, targets: [root])
        precondition(evidence.changedDeclarations.map(\.name) == ["run"])
        precondition(evidence.references.count == 1)
        precondition(evidence.references[0].path == "\(root.lastPathComponent)/caller.py")
        precondition(evidence.references[0].line == 4 && evidence.references[0].symbol == "run")
        precondition(evidence.scannedFileCount == 2, "secret or symlink file was scanned")
        precondition(evidence.warnings.contains { $0.contains("비밀정보") })

        let result = try await NativeLocalAIImpact.analyze(proposal: proposal, targets: [root],
            configuration: LocalAIConfiguration(response: "변경된 함수 호출 후보가 있습니다."))
        precondition(result.summary == "변경된 함수 호출 후보가 있습니다.")
        precondition(result.references.count == 1)
        let sourceAfterAnalysis = try String(contentsOf: sourceURL, encoding: .utf8)
        precondition(sourceAfterAnalysis == original)

        try "def run(user_input):\n    return 0\n".write(to: sourceURL, atomically: true, encoding: .utf8)
        do {
            _ = try NativeLocalAIImpact.inspect(proposal: proposal, targets: [root])
            fatalError("stale original accepted")
        } catch NativeLocalAIImpactError.staleSource { }
        print("NativeLocalAIImpact tests passed")
    }
}
'''

with tempfile.TemporaryDirectory(prefix='koda-impact-tests-') as directory:
    directory = Path(directory)
    harness = directory / 'Harness.swift'
    harness.write_text(HARNESS)
    binary = directory / 'test'
    subprocess.run(['swiftc', str(SOURCE), str(harness), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
