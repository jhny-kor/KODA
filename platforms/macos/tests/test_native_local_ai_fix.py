#!/usr/bin/env python3
"""Compile the production proposal gate with deterministic scanner/LLM doubles."""
from pathlib import Path
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[1] / 'app/KODA/KODA/NativeLocalAIFix.swift'
VALIDATOR = Path(__file__).resolve().parents[1] / 'app/KODA/KODA/NativeLocalAISourceValidator.swift'
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
}
struct NativeScanResult {
    let findings: [NativeFinding]
    let warnings: [String]
    let scannedFileCount: Int
}
struct NativeSecurityScanner {
    func scan(targets: [URL]) throws -> NativeScanResult {
        let file = targets[0]
        let source = try String(contentsOf: file, encoding: .utf8)
        let lines = source.components(separatedBy: .newlines)
        var findings: [NativeFinding] = []
        for (index, line) in lines.enumerated() {
            let rule: (String, String, String)?
            if line.contains("unsafe_call()") { rule = ("code.unsafe", "high", "code") }
            else if line.contains("new_risk()") { rule = ("code.new", "high", "code") }
            else if line.contains("other_risk(") { rule = ("code.other", "medium", "code") }
            else if line.contains("api_key =") { rule = ("secret.key", "medium", "secrets") }
            else { rule = nil }
            if let rule {
                findings.append(NativeFinding(ruleID: rule.0, severity: rule.1, category: rule.2,
                    title: "fixture", path: "\(file.lastPathComponent)/\(file.lastPathComponent)",
                    line: index + 1, evidence: line, recommendation: "fix"))
            }
        }
        return NativeScanResult(findings: findings,
            warnings: source.contains("scan_warning()") ? ["fixture incomplete scan"] : [],
            scannedFileCount: 1)
    }
}
final class LocalAIConfiguration {
    private var responses: [String]
    private(set) var prompts: [String] = []
    var onResponse: (() -> Void)?
    init(response: String) { responses = [response] }
    init(responses: [String]) { self.responses = responses }
    func next(prompt: String) -> String {
        prompts.append(prompt)
        precondition(!responses.isEmpty, "unexpected extra model request")
        onResponse?()
        return responses.removeFirst()
    }
}
struct LocalAIClient {
    func completeStreaming(configuration: LocalAIConfiguration, prompt: String, maxTokens: Int,
                           system: String, timeoutSeconds: TimeInterval) async throws -> String {
        precondition(maxTokens == 8192 && !system.isEmpty && [300, 1500].contains(timeoutSeconds))
        return configuration.next(prompt: prompt)
    }
}

@main struct Test {
    static func main() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("KODA-fix-harness-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let sourceURL = root.appendingPathComponent("sample.py")
        let original = "def run():\n    unsafe_call()\n"
        try original.write(to: sourceURL, atomically: true, encoding: .utf8)
        let finding = try NativeSecurityScanner().scan(targets: [sourceURL]).findings[0]

        let valid = "def run():\n    safe_call()\n"
        let proposal = try await NativeLocalAIFix.propose(finding: finding, targets: [sourceURL],
            configuration: LocalAIConfiguration(response: valid))
        precondition(proposal.original == original && proposal.proposed == valid)
        let sourceAfterProposal = try String(contentsOf: sourceURL, encoding: .utf8)
        precondition(sourceAfterProposal == original, "source was modified")

        let retried = LocalAIConfiguration(responses: [
            "def run():\n    unsafe_call()\n",
            valid
        ])
        let repaired = try await NativeLocalAIFix.propose(finding: finding, targets: [sourceURL],
            configuration: retried, maxAttempts: 3)
        precondition(repaired.proposed == valid && retried.prompts.count == 2)
        precondition(retried.prompts[1].contains("직전 후보"))
        precondition(retried.prompts[1].contains("code.unsafe"))
        precondition(repaired.validationSummary.contains("2회차"))

        let malformedThenValid = LocalAIConfiguration(responses: ["not a Python source", valid])
        _ = try await NativeLocalAIFix.propose(finding: finding, targets: [sourceURL],
            configuration: malformedThenValid, maxAttempts: 3)
        precondition(malformedThenValid.prompts.count == 2)

        let repeated = LocalAIConfiguration(responses: [
            "def run():\n    unsafe_call()\n",
            "def run():\n    unsafe_call()\n"
        ])
        do {
            _ = try await NativeLocalAIFix.propose(finding: finding, targets: [sourceURL],
                configuration: repeated, maxAttempts: 3)
            fatalError("repeated candidate was accepted")
        } catch NativeLocalAIFixError.retryStalled { }
        precondition(repeated.prompts.count == 2)

        let exhausted = LocalAIConfiguration(responses: [
            "def run():\n    new_risk()  # one\n",
            "def run():\n    new_risk()  # two\n",
            "def run():\n    new_risk()  # three\n"
        ])
        do {
            _ = try await NativeLocalAIFix.propose(finding: finding, targets: [sourceURL],
                configuration: exhausted, maxAttempts: 10)
            fatalError("exhausted repair loop was accepted")
        } catch NativeLocalAIFixError.retryExhausted(let count, _) {
            precondition(count == 3)
        }
        precondition(exhausted.prompts.count == 3)
        let sourceAfterLoop = try String(contentsOf: sourceURL, encoding: .utf8)
        precondition(sourceAfterLoop == original)

        let secretCandidate = LocalAIConfiguration(responses: [
            "api_key = \"supersecret123\"\ndef run():\n    safe_call()\n", valid
        ])
        do {
            _ = try await NativeLocalAIFix.propose(finding: finding, targets: [sourceURL],
                configuration: secretCandidate, maxAttempts: 3)
            fatalError("secret-bearing candidate was retried")
        } catch NativeLocalAIFixError.candidateContainsSecrets { }
        precondition(secretCandidate.prompts.count == 1)

        let longRejected = "def run():\n    new_risk()\n# " + String(repeating: "z", count: 5_000) + "\n"
        let boundedRetry = LocalAIConfiguration(responses: [longRejected, valid])
        _ = try await NativeLocalAIFix.propose(finding: finding, targets: [sourceURL],
            configuration: boundedRetry, maxAttempts: 3)
        precondition(boundedRetry.prompts.count == 2)
        precondition(boundedRetry.prompts[1].contains("본문은 입력 크기 제한으로 생략"))
        precondition(!boundedRetry.prompts[1].contains(String(repeating: "z", count: 100)))

        let otherURL = root.appendingPathComponent("other.py")
        let originalOther = "def run():\n    unsafe_call()\n    other_risk(\"old\")\n"
        try originalOther.write(to: otherURL, atomically: true, encoding: .utf8)
        let otherFinding = try NativeSecurityScanner().scan(targets: [otherURL]).findings[0]
        do {
            _ = try await NativeLocalAIFix.propose(finding: otherFinding, targets: [otherURL],
                configuration: LocalAIConfiguration(response:
                    "def run():\n    safe_call()\n    other_risk(\"new\")\n"))
            fatalError("same-rule finding with changed evidence was accepted")
        } catch NativeLocalAIFixError.scannerRejected { }
        let otherAfterRejection = try String(contentsOf: otherURL, encoding: .utf8)
        precondition(otherAfterRejection == originalOther)

        let incompleteCandidate = LocalAIConfiguration(responses: [
            "def run():\n    scan_warning()\n", valid
        ])
        do {
            _ = try await NativeLocalAIFix.propose(finding: finding, targets: [sourceURL],
                configuration: incompleteCandidate, maxAttempts: 3)
            fatalError("incomplete candidate scan was retried")
        } catch NativeLocalAIFixError.candidateScanIncomplete { }
        precondition(incompleteCandidate.prompts.count == 1)

        let staleDuringGeneration = LocalAIConfiguration(responses: [valid, valid])
        staleDuringGeneration.onResponse = {
            try! "def run():\n    changed()\n".write(to: sourceURL, atomically: true, encoding: .utf8)
        }
        do {
            _ = try await NativeLocalAIFix.propose(finding: finding, targets: [sourceURL],
                configuration: staleDuringGeneration, maxAttempts: 3)
            fatalError("source changed during generation")
        } catch NativeLocalAIFixError.staleSource { }
        precondition(staleDuringGeneration.prompts.count == 1)
        try original.write(to: sourceURL, atomically: true, encoding: .utf8)

        let incompleteOriginal = "def run():\n    unsafe_call()\n    scan_warning()\n"
        try incompleteOriginal.write(to: otherURL, atomically: true, encoding: .utf8)
        let incompleteFinding = try NativeSecurityScanner().scan(targets: [otherURL]).findings[0]
        let neverCalled = LocalAIConfiguration(response: valid)
        do {
            _ = try await NativeLocalAIFix.propose(finding: incompleteFinding, targets: [otherURL],
                configuration: neverCalled, maxAttempts: 3)
            fatalError("incomplete original scan was accepted")
        } catch NativeLocalAIFixError.baselineScanIncomplete { }
        precondition(neverCalled.prompts.isEmpty)

        do {
            _ = try await NativeLocalAIFix.propose(finding: finding, targets: [sourceURL],
                configuration: LocalAIConfiguration(response: "def run():\n    new_risk()\n"))
            fatalError("new high-severity finding was accepted")
        } catch NativeLocalAIFixError.scannerRejected { }

        do {
            _ = try await NativeLocalAIFix.propose(finding: finding, targets: [sourceURL],
                configuration: LocalAIConfiguration(response: "def replacement():\n    safe_call()\n"))
            fatalError("changed Python interface was accepted")
        } catch NativeLocalAIFixError.changedPythonAPI { }

        do {
            _ = try await NativeLocalAIFix.propose(finding: finding, targets: [sourceURL],
                configuration: LocalAIConfiguration(response: "def run(:\n    safe_call()\n"))
            fatalError("invalid Python syntax was accepted")
        } catch NativeLocalAIFixError.invalidSyntax { }

        do {
            _ = try await NativeLocalAIFix.propose(finding: finding, targets: [sourceURL],
                configuration: LocalAIConfiguration(response: "Here is a fix: ```python\n"))
            fatalError("malformed output was accepted")
        } catch NativeLocalAIFixError.malformedProposal { }

        try "def run():\n    safe_call()\n".write(to: sourceURL, atomically: true, encoding: .utf8)
        do {
            _ = try await NativeLocalAIFix.propose(finding: finding, targets: [sourceURL],
                configuration: LocalAIConfiguration(response: valid))
            fatalError("stale finding was accepted")
        } catch NativeLocalAIFixError.staleFinding { }

        try "api_key = \"supersecret123\"\ndef run():\n    unsafe_call()\n".write(to: sourceURL, atomically: true, encoding: .utf8)
        let secretFinding = try NativeSecurityScanner().scan(targets: [sourceURL]).findings.last!
        do {
            _ = try await NativeLocalAIFix.propose(finding: secretFinding, targets: [sourceURL],
                configuration: LocalAIConfiguration(response: valid))
            fatalError("secret-bearing source was sent")
        } catch NativeLocalAIFixError.containsSecrets { }

        let sourceAfterRejection = try String(contentsOf: sourceURL, encoding: .utf8)
        precondition(sourceAfterRejection.contains("supersecret123"))

        let javascriptURL = root.appendingPathComponent("sample.js")
        let originalJavaScript = "export function run() { unsafe_call(); }\n"
        let validJavaScript = "export function run() { safe_call(); }\n"
        try originalJavaScript.write(to: javascriptURL, atomically: true, encoding: .utf8)
        let javascriptFinding = try NativeSecurityScanner().scan(targets: [javascriptURL]).findings[0]
        let javascriptProposal = try await NativeLocalAIFix.propose(
            finding: javascriptFinding, targets: [javascriptURL],
            configuration: LocalAIConfiguration(response: validJavaScript))
        precondition(javascriptProposal.proposed == validJavaScript)
        let javascriptAfter = try String(contentsOf: javascriptURL, encoding: .utf8)
        precondition(javascriptAfter == originalJavaScript)
        do {
            _ = try await NativeLocalAIFix.propose(finding: javascriptFinding, targets: [javascriptURL],
                configuration: LocalAIConfiguration(response: "export function renamed() { safe_call(); }\n"))
            fatalError("changed JavaScript export was accepted")
        } catch NativeLocalAIFixError.changedSourceInterface { }
        do {
            _ = try await NativeLocalAIFix.propose(finding: javascriptFinding, targets: [javascriptURL],
                configuration: LocalAIConfiguration(response:
                    "/*\nexport function run() { safe_call(); }\n*/\nexport function renamed() { safe_call(); }\n"))
            fatalError("comment-spoofed JavaScript export was accepted")
        } catch NativeLocalAIFixError.changedSourceInterface { }
        do {
            _ = try await NativeLocalAIFix.propose(finding: javascriptFinding, targets: [javascriptURL],
                configuration: LocalAIConfiguration(response: "export function run( { safe_call(); }\n"))
            fatalError("invalid JavaScript was accepted")
        } catch NativeLocalAIFixError.invalidSyntax { }

        let scriptURL = root.appendingPathComponent("script.js")
        let originalScript = "module.exports.run = function() { unsafe_call(); };\n"
        let validScript = "module.exports.run = function() { safe_call(); };\n"
        try originalScript.write(to: scriptURL, atomically: true, encoding: .utf8)
        let scriptFinding = try NativeSecurityScanner().scan(targets: [scriptURL]).findings[0]
        let scriptProposal = try await NativeLocalAIFix.propose(finding: scriptFinding,
            targets: [scriptURL], configuration: LocalAIConfiguration(response: validScript))
        precondition(scriptProposal.proposed == validScript)
        do {
            _ = try await NativeLocalAIFix.propose(finding: scriptFinding, targets: [scriptURL],
                configuration: LocalAIConfiguration(response:
                    "module.exports.renamed = function() { safe_call(); };\n"))
            fatalError("changed CommonJS export was accepted")
        } catch NativeLocalAIFixError.changedSourceInterface { }

        let plainURL = root.appendingPathComponent("plain.js")
        try "function render() { unsafe_call(); }\n".write(to: plainURL, atomically: true, encoding: .utf8)
        let plainFinding = try NativeSecurityScanner().scan(targets: [plainURL]).findings[0]
        do {
            _ = try await NativeLocalAIFix.propose(finding: plainFinding, targets: [plainURL],
                configuration: LocalAIConfiguration(response: "function renamed() { safe_call(); }\n"))
            fatalError("changed JavaScript function name was accepted")
        } catch NativeLocalAIFixError.changedSourceInterface { }

        let xmlURL = root.appendingPathComponent("sample.xml")
        let originalXML = "<config><mode>unsafe_call()</mode></config>\n"
        let validXML = "<config><mode>safe_call()</mode></config>\n"
        try originalXML.write(to: xmlURL, atomically: true, encoding: .utf8)
        let xmlFinding = try NativeSecurityScanner().scan(targets: [xmlURL]).findings[0]
        let xmlProposal = try await NativeLocalAIFix.propose(finding: xmlFinding, targets: [xmlURL],
            configuration: LocalAIConfiguration(response: validXML))
        precondition(xmlProposal.proposed == validXML)
        let xmlAfter = try String(contentsOf: xmlURL, encoding: .utf8)
        precondition(xmlAfter == originalXML)
        do {
            _ = try await NativeLocalAIFix.propose(finding: xmlFinding, targets: [xmlURL],
                configuration: LocalAIConfiguration(response: "<other><mode>safe_call()</mode></other>\n"))
            fatalError("changed XML root was accepted")
        } catch NativeLocalAIFixError.changedSourceInterface { }
        do {
            _ = try await NativeLocalAIFix.propose(finding: xmlFinding, targets: [xmlURL],
                configuration: LocalAIConfiguration(response: "<config>safe_call()</config>\n"))
            fatalError("removed XML child was accepted")
        } catch NativeLocalAIFixError.changedSourceInterface { }
        do {
            _ = try await NativeLocalAIFix.propose(finding: xmlFinding, targets: [xmlURL],
                configuration: LocalAIConfiguration(response: "<config><mode>safe_call()</config>\n"))
            fatalError("invalid XML was accepted")
        } catch NativeLocalAIFixError.invalidSyntax { }
        do {
            _ = try await NativeLocalAIFix.propose(finding: xmlFinding, targets: [xmlURL],
                configuration: LocalAIConfiguration(response:
                    "<!DOCTYPE config [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><config><mode>safe_call()</mode></config>\n"))
            fatalError("XML entity declaration was accepted")
        } catch NativeLocalAIFixError.invalidSyntax { }

        try "<config>unsafe_call()".write(to: xmlURL, atomically: true, encoding: .utf8)
        let malformedOriginal = try NativeSecurityScanner().scan(targets: [xmlURL]).findings[0]
        let xmlModelNeverCalled = LocalAIConfiguration(response: validXML)
        do {
            _ = try await NativeLocalAIFix.propose(finding: malformedOriginal, targets: [xmlURL],
                configuration: xmlModelNeverCalled)
            fatalError("invalid original XML reached model")
        } catch NativeLocalAIFixError.syntaxUnavailable { }
        precondition(xmlModelNeverCalled.prompts.isEmpty)

        let javaURL = root.appendingPathComponent("Sample.java")
        let originalJava = "public class Sample { void run() { unsafe_call(); } }\n"
        try originalJava.write(to: javaURL, atomically: true, encoding: .utf8)
        let javaFinding = try NativeSecurityScanner().scan(targets: [javaURL]).findings[0]
        do {
            let javaProposal = try await NativeLocalAIFix.propose(finding: javaFinding, targets: [javaURL],
                configuration: LocalAIConfiguration(response: "public class Sample { void run() { safe_call(); } }\n"))
            precondition(javaProposal.proposed.contains("safe_call"))
        } catch NativeLocalAIFixError.syntaxUnavailable {
            // This host may not have a JDK; absence must fail closed.
        }
        let javaAfter = try String(contentsOf: javaURL, encoding: .utf8)
        precondition(javaAfter == originalJava)
        print("NativeLocalAIFix gate tests passed")
    }
}
'''

with tempfile.TemporaryDirectory(prefix='koda-fix-tests-') as directory:
    directory = Path(directory)
    harness = directory / 'Harness.swift'
    harness.write_text(HARNESS)
    binary = directory / 'test'
    subprocess.run(['swiftc', str(SOURCE), str(VALIDATOR), str(harness), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
