#!/usr/bin/env python3
"""Compile and exercise production regression-plan parsing and LLM request shape."""
from pathlib import Path
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[1] / 'app/KODA/KODA/NativeLocalAITestPlan.swift'
HARNESS = r'''
import Foundation

struct NativeFinding {
    let ruleID: String
    let recommendation: String
}
struct NativeLocalAIFixProposal {
    let finding: NativeFinding
    let sourceURL: URL
    let original: String
    let proposed: String
}
struct LocalAIConfiguration { let response: String }
struct LocalAIClient {
    func completeStreaming(configuration: LocalAIConfiguration, prompt: String, maxTokens: Int,
                           system: String, timeoutSeconds: TimeInterval) async throws -> String {
        precondition(prompt.contains("shell=True") && prompt.contains("check=True"))
        precondition(prompt.contains("code.command-injection"))
        precondition(maxTokens == 4096 && !system.isEmpty && timeoutSeconds == 1500)
        return configuration.response
    }
}

@main struct Test {
    static func main() async throws {
        let valid = #"{"cases":[{"kind":"behavior","name":"Normal input","input":"plain text","expected":"same visible result"},{"kind":"security","name":"Metacharacter input","input":"input containing a command separator","expected":"no extra command runs"},{"kind":"boundary","name":"Empty input","input":"empty string","expected":"defined behavior after owner review"}],"unknowns":["Confirm whether empty input is allowed"]}"#
        let proposal = NativeLocalAIFixProposal(
            finding: NativeFinding(ruleID: "code.command-injection", recommendation: "avoid shell"),
            sourceURL: URL(fileURLWithPath: "/tmp/sample.py"),
            original: "subprocess.run(user_input, shell=True)",
            proposed: "subprocess.run([\"echo\", user_input], check=True)")
        let plan = try await NativeLocalAITestPlanner.generate(
            proposal: proposal, configuration: LocalAIConfiguration(response: valid), korean: true)
        precondition(plan.cases.count == 3)
        precondition(plan.markdown(korean: true).contains("미실행"))
        precondition(plan.markdown(korean: true).contains("no extra command runs"))

        for bad in ["not json", #"{"cases":[],"unknowns":[]}"#,
                    #"{"cases":[{"kind":"behavior","name":"Only normal","input":"a","expected":"b"}],"unknowns":[]}"#] {
            do {
                _ = try NativeLocalAITestPlanner.parse(bad)
                fatalError("malformed or incomplete plan accepted")
            } catch is NativeLocalAITestPlanError { }
        }
        print("NativeLocalAITestPlan tests passed")
    }
}
'''

with tempfile.TemporaryDirectory(prefix='koda-ai-test-plan-') as directory:
    directory = Path(directory)
    harness = directory / 'Harness.swift'
    harness.write_text(HARNESS)
    binary = directory / 'test'
    subprocess.run(['swiftc', str(SOURCE), str(harness), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
