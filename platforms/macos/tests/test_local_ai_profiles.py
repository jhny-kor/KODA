#!/usr/bin/env python3
"""Exercise saved local-model connections across independent store loads."""
from pathlib import Path
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[1] / 'app/KODA/KODA/LocalAIProfiles.swift'
HARNESS = r'''
import Foundation

@main struct Test {
    static func main() {
        let suite = "KODA.local-ai-profiles-test.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }

        precondition(LocalAIProfileStore.migrateLegacyIfNeeded(baseURL: "http://127.0.0.1:1234/v1", model: "", defaults: defaults).isEmpty)
        let migrated = LocalAIProfileStore.migrateLegacyIfNeeded(
            baseURL: "http://127.0.0.1:1234/v1", model: "first-model", defaults: defaults)
        precondition(migrated.count == 1 && migrated[0].model == "first-model")
        precondition(LocalAIProfileStore.migrateLegacyIfNeeded(baseURL: "wrong", model: "other", defaults: defaults) == migrated)

        let second = LocalAIProfile(name: "Second", baseURL: "http://127.0.0.1:1234/v1", model: "second-model")
        let third = LocalAIProfile(name: "Other server", baseURL: "http://127.0.0.1:1235/v1", model: "third-model")
        LocalAIProfileStore.save(migrated + [second, third], to: defaults)
        let reloaded = LocalAIProfileStore.load(from: UserDefaults(suiteName: suite)!)
        precondition(reloaded == migrated + [second, third])
        let stored = defaults.data(forKey: "koda.localAI.profiles")!
        precondition(!String(decoding: stored, as: UTF8.self).contains("apiKey"))

        LocalAIProfileStore.save([second], to: defaults)
        precondition(LocalAIProfileStore.load(from: defaults) == [second])
        LocalAIProfileStore.save([], to: defaults)
        precondition(LocalAIProfileStore.migrateLegacyIfNeeded(baseURL: "old", model: "first-model", defaults: defaults).isEmpty)
        print("LocalAIProfileStore persistence tests passed")
    }
}
'''

with tempfile.TemporaryDirectory(prefix='koda-ai-profiles-') as directory:
    directory = Path(directory)
    harness = directory / 'Harness.swift'
    harness.write_text(HARNESS)
    binary = directory / 'test'
    subprocess.run(['swiftc', str(SOURCE), str(harness), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
