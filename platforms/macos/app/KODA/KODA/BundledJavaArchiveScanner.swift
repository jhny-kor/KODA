import Foundation
import Darwin

struct BundledJavaScanOutcome {
    let exitCode: Int32
    let sbomURL: URL
    let componentCount: Int
    let vulnerabilityCount: Int
    let detail: String
}

enum BundledJavaArchiveScanner {
    private static let archiveExtensions = Set(["jar", "war", "ear"])

    static func scan(targets: [URL], outputDirectory: URL, language: AppLanguage) throws -> BundledJavaScanOutcome {
        guard !targets.isEmpty else {
            throw JavaScanError.noTargets
        }

        let assets = try paths()
        try FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)
        let stagingDirectory = try stagingDirectory()
        defer { try? FileManager.default.removeItem(at: stagingDirectory) }

        let accessedTargets = targets.filter { $0.startAccessingSecurityScopedResource() }
        defer { accessedTargets.forEach { $0.stopAccessingSecurityScopedResource() } }
        try stage(targets: targets, in: stagingDirectory)

        let databaseCache = try databaseCacheDirectory()
        try importDatabaseIfNeeded(grype: assets.grype, archive: assets.databaseArchive, cache: databaseCache)

        let result = try run(
            executable: assets.scanner,
            // Java reports follow the Korean-only CLI contract independently of UI locale.
            arguments: ["jar-scan", "--target", stagingDirectory.path, "--output-dir", outputDirectory.path, "--language", "ko"],
            environment: [
                "KODA_SYFT_BIN": assets.syft.path,
                "KODA_GRYPE_BIN": assets.grype.path,
                "KODA_NVD_DATA": assets.nvdDirectory.path,
                "KODA_CISA_KEV": assets.cisaKEV.path,
                "GRYPE_DB_CACHE_DIR": databaseCache.path,
                "GRYPE_DB_AUTO_UPDATE": "false",
                "GRYPE_DB_VALIDATE_AGE": "false",
            ]
        )
        let sbomURL = outputDirectory.appendingPathComponent("server-sbom.cdx.json")
        guard FileManager.default.fileExists(atPath: sbomURL.path) else {
            throw JavaScanError.missingSBOM(result.stderr)
        }
        return BundledJavaScanOutcome(
            exitCode: result.exitCode,
            sbomURL: sbomURL,
            componentCount: componentCount(in: sbomURL),
            vulnerabilityCount: vulnerabilityCount(in: outputDirectory.appendingPathComponent("server-vulnerabilities.json")),
            detail: [result.stdout, result.stderr].filter { !$0.isEmpty }.joined(separator: "\n")
        )
    }

    private static func paths() throws -> AssetPaths {
        let contents = Bundle.main.bundleURL.appendingPathComponent("Contents", isDirectory: true)
        let resources = contents.appendingPathComponent("Resources/java-scan", isDirectory: true)
        let helpers = contents.appendingPathComponent("Helpers", isDirectory: true)
        let tools = helpers.appendingPathComponent("java-scan-tools/\(architecture)", isDirectory: true)
        let databaseDirectory = resources.appendingPathComponent("grype-db/incoming", isDirectory: true)
        guard let databaseArchive = try FileManager.default.contentsOfDirectory(at: databaseDirectory, includingPropertiesForKeys: nil).first(where: { $0.pathExtension == "zst" }) else {
            throw JavaScanError.missingAsset(databaseDirectory.path)
        }
        let paths = AssetPaths(
            scanner: helpers.appendingPathComponent("koda-java-scan-\(architecture).app/Contents/MacOS/koda-java-scan"),
            syft: tools.appendingPathComponent("syft"),
            grype: tools.appendingPathComponent("grype"),
            databaseArchive: databaseArchive,
            nvdDirectory: resources.appendingPathComponent("vuln-data/nvd", isDirectory: true),
            cisaKEV: resources.appendingPathComponent("vuln-data/known_exploited_vulnerabilities.json")
        )
        for path in [paths.scanner, paths.syft, paths.grype, paths.nvdDirectory, paths.cisaKEV] where !FileManager.default.fileExists(atPath: path.path) {
            throw JavaScanError.missingAsset(path.path)
        }
        return paths
    }

    private static func stagingDirectory() throws -> URL {
        let cache = try FileManager.default.url(for: .cachesDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let directory = cache.appendingPathComponent("java-scan/\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private static func databaseCacheDirectory() throws -> URL {
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let directory = support.appendingPathComponent("com.jhnykor.koda/java-scan/grype-db", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private static func stage(targets: [URL], in directory: URL) throws {
        for (index, target) in targets.enumerated() {
            let destination = directory.appendingPathComponent("\(index)-\(target.lastPathComponent)")
            try FileManager.default.copyItem(at: target, to: destination)
        }
    }

    private static func importDatabaseIfNeeded(grype: URL, archive: URL, cache: URL) throws {
        let marker = cache.appendingPathComponent(".koda-imported-\(archive.lastPathComponent)")
        guard !FileManager.default.fileExists(atPath: marker.path) else {
            return
        }
        let result = try run(
            executable: grype,
            arguments: ["db", "import", archive.path],
            environment: [
                "GRYPE_DB_CACHE_DIR": cache.path,
                "GRYPE_DB_AUTO_UPDATE": "false",
                "GRYPE_DB_VALIDATE_AGE": "false",
            ]
        )
        guard result.exitCode == 0 else {
            throw JavaScanError.databaseImport(result.stderr)
        }
        try Data().write(to: marker, options: .atomic)
    }

    private static func run(executable: URL, arguments: [String], environment: [String: String], timeout: TimeInterval = 1800) throws -> ProcessResult {
        let process = Process()
        let stdout = Pipe()
        let stderr = Pipe()
        let readers = [stdout.fileHandleForReading, stderr.fileHandleForReading]
        defer { readers.forEach { try? $0.close() } }
        for reader in readers {
            let flags = fcntl(reader.fileDescriptor, F_GETFL)
            guard flags >= 0, fcntl(reader.fileDescriptor, F_SETFL, flags | O_NONBLOCK) >= 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
        process.executableURL = executable
        process.arguments = arguments
        process.environment = ProcessInfo.processInfo.environment.merging(environment) { _, replacement in replacement }
        process.standardOutput = stdout
        process.standardError = stderr
        process.standardInput = FileHandle.nullDevice
        let terminated = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in terminated.signal() }
        try process.run()
        defer {
            if process.isRunning {
                process.terminate()
                if terminated.wait(timeout: .now() + .seconds(1)) == .timedOut, process.isRunning {
                    kill(process.processIdentifier, SIGKILL)
                    _ = terminated.wait(timeout: .now() + .seconds(1))
                }
            }
        }
        let deadline = DispatchTime.now() + timeout
        var output = Data()
        var errors = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        func drain(_ reader: FileHandle, into data: inout Data) throws {
            // Bound each turn so a noisy stream cannot starve its peer or the deadline.
            for _ in 0..<16 {
                let count = Darwin.read(reader.fileDescriptor, &buffer, buffer.count)
                if count > 0 { data.append(contentsOf: buffer.prefix(count)) }
                else if count == 0 || errno == EAGAIN || errno == EWOULDBLOCK { return }
                else if errno != EINTR { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            }
        }
        while true {
            try drain(readers[0], into: &output)
            try drain(readers[1], into: &errors)
            if !process.isRunning { break }
            guard DispatchTime.now() < deadline else {
                throw JavaScanError.processTimeout(executable.lastPathComponent, timeout)
            }
            // Both pipes are consumed while the child is running, without waiting
            // for EOF on one stream while the other stream fills its pipe.
            _ = terminated.wait(timeout: .now() + .milliseconds(10))
        }
        try drain(readers[0], into: &output)
        try drain(readers[1], into: &errors)
        return ProcessResult(
            exitCode: process.terminationStatus,
            stdout: String(decoding: output, as: UTF8.self),
            stderr: String(decoding: errors, as: UTF8.self)
        )
    }

    private static func componentCount(in sbom: URL) -> Int {
        jsonArrayCount(in: sbom, key: "components")
    }

    private static func vulnerabilityCount(in report: URL) -> Int {
        jsonArrayCount(in: report, key: "vulnerabilities")
    }

    private static func jsonArrayCount(in file: URL, key: String) -> Int {
        guard let data = try? Data(contentsOf: file),
              let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let values = payload[key] as? [Any] else {
            return 0
        }
        return values.count
    }

    private static var architecture: String {
        #if arch(arm64)
        return "arm64"
        #elseif arch(x86_64)
        return "amd64"
        #else
        return "unsupported"
        #endif
    }
}

private struct AssetPaths {
    let scanner: URL
    let syft: URL
    let grype: URL
    let databaseArchive: URL
    let nvdDirectory: URL
    let cisaKEV: URL
}

private struct ProcessResult {
    let exitCode: Int32
    let stdout: String
    let stderr: String
}

private enum JavaScanError: LocalizedError {
    case noTargets
    case missingAsset(String)
    case databaseImport(String)
    case missingSBOM(String)
    case processTimeout(String, TimeInterval)

    var errorDescription: String? {
        switch self {
        case .noTargets:
            return "No JAR, WAR, or EAR target was selected."
        case .missingAsset(let path):
            return "Bundled Java scanner asset is missing: \(path)"
        case .databaseImport(let detail):
            return "Bundled Grype database import failed: \(detail)"
        case .missingSBOM(let detail):
            return "Bundled Java scanner did not generate an SBOM: \(detail)"
        case .processTimeout(let executable, let seconds):
            return "Bundled Java scanner process timed out after \(seconds) seconds: \(executable)"
        }
    }
}
