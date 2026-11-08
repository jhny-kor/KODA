import Darwin
import AppKit
import Foundation
import SwiftUI

@main
struct KODAApp: App {
    @NSApplicationDelegateAdaptor(KODAAppDelegate.self) private var appDelegate

    init() {
        runHeadlessWebAuditIfRequested()
        runHeadlessJavaScanIfRequested()
        runHeadlessScanIfRequested()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
            KODAWindowCoordinator.shared.ensureMainWindowVisibleAfterLaunch()
        }
    }

    /// The same compiled app can reproduce an audit in CI without automating its windows.
    private func runHeadlessWebAuditIfRequested() {
        let environment = ProcessInfo.processInfo.environment
        guard let path = environment["KODA_WEB_AUDIT_PROFILE"], !path.isEmpty else { return }
        Task.detached(priority: .userInitiated) {
            do {
                let profileURL = URL(fileURLWithPath: path)
                guard (try profileURL.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0) <= 2_097_152 else {
                    throw WebAuditError.invalidProfile("profile too large")
                }
                let profile = try WebAuditProfile.load(data: Data(contentsOf: profileURL))
                let output = URL(fileURLWithPath: environment["KODA_WEB_AUDIT_OUTPUT_DIR"] ?? NSTemporaryDirectory())
                    .appendingPathComponent("KODA-web-audit", isDirectory: true)
                var spec: Data?
                if let input = environment["KODA_WEB_AUDIT_API_SPEC"] ?? profile.apiSpecPath {
                    let file = URL(fileURLWithPath: input, relativeTo: profileURL.deletingLastPathComponent())
                    guard (try file.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0) <= 2_097_152 else {
                        throw WebAuditError.invalidProfile("API specification too large")
                    }
                    spec = try Data(contentsOf: file)
                }
                let report = try await NativeWebAuditor.run(profile: profile, apiSpecData: spec)
                let destination = try WebAuditReportWriter.write(report: report, to: output)
                print(destination.path)
                exit(!report.completed ? 2 : (report.controls.contains { $0.status == .vulnerable } ? 1 : 0))
            } catch {
                // Profile/parser errors contain no credentials; request errors are already sanitized.
                fputs("웹 정밀 점검을 완료하지 못했습니다. 프로필·권한·입력 파일을 확인하세요.\n", stderr)
                exit(2)
            }
        }
        dispatchMain()
    }

    var body: some Scene {
        WindowGroup("KODA", id: KODAWindowCoordinator.mainWindowID) {
            ZStack {
                ContentView()
                KODAWindowRegistrationView()
                    .frame(width: 0, height: 0)
                    .accessibilityHidden(true)
            }
                .frame(minWidth: 1024, minHeight: 720)
        }
        .defaultSize(width: 1440, height: 960)
        .commands {
            CommandGroup(replacing: .newItem) {}
            KODAWindowCommands()
        }
    }

    private func runHeadlessJavaScanIfRequested() {
        let environment = ProcessInfo.processInfo.environment
        guard let targetValue = environment["KODA_JAVA_SCAN_TARGETS"], !targetValue.isEmpty else {
            return
        }
        let targets = targetValue
            .split(separator: "\n")
            .map { URL(fileURLWithPath: String($0)) }
        let outputDirectory: URL
        if let outputValue = environment["KODA_JAVA_SCAN_OUTPUT_DIR"], !outputValue.isEmpty {
            outputDirectory = URL(fileURLWithPath: outputValue)
        } else {
            outputDirectory = URL(fileURLWithPath: NSTemporaryDirectory())
                .appendingPathComponent("KODA-headless-java-scan")
        }

        do {
            let language: AppLanguage = environment["KODA_JAVA_SCAN_LANGUAGE"] == "en" ? .en : .ko
            let outcome = try BundledJavaArchiveScanner.scan(targets: targets, outputDirectory: outputDirectory, language: language)
            print(outcome.sbomURL.path)
            exit(outcome.exitCode)
        } catch {
            fputs("\(error.localizedDescription)\n", stderr)
            exit(2)
        }
    }

    private func runHeadlessScanIfRequested() {
        let environment = ProcessInfo.processInfo.environment
        guard let targetValue = environment["KODA_SCAN_TARGETS"], !targetValue.isEmpty else {
            return
        }

        let targets = targetValue
            .split(separator: "\n")
            .map { URL(fileURLWithPath: String($0)) }
        let output: URL
        if let outputValue = environment["KODA_SCAN_OUTPUT"], !outputValue.isEmpty {
            output = URL(fileURLWithPath: outputValue)
        } else {
            output = URL(fileURLWithPath: NSTemporaryDirectory())
                .appendingPathComponent("KODA-headless-security-dashboard.html")
        }

        do {
            let scanner = NativeSecurityScanner()
            let result = try scanner.scan(targets: targets)
            let language: AppLanguage = environment["KODA_SCAN_LANGUAGE"] == "en" ? .en : .ko
            try scanner.writeHTMLReport(result, to: output, language: language)
            if let markdownOutput = environment["KODA_SCAN_OUTPUT_MARKDOWN"], !markdownOutput.isEmpty {
                try scanner.writeMarkdownReport(result, to: URL(fileURLWithPath: markdownOutput), language: language)
            }
            if let pdfOutput = environment["KODA_SCAN_OUTPUT_PDF"], !pdfOutput.isEmpty {
                try scanner.writePDFReport(result, to: URL(fileURLWithPath: pdfOutput), language: language)
            }
            print(output.path)
            if shouldFail(result, failOn: environment["KODA_SCAN_FAIL_ON"]) {
                exit(1)
            }
            exit(0)
        } catch {
            fputs("\(error.localizedDescription)\n", stderr)
            exit(2)
        }
    }

    private func shouldFail(_ result: NativeScanResult, failOn: String?) -> Bool {
        guard let failOn, let threshold = severityRank(failOn) else {
            return false
        }
        return result.findings.contains { finding in
            (severityRank(finding.severity) ?? 0) >= threshold
        }
    }

    private func severityRank(_ severity: String) -> Int? {
        switch severity.lowercased() {
        case "critical": return 5
        case "high": return 4
        case "medium": return 3
        case "low": return 2
        case "info": return 1
        default: return nil
        }
    }
}

private final class KODAAppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        guard !flag else {
            return true
        }

        DispatchQueue.main.async {
            KODAWindowCoordinator.shared.showMainWindow()
        }
        return false
    }
}

private final class KODAWindowCoordinator {
    static let shared = KODAWindowCoordinator()
    static let mainWindowID = "main-window"

    private var openMainWindow: (() -> Void)?
    private var fallbackWindow: NSWindow?

    func ensureMainWindowVisibleAfterLaunch() {
        showMainWindow()
    }

    func register(openWindow: OpenWindowAction) {
        openMainWindow = {
            openWindow(id: Self.mainWindowID)
        }
    }

    func showMainWindow() {
        if focusMainWindow() {
            return
        }

        guard let openMainWindow else {
            showFallbackWindow()
            return
        }

        openMainWindow()
        DispatchQueue.main.async {
            _ = self.focusMainWindow()
        }
    }

    @discardableResult
    private func focusMainWindow() -> Bool {
        NSApp.activate(ignoringOtherApps: true)

        guard let window = NSApp.windows.first(where: { window in
            window.identifier?.rawValue == Self.mainWindowID
                || window.title == "KODA"
                || (window.styleMask.contains(.titled) && window.canBecomeMain)
        }) else {
            return false
        }

        window.makeKeyAndOrderFront(nil)
        return true
    }

    private func showFallbackWindow() {
        if let fallbackWindow {
            NSApp.activate(ignoringOtherApps: true)
            fallbackWindow.makeKeyAndOrderFront(nil)
            return
        }

        let window = NSWindow(
            contentRect: initialWindowFrame(),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.identifier = NSUserInterfaceItemIdentifier(Self.mainWindowID)
        window.title = "KODA"
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: ContentView().frame(minWidth: 1024, minHeight: 720))
        fallbackWindow = window
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    private func initialWindowFrame() -> NSRect {
        guard let screen = NSScreen.main else {
            return NSRect(x: 100, y: 100, width: 1440, height: 960)
        }
        let visible = screen.visibleFrame
        let width = min(visible.width * 0.85, 1700)
        let height = min(visible.height * 0.85, 1100)
        let originX = visible.minX + (visible.width - width) / 2
        let originY = visible.minY + (visible.height - height) / 2
        return NSRect(x: originX, y: originY, width: width, height: height)
    }
}

private struct KODAWindowCommands: Commands {
    var body: some Commands {
        CommandGroup(after: .windowArrangement) {
            Button("Show KODA") {
                KODAWindowCoordinator.shared.showMainWindow()
            }
            .keyboardShortcut("0", modifiers: [.command])
        }
    }
}

private struct KODAWindowRegistrationView: View {
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        KODAWindowAccessor()
            .onAppear {
                KODAWindowCoordinator.shared.register(openWindow: openWindow)
            }
    }
}

private struct KODAWindowAccessor: NSViewRepresentable {
    // Size the window to a large share of the screen only once, so we don't fight
    // the user's manual resizing or macOS state restoration on later updates.
    private static var hasSizedInitialWindow = false

    func makeNSView(context: Context) -> NSView {
        let view = NSView(frame: .zero)
        configureWindow(for: view)
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        configureWindow(for: nsView)
    }

    private func configureWindow(for view: NSView) {
        DispatchQueue.main.async {
            guard let window = view.window else {
                return
            }

            window.identifier = NSUserInterfaceItemIdentifier(KODAWindowCoordinator.mainWindowID)
            window.title = "KODA"
            Self.sizeInitialWindowIfNeeded(window)
        }
    }

    private static func sizeInitialWindowIfNeeded(_ window: NSWindow) {
        guard !hasSizedInitialWindow else { return }
        hasSizedInitialWindow = true

        guard let screen = window.screen ?? NSScreen.main else { return }
        let visible = screen.visibleFrame
        // Open at 85% of the available screen, capped to a comfortable maximum,
        // then center it.
        let width = min(visible.width * 0.85, 1700)
        let height = min(visible.height * 0.85, 1100)
        let originX = visible.minX + (visible.width - width) / 2
        let originY = visible.minY + (visible.height - height) / 2
        window.setFrame(NSRect(x: originX, y: originY, width: width, height: height), display: true, animate: false)
    }
}
