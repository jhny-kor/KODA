import AppKit
import Foundation
import SwiftUI

/// Shared store for per-machine rule on/off state. The Settings popup writes it,
/// and NativeSecurityScanner reads it to drop disabled rules from scan results
/// (a post-scan filter, matching the web dashboard's `disabled_rules` behavior).
enum KodaRuleSettings {
    static let defaultsKey = "koda.disabledRules"

    static func disabledIDs() -> Set<String> {
        guard
            let raw = UserDefaults.standard.string(forKey: defaultsKey),
            let data = raw.data(using: .utf8),
            let list = try? JSONDecoder().decode([String].self, from: data)
        else {
            return []
        }
        return Set(list)
    }

    static func save(_ ids: Set<String>) {
        let encoded = try? JSONEncoder().encode(Array(ids).sorted())
        let json = encoded.flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
        UserDefaults.standard.set(json, forKey: defaultsKey)
    }
}

struct RuleCatalogRule: Decodable, Identifiable, Hashable, Sendable {
    let id: String
    let title: String
    let description: String
}

struct RuleCatalogGroup: Decodable, Identifiable, Hashable, Sendable {
    let key: String
    let kind: String  // "security" | "quality"
    let label: String
    let rules: [RuleCatalogRule]

    var id: String { key }
}

/// Loads the bundled `rules_catalog.json` (generated from the shared Python engine
/// via `python -m security_scanner.rules_export`).
enum RuleCatalog {
    private static let allGroups: [String: [RuleCatalogGroup]] = {
        guard
            let url = Bundle.main.url(forResource: "rules_catalog", withExtension: "json"),
            let data = try? Data(contentsOf: url),
            let groups = try? JSONDecoder().decode([String: [RuleCatalogGroup]].self, from: data)
        else {
            return [:]
        }
        return groups
    }()

    static func groups(language: AppLanguage) -> [RuleCatalogGroup] {
        allGroups[language.rawValue] ?? allGroups["ko"] ?? []
    }

    static func preload() async {
        await Task.detached(priority: .utility) {
            _ = allGroups
        }.value
    }
}

struct SettingsView: View {
    @Binding var language: AppLanguage
    var onClose: () -> Void

    @State private var groups: [RuleCatalogGroup] = []
    @State private var disabled: Set<String> = KodaRuleSettings.disabledIDs()
    @State private var tab: String = "security"
    @State private var expandedGroups: Set<String> = []
    @State private var isLoading = true

    private var visibleGroups: [RuleCatalogGroup] {
        groups.filter { $0.kind == tab }
    }

    private var title: String { language == .ko ? "KODA 설정" : "KODA settings" }
    private var intro: String {
        if tab == "ai" { return language == .ko ? "OpenAI 호환 로컬 모델 연결을 설정합니다." : "Configure an OpenAI-compatible local model." }
        return language == .ko
            ? "규칙을 개별적으로 켜거나 끌 수 있습니다. 끈 규칙은 점검 결과에서 제외됩니다."
            : "Turn individual rules on or off. Disabled rules are excluded from scan results."
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.title2.weight(.bold))
                    Text(intro).font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                Button(language == .ko ? "닫기" : "Close", action: onClose)
                    .keyboardShortcut(.cancelAction)
            }
            .padding(20)

            HStack(spacing: 8) {
                tabButton("security", language == .ko ? "보안점검" : "Security check")
                tabButton("quality", language == .ko ? "품질점검" : "Quality check")
                tabButton("ai", language == .ko ? "로컬 AI" : "Local AI")
                Spacer()
                if tab != "ai" {
                    Button(language == .ko ? "모두 사용" : "Enable all") {
                        disabled.removeAll()
                        KodaRuleSettings.save(disabled)
                    }
                    .disabled(disabled.isEmpty)

                    Button(language == .ko ? "모두 닫기" : "Collapse all") {
                        expandedGroups.removeAll()
                    }
                    .disabled(visibleGroups.isEmpty || expandedGroups.isEmpty)
                }
            }
            .padding(.horizontal, 20)

            Divider().padding(.top, 12)

            ScrollView {
                if tab == "ai" {
                    LocalAIView(language: language)
                } else if isLoading {
                    ProgressView(language == .ko ? "기준 목록을 준비하고 있습니다…" : "Loading standards…")
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(20)
                } else if visibleGroups.isEmpty {
                    Text(language == .ko ? "규칙 목록을 불러올 수 없습니다." : "Rule catalog is unavailable.")
                        .foregroundStyle(.secondary)
                        .padding(20)
                } else {
                    LazyVStack(alignment: .leading, spacing: 10) {
                        ForEach(visibleGroups) { group in
                            DisclosureGroup(isExpanded: expansionBinding(for: group.key)) {
                                LazyVStack(alignment: .leading, spacing: 0) {
                                    ForEach(group.rules) { rule in
                                        ruleRow(rule)
                                        Divider()
                                    }
                                }
                                .padding(.top, 8)
                            } label: {
                                groupHeader(group)
                            }
                            .padding(12)
                            .background(KODATheme.cardBackground)
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                            .overlay {
                                RoundedRectangle(cornerRadius: 8)
                                    .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                            }
                        }
                    }
                    .padding(20)
                }
            }
        }
        .frame(minWidth: 560, minHeight: 520)
        .task(id: language) {
            if groups.isEmpty { isLoading = true }
            let rawLanguage = language.rawValue
            let loadedGroups = await Task.detached(priority: .userInitiated) {
                RuleCatalog.groups(language: AppLanguage(rawValue: rawLanguage) ?? .ko)
            }.value
            guard !Task.isCancelled else { return }
            groups = loadedGroups
            expandedGroups.removeAll()
            isLoading = false
        }
    }

    private func tabButton(_ value: String, _ label: String) -> some View {
        Button(label) { tab = value }
            .buttonStyle(.borderedProminent)
            .tint(tab == value ? .accentColor : Color(nsColor: .controlColor))
            .foregroundStyle(tab == value ? Color.white : Color.primary)
    }

    private func groupHeader(_ group: RuleCatalogGroup) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(group.label)
                .font(.headline)
                .lineLimit(2)

            Spacer(minLength: 8)

            Text("\(enabledRuleCount(in: group))/\(group.rules.count)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        }
    }

    private func enabledRuleCount(in group: RuleCatalogGroup) -> Int {
        group.rules.reduce(into: 0) { count, rule in
            if !disabled.contains(rule.id) { count += 1 }
        }
    }

    private func expansionBinding(for key: String) -> Binding<Bool> {
        Binding(
            get: { expandedGroups.contains(key) },
            set: { isExpanded in
                if isExpanded {
                    expandedGroups.insert(key)
                } else {
                    expandedGroups.remove(key)
                }
            }
        )
    }

    private func ruleRow(_ rule: RuleCatalogRule) -> some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(rule.title).font(.body.weight(.medium))
                Text(rule.id).font(.caption.monospaced()).foregroundStyle(.secondary)
                if !rule.description.isEmpty {
                    Text(rule.description).font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            Toggle("", isOn: binding(for: rule.id))
                .labelsHidden()
                .toggleStyle(.switch)
        }
    }

    private func binding(for ruleID: String) -> Binding<Bool> {
        Binding(
            get: { !disabled.contains(ruleID) },
            set: { enabled in
                if enabled {
                    disabled.remove(ruleID)
                } else {
                    disabled.insert(ruleID)
                }
                KodaRuleSettings.save(disabled)
            }
        )
    }
}

/// Minimal, dependency-free .xlsx writer (inlineStr cells) built by zipping the
/// SpreadsheetML parts with /usr/bin/zip -- mirrors reporting.render_xlsx so the
/// macOS export matches the web dashboard.
enum NativeXlsxExporter {
    static func write(findings: [NativeFinding], language: AppLanguage, to destination: URL) throws {
        let headers = language == .ko
            ? ["심각도", "분류", "룰", "제목", "경로", "줄", "권장 조치"]
            : ["Severity", "Category", "Rule", "Title", "Path", "Line", "Recommendation"]
        var rows: [[String]] = [headers]
        for finding in findings {
            rows.append([
                finding.severity,
                finding.category,
                finding.ruleID,
                finding.title,
                finding.path,
                finding.line.map(String.init) ?? "",
                finding.recommendation,
            ])
        }

        var sheetRows = ""
        for (rowIndex, row) in rows.enumerated() {
            var cells = ""
            for (colIndex, value) in row.enumerated() {
                let ref = "\(columnRef(colIndex))\(rowIndex + 1)"
                cells += "<c r=\"\(ref)\" t=\"inlineStr\"><is><t xml:space=\"preserve\">\(escape(value))</t></is></c>"
            }
            sheetRows += "<row r=\"\(rowIndex + 1)\">\(cells)</row>"
        }

        let members: [String: String] = [
            "[Content_Types].xml": """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>
            """,
            "_rels/.rels": """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>
            """,
            "xl/workbook.xml": """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Findings" sheetId="1" r:id="rId1"/></sheets></workbook>
            """,
            "xl/_rels/workbook.xml.rels": """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>
            """,
            "xl/worksheets/sheet1.xml": """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>\(sheetRows)</sheetData></worksheet>
            """,
        ]

        let fileManager = FileManager.default
        let workDir = fileManager.temporaryDirectory.appendingPathComponent("koda-xlsx-\(UUID().uuidString)")
        try fileManager.createDirectory(at: workDir, withIntermediateDirectories: true)
        defer { try? fileManager.removeItem(at: workDir) }

        for (name, content) in members {
            let fileURL = workDir.appendingPathComponent(name)
            try fileManager.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try content.data(using: .utf8)?.write(to: fileURL)
        }

        let archive = workDir.appendingPathComponent("out.xlsx")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
        process.currentDirectoryURL = workDir
        process.arguments = ["-r", "-X", archive.path] + members.keys.map { $0 }
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "KODA.xlsx", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: "xlsx packaging failed"])
        }

        if fileManager.fileExists(atPath: destination.path) {
            try fileManager.removeItem(at: destination)
        }
        try fileManager.copyItem(at: archive, to: destination)
    }

    private static func columnRef(_ index: Int) -> String {
        var value = index + 1
        var ref = ""
        while value > 0 {
            let remainder = (value - 1) % 26
            ref = String(UnicodeScalar(65 + remainder)!) + ref
            value = (value - 1) / 26
        }
        return ref
    }

    private static func escape(_ text: String) -> String {
        text
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }
}
