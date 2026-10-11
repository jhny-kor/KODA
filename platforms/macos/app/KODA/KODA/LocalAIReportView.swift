import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct LocalAIReportView: View {
    let report: ScanReportItem
    let language: AppLanguage
    @Environment(\.dismiss) private var dismiss
    @AppStorage("koda.localAI.selectedProfileID") private var selectedProfileID = ""
    @State private var profiles: [LocalAIProfile] = []
    @State private var selectedID = ""
    @State private var generated: NativeAIReport?
    @State private var error = ""
    @State private var running = false
    @State private var task: Task<Void, Never>?

    private var ko: Bool { language == .ko }
    private var selected: LocalAIProfile? { profiles.first { $0.id == selectedID } }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text(ko ? "로컬 AI 보조 보고서" : "Local AI assisted report").font(.title2.weight(.bold))
                Spacer()
                Button(ko ? "닫기" : "Close") { dismiss() }
            }
            Text(ko ? "KODA 발견 수·심각도·점수는 원본 결과를 사용합니다. AI는 규칙 메타데이터로 조치·검증 계획 초안만 작성합니다. 파일 경로·소스·증거는 전송하지 않습니다."
                    : "KODA counts, severity and score remain authoritative. AI drafts guidance from rule metadata only; paths, source and evidence are not sent.")
                .font(.callout).foregroundStyle(.secondary)
            HStack {
                Picker(ko ? "저장된 모델" : "Saved model", selection: $selectedID) {
                    Text(ko ? "연결 선택" : "Choose connection").tag("")
                    ForEach(profiles) { profile in
                        Text("\(profile.name) · \(profile.model)").tag(profile.id)
                    }
                }
                .frame(maxWidth: 450)
                Button(ko ? "보고서 생성" : "Generate report") { generate() }
                    .disabled(running || selected == nil)
                if running { ProgressView().controlSize(.small) }
                if running { Button(ko ? "취소" : "Cancel") { task?.cancel() } }
            }
            if profiles.isEmpty {
                Text(ko ? "설정에서 로컬 AI 연결을 먼저 저장하세요." : "Save a local AI connection in Settings first.")
                    .foregroundStyle(.secondary)
            }
            if !error.isEmpty { Text(error).foregroundStyle(.red).textSelection(.enabled) }
            if let generated {
                HStack {
                    Text(ko ? "AI 초안 · 테스트 미실행" : "AI draft · Tests not run").font(.headline)
                    Spacer()
                    Button(ko ? "Markdown 별도 저장" : "Save separate Markdown") { save(generated) }
                }
                ScrollView {
                    Text(generated.markdown).font(.system(.body, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                }
                .padding(10)
                .background(Color(nsColor: .textBackgroundColor))
            }
        }
        .padding(20)
        .frame(minWidth: 720, minHeight: 520)
        .onAppear {
            profiles = LocalAIProfileStore.load()
            selectedID = profiles.first(where: { $0.id == selectedProfileID })?.id ?? profiles.first?.id ?? ""
        }
        .onChange(of: selectedID) { _ in generated = nil; error = "" }
        .onDisappear { task?.cancel() }
    }

    private func generate() {
        guard let profile = selected else { return }
        running = true; error = ""; generated = nil
        task = Task { @MainActor in
            defer { running = false }
            do {
                let key = try LocalAIKeychain.load(for: profile.baseURL)
                let configuration = LocalAIConfiguration(baseURL: profile.baseURL, model: profile.model, apiKey: key)
                let result = NativeScanResult(
                    findings: report.findings, warnings: report.warnings,
                    targetCount: report.targetCount, scannedFileCount: report.scannedFileCount,
                    generatedAt: report.generatedAt)
                let draft = try await NativeAIReportService.generate(result: result, configuration: configuration)
                try Task.checkCancellation()
                generated = draft
            } catch {
                if !Task.isCancelled { self.error = error.localizedDescription }
            }
        }
    }

    private func save(_ draft: NativeAIReport) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "KODA-AI-report.md"
        panel.allowedContentTypes = [UTType(filenameExtension: "md") ?? .plainText]
        panel.message = ko ? "AI 보조 보고서는 KODA 원본 보고서와 별도로 저장됩니다." : "Save the AI draft separately from the KODA report."
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            let destination = url.resolvingSymlinksInPath().standardizedFileURL
            let originals = [report.files.koMarkdownURL, report.files.enMarkdownURL]
                .map { $0.resolvingSymlinksInPath().standardizedFileURL }
            guard !originals.contains(destination) else {
                error = ko ? "KODA 원본 보고서는 덮어쓸 수 없습니다." : "The original KODA report cannot be overwritten."
                return
            }
            do { try draft.markdown.write(to: url, atomically: true, encoding: .utf8) }
            catch { self.error = error.localizedDescription }
        }
    }
}
