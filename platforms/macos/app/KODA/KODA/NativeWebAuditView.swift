import AppKit
import SwiftUI
import UniformTypeIdentifiers

@MainActor
final class NativeWebAuditViewModel: ObservableObject {
    @Published var target = "https://"
    @Published var authorized = false
    @Published var active = false
    @Published var authorization = ""
    @Published var secondAuthorization = ""
    @Published var apiURL: URL?
    @Published var profileName = "기본 프로필"
    @Published var running = false
    @Published var status = "대상과 점검 권한을 확인하세요."
    @Published var report: WebAuditReport?
    @Published var reportURL: URL?
    @Published var requestLimit = 300
    @Published var timeLimit = 120
    private var imported: WebAuditProfile?
    private var task: Task<Void, Never>?
    private var accessedURLs: [URL] = []

    var readOnlyDistribution: Bool {
        #if KODA_APP_STORE
        true
        #else
        false
        #endif
    }

    func chooseAPI() {
        let panel = NSOpenPanel(); panel.allowedContentTypes = [.json]; panel.allowsMultipleSelection = false
        panel.message = "OpenAPI 3 / Swagger 2 JSON 명세를 선택하세요."
        if panel.runModal() == .OK, let url = panel.url {
            if url.startAccessingSecurityScopedResource() { accessedURLs.append(url) }
            apiURL = url
        }
    }

    func importProfile() {
        let panel = NSOpenPanel(); panel.allowedContentTypes = [.json]
        if panel.runModal() == .OK, let url = panel.url {
            let access = url.startAccessingSecurityScopedResource(); defer { if access { url.stopAccessingSecurityScopedResource() } }
            do {
                guard (try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0) <= 2_097_152 else { throw WebAuditError.invalidProfile("profile too large") }
                let profile = try WebAuditProfile.load(data: Data(contentsOf: url))
                imported = profile; target = profile.target; active = profile.active && !readOnlyDistribution
                // An imported file cannot grant authority on the operator's behalf.
                authorized = false
                requestLimit = profile.limits.maxRequests; timeLimit = Int(profile.limits.maxDuration)
                profileName = url.lastPathComponent
                status = "프로필 로드: 계정 \(profile.accounts.count) · 리소스 \(profile.resources.count) · 시나리오 \(profile.scenarios.count) · 추가 규칙 \(profile.rules.count)"
                if let path = profile.apiSpecPath {
                    apiURL = URL(fileURLWithPath: path, relativeTo: url.deletingLastPathComponent()).standardizedFileURL
                }
            } catch { status = "프로필을 읽지 못했습니다: \(error.localizedDescription)" }
        }
    }

    func exportStarter() {
        let panel = NSSavePanel(); panel.allowedContentTypes = [.json]; panel.nameFieldStringValue = "koda-web-profile.json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        var profile = WebAuditProfile(target: target)
        profile.accounts = [WebAuditAccount(id: "userA", headers: ["Authorization": "${ENV:KODA_USER_A}"]),
                            WebAuditAccount(id: "userB", headers: ["Authorization": "${ENV:KODA_USER_B}"])]
        profile.resources = [WebAuditResource(id: "private-resource", path: "/api/me", expectations: [
            "anonymous": WebAuditExpectation(statusCodes: [401, 403]),
            "userA": WebAuditExpectation(statusCodes: [200], bodyContains: "userA")])]
        profile.scenarios = [WebAuditScenario(id: "home-available", controlID: "web.process-validation",
            steps: [WebAuditStep(path: "/", expectedStatusCodes: [200])])]
        do { try profile.encoded().write(to: url, options: .atomic); status = "프로필 예제를 저장했습니다. 대상별 경로와 기대 응답을 수정하세요." }
        catch { status = error.localizedDescription }
    }

    func start() {
        guard !running, authorized else { status = "대상 점검 권한을 확인해야 합니다."; return }
        let panel = NSOpenPanel(); panel.canChooseDirectories = true; panel.canChooseFiles = false
        panel.canCreateDirectories = true; panel.message = "점검 보고서를 저장할 폴더를 선택하세요."
        guard panel.runModal() == .OK, let directory = panel.url else { return }
        let access = directory.startAccessingSecurityScopedResource()
        let output = directory.appendingPathComponent("KODA-web-\(UUID().uuidString.prefix(8))", isDirectory: true)
        var profile = imported ?? WebAuditProfile(target: target)
        profile.target = target.trimmingCharacters(in: .whitespacesAndNewlines)
        profile.authorized = authorized; profile.active = active && !readOnlyDistribution
        profile.limits.maxRequests = requestLimit; profile.limits.maxDuration = Double(timeLimit)
        if !authorization.isEmpty { profile.headers["Authorization"] = authorization }
        if !secondAuthorization.isEmpty {
            profile.accounts.removeAll { $0.id == "secondary" }
            profile.accounts.append(WebAuditAccount(id: "secondary", headers: ["Authorization": secondAuthorization]))
        }
        if readOnlyDistribution { profile.allowStateChanges = false; profile.allowedMethods = ["GET", "HEAD"] }
        let specURL = apiURL
        running = true; report = nil; reportURL = nil; status = "범위와 실행 한도를 검증하고 있습니다."
        task = Task { [self] in
            defer { if access { directory.stopAccessingSecurityScopedResource() }; running = false; task = nil }
            do {
                var apiData: Data?
                if let specURL {
                    guard (try specURL.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0) <= 2_097_152 else { throw WebAuditError.invalidProfile("API specification too large") }
                    apiData = try Data(contentsOf: specURL)
                }
                let result = try await NativeWebAuditor.run(profile: profile, apiSpecData: apiData) { [weak self] message in
                    Task { @MainActor in if self?.running == true { self?.status = message } }
                }
                report = result
                reportURL = try WebAuditReportWriter.write(report: result, to: output)
                status = result.completed ? "점검 완료 · 보고서를 저장했습니다." : "점검 미완료 · 실행 공백과 증거를 보고서에서 확인하세요."
            } catch {
                status = "점검 실패: \(WebAuditRedactor(profile: profile).clean(error.localizedDescription))"
            }
        }
    }

    func cancel() { task?.cancel(); status = "점검 중지 중 · 미실행 항목과 정리 상태를 기록합니다." }
    func openReport() { if let reportURL { NSWorkspace.shared.open(reportURL) } }
    func showFolder() { if let reportURL { NSWorkspace.shared.activateFileViewerSelecting([reportURL]) } }
}

struct NativeWebAuditView: View {
    @StateObject private var model = NativeWebAuditViewModel()
    @State private var selectedControl: String?
    let language: AppLanguage
    var onClose: () -> Void = {}

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(language == .ko ? "웹 정밀 점검" : "Web Audit").font(.title.bold())
            Text("승인 범위에서 HTTP·API·권한·업무 시나리오를 검사하고 근거를 저장합니다.").foregroundStyle(.secondary)
            HStack {
                TextField("https://staging.example.com", text: $model.target).textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("web-audit.target")
                Button("프로필 가져오기", action: model.importProfile)
                Button("프로필 예제 저장", action: model.exportStarter)
            }.disabled(model.running)
            HStack {
                Text(model.profileName).foregroundStyle(.secondary)
                Spacer()
                Button("API 명세 선택", action: model.chooseAPI)
                if let api = model.apiURL { Text(api.lastPathComponent); Button("해제") { model.apiURL = nil } }
            }.disabled(model.running)
            DisclosureGroup("계정과 실행 한도") {
                VStack(alignment: .leading) {
                    SecureField("기본 계정 Authorization (선택)", text: $model.authorization)
                    SecureField("비교 계정 Authorization (선택, actor: secondary)", text: $model.secondAuthorization)
                    Text("계정별 기대 응답과 정리 절차는 프로필에서 지정합니다. 계정 정보는 보고서에 저장하지 않습니다.").font(.caption).foregroundStyle(.secondary)
                    HStack {
                        Stepper("최대 요청 \(model.requestLimit)건", value: $model.requestLimit, in: 10...5000, step: 10)
                        Stepper("최대 \(model.timeLimit)초", value: $model.timeLimit, in: 10...3600, step: 10)
                    }
                }.padding(.top, 8)
            }.disabled(model.running)
            HStack {
                Toggle("능동 검사", isOn: $model.active).disabled(model.running || model.readOnlyDistribution)
                Toggle("본인이 소유하거나 점검 허가를 받은 대상입니다", isOn: $model.authorized)
                    .accessibilityIdentifier("web-audit.authorized").disabled(model.running)
            }
            HStack {
                Button("점검 시작", action: model.start).buttonStyle(.borderedProminent)
                    .disabled(model.running || !model.authorized).accessibilityIdentifier("web-audit.start")
                Button("중지", action: model.cancel).disabled(!model.running).accessibilityIdentifier("web-audit.cancel")
                if model.running { ProgressView().controlSize(.small) }
                Spacer()
                Button("보고서 열기", action: model.openReport).disabled(model.reportURL == nil)
                Button("저장 폴더", action: model.showFolder).disabled(model.reportURL == nil)
                Button("닫기", action: onClose).disabled(model.running)
            }
            Text(model.status).font(.callout).textSelection(.enabled).accessibilityIdentifier("web-audit.status")
            if let report = model.report {
                HStack {
                    Text("요청 \(report.metrics.requests) · 증거 \(report.observations.count) · 차단 \(report.metrics.blocked)")
                    Spacer(); Text(report.completed ? "실행 완료" : "실행 공백 있음").foregroundStyle(report.completed ? .green : .orange)
                }
                List(report.controls, id: \.controlID, selection: $selectedControl) { control in
                    HStack {
                        Text(control.title).frame(width: 150, alignment: .leading)
                        Text(control.status.rawValue).font(.system(.caption, design: .monospaced)).frame(width: 135, alignment: .leading)
                            .foregroundStyle(control.status == .vulnerable ? .red : (control.status == .pass ? .green : .secondary))
                        Text(control.reason).font(.caption).foregroundStyle(.secondary)
                    }.tag(control.controlID)
                }
                if let selectedControl {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 10) {
                            ForEach(report.observations.filter { $0.controlID == selectedControl }, id: \.evidenceID) { evidence in
                                Text("\(evidence.title)\n\(evidence.method) \(evidence.endpoint)\n\(evidence.evidence)").font(.caption).textSelection(.enabled)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }.frame(maxHeight: 140)
                }
            } else {
                VStack(spacing: 12) {
                    Image(systemName: "checklist").font(.largeTitle)
                    Text("점검 결과").font(.headline)
                    Text("미점검 항목은 안전 판정으로 표시하지 않습니다.").foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }.padding(24).frame(minWidth: 880, minHeight: 690).interactiveDismissDisabled(model.running)
    }
}
