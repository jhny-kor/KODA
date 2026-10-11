import SwiftUI
import WebKit

struct ContentView: View {
    @StateObject private var scanner = ScannerBridge()
    @State private var activeStandard: AppSecurityStandard?
    @State private var activeReport: ScanReportItem?
    @State private var activeRemediationReport: ScanReportItem?
    @State private var activeHelpGuide: HelpGuideRoute?
    @State private var language: AppLanguage = .ko
    @State private var showFixWizard = false
    @State private var fixPlans: [SecurityFixPlan] = []
    @State private var showScoreHistory = false
    @State private var showMainHelp = false
    @State private var showSettings = false
    @State private var showProjectProfiles = false
    @State private var showThreatModelWizard = false
    @State private var showComplianceDashboard = false
    @AppStorage("koda.dashboard.topFraction.v2") private var dashboardTopFraction = 0.25

    var body: some View {
        GeometryReader { proxy in
            if showMainHelp {
                MainHelpScreen(language: $language) {
                    showMainHelp = false
                }
            } else if let activeHelpGuide {
                HelpGuideScreen(
                    route: activeHelpGuide,
                    language: $language
                ) {
                    self.activeHelpGuide = nil
                }
            } else if let activeRemediationReport {
                RemediationGuideScreen(
                    report: activeRemediationReport,
                    targets: scanner.selectedTargets,
                    language: $language
                ) {
                    self.activeRemediationReport = nil
                }
            } else if let activeReport {
                ScanReportDetailScreen(
                    report: activeReport,
                    language: $language,
                    maskReportExports: $scanner.maskReportExports
                ) {
                    self.activeReport = nil
                } onHelp: {
                    self.activeHelpGuide = HelpGuideRoute(report: activeReport)
                } onRemediation: {
                    self.activeRemediationReport = activeReport
                } onExport: { format in
                    scanner.export(activeReport, as: format, language: language)
                }
            } else if let activeStandard {
                SecurityStandardDetailScreen(
                    standard: activeStandard,
                    language: $language
                ) {
                    self.activeStandard = nil
                } onHelp: {
                    self.activeHelpGuide = HelpGuideRoute(standard: activeStandard)
                }
            } else {
                homeView(size: proxy.size)
            }
        }
        .frame(minWidth: 860, minHeight: 640)
        .task {
            await RuleCatalog.preload()
        }
        .sheet(isPresented: $showSettings) {
            SettingsView(language: $language) {
                showSettings = false
            }
        }
        .sheet(isPresented: $showFixWizard) {
            SecurityFixWizardSheet(
                plans: fixPlans,
                language: language,
                onApply: { plans in
                    scanner.applySecurityFixPlans(plans, language: language)
                    showFixWizard = false
                },
                onCancel: {
                    showFixWizard = false
                }
            )
        }
        .sheet(isPresented: $showScoreHistory) {
            SecurityScoreHistorySheet(
                snapshots: scanner.scoreHistory,
                language: language,
                onClose: {
                    showScoreHistory = false
                },
                onClear: {
                    scanner.clearScoreHistory(language: language)
                }
            )
        }
        .sheet(isPresented: $showProjectProfiles) {
            ProjectProfilesSheet(
                profiles: scanner.projectProfiles,
                language: language,
                onLoad: { profile in
                    scanner.loadProjectProfile(profile, language: language)
                    showProjectProfiles = false
                },
                onDelete: { profile in
                    scanner.deleteProjectProfile(profile, language: language)
                },
                onClose: {
                    showProjectProfiles = false
                }
            )
        }
        .sheet(isPresented: $showThreatModelWizard) {
            ThreatModelWizardSheet(language: language) { markdown in
                scanner.exportThreatModelTemplate(markdown: markdown, language: language)
                showThreatModelWizard = false
            } onClose: {
                showThreatModelWizard = false
            }
        }
        .sheet(isPresented: $showComplianceDashboard) {
            ComplianceDashboardSheet(
                standards: SecurityStandardCatalog.all,
                reports: scanner.reportItems,
                language: language
            ) {
                showComplianceDashboard = false
            }
        }
    }

    private func homeView(size: CGSize) -> some View {
        let metrics = layoutMetrics(for: size)

        return DashboardSplitView(topFraction: $dashboardTopFraction) {
            GeometryReader { topProxy in
                VStack(alignment: .leading, spacing: metrics.verticalSpacing) {
                    header
                    targetPicker(maxHeight: targetListHeight(for: topProxy.size, metrics: metrics))
                }
                .padding(metrics.outerPadding)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
        } bottom: {
            lowerPane(minimumCardWidth: metrics.minimumCardWidth)
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 16) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 56, height: 56)
                .clipShape(RoundedRectangle(cornerRadius: 12))

            VStack(alignment: .leading, spacing: 6) {
                Text("KODA")
                    .font(.system(size: 31, weight: .bold))
                Text(language.appSubtitle)
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Menu {
                Menu {
                    Button {
                        fixPlans = scanner.buildSecurityFixPlans(language: language)
                        showFixWizard = true
                    } label: {
                        Label(language.autoFixWizardTitle, systemImage: "wand.and.sparkles")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.applySecurityToolkit(language: language)
                    } label: {
                        Label(language.applyPreventionToolkitTitle, systemImage: "folder.badge.gearshape")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.installPreCommitHook(language: language)
                    } label: {
                        Label(language.installPreCommitHookTitle, systemImage: "checkmark.seal")
                    }
                    .disabled(!scanner.hasSelection || scanner.isRunning)

                    Button {
                        scanner.createIgnoreTemplate(language: language)
                    } label: {
                        Label(language.createIgnoreFileTitle, systemImage: "eye.slash")
                    }
                    .disabled(scanner.isRunning)
                } label: {
                    Label(language == .ko ? "적용 & 차단" : "Apply & Block", systemImage: "checkmark.shield")
                }

                Menu {
                    Button {
                        scanner.exportSBOM(language: language)
                    } label: {
                        Label(language.generateSBOMTitle, systemImage: "shippingbox")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportJavaArchiveSecurityPackage(language: language)
                    } label: {
                        Label(language == .ko ? "Java SBOM · 취약점 분석" : "Java SBOM · Vulnerability Scan", systemImage: "archivebox.fill")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportVEX(language: language)
                    } label: {
                        Label(language.generateVEXTitle, systemImage: "doc.text.magnifyingglass")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportReleaseSecurityPackage(language: language)
                    } label: {
                        Label(language.releaseSecurityPackageTitle, systemImage: "archivebox")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportReleaseSigningPlan(language: language)
                    } label: {
                        Label(language.releaseSigningPlanTitle, systemImage: "signature")
                    }
                    .disabled(scanner.isRunning)
                } label: {
                    Label(language == .ko ? "의존성 & 공급망" : "Dependencies & Supply Chain", systemImage: "shippingbox.and.arrow.backward")
                }

                Menu {
                    Button {
                        scanner.runWebScan(language: language)
                    } label: {
                        Label(language == .ko ? "웹사이트 점검 (실시간)" : "Scan Website (Live)", systemImage: "globe")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportZAPBaselinePlan(language: language)
                    } label: {
                        Label(language.generateZAPPlanTitle, systemImage: "bolt.shield")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.runZAPBaseline(language: language)
                    } label: {
                        Label(language.runZAPDASTTitle, systemImage: "play.shield")
                    }
                    .disabled(scanner.isRunning)
                } label: {
                    Label(language == .ko ? "동적 점검 (DAST)" : "Dynamic Testing (DAST)", systemImage: "bolt.shield")
                }

                Menu {
                    Button {
                        scanner.exportEvidenceChecklist(language: language)
                    } label: {
                        Label(language.evidenceChecklistTitle, systemImage: "checklist")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportRepositorySecurityChecklist(language: language)
                    } label: {
                        Label(language.repositorySecurityChecklistTitle, systemImage: "lock.shield")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportSSDFWorkflowPlan(language: language)
                    } label: {
                        Label(language.ssdfWorkflowPlanTitle, systemImage: "list.clipboard")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportSecureByDesignPlan(language: language)
                    } label: {
                        Label(language.secureByDesignPlanTitle, systemImage: "shield.righthalf.filled")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        showThreatModelWizard = true
                    } label: {
                        Label(language.threatModelWizardTitle, systemImage: "person.text.rectangle")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        showComplianceDashboard = true
                    } label: {
                        Label(language.complianceDashboardTitle, systemImage: "checkmark.rectangle.stack")
                    }

                    Button {
                        scanner.exportSecretResponseChecklist(language: language)
                    } label: {
                        Label(language.secretRotationRunbookTitle, systemImage: "key.horizontal")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportAILLMSecurityPlan(language: language)
                    } label: {
                        Label(language.aiLLMSecurityPlanTitle, systemImage: "sparkles")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportMobileSecurityPlan(language: language)
                    } label: {
                        Label(language.mobileSecurityPlanTitle, systemImage: "iphone.and.arrow.forward")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportNISTCSFProfile(language: language)
                    } label: {
                        Label(language.nistCSFProfileTitle, systemImage: "hexagon.lefthalf.filled")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportCISAAttestationChecklist(language: language)
                    } label: {
                        Label(language.cisaAttestationChecklistTitle, systemImage: "doc.text.badge.checkmark")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportAPISecurityPlan(language: language)
                    } label: {
                        Label(language == .ko ? "API 보안 계획" : "API Security Plan", systemImage: "point.3.connected.trianglepath.dotted")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportSCVSPlan(language: language)
                    } label: {
                        Label(language == .ko ? "OWASP SCVS 계획" : "OWASP SCVS Plan", systemImage: "shippingbox.and.arrow.backward")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportPrivacyDataMap(language: language)
                    } label: {
                        Label(language == .ko ? "개인정보 데이터 맵" : "Privacy Data Map", systemImage: "person.text.rectangle")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportSecurityRoadmap(language: language)
                    } label: {
                        Label(language == .ko ? "보안 로드맵" : "Security Roadmap", systemImage: "map")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportEvidenceRegister(language: language)
                    } label: {
                        Label(language == .ko ? "보안 증적 보관대장" : "Evidence Register", systemImage: "archivebox")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportSecurityHeadersBaseline(language: language)
                    } label: {
                        Label(language == .ko ? "보안 헤더 기준" : "Security Headers", systemImage: "rectangle.and.text.magnifyingglass")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportContainerHardeningBaseline(language: language)
                    } label: {
                        Label(language == .ko ? "컨테이너 하드닝 기준" : "Container Hardening", systemImage: "shippingbox")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        scanner.exportCloudIACSecurityPlan(language: language)
                    } label: {
                        Label(language == .ko ? "Cloud/IaC 보안 계획" : "Cloud/IaC Security", systemImage: "cloud")
                    }
                    .disabled(scanner.isRunning)
                } label: {
                    Label(language == .ko ? "거버넌스 & 컴플라이언스 문서" : "Governance & Compliance Docs", systemImage: "doc.text")
                }

                Menu {
                    Button {
                        scanner.exportScoreDiff(language: language)
                    } label: {
                        Label(language.scoreDiffTitle, systemImage: "arrow.triangle.2.circlepath")
                    }
                    .disabled(scanner.isRunning)

                    Button {
                        showScoreHistory = true
                    } label: {
                        Label(language.scoreHistoryTitle, systemImage: "chart.line.uptrend.xyaxis")
                    }
                } label: {
                    Label(language == .ko ? "기록 & 추이" : "Reports & Trends", systemImage: "chart.line.uptrend.xyaxis")
                }

                Menu {
                    Button {
                        scanner.saveProjectProfile(language: language)
                    } label: {
                        Label(language.saveProjectProfileTitle, systemImage: "tray.and.arrow.down")
                    }
                    .disabled(!scanner.hasSelection || scanner.isRunning)

                    Button {
                        showProjectProfiles = true
                    } label: {
                        Label(language.projectProfilesTitle, systemImage: "folder.badge.person.crop")
                    }
                } label: {
                    Label(language == .ko ? "작업 효율" : "Productivity", systemImage: "folder.badge.person.crop")
                }

                Divider()

                Button {
                    scanner.exportSecurityToolkit(language: language)
                } label: {
                    Label(language.exportPreventionToolkitTitle, systemImage: "doc.badge.gearshape")
                }
                .disabled(scanner.isRunning)
            } label: {
                Label(language.preventionToolkitTitle, systemImage: "shield.lefthalf.filled")
            }
            .menuStyle(.borderlessButton)

            Button {
                showMainHelp = true
            } label: {
                Label(language.helpTitle, systemImage: "questionmark.circle")
            }
            .buttonStyle(.borderless)

            Button {
                showSettings = true
            } label: {
                Label(language == .ko ? "설정" : "Settings", systemImage: "gearshape")
            }
            .buttonStyle(.borderless)

            Toggle(language.maskReportExportTitle, isOn: $scanner.maskReportExports)
                .toggleStyle(.switch)
                .font(.caption.weight(.semibold))
                .help(language.maskReportExportHelp)

            LanguageToggle(language: $language)
        }
    }

    private func targetPicker(maxHeight: CGFloat) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(language.targetsTitle)
                    .font(.headline)

                Spacer()

                Button(language.chooseFolderTitle) {
                    scanner.chooseFolder(language: language)
                }
                .disabled(scanner.isRunning)

                Button(language.uploadFilesTitle) {
                    scanner.chooseFiles(language: language)
                }
                .disabled(scanner.isRunning)

                Button(language.clearSelectionTitle) {
                    scanner.clearSelection()
                }
                .disabled(!scanner.hasSelection || scanner.isRunning)

                Button(scanner.isRunning ? language.runningTitle : language.runScanTitle) {
                    scanner.runScan()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(!scanner.hasSelection || scanner.isRunning)

                Button(scanner.isRunning ? language.runningTitle : language.screenQualityRunTitle) {
                    scanner.runScreenQualityScan(language: language)
                }
                .buttonStyle(.bordered)
                .disabled(!scanner.hasSelection || scanner.isRunning)

                Menu {
                    Button {
                        scanner.runOSVLookup(language: language)
                    } label: {
                        Label(language.runOSVLookupTitle, systemImage: "network")
                    }
                    Button {
                        scanner.runHostScan(language: language)
                    } label: {
                        Label(language.runHostScanTitle, systemImage: "lock.laptopcomputer")
                    }
                    Button {
                        scanner.runAITriage(language: language)
                    } label: {
                        Label(language.runAITriageTitle, systemImage: "sparkles")
                    }
                    Button {
                        scanner.runChangedOnlyScan(language: language)
                    } label: {
                        Label(language.runChangedOnlyTitle, systemImage: "arrow.triangle.branch")
                    }
                } label: {
                    Label(language == .ko ? "추가 점검" : "More scans", systemImage: "plus.magnifyingglass")
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .disabled(scanner.isRunning)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    if scanner.selectedTargets.isEmpty {
                        Text(language.noTargetsTitle)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 10)
                            .background(KODATheme.insetBackground.opacity(0.65))
                            .clipShape(RoundedRectangle(cornerRadius: 7))
                    } else {
                        ForEach(scanner.selectedTargets, id: \.path) { target in
                            HStack(spacing: 8) {
                                Image(systemName: target.hasDirectoryPath ? "folder" : "doc")
                                    .foregroundStyle(.secondary)
                                Text(target.path)
                                    .lineLimit(1)
                                    .truncationMode(.middle)

                                Spacer(minLength: 8)

                                Button {
                                    scanner.removeTarget(target)
                                } label: {
                                    Image(systemName: "xmark.circle.fill")
                                        .foregroundStyle(.secondary)
                                }
                                .buttonStyle(.plain)
                                .help(language.removeTargetHelp)
                                .disabled(scanner.isRunning)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(KODATheme.insetBackground.opacity(0.78))
                            .clipShape(RoundedRectangle(cornerRadius: 7))
                        }
                    }
                }
                .padding(8)
            }
            .frame(maxHeight: maxHeight)
            .background(KODATheme.cardBackground)
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    private var statusBar: some View {
        HStack(spacing: 14) {
            Circle()
                .fill(scanner.statusColor)
                .frame(width: 8, height: 8)

            Text(scanner.statusMessage(language: language))
                .foregroundStyle(scanner.statusColor)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)

            if !scanner.detailMessage(language: language).isEmpty {
                Text(scanner.detailMessage(language: language))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .textSelection(.enabled)
            }

            Spacer()
        }
        .font(.callout)
    }

    private func lowerPane(minimumCardWidth: CGFloat) -> some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 12) {
                    Text(language.resultsTitle)
                        .font(.title3.weight(.bold))

                    Spacer()
                }

                statusBar
            }
            .padding(.horizontal, 22)
            .padding(.top, 14)
            .padding(.bottom, 12)

            Divider()

            ScanResultsGroupedView(
                reports: scanner.reportItems,
                standards: SecurityStandardCatalog.all,
                minimumCardWidth: minimumCardWidth,
                language: language
            ) { report in
                activeReport = report
                activeHelpGuide = nil
            } onSelectStandard: { standard in
                activeStandard = standard
                activeHelpGuide = nil
            }
        }
    }

    private func layoutMetrics(for size: CGSize) -> DashboardLayoutMetrics {
        DashboardLayoutMetrics(
            outerPadding: min(22, max(14, size.width * 0.02)),
            verticalSpacing: min(14, max(8, size.height * 0.014)),
            minimumCardWidth: min(340, max(250, size.width * 0.28))
        )
    }

    private func targetListHeight(for size: CGSize, metrics: DashboardLayoutMetrics) -> CGFloat {
        let reservedHeaderAndActions = CGFloat(140)
        return min(140, max(72, size.height - reservedHeaderAndActions - metrics.outerPadding))
    }
}

private struct DashboardSplitView<Top: View, Bottom: View>: View {
    @Binding var topFraction: Double
    let minTopHeight: CGFloat
    let minBottomHeight: CGFloat
    let top: () -> Top
    let bottom: () -> Bottom
    @State private var dragStartFraction: Double?
    @State private var liveTopFraction: Double?

    private let handleHeight = CGFloat(16)

    init(
        topFraction: Binding<Double>,
        minTopHeight: CGFloat = 160,
        minBottomHeight: CGFloat = 260,
        @ViewBuilder top: @escaping () -> Top,
        @ViewBuilder bottom: @escaping () -> Bottom
    ) {
        self._topFraction = topFraction
        self.minTopHeight = minTopHeight
        self.minBottomHeight = minBottomHeight
        self.top = top
        self.bottom = bottom
    }

    var body: some View {
        GeometryReader { proxy in
            let availableHeight = max(1, proxy.size.height - handleHeight)
            let displayedFraction = clamped(liveTopFraction ?? topFraction, availableHeight: availableHeight)
            let topHeight = availableHeight * CGFloat(displayedFraction)
            let bottomHeight = availableHeight - topHeight

            VStack(spacing: 0) {
                top()
                    .frame(height: topHeight)

                splitHandle(availableHeight: availableHeight, displayedFraction: displayedFraction)

                bottom()
                    .frame(height: bottomHeight)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func splitHandle(availableHeight: CGFloat, displayedFraction: Double) -> some View {
        ZStack {
            Rectangle()
                .fill(Color(nsColor: .separatorColor))
                .frame(maxWidth: .infinity, maxHeight: 1)

            Capsule()
                .fill(Color.secondary.opacity(0.65))
                .frame(width: 48, height: 4)
        }
        .frame(height: handleHeight)
        .frame(maxWidth: .infinity)
        .background(Color(nsColor: .windowBackgroundColor).opacity(0.03))
        .contentShape(Rectangle())
        .gesture(
            DragGesture(minimumDistance: 0)
                .onChanged { value in
                    if dragStartFraction == nil {
                        dragStartFraction = displayedFraction
                    }
                    let start = dragStartFraction ?? displayedFraction
                    liveTopFraction = clamped(
                        start + Double(value.translation.height / availableHeight),
                        availableHeight: availableHeight
                    )
                }
                .onEnded { _ in
                    let finalFraction = clamped(liveTopFraction ?? topFraction, availableHeight: availableHeight)
                    topFraction = finalFraction
                    liveTopFraction = nil
                    dragStartFraction = nil
                }
        )
        .accessibilityLabel("점검 결과 조회 위치 조절")
    }

    private func clamped(_ fraction: Double, availableHeight: CGFloat) -> Double {
        let minimumTop = min(minTopHeight, availableHeight * 0.75)
        let minimumBottom = min(minBottomHeight, max(0, availableHeight - minimumTop))
        let lowerBound = min(0.85, max(0.15, Double(minimumTop / availableHeight)))
        let upperBound = max(lowerBound, min(0.85, Double((availableHeight - minimumBottom) / availableHeight)))
        return min(max(fraction, lowerBound), upperBound)
    }
}

private struct DashboardLayoutMetrics {
    let outerPadding: CGFloat
    let verticalSpacing: CGFloat
    let minimumCardWidth: CGFloat
}

private struct MainHelpScreen: View {
    @Binding var language: AppLanguage
    let onBack: () -> Void

    var body: some View {
        GeometryReader { proxy in
            VStack(spacing: 0) {
                KODAScreenTopBar(language: $language, onBack: onBack) {
                    Text(language.mainHelpTitle)
                        .font(.title.weight(.bold))
                        .foregroundStyle(.white)
                        .lineLimit(1)
                } actions: {
                    EmptyView()
                }

                ScrollView {
                    VStack(alignment: .leading, spacing: 24) {
                        HStack(alignment: .top, spacing: 18) {
                            Image(systemName: "questionmark.circle")
                                .font(.system(size: 44, weight: .semibold))
                                .foregroundStyle(.blue)
                                .frame(width: 54, height: 54)

                            VStack(alignment: .leading, spacing: 10) {
                                Text(language.preventionToolkitTitle)
                                    .font(.system(size: 30, weight: .bold))
                                Text(language.mainHelpSubtitle)
                                    .font(.system(size: 20, weight: .regular))
                                    .foregroundStyle(.secondary)
                                    .lineSpacing(4)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }

                        LazyVGrid(columns: [GridItem(.adaptive(minimum: min(520, max(360, proxy.size.width * 0.42))), spacing: 18)], spacing: 18) {
                            HelpSummaryBlock(
                                icon: "1.circle",
                                title: language.firstRunGuideTitle,
                                items: language.firstRunGuideItems
                            )
                            HelpSummaryBlock(
                                icon: "shield.checkered",
                                title: language.preventionKitAboutTitle,
                                items: language.preventionKitAboutItems
                            )
                            ForEach(language.preventionKitGroups) { group in
                                HelpSummaryBlock(
                                    icon: "checklist.checked",
                                    title: group.title,
                                    items: group.items
                                )
                            }
                            HelpSummaryBlock(
                                icon: "list.bullet.rectangle",
                                title: language.preventionKitUsageTitle,
                                items: language.preventionKitUsageItems
                            )
                            HelpSummaryBlock(
                                icon: "square.and.arrow.down",
                                title: language.resultDownloadGuideTitle,
                                items: language.resultDownloadGuideItems
                            )
                            HelpSummaryBlock(
                                icon: "exclamationmark.shield",
                                title: language.safetyGuideTitle,
                                items: language.safetyGuideItems
                            )
                        }
                    }
                    .padding(.horizontal, min(64, max(28, proxy.size.width * 0.05)))
                    .padding(.vertical, 34)
                    .frame(maxWidth: .infinity, alignment: .topLeading)
                }
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

private struct ScreenQualityScreen: View {
    @ObservedObject var scanner: ScannerBridge
    @Binding var language: AppLanguage
    let onBack: () -> Void
    let onSelectReport: (ScanReportItem) -> Void

    var body: some View {
        GeometryReader { proxy in
            VStack(spacing: 0) {
                KODAScreenTopBar(language: $language, onBack: onBack) {
                    Text(language.screenQualityTitle)
                        .font(.title.weight(.bold))
                        .foregroundStyle(.white)
                        .lineLimit(1)
                } actions: {
                    EmptyView()
                }

                VStack(alignment: .leading, spacing: 14) {
                    HStack(alignment: .top, spacing: 16) {
                        Image(systemName: "doc.text.magnifyingglass")
                            .font(.system(size: 38, weight: .semibold))
                            .foregroundStyle(.blue)
                            .frame(width: 48, height: 48)

                        VStack(alignment: .leading, spacing: 8) {
                            Text(language.screenQualityHeadline)
                                .font(.title2.weight(.bold))
                            Text(language.screenQualityDescription)
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .lineSpacing(3)
                                .fixedSize(horizontal: false, vertical: true)
                        }

                        Spacer()
                    }

                    targetControls(maxHeight: min(110, max(66, proxy.size.height * 0.14)))
                    statusRow
                }
                .padding(.horizontal, min(34, max(20, proxy.size.width * 0.035)))
                .padding(.vertical, 18)

                Divider()

                resultSection(width: proxy.size.width)
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private func resultSection(width: CGFloat) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(language.screenQualityResultTitle)
                        .font(.title3.weight(.bold))
                    Text(language.screenQualityResultSubtitle)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }

                if let report = scanner.screenQualityReportItems.first(where: \.isOverall) {
                    Button {
                        onSelectReport(report)
                    } label: {
                        VStack(alignment: .leading, spacing: 12) {
                            HStack(alignment: .top, spacing: 12) {
                                Image(systemName: "doc.text.magnifyingglass")
                                    .font(.system(size: 24, weight: .semibold))
                                    .foregroundStyle(.blue)
                                    .frame(width: 34, height: 34)

                                VStack(alignment: .leading, spacing: 5) {
                                    Text(language.screenQualityTitle)
                                        .font(.headline)
                                        .foregroundStyle(.primary)
                                    Text(report.badge(language: language))
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.blue)
                                }

                                Spacer()
                                Image(systemName: "arrow.up.right.square")
                                    .foregroundStyle(.secondary)
                            }

                            Text(language.screenQualityReportDescription)
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                                .fixedSize(horizontal: false, vertical: true)

                            HStack(spacing: 12) {
                                Label(language.findingCountText(report.findingCount), systemImage: "list.bullet.rectangle")
                                Label(language.riskScoreText(report.riskScore), systemImage: "gauge.with.dots.needle.50percent")
                            }
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        }
                        .padding(16)
                        .frame(maxWidth: min(420, max(280, width * 0.42)), minHeight: 150, alignment: .topLeading)
                        .background(KODATheme.cardBackground)
                        .overlay(alignment: .leading) {
                            Rectangle()
                                .fill(Color.blue)
                                .frame(width: 4)
                        }
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                        .overlay {
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                        }
                    }
                    .buttonStyle(.plain)
                } else {
                    HStack(spacing: 12) {
                        Image(systemName: "play.circle")
                            .font(.title2.weight(.semibold))
                            .foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(language.screenQualityRunTitle)
                                .font(.headline)
                            Text(language.screenQualityEmptyResult)
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(16)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(KODATheme.cardBackground)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .overlay {
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                    }
                }
            }
            .padding(22)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private func targetControls(maxHeight: CGFloat) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Text(language.targetsTitle)
                    .font(.headline)

                Spacer()

                Button(language.chooseFolderTitle) {
                    scanner.chooseFolder(language: language)
                }
                .disabled(scanner.isRunning)

                Button(language.uploadFilesTitle) {
                    scanner.chooseFiles(language: language)
                }
                .disabled(scanner.isRunning)

                Button(language.clearSelectionTitle) {
                    scanner.clearSelection()
                }
                .disabled(!scanner.hasSelection || scanner.isRunning)

                Button(scanner.isRunning ? language.runningTitle : language.screenQualityRunTitle) {
                    scanner.runScreenQualityScan(language: language)
                }
                .buttonStyle(.borderedProminent)
                .disabled(!scanner.hasSelection || scanner.isRunning)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    if scanner.selectedTargets.isEmpty {
                        Text(language.screenQualityNoTargets)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 10)
                            .background(KODATheme.insetBackground.opacity(0.65))
                            .clipShape(RoundedRectangle(cornerRadius: 7))
                    } else {
                        ForEach(scanner.selectedTargets, id: \.path) { target in
                            HStack(spacing: 8) {
                                Image(systemName: target.hasDirectoryPath ? "folder" : "doc")
                                    .foregroundStyle(.secondary)
                                Text(target.path)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                Spacer()
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(KODATheme.insetBackground.opacity(0.78))
                            .clipShape(RoundedRectangle(cornerRadius: 7))
                        }
                    }
                }
                .padding(8)
            }
            .frame(maxHeight: maxHeight)
            .background(KODATheme.cardBackground)
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    private var statusRow: some View {
        HStack(spacing: 12) {
            Circle()
                .fill(scanner.statusColor)
                .frame(width: 8, height: 8)

            Text(scanner.statusMessage(language: language))
                .foregroundStyle(scanner.statusColor)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)

            if !scanner.detailMessage(language: language).isEmpty {
                Text(scanner.detailMessage(language: language))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .textSelection(.enabled)
            }

            Spacer()
        }
        .font(.callout)
    }
}

private struct HelpSummaryBlock: View {
    let icon: String
    let title: String
    let items: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label(title, systemImage: icon)
                .font(.title2.weight(.bold))

            VStack(alignment: .leading, spacing: 12) {
                ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                    HStack(alignment: .top, spacing: 12) {
                        Circle()
                            .fill(Color.secondary.opacity(0.75))
                            .frame(width: 7, height: 7)
                            .padding(.top, 7)

                        Text(item)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .lineSpacing(3)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(KODATheme.insetBackground.opacity(0.72))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

private enum FixPlanTier: Int, CaseIterable {
    case essential
    case recommended
    case compliance

    func title(_ language: AppLanguage) -> String {
        switch (self, language) {
        case (.essential, .ko): return "필수 기본"
        case (.essential, .en): return "Essentials"
        case (.recommended, .ko): return "권장"
        case (.recommended, .en): return "Recommended"
        case (.compliance, .ko): return "컴플라이언스 · 선택"
        case (.compliance, .en): return "Compliance · Optional"
        }
    }

    func subtitle(_ language: AppLanguage) -> String {
        switch (self, language) {
        case (.essential, .ko): return "거의 모든 프로젝트가 먼저 갖춰야 하는 핵심 가드레일입니다."
        case (.essential, .en): return "Core guardrails almost every project should have first."
        case (.recommended, .ko): return "성숙한 보안 운영을 위해 추가하면 좋은 항목입니다."
        case (.recommended, .en): return "Worth adding as your security practice matures."
        case (.compliance, .ko): return "특정 규제·프레임워크가 필요할 때 선택적으로 추가하세요."
        case (.compliance, .en): return "Add only when a specific framework or regulation applies."
        }
    }

    /// Classify a plan by its target file path into a usability tier.
    static func tier(for plan: SecurityFixPlan) -> FixPlanTier {
        let essentials: Set<String> = [
            "SECURITY.md",
            ".gitignore",
            ".dockerignore",
            ".env.example",
            ".github/dependabot.yml",
            ".github/workflows/koda-security.yml",
            "docs/security/PRE_COMMIT.md",
        ]
        let compliance: Set<String> = [
            "docs/security/NIST_SSDF_WORKFLOW.md",
            "docs/security/NIST_CSF_2_PROFILE.md",
            "docs/security/CISA_SECURE_SOFTWARE_ATTESTATION.md",
            "docs/security/SCVS_PLAN.md",
            "docs/security/AI_LLM_SECURITY.md",
            "docs/security/MOBILE_SECURITY.md",
            "docs/security/PRIVACY_DATA_MAP.md",
            "docs/security/EVIDENCE_REGISTER.md",
            "docs/security/CLOUD_IAC_SECURITY.md",
        ]
        if essentials.contains(plan.relativePath) { return .essential }
        if compliance.contains(plan.relativePath) { return .compliance }
        return .recommended
    }
}

private struct SecurityFixWizardSheet: View {
    let plans: [SecurityFixPlan]
    let language: AppLanguage
    let onApply: ([SecurityFixPlan]) -> Void
    let onCancel: () -> Void
    @State private var selectedIDs: Set<String>
    @State private var complianceExpanded = false

    init(
        plans: [SecurityFixPlan],
        language: AppLanguage,
        onApply: @escaping ([SecurityFixPlan]) -> Void,
        onCancel: @escaping () -> Void
    ) {
        self.plans = plans
        self.language = language
        self.onApply = onApply
        self.onCancel = onCancel
        // Default to essentials only so the wizard is actionable, not overwhelming.
        let essentialIDs = plans.filter { FixPlanTier.tier(for: $0) == .essential }.map(\.id)
        self._selectedIDs = State(initialValue: Set(essentialIDs))
    }

    private var selectedPlans: [SecurityFixPlan] {
        plans.filter { selectedIDs.contains($0.id) }
    }

    private func plans(in tier: FixPlanTier) -> [SecurityFixPlan] {
        plans.filter { FixPlanTier.tier(for: $0) == tier }
    }

    private func selectTiers(_ tiers: Set<FixPlanTier>) {
        selectedIDs = Set(plans.filter { tiers.contains(FixPlanTier.tier(for: $0)) }.map(\.id))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "wand.and.sparkles")
                    .font(.title2.weight(.bold))
                    .foregroundStyle(.blue)
                    .frame(width: 34, height: 34)

                VStack(alignment: .leading, spacing: 6) {
                    Text(language.autoFixWizardTitle)
                        .font(.title2.weight(.bold))
                    Text(language.autoFixWizardSubtitle)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }

                Spacer()
            }
            .padding(20)

            Divider()

            if plans.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text(language.noAutoFixesTitle)
                        .font(.headline)
                    Text(language.noAutoFixesSubtitle)
                        .foregroundStyle(.secondary)
                }
                .padding(20)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            } else {
                quickSelectBar
                Divider()
                ScrollView {
                    VStack(alignment: .leading, spacing: 18) {
                        tierSection(.essential, collapsible: false)
                        tierSection(.recommended, collapsible: false)
                        tierSection(.compliance, collapsible: true)
                    }
                    .padding(20)
                }
            }

            Divider()

            HStack {
                Text(language.selectedFixCountText(selectedPlans.count, total: plans.count))
                    .font(.callout)
                    .foregroundStyle(.secondary)

                Spacer()

                Button(language.cancelTitle) {
                    onCancel()
                }

                Button(language.applySelectedFixesTitle) {
                    onApply(selectedPlans)
                }
                .buttonStyle(.borderedProminent)
                .disabled(selectedPlans.isEmpty)
            }
            .padding(16)
        }
        .frame(width: 720, height: 640)
    }

    private var quickSelectBar: some View {
        HStack(spacing: 10) {
            Text(language == .ko ? "빠른 선택:" : "Quick select:")
                .font(.callout.weight(.semibold))
                .foregroundStyle(.secondary)
            Button(language == .ko ? "필수만" : "Essentials only") { selectTiers([.essential]) }
            Button(language == .ko ? "권장까지" : "Up to recommended") { selectTiers([.essential, .recommended]) }
            Button(language == .ko ? "전체" : "All") { selectTiers(Set(FixPlanTier.allCases)) }
            Button(language == .ko ? "해제" : "None") { selectedIDs = [] }
            Spacer()
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
        .padding(.horizontal, 20)
        .padding(.vertical, 10)
    }

    @ViewBuilder
    private func tierSection(_ tier: FixPlanTier, collapsible: Bool) -> some View {
        let tierPlans = plans(in: tier)
        if !tierPlans.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                if collapsible {
                    DisclosureGroup(isExpanded: $complianceExpanded) {
                        VStack(alignment: .leading, spacing: 10) {
                            ForEach(tierPlans) { planRow($0) }
                        }
                        .padding(.top, 8)
                    } label: {
                        sectionHeader(tier, count: tierPlans.count)
                    }
                } else {
                    sectionHeader(tier, count: tierPlans.count)
                    ForEach(tierPlans) { planRow($0) }
                }
            }
        }
    }

    private func sectionHeader(_ tier: FixPlanTier, count: Int) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 8) {
                Text(tier.title(language))
                    .font(.headline)
                Text("\(selectedCount(in: tier))/\(count)")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            Text(tier.subtitle(language))
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func selectedCount(in tier: FixPlanTier) -> Int {
        plans(in: tier).filter { selectedIDs.contains($0.id) }.count
    }

    private func planRow(_ plan: SecurityFixPlan) -> some View {
        Toggle(isOn: Binding(
            get: { selectedIDs.contains(plan.id) },
            set: { isSelected in
                if isSelected {
                    selectedIDs.insert(plan.id)
                } else {
                    selectedIDs.remove(plan.id)
                }
            }
        )) {
            VStack(alignment: .leading, spacing: 4) {
                Text(plan.title(language: language))
                    .font(.headline)
                Text(plan.detail(language: language))
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .toggleStyle(.checkbox)
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(KODATheme.cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

private struct ProjectProfilesSheet: View {
    let profiles: [ProjectProfile]
    let language: AppLanguage
    let onLoad: (ProjectProfile) -> Void
    let onDelete: (ProjectProfile) -> Void
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "folder.badge.person.crop")
                    .font(.title2.weight(.bold))
                    .foregroundStyle(.blue)
                    .frame(width: 34, height: 34)

                VStack(alignment: .leading, spacing: 6) {
                    Text(language.projectProfilesTitle)
                        .font(.title2.weight(.bold))
                    Text(subtitle)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }

                Spacer()
            }
            .padding(20)

            Divider()

            if profiles.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text(emptyTitle)
                        .font(.headline)
                    Text(emptySubtitle)
                        .foregroundStyle(.secondary)
                }
                .padding(20)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(profiles) { profile in
                            profileRow(profile)
                        }
                    }
                    .padding(20)
                }
            }

            Divider()

            HStack {
                Spacer()
                Button(language.closeTitle) {
                    onClose()
                }
                .buttonStyle(.borderedProminent)
            }
            .padding(16)
        }
        .frame(width: 720, height: 560)
    }

    private func profileRow(_ profile: ProjectProfile) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 12) {
                VStack(alignment: .leading, spacing: 5) {
                    Text(profile.name)
                        .font(.headline)
                    Text("\(profile.formattedDate) · \(targetCountText(profile.targets.count))")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Button(loadTitle) {
                    onLoad(profile)
                }
                .buttonStyle(.borderedProminent)

                Button(role: .destructive) {
                    onDelete(profile)
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                .help(deleteTitle)
            }

            VStack(alignment: .leading, spacing: 5) {
                ForEach(profile.targetPaths.prefix(4), id: \.self) { path in
                    Text(path)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                if profile.targetPaths.count > 4 {
                    Text(moreTargetsText(profile.targetPaths.count - 4))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(KODATheme.cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }

    private var subtitle: String {
        switch language {
        case .ko: return "자주 점검하는 폴더와 파일 묶음을 저장해 다음 실행 때 빠르게 불러옵니다."
        case .en: return "Save frequently scanned folders and files, then reload them quickly on the next run."
        }
    }

    private var emptyTitle: String {
        switch language {
        case .ko: return "저장된 프로파일이 없습니다."
        case .en: return "No saved profiles."
        }
    }

    private var emptySubtitle: String {
        switch language {
        case .ko: return "점검 대상을 선택한 뒤 예방 키트 메뉴에서 현재 대상을 프로파일로 저장하세요."
        case .en: return "Choose scan targets, then use the Prevention Kit menu to save the current targets as a profile."
        }
    }

    private var loadTitle: String {
        switch language {
        case .ko: return "불러오기"
        case .en: return "Load"
        }
    }

    private var deleteTitle: String {
        switch language {
        case .ko: return "프로파일 삭제"
        case .en: return "Delete profile"
        }
    }

    private func targetCountText(_ count: Int) -> String {
        switch language {
        case .ko: return "대상 \(count)개"
        case .en: return "\(count) target\(count == 1 ? "" : "s")"
        }
    }

    private func moreTargetsText(_ count: Int) -> String {
        switch language {
        case .ko: return "외 \(count)개 경로"
        case .en: return "\(count) more path\(count == 1 ? "" : "s")"
        }
    }
}

private struct ThreatModelWizardSheet: View {
    let language: AppLanguage
    let onSave: (String) -> Void
    let onClose: () -> Void
    @State private var hasAuth = true
    @State private var hasPII = true
    @State private var hasPayment = false
    @State private var hasAdmin = true
    @State private var hasPublicAPI = true
    @State private var hasFileUpload = false
    @State private var hasAILLM = false
    @State private var hasMobile = false
    @State private var hasCloud = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "person.text.rectangle")
                    .font(.title2.weight(.bold))
                    .foregroundStyle(.blue)
                    .frame(width: 34, height: 34)

                VStack(alignment: .leading, spacing: 6) {
                    Text(language.threatModelWizardTitle)
                        .font(.title2.weight(.bold))
                    Text(language.threatModelWizardSubtitle)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(20)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    Toggle(language.threatModelAuthTitle, isOn: $hasAuth)
                    Toggle(language.threatModelPIITitle, isOn: $hasPII)
                    Toggle(language.threatModelPaymentTitle, isOn: $hasPayment)
                    Toggle(language.threatModelAdminTitle, isOn: $hasAdmin)
                    Toggle(language.threatModelPublicAPITitle, isOn: $hasPublicAPI)
                    Toggle(language.threatModelFileUploadTitle, isOn: $hasFileUpload)
                    Toggle(language.threatModelAILLMTitle, isOn: $hasAILLM)
                    Toggle(language.threatModelMobileTitle, isOn: $hasMobile)
                    Toggle(language.threatModelCloudTitle, isOn: $hasCloud)

                    VStack(alignment: .leading, spacing: 8) {
                        Text(language.recommendedControlsTitle)
                            .font(.headline)
                        ForEach(recommendations, id: \.self) { item in
                            Label(item, systemImage: "checkmark.circle")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(KODATheme.cardBackground)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }
                .toggleStyle(.checkbox)
                .padding(20)
            }

            Divider()

            HStack {
                Spacer()
                Button(language.cancelTitle) { onClose() }
                Button(language.saveThreatModelTitle) { onSave(markdown) }
                    .buttonStyle(.borderedProminent)
            }
            .padding(16)
        }
        .frame(width: 720, height: 620)
    }

    private var recommendations: [String] {
        var items: [String] = [
            language.recommendThreatModelBase,
            language.recommendSecurityPolicy,
            language.recommendSASTDependency,
        ]
        if hasAuth || hasAdmin { items.append(language.recommendAuthSession) }
        if hasPII || hasPayment { items.append(language.recommendSecretRotation) }
        if hasPublicAPI || hasFileUpload { items.append(language.recommendDASTASVS) }
        if hasAILLM { items.append(language.recommendLLMPlan) }
        if hasMobile { items.append(language.recommendMASVSPlan) }
        if hasCloud { items.append(language.recommendIaCContainer) }
        return items
    }

    private var markdown: String {
        let selected = [
            (hasAuth, language.threatModelAuthTitle),
            (hasPII, language.threatModelPIITitle),
            (hasPayment, language.threatModelPaymentTitle),
            (hasAdmin, language.threatModelAdminTitle),
            (hasPublicAPI, language.threatModelPublicAPITitle),
            (hasFileUpload, language.threatModelFileUploadTitle),
            (hasAILLM, language.threatModelAILLMTitle),
            (hasMobile, language.threatModelMobileTitle),
            (hasCloud, language.threatModelCloudTitle),
        ].filter { $0.0 }.map { $0.1 }
        let title = language == .ko ? "KODA 위협 모델 초안" : "KODA Threat Model Draft"
        let selectedTitle = language == .ko ? "선택된 특성" : "Selected Characteristics"
        let recommendationsTitle = language == .ko ? "권장 통제" : "Recommended Controls"
        return """
        # \(title)

        ## \(selectedTitle)

        \(selected.map { "- [ ] \($0)" }.joined(separator: "\n"))

        ## \(recommendationsTitle)

        \(recommendations.map { "- [ ] \($0)" }.joined(separator: "\n"))

        ## Assets

        | Asset | Sensitivity | Owner | Notes |
        | --- | --- | --- | --- |
        | Customer data | high | TBD | TBD |
        | Secrets and tokens | critical | TBD | TBD |
        | Build and release artifacts | high | TBD | TBD |

        ## Abuse Cases

        - [ ] Unauthorized access to sensitive functions
        - [ ] Secret exposure through source, logs, prompts, or artifacts
        - [ ] Supply-chain compromise through dependency or CI workflow
        - [ ] File upload/download or path traversal abuse
        - [ ] Runtime-only risks requiring DAST or penetration testing
        """
    }
}

private struct ComplianceDashboardSheet: View {
    let standards: [AppSecurityStandard]
    let reports: [ScanReportItem]
    let language: AppLanguage
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "checkmark.rectangle.stack")
                    .font(.title2.weight(.bold))
                    .foregroundStyle(.green)
                    .frame(width: 34, height: 34)
                VStack(alignment: .leading, spacing: 6) {
                    Text(language.complianceDashboardTitle)
                        .font(.title2.weight(.bold))
                    Text(language.complianceDashboardSubtitle)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(20)

            Divider()

            ScrollView {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 300), spacing: 12)], spacing: 12) {
                    ForEach(standards) { standard in
                        complianceCard(standard)
                    }
                }
                .padding(20)
            }

            Divider()
            HStack {
                Spacer()
                Button(language.closeTitle) { onClose() }
                    .buttonStyle(.borderedProminent)
            }
            .padding(16)
        }
        .frame(width: 880, height: 640)
    }

    private func complianceCard(_ standard: AppSecurityStandard) -> some View {
        let report = reports.first { $0.id == standard.id }
        let state = complianceState(for: standard, report: report)
        return VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: standard.icon)
                    .foregroundStyle(standard.accent.color)
                    .frame(width: 24)
                VStack(alignment: .leading, spacing: 3) {
                    Text(standard.title(language: language))
                        .font(.headline)
                    Text(standard.badge(language: language))
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(standard.accent.color)
                }
                Spacer()
                Text(state.label)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(state.color)
            }
            Text(reportSummary(report))
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(KODATheme.cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }

    private func complianceState(for standard: AppSecurityStandard, report: ScanReportItem?) -> (label: String, color: Color) {
        guard let report else {
            return (language == .ko ? "점검 전" : "Not scanned", .secondary)
        }
        if report.findingCount > 0 {
            return (language == .ko ? "조치 필요" : "Needs action", .orange)
        }
        if standard.coverage(language: language).localizedCaseInsensitiveContains(language.evidenceRequiredBadge) || standard.coverage(language: language).localizedCaseInsensitiveContains(language.externalIntegrationBadge) {
            return (language == .ko ? "증적 보완" : "Evidence needed", .blue)
        }
        return (language == .ko ? "자동 확인" : "Auto verified", .green)
    }

    private func reportSummary(_ report: ScanReportItem?) -> String {
        guard let report else {
            return language == .ko ? "스캔 실행 후 기준별 발견 항목과 위험점수를 표시합니다." : "Run a scan to show findings and risk score for this standard."
        }
        switch language {
        case .ko:
            return "발견 \(report.findingCount)건 · 위험점수 \(report.riskScore)점"
        case .en:
            return "\(report.findingCount) findings · \(report.riskScore) risk points"
        }
    }
}

private struct SecurityScoreHistorySheet: View {
    let snapshots: [SecurityScoreSnapshot]
    let language: AppLanguage
    let onClose: () -> Void
    let onClear: () -> Void

    private var comparison: (current: SecurityScoreSnapshot, baseline: SecurityScoreSnapshot)? {
        guard snapshots.count >= 2 else { return nil }
        return (snapshots[0], snapshots[1])
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "chart.line.uptrend.xyaxis")
                    .font(.title2.weight(.bold))
                    .foregroundStyle(.green)
                    .frame(width: 34, height: 34)

                VStack(alignment: .leading, spacing: 6) {
                    Text(language.scoreHistoryTitle)
                        .font(.title2.weight(.bold))
                    Text(language.scoreHistorySubtitle)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }

                Spacer()
            }
            .padding(20)

            Divider()

            if snapshots.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text(language.noScoreHistoryTitle)
                        .font(.headline)
                    Text(language.noScoreHistorySubtitle)
                        .foregroundStyle(.secondary)
                }
                .padding(20)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        if let comparison {
                            ScoreHistoryComparisonCard(
                                current: comparison.current,
                                baseline: comparison.baseline,
                                language: language
                            )
                        }

                        ForEach(snapshots.prefix(30)) { snapshot in
                            HStack(alignment: .top, spacing: 12) {
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(snapshot.formattedDate)
                                        .font(.headline)
                                    Text(snapshot.targets.joined(separator: ", "))
                                        .font(.callout)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(2)
                                }

                                Spacer()

                                VStack(alignment: .trailing, spacing: 5) {
                                    Text(language.riskScoreText(snapshot.riskScore))
                                        .font(.headline)
                                    Text(language.findingCountText(snapshot.findingCount))
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(KODATheme.cardBackground)
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                        }
                    }
                    .padding(20)
                }
            }

            Divider()

            HStack {
                Button(language.clearHistoryTitle) {
                    onClear()
                }
                .disabled(snapshots.isEmpty)

                Spacer()

                Button(language.closeTitle) {
                    onClose()
                }
                .buttonStyle(.borderedProminent)
            }
            .padding(16)
        }
        .frame(width: 620, height: 520)
    }
}

private struct ScoreHistoryComparisonCard: View {
    let current: SecurityScoreSnapshot
    let baseline: SecurityScoreSnapshot
    let language: AppLanguage

    private let severities = ["critical", "high", "medium", "low", "info"]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text(title)
                    .font(.headline)
                Spacer()
                Text(statusText(for: totalRiskDelta))
                    .font(.caption.weight(.bold))
                    .foregroundStyle(deltaColor(totalRiskDelta))
            }

            HStack(spacing: 10) {
                deltaTile(title: scoreTitle, delta: totalRiskDelta, suffix: language == .ko ? "점" : " pts")
                deltaTile(title: findingTitle, delta: findingDelta, suffix: language == .ko ? "건" : "")
            }

            VStack(alignment: .leading, spacing: 7) {
                Text(severityTitle)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.secondary)

                ForEach(severities, id: \.self) { severity in
                    let delta = severityDelta(severity)
                    HStack(spacing: 8) {
                        Text(language.severityLabel(severity))
                            .font(.caption)
                            .frame(width: 64, alignment: .leading)
                        Capsule()
                            .fill(deltaColor(delta).opacity(delta == 0 ? 0.18 : 0.75))
                            .frame(width: barWidth(for: delta), height: 7)
                        Spacer(minLength: 6)
                        Text(signed(delta))
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(deltaColor(delta))
                            .frame(width: 42, alignment: .trailing)
                    }
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(KODATheme.insetBackground.opacity(0.72))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }

    private var totalRiskDelta: Int {
        current.riskScore - baseline.riskScore
    }

    private var findingDelta: Int {
        current.findingCount - baseline.findingCount
    }

    private var title: String {
        switch language {
        case .ko: return "최근 점검과 이전 점검 비교"
        case .en: return "Latest Scan vs Previous Scan"
        }
    }

    private var scoreTitle: String {
        switch language {
        case .ko: return "위험점수 변화"
        case .en: return "Risk delta"
        }
    }

    private var findingTitle: String {
        switch language {
        case .ko: return "발견 항목 변화"
        case .en: return "Finding delta"
        }
    }

    private var severityTitle: String {
        switch language {
        case .ko: return "위험군별 변화"
        case .en: return "Severity deltas"
        }
    }

    private func deltaTile(title: String, delta: Int, suffix: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("\(signed(delta))\(suffix)")
                .font(.title3.weight(.bold).monospacedDigit())
                .foregroundStyle(deltaColor(delta))
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(KODATheme.cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private func severityDelta(_ severity: String) -> Int {
        (current.severityCounts[severity] ?? 0) - (baseline.severityCounts[severity] ?? 0)
    }

    private func signed(_ value: Int) -> String {
        value > 0 ? "+\(value)" : "\(value)"
    }

    private func deltaColor(_ value: Int) -> Color {
        if value < 0 { return .green }
        if value > 0 { return .red }
        return .secondary
    }

    private func statusText(for delta: Int) -> String {
        if delta < 0 {
            return language == .ko ? "개선" : "Improved"
        }
        if delta > 0 {
            return language == .ko ? "악화" : "Worsened"
        }
        return language == .ko ? "변화 없음" : "No change"
    }

    private func barWidth(for delta: Int) -> CGFloat {
        max(18, min(130, CGFloat(abs(delta)) * 14 + 18))
    }
}

private struct ScanReportDetailScreen: View {
    let report: ScanReportItem
    @Binding var language: AppLanguage
    @Binding var maskReportExports: Bool
    let onBack: () -> Void
    let onHelp: () -> Void
    let onRemediation: () -> Void
    let onExport: (ReportExportFormat) -> Void
    @Environment(\.colorScheme) private var colorScheme
    @State private var showAIReport = false

    var body: some View {
        VStack(spacing: 0) {
            detailTopBar

            ReportWebView(url: report.htmlURL(language: language), colorScheme: colorScheme)
                .id(report.htmlURL(language: language))
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .sheet(isPresented: $showAIReport) {
            LocalAIReportView(report: report, language: language)
        }
    }

    private var detailTopBar: some View {
        KODAScreenTopBar(language: $language, onBack: onBack) {
            VStack(alignment: .leading, spacing: 4) {
                Text(report.title(language: language))
                    .font(.title2.weight(.bold))
                    .foregroundStyle(.white)
                    .lineLimit(1)
                Text("\(language.findingsTitle): \(report.findingCount) | \(language.riskScoreTitle): \(report.riskScore)")
                    .font(.caption)
                    .foregroundStyle(.white.opacity(0.75))
            }
        } actions: {
            Button {
                showAIReport = true
            } label: {
                Label(language == .ko ? "AI 보조 보고서" : "AI report", systemImage: "sparkles")
            }
            .buttonStyle(.borderless)
            .foregroundStyle(.white)

            Menu {
                Toggle(language.maskReportExportTitle, isOn: $maskReportExports)
                Divider()
                ForEach(ReportExportFormat.allCases, id: \.self) { format in
                    Button(format.title(language: language)) {
                        onExport(format)
                    }
                }
            } label: {
                Label(language.exportTitle, systemImage: "square.and.arrow.down")
                    .font(.callout.weight(.bold))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                    .foregroundStyle(.white)
                    .background(Color(red: 0.04, green: 0.47, blue: 0.72))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .overlay {
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color.white.opacity(0.28), lineWidth: 1)
                    }
            }
            .menuStyle(.borderlessButton)

            Button {
                onRemediation()
            } label: {
                Label(language.remediationGuideTitle, systemImage: "wrench.and.screwdriver")
            }
            .buttonStyle(.borderless)
            .foregroundStyle(.white)

            Button {
                onHelp()
            } label: {
                Label(language.helpTitle, systemImage: "questionmark.circle")
            }
            .buttonStyle(.borderless)
            .foregroundStyle(.white)
        }
    }
}

private struct RemediationGuideScreen: View {
    let report: ScanReportItem
    let targets: [URL]
    @Binding var language: AppLanguage
    let onBack: () -> Void

    private var prioritizedFindings: [NativeFinding] {
        report.findings.sorted { left, right in
            let leftScore = NativeScanResult.score(for: left.severity)
            let rightScore = NativeScanResult.score(for: right.severity)
            if leftScore != rightScore {
                return leftScore > rightScore
            }
            return left.path < right.path
        }
    }

    var body: some View {
        GeometryReader { proxy in
            VStack(spacing: 0) {
                KODAScreenTopBar(language: $language, onBack: onBack) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(language.remediationGuideTitle)
                            .font(.title2.weight(.bold))
                            .foregroundStyle(.white)
                            .lineLimit(1)
                        Text(report.title(language: language))
                            .font(.caption)
                            .foregroundStyle(.white.opacity(0.75))
                            .lineLimit(1)
                    }
                } actions: {
                    EmptyView()
                }

                ScrollView {
                    VStack(alignment: .leading, spacing: 18) {
                        overviewGrid(width: proxy.size.width)

                        section(title: priorityTitle) {
                            VStack(alignment: .leading, spacing: 10) {
                                ForEach(immediateActions, id: \.self) { item in
                                    HStack(alignment: .top, spacing: 9) {
                                        Image(systemName: "checkmark.circle.fill")
                                            .foregroundStyle(.green)
                                            .padding(.top, 2)
                                        Text(item)
                                            .font(.callout)
                                            .foregroundStyle(.secondary)
                                            .fixedSize(horizontal: false, vertical: true)
                                    }
                                }
                            }
                            .padding(16)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(KODATheme.cardBackground)
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                            .overlay {
                                RoundedRectangle(cornerRadius: 8)
                                    .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                            }
                        }

                        section(title: findingGuideTitle) {
                            if prioritizedFindings.isEmpty {
                                VStack(alignment: .leading, spacing: 8) {
                                    Text(noFindingsTitle)
                                        .font(.headline)
                                    Text(noFindingsSubtitle)
                                        .foregroundStyle(.secondary)
                                }
                                .padding(16)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(KODATheme.cardBackground)
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                            } else {
                                LazyVGrid(columns: columns(width: proxy.size.width), spacing: 12) {
                                    ForEach(Array(prioritizedFindings.prefix(18).enumerated()), id: \.offset) { _, finding in
                                        RemediationFindingCard(finding: finding, targets: targets, language: language)
                                    }
                                }
                            }
                        }
                    }
                    .padding(.horizontal, min(46, max(22, proxy.size.width * 0.04)))
                    .padding(.vertical, 24)
                }
            }
            .background(Color(nsColor: .windowBackgroundColor))
        }
    }

    private func overviewGrid(width: CGFloat) -> some View {
        LazyVGrid(columns: columns(width: width), spacing: 12) {
            remediationSummaryTile(title: language.findingsTitle, value: "\(report.findingCount)")
            remediationSummaryTile(title: language.riskScoreTitle, value: "\(report.riskScore)")
            remediationSummaryTile(title: standardTitle, value: report.badge(language: language))
        }
    }

    private func remediationSummaryTile(title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.caption.weight(.bold))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.title3.weight(.bold))
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(14)
        .frame(maxWidth: .infinity, minHeight: 86, alignment: .leading)
        .background(KODATheme.cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }

    private func section<Content: View>(title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.title2.weight(.bold))
            content()
        }
    }

    private func columns(width: CGFloat) -> [GridItem] {
        [GridItem(.adaptive(minimum: width > 1100 ? 340 : 280), spacing: 12)]
    }

    private var standardTitle: String {
        switch language {
        case .ko: return "기준"
        case .en: return "Standard"
        }
    }

    private var priorityTitle: String {
        switch language {
        case .ko: return "권장 조치 순서"
        case .en: return "Recommended Order"
        }
    }

    private var findingGuideTitle: String {
        switch language {
        case .ko: return "발견 항목별 조치"
        case .en: return "Finding-Level Remediation"
        }
    }

    private var noFindingsTitle: String {
        switch language {
        case .ko: return "현재 활성화된 점검 범위에서 탐지된 항목이 없습니다."
        case .en: return "No findings were detected within the active scan scope."
        }
    }

    private var noFindingsSubtitle: String {
        switch language {
        case .ko: return "이 결과는 전체 보안성을 보장하지 않습니다. 인증 상태, 활성화된 옵션, 접근 가능한 화면과 API에 따라 점검 범위가 달라집니다."
        case .en: return "This does not guarantee that the target is free of vulnerabilities; coverage depends on authentication, enabled options, and reachable pages and APIs."
        }
    }

    private var immediateActions: [String] {
        switch language {
        case .ko:
            return [
                "치명/높음 항목과 비밀값 노출은 먼저 처리하고, 실제 키라면 즉시 폐기 또는 회전합니다.",
                "취약 의존성은 고정 버전과 lockfile을 확인한 뒤 업그레이드, 패치, 대체 또는 보완 통제를 선택합니다.",
                "디버그, CORS, 쿠키, 디렉터리 리스팅, WebDAV 같은 설정 문제는 운영 기본값을 보수적으로 조정합니다.",
                "조치 후 같은 프로파일로 다시 점검하고 보안 점수 추적에서 위험점수와 위험군별 변화가 낮아졌는지 확인합니다.",
            ]
        case .en:
            return [
                "Start with critical/high findings and exposed secrets. Revoke or rotate any real key immediately.",
                "For vulnerable dependencies, verify pinned versions and lockfiles, then upgrade, patch, replace, or document compensating controls.",
                "For configuration issues such as debug mode, CORS, cookies, directory listing, and WebDAV, move production defaults to conservative settings.",
                "After remediation, rerun the same profile and confirm risk score and severity deltas went down in Security Score History.",
            ]
        }
    }
}

private struct RemediationFindingCard: View {
    @State private var showLocalAI = false
    let finding: NativeFinding
    let targets: [URL]
    let language: AppLanguage

    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack(alignment: .top, spacing: 8) {
                Text(finding.title)
                    .font(.headline)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 8)
                Text(language.severityLabel(finding.severity))
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.white)
                    .padding(.horizontal, 9)
                    .padding(.vertical, 4)
                    .background(severityColor)
                    .clipShape(Capsule())
            }

            infoLine(title: ruleTitle, value: finding.ruleID)
            infoLine(title: categoryTitle, value: categoryLabel)
            infoLine(title: locationTitle, value: locationText)

            VStack(alignment: .leading, spacing: 5) {
                Text(recommendationTitle)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.secondary)
                Text(finding.recommendation.isEmpty ? fallbackRecommendation : finding.recommendation)
                    .font(.callout)
                    .foregroundStyle(.primary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Button(language == .ko ? "로컬 AI 설명" : "Local AI explanation") { showLocalAI = true }
                .sheet(isPresented: $showLocalAI) {
                    VStack {
                        ScrollView {
                            LocalAIView(language: language, finding: finding, targets: targets)
                        }
                        .frame(maxHeight: 720)
                        Button(language == .ko ? "닫기" : "Close") { showLocalAI = false }.padding(.bottom)
                    }.frame(width: 640)
                }

            if let pane = settingsPane {
                Button {
                    openSettings(pane)
                } label: {
                    Label(language == .ko ? "해당 설정 열기" : "Open This Setting", systemImage: "gearshape")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(KODATheme.cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }

    /// Maps a host posture finding to the System Settings pane that fixes it.
    /// Returns nil for non-host findings (no one-click target).
    private var settingsPane: String? {
        guard finding.ruleID.hasPrefix("host.macos.") else { return nil }
        if finding.ruleID.contains("filevault") || finding.ruleID.contains("gatekeeper") {
            return "com.apple.settings.PrivacySecurity.extension"
        }
        if finding.ruleID.contains("firewall") {
            return "com.apple.Network-Settings.extension"
        }
        if finding.ruleID.contains("auto-security-updates") {
            return "com.apple.Software-Update-Settings.extension"
        }
        if finding.ruleID.contains("auto-login") {
            return "com.apple.Users-Groups-Settings.extension"
        }
        if finding.ruleID.contains("screen-lock") {
            return "com.apple.Lock-Screen-Settings.extension"
        }
        if finding.ruleID.contains("guest-account") {
            return "com.apple.Users-Groups-Settings.extension"
        }
        return nil
    }

    private func openSettings(_ pane: String) {
        if let url = URL(string: "x-apple.systempreferences:\(pane)"),
           NSWorkspace.shared.open(url) {
            return
        }
        // Fallback: open System Settings app directly if the deep link is unavailable.
        if let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.systempreferences") {
            NSWorkspace.shared.openApplication(at: app, configuration: NSWorkspace.OpenConfiguration())
        }
    }

    private func infoLine(title: String, value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 7) {
            Text(title)
                .font(.caption.weight(.bold))
                .foregroundStyle(.secondary)
                .frame(width: 72, alignment: .leading)
            Text(value)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
    }

    private var severityColor: Color {
        switch finding.severity {
        case "critical": return .purple
        case "high": return .red
        case "medium": return .orange
        case "low": return .blue
        default: return .gray
        }
    }

    private var locationText: String {
        if let line = finding.line {
            return "\(finding.path):\(line)"
        }
        return finding.path
    }

    private var categoryLabel: String {
        switch (language, finding.category) {
        case (.ko, "secrets"): return "비밀값"
        case (.ko, "dependencies"): return "의존성"
        case (.ko, "configuration"): return "설정"
        case (.ko, "code"): return "코드"
        case (.ko, "prevention"): return "예방"
        case (.ko, "screen_quality"): return "화면 품질"
        case (.en, "secrets"): return "Secrets"
        case (.en, "dependencies"): return "Dependencies"
        case (.en, "configuration"): return "Configuration"
        case (.en, "code"): return "Code"
        case (.en, "prevention"): return "Prevention"
        case (.en, "screen_quality"): return "Screen Quality"
        default: return finding.category
        }
    }

    private var ruleTitle: String {
        language == .ko ? "룰" : "Rule"
    }

    private var categoryTitle: String {
        language == .ko ? "분류" : "Category"
    }

    private var locationTitle: String {
        language == .ko ? "위치" : "Location"
    }

    private var recommendationTitle: String {
        language == .ko ? "권장 조치" : "Recommendation"
    }

    private var fallbackRecommendation: String {
        language == .ko ? "항목의 근거를 검토하고 안전한 설정 또는 코드 패턴으로 수정하세요." : "Review the evidence and replace it with a safe configuration or code pattern."
    }
}

private extension AppLanguage {
    var screenQualityTitle: String {
        switch self {
        case .ko: return "화면 품질"
        case .en: return "Screen Quality"
        }
    }

    var screenQualityHeadline: String {
        switch self {
        case .ko: return "보안 점검과 분리된 화면 소스 품질 점검"
        case .en: return "Screen source quality checks separated from security scanning"
        }
    }

    var screenQualityDescription: String {
        switch self {
        case .ko:
            return "HTML, JSP, CLX, JS, TS, Vue, React 화면 소스에서 접근성, 웹표준, 입력폼, 버튼, 링크, 민감정보 및 시스템 경로 노출 항목을 점검합니다."
        case .en:
            return "Checks HTML, JSP, CLX, JS, TS, Vue, and React screen source for accessibility, standards, forms, buttons, links, sensitive text, and system path exposure."
        }
    }

    var screenQualityRunTitle: String {
        switch self {
        case .ko: return "화면 품질 점검"
        case .en: return "Run Screen Quality"
        }
    }

    var screenQualityNoTargets: String {
        switch self {
        case .ko: return "화면 소스가 있는 폴더나 파일을 선택하세요."
        case .en: return "Choose folders or files containing screen source."
        }
    }

    var screenQualityResultTitle: String {
        switch self {
        case .ko: return "화면 품질 점검결과"
        case .en: return "Screen Quality Results"
        }
    }

    var screenQualityResultSubtitle: String {
        switch self {
        case .ko: return "보안 기준 카드와 분리된 화면 소스 품질 리포트입니다."
        case .en: return "A screen source quality report separated from security standard cards."
        }
    }

    var screenQualityReportDescription: String {
        switch self {
        case .ko: return "접근성, 웹표준, 버튼, 링크, 폼, 노출 위험만 모아 확인합니다."
        case .en: return "Review only accessibility, standards, buttons, links, forms, and exposure risks."
        }
    }

    var screenQualityEmptyResult: String {
        switch self {
        case .ko: return "대상을 선택하고 화면 품질 점검을 실행하면 리포트 카드가 표시됩니다."
        case .en: return "Choose a target and run screen quality to show the report card."
        }
    }
}

struct ReportWebView: NSViewRepresentable {
    let url: URL
    let colorScheme: ColorScheme

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeNSView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.allowsMagnification = true
        webView.setValue(false, forKey: "drawsBackground")
        return webView
    }

    func updateNSView(_ webView: WKWebView, context: Context) {
        let appearanceName: NSAppearance.Name = colorScheme == .dark ? .darkAqua : .aqua
        webView.appearance = NSAppearance(named: appearanceName)

        guard context.coordinator.loadedURL != url || context.coordinator.loadedColorScheme != colorScheme else {
            return
        }

        context.coordinator.loadedURL = url
        context.coordinator.loadedColorScheme = colorScheme
        webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
    }

    final class Coordinator {
        var loadedURL: URL?
        var loadedColorScheme: ColorScheme?
    }
}
