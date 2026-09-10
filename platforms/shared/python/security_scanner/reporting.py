from __future__ import annotations

import base64
import io
import html
import json
import os
import re
import zipfile
from dataclasses import asdict, is_dataclass
from functools import lru_cache
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from threading import BoundedSemaphore
from urllib.parse import urlparse

from . import __version__
from .checks.secrets import SECRET_RULES, _redact_line
from .dependency_inventory import component_payload
from .models import DependencyComponent, Finding, SEVERITIES, SEVERITY_RANK
from .sbom import cyclonedx_payload, nis_sbom_payload, render_cyclonedx, render_nis_sbom
from .standards import (
    CODE_PATTERN_RULE_IDS,
    CONFIGURATION_RULE_IDS,
    DEFAULT_STANDARD,
    DEFAULT_STANDARD_CATEGORY,
    DEPENDENCY_RULE_IDS,
    PREVENTION_RULE_IDS,
    SCREEN_QUALITY_RULE_IDS,
    SECRET_RULE_IDS,
    SECURITY_STANDARDS,
    SENSITIVE_COMMENT_RULE_IDS,
    SW49_STATUSES,
    SW49_SUPPORT_LEVELS,
    rule_standard_mappings_payload,
    standards_payload,
    sw49_payload,
)
from .vex import render_cyclonedx_vex


SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 40,
    "medium": 10,
    "low": 3,
    "info": 1,
}

SEVERITY_SECURITY_SCORES = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.0",
    "low": "2.0",
    "info": "0.0",
}


_KODA_LOGO_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3 5 6v5c0 4.6 2.8 8.2 7 10 4.2-1.8 7-5.4 7-10V6l-7-3Z"/><path d="m9 12 2 2 4-5"/></svg>'


def _source_analysis_payload(value: object) -> dict[str, object]:
    """Serialize the immutable source-analysis summary without rebuilding it.

    The core summary may be a dataclass, a mapping, or expose ``to_dict`` across
    package versions.  Unknown values are represented conservatively so legacy
    callers still produce a valid report without claiming coverage.
    """
    if value is None:
        return {}
    try:
        if hasattr(value, "to_dict"):
            raw = value.to_dict()
        elif is_dataclass(value):
            raw = asdict(value)
        elif isinstance(value, dict):
            raw = dict(value)
        elif hasattr(value, "__dict__"):
            raw = vars(value)
        else:
            raw = {"value": str(value)}
    except Exception:
        raw = {"status": "NOT_SCANNED", "reason": "source_analysis_serialization_failed"}
    if isinstance(raw, dict):
        all_findings = raw.pop("all_findings", ())
        report_findings = raw.pop("report_findings", ())
        raw["all_finding_count"] = len(all_findings) if isinstance(all_findings, (list, tuple)) else 0
        raw["report_finding_count"] = len(report_findings) if isinstance(report_findings, (list, tuple)) else 0
    return _json_safe(raw) if isinstance(raw, dict) else {"value": str(raw)}


def _json_safe(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    if is_dataclass(value):
        return _json_safe(asdict(value))
    if hasattr(value, "value") and not isinstance(value, (str, int, float, bool)):
        return str(value.value)
    return value

TRANSLATIONS = {
    "en": {
        "html_lang": "en",
        "title": "KODA",
        "generated": "Generated",
        "risk_score": "Risk score",
        "targets": "Targets",
        "findings": "Findings",
        "filters": "Filters",
        "help": "Help",
        "dashboard": "Dashboard",
        "screen_quality": "Screen Quality",
        "screen_quality_title": "Screen Quality Scan",
        "screen_quality_intro": "Check screen source separately from security findings: accessibility, standards, form controls, links, sensitive text, and system path exposure.",
        "screen_quality_run": "Quality Check",
        "screen_quality_done": "Screen quality scan complete",
        "screen_quality_note": "Uses only the screen_quality category. Choose a project folder with HTML, JSP, CLX, JS, TS, Vue, or React source.",
        "help_title": "Security Standards Help",
        "help_intro": "Review each selectable standard, what KODA checks locally, and links to the official source.",
        "coverage_matrix": "Coverage Matrix",
        "coverage": "Coverage",
        "publication_info": "Issuer / release",
        "official_links": "Official links",
        "check_categories": "Check criteria",
        "mapped_checks": "mapped checks",
        "auto_supported": "automatic",
        "automatic_coverage": "automatic checks",
        "external_required": "external integration required",
        "evidence_required": "evidence review required",
        "local_coverage": "automatic checks",
        "rule_details": "Rule Details",
        "related_standards": "Related standards",
        "no_related_standards": "No standard mapping recorded.",
        "dependency_components": "Components",
        "download_sbom": "Download SBOM",
        "sbom_format": "SBOM format",
        "sbom_cyclonedx_16": "CycloneDX 1.6 (JSON)",
        "sbom_nis_10": "NIS-SBOM 1.0 (CSV)",
        "settings": "Settings",
        "settings_title": "Check rule settings",
        "settings_intro": "Turn individual rules on or off. Disabled rules are excluded from scan results.",
        "settings_tab_security": "Security check",
        "settings_tab_quality": "Quality check",
        "settings_loading": "Loading rules…",
        "settings_reset": "Enable all",
        "settings_disable_all": "Disable all",
        "settings_expand_all": "Expand all",
        "settings_collapse_all": "Collapse all",
        "download_report": "Report",
        "download_format_prompt": "Choose a format to save",
        "download_standard_label": "Standard",
        "download_all": "All findings",
        "download_cancel": "Cancel",
        "download_md": "Markdown",
        "download_xlsx": "Excel (xlsx)",
        "download_hwpx": "Hangul (hwpx)",
        "download_pdf": "PDF",
        "download_html": "HTML (CLI summary + detail)",
        "download_report_empty": "Run a scan first to download a report.",
        "download_future_title": "Format support notice",
        "download_future_support": "The selected format uses the current findings and standard. If it is unavailable, use the CLI report export.",
        "download_notice_close": "Close",
        "sbom_unavailable": "No dependency components available for SBOM.",
        "osv_toggle": "OSV/CVE + KEV/EPSS lookup",
        "osv_network_note": "Queries exact dependency versions through OSV.dev and enriches CVEs with CISA KEV and FIRST EPSS priority data.",
        "host_toggle": "Check this computer (host posture)",
        "host_note": "Also checks this machine's security posture (disk encryption, firewall, system integrity, updates). Runs read-only OS commands.",
        "supported": "supported",
        "not_supported": "not supported",
        "scan_directory": "Scan Directory",
        "scan_standard": "Security Standard",
        "scan_standard_category": "Standard Category",
        "scan_path_placeholder": "No folder selected",
        "choose_folder": "Choose Folder",
        "scan_now": "Security Scan",
        "upload_scan_title": "Scan File or Archive",
        "upload_scan_now": "Analyze Upload",
        "upload_scan_note": "Scans one file or the extracted contents of ZIP, TAR, GZ, JAR, WAR, and EAR archives. Archives are extracted to temporary storage and removed after the scan.",
        "upload_scan_required": "Choose a file or archive first.",
        "web_scan_title": "Scan Website (Live)",
        "web_url_placeholder": "https://example.com",
        "web_scan_now": "Scan URL",
        "web_scan_note": "Checks live security headers, TLS, cookies, and CORS with read-only requests. Only scan sites you are authorized to test.",
        "web_crawl_options": "Crawl & login options",
        "web_select_all": "Select all options",
        "web_clear_all": "Clear all options",
        "web_crawl_enable": "Crawl sub-pages (same host)",
        "web_render_enable": "Render JS for SPA links (needs 'render' extra)",
        "web_discover_assets": "Mine JS bundles for routes/APIs",
        "web_capture_network": "Capture network requests (with render)",
        "web_interact": "Click elements to find routes (with render)",
        "web_scan_js_secrets": "Scan JS bundles for leaked secrets",
        "web_ingest_sitemap": "Ingest robots.txt / sitemap.xml",
        "web_probe_paths": "Probe sensitive paths (/.env, /.git ...)",
        "web_active": "Active verify (XSS/SQLi/redirect payloads — authorized only)",
        "web_compare_unauth": "Access-control check: compare vs unauthenticated",
        "web_secondary_label": "Second account cookie/header (cross-account IDOR/BOLA)",
        "web_secondary_placeholder": "Cookie: sid=second-account",
        "web_api_spec_label": "API spec (OpenAPI/HAR/Postman JSON) to scan its GET endpoints",
        "web_api_spec_placeholder": "{ \"openapi\": \"3.0.0\", ... }",
        "web_seeds_label": "Extra routes to scan (one URL/path per line)",
        "web_seeds_placeholder": "/help\n/api/items",
        "web_allowed_origins_label": "Allowed origins (one exact http(s) origin per line; credentials are never forwarded)",
        "web_allowed_origins_placeholder": "https://api.example.com",
        "web_login_legend": "Login (optional)",
        "web_login_url": "Login form URL",
        "web_login_user": "Username",
        "web_login_pass": "Password",
        "web_headers_label": "Cookie / headers (one 'Name: value' per line)",
        "web_headers_placeholder": "Cookie: session=...",
        "web_pages_scanned": "pages scanned",
        "zap_scan_title": "OWASP ZAP Deep Scan (Docker)",
        "zap_scan_now": "Run ZAP Scan",
        "zap_scan_note": "Runs a ZAP Automation plan (spider + optional AJAX spider + optional active scan) via Docker. Active scan sends attack traffic — authorized targets only.",
        "zap_options_label": "ZAP options",
        "zap_ajax": "AJAX spider (render JS-heavy apps)",
        "zap_active": "Active scan (sends attack traffic)",
        "zap_authorized": "I own or am explicitly authorized to actively test this target",
        "zap_merge": "Merge results into the current report (combine with the code scan)",
        "zap_include_label": "Include paths (one regex per line, e.g. https://site/.*)",
        "zap_exclude_label": "Exclude paths (one regex per line, e.g. https://site/logout.*)",
        "zap_login_legend": "Authenticated scan (optional): scan behind a login",
        "zap_need_authorization": "Enable the authorization checkbox before running an active scan.",
        "prevention_kit_title": "Prevention Kit",
        "prevention_kit_note": "Writes baseline guardrails into the selected folder above.",
        "prevention_apply_toolkit": "Apply guardrail files",
        "prevention_install_hook": "Install pre-commit hook",
        "prevention_create_ignore": "Create ignore template",
        "prevention_need_folder": "Choose a folder above first.",
        "prevention_running": "Applying prevention kit...",
        "prevention_done": "Prevention kit applied",
        "prevention_written": "written",
        "prevention_kept": "kept existing",
        "prevention_failed": "Prevention kit failed",
        "discover_projects": "Discover projects",
        "scan_status_idle": "Ready",
        "scan_status_running": "Scanning...",
        "scan_status_done": "Scan complete",
        "scan_status_failed": "Scan failed",
        "scan_category_not_supported": "not yet supported",
        "folder_selection_cancelled": "Folder selection cancelled.",
        "folder_selection_failed": "Folder selection failed",
        "folder_selected": "Folder selected",
        "server_required": "Run python3 -m security_scanner app and open the local dashboard.",
        "search_placeholder": "Search title, rule, path, evidence",
        "reset": "Reset",
        "project_risk": "Project Risk",
        "severity_distribution": "Severity Distribution",
        "severity": "Severity",
        "finding": "Finding",
        "target": "Target",
        "location": "Location",
        "evidence": "Evidence",
        "action": "Action",
        "source_context": "Source context",
        "source_context_unavailable": "Source context is unavailable for this finding.",
        "problem_location": "Problem location",
        "no_findings_display": "No findings to display.",
        "no_findings_filter": "No findings match the current filters.",
        "sw49_heading": "SW Development Security 49 Control Status",
        "sw49_intro": "All 49 official implementation-stage weaknesses. Controls without automated coverage are never marked PASS.",
        "sw49_zero_note": "No vulnerable items were detected within the checks that actually ran. Partial, not-applicable, and not-scanned controls must be interpreted separately; this does not mean all 49 controls are satisfied.",
        "sw49_columns": {
            "official_id": "Official item (KODA ID)",
            "category": "Type",
            "title": "Weakness",
            "cwe": "CWE",
            "support": "Support",
            "executed": "Executed",
            "status": "Verdict",
            "rules": "KODA rules",
            "finding_count": "Findings",
            "evidence": "Evidence",
            "notes": "Limitations",
        },
        "sw49_status_labels": {
            "PASS": "Pass",
            "VULNERABLE": "Vulnerable",
            "NEEDS_REVIEW": "Needs review",
            "UNSUPPORTED": "Unsupported",
            "NOT_APPLICABLE": "Not applicable",
            "NOT_SCANNED": "Not scanned",
        },
        "sw49_support_labels": {
            "automated": "Automated",
            "partial": "Partial",
            "manual-review": "Manual review",
            "unsupported": "Unsupported",
        },
        "sw49_summary_labels": {
            "total": "Official controls",
            "automated": "Automated",
            "partial": "Partial",
            "manual-review": "Manual review",
            "unsupported": "Unsupported",
        },
        "sw49_executed_yes": "Run",
        "sw49_executed_no": "Not run",
        "no_targets_recorded": "No targets recorded.",
        "all_severities": "All severities",
        "all_categories": "All categories",
        "all_targets": "All targets",
        "all_locations": "All locations",
        "risk_score_metric": "Risk Score",
        "risk_score_sub": "weighted local score",
        "risk_score_formula": "Calculation uses context-confirmed findings only: critical 100, high 40, medium 10, low 3, info 1.",
        "critical_sub": "immediate review",
        "high_sub": "near-term fix",
        "medium_sub": "planned remediation",
        "low_info_metric": "Low + Info",
        "low_info_sub": "hygiene backlog",
        "blocking": "Blocking",
        "blocking_sub": "critical or high",
        "remediate": "Remediate",
        "review_this_finding": "Review this finding.",
        "summary_link": "Summary",
        "finding_singular": "finding",
        "finding_plural": "findings",
        "unknown": "unknown",
        "report_heading": "Local Security Scan Report",
        "summary": "Summary",
        "total_findings": "Total findings",
        "scanned_targets": "Scanned targets",
        "no_threshold_findings": "No findings matched the selected severity threshold.",
        "rule": "Rule",
        "category": "Category",
        "why_it_matters": "Why it matters",
        "recommendation": "Recommendation",
        "severity_labels": {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
        },
        "category_labels": {
            "secrets": "Secrets",
            "dependencies": "Dependencies",
            "configuration": "Configuration",
            "code": "Code Patterns",
            "prevention": "Prevention Guardrails",
            "screen_quality": "Screen Quality",
            "host": "Host Posture",
            "web": "Web Posture",
        },
    },
    "ko": {
        "html_lang": "ko",
        "title": "KODA",
        "generated": "생성 시각",
        "risk_score": "위험 점수",
        "targets": "점검 대상",
        "findings": "발견 항목",
        "filters": "필터",
        "help": "도움말",
        "dashboard": "대시보드",
        "screen_quality": "화면 품질",
        "screen_quality_title": "화면 품질 점검",
        "screen_quality_intro": "보안 발견 항목과 분리해 화면 소스의 접근성, 웹표준, 폼 컨트롤, 링크, 민감정보 및 시스템 경로 노출을 점검합니다.",
        "screen_quality_run": "품질점검",
        "screen_quality_done": "화면 품질 점검 완료",
        "screen_quality_note": "screen_quality 카테고리만 실행합니다. HTML, JSP, CLX, JS, TS, Vue, React 화면 소스가 있는 프로젝트 폴더를 선택하세요.",
        "help_title": "보안 점검 기준 도움말",
        "help_intro": "선택 가능한 보안 기준, 로컬 점검 범위, 공식 출처 링크를 확인합니다.",
        "coverage_matrix": "커버리지 매트릭스",
        "coverage": "점검 범위",
        "publication_info": "발행기관 / 판본",
        "official_links": "공식 링크",
        "check_categories": "점검 기준",
        "mapped_checks": "매핑된 점검",
        "auto_supported": "자동",
        "automatic_coverage": "자동 점검",
        "external_required": "외부 연동 필요",
        "evidence_required": "증적 확인 필요",
        "local_coverage": "자동 점검",
        "rule_details": "룰 상세 도움말",
        "related_standards": "관련 보안 기준",
        "no_related_standards": "연결된 기준 매핑이 없습니다.",
        "dependency_components": "컴포넌트",
        "download_sbom": "SBOM 다운로드",
        "sbom_format": "SBOM 생성 형식",
        "sbom_cyclonedx_16": "CycloneDX 1.6 (JSON)",
        "sbom_nis_10": "국정원 NIS-SBOM 1.0 (CSV)",
        "settings": "설정",
        "settings_title": "점검 규칙 설정",
        "settings_intro": "규칙을 개별적으로 켜거나 끌 수 있습니다. 끈 규칙은 점검 결과에서 제외됩니다.",
        "settings_tab_security": "보안점검",
        "settings_tab_quality": "품질점검",
        "settings_loading": "규칙을 불러오는 중…",
        "settings_reset": "모두 사용",
        "settings_disable_all": "모두 해제",
        "settings_expand_all": "+",
        "settings_collapse_all": "−",
        "download_report": "보고서",
        "download_format_prompt": "저장할 형식을 선택하세요",
        "download_standard_label": "기준",
        "download_all": "전체",
        "download_cancel": "취소",
        "download_md": "마크다운",
        "download_xlsx": "엑셀 (xlsx)",
        "download_hwpx": "한글 (hwpx)",
        "download_pdf": "PDF",
        "download_html": "HTML (CLI 요약 + 상세)",
        "download_report_empty": "먼저 점검을 실행한 뒤 결과를 다운로드하세요.",
        "download_future_title": "형식 지원 안내",
        "download_future_support": "선택한 기준과 현재 결과를 반영해 내보냅니다. 형식을 사용할 수 없으면 CLI 보고서 내보내기를 이용하세요.",
        "download_notice_close": "닫기",
        "sbom_unavailable": "SBOM으로 내보낼 의존성 컴포넌트가 없습니다.",
        "osv_toggle": "OSV/CVE + KEV/EPSS 조회",
        "osv_network_note": "정확한 의존성 버전을 OSV.dev로 조회하고 CVE에 CISA KEV와 FIRST EPSS 우선순위 정보를 덧붙입니다.",
        "host_toggle": "이 컴퓨터 점검 (호스트 보안 상태)",
        "host_note": "이 기기의 보안 상태(디스크 암호화, 방화벽, 시스템 무결성, 업데이트)도 함께 점검합니다. 읽기 전용 OS 명령을 실행합니다.",
        "supported": "지원",
        "not_supported": "미지원",
        "scan_directory": "점검 경로",
        "scan_standard": "보안 기준",
        "scan_standard_category": "기준 카테고리",
        "scan_path_placeholder": "선택된 폴더 없음",
        "choose_folder": "폴더 선택",
        "scan_now": "보안 점검",
        "upload_scan_title": "파일·압축파일 점검",
        "upload_scan_now": "업로드 분석",
        "upload_scan_note": "파일 1개 또는 ZIP, TAR, GZ, JAR, WAR, EAR 압축 해제 내용을 점검합니다. 임시 저장 파일은 점검 후 삭제됩니다.",
        "upload_scan_required": "먼저 파일 또는 압축파일을 선택하세요.",
        "web_scan_title": "웹사이트 점검 (실시간)",
        "web_url_placeholder": "https://example.com",
        "web_scan_now": "URL 점검",
        "web_scan_note": "읽기 전용 요청으로 실시간 보안 헤더·TLS·쿠키·CORS를 점검합니다. 점검 권한이 있는 사이트에만 실행하세요.",
        "web_crawl_options": "크롤·로그인 옵션",
        "web_select_all": "옵션 전체 선택",
        "web_clear_all": "옵션 전체 해제",
        "web_crawl_enable": "하위 페이지 크롤 (같은 호스트)",
        "web_render_enable": "SPA 링크용 JS 렌더링 ('render' 확장 필요)",
        "web_discover_assets": "JS 번들에서 라우트/API 추출",
        "web_capture_network": "네트워크 요청 캡처 (렌더링 시)",
        "web_interact": "요소 클릭으로 라우트 탐색 (렌더링 시)",
        "web_scan_js_secrets": "JS 번들에서 유출 시크릿 스캔",
        "web_ingest_sitemap": "robots.txt / sitemap.xml 수집",
        "web_probe_paths": "민감 경로 프로브 (/.env, /.git ...)",
        "web_active": "능동 검증 (XSS/SQLi/리다이렉트 페이로드 — 권한 대상만)",
        "web_compare_unauth": "접근통제 점검: 비인증과 비교",
        "web_secondary_label": "두 번째 계정 쿠키/헤더 (계정 간 IDOR/BOLA)",
        "web_secondary_placeholder": "Cookie: sid=second-account",
        "web_api_spec_label": "API 스펙(OpenAPI/HAR/Postman JSON) — GET 엔드포인트 점검",
        "web_api_spec_placeholder": "{ \"openapi\": \"3.0.0\", ... }",
        "web_seeds_label": "추가 점검 경로 (한 줄에 URL/경로 하나)",
        "web_seeds_placeholder": "/help\n/api/items",
        "web_allowed_origins_label": "허용 Origin (한 줄에 정확한 http(s) Origin 하나, 인증정보는 전달하지 않음)",
        "web_allowed_origins_placeholder": "https://api.example.com",
        "web_login_legend": "로그인 (선택)",
        "web_login_url": "로그인 폼 URL",
        "web_login_user": "아이디",
        "web_login_pass": "비밀번호",
        "web_headers_label": "쿠키 / 헤더 (한 줄에 'Name: value')",
        "web_headers_placeholder": "Cookie: session=...",
        "web_pages_scanned": "페이지 점검",
        "zap_scan_title": "OWASP ZAP 심층 점검 (Docker)",
        "zap_scan_now": "ZAP 점검 실행",
        "zap_scan_note": "Docker로 ZAP Automation 계획(스파이더 + 선택적 AJAX 스파이더 + 선택적 능동 점검)을 실행합니다. 능동 점검은 실제 공격 트래픽을 보내므로 권한이 있는 대상에만 사용하세요.",
        "zap_options_label": "ZAP 옵션",
        "zap_ajax": "AJAX 스파이더 (JS 위주 앱 렌더링)",
        "zap_active": "능동 점검 (공격 트래픽 전송)",
        "zap_authorized": "본인이 소유했거나 명시적으로 능동 점검 허가를 받은 대상입니다",
        "zap_merge": "현재 보고서에 결과 통합 (코드 점검 결과와 합치기)",
        "zap_include_label": "포함 경로 (한 줄당 정규식, 예: https://site/.*)",
        "zap_exclude_label": "제외 경로 (한 줄당 정규식, 예: https://site/logout.*)",
        "zap_login_legend": "인증 점검 (선택): 로그인 이후 화면 점검",
        "zap_need_authorization": "능동 점검을 실행하려면 먼저 권한 확인란을 선택하세요.",
        "prevention_kit_title": "예방 키트",
        "prevention_kit_note": "위에서 선택한 폴더에 기본 예방 가드레일 파일을 생성합니다.",
        "prevention_apply_toolkit": "가드레일 파일 생성",
        "prevention_install_hook": "커밋 전 차단 훅 설치",
        "prevention_create_ignore": "예외 템플릿 생성",
        "prevention_need_folder": "먼저 위에서 폴더를 선택하세요.",
        "prevention_running": "예방 키트를 적용하고 있습니다...",
        "prevention_done": "예방 키트 적용 완료",
        "prevention_written": "생성",
        "prevention_kept": "기존 유지",
        "prevention_failed": "예방 키트 실패",
        "discover_projects": "하위 프로젝트 탐색",
        "scan_status_idle": "대기 중",
        "scan_status_running": "점검 중...",
        "scan_status_done": "점검 완료",
        "scan_status_failed": "점검 실패",
        "scan_category_not_supported": "아직 미지원",
        "folder_selection_cancelled": "폴더 선택이 취소되었습니다.",
        "folder_selection_failed": "폴더 선택 실패",
        "folder_selected": "폴더 선택됨",
        "server_required": "python3 -m security_scanner app으로 로컬 대시보드를 열어주세요.",
        "search_placeholder": "제목, 규칙, 경로, 근거 검색",
        "reset": "초기화",
        "project_risk": "프로젝트 위험도",
        "severity_distribution": "심각도 분포",
        "severity": "심각도",
        "finding": "발견 항목",
        "target": "대상",
        "location": "위치",
        "evidence": "근거",
        "action": "조치",
        "source_context": "소스 원문 문맥",
        "source_context_unavailable": "이 항목의 소스 원문 문맥을 읽을 수 없습니다.",
        "problem_location": "문제 위치",
        "no_findings_display": "표시할 발견 항목이 없습니다.",
        "no_findings_filter": "현재 필터와 일치하는 발견 항목이 없습니다.",
        "sw49_heading": "소프트웨어 개발보안 49 기준 현황",
        "sw49_intro": "공식 구현단계 보안약점 49개 전체 상태입니다. 자동 점검이 없는 기준은 통과로 표시하지 않습니다.",
        "sw49_zero_note": "현재 실행된 점검 범위에서는 취약 항목이 탐지되지 않았습니다. 부분 점검·해당 없음·미실행 기준은 별도로 확인해야 하며, 전체 49개 기준의 준수를 의미하지 않습니다.",
        "sw49_columns": {
            "official_id": "공식 항목 (KODA ID)",
            "category": "분류",
            "title": "기준명",
            "cwe": "CWE",
            "support": "지원 수준",
            "executed": "실행 상태",
            "status": "판정",
            "rules": "연결 룰",
            "finding_count": "발견 건수",
            "evidence": "근거",
            "notes": "제한사항",
        },
        "sw49_status_labels": {
            "PASS": "통과",
            "VULNERABLE": "취약",
            "NEEDS_REVIEW": "수동 검토 필요",
            "UNSUPPORTED": "미지원",
            "NOT_APPLICABLE": "해당 없음",
            "NOT_SCANNED": "미실행",
        },
        "sw49_support_labels": {
            "automated": "자동",
            "partial": "부분 자동",
            "manual-review": "수동 검토",
            "unsupported": "미지원",
        },
        "sw49_summary_labels": {
            "total": "공식 기준",
            "automated": "자동 지원",
            "partial": "부분 지원",
            "manual-review": "수동 검토",
            "unsupported": "미지원",
        },
        "sw49_executed_yes": "실행됨",
        "sw49_executed_no": "미실행",
        "no_targets_recorded": "기록된 대상이 없습니다.",
        "all_severities": "모든 심각도",
        "all_categories": "모든 종류",
        "all_targets": "모든 대상",
        "all_locations": "모든 위치",
        "risk_score_metric": "위험 점수",
        "risk_score_sub": "가중 로컬 점수",
        "risk_score_formula": "계산: 문맥 확인된 항목만 치명 100점, 높음 40점, 중간 10점, 낮음 3점, 정보 1점씩 합산합니다.",
        "critical_sub": "즉시 검토",
        "high_sub": "빠른 수정 필요",
        "medium_sub": "계획된 조치",
        "low_info_metric": "낮음 + 정보",
        "low_info_sub": "보안 위생 백로그",
        "blocking": "차단 항목",
        "blocking_sub": "치명 또는 높음",
        "remediate": "조치 보기",
        "review_this_finding": "이 발견 항목을 검토하세요.",
        "summary_link": "요약으로 돌아가기",
        "finding_singular": "건",
        "finding_plural": "건",
        "unknown": "알 수 없음",
        "report_heading": "로컬 보안 점검 리포트",
        "summary": "요약",
        "total_findings": "전체 발견 항목",
        "scanned_targets": "점검 대상",
        "no_threshold_findings": "선택한 심각도 기준에 해당하는 발견 항목이 없습니다.",
        "rule": "규칙",
        "category": "종류",
        "why_it_matters": "중요한 이유",
        "recommendation": "권장 조치",
        "severity_labels": {
            "critical": "치명",
            "high": "높음",
            "medium": "중간",
            "low": "낮음",
            "info": "정보",
        },
        "category_labels": {
            "secrets": "비밀값",
            "dependencies": "의존성",
            "configuration": "설정",
            "code": "코드 패턴",
            "prevention": "예방 가드레일",
            "screen_quality": "화면 품질",
            "host": "호스트 보안 상태",
            "web": "웹 보안 상태",
        },
    },
}

RULE_TRANSLATIONS_KO = {
    "prevention.security-policy-missing": {
        "title": "보안 정책 문서가 없음",
        "description": "취약점 신고, 지원 버전, 공개 절차를 설명하는 SECURITY.md가 없습니다.",
        "recommendation": "SECURITY.md에 신고 연락처, 지원 범위, 취약점 공개 기대사항을 작성하세요.",
    },
    "prevention.dependency-update-automation-missing": {
        "title": "의존성 업데이트 자동화가 없음",
        "description": "Dependabot 또는 Renovate 설정이 없어 취약·노후 의존성을 지속적으로 확인하기 어렵습니다.",
        "recommendation": "Dependabot 또는 Renovate를 추가해 의존성 업데이트와 취약점 알림을 자동화하세요.",
    },
    "prevention.ci-security-scan-missing": {
        "title": "CI 보안 점검 워크플로가 없음",
        "description": "CI에서 실행되는 보안 점검 워크플로가 확인되지 않았습니다.",
        "recommendation": "KODA, CodeQL, Semgrep, OSV, Trivy, Gitleaks, ZAP baseline 같은 보안 점검을 CI에 추가하세요.",
    },
    "prevention.env-not-gitignored": {
        "title": ".env 파일이 gitignore로 제외되지 않음",
        "description": "환경 파일이 존재하지만 .gitignore에서 제외하는 패턴이 확인되지 않았습니다.",
        "recommendation": ".gitignore에 .env, .env.* 또는 동등한 제외 패턴을 추가하세요.",
    },
    "prevention.env-example-missing": {
        "title": "정제된 환경 예시 파일이 없음",
        "description": "실제 환경 파일은 있으나 안전하게 공유 가능한 .env.example 또는 .env.sample이 없습니다.",
        "recommendation": "실제 값은 저장소 밖에 두고, 필요한 키만 담은 .env.example 또는 .env.sample을 커밋하세요.",
    },
    "prevention.dockerignore-missing": {
        "title": ".dockerignore가 없음",
        "description": "Dockerfile이 있지만 Docker 빌드 컨텍스트에서 제외할 파일 목록이 없습니다.",
        "recommendation": ".dockerignore를 추가해 비밀값, VCS 메타데이터, 빌드 산출물, 로컬 파일이 이미지 빌드에 포함되지 않게 하세요.",
    },
    "prevention.sbom-missing": {
        "title": "SBOM 산출물이 없음",
        "description": "의존성 매니페스트는 있으나 로컬 SBOM 산출물이 확인되지 않았습니다.",
        "recommendation": "릴리스 또는 CI 단계에서 CycloneDX나 SPDX SBOM을 생성하고 보관하세요.",
    },
    "prevention.sast-workflow-missing": {
        "title": "SAST 워크플로가 없음",
        "description": "CodeQL, Semgrep 등 정적 분석 workflow가 확인되지 않았습니다.",
        "recommendation": "Pull request에서 코드 수준 보안 점검이 실행되도록 CodeQL 또는 Semgrep 같은 SAST workflow를 추가하세요.",
    },
    "prevention.openssf-scorecard-missing": {
        "title": "OpenSSF Scorecard 워크플로가 없음",
        "description": "공급망 보안 상태를 지속적으로 점검하는 OpenSSF Scorecard workflow가 확인되지 않았습니다.",
        "recommendation": "토큰 권한, 고정된 액션, SAST, 의존성 업데이트 자동화 상태를 추적하도록 OpenSSF Scorecard를 CI에 추가하세요.",
    },
    "prevention.github-token-permissions-not-readonly": {
        "title": "GitHub Actions 토큰 권한이 읽기 전용으로 제한되지 않음",
        "description": "workflow token의 기본 권한이 최소 권한으로 명시되어 있지 않습니다.",
        "recommendation": "workflow 최상단에 permissions: contents: read를 설정하고, 쓰기 권한은 필요한 job에만 별도로 부여하세요.",
    },
    "prevention.github-actions-unpinned": {
        "title": "GitHub Actions 참조가 느슨하게 고정됨",
        "description": "main, master, latest 같은 mutable branch/ref를 참조하는 GitHub Actions가 있습니다.",
        "recommendation": "외부 GitHub Actions는 검토한 버전 태그나 immutable commit SHA로 고정하세요.",
    },
    "prevention.slsa-sigstore-missing": {
        "title": "릴리스 서명 또는 출처 증명이 없음",
        "description": "SLSA provenance, Sigstore, cosign, attestation workflow가 확인되지 않았습니다.",
        "recommendation": "릴리스 산출물에 Sigstore/cosign 서명 또는 SLSA provenance 생성을 추가하세요.",
    },
    "prevention.zap-baseline-missing": {
        "title": "DAST baseline이 설정되지 않음",
        "description": "웹 프로젝트로 보이나 OWASP ZAP baseline workflow 또는 가이드가 확인되지 않았습니다.",
        "recommendation": "권한이 있는 staging URL에 대해 OWASP ZAP baseline 점검 또는 DAST 인수인계 절차를 추가하세요.",
    },
    "prevention.dependency-track-integration-missing": {
        "title": "Dependency-Track SBOM 업로드가 설정되지 않음",
        "description": "의존성 매니페스트는 있으나 Dependency-Track 같은 SBOM 분석 backend로 업로드하는 workflow가 없습니다.",
        "recommendation": "릴리스 SBOM을 Dependency-Track 또는 동등한 SBOM 분석 backend에 업로드하도록 자동화하세요.",
    },
    "prevention.vex-missing": {
        "title": "VEX 문서가 없음",
        "description": "의존성 취약점 검토 결과를 추적할 VEX 산출물이 확인되지 않았습니다.",
        "recommendation": "검토된 의존성 취약점에 대해 exploitable, fixed, not_affected 같은 VEX 결정을 문서화하세요.",
    },
    "prevention.binary-artifact-committed": {
        "title": "바이너리 릴리스 산출물이 저장소에 포함됨",
        "description": "소스 저장소에 실행 파일 또는 빌드 산출물로 보이는 파일이 포함되어 있습니다.",
        "recommendation": "의도적으로 vendoring한 파일이 아니라면 제거하고, 필요한 경우 출처 증명·체크섬·서명을 함께 관리하세요.",
    },
    "prevention.threat-model-missing": {
        "title": "위협 모델 문서가 없음",
        "description": "신뢰 경계, 주요 자산, 악용 시나리오, 보안 가정이 문서화되어 있지 않습니다.",
        "recommendation": "출시 전 위협 모델을 작성하고 인증, 데이터, 외부 연동, 운영 권한의 경계를 정리하세요.",
    },
    "prevention.secret-rotation-runbook-missing": {
        "title": "비밀값 회전 절차 문서가 없음",
        "description": "비밀값 노출 시 폐기, 재발급, 사용 이력 확인, 재점검 절차가 문서화되어 있지 않습니다.",
        "recommendation": "비밀값 노출 대응 runbook을 작성하고 키 회전, 감사, 재점검 책임자를 지정하세요.",
    },
    "prevention.ai-llm-security-plan-missing": {
        "title": "AI/LLM 보안 계획이 없음",
        "description": "AI 또는 LLM 사용 흔적이 있으나 프롬프트 인젝션, 도구 권한, 민감정보 처리 기준이 문서화되어 있지 않습니다.",
        "recommendation": "프롬프트 경계, 도구 allowlist, 민감정보 마스킹, 모델/제공자 목록, 적대적 테스트를 문서화하세요.",
    },
    "prevention.mobile-security-plan-missing": {
        "title": "모바일 보안 계획이 없음",
        "description": "모바일 프로젝트 파일이 있으나 MASVS 범위, 플랫폼 설정, 저장소/네트워크/릴리스 테스트 기준이 문서화되어 있지 않습니다.",
        "recommendation": "Android/iOS 설정, 저장소, 통신, 서명, 기기 테스트 요구사항을 모바일 보안 계획에 정리하세요.",
    },
    "prevention.nist-csf-profile-missing": {
        "title": "NIST CSF 2.0 프로파일이 없음",
        "description": "Govern, Identify, Protect, Detect, Respond, Recover 기능에 대한 프로젝트 증적 매핑이 없습니다.",
        "recommendation": "NIST CSF 2.0 기능별 소유자, 증적, 점검 주기, 예외 처리 기준을 문서화하세요.",
    },
    "prevention.cisa-attestation-missing": {
        "title": "CISA 보안 소프트웨어 개발 확인서 증적이 없음",
        "description": "CISA/OMB 확인서에 필요한 개발, 검증, 공급망, 취약점 대응 증적이 문서화되어 있지 않습니다.",
        "recommendation": "SSDF 기반 개발 환경, 제3자 구성요소, 검증, 취약점 대응 증적을 확인서 체크리스트로 관리하세요.",
    },
    "prevention.api-security-plan-missing": {
        "title": "API 보안 계획이 없음",
        "description": "API 라우트 또는 핸들러가 있으나 인벤토리, 인증/인가, rate limit, 외부 API 사용 기준이 문서화되어 있지 않습니다.",
        "recommendation": "API_SECURITY.md에 API 목록, 객체/기능 권한, 스키마 검증, 남용 방지, 외부 API timeout/allowlist 기준을 작성하세요.",
    },
    "prevention.scvs-plan-missing": {
        "title": "OWASP SCVS 구성요소 검증 계획이 없음",
        "description": "의존성 매니페스트가 있으나 구성요소 인벤토리, SBOM, 빌드 환경, 패키지 관리, 출처 증명이 정리되어 있지 않습니다.",
        "recommendation": "SCVS_PLAN.md에 V1~V6 통제별 증적 위치와 검토 책임자를 기록하세요.",
    },
    "prevention.privacy-data-map-missing": {
        "title": "개인정보 데이터 맵이 없음",
        "description": "개인정보 필드, 처리 목적, 저장 위치, 보관 기간, 공유 여부가 문서화되어 있지 않습니다.",
        "recommendation": "PRIVACY_DATA_MAP.md에 개인정보 항목, 로그 제한, 보관/삭제 기준, 외부 전달 여부를 정리하세요.",
    },
    "prevention.security-roadmap-missing": {
        "title": "보안 로드맵이 없음",
        "description": "보안 backlog, 담당자, 기한, 위험 수용 항목을 추적하는 계획이 없습니다.",
        "recommendation": "SECURITY_ROADMAP.md로 우선순위, 표준, 담당자, 기한, 증적 위치를 관리하세요.",
    },
    "prevention.evidence-register-missing": {
        "title": "보안 증적 보관대장이 없음",
        "description": "점검 리포트, SBOM, VEX, DAST, 위협모델, 승인 기록의 위치와 담당자가 정리되어 있지 않습니다.",
        "recommendation": "EVIDENCE_REGISTER.md에 릴리스/감사에 필요한 보안 증적의 위치, 소유자, 검토일을 기록하세요.",
    },
    "prevention.exception-reason-missing": {
        "title": "예외 항목에 사유가 없음",
        "description": "koda-ignore.yml 예외에 왜 수용하거나 오탐으로 보는지 사유가 없습니다.",
        "recommendation": "각 예외에 구체적인 reason을 기록하세요.",
    },
    "prevention.exception-owner-missing": {
        "title": "예외 항목에 담당자가 없음",
        "description": "koda-ignore.yml 예외에 갱신과 검토를 책임질 owner가 없습니다.",
        "recommendation": "각 예외에 담당 팀, 담당자, 또는 티켓 큐를 owner로 기록하세요.",
    },
    "prevention.exception-expiry-missing": {
        "title": "예외 항목에 만료일이 없거나 잘못됨",
        "description": "예외가 영구 방치되지 않도록 until 날짜가 필요합니다.",
        "recommendation": "until을 YYYY-MM-DD 형식으로 추가하고 만료 전에 재검토하세요.",
    },
    "prevention.exception-expired": {
        "title": "예외 항목이 만료됨",
        "description": "만료된 예외는 더 이상 발견 항목을 억제하지 않으며 재검토가 필요합니다.",
        "recommendation": "근본 원인을 수정하거나 새 승인 사유와 만료일로 예외를 갱신하세요.",
    },
    "prevention.k8s-network-policy-missing": {
        "title": "Kubernetes NetworkPolicy가 없음",
        "description": "Kubernetes workload manifest는 있으나 네트워크 격리 정책이 확인되지 않았습니다.",
        "recommendation": "NetworkPolicy를 추가하거나 다른 네트워크 격리 계층을 사용한다는 근거를 문서화하세요.",
    },
    "prevention.security-headers-guide-missing": {
        "title": "보안 헤더 기준 문서가 없음",
        "description": "웹 프로젝트로 보이나 CSP, HSTS, nosniff, Referrer-Policy 같은 기본 헤더 기준이 없습니다.",
        "recommendation": "SECURITY_HEADERS.md에 서비스별 보안 헤더 baseline과 예외를 정리하세요.",
    },
    "prevention.container-hardening-guide-missing": {
        "title": "컨테이너 하드닝 기준 문서가 없음",
        "description": "컨테이너 배포 파일이 있으나 non-root, capability drop, seccomp, resource limit 기준이 문서화되어 있지 않습니다.",
        "recommendation": "CONTAINER_HARDENING.md에 Docker/Compose/Kubernetes 하드닝 기준을 기록하세요.",
    },
    "prevention.cloud-iac-security-plan-missing": {
        "title": "Cloud/IaC 보안 계획이 없음",
        "description": "클라우드 또는 IaC 파일이 있으나 노출, IAM, 암호화, 상태 파일 관리 기준이 문서화되어 있지 않습니다.",
        "recommendation": "CLOUD_IAC_SECURITY.md에 public ingress, IAM 최소권한, 암호화, Terraform state 보호 기준을 작성하세요.",
    },
    "secret.private-key": {
        "title": "개인 키 자료",
        "description": "개인 키로 보이는 값이 로컬 프로젝트 파일에 포함되어 있습니다.",
        "recommendation": "개인 키를 보안 저장소로 옮기고 실제로 사용된 키라면 즉시 교체하세요.",
    },
    "secret.aws-access-key": {
        "title": "AWS 액세스 키 ID",
        "description": "AWS 액세스 키로 보이는 값이 로컬 프로젝트 파일에 포함되어 있습니다.",
        "recommendation": "키를 환경 변수나 보안 저장소로 옮기고 실제 키라면 회전하세요.",
    },
    "secret.github-token": {
        "title": "GitHub 토큰",
        "description": "GitHub 토큰으로 보이는 값이 로컬 프로젝트 파일에 포함되어 있습니다.",
        "recommendation": "토큰을 폐기하거나 회전하고, 앞으로는 보안 저장소에서 주입하세요.",
    },
    "secret.openai-key": {
        "title": "OpenAI API 키",
        "description": "OpenAI API 키로 보이는 값이 로컬 프로젝트 파일에 포함되어 있습니다.",
        "recommendation": "키를 보안 저장소로 옮기고 실제 키라면 회전하세요.",
    },
    "secret.slack-token": {
        "title": "Slack 토큰",
        "description": "Slack 토큰으로 보이는 값이 로컬 프로젝트 파일에 포함되어 있습니다.",
        "recommendation": "토큰을 회전하고 환경 변수나 보안 저장소에서만 주입하세요.",
    },
    "secret.generic-assignment": {
        "title": "하드코딩된 비밀값 의심 대입",
        "description": "비밀값처럼 보이는 값이 로컬 프로젝트 파일에 직접 대입되어 있습니다.",
        "recommendation": "비밀값을 환경 변수나 로컬 보안 저장소로 옮기고 실제 값이면 회전하세요.",
    },
    "dependency.package-json-invalid": {
        "title": "잘못된 package.json",
        "description": "잘못된 의존성 매니페스트는 의존성 검토와 재현 가능한 설치를 방해할 수 있습니다.",
        "recommendation": "의존성 도구가 안정적으로 검사할 수 있도록 package.json 문법을 수정하세요.",
    },
    "dependency.node-missing-lockfile": {
        "title": "Node 프로젝트에 lockfile이 없음",
        "description": "lockfile이 없으면 설치 결과가 재현되지 않아 공급망 변경 위험이 커집니다.",
        "recommendation": "프로젝트에서 사용하는 패키지 매니저의 lockfile을 커밋하세요.",
    },
    "dependency.node-unbounded-version": {
        "title": "범위가 제한되지 않은 Node 의존성 버전",
        "description": "제한 없는 의존성 버전은 설치 시 예상하지 못한 코드를 가져올 수 있습니다.",
        "recommendation": "검토한 semver 범위로 제한하고 lockfile을 최신으로 유지하세요.",
    },
    "dependency.node-insecure-url": {
        "title": "HTTP로 가져오는 의존성",
        "description": "HTTP 의존성 소스는 전송 중 변조될 수 있습니다.",
        "recommendation": "HTTPS 또는 신뢰할 수 있는 패키지 레지스트리 소스를 사용하세요.",
    },
    "dependency.remote-shell-script": {
        "title": "원격 콘텐츠를 셸로 실행하는 패키지 스크립트",
        "description": "패키지 스크립트에서 원격 콘텐츠를 바로 실행하면 감사하기 어렵고 내용이 바뀔 수 있습니다.",
        "recommendation": "설치 스크립트를 vendoring하거나 체크섬을 검증하는 명시적 단계로 바꾸세요.",
    },
    "dependency.python-insecure-url": {
        "title": "HTTP로 가져오는 Python 의존성",
        "description": "HTTP 의존성 소스는 전송 중 변조될 수 있습니다.",
        "recommendation": "HTTPS 또는 신뢰할 수 있는 패키지 인덱스를 사용하세요.",
    },
    "dependency.python-unpinned-requirement": {
        "title": "고정되지 않은 Python 의존성",
        "description": "고정되지 않은 requirements는 설치 시점마다 달라질 수 있어 의존성 검토가 어려워집니다.",
        "recommendation": "배포 requirements에는 버전을 고정하거나 생성된 lockfile을 사용하세요.",
    },
    "dependency.python-wildcard-version": {
        "title": "와일드카드 Python 의존성 버전",
        "description": "와일드카드 버전은 설치 시 예상하지 못한 코드를 가져올 수 있습니다.",
        "recommendation": "검토한 버전 범위나 lockfile을 사용하세요.",
    },
    "dependency.docker-unpinned-base": {
        "title": "Docker 베이스 이미지가 고정되지 않음",
        "description": "떠 있는 베이스 이미지 태그는 검토 없이 바뀔 수 있습니다.",
        "recommendation": "검토한 태그 또는 digest로 고정하세요.",
    },
    "dependency.docker-remote-shell": {
        "title": "Docker 빌드에서 원격 콘텐츠를 셸로 실행",
        "description": "빌드 중 원격 콘텐츠를 바로 실행하면 감사하기 어렵고 내용이 바뀔 수 있습니다.",
        "recommendation": "아티팩트를 내려받은 뒤 서명이나 체크섬을 검증하고 실행하세요.",
    },
    "config.env-file-present": {
        "title": "환경 파일이 프로젝트 트리에 있음",
        "description": "로컬 환경 파일에는 자격 증명이나 운영 설정이 들어 있는 경우가 많습니다.",
        "recommendation": "실제 환경 파일은 저장소 밖에 두고, 커밋할 때는 정리된 예제 파일만 포함하세요.",
    },
    "config.private-key-like-file": {
        "title": "개인 키로 보이는 파일",
        "description": "테스트 전용이 아니라면 개인 키 자료는 프로젝트 폴더 안에 두지 않아야 합니다.",
        "recommendation": "개인 키를 보안 저장소로 옮기고 실제로 사용된 키라면 회전하세요.",
    },
    "config.debug-enabled": {
        "title": "디버그 모드가 활성화된 것으로 보임",
        "description": "디버그 모드는 배포 환경에서 내부 정보, 스택 트레이스, 위험한 엔드포인트를 노출할 수 있습니다.",
        "recommendation": "공유, 스테이징, 운영 설정에서는 디버그 모드를 비활성화하세요.",
    },
    "config.development-environment": {
        "title": "개발 환경 플래그가 있음",
        "description": "개발 환경 설정이 배포에 재사용되면 런타임 보안 가정이 약해질 수 있습니다.",
        "recommendation": "로컬 개발 설정과 배포 설정을 분리하세요.",
    },
    "config.docker-root-user": {
        "title": "Docker 이미지가 root로 실행되도록 설정됨",
        "description": "root 컨테이너는 프로세스 침해 시 영향 범위를 키웁니다.",
        "recommendation": "root가 꼭 필요하지 않다면 최소 권한 사용자로 실행하세요.",
    },
    "config.docker-add-http": {
        "title": "Dockerfile ADD가 HTTP를 사용함",
        "description": "HTTP 다운로드는 이미지 빌드 중 전송 경로에서 변조될 수 있습니다.",
        "recommendation": "HTTPS를 사용하고 아티팩트 체크섬을 검증하세요.",
    },
    "config.docker-no-user": {
        "title": "Dockerfile에 비root USER가 없음",
        "description": "USER 지시어가 없는 이미지는 보통 root로 실행됩니다.",
        "recommendation": "가능하면 런타임 단계에 비root USER를 추가하세요.",
    },
    "config.compose-privileged": {
        "title": "Compose 서비스가 privileged 모드를 사용함",
        "description": "privileged 컨테이너는 호스트에 대한 광범위한 접근 권한을 가집니다.",
        "recommendation": "privileged 모드를 제거하고 필요한 capability만 명시적으로 부여하세요.",
    },
    "config.compose-host-network": {
        "title": "Compose 서비스가 host 네트워크를 사용함",
        "description": "host 네트워크는 격리를 약화시키고 로컬 서비스를 노출할 수 있습니다.",
        "recommendation": "host 네트워크가 꼭 필요하지 않다면 명시적 포트 매핑을 사용하세요.",
    },
    "config.compose-docker-sock": {
        "title": "Compose 서비스가 Docker 소켓을 마운트함",
        "description": "Docker 소켓 접근은 사실상 호스트 수준 제어 권한에 가깝습니다.",
        "recommendation": "Docker 소켓 마운트를 피하거나 목적별 프록시 뒤로 격리하세요.",
    },
    "config.compose-dangerous-capability": {
        "title": "Compose 서비스가 광범위한 Linux capability를 부여함",
        "description": "SYS_ADMIN, NET_ADMIN 같은 capability는 컨테이너 격리와 호스트 보호를 약화시킬 수 있습니다.",
        "recommendation": "불필요한 capability를 제거하고 필요한 권한만 명시적으로 부여하세요.",
    },
    "config.compose-host-pid": {
        "title": "Compose 서비스가 host PID namespace를 사용함",
        "description": "host PID namespace는 호스트 프로세스 가시성을 넓혀 격리를 약화시킵니다.",
        "recommendation": "host PID 접근이 꼭 필요한 경우가 아니면 기본 PID namespace를 사용하세요.",
    },
    "config.compose-secret-in-environment": {
        "title": "Compose 환경값에 비밀값이 직접 포함됨",
        "description": "Compose 파일의 환경 변수 값은 저장소와 컨테이너 메타데이터를 통해 노출될 수 있습니다.",
        "recommendation": "민감값은 secret manager 또는 런타임 주입으로 옮기고 compose에는 placeholder만 남기세요.",
    },
    "config.k8s-privileged-container": {
        "title": "Kubernetes 컨테이너가 privileged 모드를 사용함",
        "description": "privileged 컨테이너는 호스트 수준 접근 권한을 얻을 수 있습니다.",
        "recommendation": "privileged 모드를 제거하고 필요한 Linux capability만 명시하세요.",
    },
    "config.k8s-allow-privilege-escalation": {
        "title": "Kubernetes 컨테이너가 권한 상승을 허용함",
        "description": "권한 상승 허용은 컨테이너 격리를 약화시킵니다.",
        "recommendation": "문서화된 요구사항이 없다면 allowPrivilegeEscalation: false를 설정하세요.",
    },
    "config.k8s-host-network": {
        "title": "Kubernetes workload가 host network를 사용함",
        "description": "host network는 일반적인 Pod 네트워크 격리를 우회합니다.",
        "recommendation": "필요하지 않다면 Pod 네트워크와 Service/NetworkPolicy를 사용하세요.",
    },
    "config.k8s-hostpath-volume": {
        "title": "Kubernetes workload가 hostPath 볼륨을 마운트함",
        "description": "hostPath는 호스트 파일시스템 경로를 컨테이너에 노출합니다.",
        "recommendation": "가능하면 PersistentVolume으로 대체하고, 불가피한 경우 사유를 문서화하세요.",
    },
    "config.k8s-run-as-root": {
        "title": "Kubernetes workload가 root 실행을 허용함",
        "description": "root 사용자 실행은 컨테이너 침해 시 영향 범위를 키울 수 있습니다.",
        "recommendation": "runAsNonRoot: true와 비root 런타임 사용자를 설정하세요.",
    },
    "config.k8s-service-account-token": {
        "title": "Kubernetes service account token 자동 마운트",
        "description": "불필요한 service account token은 Pod 침해 시 Kubernetes API 접근 경로가 될 수 있습니다.",
        "recommendation": "Kubernetes API 접근이 필요하지 않다면 automountServiceAccountToken: false를 설정하세요.",
    },
    "config.k8s-unpinned-image": {
        "title": "Kubernetes 이미지가 고정되지 않음",
        "description": "latest 또는 태그 없는 이미지는 검토 없이 내용이 바뀔 수 있습니다.",
        "recommendation": "검토된 버전 태그 또는 immutable digest로 이미지를 고정하세요.",
    },
    "config.k8s-seccomp-unconfined": {
        "title": "Kubernetes seccomp가 unconfined로 설정됨",
        "description": "unconfined seccomp는 커널 syscall 경계를 약화합니다.",
        "recommendation": "검토된 예외가 없다면 RuntimeDefault seccomp profile을 사용하세요.",
    },
    "config.k8s-dangerous-capability": {
        "title": "Kubernetes workload에 광범위한 capability가 추가됨",
        "description": "SYS_ADMIN, NET_ADMIN 같은 capability는 Pod 격리를 크게 약화할 수 있습니다.",
        "recommendation": "기본적으로 capability를 모두 drop하고 필요한 최소 capability만 검토 후 추가하세요.",
    },
    "config.terraform-public-storage": {
        "title": "Terraform 저장소 ACL이 public으로 설정됨",
        "description": "공개 저장소 설정은 데이터 노출로 이어질 수 있습니다.",
        "recommendation": "private ACL을 기본값으로 두고, 공개가 필요한 경우 명시적 정책 검토를 남기세요.",
    },
    "config.terraform-public-access-block-disabled": {
        "title": "Terraform public access block이 비활성화됨",
        "description": "public access block 통제를 끄면 실수로 공개될 가능성이 커집니다.",
        "recommendation": "문서화된 공개 버킷 설계가 없다면 public access block을 유지하세요.",
    },
    "config.terraform-open-admin-port": {
        "title": "Terraform 보안그룹이 관리자 포트를 인터넷에 공개함",
        "description": "SSH/RDP를 0.0.0.0/0에 공개하면 초기 침투 경로가 될 수 있습니다.",
        "recommendation": "관리자 포트는 VPN, bastion, 승인된 CIDR로 제한하세요.",
    },
    "config.terraform-wildcard-iam-action": {
        "title": "Terraform IAM 정책이 wildcard action을 허용함",
        "description": "IAM action wildcard는 최소 권한 원칙을 약화시키고 권한 확대 위험을 키웁니다.",
        "recommendation": "필요한 최소 action만 명시하고 예외 사유를 문서화하세요.",
    },
    "config.terraform-wildcard-principal": {
        "title": "Terraform IAM 정책이 wildcard principal을 허용함",
        "description": "wildcard principal은 의도하지 않은 주체에게 접근을 허용할 수 있습니다.",
        "recommendation": "승인된 계정, 역할, 서비스 주체로 principal을 제한하세요.",
    },
    "config.terraform-public-ingress": {
        "title": "Terraform 보안그룹이 public ingress를 허용함",
        "description": "0.0.0.0/0 ingress는 관리자 포트가 아니어도 노출 범위 검토가 필요합니다.",
        "recommendation": "소스 CIDR을 의도한 클라이언트로 제한하거나 승인된 edge/load balancer 통제로 앞단을 제한하세요.",
    },
    "config.terraform-unencrypted-storage": {
        "title": "Terraform 저장소 암호화가 꺼져 있음",
        "description": "저장소 암호화를 끄면 디스크, 버킷, 스냅샷, 백업 접근 시 데이터가 노출될 수 있습니다.",
        "recommendation": "저장 시 암호화를 활성화하고 서비스별 예외는 문서화하세요.",
    },
    "config.terraform-sensitive-output": {
        "title": "Terraform output이 민감값을 노출할 수 있음",
        "description": "Terraform output은 state, 로그, CI 산출물에 남을 수 있습니다.",
        "recommendation": "민감 output에는 sensitive = true를 설정하고 원시 자격증명 출력을 피하세요.",
    },
    "config.github-pull-request-target": {
        "title": "GitHub Actions가 pull_request_target을 사용함",
        "description": "pull_request_target은 권한 있는 저장소 컨텍스트에서 실행되어 PR 코드와 함께 쓰면 위험합니다.",
        "recommendation": "비신뢰 PR 코드는 pull_request에서 실행하고, 권한 작업과 checkout/build 단계를 분리하세요.",
    },
    "config.github-untrusted-event-in-run": {
        "title": "GitHub Actions run 단계에 이벤트 데이터가 직접 삽입됨",
        "description": "PR 이벤트 필드는 공격자가 제어할 수 있는 문자열을 포함할 수 있습니다.",
        "recommendation": "이벤트 값은 환경변수로 전달하고 셸 사용 전에 quoting과 검증을 적용하세요.",
    },
    "config.android-debuggable": {
        "title": "Android 앱이 debuggable로 설정됨",
        "description": "릴리스 앱의 debuggable 설정은 런타임 조작과 정보 노출 위험을 높입니다.",
        "recommendation": "릴리스 빌드에서는 android:debuggable을 비활성화하고 빌드 타입별 설정을 분리하세요.",
    },
    "config.android-allow-backup": {
        "title": "Android 백업이 허용됨",
        "description": "민감 데이터가 포함된 앱에서 백업 허용은 로컬 데이터 유출 위험을 키울 수 있습니다.",
        "recommendation": "민감 앱은 백업을 비활성화하거나 백업 제외 규칙을 명확히 설정하세요.",
    },
    "config.android-cleartext-traffic": {
        "title": "Android cleartext traffic이 허용됨",
        "description": "평문 HTTP 통신은 네트워크 구간에서 변조와 도청 위험이 있습니다.",
        "recommendation": "HTTPS를 기본으로 강제하고 예외는 network security config로 제한하세요.",
    },
    "config.android-exported-component": {
        "title": "Android component가 exported로 설정됨",
        "description": "exported component는 외부 앱의 진입점이 될 수 있어 권한 검토가 필요합니다.",
        "recommendation": "의도한 component만 export하고 민감 component에는 permission을 요구하세요.",
    },
    "config.ios-ats-arbitrary-loads": {
        "title": "iOS ATS가 임의 네트워크 로드를 허용함",
        "description": "NSAllowsArbitraryLoads는 앱 전체의 전송 보안 기본값을 약화시킬 수 있습니다.",
        "recommendation": "ATS를 유지하고 필요한 예외는 검토된 도메인 단위로 제한하세요.",
    },
    "config.ios-file-sharing-enabled": {
        "title": "iOS 파일 공유가 활성화됨",
        "description": "UIFileSharingEnabled는 앱 문서를 사용자가 직접 접근할 수 있게 하므로 민감 파일 검토가 필요합니다.",
        "recommendation": "민감 문서가 아니라는 근거가 없다면 파일 공유를 비활성화하세요.",
    },
    "config.ios-open-documents-in-place": {
        "title": "iOS 문서 제자리 열기가 활성화됨",
        "description": "문서 provider 흐름에서 외부 앱과 파일 변경 범위가 넓어질 수 있습니다.",
        "recommendation": "문서 provider 흐름과 민감 파일 처리 범위를 검토하고 필요한 경우 제한하세요.",
    },
    "code.xss-dom-sink": {
        "title": "XSS 의심 HTML 출력 지점",
        "description": "사용자 입력으로 보이는 값이 HTML 렌더링 지점으로 전달되는 패턴입니다.",
        "recommendation": "텍스트 렌더링, 컨텍스트별 출력 인코딩, 검증된 sanitizer를 사용하세요.",
    },
    "code.sql-dynamic-query": {
        "title": "동적 SQL 쿼리로 인한 SQL 삽입 의심",
        "description": "SQL 문자열이 실행 직전에 동적으로 조립되는 패턴입니다.",
        "recommendation": "문자열 조합 대신 파라미터 바인딩이나 ORM의 안전한 쿼리 API를 사용하세요.",
    },
    "code.command-injection": {
        "title": "명령어 삽입 의심",
        "description": "셸 또는 프로세스 실행 API에 동적 입력이나 사용자 입력이 전달되는 패턴입니다.",
        "recommendation": "사용자 입력을 셸에 넘기지 말고, 고정된 인자 배열과 allowlist 검증을 사용하세요.",
    },
    "code.path-traversal": {
        "title": "경로 조작 의심",
        "description": "파일 시스템 API가 사용자 제어 경로 데이터를 사용하는 패턴입니다.",
        "recommendation": "허용된 기준 디렉터리 안에서 경로를 정규화하고, 상위 경로 이동을 차단하세요.",
    },
    "code.csrf-disabled": {
        "title": "CSRF 보호 비활성화 의심",
        "description": "라우트 또는 애플리케이션에서 CSRF 보호를 비활성화하는 패턴입니다.",
        "recommendation": "브라우저 인증을 쓰는 상태 변경 요청에는 CSRF 보호를 유지하거나 보완 통제를 문서화하세요.",
    },
    "code.auth-disabled-endpoint": {
        "title": "인증 또는 인가 우회 설정 의심",
        "description": "엔드포인트나 핸들러에서 인증 또는 인가를 명시적으로 우회하는 패턴입니다.",
        "recommendation": "정말 공개 엔드포인트인지 확인하고, 민감한 작업에는 인가 검사를 강제하세요.",
    },
    "code.eval-user-input": {
        "title": "eval 계열 API를 통한 코드 삽입 의심",
        "description": "사용자 입력이 동적 코드 실행 API로 전달되는 패턴입니다.",
        "recommendation": "동적 코드 실행을 제거하고, 허용된 작업만 고정 dispatch table로 처리하세요.",
    },
    "code.unsafe-deserialization": {
        "title": "위험한 역직렬화 API 사용",
        "description": "신뢰할 수 없는 데이터에 위험할 수 있는 역직렬화 API가 사용된 패턴입니다.",
        "recommendation": "안전한 파서를 사용하고, 역직렬화는 서명된 신뢰 입력으로 제한하세요.",
    },
    "code.ssrf-user-url": {
        "title": "사용자 제어 URL 요청으로 인한 SSRF 의심",
        "description": "서버 측 HTTP 클라이언트가 사용자 입력에서 온 URL을 요청하는 패턴입니다.",
        "recommendation": "허용된 호스트만 요청하고 사설망 대역을 차단하며 임의 URL 전달을 피하세요.",
    },
    "code.unrestricted-file-upload": {
        "title": "제한 없는 파일 업로드 의심",
        "description": "업로드 파일을 클라이언트가 제어하는 이름이나 느슨한 저장 설정으로 저장하는 패턴입니다.",
        "recommendation": "콘텐츠 타입과 확장자를 검증하고 서버 측 파일명을 생성하며 실행 경로 밖에 저장하세요.",
    },
    "code.dangerous-c-buffer-api": {
        "title": "위험한 C/C++ 버퍼 API 사용",
        "description": "버퍼 오버플로우와 자주 연결되는 오래된 C/C++ API가 사용된 패턴입니다.",
        "recommendation": "경계가 있는 대체 API를 사용하고 대상 버퍼 크기를 검증하세요.",
    },
    "code.integer-overflow-user-input": {
        "title": "외부 정수 입력의 범위 검증 누락 의심",
        "description": "외부 입력에서 파싱한 정수가 범위 확인 없이 배열 인덱스나 할당 크기에 사용되는 패턴입니다.",
        "recommendation": "인덱스·할당·산술에 사용하기 전에 하한과 상한을 모두 검증하세요.",
    },
    "code.security-decision-user-input": {
        "title": "외부 입력에 의한 보안·업무 결정 의심",
        "description": "역할, 권한, 가격 등의 결정값이 요청 입력에서 직접 전달되는 패턴입니다.",
        "recommendation": "결정값은 신뢰할 수 있는 서버측 상태에서 조회하고 외부 입력을 검증하세요.",
    },
    "code.authorization-check-missing": {
        "title": "중요 기능의 인가 검사 누락 의심",
        "description": "중요 엔드포인트나 메소드 주변에서 역할·소유권·권한 검사가 보이지 않습니다.",
        "recommendation": "민감 작업 전에 기능 수준과 객체 수준 인가를 모두 강제하세요.",
    },
    "code.insecure-resource-permissions": {
        "title": "중요 자원의 과도한 권한 설정",
        "description": "모든 사용자 쓰기 또는 전체 제어 권한을 명시적으로 부여하는 패턴입니다.",
        "recommendation": "필요한 서비스 계정에만 최소 읽기·쓰기 권한을 부여하세요.",
    },
    "code.weak-password-policy": {
        "title": "취약한 비밀번호 길이 정책",
        "description": "명시된 비밀번호 최소 길이가 8자보다 짧습니다.",
        "recommendation": "조직 정책에 맞는 최소 길이와 유출 비밀번호 차단 정책을 적용하세요.",
    },
    "code.uncontrolled-loop": {
        "title": "종료 경로 없는 반복문·재귀 의심",
        "description": "상수 조건 반복문 또는 직접 재귀에서 종료 경로가 보이지 않습니다.",
        "recommendation": "종료 조건, 제한 횟수, 시간 제한 또는 재귀 기저 조건을 추가하세요.",
    },
    "code.session-shared-state": {
        "title": "세션 데이터의 공유 상태 저장 의심",
        "description": "요청별 사용자 데이터가 모듈 전역 또는 서블릿·컨트롤러 인스턴스 필드에 저장됩니다.",
        "recommendation": "사용자 데이터는 요청·세션 범위에 유지하고 공유 가변 필드에 저장하지 마세요.",
    },
    "code.private-array-return": {
        "title": "Private 배열의 직접 반환",
        "description": "public 메소드가 private 배열 또는 가변 컬렉션 참조를 직접 반환합니다.",
        "recommendation": "clone, 불변 뷰 또는 방어적 복사본을 반환하세요.",
    },
    "code.private-array-assignment": {
        "title": "Public 데이터의 Private 배열 직접 할당",
        "description": "호출자가 소유한 배열 또는 가변 컬렉션 참조를 private 필드에 직접 저장합니다.",
        "recommendation": "저장 전에 입력을 clone하거나 방어적으로 복사하세요.",
    },
    "code.dangerous-managed-api": {
        "title": "위험한 Java/J2EE 또는 C# API 사용",
        "description": "가이드가 관리형 애플리케이션 문맥에서 취약하다고 제시한 API 사용 패턴입니다.",
        "recommendation": "직접 소켓·강제 프로세스 종료 대신 관리형 연결 API와 정상 종료 절차를 사용하세요.",
    },
    "code.unbounded-request-body": {
        "title": "요청 본문 크기 제한이 보이지 않음",
        "description": "명시적 크기 제한 없이 요청 본문 파서가 활성화된 패턴입니다.",
        "recommendation": "보수적인 요청 본문 크기 제한을 설정하고 과도한 요청은 초기에 거부하세요.",
    },
    "code.logging-sensitive-data": {
        "title": "민감정보 로깅 의심",
        "description": "로그 또는 콘솔 출력에 자격 증명, 토큰, 세션, 쿠키 정보가 포함될 수 있는 패턴입니다.",
        "recommendation": "민감값은 로그에서 제거하고, 필요한 경우 마스킹된 식별자나 안전한 이벤트 메타데이터만 남기세요.",
    },
    "code.empty-exception-handler": {
        "title": "빈 예외 처리 블록",
        "description": "예외를 기록하거나 복구하지 않고 무시하는 패턴입니다.",
        "recommendation": "예상 가능한 예외만 명시적으로 처리하고, 보안상 중요한 실패는 정제된 컨텍스트로 기록하세요.",
    },
    "code.stack-trace-exposure": {
        "title": "스택 트레이스 노출 의심",
        "description": "애플리케이션 코드에서 원시 스택 트레이스를 출력할 수 있는 패턴입니다.",
        "recommendation": "중앙화된 오류 처리로 라우팅하고 로컬 디버깅 외에는 원시 스택 트레이스를 출력하지 마세요.",
    },
    "code.unversioned-api-route": {
        "title": "버전 없는 API 라우트",
        "description": "공개 API로 보이는 라우트에 명시적인 버전 경로가 없는 패턴입니다.",
        "recommendation": "공개 API를 인벤토리화하고 /api/v1/... 같은 명시적 버전 경로를 사용하세요.",
    },
    "code.insecure-temp-file": {
        "title": "안전하지 않은 임시 파일 사용",
        "description": "예측 가능한 임시 파일명 또는 직접 지정한 /tmp 경로를 파일 작업에 사용하는 패턴입니다.",
        "recommendation": "원자적으로 파일을 생성하는 안전한 임시 파일 API를 사용하고 예측 가능한 공유 경로를 피하세요.",
    },
    "code.wildcard-cors": {
        "title": "와일드카드 CORS 허용",
        "description": "모든 출처의 요청을 허용하는 CORS 설정 패턴입니다.",
        "recommendation": "신뢰할 수 있는 애플리케이션 도메인만 허용하고, 자격 증명 허용과 와일드카드 출처를 함께 사용하지 마세요.",
    },
    "code.public-bind-all-interfaces": {
        "title": "모든 인터페이스 바인딩",
        "description": "서비스가 모든 네트워크 인터페이스에서 수신하도록 설정된 패턴입니다.",
        "recommendation": "개발 서비스는 기본적으로 localhost에 바인딩하고, 외부 노출은 명시적 설정으로만 허용하세요.",
    },
    "code.insecure-cookie-settings": {
        "title": "안전하지 않은 쿠키 설정",
        "description": "세션 쿠키의 Secure 또는 HttpOnly 보호가 비활성화된 것으로 보이는 패턴입니다.",
        "recommendation": "세션 쿠키에 Secure, HttpOnly, 적절한 SameSite 속성을 설정하고 로컬 개발 외에는 약화하지 마세요.",
    },
    "code.jwt-verification-disabled": {
        "title": "JWT 서명 검증이 비활성화된 것으로 보임",
        "description": "JWT decode 또는 검증 설정에서 서명 검증이 꺼져 있을 수 있습니다.",
        "recommendation": "모든 JWT에 대해 서명, issuer, audience, 만료, 알고리즘 검증을 강제하세요.",
    },
    "code.jwt-none-algorithm": {
        "title": "JWT none 알고리즘 허용 의심",
        "description": "JWT 설정이 서명 없는 none 알고리즘을 허용할 수 있습니다.",
        "recommendation": "승인된 서명 알고리즘 allowlist만 허용하고 unsigned token은 거부하세요.",
    },
    "code.session-long-expiry": {
        "title": "세션 또는 토큰 만료 시간이 과도함",
        "description": "애플리케이션 자격증명으로 쓰이는 세션이나 토큰 수명이 매우 길어 보입니다.",
        "recommendation": "짧은 access token, 회전되는 refresh token, 장기 세션 예외 문서를 사용하세요.",
    },
    "code.api-route-missing-auth": {
        "title": "민감 API 라우트에 인증 가드가 보이지 않음",
        "description": "관리자, 사용자, 계정, 결제 등 민감 API 라우트가 명시적 인증/인가 가드 없이 선언된 것으로 보입니다.",
        "recommendation": "민감 API handler 실행 전에 라우트 수준 인증과 객체/기능 권한 검사를 강제하세요.",
    },
    "code.api-mass-assignment": {
        "title": "API 요청 body의 mass assignment 의심",
        "description": "요청 body가 모델 생성/수정/저장 호출에 직접 전달되는 패턴입니다.",
        "recommendation": "허용 필드만 명시적으로 매핑하고 예상하지 않은 속성은 저장 전에 거부하세요.",
    },
    "code.api-missing-rate-limit": {
        "title": "API rate limit 기준이 보이지 않음",
        "description": "API framework bootstrap이 있으나 이 라인에서 rate limit 또는 quota 통제가 확인되지 않습니다.",
        "recommendation": "로그인, 가입, 비밀번호 재설정, 검색, export, 고비용 API에 rate limit과 남용 방지 통제를 추가하세요.",
    },
    "code.external-api-no-timeout": {
        "title": "외부 API 호출에 timeout이 보이지 않음",
        "description": "외부 API 호출에 명시적 timeout 또는 abort signal이 없어 장애 전파와 리소스 고갈 위험이 있습니다.",
        "recommendation": "외부 API 호출에 timeout, backoff 재시도, 목적지 allowlist를 적용하세요.",
    },
    "code.pii-logging": {
        "title": "개인정보 로깅 의심",
        "description": "로그 또는 콘솔 출력에 이메일, 전화번호, 주소, 주민번호 등 개인정보 필드가 포함될 수 있습니다.",
        "recommendation": "개인정보는 로그에서 제거하거나 마스킹하고 보관 기간과 접근 권한을 문서화하세요.",
    },
    "code.directory-listing-enabled": {
        "title": "디렉터리 리스팅 활성화 의심",
        "description": "웹 서버 설정에서 디렉터리 목록 노출이 활성화된 것으로 보이는 패턴입니다.",
        "recommendation": "디렉터리 리스팅을 비활성화하고 의도한 파일만 통제된 라우트나 정적 자산 설정으로 제공하세요.",
    },
    "code.webdav-enabled": {
        "title": "WebDAV 활성화 의심",
        "description": "WebDAV 또는 HTTP PUT 기반 게시 기능이 활성화된 것으로 보이는 패턴입니다.",
        "recommendation": "명시적으로 필요하지 않다면 WebDAV를 비활성화하고, 필요한 경우 인증과 네트워크 통제로 제한하세요.",
    },
    "code.legacy-board-software": {
        "title": "레거시 게시판 소프트웨어 흔적",
        "description": "과거 반복적인 웹 침해와 연결되었던 레거시 게시판 소프트웨어 흔적이 포함된 패턴입니다.",
        "recommendation": "실제 사용 여부를 확인하고, 업데이트 또는 제거하며 업로드/다운로드 기능은 보완 통제 뒤로 격리하세요.",
    },
    "code.weak-hash": {
        "title": "약한 해시 알고리즘 사용 의심",
        "description": "비밀번호, 서명, 무결성 확인에 부적절할 수 있는 MD5 또는 SHA-1 사용 패턴입니다.",
        "recommendation": "자격 증명에는 전용 비밀번호 해시를 사용하고, 무결성에는 필요한 경우 SHA-256 이상 승인 알고리즘을 사용하세요.",
    },
    "code.xml-external-entity": {
        "title": "XML 외부 엔티티 처리 위험",
        "description": "외부 엔티티 처리를 비활성화하지 않으면 위험할 수 있는 XML 파서 사용 패턴입니다.",
        "recommendation": "DTD와 외부 엔티티 해석을 비활성화하거나 신뢰할 수 없는 XML에는 강화된 파서 설정을 사용하세요.",
    },
    "code.open-redirect-user-input": {
        "title": "사용자 입력 기반 오픈 리다이렉트 가능성",
        "description": "리다이렉트 대상 URL이 허용 목록 없이 사용자 입력으로 구성되는 것으로 보입니다.",
        "recommendation": "허용된 내부 경로로만 리다이렉트하거나, 사용자 입력을 고정된 목적지에 매핑하세요.",
    },
    "code.xml-injection": {
        "title": "문자열 조립을 통한 XML 삽입 가능성",
        "description": "사용자 입력이 이스케이프 없이 XML 본문에 문자열 연결로 삽입되는 것으로 보입니다.",
        "recommendation": "XML 직렬화 라이브러리를 사용하거나 사용자 입력을 XML 규칙에 맞게 이스케이프하세요.",
    },
    "code.ldap-injection": {
        "title": "LDAP 필터 조립을 통한 LDAP 삽입 가능성",
        "description": "LDAP 검색 필터가 이스케이프 없이 동적 입력으로 조립되는 것으로 보입니다.",
        "recommendation": "LDAP 필터 메타문자를 이스케이프하거나 파라미터화된 LDAP 질의 API를 사용하세요.",
    },
    "code.http-response-splitting": {
        "title": "HTTP 응답분할 가능성",
        "description": "사용자 입력이 CR/LF 필터링 없이 HTTP 응답 헤더로 전달되는 것으로 보입니다.",
        "recommendation": "헤더에 쓰기 전 CR/LF 문자를 제거·거부하고 사용자 입력을 검증하세요.",
    },
    "code.format-string-user-input": {
        "title": "포맷 스트링이 외부에서 제어될 가능성",
        "description": "변수가 포맷 문자열로 직접 사용되어 포맷 지시자 삽입이 가능할 수 있습니다.",
        "recommendation": "고정된 포맷 문자열을 사용하고 동적 데이터는 인자로 전달하세요. 예: printf(\"%s\", value)",
    },
    "code.insufficient-key-length": {
        "title": "충분하지 않은 암호 키 길이",
        "description": "비대칭 키가 2048비트 미만으로 생성되는 것으로 보입니다.",
        "recommendation": "새 키는 RSA/DSA/DH 2048비트 이상 또는 최신 타원곡선 알고리즘을 사용하세요.",
    },
    "code.insecure-random-security-use": {
        "title": "보안 문맥에서 비암호학적 난수 사용",
        "description": "토큰·인증코드 등 보안 목적 값이 비암호학적 난수 API로 생성되는 것으로 보입니다.",
        "recommendation": "토큰, 코드, 키, 솔트에는 CSPRNG(secrets, SecureRandom, crypto.randomBytes 등)를 사용하세요.",
    },
    "code.tls-certificate-verification-disabled": {
        "title": "TLS 인증서 검증 비활성화",
        "description": "외부 연결에서 인증서 또는 호스트명 검증이 꺼져 있는 것으로 보입니다.",
        "recommendation": "인증서·호스트명 검증을 항상 유지하고, 검증을 끄는 대신 올바른 신뢰 앵커를 구성하세요.",
    },
    "code.password-hash-without-salt": {
        "title": "솔트 없는 비밀번호 해시 가능성",
        "description": "자격증명이 전용 KDF 없이 빠른 해시 함수로 직접 해싱되는 것으로 보입니다.",
        "recommendation": "bcrypt, scrypt, Argon2, PBKDF2 같은 솔트 적용 KDF로 비밀번호를 해싱하세요.",
    },
    "code.null-pointer-dereference": {
        "title": "NULL 포인터 역참조 가능성",
        "description": "null이거나 null을 반환할 수 있는 조회 결과가 방어 처리 없이 참조되는 것으로 보입니다.",
        "recommendation": "참조 전에 null을 검사하고, non-null 반환 계약이나 Objects.requireNonNull·Optional.orElseThrow 같은 실패 폐쇄형 처리를 사용하세요.",
    },
    "secret.sensitive-comment": {
        "title": "주석 안에 포함된 민감정보",
        "description": "주석에 자격증명으로 보이는 값이 남아 있습니다. 발견 증거는 마스킹되어 표시됩니다.",
        "recommendation": "주석에서 자격증명을 제거하고, 실제 값이었다면 즉시 교체하세요.",
    },
    "code.llm-prompt-user-concat": {
        "title": "LLM 프롬프트에 사용자 입력이 직접 결합됨",
        "description": "사용자 제어 입력이 system/developer prompt 또는 메시지 구성에 직접 섞이는 패턴입니다.",
        "recommendation": "시스템 지시는 고정하고 사용자 콘텐츠는 별도 메시지 필드로 분리하며 프롬프트 인젝션 테스트를 추가하세요.",
    },
    "code.llm-tool-unrestricted": {
        "title": "LLM 도구 호출 권한이 넓게 열려 있음",
        "description": "모델이 셸, 파일, 브라우저, HTTP, 데이터베이스 같은 광범위한 도구를 제한 없이 호출할 수 있는 패턴입니다.",
        "recommendation": "작업별 도구 allowlist, 인자 검증, 부작용 작업 확인, 도구 호출 로그를 적용하세요.",
    },
    "code.llm-sensitive-data-in-prompt": {
        "title": "민감정보가 LLM 프롬프트로 전달될 수 있음",
        "description": "credential, token, cookie, session 같은 민감 필드가 LLM 요청에 포함될 수 있는 패턴입니다.",
        "recommendation": "LLM 호출 전 민감값을 제거하거나 마스킹하고 프롬프트가 로컬 신뢰 경계를 벗어나는지 문서화하세요.",
    },
    "dependency.osv-known-vulnerability": {
        "title": "알려진 취약 의존성",
        "description": "취약점 데이터베이스가 이 정확한 의존성 버전의 알려진 취약점을 보고했습니다.",
        "recommendation": "취약점 식별자를 확인한 뒤 업그레이드, 패치, 대체, 또는 보완 통제를 문서화하세요.",
    },
}


def filter_by_min_severity(findings: list[Finding], min_severity: str) -> list[Finding]:
    threshold = SEVERITY_RANK[min_severity]
    return [finding for finding in findings if SEVERITY_RANK[finding.severity] >= threshold]


def render_report(
    findings: list[Finding],
    report_format: str,
    target_names: tuple[str, ...] = (),
    language: str = "en",
    *,
    target_paths: dict[str, str] | None = None,
    components: tuple[DependencyComponent, ...] = (),
    warnings: tuple[str, ...] = (),
    standard: str = DEFAULT_STANDARD,
    standard_category: str = DEFAULT_STANDARD_CATEGORY,
    scanned_categories: tuple[str, ...] = (),
    source_analysis: object | None = None,
) -> str:
    if report_format == "cyclonedx":
        return render_cyclonedx(components)
    if report_format == "nis-sbom":
        return render_nis_sbom(components, product_name=target_names[0] if target_names else "KODA scan")
    if report_format == "cyclonedx-vex":
        return render_cyclonedx_vex(findings)
    if report_format == "json":
        return render_json(
            findings,
            target_names,
            language,
            target_paths=target_paths,
            components=components,
            warnings=warnings,
            standard=standard,
            standard_category=standard_category,
            scanned_categories=scanned_categories,
            source_analysis=source_analysis,
        )
    if report_format == "markdown":
        report = render_markdown(
            findings,
            target_names,
            language,
            target_paths=target_paths,
            standard_mappings=_rule_mappings_for_findings(findings, standard, standard_category),
            source_analysis=source_analysis,
        )
        if standard == "sw-dev-security-49":
            sw49 = sw49_payload(findings, scanned_categories, standard_category, source_analysis)
            report = report.rstrip("\n") + "\n" + "\n".join(_sw49_markdown_lines(sw49, language)) + "\n"
        return report
    if report_format == "html":
        return render_html(
            findings,
            target_names,
            language,
            target_paths=target_paths,
            components=components,
            warnings=warnings,
            standard=standard,
            standard_category=standard_category,
            scanned_categories=scanned_categories,
            source_analysis=source_analysis,
        )
    if report_format == "sarif":
        return render_sarif(findings, source_analysis=source_analysis)
    raise ValueError(f"Unsupported report format: {report_format}")


def render_json(
    findings: list[Finding],
    target_names: tuple[str, ...] = (),
    language: str = "en",
    *,
    target_paths: dict[str, str] | None = None,
    components: tuple[DependencyComponent, ...] = (),
    warnings: tuple[str, ...] = (),
    standard: str = DEFAULT_STANDARD,
    standard_category: str = DEFAULT_STANDARD_CATEGORY,
    scanned_categories: tuple[str, ...] = (),
    source_analysis: object | None = None,
) -> str:
    all_mappings = _rule_mappings_for_findings(findings, standard, standard_category)
    payload = {
        "generated_at": _generated_at()[0],
        "language": _labels(language)["html_lang"],
        "scanner": {"name": "KODA", "version": __version__},
        "summary": _summary(findings, target_names, target_paths, source_analysis),
        "warnings": list(warnings),
        "components": [component_payload(component) for component in components],
        "findings": [
            _finding_payload(finding, all_mappings.get(finding.rule_id, ()))
            for finding in findings
        ],
    }
    if source_analysis is not None:
        payload["source_analysis"] = _source_analysis_payload(source_analysis)
    if standard == "sw-dev-security-49":
        payload["sw49"] = sw49_payload(findings, scanned_categories, standard_category, source_analysis)
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_markdown(
    findings: list[Finding],
    target_names: tuple[str, ...] = (),
    language: str = "en",
    *,
    target_paths: dict[str, str] | None = None,
    standard_mappings: dict[str, list[dict[str, object]]] | None = None,
    source_analysis: object | None = None,
) -> str:
    labels = _labels(language)
    generated_at, generated_display = _generated_at()
    summary = _summary(findings, target_names, target_paths, source_analysis)
    lines = [
        f"# {labels['report_heading']}",
        "",
        f"{labels['generated']}: {generated_display}",
        "",
        f"## {labels['summary']}",
        "",
        f"- {labels['total_findings']}: {len(findings)}",
        f"- {labels['scanned_targets']}: {summary['target_count']}",
        f"- {labels['risk_score']}: {summary['risk_score']}",
    ]
    for severity in reversed(SEVERITIES):
        count = summary["by_severity"].get(severity, 0)
        if count:
            lines.append(f"- {labels['severity_labels'][severity]}: {count}")
    for category, count in sorted(summary["by_category"].items()):
        lines.append(f"- {_category_label(category, language)}: {count}")
    for target, count in sorted(summary["by_target"].items()):
        if target:
            lines.append(f"- {labels['target']} `{_target_display(target, summary)}`: {count}")
    if source_analysis is not None:
        analysis = _source_analysis_payload(source_analysis)
        lines.extend(["", "- Source analysis coverage: " + str(analysis.get("coverage_status") or analysis.get("status") or "recorded")])

    if not findings:
        lines.extend(["", str(labels["no_threshold_findings"])])
        return "\n".join(lines) + "\n"

    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.severity].append(finding)

    for severity in reversed(SEVERITIES):
        severity_findings = grouped.get(severity, [])
        if not severity_findings:
            continue
        lines.extend(["", f"## {labels['severity_labels'][severity]} {labels['findings']}", ""])
        for finding in severity_findings:
            location = str(finding.path)
            if finding.line:
                location = f"{location}:{finding.line}"
            display = _localized_finding_payload(finding, language)
            lines.extend(
                [
                    f"### {display['title']}",
                    "",
                    f"- {labels['rule']}: `{finding.rule_id}`",
                    f"- {labels['category']}: `{_category_label(finding.category, language)}`",
                    f"- {labels['target']}: `{_target_display(finding.target, summary)}`",
                    f"- {labels['location']}: `{location}`",
                    f"- {'판정' if language == 'ko' else 'Verification'}: `{_source_verification_label(finding.verification_status, language)}`",
                ]
            )
            if finding.verification_note:
                lines.append(f"- {'판정 근거' if language == 'ko' else 'Verification note'}: {finding.verification_note}")
            if finding.evidence:
                lines.append(f"- {labels['evidence']}: `{finding.evidence}`")
            mapping_texts = [
                _standard_mapping_text(mapping, language)
                for mapping in (standard_mappings or {}).get(finding.rule_id, ())
                if isinstance(mapping, dict)
            ]
            mapping_texts = list(dict.fromkeys(text for text in mapping_texts if text))
            if mapping_texts:
                mapping_label = "공식 점검 기준" if language == "ko" else "Official criteria"
                lines.append(f"- {mapping_label}: " + "; ".join(mapping_texts))
            if display["description"]:
                lines.append(f"- {labels['why_it_matters']}: {display['description']}")
            if display["recommendation"]:
                lines.append(f"- {labels['recommendation']}: {display['recommendation']}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_sarif(findings: list[Finding], *, source_analysis: object | None = None) -> str:
    rules_by_id: dict[str, Finding] = {}
    for finding in findings:
        rules_by_id.setdefault(finding.rule_id, finding)

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "KODA",
                        "semanticVersion": __version__,
                        "rules": [_sarif_rule(finding) for finding in rules_by_id.values()],
                    }
                },
                "results": [_sarif_result(finding) for finding in findings],
            }
        ],
    }
    if source_analysis is not None:
        payload["runs"][0]["properties"] = {"koda.source_analysis": _source_analysis_payload(source_analysis)}
    return json.dumps(payload, indent=2, ensure_ascii=False)


def filter_disabled_rules(findings: list[Finding], disabled_rules: object) -> list[Finding]:
    """Drop findings whose rule_id the user turned off in Settings (post-scan filter)."""
    disabled = {str(item) for item in disabled_rules} if disabled_rules else set()
    if not disabled:
        return findings
    return [finding for finding in findings if finding.rule_id not in disabled]


# --- Rule catalog (single source for the Settings popup on web + macOS) ---------

# Master set of toggleable file-scan security rules. Standard groups list only
# these (host-only / evidence-only mappings are excluded from the toggle list).
_KNOWN_SECURITY_RULE_IDS = frozenset(
    SECRET_RULE_IDS
    + SENSITIVE_COMMENT_RULE_IDS
    + DEPENDENCY_RULE_IDS
    + CONFIGURATION_RULE_IDS
    + CODE_PATTERN_RULE_IDS
    + PREVENTION_RULE_IDS
)

_QUALITY_RULE_GROUPS = (("screen_quality", SCREEN_QUALITY_RULE_IDS),)

# screen.* rules are not in RULE_TRANSLATIONS_KO; keep their KO titles here.
_SCREEN_KO_META = {
    "screen.html-lang-missing": {"title": "HTML 언어가 선언되지 않음", "description": "html 요소에 lang 속성이 없으면 접근성과 검색 처리가 저하됩니다."},
    "screen.viewport-missing": {"title": "반응형 viewport 메타 태그가 없음", "description": "viewport 메타 태그가 없으면 모바일 화면 대응이 어렵습니다."},
    "screen.image-alt-missing": {"title": "이미지에 대체 텍스트가 없음", "description": "alt 텍스트가 없으면 스크린리더 사용자가 이미지를 이해할 수 없습니다."},
    "screen.input-label-missing": {"title": "입력 필드에 접근 가능한 레이블이 없음", "description": "레이블이 없는 입력은 보조 기술에서 용도를 알 수 없습니다."},
    "screen.button-type-missing": {"title": "버튼 type이 명시되지 않음", "description": "type이 없는 버튼은 폼에서 의도치 않게 submit될 수 있습니다."},
    "screen.link-target-empty": {"title": "링크 대상이 비어 있거나 자리표시자임", "description": "빈 href 링크는 키보드/스크린리더 탐색을 방해합니다."},
    "screen.sensitive-text-exposed": {"title": "화면 소스에 민감 텍스트가 노출됨", "description": "클라이언트 렌더링 소스에 비밀값이나 민감 정보가 남아 있습니다."},
    "screen.system-path-exposed": {"title": "화면 소스에 시스템 경로가 노출됨", "description": "내부 시스템 경로가 사용자 화면 소스에 드러나 있습니다."},
}


def _humanize_rule_id(rule_id: str) -> str:
    tail = rule_id.split(".", 1)[-1]
    return tail.replace("-", " ").replace("_", " ").strip().capitalize() or rule_id


def _catalog_rule(rule_id: str, language: str) -> dict[str, str]:
    if language == "ko":
        meta = RULE_TRANSLATIONS_KO.get(rule_id) or _SCREEN_KO_META.get(rule_id)
        if meta:
            return {"id": rule_id, "title": str(meta["title"]), "description": str(meta.get("description", ""))}
    return {"id": rule_id, "title": _humanize_rule_id(rule_id), "description": ""}


def _standard_rule_ids(standard: object) -> list[str]:
    """Deduplicated toggleable rule ids a standard maps to, in first-seen order."""
    seen: list[str] = []
    for category in standard.categories:
        for rule_id in category.rule_ids:
            if rule_id in _KNOWN_SECURITY_RULE_IDS and rule_id not in seen:
                seen.append(rule_id)
    return seen


def build_rule_catalog(language: str = "ko") -> list[dict[str, object]]:
    """Grouped rule catalog for the Settings popup.

    Security rules are grouped by standard (기준별) -- e.g. "소프트웨어 개발보안 49" --
    listing each standard's own rules. Quality rules stay grouped by category.
    """
    labels = _labels(language)
    category_labels = labels.get("category_labels", {})
    if not isinstance(category_labels, dict):
        category_labels = {}
    groups: list[dict[str, object]] = []

    for standard in SECURITY_STANDARDS:
        # The default "local" profile is every toggleable rule at once; the
        # per-standard groups below already cover all of them.
        if standard.id == DEFAULT_STANDARD:
            continue
        rule_ids = _standard_rule_ids(standard)
        if not rule_ids:
            continue
        label = standard.labels.get(language) or standard.labels.get("en") or standard.id
        groups.append(
            {
                "key": standard.id,
                "kind": "security",
                "label": str(label),
                "rules": [_catalog_rule(rule_id, language) for rule_id in rule_ids],
            }
        )

    for key, rule_ids in _QUALITY_RULE_GROUPS:
        groups.append(
            {
                "key": key,
                "kind": "quality",
                "label": str(category_labels.get(key, key)),
                "rules": [_catalog_rule(rule_id, language) for rule_id in rule_ids],
            }
        )
    return groups


# --- Downloadable exports built from the dashboard payload (stdlib only) --------

_EXPORT_COLUMNS = {
    "en": ("Severity", "Category", "Rule", "Title", "Path", "Line", "Official criteria / CWE", "Recommendation"),
    "ko": ("심각도", "분류", "룰", "제목", "경로", "줄", "공식 점검 기준 / CWE", "권장 조치"),
}


def _finding_from_payload(item: dict[str, object]) -> Finding:
    severity = str(item.get("severity", "info"))
    if severity not in SEVERITIES:
        severity = "info"
    line = item.get("line")
    return Finding(
        rule_id=str(item.get("rule_id", "")),
        category=str(item.get("category", "")),
        severity=severity,
        title=str(item.get("title", "")),
        path=Path(str(item.get("path", "."))),
        target=str(item.get("target", "")),
        line=int(line) if isinstance(line, int) else None,
        evidence=str(item.get("evidence", "")),
        description=str(item.get("description", "")),
        recommendation=str(item.get("recommendation", "")),
        resource=str(item.get("resource", "")),
        verification_status=str(item.get("verification_status", "confirmed")),
        verification_note=str(item.get("verification_note", "")),
        analyzer=str(item.get("analyzer", "koda-local")),
        analyzer_version=str(item.get("analyzer_version", "")),
        analyzer_rule_id=str(item.get("analyzer_rule_id", "")),
        cwe_ids=tuple(str(value) for value in item.get("cwe_ids", ()) if isinstance(value, str)) if isinstance(item.get("cwe_ids", ()), (list, tuple)) else (),
        evidence_kind=str(item.get("evidence_kind", "direct")),
        trace=tuple(value for value in item.get("trace", ()) if isinstance(value, dict)) if isinstance(item.get("trace", ()), (list, tuple)) else (),
        evidence_id=str(item.get("evidence_id", "")),
        issue_key=str(item.get("issue_key", "")),
    )


def _payload_report_context(
    payload: dict[str, object],
    findings: list[Finding],
) -> tuple[tuple[str, ...], dict[str, str], tuple[DependencyComponent, ...], dict[str, object]]:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    scan = payload.get("scan") if isinstance(payload.get("scan"), dict) else {}
    raw_targets = summary.get("by_target")
    target_names = (
        tuple(str(target) for target in raw_targets if str(target).strip())
        if isinstance(raw_targets, dict) and raw_targets
        else tuple(sorted({finding.target for finding in findings if finding.target}))
    )
    raw_paths = summary.get("target_paths")
    target_paths = (
        {str(target): str(path) for target, path in raw_paths.items()}
        if isinstance(raw_paths, dict)
        else {}
    )
    raw_components = payload.get("components")
    components: list[DependencyComponent] = []
    if isinstance(raw_components, list):
        for item in raw_components:
            if not isinstance(item, dict):
                continue
            line = item.get("line")
            components.append(
                DependencyComponent(
                    name=str(item.get("name") or ""),
                    ecosystem=str(item.get("ecosystem") or ""),
                    version=str(item.get("version") or ""),
                    path=Path(str(item.get("path") or ".")),
                    target=str(item.get("target") or ""),
                    line=int(line) if isinstance(line, int) and not isinstance(line, bool) else None,
                    scope=str(item.get("scope") or "required"),
                    source=str(item.get("source") or ""),
                    purl=str(item.get("purl") or ""),
                )
            )
    return target_names, target_paths, tuple(components), scan


def render_markdown_from_payload(payload: dict[str, object], language: str = "ko") -> str:
    findings = [_finding_from_payload(item) for item in _payload_findings(payload, language)]
    target_names, target_paths, _, scan = _payload_report_context(payload, findings)
    standard = str(scan.get("standard") or DEFAULT_STANDARD)
    standard_category = str(scan.get("standard_category") or DEFAULT_STANDARD_CATEGORY)
    mappings = _rule_mappings_for_findings(findings, standard, standard_category)
    report = render_markdown(
        findings,
        target_names,
        language,
        target_paths=target_paths,
        standard_mappings=mappings,
        source_analysis=payload.get("source_analysis"),
    )
    if standard == "sw-dev-security-49":
        sw49 = _payload_sw49(payload) or sw49_payload(
            findings,
            tuple(str(item) for item in scan.get("scanned_categories", ()) if str(item).strip()),
            standard_category,
            payload.get("source_analysis"),
        )
        report = report.rstrip("\n") + "\n" + "\n".join(_sw49_markdown_lines(sw49, language)) + "\n"
    web_audit = payload.get("web_audit")
    if isinstance(web_audit, dict):
        report = report.rstrip("\n") + "\n\n" + render_web_audit_markdown(web_audit, language=language)
    return report


def render_web_audit_markdown(result: dict[str, object], language: str = "ko") -> str:
    """Render the redacted 21-control result for CLI and dashboard exports."""
    controls = result.get("controls") if isinstance(result.get("controls"), list) else []
    korean = language == "ko"
    title = "웹취약점 21개 항목 자동 점검" if korean else "21-control web vulnerability audit"
    headers = "| ID | 항목 | 상태 | 실행 | 커버리지 | 사유 |\n|---|---|---|---:|---:|---|" if korean else "| ID | Control | Status | Executed | Coverage | Reason |\n|---|---|---|---:|---:|---|"
    lines = [f"## {title}", "", f"- Overall: `{result.get('status', 'NOT_SCANNED')}`", "", headers]
    for item in controls:
        if not isinstance(item, dict):
            continue
        coverage = item.get("coverage") if isinstance(item.get("coverage"), dict) else {}
        required = coverage.get("required", 0)
        completed = coverage.get("completed", 0)
        lines.append(
            f"| `{_web_audit_markdown_escape(str(item.get('id', '')))}` | {_web_audit_markdown_escape(str(item.get('title', '')))} | "
            f"`{_web_audit_markdown_escape(str(item.get('status', 'NOT_SCANNED')))}` | "
            f"{'yes' if item.get('executed') else 'no'} | {completed}/{required} | "
            f"{_web_audit_markdown_escape(str(item.get('reason_code', '')))} |"
        )
    traffic = result.get("traffic") if isinstance(result.get("traffic"), dict) else {}
    lines.extend(["", f"- Requests: `{traffic.get('requests', 0)}`", f"- Pages: `{traffic.get('pages', 0)}`", ""])
    return "\n".join(lines)


def _web_audit_markdown_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def render_html_pair_zip_from_payload(payload: dict[str, object], language: str = "ko") -> bytes:
    """Export the dashboard findings as a linked main/detail HTML pair."""
    findings = [_finding_from_payload(item) for item in _payload_findings(payload, language)]
    target_names, target_paths, components, scan = _payload_report_context(payload, findings)
    standard = str(scan.get("standard") or DEFAULT_STANDARD)
    standard_category = str(scan.get("standard_category") or DEFAULT_STANDARD_CATEGORY)
    raw_warnings = scan.get("warnings")
    warnings = tuple(str(item) for item in raw_warnings if str(item).strip()) if isinstance(raw_warnings, (list, tuple)) else ()
    kind = "library" if scan.get("scope") == "library" else str(scan.get("kind") or "source")
    main_html, detail_html = render_html_pair(
        findings,
        target_names=target_names,
        target_paths=target_paths,
        language=language,
        detail_href="report-detail.html",
        summary_href=None,
        components=components,
        scan_path=str(scan.get("path") or ", ".join(target_paths.values())),
        kind=kind,
        standard=standard,
        standard_category=standard_category,
        warnings=warnings,
        enable_osv=bool(scan.get("enable_osv", False)),
        scanned_categories=tuple(str(item) for item in scan.get("scanned_categories", ()) if str(item).strip()),
        source_analysis=payload.get("source_analysis"),
    )
    web_audit = payload.get("web_audit")
    if isinstance(web_audit, dict):
        audit_html = _web_audit_html(web_audit, language)
        main_html = main_html.replace("</main>", f"{audit_html}</main>", 1)
        detail_html = detail_html.replace("</main>", f"{audit_html}</main>", 1)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.html", main_html)
        archive.writestr("report-detail.html", detail_html)
    return buffer.getvalue()


def _payload_sw49(payload: dict[str, object]) -> dict[str, object] | None:
    sw49 = payload.get("sw49")
    if isinstance(sw49, dict) and isinstance(sw49.get("controls"), list) and sw49["controls"]:
        return sw49
    return None


def _sw49_display_row(entry: dict[str, object], language: str) -> dict[str, str]:
    labels = _labels(language)
    status_labels = labels.get("sw49_status_labels", {})
    support_labels = labels.get("sw49_support_labels", {})
    category_labels = entry.get("category_labels", {})
    title = entry.get("title", {})
    notes = entry.get("notes", {})
    status = str(entry.get("status", ""))
    support = str(entry.get("support_level", ""))
    guide_id = str(entry.get("guide_id", "")).strip()
    koda_id = str(entry.get("official_id", "")).strip()
    display_id = f"{guide_id} ({koda_id})" if guide_id and koda_id else guide_id or koda_id
    if status == "NOT_APPLICABLE":
        executed = str(status_labels.get(status, status)) if isinstance(status_labels, dict) else status
    else:
        executed = str(labels.get("sw49_executed_yes", "Run")) if entry.get("executed") else str(labels.get("sw49_executed_no", "Not run"))
    return {
        "official_id": display_id,
        "category": str(category_labels.get(language) or category_labels.get("en") or entry.get("category_id", "")) if isinstance(category_labels, dict) else str(entry.get("category_id", "")),
        "title": str(title.get(language) or title.get("en") or "") if isinstance(title, dict) else str(title),
        "cwe": ", ".join(str(item) for item in entry.get("cwe_ids", [])),
        "support": str(support_labels.get(support, support)) if isinstance(support_labels, dict) else support,
        "executed": executed,
        "status": str(status_labels.get(status, status)) if isinstance(status_labels, dict) else status,
        "rules": ", ".join(str(item) for item in entry.get("rule_ids", [])),
        "finding_count": str(entry.get("finding_count", 0)),
        "evidence": ", ".join(str(item) for item in entry.get("evidence", [])),
        "notes": str(notes.get(language) or notes.get("en") or "") if isinstance(notes, dict) else "",
    }


_SW49_COLUMN_KEYS = ("official_id", "category", "title", "cwe", "support", "executed", "status", "rules", "finding_count", "evidence", "notes")


def _sw49_summary_lines(sw49: dict[str, object], language: str) -> list[str]:
    labels = _labels(language)
    summary_labels = labels.get("sw49_summary_labels", {})
    status_labels = labels.get("sw49_status_labels", {})
    support_counts = sw49.get("support_counts", {})
    status_counts = sw49.get("status_counts", {})
    lines = [f"- {summary_labels.get('total', 'Official controls')}: {sw49.get('total', 0)}"]
    if isinstance(support_counts, dict):
        for level in SW49_SUPPORT_LEVELS:
            lines.append(f"- {summary_labels.get(level, level)}: {support_counts.get(level, 0)}")
    if isinstance(status_counts, dict):
        for status in SW49_STATUSES:
            lines.append(f"- {status_labels.get(status, status)}: {status_counts.get(status, 0)}")
    return lines


def _sw49_markdown_lines(sw49: dict[str, object], language: str) -> list[str]:
    labels = _labels(language)
    columns = labels.get("sw49_columns", {})
    if not isinstance(columns, dict):
        columns = {}
    lines = ["", f"## {labels.get('sw49_heading', 'SW Development Security 49')}", "", str(labels.get("sw49_intro", "")), ""]
    lines.extend(_sw49_summary_lines(sw49, language))
    lines.append("")
    header = [str(columns.get(key, key)) for key in _SW49_COLUMN_KEYS]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + " --- |" * len(header))
    for entry in sw49.get("controls", []):
        if not isinstance(entry, dict):
            continue
        row = _sw49_display_row(entry, language)
        lines.append("| " + " | ".join(row[key].replace("|", "\\|") for key in _SW49_COLUMN_KEYS) + " |")
    status_counts = sw49.get("status_counts", {})
    if isinstance(status_counts, dict) and not status_counts.get("VULNERABLE"):
        lines.extend(["", str(labels.get("sw49_zero_note", ""))])
    return lines


def _payload_findings(payload: dict[str, object], language: str = "en") -> list[dict[str, object]]:
    """Return findings from either API payloads or dashboard payloads.

    Older export callers pass a top-level ``findings`` list, while the
    dashboard stores localized findings under ``findings_by_language``.  Both
    shapes are accepted so downloading a report from the dashboard cannot
    silently turn a populated scan into a zero-finding report.
    """
    findings = payload.get("findings")
    if isinstance(findings, list):
        return [item for item in findings if isinstance(item, dict)]

    localized = payload.get("findings_by_language")
    if not isinstance(localized, dict):
        return []
    values = localized.get(language) or localized.get("en") or localized.get("ko") or []
    return [item for item in values if isinstance(item, dict)] if isinstance(values, list) else []


def _finding_mapping_text(item: dict[str, object], language: str) -> str:
    mappings = item.get("standard_mappings")
    if isinstance(mappings, dict):
        mappings = mappings.get("mappings") or mappings.get("standards") or []
    if not isinstance(mappings, list):
        return ""
    values = [
        _standard_mapping_text(mapping, language)
        for mapping in mappings
        if isinstance(mapping, dict)
    ]
    return "\n".join(dict.fromkeys(value for value in values if value))


def _col_ref(index: int) -> str:
    ref = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        ref = chr(65 + remainder) + ref
    return ref


def _xlsx_cell(row: int, col: int, value: object) -> str:
    ref = f"{_col_ref(col)}{row}"
    text = html.escape("" if value is None else str(value))
    return f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>'


def render_xlsx(payload: dict[str, object], language: str = "ko") -> bytes:
    """Minimal but valid .xlsx (inlineStr cells, no shared-strings table)."""
    headers = _EXPORT_COLUMNS.get(language, _EXPORT_COLUMNS["en"])
    rows: list[list[object]] = [list(headers)]
    for item in _payload_findings(payload, language):
        rows.append(
            [
                item.get("severity", ""),
                item.get("category", ""),
                item.get("rule_id", ""),
                item.get("title", ""),
                item.get("path", ""),
                item.get("line", ""),
                _finding_mapping_text(item, language),
                item.get("recommendation", ""),
            ]
        )

    sheets: list[tuple[str, list[list[object]]]] = [("Findings", rows)]

    web_audit = payload.get("web_audit")
    if isinstance(web_audit, dict):
        controls = web_audit.get("controls") if isinstance(web_audit.get("controls"), list) else []
        audit_rows: list[list[object]] = [["ID", "Control", "Status", "Executed", "Completed", "Required", "Reason"]]
        for item in controls:
            if not isinstance(item, dict):
                continue
            coverage = item.get("coverage") if isinstance(item.get("coverage"), dict) else {}
            audit_rows.append([
                item.get("id", ""), item.get("title", ""), item.get("status", ""),
                "yes" if item.get("executed") else "no", coverage.get("completed", 0),
                coverage.get("required", 0), item.get("reason_code", ""),
            ])
        sheets.append(("WebAudit", audit_rows))

    sw49 = _payload_sw49(payload)
    if sw49:
        labels = _labels(language)
        columns = labels.get("sw49_columns", {})
        if not isinstance(columns, dict):
            columns = {}
        sw49_rows: list[list[object]] = [[str(columns.get(key, key)) for key in _SW49_COLUMN_KEYS]]
        for entry in sw49.get("controls", []):
            if not isinstance(entry, dict):
                continue
            row_data = _sw49_display_row(entry, language)
            sw49_rows.append([row_data[key] for key in _SW49_COLUMN_KEYS])
        sheets.append(("SW49", sw49_rows))

    return _render_xlsx_sheets(sheets)


def render_rows_xlsx(sheet_name: str, rows: list[list[object]]) -> bytes:
    """Render ordinary tabular rows with the report writer's minimal XLSX package."""
    return _render_xlsx_sheets([(sheet_name, rows)])


def _render_xlsx_sheets(sheets: list[tuple[str, list[list[object]]]]) -> bytes:
    def _sheet_xml(sheet_rows_data: list[list[object]]) -> str:
        sheet_rows = []
        for r_index, row in enumerate(sheet_rows_data, start=1):
            cells = "".join(_xlsx_cell(r_index, c_index, value) for c_index, value in enumerate(row))
            sheet_rows.append(f'<row r="{r_index}">{cells}</row>')
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            f"<sheetData>{''.join(sheet_rows)}</sheetData></worksheet>"
        )

    sheet_overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{index}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for index in range(1, len(sheets) + 1)
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        f"{sheet_overrides}"
        "</Types>"
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )
    sheet_entries = "".join(
        f'<sheet name="{html.escape(name, quote=True)}" sheetId="{index}" r:id="rId{index}"/>'
        for index, (name, _) in enumerate(sheets, start=1)
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheets>{sheet_entries}</sheets></workbook>"
    )
    workbook_rel_entries = "".join(
        f'<Relationship Id="rId{index}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{index}.xml"/>'
        for index in range(1, len(sheets) + 1)
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f"{workbook_rel_entries}"
        "</Relationships>"
    )
    members = {
        "[Content_Types].xml": content_types,
        "_rels/.rels": root_rels,
        "xl/workbook.xml": workbook,
        "xl/_rels/workbook.xml.rels": workbook_rels,
    }
    for index, (_, sheet_rows_data) in enumerate(sheets, start=1):
        members[f"xl/worksheets/sheet{index}.xml"] = _sheet_xml(sheet_rows_data)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


_PDF_MAX_REPORT_CHARS = 500_000
_PDF_RENDERER = BoundedSemaphore(1)


class PdfExportError(RuntimeError):
    pass


def render_pdf(payload: dict[str, object], language: str = "ko") -> bytes:
    report = render_markdown_from_payload(payload, language)
    if len(report) > _PDF_MAX_REPORT_CHARS:
        raise PdfExportError("PDF export is limited to 500,000 report characters")
    if not _PDF_RENDERER.acquire(blocking=False):
        raise PdfExportError("PDF renderer is busy; try again shortly")
    try:
        from .web import _ensure_bundled_browsers_path

        _ensure_bundled_browsers_path()
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise PdfExportError("PDF export requires the bundled Chromium renderer") from exc

        content = html.escape(report)
        document = (
            "<!doctype html><meta charset=\"utf-8\"><style>"
            "@page { size: A4; margin: 16mm; }"
            "body { color: #111827; font-family: 'Noto Sans KR', 'Malgun Gothic', 'NanumGothic', sans-serif; }"
            "pre { font: 10pt/1.55 inherit; white-space: pre-wrap; overflow-wrap: anywhere; }"
            "</style><pre>"
            f"{content}"
            "</pre>"
        )
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                try:
                    page = browser.new_page()
                    page.set_content(document, wait_until="load")
                    return page.pdf(format="A4", print_background=True)
                finally:
                    browser.close()
        except PlaywrightError as exc:
            raise PdfExportError(f"PDF renderer failed: {exc}") from exc
    finally:
        _PDF_RENDERER.release()


_HWPX_TEMPLATE_PATH = Path(__file__).resolve().parent / "assets" / "koda-hwpx-template.hwpx"


def _hwpx_paragraph(text: str, char_pr: str, para_pr: str, para_id: int, *, sec_pr: str = "") -> str:
    runs = f'<hp:run charPrIDRef="9">{sec_pr}</hp:run>' if sec_pr else ""
    runs += f'<hp:run charPrIDRef="{char_pr}"><hp:t>{html.escape(text)}</hp:t></hp:run>'
    return (
        f'<hp:p id="{para_id}" paraPrIDRef="{para_pr}" styleIDRef="0" '
        f'pageBreak="0" columnBreak="0" merged="0">{runs}</hp:p>'
    )


def render_hwpx(payload: dict[str, object], language: str = "ko") -> bytes:
    """Fill the bundled 한글(HWPX) template with the scan findings (stdlib zip only)."""
    labels = _labels(language)
    severity_labels = labels.get("severity_labels", {})
    if not isinstance(severity_labels, dict):
        severity_labels = {}
    template_bytes = _HWPX_TEMPLATE_PATH.read_bytes()
    with zipfile.ZipFile(io.BytesIO(template_bytes)) as archive:
        members = [(info.filename, archive.read(info.filename)) for info in archive.infolist()]
    section = next(data for name, data in members if name == "Contents/section0.xml").decode("utf-8")

    prefix = section[: section.find("<hp:p")]
    sec_pr = section[section.find("<hp:secPr") : section.find("</hp:secPr>") + len("</hp:secPr>")]

    generated_at, generated_display = _generated_at()
    findings = _payload_findings(payload, language)
    para_id = 1000
    paragraphs = [_hwpx_paragraph(str(labels.get("report_heading", "Report")), "12", "21", para_id, sec_pr=sec_pr)]
    para_id += 1
    paragraphs.append(_hwpx_paragraph(f"{labels.get('generated', 'Generated')}: {generated_display}", "16", "25", para_id))
    para_id += 1
    paragraphs.append(_hwpx_paragraph(f"{labels.get('total_findings', 'Findings')}: {len(findings)}", "16", "25", para_id))

    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in findings:
        grouped[str(item.get("category", ""))].append(item)
    for category in sorted(grouped):
        para_id += 1
        paragraphs.append(_hwpx_paragraph(_category_label(category, language), "17", "24", para_id))
        for item in grouped[category]:
            severity = str(item.get("severity", ""))
            sev_label = str(severity_labels.get(severity, severity))
            location = str(item.get("path", ""))
            line = item.get("line")
            if line:
                location = f"{location}:{line}"
            recommendation = str(item.get("recommendation", "")).strip()
            text = f"[{sev_label}] {item.get('title', '')} · {location}"
            criteria = _finding_mapping_text(item, language)
            if criteria:
                text += f" · {criteria.replace(chr(10), '; ')}"
            if recommendation:
                text += f" · {recommendation}"
            para_id += 1
            paragraphs.append(_hwpx_paragraph(text, "16", "25", para_id))

    sw49 = _payload_sw49(payload)
    if sw49:
        para_id += 1
        paragraphs.append(_hwpx_paragraph(str(labels.get("sw49_heading", "SW49")), "17", "24", para_id))
        for line in _sw49_summary_lines(sw49, language):
            para_id += 1
            paragraphs.append(_hwpx_paragraph(line.lstrip("- "), "16", "25", para_id))
        for entry in sw49.get("controls", []):
            if not isinstance(entry, dict):
                continue
            row = _sw49_display_row(entry, language)
            text = (
                f"{row['official_id']} {row['title']} · {row['category']} · {row['cwe']} · {row['support']} · "
                f"{row['executed']} · {row['status']}"
            )
            if row["finding_count"] not in ("", "0"):
                text += f" · {row['finding_count']}"
            if row["evidence"]:
                text += f" · {row['evidence']}"
            if row["notes"]:
                text += f" · {row['notes']}"
            para_id += 1
            paragraphs.append(_hwpx_paragraph(text, "16", "25", para_id))
        status_counts = sw49.get("status_counts", {})
        if isinstance(status_counts, dict) and not status_counts.get("VULNERABLE"):
            para_id += 1
            paragraphs.append(_hwpx_paragraph(str(labels.get("sw49_zero_note", "")), "16", "25", para_id))

    web_audit = payload.get("web_audit")
    if isinstance(web_audit, dict):
        para_id += 1
        paragraphs.append(_hwpx_paragraph("웹취약점 21개 항목 자동 점검", "17", "24", para_id))
        for item in web_audit.get("controls", []):
            if not isinstance(item, dict):
                continue
            coverage = item.get("coverage") if isinstance(item.get("coverage"), dict) else {}
            para_id += 1
            paragraphs.append(_hwpx_paragraph(
                f"{item.get('id', '')} · {item.get('title', '')} · {item.get('status', 'NOT_SCANNED')} · "
                f"{coverage.get('completed', 0)}/{coverage.get('required', 0)} · {item.get('reason_code', '')}",
                "16", "25", para_id,
            ))

    new_section = (prefix + "".join(paragraphs) + "</hs:sec>").encode("utf-8")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members:
            if name.startswith("Preview/"):
                continue  # stale template thumbnail; 한글 regenerates on save
            if name == "Contents/section0.xml":
                data = new_section
            compress = zipfile.ZIP_STORED if name == "mimetype" else zipfile.ZIP_DEFLATED
            archive.writestr(name, data, compress_type=compress)
    return buffer.getvalue()


def _web_audit_html(result: dict[str, object], language: str = "ko") -> str:
    controls = result.get("controls") if isinstance(result.get("controls"), list) else []
    rows: list[str] = []
    for item in controls:
        if not isinstance(item, dict):
            continue
        coverage = item.get("coverage") if isinstance(item.get("coverage"), dict) else {}
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(str(item.get('id', '')))}</code></td>"
            f"<td>{html.escape(str(item.get('title', '')))}</td>"
            f"<td><strong>{html.escape(str(item.get('status', 'NOT_SCANNED')))}</strong></td>"
            f"<td>{'yes' if item.get('executed') else 'no'}</td>"
            f"<td>{html.escape(str(coverage.get('completed', 0)))}/{html.escape(str(coverage.get('required', 0)))}</td>"
            f"<td>{html.escape(str(item.get('reason_code', '')))}</td>"
            "</tr>"
        )
    title = "웹취약점 21개 항목 자동 점검" if language == "ko" else "21-control web vulnerability audit"
    return (
        '<section class="web-audit-results">'
        f"<h2>{html.escape(title)}</h2>"
        f"<p>Overall: <strong>{html.escape(str(result.get('status', 'NOT_SCANNED')))}</strong></p>"
        '<table><thead><tr><th>ID</th><th>Control</th><th>Status</th><th>Executed</th><th>Coverage</th><th>Reason</th></tr></thead>'
        f"<tbody>{''.join(rows)}</tbody></table></section>"
    )


def render_html(
    findings: list[Finding],
    target_names: tuple[str, ...] = (),
    language: str = "en",
    *,
    target_paths: dict[str, str] | None = None,
    components: tuple[DependencyComponent, ...] = (),
    warnings: tuple[str, ...] = (),
    standard: str = DEFAULT_STANDARD,
    standard_category: str = DEFAULT_STANDARD_CATEGORY,
    scanned_categories: tuple[str, ...] = (),
    source_analysis: object | None = None,
) -> str:
    payload = build_dashboard_payload(
        findings,
        target_names,
        language,
        target_paths=target_paths,
        warnings=warnings,
        standard=standard,
        standard_category=standard_category,
        components=components,
        scanned_categories=scanned_categories,
        source_analysis=source_analysis,
    )
    return _render_html_payload(payload, language)


def render_html_pair(
    findings: list[Finding],
    target_names: tuple[str, ...] = (),
    language: str = "en",
    *,
    detail_href: str = "security-dashboard-detail.html",
    summary_href: str | None = None,
    target_paths: dict[str, str] | None = None,
    warnings: tuple[str, ...] = (),
    scan_path: str | None = None,
    kind: str = "source",
    standard: str = DEFAULT_STANDARD,
    standard_category: str = DEFAULT_STANDARD_CATEGORY,
    components: tuple[DependencyComponent, ...] = (),
    enable_osv: bool = False,
    scanned_categories: tuple[str, ...] = (),
    source_analysis: object | None = None,
) -> tuple[str, str]:
    """Render a compact landing page and the full source findings page.

    The existing ``render_html`` remains a single document for the embedded
    dashboard/server API.  File-based CLI reports use this pair so a reviewer
    can open a summary first and follow a relative link to the complete table.
    """
    payload = build_dashboard_payload(
        findings,
        target_names,
        language,
        target_paths=target_paths,
        warnings=warnings,
        scan_path=scan_path,
        kind=kind,
        standard=standard,
        standard_category=standard_category,
        components=components,
        enable_osv=enable_osv,
        scanned_categories=scanned_categories,
        source_analysis=source_analysis,
    )
    # File reports are Korean-only for now. The summary links to the sibling
    # detail artifact, while the detail page remains independently openable.
    report_language = "ko"
    main_html = _render_html_main(payload, report_language, detail_href)
    report_mode = "LIBRARY VULNERABILITY REPORT" if kind == "library" else "STATIC ANALYSIS REPORT"
    main_html = main_html.replace(
        '<section class="source-summary-panel">',
        f'{_source_main_filter_markup(payload, report_language)}<section class="source-summary-panel">',
        1,
    )
    main_html = main_html.replace('</style>', f'{_SOURCE_MAIN_EXTRA_CSS}</style>', 1)
    main_html = main_html.replace('</style>', '.koda-main-mark svg{width:24px;height:24px}</style>', 1)
    main_html = main_html.replace('</body>', f'{_SOURCE_MAIN_FILTER_SCRIPT}</body>', 1)
    main_html = main_html.replace(
        'class="koda-main-classification-badge"',
        'class="koda-main-classification-badge" style="order:2"',
    )
    main_html = main_html.replace(
        '<main><div class="koda-main-brand"><span class="koda-main-mark">K</span><span>Korean On-Device Auditor</span>',
        '<main><header class="report-brand"><div class="brand"><span class="koda-main-mark">K</span><span class="brand-copy"><strong>KODA</strong><span>Korean On-Device Auditor</span></span></div><div class="report-header-actions">',
        1,
    ).replace(
        '</div><section class="koda-main-hero">',
        f'<span class="report-mode">{report_mode}</span></div></header><section class="koda-main-hero">',
        1,
    )
    detail_html = _render_html_detail(payload, report_language).replace(
        "</style>",
        f"{_SOURCE_DETAIL_EXTRA_CSS}</style>",
        1,
    ).replace(
        '<div class="language-buttons"><button id="lang-ko" type="button">한국어</button>'
        '<button id="lang-en" type="button">English</button></div>',
        "",
    )
    detail_html = re.sub(
        r'<header class="report-head"><div><small>(.*?)</small><h1>(.*?)</h1></div><span class="external-classification-badge">대외 비공개</span></header>',
        rf'<header class="report-brand"><div class="brand"><span class="source-detail-mark" aria-hidden="true">K</span><span class="brand-copy"><strong>KODA</strong><span>Korean On-Device Auditor</span></span></div><div class="report-header-actions"><span class="report-mode">{report_mode}</span><span class="external-classification-badge">대외 비공개</span></div></header><div class="report-head-title"><small>\1</small><h1>\2</h1></div>',
        detail_html,
        count=1,
        flags=re.DOTALL,
    )
    for value, label in (
        ("critical", "치명"),
        ("high", "높음"),
        ("medium", "중간"),
        ("low", "낮음"),
        ("info", "정보"),
    ):
        detail_html = detail_html.replace(
            f'<option value="{value}">{value.capitalize() if value != "info" else "Info"}</option>',
            f'<option value="{value}">{label}</option>',
        )
    main_html = main_html.replace(
        '<span class="koda-main-mark">K</span>',
        f'<span class="koda-main-mark" aria-hidden="true">{_KODA_LOGO_SVG}</span>',
    )
    detail_html = detail_html.replace(
        '<span class="source-detail-mark" aria-hidden="true">K</span>',
        f'<span class="source-detail-mark" aria-hidden="true">{_KODA_LOGO_SVG}</span>',
    )
    detail_html = detail_html.replace("</style>", ".source-detail-mark svg{width:24px;height:24px}</style>", 1)
    return main_html, detail_html


def _render_html_payload(payload: dict[str, object], language: str, *, summary_href: str | None = None) -> str:
    labels = _labels(language)
    json_payload = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    replacements = _html_replacements(labels, json_payload)
    # Main and detail reports are independent artifacts.  Do not inject a
    # cross-page back link; the caller can open either file directly.
    replacements["__INITIAL_SUMMARY_LINK_HTML__"] = ""
    replacements["__INITIAL_SSBOM_TRACKER_LINK_HTML__"] = _sbom_tracker_link_markup(language)
    content = HTML_TEMPLATE
    for placeholder, value in replacements.items():
        content = content.replace(placeholder, value)
    return content


def _sbom_tracker_url() -> str:
    """Return a safe, explicitly configured SBOM Tracker URL.

    The link is intentionally opt-in so an air-gapped deployment never shows a
    dead or unintended external destination. Credentials in URLs are rejected
    because the value is copied into rendered HTML.
    """
    value = os.environ.get("KODA_SSBOM_TRACKER_URL", "").strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    if parsed.username is not None or parsed.password is not None:
        return ""
    return value


def _sbom_tracker_link_markup(language: str) -> str:
    url = _sbom_tracker_url()
    if not url:
        return ""
    label = "SBOM Tracker 열기" if language == "ko" else "Open SBOM Tracker"
    return (
        '<a class="topbar-action topbar-action-link" '
        f'href="{html.escape(url, quote=True)}" target="_blank" '
        f'rel="noopener noreferrer">{html.escape(label)}</a>'
    )


def _source_sw49_table_markup(payload: dict[str, object], language: str) -> str:
    sw49 = _payload_sw49(payload)
    if not sw49:
        return ""
    labels = _labels(language)
    is_ko = language == "ko"
    heading = str(labels.get("sw49_heading", "소프트웨어 개발보안 49 기준 현황"))
    intro = str(labels.get("sw49_intro", ""))
    summary = " · ".join(line.lstrip("- ") for line in _sw49_summary_lines(sw49, language))
    columns = (
        ("공식 항목 (KODA ID)", "기준명", "CWE", "지원 수준", "실행 상태", "판정", "발견 건수")
        if is_ko
        else ("Official item (KODA ID)", "Weakness", "CWE", "Support", "Executed", "Verdict", "Findings")
    )
    head = "".join(f"<th>{html.escape(column)}</th>" for column in columns)
    rows: list[str] = []
    for entry in sw49.get("controls", ()):
        if not isinstance(entry, dict):
            continue
        row = _sw49_display_row(entry, language)
        control_id = str(entry.get("control_id") or "")
        status = str(entry.get("status") or "")
        values = (
            row["official_id"],
            row["title"],
            row["cwe"],
            row["support"],
            row["executed"],
            row["status"],
            row["finding_count"],
        )
        cells = "".join(f"<td>{html.escape(value)}</td>" for value in values)
        rows.append(
            f'<tr data-sw49-control="{html.escape(control_id, quote=True)}" '
            f'data-sw49-status="{html.escape(status, quote=True)}">{cells}</tr>'
        )
    zero_note = ""
    status_counts = sw49.get("status_counts")
    if isinstance(status_counts, dict) and not status_counts.get("VULNERABLE"):
        zero_note = f'<p class="sw49-zero-note">{html.escape(str(labels.get("sw49_zero_note", "")))}</p>'
    return (
        '<section class="source-sw49-panel">'
        f'<div class="source-summary-head"><h2>{html.escape(heading)}</h2><p>{html.escape(intro)}</p>'
        f'<p class="sw49-summary">{html.escape(summary)}</p></div>'
        '<div class="source-sw49-wrap"><table class="source-sw49-table"><thead><tr>'
        f'{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>{zero_note}</section>'
    )


def _render_html_main(payload: dict[str, object], language: str, detail_href: str) -> str:
    labels = _labels(language)
    summary = payload.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    scan = payload.get("scan", {})
    if not isinstance(scan, dict):
        scan = {}
    standards = payload.get("standards", [])
    standard_label = str(scan.get("standard", DEFAULT_STANDARD))
    standard_id = standard_label
    category_label = str(scan.get("standard_category", DEFAULT_STANDARD_CATEGORY))
    for item in standards:
        if isinstance(item, dict) and item.get("id") == standard_label:
            localized = item.get("labels", {})
            if isinstance(localized, dict):
                standard_label = str(localized.get(language, localized.get("en", standard_label)))
            for category in item.get("categories", ()):
                if isinstance(category, dict) and category.get("id") == category_label:
                    category_labels = category.get("labels", {})
                    if isinstance(category_labels, dict):
                        category_label = str(category_labels.get(language, category_labels.get("en", category_label)))
                    break
            break

    is_ko = language == "ko"
    is_library = scan.get("kind") == "library"
    title = ("라이브러리 취약점 분석 요약" if is_ko else "Library Vulnerability Summary") if is_library else ("소스 보안 분석 요약" if is_ko else "Source Security Scan Summary")
    eyebrow = ("KODA · 라이브러리 취약점" if is_ko else "KODA · LIBRARY VULNERABILITY") if is_library else ("KODA · 정적 분석" if is_ko else "KODA · STATIC ANALYSIS")
    intro = "요약을 확인한 뒤 전체 취약점과 근거는 상세 보고서에서 확인하세요." if is_ko else "Review the summary first, then open the detailed findings and evidence."
    target_text = "대상" if is_ko else "Target"
    standard_text = "기준" if is_ko else "Standard"
    category_text = "범주" if is_ko else "Category"
    generated_text = "생성" if is_ko else "Generated"
    languages_text = "분석 언어" if is_ko else "Analyzed languages"
    findings_text = "전체 취약점" if is_ko else "Total findings"
    severity_text = {
        "critical": "치명" if is_ko else "Critical",
        "high": "높음" if is_ko else "High",
        "medium": "중간" if is_ko else "Medium",
        "low": "낮음" if is_ko else "Low",
    }
    target_names = payload.get("scan", {}).get("path", "") if isinstance(payload.get("scan"), dict) else ""
    by_severity = summary.get("by_severity", {}) if isinstance(summary.get("by_severity"), dict) else {}
    cards = (
        ("total", findings_text, summary.get("displayed_finding_count", len(payload.get("findings_by_language", {}).get("en", ())))),
        ("critical", severity_text["critical"], by_severity.get("critical", 0)),
        ("high", severity_text["high"], by_severity.get("high", 0)),
        ("medium", severity_text["medium"], by_severity.get("medium", 0)),
        ("low", severity_text["low"], by_severity.get("low", 0)),
    )
    cards_html = "".join(
        f'<article class="koda-main-card koda-main-card--{key}"><span>{html.escape(str(label))}</span><strong>{html.escape(_format_main_count(value))}</strong></article>'
        for key, label, value in cards
    )
    generated_at = str(payload.get("generated_display", payload.get("generated_at", "")))
    analyzed_languages = summary.get("analyzed_languages", ())
    if not isinstance(analyzed_languages, (list, tuple)):
        analyzed_languages = ()
    analyzed_languages_text = ", ".join(str(item) for item in analyzed_languages if str(item).strip())
    critical_count = by_severity.get("critical", 0)
    high_count = by_severity.get("high", 0)
    if is_ko:
        detail_hint = "구성요소, 취약점 식별자와 조치 방법" if is_library else "파일 위치, 문제행 문맥과 수정 방법"
        priority = f"우선 조치: 치명 {_format_main_count(critical_count)}건 · 높음 {_format_main_count(high_count)}건. 상세 보고서에서 {detail_hint}을 확인하세요."
    else:
        detail_hint = "components, vulnerability identifiers, and remediation guidance" if is_library else "file locations, source context, and remediation guidance"
        priority = f"Priority action: {_format_main_count(critical_count)} Critical · {_format_main_count(high_count)} High. Use the detailed report for {detail_hint}."
    findings = _source_report_findings(payload, language)
    summary_heading = ("라이브러리 취약점 요약" if is_ko else "Library vulnerability summary") if is_library else ("소스 취약점 요약" if is_ko else "Source finding summary")
    summary_intro = ("구성요소·버전·취약점 식별자별 결과입니다." if is_ko else "Results by component, version, and vulnerability identifier.") if is_library else ("문맥 확인 결과와 추가 검토가 필요한 후보를 구분한 파일·행·규칙별 결과입니다." if is_ko else "Results by file, line, and rule, separating context-confirmed findings from review candidates.")
    table_headers = (
        ("심각도", "규칙", "위치", "발견 내용", "기준")
        if is_ko
        else ("Severity", "Rule", "Location", "Finding", "Standard")
    )
    grouped: dict[tuple[str, str, str], dict[str, object]] = {}
    for item in findings:
        key = (
            str(item.get("severity") or "info").lower(),
            str(item.get("rule_id") or "—"),
            str(item.get("verification_status") or "confirmed"),
        )
        group = grouped.setdefault(
            key,
            {"severity": key[0], "rule_id": key[1], "verification_status": key[2], "items": []},
        )
        group["items"].append(item)

    table_rows_parts: list[str] = []
    for group in grouped.values():
        group_items = group["items"]
        locations = list(dict.fromkeys(_source_location(item) for item in group_items))
        finding_texts = list(dict.fromkeys(str(item.get("title") or item.get("evidence") or "—") for item in group_items))
        standards = list(dict.fromkeys(_source_standard_text(payload, item, language) for item in group_items))
        severity = str(group["severity"])
        rule_id = str(group["rule_id"])
        verification_status = str(group["verification_status"])
        verification_label = _source_verification_label(verification_status, language)
        location_html = _source_collapsible_lines(locations, language)
        finding_html = (
            f'<span class="source-verification source-verification--{html.escape(verification_status)}">{html.escape(verification_label)}</span><br>'
            + "<br>".join(html.escape(value) for value in finding_texts)
        )
        standard_html = f'<span class="source-criteria">{html.escape(chr(10).join(standards))}</span>'
        searchable = " ".join((severity, rule_id, *locations, *finding_texts, *standards)).casefold()
        table_rows_parts.append(
            f'<tr data-source-group="true" data-severity="{html.escape(severity)}" data-finding-count="{len(group_items)}" data-search="{html.escape(searchable, quote=True)}">'
            f'<td><span class="source-severity source-severity--{html.escape(severity)}">{html.escape(_source_severity_label(severity, language))}</span></td>'
            f'<td><code>{html.escape(rule_id)}</code></td><td>{location_html}</td><td>{finding_html}</td><td>{standard_html}</td></tr>'
        )
    table_rows = "".join(table_rows_parts) or f'<tr><td colspan="5">{"탐지된 취약점이 없습니다." if is_ko else "No findings were detected."}</td></tr>'
    columns = (("severity", 120), ("rule", 220), ("location", 300), ("finding", 300), ("standard", 300))
    table_width = sum(width for _, width in columns)
    colgroup = "<colgroup>" + "".join(f'<col style="width:{width}px">' for _, width in columns) + "</colgroup>"
    resizable_headers = "".join(
        f'<th scope="col">{html.escape(header)}<span class="column-resizer" role="separator" aria-orientation="vertical" aria-label="열 너비 조절" title="열 너비 조절" tabindex="0" data-column-index="{index}"></span></th>'
        for index, header in enumerate(table_headers)
    )
    sw49_table = _source_sw49_table_markup(payload, language)
    return f'''<!doctype html><html lang="{html.escape(language, quote=True)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="icon" href="__KODA_MARK__"><title>{html.escape(title)}</title><style>
:root{{color-scheme:light;--ink:#10233f;--muted:#60708a;--line:#dce4ee;--brand:#1368e8;--bg:#f4f7fb;--surface:#fff;--critical:#b42318;--high:#c64b09;--medium:#886100;--low:#246b49}}*{{box-sizing:border-box}}body{{margin:0;background:linear-gradient(145deg,#eef5ff,var(--bg) 45%);color:var(--ink);font:15px/1.55 Inter,Pretendard,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}main{{max-width:1120px;margin:0 auto;padding:clamp(24px,6vw,72px) 24px}}.koda-main-brand{{display:flex;align-items:center;gap:12px;margin-bottom:26px;color:var(--muted);font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase}}.koda-main-classification-badge{{display:inline-flex;align-items:center;min-height:38px;margin-left:auto;padding:7px 14px;border:2px solid #ef4444;border-radius:0;color:#b42318;background:none;font-size:13px;font-weight:900;letter-spacing:.06em;white-space:nowrap}}.koda-main-mark{{display:grid;place-items:center;width:42px;height:42px;border-radius:13px;color:#fff;background:linear-gradient(145deg,#1368e8,#0b3b89);font-weight:900;font-size:18px}}.koda-main-hero{{padding:34px;border-radius:24px;color:#fff;background:linear-gradient(125deg,#0b2853,#1676f3);box-shadow:0 18px 48px rgba(15,35,64,.15)}}.koda-main-hero p{{margin:0 0 10px;color:#b9d7ff;font-size:12px;font-weight:800;letter-spacing:.1em}}h1{{margin:0;font-size:clamp(30px,5vw,52px);line-height:1.05;letter-spacing:-.045em}}.koda-main-intro{{margin:18px 0 0;max-width:680px;color:#d9e8ff}}.koda-main-meta{{display:grid;gap:8px;margin-top:22px;color:#d9e8ff}}.koda-main-meta b{{color:#fff}}.koda-main-cards{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:18px 0}}.koda-main-card{{padding:18px;border:1px solid var(--line);border-radius:16px;background:var(--surface);box-shadow:0 8px 20px rgba(15,35,64,.05)}}.koda-main-card span{{display:block;color:var(--muted);font-size:12px;font-weight:750}}.koda-main-card--critical span{{color:var(--critical)}}.koda-main-card--high span{{color:var(--high)}}.koda-main-card--medium span{{color:var(--medium)}}.koda-main-card--low span{{color:var(--low)}}.koda-main-card strong{{display:block;margin-top:8px;color:var(--ink);font-size:30px;letter-spacing:-.04em}}.koda-main-note{{margin-top:18px;padding:18px;border:1px solid var(--line);border-radius:16px;background:#fff;color:var(--muted)}}.source-summary-panel{{overflow:hidden;margin-top:18px;border:1px solid var(--line);border-radius:18px;background:#fff;box-shadow:0 10px 28px rgba(15,35,64,.06)}}.source-summary-head{{padding:20px 22px 14px;border-bottom:1px solid var(--line)}}.source-summary-head h2{{margin:0;font-size:20px}}.source-summary-head p{{margin:5px 0 0;color:var(--muted)}}.source-summary-wrap{{overflow:auto}}.source-summary-table{{width:{table_width}px;min-width:100%;border-collapse:separate;border-spacing:0;table-layout:fixed}}.source-summary-table th{{position:relative;padding:11px 13px;background:#f6f8fb;color:#4a5b73;text-align:left;font-size:11px;letter-spacing:.04em}}.source-summary-table td{{padding:13px;border-top:1px solid #e7edf4;vertical-align:top;overflow-wrap:anywhere}}.source-summary-table th:not(:last-child),.source-summary-table td:not(:last-child){{border-right:1px solid #e7edf4}}.source-severity{{display:inline-flex;padding:4px 8px;border-radius:999px;font-size:11px;font-weight:800}}.source-severity--critical{{color:var(--critical);background:#fff0ee}}.source-severity--high{{color:var(--high);background:#fff4e8}}.source-severity--medium{{color:var(--medium);background:#fff8d8}}.source-severity--low,.source-severity--info{{color:var(--low);background:#ecfdf3}}code{{font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;color:#0b3b89}}footer{{margin-top:24px;color:var(--muted);font-size:12px}}@media(max-width:820px){{.koda-main-cards{{grid-template-columns:repeat(3,1fr)}}.koda-main-hero{{padding:26px 22px}}}}@media(max-width:520px){{.koda-main-cards{{grid-template-columns:repeat(2,1fr)}}}}@media(max-width:360px){{.koda-main-cards{{grid-template-columns:1fr}}}}
main{{max-width:1560px;padding:28px}}.detail-cta{{display:flex;justify-content:flex-end;margin-top:18px}}.detail-cta a{{display:inline-flex;align-items:center;gap:10px;min-height:48px;padding:0 20px;border:1px solid #0b3b89;border-radius:13px;color:#fff;background:linear-gradient(135deg,#1368e8,#0b3b89);box-shadow:0 12px 24px rgba(19,104,232,.24);text-decoration:none;font-weight:850;transition:transform .16s ease,box-shadow .16s ease}}.detail-cta a:hover{{transform:translateY(-2px);box-shadow:0 16px 30px rgba(19,104,232,.3)}}.detail-cta a:focus-visible{{outline:3px solid #8ec5ff;outline-offset:3px}}
</style></head><body><main><div class="koda-main-brand"><span class="koda-main-mark">K</span><span>Korean On-Device Auditor</span><span class="koda-main-classification-badge" title="대외 비공개">대외 비공개</span></div><section class="koda-main-hero"><p>{html.escape(eyebrow)}</p><h1>{html.escape(title)}</h1><div class="koda-main-intro">{html.escape(intro)}</div><div class="koda-main-meta"><span><b>{html.escape(target_text)}</b> {html.escape(str(target_names)) or "—"}</span><span><b>{html.escape(languages_text)}</b> {html.escape(analyzed_languages_text) or "—"}</span><span><b>{html.escape(standard_text)}</b> {html.escape(standard_label)} · {html.escape(category_text)} {html.escape(category_label)}</span><span><b>{html.escape(generated_text)}</b> {html.escape(generated_at) or "—"}</span></div></section><section class="koda-main-cards">{cards_html}</section><div class="koda-main-note">{html.escape(priority)}</div><section class="source-summary-panel"><div class="source-summary-head"><h2>{html.escape(summary_heading)}</h2><p>{html.escape(summary_intro)}</p></div><div class="source-summary-wrap"><table class="source-summary-table" style="width:{table_width}px">{colgroup}<thead><tr>{resizable_headers}</tr></thead><tbody>{table_rows}</tbody></table></div></section>{sw49_table}<div class="detail-cta"><a href="{html.escape(detail_href, quote=True)}">상세 보고서 더보기 <span aria-hidden="true">→</span></a></div><footer>KODA · {html.escape(generated_at)}</footer></main></body></html>'''


def _source_report_findings(payload: dict[str, object], language: str) -> list[dict[str, object]]:
    localized = payload.get("findings_by_language")
    if not isinstance(localized, dict):
        return []
    values = localized.get(language) or localized.get("en") or localized.get("ko") or []
    return [item for item in values if isinstance(item, dict)] if isinstance(values, list) else []


def _source_severity_label(severity: str, language: str) -> str:
    key = severity.lower()
    labels = {"critical": "치명", "high": "높음", "medium": "중간", "low": "낮음", "info": "정보"}
    return labels.get(key, severity) if language == "ko" else key.capitalize()


def _source_verification_label(status: object, language: str) -> str:
    confirmed = str(status or "confirmed") == "confirmed"
    if language == "ko":
        return "문맥 확인" if confirmed else "검토 필요"
    return "Context confirmed" if confirmed else "Needs review"


def _source_location(item: dict[str, object]) -> str:
    path = str(item.get("path") or item.get("target") or "—")
    line = item.get("line")
    return f"{path}:{line}" if line not in (None, "", 0) else path


def _source_collapsible_lines(values: list[str], language: str) -> str:
    unique_values = list(dict.fromkeys(str(value) for value in values if str(value).strip())) or ["—"]
    visible = unique_values[:3]
    hidden = unique_values[3:]
    items = "".join(
        f'<code class="source-collapse-item"{" hidden" if index >= 3 else ""}>{html.escape(value)}</code>'
        for index, value in enumerate(unique_values)
    )
    if not hidden:
        return f'<div class="source-location-list">{items}</div>'
    more = "더보기" if language == "ko" else "More"
    collapse = "접기" if language == "ko" else "Collapse"
    controls = (
        f'<div class="source-collapse-controls"><button type="button" class="source-collapse-toggle source-collapse-more" aria-expanded="false">{more} ({len(hidden)})</button>'
        f'<button type="button" class="source-collapse-toggle source-collapse-less" aria-expanded="true" hidden>{collapse}</button></div>'
    )
    return f'<div class="source-location-list">{items}{controls}</div>'


def _source_standard_text(payload: dict[str, object], item: dict[str, object], language: str) -> str:
    mappings = payload.get("rule_mappings")
    mapping = mappings.get(str(item.get("rule_id") or ""), []) if isinstance(mappings, dict) else []
    values = (mapping.get("mappings") or mapping.get("standards") or []) if isinstance(mapping, dict) else mapping
    if isinstance(values, list):
        scan = payload.get("scan") if isinstance(payload.get("scan"), dict) else {}
        selected_standard = str(scan.get("standard") or "")
        selected_category = str(scan.get("standard_category") or "")
        scoped_metadata = any(
            isinstance(value, dict) and bool(value.get("standard_id") or value.get("standard"))
            for value in values
        )
        selected = [
            value for value in values
            if isinstance(value, dict)
            and (not selected_standard or str(value.get("standard_id") or value.get("standard") or "") == selected_standard)
            and (not selected_category or selected_category == "all" or str(value.get("category_id") or value.get("category") or "") == selected_category)
        ]
        if selected_standard and scoped_metadata:
            values = selected
        labels = [
            _standard_mapping_text(value, language)
            for value in values
            if isinstance(value, dict)
        ]
        labels = list(dict.fromkeys(label for label in labels if label))
        if labels:
            return "\n\n".join(labels)
    scan = payload.get("scan") if isinstance(payload.get("scan"), dict) else {}
    standard_id = str(scan.get("standard") or "")
    category_id = str(scan.get("standard_category") or "")
    for standard in payload.get("standards", ()) if isinstance(payload.get("standards"), list) else ():
        if not isinstance(standard, dict) or str(standard.get("id") or "") != standard_id:
            continue
        standard_labels = standard.get("labels") if isinstance(standard.get("labels"), dict) else {}
        standard_label = str(standard_labels.get(language) or standard_labels.get("ko") or standard_labels.get("en") or standard_id)
        for category in standard.get("categories", ()) if isinstance(standard.get("categories"), list) else ():
            if not isinstance(category, dict) or str(category.get("id") or "") != category_id:
                continue
            category_labels = category.get("labels") if isinstance(category.get("labels"), dict) else {}
            category_label = str(category_labels.get(language) or category_labels.get("ko") or category_labels.get("en") or category_id)
            return f"{standard_label}\n{category_label}"
        return standard_label
    return str(item.get("category") or item.get("rule_id") or "—")


_SOURCE_DETAIL_EXTRA_CSS = """
.report-brand{display:flex;align-items:center;justify-content:space-between;gap:16px;min-height:64px;margin-bottom:22px;padding:10px 0 16px;border-bottom:1px solid #dce4ee}.report-brand .brand{display:flex;align-items:center;gap:12px}.source-detail-mark{display:grid;place-items:center;width:44px;height:44px;border-radius:13px;color:#fff;background:linear-gradient(145deg,#1368e8,#0b3b89);font-size:18px;font-weight:900}.report-brand .brand-copy strong{display:block;color:#10233f;font-size:17px;letter-spacing:-.02em}.report-brand .brand-copy span{display:block;color:#60708a;font-size:12px;font-weight:500}.report-header-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.report-mode{display:inline-flex;align-items:center;height:36px;padding:0 12px;border:1px solid #b8cdf1;border-radius:999px;color:#0b3b89;background:#edf4ff;font-size:11px;font-weight:800;letter-spacing:.04em}.report-head-title{display:grid;gap:3px;margin-bottom:20px}.report-head-title small{color:#60708a;font-weight:800;letter-spacing:.04em}.report-head-title h1{margin:0;font-size:clamp(28px,4vw,46px);letter-spacing:-.04em}.external-classification-badge{display:inline-flex;align-items:center;min-height:46px;margin-left:0;padding:9px 18px;border:2px solid #ef4444;border-radius:0;color:#b42318;background:none;font-size:14px;font-weight:900;letter-spacing:.06em;white-space:nowrap}
.source-verification{display:inline-flex;padding:3px 7px;border-radius:999px;background:#e8f4ff;color:#0b3b89;font-size:10px;font-weight:850}.source-verification--needs_review{background:#fff4d6;color:#7a5400}
@media(max-width:760px){.report-brand{align-items:flex-start;flex-wrap:wrap}.external-classification-badge{margin-left:0}}
"""


_SOURCE_MAIN_EXTRA_CSS = """
.report-brand{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:26px}.report-brand .brand{display:flex;align-items:center;gap:12px}.report-brand .brand-copy strong{display:block;color:#10233f;font-size:17px;letter-spacing:-.02em}.report-brand .brand-copy span{display:block;color:#60708a;font-size:12px;font-weight:500;letter-spacing:0;text-transform:none}.report-header-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.report-mode{display:inline-flex;align-items:center;height:36px;padding:0 12px;border:1px solid #b8cdf1;border-radius:999px;color:#0b3b89;background:#edf4ff;font-size:11px;font-weight:800;letter-spacing:.04em}.report-brand .koda-main-classification-badge{margin-left:0}.koda-main-classification-badge{min-height:46px;padding:9px 18px;font-size:14px}.source-main-filters{display:grid;grid-template-columns:minmax(240px,1.6fr) repeat(3,minmax(150px,1fr));gap:10px;margin:18px 0 0;padding:14px;border:1px solid #dce4ee;border-radius:16px;background:#fff;box-shadow:0 8px 20px rgba(15,35,64,.04)}
.source-main-filters label{display:grid;gap:5px;color:#60708a;font-size:11px;font-weight:800}.source-main-filters input,.source-main-filters select{width:100%;min-height:42px;border:1px solid #cbd6e5;border-radius:10px;padding:0 11px;background:#fff;color:#10233f}.source-main-filter-count{grid-column:1/-1;color:#60708a;font-size:12px}.source-severity-panel{margin:18px 0 0;padding:20px;border:1px solid #dce4ee;border-radius:18px;background:#fff;box-shadow:0 8px 20px rgba(15,35,64,.04)}.source-severity-panel h2{margin:0;font-size:18px}.source-severity-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-top:14px}.source-severity-card{min-width:0;padding:14px;border:1px solid #e7edf4;border-radius:12px;background:#f8fafc}.source-severity-card strong{display:block;font-size:12px}.source-severity-card b{display:block;margin-top:3px;font-size:22px}.source-severity-locations{margin-top:8px;color:#60708a;font:11px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}@media(max-width:820px){.source-main-filters{grid-template-columns:1fr 1fr}.source-severity-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:520px){.source-main-filters{grid-template-columns:1fr}.source-severity-grid{grid-template-columns:1fr}}
.source-summary-wrap{overflow:auto;padding:0 20px 20px}.source-summary-table{border-left:1px solid #dce4ee;border-right:1px solid #dce4ee}.source-summary-table th:first-child,.source-summary-table td:first-child{min-width:92px;white-space:nowrap}
.source-summary-table{table-layout:fixed}.source-summary-table th{position:relative}.source-criteria{display:block;white-space:pre-line}.source-verification{display:inline-flex;margin-top:6px;padding:3px 7px;border-radius:999px;background:#e8f4ff;color:#0b3b89;font-size:10px;font-weight:850}.source-verification--needs_review{background:#fff4d6;color:#7a5400}.source-location-list{display:grid;gap:5px}.source-location-list code{overflow-wrap:anywhere}.source-collapse-item[hidden],.source-collapse-toggle[hidden]{display:none!important}.source-collapse-controls{display:flex;gap:6px;margin-top:2px}.source-collapse-toggle{min-height:30px;padding:0 8px;border:1px solid #cbd6e5;border-radius:8px;color:#0b3b89;background:#fff;cursor:pointer;font-size:11px;font-weight:750}.source-severity-details{margin-top:8px}.source-severity-details summary{color:#0b3b89;font-size:11px;font-weight:800;cursor:pointer}.source-severity-locations{margin-top:7px;color:#60708a;font:11px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}.column-resizer{position:absolute;top:0;right:-5px;z-index:3;width:10px;height:100%;cursor:col-resize;touch-action:none;user-select:none}.column-resizer::after{content:"";position:absolute;top:24%;bottom:24%;left:4px;width:2px;border-radius:2px;background:transparent}.column-resizer:hover::after,.column-resizer:focus-visible::after{background:#1368e8}
.source-sw49-panel{overflow:hidden;margin-top:18px;border:1px solid #dce4ee;border-radius:18px;background:#fff;box-shadow:0 10px 28px rgba(15,35,64,.06)}.source-sw49-wrap{overflow:auto;padding:0 20px 20px}.source-sw49-table{width:100%;min-width:1060px;border-collapse:separate;border-spacing:0;border:1px solid #dce4ee}.source-sw49-table th{padding:10px 12px;background:#f6f8fb;color:#4a5b73;text-align:left;font-size:11px}.source-sw49-table td{padding:11px 12px;border-top:1px solid #e7edf4;vertical-align:top}.source-sw49-table th:not(:last-child),.source-sw49-table td:not(:last-child){border-right:1px solid #e7edf4}.source-sw49-table tr[data-sw49-status="VULNERABLE"] td{background:#fff5f4}.sw49-summary{color:#0b3b89!important;font-weight:750}.sw49-zero-note{margin:0 20px 20px;padding:12px 14px;border-radius:10px;background:#fff8d8;color:#6c5200}
"""


def _source_main_filter_markup(payload: dict[str, object], language: str) -> str:
    findings = _source_report_findings(payload, language)
    locations = sorted({_source_location(item).rsplit(":", 1)[0] for item in findings})
    standards = sorted({_source_standard_text(payload, item, language) for item in findings})
    def options(values: list[str]) -> str:
        return "".join(
            f'<option value="{html.escape(value, quote=True)}">{html.escape(value)}</option>'
            for value in values
            if value
        )

    by_severity: dict[str, list[str]] = {severity: [] for severity in ("critical", "high", "medium", "low", "info")}
    for item in findings:
        by_severity.setdefault(str(item.get("severity") or "info").lower(), []).append(_source_location(item))
    severity_labels = {"critical": "치명", "high": "높음", "medium": "중간", "low": "낮음", "info": "정보"}
    severity_cards = "".join(
        f'<article class="source-severity-card"><strong>{severity_labels.get(severity, severity)}</strong><b>{len(values):,}건</b><details class="source-severity-details"><summary>상세 경로 보기</summary><div class="source-severity-locations">{html.escape(" · ".join(dict.fromkeys(values)) or "위치 없음")}</div></details></article>'
        for severity, values in by_severity.items()
    )
    return (
        '<section class="source-main-filters" aria-label="상세정보 필터">'
        '<label>상세정보 검색<input id="source-main-query" type="search" placeholder="규칙, 위치, 발견 내용 검색"></label>'
        '<label>심각도<select id="source-main-severity"><option value="">전체 심각도</option><option value="critical">치명</option><option value="high">높음</option><option value="medium">중간</option><option value="low">낮음</option><option value="info">정보</option></select></label>'
        f'<label>위치<select id="source-main-location"><option value="">전체 위치</option>{options(locations)}</select></label>'
        f'<label>점검 기준<select id="source-main-standard"><option value="">전체 기준</option>{options(standards)}</select></label>'
        f'<span id="source-main-filter-count" class="source-main-filter-count" aria-live="polite">전체 {len(findings):,}건</span></section>'
        '<section class="source-severity-panel"><h2>심각도별 위치</h2><p>심각도별 발견 개수와 해당 위치를 한 번에 확인합니다.</p>'
        f'<div class="source-severity-grid">{severity_cards}</div></section>'
    )


_SOURCE_MAIN_FILTER_SCRIPT = '''<script>(function(){const q=document.getElementById("source-main-query"),severity=document.getElementById("source-main-severity"),location=document.getElementById("source-main-location"),standard=document.getElementById("source-main-standard"),count=document.getElementById("source-main-filter-count"),table=document.querySelector(".source-summary-table");if(!q||!severity||!location||!standard||!count||!table)return;const rows=[...table.querySelectorAll("tbody tr[data-source-group]")],labels={critical:"치명",high:"높음",medium:"중간",low:"낮음",info:"정보"};const apply=()=>{const query=q.value.trim().toLowerCase(),selectedSeverity=severity.value,selectedLocation=location.value,selectedStandard=standard.value;let visible=0;rows.forEach(row=>{const rowSeverity=row.dataset.severity||"",rowLocation=(row.cells[2]?.textContent||"").trim(),rowStandard=(row.cells[4]?.textContent||"").trim(),haystack=(row.dataset.search||row.textContent).toLowerCase();const hidden=!!((query&&!haystack.includes(query))||(selectedSeverity&&rowSeverity!==selectedSeverity)||(selectedLocation&&!rowLocation.includes(selectedLocation))||(selectedStandard&&!rowStandard.includes(selectedStandard)));row.hidden=hidden;if(!hidden)visible+=Number(row.dataset.findingCount||1)});count.textContent=`필터 결과 ${visible.toLocaleString()}건 / 전체 ${[...table.querySelectorAll("tbody tr[data-source-group]")].reduce((total,row)=>total+Number(row.dataset.findingCount||1),0).toLocaleString()}건`;};[q,severity,location,standard].forEach(control=>{control.addEventListener("input",apply);control.addEventListener("change",apply)});table.querySelectorAll(".column-resizer").forEach(handle=>{const index=Number(handle.dataset.columnIndex),column=table.querySelectorAll("col")[index];if(!column)return;const resize=width=>{const previous=column.getBoundingClientRect().width,next=Math.max(64,width);column.style.width=`${next}px`;table.style.width=`${Math.max(table.getBoundingClientRect().width+next-previous,table.parentElement.clientWidth)}px`};handle.addEventListener("pointerdown",event=>{event.preventDefault();const startX=event.clientX,startWidth=column.getBoundingClientRect().width;handle.setPointerCapture(event.pointerId);const move=current=>resize(startWidth+current.clientX-startX);handle.addEventListener("pointermove",move);handle.addEventListener("pointerup",()=>handle.removeEventListener("pointermove",move),{once:true})});handle.addEventListener("keydown",event=>{if(event.key==="ArrowLeft"||event.key==="ArrowRight"){event.preventDefault();resize(column.getBoundingClientRect().width+(event.key==="ArrowRight"?16:-16))}})});document.querySelectorAll(".source-collapse-controls").forEach(controls=>{const root=controls.parentElement,items=[...root.querySelectorAll(".source-collapse-item")],more=controls.querySelector(".source-collapse-more"),less=controls.querySelector(".source-collapse-less");more?.addEventListener("click",()=>{items.forEach(item=>item.hidden=false);more.hidden=true;if(less)less.hidden=false;more.setAttribute("aria-expanded","true")});less?.addEventListener("click",()=>{items.forEach((item,index)=>item.hidden=index>=3);more.hidden=false;if(less)less.hidden=true;more.setAttribute("aria-expanded","false")})});apply();})();</script>'''


def _render_html_detail(payload: dict[str, object], language: str) -> str:
    is_ko = language == "ko"
    findings = _source_report_findings(payload, language)
    scan = payload.get("scan") if isinstance(payload.get("scan"), dict) else {}
    is_library = scan.get("kind") == "library"
    title = ("라이브러리 취약점 상세" if is_ko else "Library Vulnerability Detail") if is_library else ("소스코드 취약점 상세" if is_ko else "Source Code Vulnerability Detail")
    report_context = "KODA · LIBRARY VULNERABILITY" if is_library else "KODA · STATIC ANALYSIS"
    problem = "문제 설명" if is_ko else "Problem description"
    evidence_label = "탐지 근거" if is_ko else "Evidence"
    remediation = "조치 방법" if is_ko else "Remediation"
    context_label = ("구성요소 근거" if is_ko else "Component evidence") if is_library else ("소스 문맥" if is_ko else "Source context")
    unavailable = ("추가 구성요소 근거가 없습니다." if is_ko else "No additional component evidence is available.") if is_library else ("소스 문맥을 표시할 수 없습니다." if is_ko else "Source context is unavailable for this finding.")
    all_locations = "전체 위치" if is_ko else "All locations"
    cards: list[str] = []
    location_options = sorted({_source_location(item).rsplit(":", 1)[0] for item in findings})
    for index, item in enumerate(findings, 1):
        severity = str(item.get("severity") or "info").lower()
        location = _source_location(item)
        source_context = item.get("source_context")
        context_rows: list[str] = []
        context_values = source_context.get("lines", []) if isinstance(source_context, dict) else source_context
        if isinstance(context_values, list):
            for row in context_values:
                if not isinstance(row, dict):
                    continue
                number = row.get("number") or row.get("line") or row.get("line_number") or ""
                content = row.get("text") or row.get("content") or ""
                focus = bool(row.get("is_focus") or row.get("focus"))
                redaction_marker = "<!-- <redacted sensitive source line> -->" if row.get("redacted") else ""
                context_rows.append(f'{redaction_marker}<div class="source-code-line{" source-code-line--focus" if focus else ""}"><span>{html.escape(str(number))}</span><code>{html.escape(str(content))}</code></div>')
        if context_rows:
            context_html = "".join(context_rows)
        elif str(item.get("rule_id") or "").startswith("secret."):
            context_html = '<!-- <redacted sensitive source line> --><p class="unavailable">&lt;redacted sensitive source line&gt;</p>'
        else:
            context_html = f'<p class="unavailable">{html.escape(unavailable)}</p>'
        search = " ".join(str(item.get(key) or "") for key in ("title", "rule_id", "path", "evidence", "description")).lower()
        cards.append(
            f'<article class="finding" data-severity="{html.escape(severity)}" data-location="{html.escape(location.rsplit(":", 1)[0], quote=True)}" data-search="{html.escape(search, quote=True)}">'
            f'<header><div><span class="source-severity source-severity--{html.escape(severity)}">{html.escape(_source_severity_label(severity, language))}</span> <code>{html.escape(str(item.get("rule_id") or ""))}</code> <span class="source-verification source-verification--{html.escape(str(item.get("verification_status") or "confirmed"))}">{html.escape(_source_verification_label(item.get("verification_status"), language))}</span></div><strong>#{index}</strong></header>'
            f'<h2>{html.escape(str(item.get("title") or item.get("evidence") or "—"))}</h2><p class="location"><code>{html.escape(location)}</code></p>'
            f'<section><h3>{html.escape(problem)}</h3><p>{html.escape(str(item.get("description") or item.get("evidence") or "—"))}</p></section>'
            f'<section><h3>{html.escape(evidence_label)}</h3><pre>{html.escape(str(item.get("evidence") or "—"))}</pre></section>'
            f'<section><h3>{html.escape(context_label)}</h3><div class="source_context source-context">{context_html}</div></section>'
            f'<section><h3>{html.escape(remediation)}</h3><p>{html.escape(str(item.get("recommendation") or "—"))}</p><p class="standards"><strong>점검 기준</strong><br>{html.escape(_source_standard_text(payload, item, language))}</p></section></article>'
        )
    empty = "탐지된 취약점이 없습니다." if is_ko else "No findings were detected."
    cards_html = "".join(cards) or f'<p class="empty">{empty}</p>'
    options = "".join(f'<option value="{html.escape(value, quote=True)}">{html.escape(value)}</option>' for value in location_options)
    return f'''<!doctype html><html lang="{html.escape(language, quote=True)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,"><title>{html.escape(title)}</title><style>
main{{max-width:1560px!important;padding:28px!important}}.language-buttons{{display:none!important}}
:root{{--ink:#10233f;--muted:#60708a;--line:#dce4ee;--brand:#1368e8;--critical:#b42318;--high:#c64b09;--medium:#886100;--low:#246b49}}*{{box-sizing:border-box}}body{{margin:0;background:#f4f7fb;color:var(--ink);font:15px/1.6 Inter,Pretendard,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}main{{max-width:1000px;margin:auto;padding:32px 22px 64px}}.report-head{{display:flex;align-items:center;gap:12px;margin-bottom:20px}}.report-head h1{{margin:0;font-size:clamp(28px,5vw,46px)}}.external-classification-badge{{margin-left:auto;padding:7px 14px;border:2px solid #ef4444;border-radius: 0;color:#b42318;background: none;font-weight:900}}.toolbar{{display:grid;grid-template-columns:1fr 170px 220px auto;gap:10px;margin:18px 0;padding:14px;border:1px solid var(--line);border-radius:14px;background:#fff}}input,select{{min-height:40px;border:1px solid #cbd6e5;border-radius:9px;padding:0 11px;background:#fff}}.finding{{margin:16px 0;padding:24px;border:1px solid var(--line);border-radius:18px;background:#fff;box-shadow:0 8px 24px rgba(15,35,64,.05)}}.finding[hidden]{{display:none}}.finding header{{display:flex;justify-content:space-between;gap:14px}}.finding h2{{margin:14px 0 4px;font-size:22px}}.finding h3{{margin:18px 0 6px;font-size:14px}}.location,.unavailable,.standards{{color:var(--muted)}}.standards{{white-space:pre-line}}.source-severity{{display:inline-flex;padding:4px 8px;border-radius:999px;font-size:11px;font-weight:800}}.source-severity--critical{{color:var(--critical);background:#fff0ee}}.source-severity--high{{color:var(--high);background:#fff4e8}}.source-severity--medium{{color:var(--medium);background:#fff8d8}}.source-severity--low,.source-severity--info{{color:var(--low);background:#ecfdf3}}pre,.source-context{{overflow:auto;padding:14px;border-radius:10px;background:#0d1b2e;color:#dce8f8}}pre{{white-space:pre-wrap}}.source-code-line{{display:grid;grid-template-columns:48px 1fr;gap:12px;padding:2px 8px}}.source-code-line span{{color:#7890ad;text-align:right}}.source-code-line code{{color:inherit;white-space:pre}}.source-code-line--focus{{background:#46350e;outline:1px solid #d6a514}}@media(max-width:760px){{.toolbar{{grid-template-columns:1fr}}.report-head{{align-items:flex-start;flex-wrap:wrap}}.external-classification-badge{{margin-left:0}}}}
</style></head><body><main data-standard="{html.escape(str(scan.get('standard') or DEFAULT_STANDARD), quote=True)}"><header class="report-head"><div><small>{report_context} · {html.escape(str(scan.get('standard') or DEFAULT_STANDARD))}</small><h1>{html.escape(title)}</h1></div><span class="external-classification-badge">대외 비공개</span><div class="language-buttons"><button id="lang-ko" type="button">한국어</button><button id="lang-en" type="button">English</button></div></header><div class="toolbar"><input id="query" type="search" placeholder="{'검색' if is_ko else 'Search findings'}"><select id="severity"><option value="">{'전체 심각도' if is_ko else 'All severities'}</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select><select id="location"><option value="">{html.escape(all_locations)}</option>{options}</select></div><p><span id="visibleCount">{len(findings)}</span> / {len(findings)}</p><section id="findings">{cards_html}</section></main><script>(function(){{const q=document.getElementById('query'),s=document.getElementById('severity'),l=document.getElementById('location'),c=document.getElementById('visibleCount');function filter(){{let visible=0;document.querySelectorAll('.finding').forEach(card=>{{const hidden=(q.value&&!card.dataset.search.includes(q.value.toLowerCase()))||(s.value&&card.dataset.severity!==s.value)||(l.value&&card.dataset.location!==l.value);card.hidden=hidden;if(!hidden)visible++;}});c.textContent=visible;}}[q,s,l].forEach(control=>{{control.addEventListener('input',filter);control.addEventListener('change',filter);}});}})();</script></body></html>'''


def _format_main_count(value: object) -> str:
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, int):
        return f"{value:,}"
    return str(value)


def build_dashboard_payload(
    findings: list[Finding],
    target_names: tuple[str, ...] = (),
    language: str = "en",
    *,
    target_paths: dict[str, str] | None = None,
    warnings: tuple[str, ...] = (),
    scan_path: str | None = None,
    kind: str = "directory",
    standard: str = DEFAULT_STANDARD,
    standard_category: str = DEFAULT_STANDARD_CATEGORY,
    components: tuple[DependencyComponent, ...] = (),
    enable_osv: bool = False,
    scanned_categories: tuple[str, ...] = (),
    source_analysis: object | None = None,
) -> dict[str, object]:
    generated, generated_display = _generated_at()
    summary = _summary(findings, target_names, target_paths, source_analysis)
    summary["raw_finding_count"] = len(findings)
    summary["displayed_finding_count"] = len(findings)
    labels = _labels(language)
    sw49 = (
        sw49_payload(findings, scanned_categories, standard_category, source_analysis)
        if standard == "sw-dev-security-49"
        else None
    )
    rule_mappings = _rule_mappings_for_findings(findings, standard, standard_category)
    payload = {
        "sw49": sw49,
        "generated_at": generated,
        "generated_display": generated_display,
        "language": labels["html_lang"],
        "labels_by_language": TRANSLATIONS,
        "standards": standards_payload(),
        "rule_mappings": rule_mappings,
        "components": [component_payload(component) for component in components],
        "sbom": cyclonedx_payload(components),
        "nis_sbom": nis_sbom_payload(components, product_name=target_names[0] if target_names else "KODA scan"),
        "scanner": {"name": "KODA", "version": __version__},
        "summary": summary,
        "scan": {
            "kind": kind,
            "path": scan_path or "",
            "standard": standard,
            "standard_category": standard_category,
            "scanned_categories": list(scanned_categories),
            "warnings": list(warnings),
            "enable_osv": enable_osv,
            "coverage_message": "현재 활성화된 점검 범위에서 탐지된 항목입니다." if kind == "web" else "",
        },
        "findings_by_language": {
            "en": [
                _finding_payload(finding, rule_mappings.get(finding.rule_id, ()))
                for finding in findings
            ],
            "ko": [
                _localized_finding_payload(
                    finding,
                    "ko",
                    rule_mappings.get(finding.rule_id, ()),
                )
                for finding in findings
            ],
        },
    }
    if source_analysis is not None:
        payload["source_analysis"] = _source_analysis_payload(source_analysis)
    return payload


@lru_cache(maxsize=1)
def _koda_mark_data_uri() -> str:
    """KODA app icon as a data URI so offline HTML reports stay self-contained."""
    mark = Path(__file__).with_name("assets") / "koda-mark.png"
    try:
        return "data:image/png;base64," + base64.b64encode(mark.read_bytes()).decode("ascii")
    except OSError:
        return "data:,"


def _html_replacements(labels: dict[str, object], json_payload: str) -> dict[str, str]:
    return {
        "__DATA__": json_payload,
        "__KODA_MARK__": _koda_mark_data_uri(),
        "__INITIAL_LANG__": html.escape(str(labels["html_lang"]), quote=True),
        "__INITIAL_TITLE__": html.escape(str(labels["title"]), quote=True),
        "__INITIAL_HELP__": html.escape(str(labels["help"])),
        "__INITIAL_SCREEN_QUALITY__": html.escape(str(labels["screen_quality"])),
        "__INITIAL_SCREEN_QUALITY_TITLE__": html.escape(str(labels["screen_quality_title"])),
        "__INITIAL_SCREEN_QUALITY_INTRO__": html.escape(str(labels["screen_quality_intro"])),
        "__INITIAL_SCREEN_QUALITY_RUN__": html.escape(str(labels["screen_quality_run"])),
        "__INITIAL_SCREEN_QUALITY_NOTE__": html.escape(str(labels["screen_quality_note"])),
        "__INITIAL_HELP_TITLE__": html.escape(str(labels["help_title"])),
        "__INITIAL_HELP_INTRO__": html.escape(str(labels["help_intro"])),
        "__INITIAL_FILTERS__": html.escape(str(labels["filters"]), quote=True),
        "__INITIAL_SCAN_DIRECTORY__": html.escape(str(labels["scan_directory"])),
        "__INITIAL_SCAN_STANDARD__": html.escape(str(labels["scan_standard"])),
        "__INITIAL_SCAN_STANDARD_CATEGORY__": html.escape(str(labels["scan_standard_category"])),
        "__INITIAL_SCAN_PATH_PLACEHOLDER__": html.escape(str(labels["scan_path_placeholder"]), quote=True),
        "__INITIAL_CHOOSE_FOLDER__": html.escape(str(labels["choose_folder"])),
        "__INITIAL_SCAN_NOW__": html.escape(str(labels["scan_now"])),
        "__INITIAL_UPLOAD_SCAN_TITLE__": html.escape(str(labels["upload_scan_title"])),
        "__INITIAL_UPLOAD_SCAN_NOW__": html.escape(str(labels["upload_scan_now"])),
        "__INITIAL_UPLOAD_SCAN_NOTE__": html.escape(str(labels["upload_scan_note"])),
        "__INITIAL_WEB_SCAN_TITLE__": html.escape(str(labels["web_scan_title"])),
        "__INITIAL_WEB_URL_PLACEHOLDER__": html.escape(str(labels["web_url_placeholder"]), quote=True),
        "__INITIAL_WEB_SCAN_NOW__": html.escape(str(labels["web_scan_now"])),
        "__INITIAL_ZAP_SCAN_TITLE__": html.escape(str(labels["zap_scan_title"])),
        "__INITIAL_ZAP_SCAN_NOW__": html.escape(str(labels["zap_scan_now"])),
        "__INITIAL_PREVENTION_KIT_TITLE__": html.escape(str(labels["prevention_kit_title"])),
        "__INITIAL_PREVENTION_APPLY_TOOLKIT__": html.escape(str(labels["prevention_apply_toolkit"])),
        "__INITIAL_PREVENTION_INSTALL_HOOK__": html.escape(str(labels["prevention_install_hook"])),
        "__INITIAL_PREVENTION_CREATE_IGNORE__": html.escape(str(labels["prevention_create_ignore"])),
        "__INITIAL_DISCOVER_PROJECTS__": html.escape(str(labels["discover_projects"])),
        "__INITIAL_SCAN_STATUS_IDLE__": html.escape(str(labels["scan_status_idle"])),
        "__INITIAL_SEARCH_PLACEHOLDER__": html.escape(str(labels["search_placeholder"]), quote=True),
        "__INITIAL_RESET__": html.escape(str(labels["reset"])),
        "__INITIAL_PROJECT_RISK__": html.escape(str(labels["project_risk"])),
        "__INITIAL_SEVERITY_DISTRIBUTION__": html.escape(str(labels["severity_distribution"])),
        "__INITIAL_SEVERITY__": html.escape(str(labels["severity"])),
        "__INITIAL_FINDING__": html.escape(str(labels["finding"])),
        "__INITIAL_TARGET__": html.escape(str(labels["target"])),
        "__INITIAL_LOCATION__": html.escape(str(labels["location"])),
        "__INITIAL_EVIDENCE__": html.escape(str(labels["evidence"])),
        "__INITIAL_ACTION__": html.escape(str(labels["action"])),
        "__INITIAL_EMPTY__": html.escape(str(labels["no_findings_display"])),
    }


def _localized_mapping_value(value: object, language: str) -> str:
    if isinstance(value, dict):
        return str(value.get(language) or value.get("ko") or value.get("en") or "")
    return str(value or "")


def _standard_mapping_text(mapping: dict[str, object], language: str) -> str:
    """Human-readable standard reference, including official SW49 item and CWE."""
    standard_id = str(mapping.get("standard_id") or mapping.get("standard") or "")
    standard = _localized_mapping_value(
        mapping.get("standard_labels") or mapping.get("standard_label") or standard_id,
        language,
    )
    guide_id = str(mapping.get("guide_id") or "").strip()
    koda_id = str(mapping.get("official_id") or "").strip()
    title = _localized_mapping_value(
        mapping.get("control_title") or mapping.get("title"),
        language,
    )
    cwe_ids = mapping.get("cwe_ids")
    cwe = ", ".join(str(item) for item in cwe_ids) if isinstance(cwe_ids, (list, tuple)) else ""
    if guide_id or koda_id or title:
        item_id = f"{guide_id} ({koda_id})" if guide_id and koda_id else guide_id or koda_id
        item = " ".join(part for part in (item_id, title) if part)
        return "\n".join(part for part in (standard, item, cwe) if part)

    category = _localized_mapping_value(
        mapping.get("category_labels") or mapping.get("category_label") or mapping.get("category_id"),
        language,
    )
    return "\n".join(part for part in (standard, category) if part)


def _rule_mappings_for_findings(
    findings: list[Finding],
    standard_id: str = "",
    category_id: str = DEFAULT_STANDARD_CATEGORY,
) -> dict[str, list[dict[str, object]]]:
    rule_ids = {finding.rule_id for finding in findings}
    if not rule_ids:
        return {}
    all_mappings = rule_standard_mappings_payload()
    resolved: dict[str, list[dict[str, object]]] = {}
    for rule_id in sorted(rule_ids):
        values = all_mappings.get(rule_id, [])
        selected = [
            mapping
            for mapping in values
            if (not standard_id or str(mapping.get("standard_id") or "") == standard_id)
            and (
                not category_id
                or category_id == DEFAULT_STANDARD_CATEGORY
                or str(mapping.get("category_id") or "") == category_id
            )
        ]
        resolved[rule_id] = selected if standard_id else values
    return resolved


def write_report(content: str, output: Path | None) -> None:
    if output is None:
        print(content, end="")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8", newline="")


_SOURCE_CONTEXT_BEFORE = 3
_SOURCE_CONTEXT_AFTER = 3
_SOURCE_CONTEXT_MAX_BYTES = 5 * 1024 * 1024


def _redact_source_line(line: str) -> str:
    redacted = line
    for rule in SECRET_RULES:
        for match in rule.pattern.finditer(redacted):
            try:
                secret_value = match.group(rule.secret_group)
            except (IndexError, AttributeError):
                secret_value = ""
            if secret_value:
                redacted = _redact_line(redacted, secret_value)
    return redacted


def _source_context_payload(finding: Finding) -> dict[str, object]:
    """Return a bounded, report-safe source window for a file finding.

    Secret findings intentionally keep line numbers but replace every source
    line with a redaction marker. This prevents private-key bodies or unusual
    token formats from being copied into the HTML/embedded JSON.
    """
    if finding.line is None or finding.resource:
        return {"available": False, "reason": "no_file_line", "lines": []}
    try:
        path = finding.path
        if not path.is_file():
            return {"available": False, "reason": "file_unavailable", "lines": []}
        if path.stat().st_size > _SOURCE_CONTEXT_MAX_BYTES:
            return {"available": False, "reason": "file_too_large", "lines": []}
        source_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, UnicodeError):
        return {"available": False, "reason": "file_unavailable", "lines": []}

    focus_line = int(finding.line)
    if focus_line < 1 or focus_line > len(source_lines):
        return {"available": False, "reason": "line_unavailable", "lines": []}
    start_line = max(1, focus_line - _SOURCE_CONTEXT_BEFORE)
    end_line = min(len(source_lines), focus_line + _SOURCE_CONTEXT_AFTER)
    secret_finding = finding.category == "secrets"
    context_lines = []
    for number in range(start_line, end_line + 1):
        source_line = source_lines[number - 1]
        if secret_finding:
            display_line = "<redacted sensitive source line>"
            redacted = True
        else:
            display_line = _redact_source_line(source_line)
            redacted = display_line != source_line
        context_lines.append(
            {
                "number": number,
                "text": display_line,
                "is_focus": number == focus_line,
                "redacted": redacted,
            }
        )
    return {
        "available": True,
        "start_line": start_line,
        "end_line": end_line,
        "focus_line": focus_line,
        "lines": context_lines,
    }


def _finding_payload(
    finding: Finding,
    standard_mappings: tuple[dict[str, object], ...] | list[dict[str, object]] = (),
) -> dict[str, object]:
    payload = {
        "rule_id": finding.rule_id,
        "category": finding.category,
        "severity": finding.severity,
        "title": finding.title,
        "target": finding.target,
        "path": str(finding.path),
        "line": finding.line,
        "evidence": finding.evidence,
        "description": finding.description,
        "recommendation": finding.recommendation,
        "resource": finding.resource,
        "reachable": finding.reachable,
        "verification_status": finding.verification_status,
        "verification_note": finding.verification_note,
        "triage_verdict": finding.triage_verdict,
        "triage_confidence": finding.triage_confidence,
        "triage_note": finding.triage_note,
        "analyzer": finding.analyzer,
        "analyzer_version": finding.analyzer_version,
        "analyzer_rule_id": finding.analyzer_rule_id,
        "cwe_ids": list(finding.cwe_ids),
        "evidence_kind": finding.evidence_kind,
        "trace": [dict(step) for step in finding.trace],
        "evidence_id": finding.evidence_id,
        "issue_key": finding.issue_key,
        "standard_mappings": [dict(mapping) for mapping in standard_mappings],
    }
    if finding.line is not None and not finding.resource:
        payload["source_context"] = _source_context_payload(finding)
    return payload


def _localized_finding_payload(
    finding: Finding,
    language: str,
    standard_mappings: tuple[dict[str, object], ...] | list[dict[str, object]] = (),
) -> dict[str, object]:
    payload = _finding_payload(finding, standard_mappings)
    if language != "ko":
        return payload

    translated = RULE_TRANSLATIONS_KO.get(finding.rule_id)
    if not translated:
        return payload

    payload.update(translated)
    return payload


def _summary(
    findings: list[Finding],
    target_names: tuple[str, ...] = (),
    target_paths: dict[str, str] | None = None,
    source_analysis: object | None = None,
) -> dict[str, object]:
    by_target = Counter({target: 0 for target in target_names})
    by_target.update(finding.target for finding in findings)
    by_severity = Counter(finding.severity for finding in findings)
    confirmed_by_severity = Counter(
        finding.severity for finding in findings if finding.verification_status == "confirmed"
    )
    risk_score = sum(confirmed_by_severity[severity] * SEVERITY_WEIGHTS[severity] for severity in SEVERITIES)
    resolved_target_paths = dict(target_paths or {})
    return {
        "target_count": len(target_names) if target_names else len({finding.target for finding in findings if finding.target}),
        "risk_score": risk_score,
        "by_severity": dict(by_severity),
        "by_verification": dict(Counter(finding.verification_status for finding in findings)),
        "by_category": dict(Counter(finding.category for finding in findings)),
        "by_target": dict(by_target),
        "target_paths": resolved_target_paths,
        "analyzed_languages": _source_analysis_languages(source_analysis),
    }


def _source_analysis_languages(source_analysis: object | None) -> list[str]:
    if isinstance(source_analysis, dict):
        values = source_analysis.get("analyzed_languages", ())
    else:
        values = getattr(source_analysis, "analyzed_languages", ())
    if not isinstance(values, (list, tuple, set, frozenset)):
        return []
    return sorted({str(value) for value in values if str(value).strip()})


def _labels(language: str) -> dict[str, object]:
    return TRANSLATIONS.get(language, TRANSLATIONS["en"])


def _category_label(category: str, language: str) -> str:
    category_labels = _labels(language).get("category_labels", {})
    if isinstance(category_labels, dict):
        return str(category_labels.get(category, category))
    return category


def _target_display(target: str, summary: dict[str, object]) -> str:
    if not target:
        return ""
    target_paths = summary.get("target_paths", {})
    if isinstance(target_paths, dict):
        return str(target_paths.get(target, target))
    return target


def _generated_at() -> tuple[str, str]:
    generated = datetime.now().astimezone()
    return generated.isoformat(timespec="seconds"), generated.strftime("%Y-%m-%d %H:%M:%S")


def _sarif_rule(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description or finding.title},
        "help": {"text": finding.recommendation or "Review this finding."},
        "properties": {
            "category": finding.category,
            "severity": finding.severity,
            "security-severity": SEVERITY_SECURITY_SCORES[finding.severity],
        },
    }


def _sarif_result(finding: Finding) -> dict[str, object]:
    region = {"startLine": finding.line or 1}
    result = {
        "ruleId": finding.rule_id,
        "level": _sarif_level(finding.severity),
        "message": {"text": _sarif_message(finding)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": str(finding.path)},
                    "region": region,
                }
            }
        ],
        "properties": {
            "category": finding.category,
            "severity": finding.severity,
            "target": finding.target,
            "evidence": finding.evidence,
            "verification_status": finding.verification_status,
            "verification_note": finding.verification_note,
            "analyzer": finding.analyzer,
            "analyzer_version": finding.analyzer_version,
            "analyzer_rule_id": finding.analyzer_rule_id,
            "cwe_ids": list(finding.cwe_ids),
            "evidence_kind": finding.evidence_kind,
            "evidence_id": finding.evidence_id,
            "issue_key": finding.issue_key,
        },
    }
    if finding.trace:
        result["codeFlows"] = [{"threadFlows": [{"locations": [{"location": {"physicalLocation": {"artifactLocation": {"uri": str(step.get("path", ""))}, "region": {"startLine": int(step.get("line") or 1)}}, "message": {"text": str(step.get("message", ""))}}} for step in finding.trace]}]}]
    return result


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity in {"medium", "low"}:
        return "warning"
    return "note"


def _sarif_message(finding: Finding) -> str:
    parts = [finding.title]
    if finding.evidence:
        parts.append(f"Evidence: {finding.evidence}")
    if finding.recommendation:
        parts.append(f"Recommendation: {finding.recommendation}")
    return " | ".join(parts)


HTML_TEMPLATE = """<!doctype html>
<html lang="__INITIAL_LANG__">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="data:,">
  <title>__INITIAL_TITLE__</title>
<style>
    :root {
      --bg: #f6f7f9;
      --panel: #ffffff;
      --ink: #14171f;
      --muted: #667085;
      --line: #d9dee8;
      --critical: #7f1d1d;
      --high: #c2410c;
      --medium: #b7791f;
      --low: #2563eb;
      --info: #64748b;
      --ok: #0f766e;
      --focus: #3157d5;
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 14px;
      line-height: 1.45;
    }

    header {
      background: #111827;
      color: #fff;
      border-bottom: 1px solid #0b1220;
    }

    .shell {
      width: min(1440px, calc(100vw - 32px));
      margin: 0 auto;
    }

    .topbar {
      position: relative;
      min-height: 76px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 24px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .brand-mark {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      flex: none;
    }

    h1 {
      margin: 0;
      font-size: 24px;
      font-weight: 700;
      letter-spacing: 0;
    }

    .meta {
      color: #cbd5e1;
      font-size: 13px;
      text-align: right;
      white-space: nowrap;
    }

    .header-side {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .topbar-actions {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    .topbar-action {
      min-width: 78px;
      min-height: 30px;
      padding: 5px 12px;
      border: 1px solid rgba(203, 213, 225, 0.42);
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.7);
      color: #ffffff;
      font-size: 12px;
      font-weight: 800;
      flex: 0 0 auto;
    }

    .settings-icon {
      display: inline-block;
      font-size: 1.45em;
      line-height: .7;
      vertical-align: -0.08em;
    }

    .topbar-action-link {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      text-decoration: none;
    }

    .topbar-menu {
      position: relative;
      display: inline-block;
      flex: 0 0 auto;
    }

    .topbar-menu > summary {
      position: relative;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      list-style: none;
      white-space: nowrap;
      padding-right: 28px;
    }

    .topbar-menu > summary::-webkit-details-marker { display: none; }
    .topbar-menu > summary::after {
      content: "";
      position: absolute;
      top: 50%;
      right: 12px;
      width: 6px;
      height: 6px;
      border-right: 2px solid currentColor;
      border-bottom: 2px solid currentColor;
      transform: translateY(-50%) rotate(45deg);
    }

    .topbar-menu-list {
      position: absolute;
      top: calc(100% + 6px);
      right: 0;
      z-index: 20;
      display: grid;
      gap: 6px;
      min-width: 190px;
      padding: 8px;
      border: 1px solid rgba(203, 213, 225, 0.42);
      border-radius: 8px;
      background: #111827;
      box-shadow: 0 10px 24px rgba(15, 23, 42, 0.24);
    }

    .topbar-menu-list button {
      width: 100%;
      min-width: 0;
      text-align: left;
      white-space: nowrap;
    }

    .language-toggle {
      display: inline-flex;
      overflow: hidden;
      border: 1px solid rgba(203, 213, 225, 0.42);
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.7);
      flex: 0 0 auto;
    }

    .language-toggle button {
      width: 42px;
      min-width: 42px;
      min-height: 30px;
      padding: 5px 9px;
      border: 0;
      border-radius: 0;
      background: transparent;
      color: #cbd5e1;
      font-size: 12px;
      font-weight: 800;
    }

    .language-toggle button.active {
      background: #ffffff;
      color: #111827;
    }

    main {
      padding: 24px 0 36px;
    }

    .metrics {
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 16px;
    }

    .metric, .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
    }

    .metric {
      padding: 14px;
      min-height: 96px;
    }

    .metric-label {
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0;
    }

    .metric-value {
      margin-top: 8px;
      font-size: 30px;
      line-height: 1;
      font-weight: 760;
    }

    .metric-sub {
      margin-top: 8px;
      color: var(--muted);
      font-size: 12px;
    }

    .risk-score-note {
      margin: -6px 0 16px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.5;
    }

    .critical { color: var(--critical); }
    .high { color: var(--high); }
    .medium { color: var(--medium); }
    .low { color: var(--low); }
    .info { color: var(--info); }
    .ok { color: var(--ok); }

    .filters {
      display: grid;
      grid-template-columns: minmax(220px, 2fr) repeat(3, minmax(140px, 1fr)) auto;
      gap: 10px;
      padding: 12px;
      margin-bottom: 16px;
      align-items: center;
    }

    .scan-panel {
      display: grid;
      gap: 12px;
      margin-bottom: 16px;
    }

    .scan-panel h2 {
      margin: 0;
      font-size: 15px;
      line-height: 1.2;
    }

    .scan-form {
      display: grid;
      grid-template-columns: minmax(180px, 1fr) auto;
      gap: 10px;
      align-items: center;
    }

    .scan-form .path-display {
      min-width: 0;
      min-height: 34px;
      padding: 7px 10px;
      font-size: 13px;
    }

    .scan-standard-form {
      display: grid;
      grid-template-columns: repeat(2, minmax(220px, 1fr));
      gap: 10px;
      align-items: end;
    }

    .scan-web-form {
      display: grid;
      grid-template-columns: auto minmax(240px, 1fr) auto;
      gap: 10px;
      align-items: center;
      margin-top: 10px;
      padding: 12px;
      border: 1px solid var(--border, #dbe4ef);
      border-radius: 12px;
      background: #f8fafc;
    }

    .scan-web-form .scan-note {
      grid-column: 1 / -1;
    }

    .scan-web-title {
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      white-space: nowrap;
    }

    /* Keep the crawl/login/active options full-width while the checkbox grid
       owns its responsive columns. */
    .scan-web-options {
      grid-column: 1 / -1;
      justify-self: stretch;
      width: 100%;
      min-width: 0;
      max-width: none;
      box-sizing: border-box;
      padding: 8px 0 2px;
    }
    .scan-web-options-content {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px 12px;
      align-items: start;
      min-width: 0;
    }
    .scan-web-options > summary {
      grid-column: 1 / -1;
      cursor: pointer;
      color: var(--muted);
      font-size: 12px;
      font-weight: 600;
    }
    .scan-option-select-all {
      grid-column: 1 / -1;
      justify-self: end;
      min-height: 28px;
      padding: 4px 10px;
      border: 1px solid var(--border, #cbd5e1);
      border-radius: 7px;
      background: #f8fafc;
      color: var(--ink, #0f172a);
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
    }
    .scan-web-check {
      display: flex;
      align-items: center;
      gap: 6px;
      min-width: 0;
      line-height: 1.35;
    }
    .scan-web-check span {
      min-width: 0;
      white-space: nowrap;
      overflow-wrap: normal;
    }
    .scan-web-check input[type="checkbox"] { flex: 0 0 auto; width: auto; margin: 0; }
    .scan-web-check.span-all { grid-column: 1 / -1; }
    .scan-web-login {
      grid-column: 1 / -1;
      display: flex;
      flex-direction: column;
      gap: 4px;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px;
      margin: 0;
      background: #eef6ff;
    }
    .scan-web-headers {
      grid-column: span 1;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .scan-web-headers-wide {
      grid-column: span 2;
      width: min(600px, 100%);
    }
    .scan-web-textareas {
      grid-column: 1 / -1;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px 12px;
      min-width: 0;
    }
    .scan-web-options input:not([type="checkbox"]),
    .scan-web-options textarea {
      width: 100%;
      box-sizing: border-box;
    }
    #web-api-spec {
      height: 37px;
      min-height: 37px;
    }
    #zap-options-content {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .scan-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }

    .scan-select {
      display: grid;
      gap: 6px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }

    .scan-option {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: var(--muted);
      font-weight: 700;
      white-space: nowrap;
    }

    .scan-option input {
      width: auto;
      min-height: auto;
      margin: 0;
    }

    .scan-note {
      color: var(--muted);
      font-size: 12px;
    }

    .scan-status {
      min-height: 20px;
      color: var(--muted);
      overflow-wrap: anywhere;
      font-size: 13px;
    }

    .scan-status.error {
      color: var(--critical);
      font-weight: 700;
    }

    .scan-status.ok {
      color: var(--ok);
      font-weight: 700;
    }

    .path-display {
      cursor: default;
      background: #f8fafc;
    }

    input, select, button {
      width: 100%;
      min-height: 38px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--ink);
      font: inherit;
      padding: 8px 10px;
    }

    button {
      width: auto;
      min-width: 88px;
      background: #111827;
      color: #fff;
      border-color: #111827;
      font-weight: 700;
      cursor: pointer;
    }

    input:focus, select:focus, button:focus {
      outline: 2px solid var(--focus);
      outline-offset: 1px;
    }

    .grid {
      display: grid;
      grid-template-columns: minmax(320px, 0.9fr) minmax(0, 1.4fr);
      gap: 16px;
      margin-bottom: 16px;
    }

    .panel {
      padding: 16px;
      min-width: 0;
    }

    .panel h2 {
      margin: 0 0 12px;
      font-size: 15px;
      line-height: 1.2;
    }

    .bars {
      display: grid;
      gap: 11px;
    }

    .bar-row {
      display: grid;
      grid-template-columns: 78px 1fr 40px;
      gap: 10px;
      align-items: center;
    }

    .bar-label {
      color: var(--muted);
      font-weight: 700;
      text-transform: capitalize;
    }

    .bar-track {
      height: 10px;
      border-radius: 999px;
      background: #eef2f7;
      overflow: hidden;
    }

    .bar-fill {
      height: 100%;
      min-width: 0;
      border-radius: inherit;
    }

    .project-list {
      display: grid;
      gap: 8px;
      max-height: 280px;
      overflow: auto;
      padding-right: 2px;
    }

    .project-row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: center;
      padding: 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fbfcfe;
    }

    .project-name {
      overflow-wrap: anywhere;
      font-weight: 700;
    }

    .project-count {
      color: var(--muted);
      font-variant-numeric: tabular-nums;
    }

    .table-wrap {
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 960px;
      table-layout: fixed;
    }

    th, td {
      padding: 11px 12px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }

    th {
      position: sticky;
      top: 0;
      z-index: 1;
      background: #f8fafc;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
      min-width: 76px;
      overflow: hidden;
      resize: horizontal;
      cursor: col-resize;
      user-select: none;
    }

    tr:last-child td {
      border-bottom: 0;
    }

    .severity-pill {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 72px;
      min-height: 24px;
      border-radius: 999px;
      padding: 2px 8px;
      color: #fff;
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
    }

    .pill-critical { background: var(--critical); }
    .pill-high { background: var(--high); }
    .pill-medium { background: var(--medium); color: #111827; }
    .pill-low { background: var(--low); }
    .pill-info { background: var(--info); }

    .location, .evidence {
      max-width: 380px;
      color: var(--muted);
      overflow-wrap: anywhere;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 12px;
    }

    details {
      max-width: 1040px;
    }

    summary {
      cursor: pointer;
      font-weight: 700;
    }

    .detail-body {
      margin-top: 8px;
      color: var(--muted);
    }

    .source-context {
      margin-top: 14px;
      max-width: 780px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #f8fafc;
    }

    .source-context > summary {
      padding: 10px 12px;
      color: var(--ink);
    }

    .source-code {
      overflow-x: auto;
      padding: 8px 0;
      border-top: 1px solid var(--line);
      background: #0f172a;
      color: #e2e8f0;
      font: 12px/1.65 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    }

    .source-code-line {
      display: grid;
      grid-template-columns: 56px minmax(0, 1fr);
      min-width: max-content;
      padding: 2px 14px 2px 0;
      white-space: pre;
    }

    .source-code-line.is-focus {
      border-left: 3px solid #f59e0b;
      padding-left: 0;
      background: rgba(245, 158, 11, 0.18);
      color: #fff7ed;
      font-weight: 700;
    }

    .source-code-number {
      padding-right: 12px;
      color: #94a3b8;
      text-align: right;
      user-select: none;
    }

    .source-code-line.is-focus .source-code-number {
      color: #fbbf24;
    }

    .source-problem-label {
      margin-left: 12px;
      color: #fbbf24;
      font-size: 11px;
      font-weight: 800;
    }

    .source-context-unavailable {
      margin: 14px 0 0;
      padding: 10px 12px;
      border-left: 3px solid #94a3b8;
      color: var(--muted);
      background: #f8fafc;
    }

    .empty {
      padding: 36px;
      text-align: center;
      color: var(--muted);
    }

    .help-view {
      display: grid;
      gap: 14px;
    }

    .help-view[hidden] {
      display: none;
    }

    .scan-run-row {
      display: flex;
      gap: 8px;
      min-width: 0;
    }
    .scan-run-row > button {
      flex: 1 1 0;
      min-width: 0;
      min-height: 34px;
      padding: 7px 11px;
      font-size: 13px;
      white-space: nowrap;
    }
    .report-download {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
      margin-top: 10px;
    }
    #report-download-open {
      cursor: pointer;
      font-weight: 600;
    }
    .report-download-btn {
      cursor: pointer;
    }
    .download-dialog {
      border: 1px solid var(--border, #cbd5e1);
      border-radius: 12px;
      padding: 18px;
      min-width: 280px;
      color: inherit;
      background: var(--panel, #ffffff);
    }
    .download-dialog::backdrop {
      background: rgba(15, 23, 42, 0.45);
    }
    .download-dialog-title {
      margin: 0 0 12px;
      font-weight: 700;
    }
    .download-dialog-standard {
      display: grid;
      gap: 4px;
      margin-bottom: 12px;
    }
    .download-dialog-standard select {
      width: 100%;
      padding: 6px 8px;
      border-radius: 8px;
      border: 1px solid var(--border, #cbd5e1);
    }
    .download-dialog-formats {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
    }
    .download-dialog-formats .report-download-btn {
      width: 100%;
    }
    .download-dialog-cancel {
      margin-top: 12px;
      width: 100%;
      cursor: pointer;
    }
    .download-notice-body {
      margin: 0 0 14px;
      color: var(--muted, #64748b);
      line-height: 1.5;
    }
    .settings-tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    #settings-collapse-all,
    #settings-expand-all {
      min-width: 54px;
      font-size: 18px;
      line-height: 1;
      background: #fff;
      border-color: #cbd5e1;
      color: #334155;
    }
    #settings-collapse-all:hover,
    #settings-expand-all:hover {
      background: #f1f5f9;
      color: #0f172a;
    }
    .settings-tab {
      cursor: pointer;
      border: 1px solid var(--border, #cbd5e1);
      background: rgba(148, 163, 184, 0.22);
      color: inherit;
      border-radius: 999px;
      padding: 6px 18px;
      font-weight: 600;
    }
    .settings-tab.active {
      background: var(--accent, #2563eb);
      color: #fff;
      border-color: transparent;
    }
    .settings-reset {
      margin-left: 0;
      cursor: pointer;
    }
    #settings-disable-all { margin-left: auto; }
    .settings-groups {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
      width: 100%;
    }
    #settings-view { width: 100%; }
    .settings-group {
      width: 100%;
      box-sizing: border-box;
      border: 1px solid var(--border, #e2e8f0);
      border-radius: 12px;
      padding: 12px 14px;
    }
    .settings-group > summary {
      cursor: pointer;
      font-weight: 700;
      font-size: 15px;
    }
    .settings-group--quality {
      grid-column: 1 / -1;
    }
    .settings-rule-list {
      display: grid;
    }
    .settings-group--quality .settings-rule-list {
      grid-template-columns: repeat(2, minmax(0, 1fr));
      column-gap: 14px;
    }
    .settings-group-summary {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .settings-group-toggle {
      width: auto;
      min-height: 28px;
      margin-left: auto;
      padding: 3px 10px;
      border: 1px solid var(--border, #cbd5e1);
      border-radius: 999px;
      background: #fff;
      color: var(--muted, #64748b);
      font-size: 11px;
      font-weight: 700;
      cursor: pointer;
    }
    .settings-group-toggle:hover {
      background: #f1f5f9;
      color: var(--ink, #0f172a);
    }
    .settings-rule {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
      padding: 8px 2px;
      border-top: 1px solid var(--border, #eef2f7);
    }
    .settings-rule:first-of-type { border-top: none; }
    .settings-rule-text { display: grid; gap: 2px; }
    .settings-rule-title { font-weight: 600; }
    .settings-rule-id { font-size: 12px; color: var(--muted); font-family: ui-monospace, monospace; }
    .settings-rule-desc { font-size: 13px; color: var(--muted); }
    .switch {
      position: relative;
      display: inline-block;
      width: 42px;
      height: 24px;
      flex: none;
    }
    .switch input { opacity: 0; width: 0; height: 0; }
    .switch .track {
      position: absolute;
      inset: 0;
      background: #cbd5e1;
      border-radius: 999px;
      transition: background 0.15s;
    }
    .switch .track::before {
      content: "";
      position: absolute;
      height: 18px;
      width: 18px;
      left: 3px;
      top: 3px;
      background: #fff;
      border-radius: 50%;
      transition: transform 0.15s;
    }
    .switch input:checked + .track { background: var(--accent, #2563eb); }
    .switch input:checked + .track::before { transform: translateX(18px); }

    @media print {
      header, #scan-panel, #filters-panel, #help-view, #settings-view,
      .topbar-actions, .language-toggle, .report-download, #scan-status { display: none !important; }
      body { background: #fff; color: #000; }
    }

    .help-heading {
      display: grid;
      gap: 6px;
      margin-bottom: 2px;
    }

    .help-heading h2 {
      margin: 0;
      font-size: 20px;
      line-height: 1.2;
    }

    .help-heading p {
      margin: 0;
      color: var(--muted);
    }

    .coverage-table {
      width: 100%;
      min-width: 760px;
      border-collapse: collapse;
      background: #ffffff;
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
    }

    .coverage-table th, .coverage-table td {
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
    }

    .coverage-table-wrap {
      overflow: auto;
      border-radius: 8px;
    }

    .status-badge {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      border-radius: 999px;
      padding: 3px 8px;
      background: #fff7ed;
      color: #9a3412;
      font-size: 12px;
      font-weight: 800;
      white-space: nowrap;
    }

    .status-badge.local {
      background: #ecfdf5;
      color: #047857;
    }

    .status-badge.external {
      background: #eff6ff;
      color: #1d4ed8;
    }

    .status-badge.evidence {
      background: #fff7ed;
      color: #9a3412;
    }

    .standards-help {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }

    .standard-card {
      display: grid;
      gap: 12px;
      min-width: 0;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
    }

    .standard-head {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: start;
    }

    .standard-card h3 {
      margin: 0 0 6px;
      font-size: 16px;
      line-height: 1.25;
    }

    .standard-card p {
      margin: 0;
      color: var(--muted);
    }

    .standard-count {
      min-width: 78px;
      border-radius: 999px;
      padding: 4px 8px;
      background: #eef2f7;
      color: var(--muted);
      font-size: 12px;
      font-weight: 800;
      text-align: center;
      white-space: nowrap;
    }

    .help-meta {
      display: grid;
      gap: 4px;
      color: var(--muted);
    }

    .help-meta strong {
      color: var(--ink);
    }

    .category-chips, .standard-links {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }

    .category-chip {
      border-radius: 999px;
      padding: 4px 8px;
      background: #eef6ff;
      color: #1d4ed8;
      font-size: 12px;
      font-weight: 800;
    }

    .category-chip.unsupported {
      background: #f1f5f9;
      color: var(--muted);
      font-weight: 700;
    }

    .rule-related {
      display: flex;
      flex-wrap: wrap;
      gap: 5px;
      margin-top: 6px;
    }

    .standard-links a {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      border-radius: 999px;
      padding: 4px 9px;
      background: #111827;
      color: #ffffff;
      font-size: 12px;
      font-weight: 800;
      text-decoration: none;
    }

    @media (max-width: 1000px) {
      .metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .filters, .scan-form, .scan-standard-form { grid-template-columns: 1fr 1fr; }
      .scan-web-options-content { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .settings-groups { grid-template-columns: 1fr; }
      .scan-actions { align-items: stretch; }
      .standards-help { grid-template-columns: 1fr; }
      .grid { grid-template-columns: 1fr; }
      button { width: 100%; }
      .settings-tabs button { width: auto; }
      .topbar-action { width: auto; }
    }

    @media (max-width: 640px) {
      .shell { width: min(100% - 20px, 1440px); }
      .topbar { align-items: flex-start; flex-direction: column; padding: 16px 0; gap: 8px; }
      .header-side { width: 100%; flex-wrap: wrap; }
      .topbar-actions { position: static; }
      .language-toggle { position: static; }
      .meta { text-align: left; white-space: normal; }
      .metrics, .filters, .scan-form, .scan-standard-form, .scan-web-form { grid-template-columns: 1fr; }
      .scan-web-options-content { grid-template-columns: 1fr; }
      #zap-options-content { grid-template-columns: 1fr; }
      .settings-group--quality .settings-rule-list { grid-template-columns: 1fr; }
      .scan-web-headers, .scan-web-login { grid-column: 1 / -1; }
      .scan-web-headers-wide { width: 100%; }
      .scan-web-textareas { grid-template-columns: 1fr; }
      .scan-actions { display: grid; grid-template-columns: 1fr; }
      .standard-head { grid-template-columns: 1fr; }
      .metric { min-height: 84px; }
      .metric-value { font-size: 26px; }
    }
  </style>
</head>
<body>
  <header>
    <div class="shell topbar">
      <div class="brand">
        <img class="brand-mark" src="__KODA_MARK__" alt="" width="32" height="32">
        <h1 id="dashboard-title">__INITIAL_TITLE__</h1>
      </div>
      <div class="header-side">
        <div class="topbar-actions">
          <div class="language-toggle" role="group" aria-label="Language">
            <button id="lang-ko" type="button">KO</button>
            <button id="lang-en" type="button">EN</button>
          </div>
          __INITIAL_SUMMARY_LINK_HTML__
          __INITIAL_SSBOM_TRACKER_LINK_HTML__
          <button id="help-toggle" class="topbar-action" type="button">__INITIAL_HELP__</button>
          <details id="prevention-kit-menu" class="topbar-menu">
            <summary id="prevention-kit-toggle" class="topbar-action">__INITIAL_PREVENTION_KIT_TITLE__</summary>
            <div class="topbar-menu-list" role="menu">
              <button id="prevention-apply-toolkit" type="button" role="menuitem">__INITIAL_PREVENTION_APPLY_TOOLKIT__</button>
              <button id="prevention-install-hook" type="button" role="menuitem">__INITIAL_PREVENTION_INSTALL_HOOK__</button>
              <button id="prevention-create-ignore" type="button" role="menuitem">__INITIAL_PREVENTION_CREATE_IGNORE__</button>
            </div>
          </details>
          <button id="settings-toggle" class="topbar-action" type="button"><span class="settings-icon" aria-hidden="true">⚙</span> 설정</button>
        </div>
        <div class="meta">
          <div id="generated-line"></div>
          <div id="summary-line"></div>
        </div>
      </div>
    </div>
  </header>

  <main class="shell">
    <div id="dashboard-view">
      <section class="panel scan-panel" id="scan-panel">
      <h2 id="scan-directory-title">__INITIAL_SCAN_DIRECTORY__</h2>
      <div class="scan-form">
        <input id="scan-path" class="path-display" type="text" autocomplete="off" readonly aria-readonly="true" placeholder="__INITIAL_SCAN_PATH_PLACEHOLDER__">
        <div class="scan-run-row">
          <button id="scan-choose" type="button">__INITIAL_CHOOSE_FOLDER__</button>
          <button id="scan-run" type="button">__INITIAL_SCAN_NOW__</button>
          <button id="screen-quality-run" type="button">__INITIAL_SCREEN_QUALITY_RUN__</button>
        </div>
      </div>
      <div class="scan-web-form">
        <label id="upload-scan-title" class="scan-web-title" for="scan-upload">__INITIAL_UPLOAD_SCAN_TITLE__</label>
        <input id="scan-upload" type="file">
        <button id="scan-upload-run" type="button">__INITIAL_UPLOAD_SCAN_NOW__</button>
        <span id="upload-scan-note" class="scan-note">__INITIAL_UPLOAD_SCAN_NOTE__</span>
      </div>
      <div class="scan-web-form">
        <span id="web-scan-title" class="scan-web-title">__INITIAL_WEB_SCAN_TITLE__</span>
        <input id="web-url" class="path-display" type="url" autocomplete="off" placeholder="__INITIAL_WEB_URL_PLACEHOLDER__">
        <details class="scan-web-options">
          <summary id="web-crawl-options-label"></summary>
          <div id="web-options-content" class="scan-web-options-content">
          <button id="web-options-select-all" class="scan-option-select-all" type="button"></button>
          <label class="scan-web-check"><input id="web-crawl" type="checkbox"> <span id="web-crawl-enable-label"></span></label>
          <label class="scan-web-check"><input id="web-render" type="checkbox"> <span id="web-render-enable-label"></span></label>
          <label class="scan-web-check"><input id="web-discover-assets" type="checkbox"> <span id="web-discover-assets-label"></span></label>
          <label class="scan-web-check"><input id="web-capture-network" type="checkbox"> <span id="web-capture-network-label"></span></label>
          <label class="scan-web-check"><input id="web-interact" type="checkbox"> <span id="web-interact-label"></span></label>
          <label class="scan-web-check"><input id="web-scan-js-secrets" type="checkbox"> <span id="web-scan-js-secrets-label"></span></label>
          <label class="scan-web-check"><input id="web-ingest-sitemap" type="checkbox"> <span id="web-ingest-sitemap-label"></span></label>
          <label class="scan-web-check"><input id="web-probe-paths" type="checkbox"> <span id="web-probe-paths-label"></span></label>
          <label class="scan-web-check"><input id="web-active" type="checkbox"> <span id="web-active-label"></span></label>
          <label class="scan-web-check"><input id="web-compare-unauth" type="checkbox"> <span id="web-compare-unauth-label"></span></label>
          <div class="scan-web-textareas">
          <label class="scan-web-headers"><span id="web-secondary-label"></span>
            <textarea id="web-secondary" rows="2" autocomplete="off"></textarea>
          </label>
          <label class="scan-web-headers"><span id="web-api-spec-label"></span>
            <textarea id="web-api-spec" rows="3" autocomplete="off"></textarea>
          </label>
          <label class="scan-web-headers"><span id="web-seeds-label"></span>
            <textarea id="web-seeds" rows="2" autocomplete="off"></textarea>
          </label>
          <label class="scan-web-headers"><span id="web-allowed-origins-label"></span>
            <textarea id="web-allowed-origins" rows="2" autocomplete="off"></textarea>
          </label>
          </div>
          <fieldset class="scan-web-login">
            <legend id="web-login-legend-label"></legend>
            <label><span id="web-login-url-label"></span> <input id="web-login-url" type="url" autocomplete="off"></label>
            <label><span id="web-login-user-label"></span> <input id="web-login-user" autocomplete="off"></label>
            <label><span id="web-login-pass-label"></span> <input id="web-login-pass" type="password" autocomplete="off"></label>
          </fieldset>
          <label class="scan-web-headers scan-web-headers-wide"><span id="web-headers-label"></span>
            <textarea id="web-headers" rows="2" autocomplete="off"></textarea>
          </label>
          </div>
        </details>
        <button id="web-scan-run" type="button">__INITIAL_WEB_SCAN_NOW__</button>
        <span id="web-scan-note" class="scan-note"></span>
      </div>
      <div class="scan-web-form">
        <span id="zap-scan-title" class="scan-web-title">__INITIAL_ZAP_SCAN_TITLE__</span>
        <input id="zap-url" class="path-display" type="url" autocomplete="off" placeholder="__INITIAL_WEB_URL_PLACEHOLDER__">
        <details class="scan-web-options">
          <summary id="zap-options-label"></summary>
          <div id="zap-options-content" class="scan-web-options-content">
          <button id="zap-options-select-all" class="scan-option-select-all" type="button"></button>
          <label class="scan-web-check"><input id="zap-ajax" type="checkbox"> <span id="zap-ajax-label"></span></label>
          <label class="scan-web-check"><input id="zap-merge" type="checkbox"> <span id="zap-merge-label"></span></label>
          <label class="scan-web-check"><input id="zap-active" type="checkbox"> <span id="zap-active-label"></span></label>
          <label class="scan-web-check"><input id="zap-authorized" type="checkbox"> <span id="zap-authorized-label"></span></label>
          <div class="scan-web-textareas">
          <label class="scan-web-headers"><span id="zap-include-label"></span>
            <textarea id="zap-include" rows="2" autocomplete="off"></textarea>
          </label>
          <label class="scan-web-headers"><span id="zap-exclude-label"></span>
            <textarea id="zap-exclude" rows="2" autocomplete="off"></textarea>
          </label>
          </div>
          <fieldset class="scan-web-login">
            <legend id="zap-login-legend-label"></legend>
            <label><span id="zap-login-url-label"></span> <input id="zap-login-url" type="url" autocomplete="off"></label>
            <label><span id="zap-login-user-label"></span> <input id="zap-login-user" autocomplete="off"></label>
            <label><span id="zap-login-pass-label"></span> <input id="zap-login-pass" type="password" autocomplete="off"></label>
          </fieldset>
          </div>
        </details>
        <button id="zap-scan-run" type="button">__INITIAL_ZAP_SCAN_NOW__</button>
        <span id="zap-scan-note" class="scan-note"></span>
      </div>
      <div class="scan-standard-form">
        <label class="scan-select">
          <span id="scan-standard-label">__INITIAL_SCAN_STANDARD__</span>
          <select id="scan-standard"></select>
        </label>
        <label class="scan-select">
          <span id="scan-standard-category-label">__INITIAL_SCAN_STANDARD_CATEGORY__</span>
          <select id="scan-standard-category"></select>
        </label>
      </div>
      <div class="scan-actions">
        <label class="scan-option" title="">
          <input id="scan-osv" type="checkbox">
          <span id="scan-osv-label"></span>
        </label>
        <label class="scan-option" title="">
          <input id="scan-host" type="checkbox">
          <span id="scan-host-label"></span>
        </label>
        <label class="scan-select">
          <span id="sbom-format-label"></span>
          <select id="sbom-format">
            <option value="cyclonedx"></option>
            <option value="nis-sbom"></option>
          </select>
        </label>
        <button id="sbom-download" type="button"></button>
        <span id="scan-osv-note" class="scan-note"></span>
        <span id="scan-host-note" class="scan-note"></span>
      </div>
      <div class="report-download" id="report-download">
        <button id="report-download-open" type="button"></button>
        <span id="report-download-note" class="scan-note"></span>
      </div>
      <dialog id="download-dialog" class="download-dialog">
        <p id="download-dialog-title" class="download-dialog-title"></p>
        <label class="download-dialog-standard">
          <span id="download-standard-label"></span>
          <select id="download-standard"></select>
        </label>
        <div class="download-dialog-formats">
          <button class="report-download-btn" type="button" data-format="md"></button>
          <button class="report-download-btn" type="button" data-format="xlsx"></button>
          <button class="report-download-btn" type="button" data-format="hwpx"></button>
          <button class="report-download-btn" type="button" data-format="pdf"></button>
          <button class="report-download-btn" type="button" data-format="html"></button>
        </div>
        <button id="download-dialog-cancel" type="button" class="download-dialog-cancel"></button>
      </dialog>
      <dialog id="download-notice-dialog" class="download-dialog">
        <p id="download-notice-title" class="download-dialog-title"></p>
        <p id="download-notice-body" class="download-notice-body"></p>
        <button id="download-notice-close" type="button" class="download-dialog-cancel"></button>
      </dialog>
      <div id="scan-status" class="scan-status">__INITIAL_SCAN_STATUS_IDLE__</div>
    </section>

    <section class="metrics" id="metrics"></section>
    <p id="risk-score-note" class="risk-score-note"></p>

    <section class="panel filters" id="filters-panel" aria-label="__INITIAL_FILTERS__">
      <input id="search" type="search" placeholder="__INITIAL_SEARCH_PLACEHOLDER__">
      <select id="severity"></select>
      <select id="category"></select>
      <select id="target"></select>
      <select id="location"></select>
      <select id="result-standard"></select>
      <button id="reset" type="button">__INITIAL_RESET__</button>
    </section>

    <section class="grid">
      <div class="panel">
        <h2 id="project-risk-title">__INITIAL_PROJECT_RISK__</h2>
        <div id="projects" class="project-list"></div>
      </div>
      <div class="panel">
        <h2 id="severity-distribution-title">__INITIAL_SEVERITY_DISTRIBUTION__</h2>
        <div id="bars" class="bars"></div>
      </div>
    </section>

    <section class="table-wrap">
      <table id="findings-table">
        <thead>
          <tr>
            <th id="th-severity">__INITIAL_SEVERITY__</th>
            <th id="th-finding">__INITIAL_FINDING__</th>
            <th id="th-target">__INITIAL_TARGET__</th>
            <th id="th-location">__INITIAL_LOCATION__</th>
            <th id="th-evidence">__INITIAL_EVIDENCE__</th>
            <th id="th-action">__INITIAL_ACTION__</th>
          </tr>
        </thead>
        <tbody id="findings"></tbody>
      </table>
      <div id="empty" class="empty" hidden>__INITIAL_EMPTY__</div>
      </section>

    <section id="sw49-section" class="table-wrap" hidden>
      <h2 id="sw49-heading"></h2>
      <p id="sw49-intro"></p>
      <p id="sw49-summary" class="sw49-summary"></p>
      <table class="coverage-table" id="sw49-table">
        <thead><tr id="sw49-head-row"></tr></thead>
        <tbody id="sw49-body"></tbody>
      </table>
      <p id="sw49-zero-note" hidden></p>
    </section>
    </div>

    <section id="help-view" class="help-view" hidden>
      <div class="help-heading">
        <h2 id="help-title">__INITIAL_HELP_TITLE__</h2>
        <p id="help-intro">__INITIAL_HELP_INTRO__</p>
      </div>
      <div class="coverage-table-wrap">
        <table class="coverage-table">
          <thead>
            <tr>
              <th id="coverage-standard-heading"></th>
              <th id="coverage-auto-heading"></th>
              <th id="coverage-status-heading"></th>
            </tr>
          </thead>
          <tbody id="coverage-matrix"></tbody>
        </table>
      </div>
      <div id="standards-help" class="standards-help"></div>
    </section>

    <section id="settings-view" class="help-view" hidden>
      <div class="help-heading">
        <h2 id="settings-title"></h2>
        <p id="settings-intro"></p>
      </div>
      <div class="settings-tabs" role="tablist">
        <button id="settings-tab-security" class="settings-tab active" type="button" data-kind="security"></button>
        <button id="settings-tab-quality" class="settings-tab" type="button" data-kind="quality"></button>
        <button id="settings-collapse-all" type="button"></button>
        <button id="settings-expand-all" type="button"></button>
        <button id="settings-disable-all" type="button"></button>
        <button id="settings-reset" class="settings-reset" type="button"></button>
      </div>
      <div id="settings-groups" class="settings-groups"></div>
    </section>
  </main>

  <script id="findings-data" type="application/json">__DATA__</script>
  <script>
    let payload = JSON.parse(document.getElementById("findings-data").textContent);
    let summary = payload.summary;
    const severityOrder = ["critical", "high", "medium", "low", "info"];
    const severityColors = { critical: "#7f1d1d", high: "#c2410c", medium: "#d69e2e", low: "#2563eb", info: "#64748b" };

    const state = {
      search: "",
      severity: "all",
      category: "all",
      target: "all",
      location: "all",
      resultStandard: "all",
      language: payload.language || "en",
      scanStatus: "",
      scannedPages: [],
      pageResults: [],
      scanStatusClass: "",
      scanRunning: false,
      scanStandard: (payload.scan && payload.scan.standard) || "local",
      scanStandardCategory: (payload.scan && payload.scan.standard_category) || "all",
      view: initialView(),
      helpRenderedLanguage: "",
      settingsTab: "security",
      settingsCatalog: null,
      settingsRenderedKey: "",
      disabledRules: loadDisabledRules(),
    };

    function byId(id) {
      return document.getElementById(id);
    }

    function loadDisabledRules() {
      try {
        const raw = window.localStorage.getItem("koda.disabledRules");
        const list = raw ? JSON.parse(raw) : [];
        return new Set(Array.isArray(list) ? list.map(String) : []);
      } catch (error) {
        return new Set();
      }
    }

    function saveDisabledRules() {
      try {
        window.localStorage.setItem("koda.disabledRules", JSON.stringify(Array.from(state.disabledRules)));
      } catch (error) {
        /* localStorage unavailable: keep in-memory only */
      }
    }

    function initialView() {
      if (location.hash === "#help") return "help";
      return "dashboard";
    }

    function escapeText(value) {
      return String(value ?? "").replace(/[&<>"']/g, (char) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
      }[char]));
    }

    function countBy(items, key) {
      return items.reduce((acc, item) => {
        const value = item[key] || "unknown";
        acc[value] = (acc[value] || 0) + 1;
        return acc;
      }, {});
    }

    function riskScore(items) {
      const weights = { critical: 100, high: 40, medium: 10, low: 3, info: 1 };
      return items.reduce((total, item) => total + (item.verification_status === "confirmed" ? (weights[item.severity] || 0) : 0), 0);
    }

    function labels() {
      return payload.labels_by_language[state.language] || payload.labels_by_language.en;
    }

    function findings() {
      return payload.findings_by_language[state.language] || payload.findings_by_language.en || [];
    }

    function severityLabels() {
      return labels().severity_labels;
    }

    function categoryLabels() {
      return labels().category_labels || {};
    }

    function categoryLabel(category) {
      return categoryLabels()[category] || category;
    }

    function labelFor(item) {
      return (item.labels && (item.labels[state.language] || item.labels.en)) || item.id || "";
    }

    function localizedText(map, fallback = "") {
      return (map && (map[state.language] || map.en)) || fallback;
    }

    function standardDefinitions() {
      return payload.standards || [];
    }

    function ruleMappings() {
      return payload.rule_mappings || {};
    }

    function components() {
      return payload.components || [];
    }

    function currentStandard() {
      return standardDefinitions().find((standard) => standard.id === state.scanStandard) || standardDefinitions()[0];
    }

    function currentStandardCategory() {
      const standard = currentStandard();
      if (!standard) return null;
      return (standard.categories || []).find((category) => category.id === state.scanStandardCategory) || null;
    }

    function firstSupportedCategory(standard) {
      return (standard.categories || []).find((category) => category.supported && category.id !== "screen_quality") || null;
    }

    function targetDisplay(target) {
      return (summary.target_paths && summary.target_paths[target]) || target || labels().unknown;
    }

    function setText(id, value) {
      byId(id).textContent = value;
    }

    function renderWebOptionSelectAllLabel() {
      const activeLabels = labels();
      const checkboxes = [...byId("web-options-content").querySelectorAll(".scan-web-check input[type='checkbox']")];
      const allChecked = checkboxes.length > 0 && checkboxes.every((input) => input.checked);
      setText("web-options-select-all", allChecked ? activeLabels.web_clear_all : activeLabels.web_select_all);
      byId("web-options-select-all").setAttribute("aria-pressed", String(allChecked));
    }

    function renderZapOptionSelectAllLabel() {
      const activeLabels = labels();
      const container = byId("zap-options-content");
      const checkboxes = [...container.querySelectorAll(".scan-web-check input[type='checkbox']")];
      const allChecked = checkboxes.length > 0 && checkboxes.every((input) => input.checked);
      setText("zap-options-select-all", allChecked ? activeLabels.web_clear_all : activeLabels.web_select_all);
      byId("zap-options-select-all").setAttribute("aria-pressed", String(allChecked));
    }

    function renderSettingsToggle() {
      const button = byId("settings-toggle");
      if (state.view === "settings") {
        setText("settings-toggle", labels().dashboard);
      } else {
        button.innerHTML = `<span class="settings-icon" aria-hidden="true">⚙</span> ${escapeText(labels().settings)}`;
      }
      button.setAttribute("aria-pressed", state.view === "settings" ? "true" : "false");
    }

    function showDownloadNotice() {
      const activeLabels = labels();
      setText("download-notice-title", activeLabels.download_future_title);
      setText("download-notice-body", activeLabels.download_future_support);
      setText("download-notice-close", activeLabels.download_notice_close);
      const dialog = byId("download-notice-dialog");
      if (typeof dialog.showModal === "function") {
        dialog.showModal();
      } else {
        window.alert(activeLabels.download_future_support);
      }
    }

    function apiEndpoint(path) {
      const endpoint = path || "/api/scan";
      if (location.protocol === "http:" || location.protocol === "https:") {
        return endpoint;
      }
      return `http://127.0.0.1:8765${endpoint}`;
    }

    async function parseJsonResponse(response) {
      try {
        return await response.json();
      } catch (error) {
        return {};
      }
    }

    function userFacingApiError(error, fallback) {
      const message = error && error.message ? error.message : "";
      if (location.protocol === "file:" && (message.includes("expected pattern") || message.includes("Failed to fetch"))) {
        return fallback;
      }
      return message || fallback;
    }

    function renderChrome() {
      const activeLabels = labels();
      document.documentElement.lang = activeLabels.html_lang;
      document.title = activeLabels.title;
      setText("dashboard-title", activeLabels.title);
      setText("help-title", activeLabels.help_title);
      setText("help-intro", activeLabels.help_intro);
      setText("generated-line", `${activeLabels.generated} ${payload.generated_display}`);
      setText(
        "summary-line",
        `${activeLabels.risk_score} ${summary.risk_score} | ${activeLabels.targets} ${summary.target_count} | ${activeLabels.findings} ${findings().length}`
      );
      byId("filters-panel").setAttribute("aria-label", activeLabels.filters);
      setText("scan-directory-title", activeLabels.scan_directory);
      byId("scan-path").placeholder = activeLabels.scan_path_placeholder;
      setText("scan-choose", activeLabels.choose_folder);
      setText("upload-scan-title", activeLabels.upload_scan_title);
      setText("scan-upload-run", state.scanRunning ? activeLabels.scan_status_running : activeLabels.upload_scan_now);
      setText("upload-scan-note", activeLabels.upload_scan_note);
      setText("scan-standard-label", activeLabels.scan_standard);
      setText("scan-standard-category-label", activeLabels.scan_standard_category);
      setText("scan-osv-label", activeLabels.osv_toggle);
      setText("scan-osv-note", activeLabels.osv_network_note);
      setText("scan-host-label", activeLabels.host_toggle);
      setText("scan-host-note", activeLabels.host_note);
      setText("sbom-format-label", activeLabels.sbom_format);
      byId("sbom-format").options[0].textContent = activeLabels.sbom_cyclonedx_16;
      byId("sbom-format").options[1].textContent = activeLabels.sbom_nis_10;
      setText("sbom-download", activeLabels.download_sbom);
      setText("report-download-open", activeLabels.download_report);
      setText("download-dialog-title", activeLabels.download_format_prompt);
      setText("download-standard-label", activeLabels.download_standard_label);
      setText("download-dialog-cancel", activeLabels.download_cancel);
      setText("download-notice-title", activeLabels.download_future_title);
      setText("download-notice-body", activeLabels.download_future_support);
      setText("download-notice-close", activeLabels.download_notice_close);
      const formatLabels = {
        md: activeLabels.download_md,
        xlsx: activeLabels.download_xlsx,
        hwpx: activeLabels.download_hwpx,
        pdf: activeLabels.download_pdf,
        html: activeLabels.download_html,
      };
      document.querySelectorAll("#download-dialog .report-download-btn").forEach((btn) => {
        btn.textContent = formatLabels[btn.getAttribute("data-format")] || "";
      });
      setText("settings-title", activeLabels.settings_title);
      setText("settings-intro", activeLabels.settings_intro);
      setText("settings-tab-security", activeLabels.settings_tab_security);
      setText("settings-tab-quality", activeLabels.settings_tab_quality);
      setText("settings-reset", activeLabels.settings_reset);
      setText("settings-disable-all", activeLabels.settings_disable_all);
      setText("settings-expand-all", activeLabels.settings_expand_all);
      setText("settings-collapse-all", activeLabels.settings_collapse_all);
      const hasFindings = (findings() || []).length > 0;
      byId("report-download-open").disabled = !hasFindings;
      setText("report-download-note", hasFindings ? "" : activeLabels.download_report_empty);
      setText("scan-run", state.scanRunning ? activeLabels.scan_status_running : activeLabels.scan_now);
      setText("screen-quality-run", state.scanRunning ? activeLabels.scan_status_running : activeLabels.screen_quality_run);
      byId("scan-run").disabled = state.scanRunning;
      byId("screen-quality-run").disabled = state.scanRunning;
      byId("scan-choose").disabled = state.scanRunning;
      byId("scan-upload").disabled = state.scanRunning;
      byId("scan-upload-run").disabled = state.scanRunning;
      setText("web-scan-title", activeLabels.web_scan_title);
      byId("web-url").placeholder = activeLabels.web_url_placeholder;
      setText("web-scan-run", state.scanRunning ? activeLabels.scan_status_running : activeLabels.web_scan_now);
      byId("web-scan-run").disabled = state.scanRunning;
      byId("web-url").disabled = state.scanRunning;
      setText("web-scan-note", activeLabels.web_scan_note);
      setText("web-crawl-options-label", activeLabels.web_crawl_options);
      renderWebOptionSelectAllLabel();
      setText("web-crawl-enable-label", activeLabels.web_crawl_enable);
      setText("web-render-enable-label", activeLabels.web_render_enable);
      setText("web-discover-assets-label", activeLabels.web_discover_assets);
      setText("web-capture-network-label", activeLabels.web_capture_network);
      setText("web-interact-label", activeLabels.web_interact);
      setText("web-scan-js-secrets-label", activeLabels.web_scan_js_secrets);
      setText("web-ingest-sitemap-label", activeLabels.web_ingest_sitemap);
      setText("web-probe-paths-label", activeLabels.web_probe_paths);
      setText("web-active-label", activeLabels.web_active);
      setText("web-compare-unauth-label", activeLabels.web_compare_unauth);
      setText("web-secondary-label", activeLabels.web_secondary_label);
      byId("web-secondary").placeholder = activeLabels.web_secondary_placeholder;
      setText("web-api-spec-label", activeLabels.web_api_spec_label);
      byId("web-api-spec").placeholder = activeLabels.web_api_spec_placeholder;
      setText("web-seeds-label", activeLabels.web_seeds_label);
      byId("web-seeds").placeholder = activeLabels.web_seeds_placeholder;
      setText("web-allowed-origins-label", activeLabels.web_allowed_origins_label);
      byId("web-allowed-origins").placeholder = activeLabels.web_allowed_origins_placeholder;
      setText("web-login-legend-label", activeLabels.web_login_legend);
      setText("web-login-url-label", activeLabels.web_login_url);
      setText("web-login-user-label", activeLabels.web_login_user);
      setText("web-login-pass-label", activeLabels.web_login_pass);
      setText("web-headers-label", activeLabels.web_headers_label);
      byId("web-headers").placeholder = activeLabels.web_headers_placeholder;
      setText("zap-scan-title", activeLabels.zap_scan_title);
      byId("zap-url").placeholder = activeLabels.web_url_placeholder;
      setText("zap-scan-run", state.scanRunning ? activeLabels.scan_status_running : activeLabels.zap_scan_now);
      byId("zap-scan-run").disabled = state.scanRunning;
      byId("zap-url").disabled = state.scanRunning;
      setText("zap-scan-note", activeLabels.zap_scan_note);
      setText("zap-options-label", activeLabels.zap_options_label);
      setText("zap-ajax-label", activeLabels.zap_ajax);
      setText("zap-active-label", activeLabels.zap_active);
      setText("zap-authorized-label", activeLabels.zap_authorized);
      setText("zap-merge-label", activeLabels.zap_merge);
      setText("zap-include-label", activeLabels.zap_include_label);
      setText("zap-exclude-label", activeLabels.zap_exclude_label);
      renderZapOptionSelectAllLabel();
      setText("zap-login-legend-label", activeLabels.zap_login_legend);
      setText("zap-login-url-label", activeLabels.web_login_url);
      setText("zap-login-user-label", activeLabels.web_login_user);
      setText("zap-login-pass-label", activeLabels.web_login_pass);
      setText("prevention-kit-toggle", activeLabels.prevention_kit_title);
      setText("prevention-apply-toolkit", activeLabels.prevention_apply_toolkit);
      setText("prevention-install-hook", activeLabels.prevention_install_hook);
      setText("prevention-create-ignore", activeLabels.prevention_create_ignore);
      byId("prevention-apply-toolkit").disabled = state.scanRunning;
      byId("prevention-install-hook").disabled = state.scanRunning;
      byId("prevention-create-ignore").disabled = state.scanRunning;
      byId("scan-standard").disabled = state.scanRunning;
      byId("scan-standard-category").disabled = state.scanRunning;
      byId("scan-osv").disabled = state.scanRunning;
      byId("scan-host").disabled = state.scanRunning;
      byId("sbom-format").disabled = components().length === 0;
      byId("sbom-download").disabled = components().length === 0;
      const scanStatus = byId("scan-status");
      scanStatus.textContent = state.scanStatus || activeLabels.scan_status_idle;
      if (payload.scan && payload.scan.kind === "web") {
        const coverage = document.createElement("div");
        const raw = summary.raw_finding_count ?? findings().length;
        const displayed = filteredFindings().length;
        coverage.textContent = `${payload.scan.coverage_message || "현재 활성화된 점검 범위에서 탐지된 항목입니다."} 전체 탐지 ${raw}건, 현재 표시 ${displayed}건.`;
        scanStatus.appendChild(coverage);
        if (payload.auth && ["failed", "uncertain"].includes(payload.auth.status)) {
          const authWarning = document.createElement("div");
          authWarning.textContent = "인증 성공을 확인하지 못했습니다. 로그인 이후 화면과 보호 API가 점검되지 않았을 수 있습니다.";
          scanStatus.appendChild(authWarning);
        }
      }
      if (state.pageResults.length) {
        const details = document.createElement("details");
        details.className = "scan-pages";
        details.innerHTML = "<summary>점검 화면 목록</summary>";
        const list = document.createElement("ul");
        state.pageResults.forEach((page) => {
          const item = document.createElement("li");
          const requested = page.requested_url || "";
          const finalURL = page.final_url || requested;
          const status = page.status ? `HTTP ${page.status}` : "request failed";
          const active = page.active_checks_executed ? "능동 검증 실행" : "능동 검증 미실행";
          const outcome = page.skip_reason || `점검 완료 (${(page.checks_executed || []).join(", ") || "headers"}; ${active})`;
          item.textContent = `요청: ${requested} | 결과: ${finalURL} | ${status} | ${outcome}`;
          list.appendChild(item);
        });
        details.appendChild(list);
        scanStatus.appendChild(details);
      }
      scanStatus.className = `scan-status ${state.scanStatusClass}`;
      setText("risk-score-note", activeLabels.risk_score_formula);
      byId("search").placeholder = activeLabels.search_placeholder;
      setText("reset", activeLabels.reset);
      setText("project-risk-title", activeLabels.project_risk);
      setText("severity-distribution-title", activeLabels.severity_distribution);
      setText("th-severity", activeLabels.severity);
      setText("th-finding", activeLabels.finding);
      setText("th-target", activeLabels.target);
      setText("th-location", activeLabels.location);
      setText("th-evidence", activeLabels.evidence);
      setText("th-action", activeLabels.action);
      setText("coverage-standard-heading", activeLabels.scan_standard);
      setText("coverage-auto-heading", activeLabels.auto_supported);
      setText("coverage-status-heading", activeLabels.coverage);
      byId("lang-ko").classList.toggle("active", state.language === "ko");
      byId("lang-en").classList.toggle("active", state.language === "en");
    }

    function renderScanStandards() {
      const standards = standardDefinitions();
      fillSelect(
        byId("scan-standard"),
        standards.map((standard) => [standard.id, labelFor(standard)]),
        state.scanStandard
      );
      const standard = currentStandard();
      if (!standard) return;
      const selectedCategory = currentStandardCategory();
      if (!selectedCategory || !selectedCategory.supported || selectedCategory.id === "screen_quality") {
        const fallback = firstSupportedCategory(standard);
        state.scanStandardCategory = fallback ? fallback.id : "all";
      }
      fillSelectOptions(
        byId("scan-standard-category"),
        (standard.categories || [])
          .filter((category) => category.id !== "screen_quality")
          .map((category) => ({
            value: category.id,
            label: category.supported ? labelFor(category) : `${labelFor(category)} (${labels().scan_category_not_supported})`,
            disabled: !category.supported,
          })),
        state.scanStandardCategory
      );
    }

    function metric(label, value, sub, colorClass = "") {
      return `
        <article class="metric">
          <div class="metric-label">${escapeText(label)}</div>
          <div class="metric-value ${colorClass}">${escapeText(value)}</div>
          <div class="metric-sub">${escapeText(sub)}</div>
        </article>
      `;
    }

    function renderMetrics(items) {
      const activeLabels = labels();
      const activeSeverityLabels = severityLabels();
      const counts = countBy(items, "severity");
      const blocked = (counts.critical || 0) + (counts.high || 0);
      byId("metrics").innerHTML = [
        metric(activeLabels.risk_score_metric, riskScore(items), activeLabels.risk_score_sub, riskScore(items) ? "high" : "ok"),
        metric(activeSeverityLabels.critical, counts.critical || 0, activeLabels.critical_sub, "critical"),
        metric(activeSeverityLabels.high, counts.high || 0, activeLabels.high_sub, "high"),
        metric(activeSeverityLabels.medium, counts.medium || 0, activeLabels.medium_sub, "medium"),
        metric(activeLabels.low_info_metric, (counts.low || 0) + (counts.info || 0), activeLabels.low_info_sub, "low"),
        metric(activeLabels.blocking, blocked, activeLabels.blocking_sub, blocked ? "high" : "ok"),
      ].join("");
    }

    function renderFilters() {
      const activeLabels = labels();
      const activeSeverityLabels = severityLabels();
      const items = findings();
      const categories = Array.from(new Set(items.map((item) => item.category))).sort();
      const targets = Object.keys(summary.by_target || {}).sort();
      const locations = Array.from(new Set(items.map((item) => item.path).filter(Boolean))).sort();
      fillSelect(byId("severity"), [["all", activeLabels.all_severities], ...severityOrder.map((sev) => [sev, activeSeverityLabels[sev]])], state.severity);
      fillSelect(byId("category"), [["all", activeLabels.all_categories], ...categories.map((cat) => [cat, categoryLabel(cat)])], state.category);
      fillSelect(byId("target"), [["all", activeLabels.all_targets], ...targets.map((target) => [target, targetDisplay(target)])], state.target);
      fillSelect(byId("location"), [["all", activeLabels.all_locations], ...locations.map((location) => [location, location])], state.location);
      const scanKind = (payload.scan && payload.scan.kind) || "directory";
      const scannedStandard = (payload.scan && payload.scan.standard) || "all";
      const standardOptions = standardDefinitions()
        .filter((standard) => standard.id === scannedStandard)
        .map((standard) => [standard.id, localizedText(standard.labels, standard.id)]);
      fillSelect(byId("result-standard"), scanKind === "web" ? [["all", activeLabels.download_all]] : [["all", activeLabels.download_all], ...standardOptions], state.resultStandard);
    }

    function fillSelect(select, entries, selected) {
      select.innerHTML = entries.map(([value, label]) => `<option value="${escapeText(value)}">${escapeText(label)}</option>`).join("");
      select.value = selected;
    }

    function fillSelectOptions(select, entries, selected) {
      select.innerHTML = entries.map((entry) => {
        const disabled = entry.disabled ? " disabled" : "";
        return `<option value="${escapeText(entry.value)}"${disabled}>${escapeText(entry.label)}</option>`;
      }).join("");
      select.value = selected;
    }

    function filteredFindings() {
      const query = state.search.trim().toLowerCase();
      return findings().filter((finding) => {
        if (state.severity !== "all" && finding.severity !== state.severity) return false;
        if (state.category !== "all" && finding.category !== state.category) return false;
        if (state.target !== "all" && finding.target !== state.target) return false;
        if (state.location !== "all" && finding.path !== state.location) return false;
        if (state.resultStandard !== "all" && state.resultStandard !== "local" && !(ruleMappings()[finding.rule_id] || []).some((mapping) => mapping.standard_id === state.resultStandard)) return false;
        if (!query) return true;
        return [finding.title, finding.rule_id, categoryLabel(finding.category), finding.path, targetDisplay(finding.target), finding.evidence, finding.recommendation]
          .join(" ")
          .toLowerCase()
          .includes(query);
      });
    }

    function renderBars(items) {
      const activeSeverityLabels = severityLabels();
      const counts = countBy(items, "severity");
      const max = Math.max(1, ...Object.values(counts));
      byId("bars").innerHTML = severityOrder.map((severity) => {
        const count = counts[severity] || 0;
        const width = `${Math.round((count / max) * 100)}%`;
        return `
          <div class="bar-row">
            <div class="bar-label">${activeSeverityLabels[severity]}</div>
            <div class="bar-track"><div class="bar-fill" style="width: ${width}; background: ${severityColors[severity]}"></div></div>
            <div>${count}</div>
          </div>
        `;
      }).join("");
    }

    function renderProjects(items) {
      const activeLabels = labels();
      const counts = { ...(summary.by_target || {}) };
      for (const finding of items) {
        counts[finding.target] = (counts[finding.target] || 0);
      }
      const rows = Object.entries(counts)
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
      byId("projects").innerHTML = rows.length
        ? rows.map(([name, count]) => `
            <div class="project-row">
              <div class="project-name">${escapeText(targetDisplay(name))}</div>
              <div class="project-count">${count} ${count === 1 ? activeLabels.finding_singular : activeLabels.finding_plural}</div>
            </div>
          `).join("")
        : `<div class="empty">${escapeText(activeLabels.no_targets_recorded)}</div>`;
    }

    function relatedStandardsHtml(ruleId) {
      const activeLabels = labels();
      const mappings = ruleMappings()[ruleId] || [];
      if (!mappings.length) {
        return `<span>${escapeText(activeLabels.no_related_standards)}</span>`;
      }
      return `<div class="rule-related">${mappings.map((mapping) => {
        const standard = labelFor({ labels: mapping.standard_labels });
        const title = mapping.control_title ? labelFor({ labels: mapping.control_title }) : "";
        const guideId = mapping.guide_id || "";
        const kodaId = mapping.official_id || "";
        const itemId = guideId && kodaId ? `${guideId} (${kodaId})` : (guideId || kodaId);
        const cwe = (mapping.cwe_ids || []).join(", ");
        const fallback = labelFor({ labels: mapping.category_labels });
        const details = [itemId && title ? `${itemId} ${title}` : (itemId || title || fallback), cwe].filter(Boolean).join(" · ");
        return `<span class="category-chip">${escapeText([standard, details].filter(Boolean).join(" · "))}</span>`;
      }).join("")}</div>`;
    }

    function sourceContextHtml(finding) {
      const activeLabels = labels();
      const context = finding.source_context;
      if (!context) return "";
      if (!context.available || !Array.isArray(context.lines) || context.lines.length === 0) {
        return `<p class="source-context-unavailable">${escapeText(activeLabels.source_context_unavailable)}</p>`;
      }
      const lines = context.lines.map((line) => {
        const focus = line.is_focus ? " is-focus" : "";
        const marker = line.is_focus
          ? `<span class="source-problem-label">${escapeText(activeLabels.problem_location)}</span>`
          : "";
        return `<div class="source-code-line${focus}"><span class="source-code-number">${escapeText(String(line.number))}</span><span>${escapeText(line.text || "")}${marker}</span></div>`;
      }).join("");
      return `<details class="source-context" open><summary>${escapeText(activeLabels.source_context)}</summary><div class="source-code" aria-label="${escapeText(activeLabels.source_context)}">${lines}</div></details>`;
    }

    function renderTable(items) {
      const activeLabels = labels();
      const activeSeverityLabels = severityLabels();
      const body = byId("findings");
      const empty = byId("empty");
      body.innerHTML = items.map((finding) => {
        const location = `${finding.path}${finding.line ? `:${finding.line}` : ""}`;
        return `
          <tr>
            <td><span class="severity-pill pill-${escapeText(finding.severity)}">${escapeText(activeSeverityLabels[finding.severity] || finding.severity)}</span></td>
            <td>
              <strong>${escapeText(finding.title)}</strong><br>
              <span class="location">${escapeText(finding.rule_id)} | ${escapeText(categoryLabel(finding.category))}</span>
            </td>
            <td>${escapeText(targetDisplay(finding.target))}</td>
            <td class="location">${escapeText(location)}</td>
            <td class="evidence">${escapeText(finding.evidence || "")}</td>
            <td>
              <details>
                <summary>${escapeText(activeLabels.remediate)}</summary>
                <div class="detail-body">
                  <strong>${escapeText(activeLabels.rule_details)}</strong>
                  <br>
                  ${escapeText(finding.description || "")}
                  <br><br>
                  ${escapeText(finding.recommendation || activeLabels.review_this_finding)}
                  <br><br>
                  <strong>${escapeText(activeLabels.related_standards)}</strong>
                  ${relatedStandardsHtml(finding.rule_id)}
                  ${sourceContextHtml(finding)}
                </div>
              </details>
            </td>
          </tr>
        `;
      }).join("");
      empty.textContent = findings().length === 0 ? activeLabels.no_findings_display : activeLabels.no_findings_filter;
      empty.hidden = items.length > 0;
    }

    function renderView() {
      const isDashboard = state.view === "dashboard";
      const isHelp = state.view === "help";
      const isSettings = state.view === "settings";
      byId("dashboard-view").hidden = !isDashboard;
      byId("help-view").hidden = !isHelp;
      byId("settings-view").hidden = !isSettings;
      setText("help-toggle", isHelp ? labels().dashboard : labels().help);
      byId("help-toggle").setAttribute("aria-pressed", isHelp ? "true" : "false");
      renderSettingsToggle();
      if (isSettings) {
        renderSettings();
      }
    }

    async function renderSettings() {
      const activeLabels = labels();
      const language = state.language;
      if (!state.settingsCatalog || state.settingsCatalog.language !== language) {
        byId("settings-groups").innerHTML = `<p>${escapeText(activeLabels.settings_loading)}</p>`;
        try {
          const response = await fetch(apiEndpoint(`/api/rules?lang=${encodeURIComponent(language)}`));
          const data = await parseJsonResponse(response);
          if (!response.ok) throw new Error(data.error || activeLabels.scan_status_failed);
          state.settingsCatalog = { language, groups: data.groups || [] };
        } catch (error) {
          byId("settings-groups").innerHTML = `<p>${escapeText(userFacingApiError(error, activeLabels.server_required))}</p>`;
          return;
        }
      }

      byId("settings-tab-security").classList.toggle("active", state.settingsTab === "security");
      byId("settings-tab-quality").classList.toggle("active", state.settingsTab === "quality");

      const groups = state.settingsCatalog.groups.filter((group) => group.kind === state.settingsTab);
      byId("settings-groups").innerHTML = groups.map((group) => {
        const rules = group.rules.map((rule) => {
          const enabled = !state.disabledRules.has(rule.id);
          const desc = rule.description ? `<span class="settings-rule-desc">${escapeText(rule.description)}</span>` : "";
          return `<div class="settings-rule">
            <div class="settings-rule-text">
              <span class="settings-rule-title">${escapeText(rule.title)}</span>
              <span class="settings-rule-id">${escapeText(rule.id)}</span>
              ${desc}
            </div>
            <label class="switch">
              <input type="checkbox" data-rule="${escapeText(rule.id)}" ${enabled ? "checked" : ""}>
              <span class="track"></span>
            </label>
          </div>`;
        }).join("");
        const allEnabled = group.rules.length > 0 && group.rules.every((rule) => !state.disabledRules.has(rule.id));
        const groupClass = group.kind === "quality" ? " settings-group--quality" : "";
        const toggleLabel = allEnabled ? activeLabels.settings_disable_all : activeLabels.settings_reset;
        return `<details class="settings-group${groupClass}" data-group-key="${escapeText(group.key)}" open>
          <summary class="settings-group-summary"><span>${escapeText(group.label)} (${group.rules.length})</span><button class="settings-group-toggle" type="button" data-group-key="${escapeText(group.key)}">${escapeText(toggleLabel)}</button></summary>
          <div class="settings-rule-list">${rules}</div>
        </details>`;
      }).join("");

      byId("settings-groups").querySelectorAll("input[data-rule]").forEach((input) => {
        input.addEventListener("change", () => {
          const ruleId = input.getAttribute("data-rule");
          if (input.checked) {
            state.disabledRules.delete(ruleId);
          } else {
            state.disabledRules.add(ruleId);
          }
          saveDisabledRules();
        });
      });
      byId("settings-groups").querySelectorAll(".settings-group-toggle").forEach((button) => {
        button.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          const group = (state.settingsCatalog.groups || []).find((item) => item.key === button.getAttribute("data-group-key"));
          if (!group) return;
          const allEnabled = group.rules.length > 0 && group.rules.every((rule) => !state.disabledRules.has(rule.id));
          group.rules.forEach((rule) => {
            if (allEnabled) state.disabledRules.add(rule.id);
            else state.disabledRules.delete(rule.id);
          });
          saveDisabledRules();
          renderSettings();
        });
      });
    }

    function selectedDownloadStandard() {
      const select = byId("download-standard");
      return select ? select.value : "all";
    }

    function findingsForStandard(standardId) {
      const items = findings() || [];
      if (!standardId || standardId === "all") return items;
      const mappings = ruleMappings();
      return items.filter((finding) =>
        (mappings[finding.rule_id] || []).some((mapping) => mapping.standard_id === standardId)
      );
    }

    function populateDownloadStandards() {
      const activeLabels = labels();
      const items = findings() || [];
      const mappings = ruleMappings();
      const counts = {};
      for (const finding of items) {
        for (const mapping of mappings[finding.rule_id] || []) {
          counts[mapping.standard_id] = (counts[mapping.standard_id] || 0) + 1;
        }
      }
      const select = byId("download-standard");
      const previous = select.value;
      let optionsHtml = `<option value="all">${escapeText(activeLabels.download_all)} (${items.length})</option>`;
      for (const standard of standardDefinitions()) {
        if (!counts[standard.id]) continue;
        const label = (standard.labels && (standard.labels[state.language] || standard.labels.en)) || standard.id;
        optionsHtml += `<option value="${escapeText(standard.id)}">${escapeText(label)} (${counts[standard.id]})</option>`;
      }
      select.innerHTML = optionsHtml;
      if (previous && [...select.options].some((option) => option.value === previous)) {
        select.value = previous;
      }
    }

    async function downloadReport(format) {
      const activeLabels = labels();
      const standardId = selectedDownloadStandard();
      const items = findingsForStandard(standardId);
      if (!items.length) return;
      const suffix = standardId && standardId !== "all" ? `-${standardId}` : "";
      try {
        const exportPayload = { ...payload, findings: items };
        if (standardId && standardId !== "all") {
          exportPayload.scan = { ...(payload.scan || {}), standard: standardId, standard_category: "all" };
        }
        const response = await fetch(apiEndpoint("/api/export"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            format,
            language: state.language,
            payload: exportPayload,
          }),
        });
        if (!response.ok) {
          const error = await parseJsonResponse(response);
          if (format !== "pdf" && [404, 405, 415, 501, 503].includes(response.status)) {
            showDownloadNotice();
            return;
          }
          throw new Error(error.error || activeLabels.scan_status_failed);
        }
        const blob = await response.blob();
        const link = document.createElement("a");
        const downloadUrl = URL.createObjectURL(blob);
        link.href = downloadUrl;
        link.download = format === "html"
          ? `koda-source-report${suffix}.zip`
          : `koda-report${suffix}.${format}`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.setTimeout(() => URL.revokeObjectURL(downloadUrl), 60_000);
      } catch (error) {
        state.scanStatus = `${activeLabels.scan_status_failed}: ${userFacingApiError(error, activeLabels.server_required)}`;
        state.scanStatusClass = "error";
        render();
      }
    }

    function coverageStatus(level, activeLabels) {
      const normalized = level || "evidence";
      if (normalized === "local") {
        return {
          className: "local",
          label: activeLabels.automatic_coverage || activeLabels.local_coverage,
        };
      }
      if (normalized === "external") {
        return {
          className: "external",
          label: activeLabels.external_required,
        };
      }
      return {
        className: "evidence",
        label: activeLabels.evidence_required,
      };
    }

    function renderHelp() {
      if (state.helpRenderedLanguage === state.language) {
        return;
      }
      const activeLabels = labels();
      const standards = standardDefinitions();
      byId("coverage-matrix").innerHTML = standards.map((standard) => {
        const leafCategories = (standard.categories || []).filter((category) => category.id !== "all");
        const supportedCount = leafCategories.filter((category) => category.supported).length;
        const total = Math.max(leafCategories.length, 1);
        const status = coverageStatus(standard.coverage_level, activeLabels);
        return `
          <tr>
            <td>${escapeText(labelFor(standard))}</td>
            <td>${supportedCount}/${total}</td>
            <td><span class="status-badge ${status.className}">${escapeText(status.label)}</span></td>
          </tr>
        `;
      }).join("");
      byId("standards-help").innerHTML = standards.map((standard) => {
        const categories = standard.categories || [];
        const leafCategories = categories.filter((category) => category.id !== "all");
        const supportedCount = leafCategories.filter((category) => category.supported).length;
        const status = coverageStatus(standard.coverage_level, activeLabels);
        const references = standard.references || [];
        const links = references.length
          ? references.map((reference) => `
              <a href="${escapeText(reference.url)}" target="_blank" rel="noopener noreferrer">${escapeText(labelFor(reference))}</a>
            `).join("")
          : `<span class="category-chip unsupported">${escapeText(activeLabels.not_supported)}</span>`;
        const categoryChips = categories.map((category) => `
          <span class="category-chip ${category.supported ? "" : "unsupported"}" title="${escapeText(category.supported ? activeLabels.supported : activeLabels.not_supported)}">
            ${escapeText(labelFor(category))}
          </span>
        `).join("");
        const issuer = localizedText(standard.issuer, "");
        const version = standard.version && standard.version !== standard.published_on
          ? `${/^\\d{4}$/.test(standard.version) ? "" : "v"}${standard.version}`
          : "";
        const publication = [issuer, version, standard.published_on || ""].filter(Boolean).join(" · ");
        return `
          <article class="standard-card">
            <div class="standard-head">
              <div>
                <h3>${escapeText(labelFor(standard))}</h3>
                <p>${escapeText(localizedText(standard.description, ""))}</p>
              </div>
              <div class="standard-count">${supportedCount}/${Math.max(leafCategories.length, 1)} ${escapeText(activeLabels.mapped_checks)}</div>
            </div>
            <div><span class="status-badge ${status.className}">${escapeText(status.label)}</span></div>
            <div class="help-meta">
              <strong>${escapeText(activeLabels.coverage)}</strong>
              <span>${escapeText(localizedText(standard.coverage, ""))}</span>
            </div>
            ${publication ? `
              <div class="help-meta">
                <strong>${escapeText(activeLabels.publication_info)}</strong>
                <span>${escapeText(publication)}</span>
              </div>
            ` : ""}
            <div class="help-meta">
              <strong>${escapeText(activeLabels.check_categories)}</strong>
              <div class="category-chips">${categoryChips}</div>
            </div>
            <div class="help-meta">
              <strong>${escapeText(activeLabels.official_links)}</strong>
              <div class="standard-links">${links}</div>
            </div>
          </article>
        `;
      }).join("");
      state.helpRenderedLanguage = state.language;
    }

    const SW49_COLUMN_KEYS = ["official_id", "category", "title", "cwe", "support", "executed", "status", "rules", "finding_count", "evidence", "notes"];

    function renderSw49() {
      const section = byId("sw49-section");
      if (!section) return;
      const sw49 = payload.sw49;
      const isSw49Scan = payload.scan && payload.scan.standard === "sw-dev-security-49";
      if (!sw49 || !isSw49Scan || !Array.isArray(sw49.controls) || !sw49.controls.length) {
        section.hidden = true;
        return;
      }
      const activeLabels = labels();
      const columns = activeLabels.sw49_columns || {};
      const statusLabels = activeLabels.sw49_status_labels || {};
      const supportLabels = activeLabels.sw49_support_labels || {};
      const summaryLabels = activeLabels.sw49_summary_labels || {};
      const language = state.language;
      section.hidden = false;
      setText("sw49-heading", activeLabels.sw49_heading || "SW49");
      setText("sw49-intro", activeLabels.sw49_intro || "");
      const supportCounts = sw49.support_counts || {};
      const statusCounts = sw49.status_counts || {};
      const summaryParts = [`${summaryLabels.total || "Total"}: ${sw49.total || 0}`];
      ["automated", "partial", "manual-review", "unsupported"].forEach((level) => {
        summaryParts.push(`${summaryLabels[level] || level}: ${supportCounts[level] || 0}`);
      });
      Object.keys(statusLabels).forEach((status) => {
        summaryParts.push(`${statusLabels[status] || status}: ${statusCounts[status] || 0}`);
      });
      setText("sw49-summary", summaryParts.join(" · "));
      byId("sw49-head-row").innerHTML = SW49_COLUMN_KEYS.map((key) => `<th>${escapeText(columns[key] || key)}</th>`).join("");
      byId("sw49-body").innerHTML = sw49.controls.map((entry) => {
        const title = entry.title ? (entry.title[language] || entry.title.en || "") : "";
        const category = entry.category_labels ? (entry.category_labels[language] || entry.category_labels.en || entry.category_id) : entry.category_id;
        const notes = entry.notes ? (entry.notes[language] || entry.notes.en || "") : "";
        const guideId = entry.guide_id || "";
        const kodaId = entry.official_id || "";
        const row = {
          official_id: guideId && kodaId ? `${guideId} (${kodaId})` : (guideId || kodaId),
          category,
          title,
          cwe: (entry.cwe_ids || []).join(", "),
          support: supportLabels[entry.support_level] || entry.support_level || "",
          executed: entry.status === "NOT_APPLICABLE"
            ? (statusLabels.NOT_APPLICABLE || "Not applicable")
            : (entry.executed ? (activeLabels.sw49_executed_yes || "Run") : (activeLabels.sw49_executed_no || "Not run")),
          status: statusLabels[entry.status] || entry.status || "",
          rules: (entry.rule_ids || []).join(", "),
          finding_count: String(entry.finding_count || 0),
          evidence: (entry.evidence || []).join(", "),
          notes,
        };
        const statusClass = entry.status === "VULNERABLE" ? "pill-high" : entry.status === "PASS" ? "pill-info" : "pill-low";
        return `<tr>${SW49_COLUMN_KEYS.map((key) => key === "status"
          ? `<td><span class="severity-pill ${statusClass}">${escapeText(row[key])}</span></td>`
          : `<td>${escapeText(row[key])}</td>`).join("")}</tr>`;
      }).join("");
      const zeroNote = byId("sw49-zero-note");
      const hasVulnerable = (statusCounts.VULNERABLE || 0) > 0;
      zeroNote.hidden = hasVulnerable;
      if (!hasVulnerable) {
        setText("sw49-zero-note", activeLabels.sw49_zero_note || "");
      }
    }

    function render() {
      renderChrome();
      renderScanStandards();
      renderView();
      if (state.view === "help") {
        renderHelp();
      }
      renderFilters();
      const items = filteredFindings();
      renderMetrics(items);
      renderBars(items);
      renderProjects(items);
      renderTable(items);
      renderSw49();
    }

    function applyPayload(nextPayload) {
      payload = nextPayload;
      summary = payload.summary;
      state.search = "";
      state.severity = "all";
      state.category = "all";
      state.target = "all";
      state.location = "all";
      state.resultStandard = payload.scan && payload.scan.kind === "web" ? "all" : (payload.scan && payload.scan.standard) || "all";
      state.scannedPages = payload.scanned_pages || [];
      state.pageResults = payload.page_results || [];
      state.scanStandard = (payload.scan && payload.scan.standard) || state.scanStandard;
      state.scanStandardCategory = (payload.scan && payload.scan.standard_category) || state.scanStandardCategory;
      byId("search").value = "";
      render();
    }

    async function chooseDirectory() {
      const activeLabels = labels();
      state.scanStatus = "";
      state.scanStatusClass = "";
      render();

      try {
        const response = await fetch(apiEndpoint("/api/select-directory"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ current_path: byId("scan-path").value || "" }),
        });
        const result = await parseJsonResponse(response);
        if (!response.ok) {
          throw new Error(result.error || activeLabels.folder_selection_failed);
        }
        if (result.cancelled) {
          state.scanStatus = activeLabels.folder_selection_cancelled;
          state.scanStatusClass = "";
          render();
          return;
        }
        byId("scan-path").value = result.path || "";
        state.scanStatus = `${activeLabels.folder_selected}: ${result.path || ""}`;
        state.scanStatusClass = "ok";
        render();
      } catch (error) {
        state.scanStatus = `${activeLabels.folder_selection_failed}: ${userFacingApiError(error, activeLabels.server_required)}`;
        state.scanStatusClass = "error";
        render();
      }
    }

    async function runDirectoryScan() {
      const activeLabels = labels();
      const path = byId("scan-path").value.trim();
      if (!path) {
        state.scanStatus = activeLabels.scan_path_placeholder;
        state.scanStatusClass = "error";
        render();
        return;
      }

      state.scanRunning = true;
      state.scanStatus = activeLabels.scan_status_running;
      state.scanStatusClass = "";
      render();

      try {
        const response = await fetch(apiEndpoint("/api/scan"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            path,
            language: state.language,
            discover_projects: true,
            standard: state.scanStandard,
            standard_category: state.scanStandardCategory,
            min_severity: "low",
            enable_osv: byId("scan-osv").checked,
            include_host: byId("scan-host").checked,
            disabled_rules: Array.from(state.disabledRules),
          }),
        });
        const nextPayload = await parseJsonResponse(response);
        if (!response.ok) {
          throw new Error(nextPayload.error || activeLabels.scan_status_failed);
        }
        state.scanRunning = false;
        state.scanStatus = `${labels().scan_status_done}: ${nextPayload.scan.path || path}`;
        state.scanStatusClass = "ok";
        applyPayload(nextPayload);
      } catch (error) {
        state.scanRunning = false;
        state.scanStatus = `${activeLabels.scan_status_failed}: ${userFacingApiError(error, activeLabels.server_required)}`;
        state.scanStatusClass = "error";
        render();
      }
    }

    async function runUploadScan() {
      const activeLabels = labels();
      const file = byId("scan-upload").files[0];
      if (!file) {
        state.scanStatus = activeLabels.upload_scan_required;
        state.scanStatusClass = "error";
        render();
        return;
      }

      state.scanRunning = true;
      state.scanStatus = activeLabels.scan_status_running;
      state.scanStatusClass = "";
      render();

      try {
        const health = await fetch(apiEndpoint("/api/health"));
        if (!health.ok) {
          throw new Error(activeLabels.server_required);
        }
        const session = health.headers.get("X-KODA-Session") || "";
        const query = new URLSearchParams({
          language: state.language,
          standard: state.scanStandard,
          standard_category: state.scanStandardCategory,
          enable_osv: byId("scan-osv").checked ? "1" : "0",
        });
        state.disabledRules.forEach((ruleId) => query.append("disabled_rule", ruleId));
        const response = await fetch(apiEndpoint(`/api/scan-upload?${query}`), {
          method: "POST",
          headers: {
            "Content-Type": "application/octet-stream",
            "X-KODA-Session": session,
            "X-KODA-Filename": encodeURIComponent(file.name),
          },
          body: file,
        });
        const nextPayload = await parseJsonResponse(response);
        if (!response.ok) {
          throw new Error(nextPayload.error || activeLabels.scan_status_failed);
        }
        state.scanRunning = false;
        state.scanStatus = `${labels().scan_status_done}: ${file.name}`;
        state.scanStatusClass = "ok";
        applyPayload(nextPayload);
      } catch (error) {
        state.scanRunning = false;
        state.scanStatus = `${activeLabels.scan_status_failed}: ${userFacingApiError(error, activeLabels.server_required)}`;
        state.scanStatusClass = "error";
        render();
      }
    }

    async function runWebScan() {
      const activeLabels = labels();
      const url = byId("web-url").value.trim();
      if (!url) {
        state.scanStatus = activeLabels.web_url_placeholder;
        state.scanStatusClass = "error";
        render();
        return;
      }

      state.scanRunning = true;
      state.scanStatus = activeLabels.scan_status_running;
      state.scanStatusClass = "";
      render();

      try {
        const headers = { "Content-Type": "application/json" };
        if (byId("web-active").checked) {
          const health = await fetch(apiEndpoint("/api/health"));
          const session = health.headers.get("X-KODA-Session");
          if (session) headers["X-KODA-Session"] = session;
        }
        const response = await fetch(apiEndpoint("/api/web-scan"), {
          method: "POST",
          headers,
          body: JSON.stringify({
            url,
            language: state.language,
            min_severity: "info",
            timeout: 10,
            crawl: byId("web-crawl").checked,
            max_pages: 50,
            max_depth: 3,
            render: byId("web-render").checked,
            discover_assets: byId("web-discover-assets").checked,
            capture_network: byId("web-capture-network").checked,
            interact: byId("web-interact").checked,
            scan_js_secrets: byId("web-scan-js-secrets").checked,
            ingest_sitemap: byId("web-ingest-sitemap").checked,
            probe_paths: byId("web-probe-paths").checked,
            active: byId("web-active").checked,
            compare_unauth: byId("web-compare-unauth").checked,
            secondary_headers: byId("web-secondary").value,
            api_spec: byId("web-api-spec").value,
            seeds: byId("web-seeds").value.split(/\\r?\\n/).map(function(s){return s.trim();}).filter(Boolean),
            allowed_origins: byId("web-allowed-origins").value.split(/\\r?\\n/).map(function(s){return s.trim();}).filter(Boolean),
            auth: {
              login_url: byId("web-login-url").value.trim(),
              username: byId("web-login-user").value,
              password: byId("web-login-pass").value,
              headers: byId("web-headers").value,
            },
          }),
        });
        const nextPayload = await parseJsonResponse(response);
        if (!response.ok) {
          throw new Error(nextPayload.error || activeLabels.scan_status_failed);
        }
        state.scanRunning = false;
        const pages = nextPayload.pages_scanned;
        const scanned = pages ? ` (${pages} ${labels().web_pages_scanned})` : "";
        const scanWarnings = (nextPayload.scan && nextPayload.scan.warnings) || [];
        const warning = scanWarnings.length ? ` — ${scanWarnings[0]}` : "";
        state.scanStatus = `${labels().scan_status_done}: ${nextPayload.scan.path || url}${scanned}${warning}`;
        state.scannedPages = nextPayload.scanned_pages || [];
        state.scanStatusClass = scanWarnings.length ? "error" : "ok";
        applyPayload(nextPayload);
      } catch (error) {
        state.scanRunning = false;
        state.scanStatus = `${activeLabels.scan_status_failed}: ${userFacingApiError(error, activeLabels.server_required)}`;
        state.scanStatusClass = "error";
        render();
      }
    }

    async function runZapScan() {
      const activeLabels = labels();
      const url = byId("zap-url").value.trim();
      if (!url) {
        state.scanStatus = activeLabels.web_url_placeholder;
        state.scanStatusClass = "error";
        render();
        return;
      }
      const activeScan = byId("zap-active").checked;
      const authorized = byId("zap-authorized").checked;
      if (activeScan && !authorized) {
        state.scanStatus = activeLabels.zap_need_authorization;
        state.scanStatusClass = "error";
        render();
        return;
      }

      state.scanRunning = true;
      state.scanStatus = activeLabels.scan_status_running;
      state.scanStatusClass = "";
      render();

      const requestBody = {
        url,
        language: state.language,
        min_severity: "info",
        ajax_spider: byId("zap-ajax").checked,
        active_scan: activeScan,
        authorization_confirmed: authorized,
        include_paths: byId("zap-include").value.split(/\\r?\\n/).map(function(s){return s.trim();}).filter(Boolean),
        exclude_paths: byId("zap-exclude").value.split(/\\r?\\n/).map(function(s){return s.trim();}).filter(Boolean),
        auth: {
          login_url: byId("zap-login-url").value.trim(),
          username: byId("zap-login-user").value,
          password: byId("zap-login-pass").value,
        },
      };
      // Fold ZAP findings into the report already on screen when requested and
      // there is something to merge into (a prior code or web scan).
      const current = (payload.findings_by_language && payload.findings_by_language.en) || [];
      if (byId("zap-merge").checked && current.length > 0) {
        requestBody.merge = payload;
      }

      try {
        const response = await fetch(apiEndpoint("/api/zap-scan"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(requestBody),
        });
        const nextPayload = await parseJsonResponse(response);
        if (!response.ok) {
          throw new Error(nextPayload.error || activeLabels.scan_status_failed);
        }
        state.scanRunning = false;
        state.scanStatus = `${labels().scan_status_done}: ${nextPayload.scan.path || url}`;
        state.scanStatusClass = "ok";
        applyPayload(nextPayload);
      } catch (error) {
        state.scanRunning = false;
        state.scanStatus = `${activeLabels.scan_status_failed}: ${userFacingApiError(error, activeLabels.server_required)}`;
        state.scanStatusClass = "error";
        render();
      }
    }

    async function runScreenQualityScan() {
      const activeLabels = labels();
      const path = byId("scan-path").value.trim();
      if (!path) {
        state.scanStatus = activeLabels.scan_path_placeholder;
        state.scanStatusClass = "error";
        render();
        return;
      }

      state.scanRunning = true;
      state.scanStatus = activeLabels.scan_status_running;
      state.scanStatusClass = "";
      render();

      try {
        const response = await fetch(apiEndpoint("/api/scan"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            path,
            language: state.language,
            discover_projects: true,
            categories: ["screen_quality"],
            standard: "local",
            standard_category: "screen_quality",
            min_severity: "low",
            enable_osv: false,
            include_host: false,
            disabled_rules: Array.from(state.disabledRules),
          }),
        });
        const nextPayload = await parseJsonResponse(response);
        if (!response.ok) {
          throw new Error(nextPayload.error || activeLabels.scan_status_failed);
        }
        state.scanRunning = false;
        state.scanStatus = `${labels().screen_quality_done}: ${nextPayload.scan.path || path}`;
        state.scanStatusClass = "ok";
        byId("scan-path").value = nextPayload.scan.path || path;
        applyPayload(nextPayload);
      } catch (error) {
        state.scanRunning = false;
        state.scanStatus = `${activeLabels.scan_status_failed}: ${userFacingApiError(error, activeLabels.server_required)}`;
        state.scanStatusClass = "error";
        render();
      }
    }

    async function runPreventionAction(action) {
      const activeLabels = labels();
      byId("prevention-kit-menu").open = false;
      const path = byId("scan-path").value.trim();
      if (!path) {
        state.scanStatus = activeLabels.prevention_need_folder;
        state.scanStatusClass = "error";
        render();
        return;
      }

      state.scanRunning = true;
      state.scanStatus = activeLabels.prevention_running;
      state.scanStatusClass = "";
      render();

      try {
        const response = await fetch(apiEndpoint("/api/prevention-kit"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action, path }),
        });
        const result = await parseJsonResponse(response);
        if (!response.ok) {
          throw new Error(result.error || activeLabels.prevention_failed);
        }
        state.scanRunning = false;
        const written = (result.results || []).filter((item) => item.status === "written").length;
        const kept = (result.results || []).filter((item) => item.status === "skipped").length;
        state.scanStatus = `${activeLabels.prevention_done}: ${activeLabels.prevention_written} ${written}, ${activeLabels.prevention_kept} ${kept}`;
        state.scanStatusClass = "ok";
        render();
      } catch (error) {
        state.scanRunning = false;
        state.scanStatus = `${activeLabels.prevention_failed}: ${userFacingApiError(error, activeLabels.server_required)}`;
        state.scanStatusClass = "error";
        render();
      }
    }

    function downloadSbom() {
      const activeLabels = labels();
      if (!components().length || !payload.sbom) {
        state.scanStatus = activeLabels.sbom_unavailable;
        state.scanStatusClass = "error";
        render();
        return;
      }
      const format = byId("sbom-format").value;
      const csvCell = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
      const nis = payload.nis_sbom || { columns: [], rows: [] };
      const content = format === "nis-sbom"
        ? "\ufeff" + [nis.columns, ...nis.rows.map((row) => nis.columns.map((column) => row[column] || ""))]
          .map((row) => row.map(csvCell).join(",")).join("\\r\\n") + "\\r\\n"
        : JSON.stringify(payload.sbom, null, 2);
      const blob = new Blob([content], { type: format === "nis-sbom" ? "text/csv;charset=utf-8" : "application/json" });
      const link = document.createElement("a");
      const downloadUrl = URL.createObjectURL(blob);
      link.href = downloadUrl;
      link.download = format === "nis-sbom" ? "koda-nis-sbom-1.0.csv" : "koda-cyclonedx-1.6.json";
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(downloadUrl), 60_000);
    }

    byId("search").addEventListener("input", (event) => {
      state.search = event.target.value;
      render();
    });
    byId("severity").addEventListener("change", (event) => {
      state.severity = event.target.value;
      render();
    });
    byId("category").addEventListener("change", (event) => {
      state.category = event.target.value;
      render();
    });
    byId("target").addEventListener("change", (event) => {
      state.target = event.target.value;
      render();
    });
    byId("location").addEventListener("change", (event) => {
      state.location = event.target.value;
      render();
    });
    byId("result-standard").addEventListener("change", (event) => {
      state.resultStandard = event.target.value;
      render();
    });
    byId("scan-standard").addEventListener("change", (event) => {
      state.scanStandard = event.target.value;
      const standard = currentStandard();
      const fallback = standard ? firstSupportedCategory(standard) : null;
      state.scanStandardCategory = fallback ? fallback.id : "all";
      render();
    });
    byId("scan-standard-category").addEventListener("change", (event) => {
      state.scanStandardCategory = event.target.value;
      render();
    });
    byId("reset").addEventListener("click", () => {
      state.search = "";
      state.severity = "all";
      state.category = "all";
      state.target = "all";
      state.location = "all";
      state.resultStandard = "all";
      byId("search").value = "";
      byId("severity").value = "all";
      byId("category").value = "all";
      byId("target").value = "all";
      byId("location").value = "all";
      byId("result-standard").value = "all";
      render();
    });
    byId("scan-choose").addEventListener("click", () => {
      chooseDirectory();
    });
    byId("scan-run").addEventListener("click", () => {
      runDirectoryScan();
    });
    byId("scan-upload-run").addEventListener("click", () => {
      runUploadScan();
    });
    byId("web-scan-run").addEventListener("click", () => {
      runWebScan();
    });
    byId("zap-scan-run").addEventListener("click", () => {
      runZapScan();
    });
    byId("zap-url").addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        runZapScan();
      }
    });
    byId("screen-quality-run").addEventListener("click", () => {
      runScreenQualityScan();
    });
    byId("prevention-apply-toolkit").addEventListener("click", () => {
      runPreventionAction("toolkit");
    });
    byId("prevention-install-hook").addEventListener("click", () => {
      runPreventionAction("hook");
    });
    byId("prevention-create-ignore").addEventListener("click", () => {
      runPreventionAction("ignore");
    });
    byId("web-options-select-all").addEventListener("click", () => {
      const checkboxes = [...byId("web-options-content").querySelectorAll(".scan-web-check input[type='checkbox']")];
      const allChecked = checkboxes.length > 0 && checkboxes.every((input) => input.checked);
      checkboxes.forEach((input) => { input.checked = !allChecked; });
      renderWebOptionSelectAllLabel();
    });
    byId("web-options-content").querySelectorAll(".scan-web-check input[type='checkbox']").forEach((input) => {
      input.addEventListener("change", renderWebOptionSelectAllLabel);
    });
    byId("zap-options-select-all").addEventListener("click", () => {
      const checkboxes = [...byId("zap-options-content").querySelectorAll(".scan-web-check input[type='checkbox']")];
      const allChecked = checkboxes.length > 0 && checkboxes.every((input) => input.checked);
      checkboxes.forEach((input) => { input.checked = !allChecked; });
      renderZapOptionSelectAllLabel();
    });
    byId("web-url").addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        runWebScan();
      }
    });
    byId("sbom-download").addEventListener("click", () => {
      downloadSbom();
    });
    byId("help-toggle").addEventListener("click", () => {
      state.view = state.view === "help" ? "dashboard" : "help";
      if (state.view === "help") {
        location.hash = "help";
      } else if (location.hash === "#help") {
        history.replaceState(null, document.title, location.href.split("#")[0]);
      }
      render();
    });
    byId("settings-toggle").addEventListener("click", () => {
      state.view = state.view === "settings" ? "dashboard" : "settings";
      render();
    });
    byId("settings-tab-security").addEventListener("click", () => {
      state.settingsTab = "security";
      renderSettings();
    });
    byId("settings-tab-quality").addEventListener("click", () => {
      state.settingsTab = "quality";
      renderSettings();
    });
    byId("settings-reset").addEventListener("click", () => {
      state.disabledRules.clear();
      saveDisabledRules();
      renderSettings();
    });
    byId("settings-disable-all").addEventListener("click", () => {
      for (const group of state.settingsCatalog?.groups || []) {
        for (const rule of group.rules || []) state.disabledRules.add(rule.id);
      }
      saveDisabledRules();
      renderSettings();
    });
    byId("settings-expand-all").addEventListener("click", () => {
      byId("settings-groups").querySelectorAll("details").forEach((group) => { group.open = true; });
    });
    byId("settings-collapse-all").addEventListener("click", () => {
      byId("settings-groups").querySelectorAll("details").forEach((group) => { group.open = false; });
    });
    byId("report-download-open").addEventListener("click", () => {
      if ((findings() || []).length === 0) return;
      populateDownloadStandards();
      const dialog = byId("download-dialog");
      if (typeof dialog.showModal === "function") {
        dialog.showModal();
      }
    });
    function closeDownloadDialog() {
      const dialog = byId("download-dialog");
      if (typeof dialog.close === "function") {
        dialog.close();
      } else {
        dialog.removeAttribute("open");
      }
    }
    byId("download-dialog-cancel").addEventListener("click", closeDownloadDialog);
    byId("download-notice-close").addEventListener("click", () => {
      const dialog = byId("download-notice-dialog");
      if (typeof dialog.close === "function") dialog.close();
      else dialog.removeAttribute("open");
    });
    document.querySelectorAll("#download-dialog .report-download-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        closeDownloadDialog();
        downloadReport(btn.getAttribute("data-format"));
      });
    });
    byId("lang-ko").addEventListener("click", () => {
      state.language = "ko";
      render();
    });
    byId("lang-en").addEventListener("click", () => {
      state.language = "en";
      render();
    });
    window.addEventListener("hashchange", () => {
      state.view = initialView();
      render();
    });

    render();
  </script>
</body>
</html>
"""
