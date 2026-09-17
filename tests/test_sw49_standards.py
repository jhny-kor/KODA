from __future__ import annotations

import io
import json
import re
import sys
import tempfile
import unittest
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.checks import code_patterns, secrets  # noqa: E402
from security_scanner.cli import _has_failure  # noqa: E402
from security_scanner.models import DEFAULT_CATEGORIES, Finding, ScannerConfig, TargetConfig  # noqa: E402
from security_scanner.reporting import (  # noqa: E402
    build_dashboard_payload,
    render_hwpx,
    render_html_pair_zip_from_payload,
    render_markdown_from_payload,
    render_report,
    render_xlsx,
)
from security_scanner.scanner import SecurityScanner  # noqa: E402
from security_scanner.standards import (  # noqa: E402
    CODE_PATTERN_RULE_IDS,
    CONFIGURATION_RULE_IDS,
    DEPENDENCY_RULE_IDS,
    OWASP_TOP_10_2025,
    OWASP_PROACTIVE_CONTROLS,
    PREVENTION_RULE_IDS,
    SECRET_RULE_IDS,
    SENSITIVE_COMMENT_RULE_IDS,
    SW49_CATEGORY_EXPECTED_COUNTS,
    SW49_CONTROLS,
    SW49_STATUSES,
    SW49_SUPPORT_LEVELS,
    SW_DEV_SECURITY_49,
    WEB_VERIFIED_RULE_IDS,
    evaluate_sw49_controls,
    rule_standard_mappings_payload,
    sw49_payload,
)

ALL_KNOWN_RULE_IDS = frozenset(
    SECRET_RULE_IDS
    + SENSITIVE_COMMENT_RULE_IDS
    + DEPENDENCY_RULE_IDS
    + CONFIGURATION_RULE_IDS
    + CODE_PATTERN_RULE_IDS
    + PREVENTION_RULE_IDS
    + WEB_VERIFIED_RULE_IDS
)

ALL_SCAN_CATEGORIES = DEFAULT_CATEGORIES

OFFICIAL_ID_RE = re.compile(r"^[ISTECPA]-\d{2}$")


# Immutable acceptance fixture for the 2021 MOIS/KISA implementation-stage
# guide.  Keep this independent from SW49_CONTROLS: structural tests alone can
# pass while an official number, Korean title, or CWE mapping is wrong.
SW49_CANONICAL_CONTROLS = (
    ("1.1", "sw49.i01", "I-01", "SQL 삽입", ("CWE-89",)),
    ("1.2", "sw49.i02", "I-02", "코드 삽입", ("CWE-94", "CWE-95")),
    ("1.3", "sw49.i03", "I-03", "경로 조작 및 자원 삽입", ("CWE-22", "CWE-99")),
    ("1.4", "sw49.i04", "I-04", "크로스사이트 스크립트", ("CWE-79", "CWE-80")),
    ("1.5", "sw49.i05", "I-05", "운영체제 명령어 삽입", ("CWE-78",)),
    ("1.6", "sw49.i06", "I-06", "위험한 형식 파일 업로드", ("CWE-434",)),
    ("1.7", "sw49.i07", "I-07", "신뢰되지 않는 URL 주소로 자동접속 연결", ("CWE-601",)),
    ("1.8", "sw49.i08", "I-08", "부적절한 XML 외부 개체 참조", ("CWE-611",)),
    ("1.9", "sw49.i09", "I-09", "XML 삽입", ("CWE-91",)),
    ("1.10", "sw49.i10", "I-10", "LDAP 삽입", ("CWE-90",)),
    ("1.11", "sw49.i11", "I-11", "크로스사이트 요청 위조", ("CWE-352",)),
    ("1.12", "sw49.i12", "I-12", "서버사이드 요청 위조", ("CWE-918",)),
    ("1.13", "sw49.i13", "I-13", "HTTP 응답분할", ("CWE-113",)),
    ("1.14", "sw49.i14", "I-14", "정수형 오버플로우", ("CWE-190",)),
    ("1.15", "sw49.i15", "I-15", "보안기능 결정에 사용되는 부적절한 입력값", ("CWE-807", "CWE-20")),
    ("1.16", "sw49.i16", "I-16", "메모리 버퍼 오버플로우", ("CWE-119", "CWE-120", "CWE-121", "CWE-122")),
    ("1.17", "sw49.i17", "I-17", "포맷 스트링 삽입", ("CWE-134",)),
    ("2.1", "sw49.s01", "S-01", "적절한 인증 없는 중요기능 허용", ("CWE-306",)),
    ("2.2", "sw49.s02", "S-02", "부적절한 인가", ("CWE-862", "CWE-863")),
    ("2.3", "sw49.s03", "S-03", "중요한 자원에 대한 잘못된 권한 설정", ("CWE-732",)),
    ("2.4", "sw49.s04", "S-04", "취약한 암호화 알고리즘 사용", ("CWE-327",)),
    ("2.5", "sw49.s05", "S-05", "암호화되지 않은 중요정보", ("CWE-311", "CWE-319")),
    ("2.6", "sw49.s06", "S-06", "하드코드된 중요정보", ("CWE-259", "CWE-321", "CWE-798")),
    ("2.7", "sw49.s07", "S-07", "충분하지 않은 키 길이 사용", ("CWE-326",)),
    ("2.8", "sw49.s08", "S-08", "적절하지 않은 난수 값 사용", ("CWE-330", "CWE-338")),
    ("2.9", "sw49.s09", "S-09", "취약한 비밀번호 허용", ("CWE-521",)),
    ("2.10", "sw49.s10", "S-10", "부적절한 전자서명 확인", ("CWE-347",)),
    ("2.11", "sw49.s11", "S-11", "부적절한 인증서 유효성 검증", ("CWE-295",)),
    ("2.12", "sw49.s12", "S-12", "사용자 하드디스크에 저장되는 쿠키를 통한 정보 노출", ("CWE-539",)),
    ("2.13", "sw49.s13", "S-13", "주석문 안에 포함된 시스템 주요정보", ("CWE-615",)),
    ("2.14", "sw49.s14", "S-14", "솔트 없이 일방향 해쉬 함수 사용", ("CWE-759",)),
    ("2.15", "sw49.s15", "S-15", "무결성 검사 없는 코드 다운로드", ("CWE-494",)),
    ("2.16", "sw49.s16", "S-16", "반복된 인증시도 제한 기능 부재", ("CWE-307",)),
    ("3.1", "sw49.t01", "T-01", "경쟁조건: 검사 시점과 사용 시점(TOCTOU)", ("CWE-367",)),
    ("3.2", "sw49.t02", "T-02", "종료되지 않는 반복문 또는 재귀 함수", ("CWE-835", "CWE-674")),
    ("4.1", "sw49.e01", "E-01", "오류 메시지 정보노출", ("CWE-209",)),
    ("4.2", "sw49.e02", "E-02", "오류 상황 대응 부재", ("CWE-390", "CWE-755")),
    ("4.3", "sw49.e03", "E-03", "부적절한 예외 처리", ("CWE-754", "CWE-755", "CWE-396", "CWE-397")),
    ("5.1", "sw49.c01", "C-01", "Null Pointer 역참조", ("CWE-476",)),
    ("5.2", "sw49.c02", "C-02", "부적절한 자원 해제", ("CWE-404", "CWE-772")),
    ("5.3", "sw49.c03", "C-03", "해제된 자원 사용", ("CWE-416",)),
    ("5.4", "sw49.c04", "C-04", "초기화되지 않은 변수 사용", ("CWE-457",)),
    ("5.5", "sw49.c05", "C-05", "신뢰할 수 없는 데이터의 역직렬화", ("CWE-502",)),
    ("6.1", "sw49.p01", "P-01", "잘못된 세션에 의한 데이터 정보 노출", ("CWE-488",)),
    ("6.2", "sw49.p02", "P-02", "제거되지 않고 남은 디버그 코드", ("CWE-489",)),
    ("6.3", "sw49.p03", "P-03", "Public 메소드부터 반환된 Private 배열", ("CWE-495",)),
    ("6.4", "sw49.p04", "P-04", "Private 배열에 Public 데이터 할당", ("CWE-496",)),
    ("7.1", "sw49.a01", "A-01", "DNS lookup에 의존한 보안결정", ("CWE-350", "CWE-247")),
    ("7.2", "sw49.a02", "A-02", "취약한 API 사용", ("CWE-676",)),
)

SW49_CANONICAL_BY_OFFICIAL_ID = {item[2]: item for item in SW49_CANONICAL_CONTROLS}


def _finding(rule_id: str, category: str = "code") -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity="high",
        title="t",
        path=Path("src/app.py"),
        line=1,
        evidence="e",
    )


def _sw49_category(category_id: str):
    for category in SW_DEV_SECURITY_49.categories:
        if category.id == category_id:
            return category
    raise AssertionError(f"missing category: {category_id}")


class Sw49ControlIntegrityTests(unittest.TestCase):
    def test_sw_dev_security_has_exactly_49_controls(self) -> None:
        self.assertEqual(len(SW49_CONTROLS), 49)

    def test_source_profile_does_not_overclaim_full_automation(self) -> None:
        support_counts = Counter(control.support_level for control in SW49_CONTROLS)
        self.assertEqual(support_counts["automated"], 0)
        self.assertEqual(support_counts["partial"], 49)
        self.assertEqual(support_counts["manual-review"], 0)
        self.assertEqual(support_counts["unsupported"], 0)

    def test_sw_dev_security_category_counts(self) -> None:
        counts = Counter(control.category_id for control in SW49_CONTROLS)
        self.assertEqual(dict(counts), SW49_CATEGORY_EXPECTED_COUNTS)

    def test_official_ids_unique_and_well_formed(self) -> None:
        official_ids = [control.official_id for control in SW49_CONTROLS]
        self.assertEqual(len(official_ids), len(set(official_ids)))
        for official_id in official_ids:
            self.assertRegex(official_id, OFFICIAL_ID_RE)

    def test_control_ids_unique_and_well_formed(self) -> None:
        control_ids = [control.control_id for control in SW49_CONTROLS]
        self.assertEqual(len(control_ids), len(set(control_ids)))
        for control_id in control_ids:
            self.assertRegex(control_id, r"^sw49\.[istecpa]\d{2}$")

    def test_no_missing_official_ids(self) -> None:
        expected = {
            f"{prefix}-{index:02d}"
            for prefix, count in (("I", 17), ("S", 16), ("T", 2), ("E", 3), ("C", 5), ("P", 4), ("A", 2))
            for index in range(1, count + 1)
        }
        self.assertEqual({control.official_id for control in SW49_CONTROLS}, expected)

    def test_canonical_guide_ids_aliases_titles_and_cwes_match(self) -> None:
        self.assertEqual(len(SW49_CANONICAL_CONTROLS), 49)
        self.assertEqual(len(SW49_CANONICAL_BY_OFFICIAL_ID), 49)
        controls = {control.official_id: control for control in SW49_CONTROLS}
        self.assertEqual(set(controls), set(SW49_CANONICAL_BY_OFFICIAL_ID))
        for guide_id, alias, official_id, korean_title, cwe_ids in SW49_CANONICAL_CONTROLS:
            control = controls[official_id]
            self.assertEqual(control.guide_id, guide_id, official_id)
            self.assertEqual(control.control_id, alias, official_id)
            self.assertEqual(control.title["ko"], korean_title, official_id)
            self.assertEqual(control.cwe_ids, cwe_ids, official_id)

    def test_all_mapped_rule_ids_exist(self) -> None:
        for control in SW49_CONTROLS:
            for rule_id in control.rule_ids:
                self.assertIn(rule_id, ALL_KNOWN_RULE_IDS, f"{control.official_id} maps unknown rule {rule_id}")

    def test_support_levels_are_valid(self) -> None:
        for control in SW49_CONTROLS:
            self.assertIn(control.support_level, SW49_SUPPORT_LEVELS)

    def test_automated_and_partial_controls_have_rules(self) -> None:
        for control in SW49_CONTROLS:
            if control.support_level in ("automated", "partial"):
                self.assertTrue(control.rule_ids, f"{control.official_id} has no rules")

    def test_no_control_is_left_without_a_local_or_external_rule(self) -> None:
        for control in SW49_CONTROLS:
            self.assertTrue(control.rule_ids, f"{control.official_id} has no executable rule")

    def test_titles_have_korean_and_english(self) -> None:
        for control in SW49_CONTROLS:
            self.assertTrue(control.title.get("ko"))
            self.assertTrue(control.title.get("en"))
            self.assertTrue(control.cwe_ids, f"{control.official_id} has no CWE mapping")

    def test_korean_seven_types_and_owasp_proactive_controls_are_exact_profiles(self) -> None:
        self.assertEqual(
            [category.id for category in SW_DEV_SECURITY_49.categories if category.id != "all"],
            list(SW49_CATEGORY_EXPECTED_COUNTS),
        )
        self.assertEqual(
            [category.id for category in OWASP_PROACTIVE_CONTROLS.categories if category.id != "all"],
            [f"c{index}-" + suffix for index, suffix in enumerate((
                "access-control", "cryptography", "input-exceptions", "security-start", "secure-defaults",
                "components", "digital-identity", "browser-security", "logging-monitoring", "ssrf",
            ), start=1)],
        )


class Sw49MappingCorrectionTests(unittest.TestCase):
    def test_sw49_rule_mapping_payload_has_complete_control_metadata(self) -> None:
        mappings = rule_standard_mappings_payload()
        expected_fields = {
            "standard_id",
            "category_id",
            "control_id",
            "guide_id",
            "official_id",
            "control_title",
            "cwe_ids",
            "support_level",
        }
        sw49_mappings = [
            mapping
            for entries in mappings.values()
            for mapping in entries
            if mapping.get("standard_id") == "sw-dev-security-49"
        ]
        self.assertTrue(sw49_mappings)
        for mapping in sw49_mappings:
            self.assertTrue(expected_fields.issubset(mapping), mapping)
            expected = SW49_CANONICAL_BY_OFFICIAL_ID[mapping["official_id"]]
            self.assertEqual(mapping["guide_id"], expected[0])
            self.assertEqual(mapping["control_id"], expected[1])
            self.assertEqual(mapping["control_title"]["ko"], expected[3])
            self.assertEqual(tuple(mapping["cwe_ids"]), expected[4])

    def test_multi_control_rules_preserve_each_sw49_mapping(self) -> None:
        mappings = rule_standard_mappings_payload()
        expected_controls = {
            "code.dangerous-c-buffer-api": {"I-16", "A-02"},
            "code.empty-exception-handler": {"E-02"},
            "code.stack-trace-exposure": {"E-01"},
            "code.broad-exception-handler": {"E-03"},
            "code.persistent-sensitive-cookie": {"S-12"},
            "code.auth-attempt-protection-missing": {"S-16"},
            "config.docker-add-http": {"S-05", "S-15"},
        }
        for rule_id, official_ids in expected_controls.items():
            actual = {
                entry["official_id"]
                for entry in mappings.get(rule_id, ())
                if entry.get("standard_id") == "sw-dev-security-49"
            }
            self.assertEqual(actual, official_ids, rule_id)

    def test_official_guide_cwe_cross_references_are_preserved(self) -> None:
        by_id = {control.official_id: control for control in SW49_CONTROLS}
        self.assertTrue({"CWE-259", "CWE-321"}.issubset(by_id["S-06"].cwe_ids))
        self.assertIn("CWE-754", by_id["E-03"].cwe_ids)

    def test_encapsulation_no_longer_maps_unrelated_rules(self) -> None:
        rule_ids = set(_sw49_category("encapsulation").rule_ids)
        for wrong in (
            "code.wildcard-cors",
            "code.public-bind-all-interfaces",
            "code.logging-sensitive-data",
            "code.pii-logging",
        ):
            self.assertNotIn(wrong, rule_ids)

    def test_api_misuse_only_maps_official_controls(self) -> None:
        rule_ids = set(_sw49_category("api-misuse").rule_ids)
        for wrong in (
            "dependency.remote-shell-script",
            "dependency.docker-remote-shell",
            "config.docker-add-http",
            "code.eval-user-input",
            "code.unsafe-deserialization",
        ):
            self.assertNotIn(wrong, rule_ids)

    def test_unsafe_deserialization_moved_to_c05(self) -> None:
        c05 = next(control for control in SW49_CONTROLS if control.official_id == "C-05")
        self.assertIn("code.unsafe-deserialization", c05.rule_ids)
        self.assertIn("code.unsafe-deserialization", _sw49_category("code-error").rule_ids)

    def test_eval_user_input_mapped_to_i02(self) -> None:
        i02 = next(control for control in SW49_CONTROLS if control.official_id == "I-02")
        self.assertIn("code.eval-user-input", i02.rule_ids)

    def test_dangerous_c_buffer_api_mapped_to_i16_and_a02(self) -> None:
        by_id = {control.official_id: control for control in SW49_CONTROLS}
        self.assertIn("code.dangerous-c-buffer-api", by_id["I-16"].rule_ids)
        self.assertIn("code.dangerous-c-buffer-api", by_id["A-02"].rule_ids)

    def test_useful_general_rules_are_kept_in_koda(self) -> None:
        for rule_id in ("code.wildcard-cors", "code.public-bind-all-interfaces", "code.logging-sensitive-data", "code.pii-logging"):
            self.assertIn(rule_id, CODE_PATTERN_RULE_IDS)

    def test_owasp_profiles_only_absorb_rules_supported_by_official_categories(self) -> None:
        by_id = {category.id: set(category.rule_ids) for category in OWASP_TOP_10_2025.categories}
        self.assertTrue(
            {
                "code.xml-injection",
                "code.ldap-injection",
                "code.http-response-splitting",
                "code.format-string-user-input",
            }.issubset(by_id["a05-injection"])
        )
        self.assertTrue(
            {
                "code.insufficient-key-length",
                "code.insecure-random-security-use",
                "code.tls-certificate-verification-disabled",
                "code.password-hash-without-salt",
            }.issubset(by_id["a04-cryptographic-failures"])
        )
        self.assertNotIn("secret.sensitive-comment", by_id["a05-injection"])


class Sw49EvaluationTests(unittest.TestCase):
    def test_zero_findings_do_not_mark_everything_pass(self) -> None:
        results = evaluate_sw49_controls([], ALL_SCAN_CATEGORIES)
        by_id = {entry["official_id"]: entry for entry in results}
        self.assertEqual(len(results), 49)
        # formerly unsupported controls now run conservative local review rules
        for official_id in ("C-02", "C-03", "C-04", "A-01"):
            self.assertEqual(by_id[official_id]["status"], "NEEDS_REVIEW")
        # Conservative local rules run, but clean partial coverage is not PASS.
        for official_id in ("S-02", "S-03", "S-09", "T-02", "P-01", "P-03", "P-04", "I-14", "I-15"):
            self.assertEqual(by_id[official_id]["status"], "NEEDS_REVIEW")
        # partial controls without findings are not PASS either
        self.assertEqual(by_id["I-16"]["status"], "NEEDS_REVIEW")

    def test_unselected_controls_are_not_scanned(self) -> None:
        results = evaluate_sw49_controls([], scanned_categories=())
        by_id = {entry["official_id"]: entry for entry in results}
        self.assertEqual(by_id["I-01"]["status"], "NOT_SCANNED")
        self.assertEqual(by_id["C-02"]["status"], "NOT_SCANNED")
        self.assertFalse(by_id["I-01"]["executed"])

    def test_selected_category_does_not_leak_findings_to_other_controls(self) -> None:
        finding = _finding("code.null-pointer-dereference")
        payload = sw49_payload([finding], ALL_SCAN_CATEGORIES, "input-validation-expression")
        c01 = next(entry for entry in payload["controls"] if entry["official_id"] == "C-01")
        self.assertEqual(c01["status"], "NOT_SCANNED")
        self.assertEqual(c01["finding_count"], 0)
        self.assertFalse(c01["executed"])

    def test_selected_category_marks_unselected_shared_rule_control_not_executed(self) -> None:
        finding = _finding("code.dangerous-c-buffer-api")
        payload = sw49_payload([finding], ALL_SCAN_CATEGORIES, "input-validation-expression")
        by_id = {entry["official_id"]: entry for entry in payload["controls"]}
        self.assertEqual(by_id["I-16"]["status"], "VULNERABLE")
        self.assertTrue(by_id["I-16"]["executed"])
        self.assertEqual(by_id["A-02"]["status"], "NOT_SCANNED")
        self.assertEqual(by_id["A-02"]["finding_count"], 0)
        self.assertFalse(by_id["A-02"]["executed"])

    def test_vulnerable_when_mapped_rule_fires(self) -> None:
        findings = [_finding("code.unsafe-deserialization")]
        results = evaluate_sw49_controls(findings, ALL_SCAN_CATEGORIES)
        by_id = {entry["official_id"]: entry for entry in results}
        self.assertEqual(by_id["C-05"]["status"], "VULNERABLE")
        self.assertEqual(by_id["C-05"]["finding_count"], 1)
        self.assertEqual(by_id["C-05"]["evidence"], ["src/app.py:1"])
        # the finding must not leak into API misuse
        self.assertNotEqual(by_id["A-02"]["status"], "VULNERABLE")

    def test_null_pointer_finding_maps_to_c01(self) -> None:
        results = evaluate_sw49_controls([_finding("code.null-pointer-dereference")], ALL_SCAN_CATEGORIES)
        by_id = {entry["official_id"]: entry for entry in results}
        self.assertEqual(by_id["C-01"]["status"], "VULNERABLE")
        self.assertEqual(by_id["C-01"]["confirmed_finding_count"], 1)

    def test_review_candidate_is_not_reported_as_confirmed_violation(self) -> None:
        finding = Finding(
            rule_id="code.auth-attempt-protection-missing",
            category="code",
            severity="low",
            title="candidate",
            path=Path("src/app.py"),
            line=1,
            verification_status="needs_review",
            verification_note="Project-wide middleware configuration must be checked.",
        )
        by_id = {
            entry["official_id"]: entry
            for entry in evaluate_sw49_controls([finding], ALL_SCAN_CATEGORIES)
        }
        self.assertEqual(by_id["S-16"]["status"], "NEEDS_REVIEW")
        self.assertEqual(by_id["S-16"]["finding_count"], 1)
        self.assertEqual(by_id["S-16"]["confirmed_finding_count"], 0)
        self.assertEqual(by_id["S-16"]["review_finding_count"], 1)
        self.assertFalse(_has_failure([finding], "low"))

    def test_partial_control_without_confirmed_finding_stays_reviewable(self) -> None:
        results = evaluate_sw49_controls([], ALL_SCAN_CATEGORIES)
        by_id = {entry["official_id"]: entry for entry in results}
        self.assertEqual(by_id["I-01"]["status"], "NEEDS_REVIEW")
        self.assertTrue(by_id["I-01"]["executed"])

    def test_statuses_are_from_allowed_set(self) -> None:
        for entry in evaluate_sw49_controls([_finding("code.weak-hash")], ALL_SCAN_CATEGORIES):
            self.assertIn(entry["status"], SW49_STATUSES)

    def test_payload_summary_counts(self) -> None:
        payload = sw49_payload([], ALL_SCAN_CATEGORIES)
        self.assertEqual(payload["total"], 49)
        self.assertEqual(sum(payload["status_counts"].values()), 49)
        self.assertEqual(sum(payload["support_counts"].values()), 49)
        self.assertEqual(payload["status_counts"]["VULNERABLE"], 0)


class Sw49NewRuleFixtureTests(unittest.TestCase):
    def _scan(self, filename: str, content: str) -> list[Finding]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / filename
            path.write_text(content, encoding="utf-8")
            target = TargetConfig(name="t", path=Path(tmp))
            if filename.endswith((".env",)) or content.lstrip().startswith(("#", "//")):
                return secrets.check_file(path, target) + code_patterns.check_file(path, target)
            return code_patterns.check_file(path, target) + secrets.check_file(path, target)

    def _rule_ids(self, filename: str, content: str) -> set[str]:
        return {finding.rule_id for finding in self._scan(filename, content)}

    def test_open_redirect_vulnerable_and_safe(self) -> None:
        self.assertIn("code.open-redirect-user-input", self._rule_ids("a.py", 'return redirect(request.args.get("next"))\n'))
        self.assertIn("code.open-redirect-user-input", self._rule_ids("a.js", "res.redirect(req.query.next);\n"))
        self.assertNotIn("code.open-redirect-user-input", self._rule_ids("a.py", 'return redirect(url_for("home"))\n'))
        self.assertNotIn("code.open-redirect-user-input", self._rule_ids("a.py", '# redirect(request.args.get("next"))\n'))

    def test_regex_only_candidates_are_explicitly_marked_for_review(self) -> None:
        findings = self._scan("a.py", "app = FastAPI()\n")
        finding = next(item for item in findings if item.rule_id == "code.api-missing-rate-limit")
        self.assertEqual(finding.verification_status, "needs_review")
        self.assertTrue(finding.verification_note)

    def test_rate_limit_bootstrap_is_suppressed_when_control_is_configured(self) -> None:
        content = """\
app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
"""
        self.assertNotIn("code.api-missing-rate-limit", self._rule_ids("a.py", content))

    def test_safe_yaml_loader_and_internal_exception_logging_are_not_findings(self) -> None:
        content = """\
document = yaml.load(payload, Loader=yaml.SafeLoader)
logger.exception("request failed")
"""
        rule_ids = self._rule_ids("a.py", content)
        self.assertNotIn("code.unsafe-deserialization", rule_ids)
        self.assertNotIn("code.stack-trace-exposure", rule_ids)

    def test_multiline_sql_flow_is_confirmed_and_parameter_binding_is_safe(self) -> None:
        vulnerable = """\
user_id = request.args["id"]
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
"""
        findings = self._scan("a.py", vulnerable)
        sql = next(item for item in findings if item.rule_id == "code.sql-dynamic-query")
        self.assertEqual(sql.line, 3)
        self.assertEqual(sql.verification_status, "confirmed")

        safe = 'cursor.execute("SELECT * FROM users WHERE id = %s", (request.args["id"],))\n'
        self.assertNotIn("code.sql-dynamic-query", self._rule_ids("a.py", safe))

    def test_java_csharp_and_php_sql_injection_flows_are_confirmed(self) -> None:
        fixtures = {
            "Query.java": (
                'String id = request.getParameter("id");\n'
                'statement.executeQuery("SELECT * FROM users WHERE id=" + id);\n'
            ),
            "Update.java": (
                'String name = request.getParameter("name");\n'
                'statement.executeUpdate("UPDATE users SET name=\'" + name + "\' WHERE id=1");\n'
            ),
            "Batch.java": (
                'String id = request.getParameter("id");\n'
                'statement.addBatch("DELETE FROM users WHERE id=" + id);\n'
                'statement.executeBatch();\n'
            ),
            "NativeQuery.java": (
                'String id = request.getParameter("id");\n'
                'entityManager.createNativeQuery("SELECT * FROM users WHERE id=" + id);\n'
            ),
            "JdbcTemplate.java": (
                'String id = request.getParameter("id");\n'
                'jdbcTemplate.update("DELETE FROM users WHERE id=" + id);\n'
            ),
            "Query.cs": (
                'var id = Request.Query["id"];\n'
                'var command = new SqlCommand("SELECT * FROM users WHERE id=" + id, connection);\n'
                'command.ExecuteReader();\n'
            ),
            "CommandText.cs": (
                'var id = Request.Query["id"];\n'
                'var command = new SqlCommand();\n'
                'command.CommandText = "DELETE FROM users WHERE id=" + id;\n'
                'command.ExecuteNonQuery();\n'
            ),
            "CommandTextAppend.cs": (
                'var id = Request.Query["id"];\n'
                'var command = new SqlCommand();\n'
                'command.CommandText += " WHERE id=" + id;\n'
                'await command.ExecuteReaderAsync();\n'
            ),
            "EntityFramework.cs": (
                'var id = Request.Query["id"];\n'
                'context.Database.ExecuteSqlRaw("DELETE FROM users WHERE id=" + id);\n'
            ),
            "query.php": (
                '$id = $_GET["id"];\n'
                '$result = mysqli_query($db, "SELECT * FROM users WHERE id=" . $id);\n'
            ),
            "pdo.php": (
                '$id = $_GET["id"];\n'
                '$result = $pdo->query("SELECT * FROM users WHERE id=" . $id);\n'
            ),
            "prepare.php": (
                '$id = $_GET["id"];\n'
                '$stmt = $pdo->prepare("SELECT * FROM users WHERE id=" . $id);\n'
            ),
            "static_pdo.php": (
                '$id = $_GET["id"];\n'
                '$stmt = PDO::prepare("SELECT * FROM users WHERE id=" . $id);\n'
            ),
            "interpolated_pdo.php": (
                '$id = $_GET["id"];\n'
                '$stmt = $pdo->prepare("SELECT * FROM users WHERE id=$id");\n'
                '$stmt->execute();\n'
            ),
            "separate_functions.php": (
                'function safe($pdo) {\n'
                '    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");\n'
                '}\n'
                'function unsafe($pdo) {\n'
                '    $id = $_GET["id"];\n'
                '    $stmt = $pdo->prepare("SELECT * FROM users WHERE id=" . $id);\n'
                '}\n'
            ),
        }
        for filename, source in fixtures.items():
            with self.subTest(filename=filename):
                finding = next(
                    item for item in self._scan(filename, source)
                    if item.rule_id == "code.sql-dynamic-query"
                )
                self.assertEqual(finding.verification_status, "confirmed")

    def test_java_csharp_and_php_bound_sql_parameters_are_safe(self) -> None:
        fixtures = {
            "Query.java": (
                'String id = request.getParameter("id");\n'
                'PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?");\n'
                'stmt.setString(1, request.getParameter("id"));\n'
                'stmt.executeQuery();\n'
            ),
            "LiteralDollar.java": (
                'String id = request.getParameter("id");\n'
                'statement.executeQuery("SELECT * FROM users WHERE id=$id");\n'
            ),
            "Query.cs": (
                'var id = Request.Query["id"];\n'
                'var command = new SqlCommand("SELECT * FROM users WHERE id=@id", connection);\n'
                'command.Parameters.AddWithValue("@id", Request.Query["id"]);\n'
                'command.ExecuteReader();\n'
            ),
            "query.php": (
                '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");\n'
                '$stmt->execute([$_GET["id"]]);\n'
            ),
            "mysqli.php": (
                '$stmt = mysqli_prepare($db, "SELECT * FROM users WHERE id = ?");\n'
                'mysqli_stmt_bind_param($stmt, "s", $_GET["id"]);\n'
                'mysqli_stmt_execute($stmt);\n'
            ),
            "mysqli_inline.php": (
                '$result = mysqli_execute_query('
                '$db, "SELECT * FROM users WHERE id = ?", [$_GET["id"]]);\n'
            ),
            "postgres.php": (
                '$id = $_GET["id"];\n'
                '$result = pg_query_params($db, "SELECT * FROM users WHERE id = $1", [$id]);\n'
            ),
            "php_single_quote.php": (
                '$id = $_GET["id"];\n'
                "$stmt = $pdo->prepare('SELECT * FROM users WHERE id=$id');\n"
                '$stmt->execute();\n'
            ),
            "php_escaped_dollar.php": (
                '$id = $_GET["id"];\n'
                '$stmt = $pdo->prepare("SELECT * FROM users WHERE id=\\$id");\n'
                '$stmt->execute();\n'
            ),
        }
        for filename, source in fixtures.items():
            with self.subTest(filename=filename):
                self.assertNotIn("code.sql-dynamic-query", self._rule_ids(filename, source))

    def test_mybatis_literal_substitution_is_reviewed_and_bound_values_are_safe(self) -> None:
        vulnerable = """\
<mapper namespace="example.Mapper">
  <select id="selectItems">
    SELECT MAX(DECODE(CRITM_ID, #{item}, CRITM_VAL)) AS ${item}
  </select>
</mapper>
"""
        finding = next(
            item for item in self._scan("Mapper.xml", vulnerable)
            if item.rule_id == "code.sql-dynamic-query"
        )
        self.assertEqual(finding.line, 3)
        self.assertEqual(finding.verification_status, "needs_review")

        safe = """\
<mapper namespace="example.Mapper">
  <select id="selectItems">SELECT * FROM items WHERE item_id = #{item}</select>
</mapper>
"""
        self.assertNotIn("code.sql-dynamic-query", self._rule_ids("Mapper.xml", safe))

    def test_multiline_xss_flow_is_confirmed_and_sanitized_flow_is_safe(self) -> None:
        vulnerable = """\
const html = location.hash;
element.innerHTML = html;
"""
        findings = self._scan("a.js", vulnerable)
        xss = next(item for item in findings if item.rule_id == "code.xss-dom-sink")
        self.assertEqual(xss.verification_status, "confirmed")

        safe = """\
const html = DOMPurify.sanitize(location.hash);
element.innerHTML = html;
"""
        self.assertNotIn("code.xss-dom-sink", self._rule_ids("a.js", safe))

        mixed = """\
const safe = DOMPurify.sanitize("<b>fixed</b>");
const tainted = location.hash;
element.innerHTML = safe + tainted;
"""
        finding = next(item for item in self._scan("a.js", mixed) if item.rule_id == "code.xss-dom-sink")
        self.assertEqual(finding.verification_status, "confirmed")

    def test_jsp_unescaped_output_is_detected_without_flagging_trusted_el(self) -> None:
        direct = '<div><%= request.getParameter("name") %></div>\n'
        finding = next(
            item for item in self._scan("view.jsp", direct)
            if item.rule_id == "code.xss-dom-sink"
        )
        self.assertEqual(finding.verification_status, "confirmed")

        el = '<div>${param.name}</div>\n'
        finding = next(
            item for item in self._scan("view.jsp", el)
            if item.rule_id == "code.xss-dom-sink"
        )
        self.assertEqual(finding.verification_status, "confirmed")

        scriptlet_sink = """\
<script>
var vsStrParam = "<%= vsStrParam %>";
document.write(vsStrParam);
</script>
"""
        finding = next(
            item for item in self._scan("view.jsp", scriptlet_sink)
            if item.rule_id == "code.xss-dom-sink"
        )
        self.assertEqual(finding.verification_status, "needs_review")

        safe = """\
<c:out value="${param.name}" />
<link rel="stylesheet" href="${thirdPartyURL}/style.css" />
<script>var value = "<%= Encode.forJavaScript(vsStrParam) %>";</script>
"""
        self.assertNotIn("code.xss-dom-sink", self._rule_ids("view.jsp", safe))

    def test_command_argument_array_without_shell_is_not_confirmed(self) -> None:
        safe = 'subprocess.run(["ping", "--", request.args["host"]], shell=False, check=True)\n'
        self.assertNotIn("code.command-injection", self._rule_ids("a.py", safe))

    def test_multiline_flows_cover_major_input_validation_controls(self) -> None:
        fixtures = {
            "code.command-injection": ("a.py", 'command = "ping " + request.args["host"]\nsubprocess.run(command, shell=True)\n'),
            "code.path-traversal": ("a.py", 'filename = request.args["file"]\nopen(filename)\n'),
            "code.eval-user-input": ("a.py", 'expression = request.args["expr"]\neval(expression)\n'),
            "code.ssrf-user-url": ("a.py", 'target_url = request.args["url"]\nrequests.get(target_url)\n'),
            "code.open-redirect-user-input": ("a.py", 'next_url = request.args["next"]\nredirect(next_url)\n'),
            "code.ldap-injection": ("a.py", 'ldap_filter = request.args["filter"]\nldap_client.search(ldap_filter)\n'),
            "code.http-response-splitting": ("a.java", 'String value = request.getParameter("value");\nresponse.setHeader("X-Value", value);\n'),
        }
        for rule_id, (filename, content) in fixtures.items():
            with self.subTest(rule_id=rule_id):
                finding = next(item for item in self._scan(filename, content) if item.rule_id == rule_id)
                self.assertEqual(finding.verification_status, "confirmed")

    def test_known_guards_stop_taint_before_major_sinks(self) -> None:
        fixtures = {
            "code.path-traversal": ("a.py", 'filename = secure_filename(request.args["file"])\nopen(filename)\n'),
            "code.ssrf-user-url": ("a.py", 'target_url = validateUrl(request.args["url"])\nrequests.get(target_url)\n'),
            "code.open-redirect-user-input": ("a.py", 'next_url = validateRedirect(request.args["next"])\nredirect(next_url)\n'),
            "code.ldap-injection": ("a.py", 'ldap_filter = escapeLdap(request.args["filter"])\nldap_client.search(ldap_filter)\n'),
            "code.http-response-splitting": ("a.java", 'String value = sanitizeHeader(request.getParameter("value"));\nresponse.setHeader("X-Value", value);\n'),
        }
        for rule_id, (filename, content) in fixtures.items():
            with self.subTest(rule_id=rule_id):
                self.assertNotIn(rule_id, self._rule_ids(filename, content))

    def test_xml_injection_vulnerable_and_safe(self) -> None:
        self.assertIn("code.xml-injection", self._rule_ids("a.py", 'doc = "<user>" + request.args.get("name")\n'))
        self.assertNotIn("code.xml-injection", self._rule_ids("a.py", 'doc = "<user>fixed</user>"\n'))

    def test_java_xxe_hardened_factory_is_not_reported(self) -> None:
        source = '''
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
DocumentBuilder builder = dbFactory.newDocumentBuilder();
builder.parse(request.getInputStream());
'''
        self.assertNotIn("code.xml-external-entity", self._rule_ids("SafeXml.java", source))

    def test_java_xxe_full_external_entity_hardening_is_not_reported(self) -> None:
        source = '''
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
dbFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbFactory.setXIncludeAware(false);
dbFactory.setExpandEntityReferences(false);
DocumentBuilder builder = dbFactory.newDocumentBuilder();
builder.parse(xmlInputStream);
'''
        self.assertNotIn("code.xml-external-entity", self._rule_ids("SafeXml.java", source))

    def test_java_xxe_unsafe_factory_with_untrusted_parse_is_reported(self) -> None:
        source = '''
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = dbFactory.newDocumentBuilder();
builder.parse(request.getInputStream());
'''
        findings = [finding for finding in self._scan("UnsafeXml.java", source) if finding.rule_id == "code.xml-external-entity"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 4)
        self.assertIn("builder.parse", findings[0].evidence)

    def test_java_xxe_hardening_after_builder_creation_is_too_late(self) -> None:
        source = '''
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = dbFactory.newDocumentBuilder();
dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
builder.parse(request.getInputStream());
'''
        self.assertIn("code.xml-external-entity", self._rule_ids("LateHardening.java", source))

    def test_java_xxe_ignored_configuration_failure_is_reported(self) -> None:
        source = '''
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
try {
    dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
} catch (ParserConfigurationException ignored) {
}
DocumentBuilder builder = dbFactory.newDocumentBuilder();
builder.parse(xmlInputStream);
'''
        self.assertIn("code.xml-external-entity", self._rule_ids("IgnoredHardening.java", source))

    def test_java_xxe_fail_closed_configuration_error_is_not_reported(self) -> None:
        source = '''
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
try {
    dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
} catch (ParserConfigurationException error) {
    throw new IllegalStateException("Secure XML parser is unavailable", error);
}
DocumentBuilder builder = dbFactory.newDocumentBuilder();
builder.parse(xmlInputStream);
'''
        self.assertNotIn("code.xml-external-entity", self._rule_ids("FailClosedHardening.java", source))

    def test_java_xxe_commented_hardening_is_not_treated_as_safe(self) -> None:
        source = '''
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
// dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
DocumentBuilder builder = dbFactory.newDocumentBuilder();
builder.parse(request.getInputStream());
'''
        self.assertIn("code.xml-external-entity", self._rule_ids("CommentedHardening.java", source))

    def test_java_xxe_later_unsafe_override_is_reported(self) -> None:
        source = '''
DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
DocumentBuilder builder = dbFactory.newDocumentBuilder();
builder.parse(xmlInputStream);
'''
        self.assertIn("code.xml-external-entity", self._rule_ids("OverriddenHardening.java", source))

    def test_java_xxe_factory_without_parse_is_not_reported(self) -> None:
        source = "DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();\n"
        self.assertNotIn("code.xml-external-entity", self._rule_ids("FactoryOnly.java", source))

    def test_ldap_injection_vulnerable_and_safe(self) -> None:
        self.assertIn("code.ldap-injection", self._rule_ids("A.java", 'String filter = "(uid=" + userInput;\n'))
        self.assertIn("code.ldap-injection", self._rule_ids("a.py", 'conn.search_s(base, scope, "(uid=%s)" % name)\n'))
        self.assertNotIn("code.ldap-injection", self._rule_ids("A.java", 'String filter = "(uid=admin)";\n'))

    def test_http_response_splitting_vulnerable_and_safe(self) -> None:
        self.assertIn("code.http-response-splitting", self._rule_ids("A.java", 'response.setHeader("X-Name", request.getParameter("n"));\n'))
        self.assertNotIn("code.http-response-splitting", self._rule_ids("A.java", 'response.setHeader("X-Name", "fixed");\n'))

    def test_format_string_vulnerable_and_safe(self) -> None:
        self.assertIn("code.format-string-user-input", self._rule_ids("a.c", "printf(user_input);\n"))
        self.assertNotIn("code.format-string-user-input", self._rule_ids("a.c", 'printf("%s", user_input);\n'))
        self.assertNotIn("code.format-string-user-input", self._rule_ids("a.c", 'sprintf(buffer, "%d", n);\n'))
        self.assertNotIn(
            "code.format-string-user-input",
            self._rule_ids(
                "A.java",
                'private static final String KEY_PATTERN = "%s:%s";\n'
                "String key = String.format(KEY_PATTERN, serviceId, judgmentCode);\n",
            ),
        )

        fixed_date = """\
import devonframe.util.DateUtil;
String applDate = DateUtil.getDate("yyyyMMdd");
String startDate = DateUtil.getNextMonthDate(applDate, 1);
String value = String.format(startDate, 6);
"""
        self.assertNotIn("code.format-string-user-input", self._rule_ids("A.java", fixed_date))
        self.assertIn(
            "code.format-string-user-input",
            self._rule_ids("A.java", fixed_date.replace("import devonframe.util.DateUtil;\n", "")),
        )

        reassigned = fixed_date.replace(
            "String value =",
            'startDate = request.getParameter("startDate");\nString value =',
        )
        self.assertIn("code.format-string-user-input", self._rule_ids("A.java", reassigned))

        compound_reassigned = fixed_date.replace(
            "String value =",
            'startDate += request.getParameter("suffix");\nString value =',
        )
        self.assertIn("code.format-string-user-input", self._rule_ids("A.java", compound_reassigned))

        conditional_reassigned = fixed_date.replace(
            "String value =",
            'if (request != null) startDate += request.getParameter("suffix");\nString value =',
        )
        self.assertIn("code.format-string-user-input", self._rule_ids("A.java", conditional_reassigned))

        cross_method = """\
import devonframe.util.DateUtil;
void first() {
    String startDate = DateUtil.getDate("yyyyMMdd");
}
void second() {
    String value = String.format(startDate, 6);
}
"""
        self.assertIn("code.format-string-user-input", self._rule_ids("A.java", cross_method))

        later_assignment = """\
import devonframe.util.DateUtil;
String value = String.format(startDate, 6);
String startDate = DateUtil.getDate("yyyyMMdd");
"""
        self.assertIn("code.format-string-user-input", self._rule_ids("A.java", later_assignment))

        class_field_source = """\
import devonframe.util.DateUtil;
class Dates {
    String applDate = DateUtil.getDate("yyyyMMdd");
    void run() {
        String startDate = DateUtil.getNextMonthDate(applDate, 1);
        String value = String.format("%s01", String.format(startDate, "yyyyMM"));
    }
}
"""
        self.assertNotIn("code.format-string-user-input", self._rule_ids("A.java", class_field_source))

    def test_regexp_exec_is_not_eval(self) -> None:
        source = """\
function getParam(name) {
    return new RegExp('[?&]' + name + '=([^&#]*)').exec(window.location.href);
}
"""
        self.assertNotIn("code.eval-user-input", self._rule_ids("viewer.html", source))
        self.assertIn(
            "code.eval-user-input",
            self._rule_ids("worker.py", 'exec(request.args["expression"])\n'),
        )
        self.assertIn(
            "code.eval-user-input",
            self._rule_ids("worker.js", "exec(window.location.href);\n"),
        )

    def test_minified_javascript_is_not_treated_as_application_source(self) -> None:
        minified = (
            '/*! jQuery v1.9.1 */(function(e,t){var token=Math.random();'
            'try{}catch(e){};t.innerHTML=location.hash})(window,document);\n'
        )
        self.assertFalse(self._scan("jquery-1.9.1.min.js", minified))
        self.assertFalse(self._scan("jquery.min.js", minified))
        self.assertIn(
            "code.xss-dom-sink",
            self._rule_ids("bundle.min.js", "/*! React v18.3.1 */\nconst value = location.hash; target.innerHTML = value;\n"),
        )
        self.assertIn(
            "code.xss-dom-sink",
            self._rule_ids("jquery.js", "const value = location.hash; target.innerHTML = value;\n"),
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "thirdparty" / "jquery-1.9.1.js"
            path.parent.mkdir()
            path.write_text(minified, encoding="utf-8")
            self.assertFalse(code_patterns.check_file(path, TargetConfig(name="t", path=Path(tmp))))

            application_path = Path(tmp) / "thirdparty" / "application.js"
            application_path.write_text("const value = location.hash; target.innerHTML = value;\n", encoding="utf-8")
            self.assertIn(
                "code.xss-dom-sink",
                {item.rule_id for item in code_patterns.check_file(application_path, TargetConfig(name="t", path=Path(tmp)))},
            )

            minified_application_path = Path(tmp) / "thirdparty" / "application.min.js"
            minified_application_path.write_text(
                "const value=location.hash;target.innerHTML=value;\n",
                encoding="utf-8",
            )
            self.assertIn(
                "code.xss-dom-sink",
                {
                    item.rule_id
                    for item in code_patterns.check_file(
                        minified_application_path,
                        TargetConfig(name="t", path=Path(tmp)),
                    )
                },
            )

            jsrender_path = Path(tmp) / "thirdparty" / "jsrender.min.js"
            jsrender_path.write_text(
                "/*! JsRender v1.0.5 */\n"
                "!function(){try{}catch(e){};target.innerHTML=location.hash}();\n",
                encoding="utf-8",
            )
            self.assertFalse(code_patterns.check_file(jsrender_path, TargetConfig(name="t", path=Path(tmp))))

            datepicker_path = Path(tmp) / "thirdparty" / "jquery" / "datepicker" / "datepicker.min.js"
            datepicker_path.parent.mkdir(parents=True)
            datepicker_path.write_text(
                "var picker=function(){try{activate()}catch(e){}};\n",
                encoding="utf-8",
            )
            self.assertFalse(code_patterns.check_file(datepicker_path, TargetConfig(name="t", path=Path(tmp))))

            jsrender_outside_vendor = Path(tmp) / "common" / "js" / "jsrender.min.js"
            jsrender_outside_vendor.parent.mkdir(parents=True)
            jsrender_outside_vendor.write_text(
                "/*! JsRender v1.0.5 */\n"
                "!function(){target.innerHTML=location.hash}();\n",
                encoding="utf-8",
            )
            self.assertFalse(code_patterns.check_file(jsrender_outside_vendor, TargetConfig(name="t", path=Path(tmp))))

            banner_application_path = Path(tmp) / "thirdparty" / "application.js"
            banner_application_path.write_text(
                "/*! JsRender v1.0.5 */\n"
                "const value = location.hash; target.innerHTML = value;\n",
                encoding="utf-8",
            )
            self.assertIn(
                "code.xss-dom-sink",
                {
                    item.rule_id
                    for item in code_patterns.check_file(
                        banner_application_path,
                        TargetConfig(name="t", path=Path(tmp)),
                    )
                },
            )

            pdfjs_viewer = Path(tmp) / "pdfjs" / "web" / "viewer.js"
            pdfjs_viewer.parent.mkdir(parents=True)
            pdfjs_viewer.write_text(
                "const layout = pdfDocument.getPageLayout().catch(function () {});\n",
                encoding="utf-8",
            )
            self.assertFalse(code_patterns.check_file(pdfjs_viewer, TargetConfig(name="t", path=Path(tmp))))

    def test_java_null_pointer_definite_and_nullable_candidates(self) -> None:
        definite = """\
User user = null;
user.getName();
"""
        finding = next(
            item
            for item in self._scan("NullDeref.java", definite)
            if item.rule_id == "code.null-pointer-dereference"
        )
        self.assertEqual(finding.line, 2)
        self.assertEqual(finding.verification_status, "confirmed")

        alias = """\
User user = null;
User selected = user;
selected.getName();
"""
        finding = next(
            item
            for item in self._scan("NullAlias.java", alias)
            if item.rule_id == "code.null-pointer-dereference"
        )
        self.assertEqual(finding.line, 3)
        self.assertEqual(finding.verification_status, "confirmed")

        nullable_lookup = "String name = users.get(userId).getName();\n"
        finding = next(
            item
            for item in self._scan("NullableLookup.java", nullable_lookup)
            if item.rule_id == "code.null-pointer-dereference"
        )
        self.assertEqual(finding.verification_status, "needs_review")

    def test_java_null_pointer_guards_and_non_null_wrappers_are_safe(self) -> None:
        guarded = """\
User user = null;
if (user == null) {
    return;
}
user.getName();
"""
        self.assertNotIn("code.null-pointer-dereference", self._rule_ids("Guarded.java", guarded))
        self.assertNotIn(
            "code.null-pointer-dereference",
            self._rule_ids("Required.java", "Objects.requireNonNull(users.get(userId)).getName();\n"),
        )
        self.assertNotIn(
            "code.null-pointer-dereference",
            self._rule_ids("OptionalValue.java", "users.findById(userId).orElseThrow().getName();\n"),
        )
        self.assertNotIn(
            "code.null-pointer-dereference",
            self._rule_ids(
                "NonNullBranch.java",
                "User user = users.get(userId);\nif (user != null) {\n    user.getName();\n}\n",
            ),
        )
        self.assertNotIn(
            "code.null-pointer-dereference",
            self._rule_ids(
                "SingleStatementGuard.java",
                "User user = users.get(userId);\nif (user != null)\n    user.getName();\n",
            ),
        )
        self.assertNotIn(
            "code.null-pointer-dereference",
            self._rule_ids(
                "InlineNonNull.java",
                "Thread thread11 = null;\nif (thread11 != null) thread11.join();\n",
            ),
        )
        self.assertNotIn(
            "code.null-pointer-dereference",
            self._rule_ids(
                "RequiredStatement.java",
                "User user = users.get(userId);\nObjects.requireNonNull(user);\nuser.getName();\n",
            ),
        )

    def test_java_null_pointer_else_branch_and_typed_map_are_reviewed(self) -> None:
        else_branch = """\
User user = users.get(userId);
if (user != null) {
    user.getName();
} else {
    user.getName();
}
"""
        findings = [
            item for item in self._scan("ElseBranch.java", else_branch)
            if item.rule_id == "code.null-pointer-dereference"
        ]
        self.assertEqual([item.line for item in findings], [5])

        typed_map = """\
Map<String, User> entries;
User selected = entries.get(userId);
selected.getName();
"""
        finding = next(
            item for item in self._scan("TypedMap.java", typed_map)
            if item.rule_id == "code.null-pointer-dereference"
        )
        self.assertEqual(finding.line, 3)
        self.assertEqual(finding.verification_status, "needs_review")

    def test_java_null_pointer_cap_keeps_late_confirmed_finding(self) -> None:
        source = "\n".join(
            [f"users.get(id{index}).getName();" for index in range(5)]
            + ["User definite = null;", "definite.getName();"]
        )
        findings = [
            item for item in self._scan("Priority.java", source)
            if item.rule_id == "code.null-pointer-dereference"
        ]
        self.assertEqual(len(findings), 5)
        self.assertTrue(any(item.line == 7 and item.verification_status == "confirmed" for item in findings))

    def test_insufficient_key_length_vulnerable_and_safe(self) -> None:
        self.assertIn("code.insufficient-key-length", self._rule_ids("a.py", "key = RSA.generate(1024)\n"))
        self.assertNotIn("code.insufficient-key-length", self._rule_ids("a.py", "key = RSA.generate(4096)\n"))

    def test_insecure_random_vulnerable_and_safe(self) -> None:
        self.assertIn("code.insecure-random-security-use", self._rule_ids("a.js", "const token = Math.random().toString(36);\n"))
        self.assertNotIn("code.insecure-random-security-use", self._rule_ids("a.js", "const delayMs = Math.random() * 100;\n"))
        self.assertNotIn("code.insecure-random-security-use", self._rule_ids("a.py", "token = secrets.token_hex(32)\n"))

    def test_tls_verification_disabled_vulnerable_and_safe(self) -> None:
        self.assertIn("code.tls-certificate-verification-disabled", self._rule_ids("a.py", "requests.get(url, verify=False)\n"))
        self.assertIn("code.tls-certificate-verification-disabled", self._rule_ids("a.js", "https.request({ rejectUnauthorized: false });\n"))
        self.assertIn("code.tls-certificate-verification-disabled", self._rule_ids("a.go", "cfg := &tls.Config{InsecureSkipVerify: true}\n"))
        self.assertNotIn("code.tls-certificate-verification-disabled", self._rule_ids("a.py", "requests.get(url, timeout=5)\n"))

    def test_password_hash_without_salt_vulnerable_and_safe(self) -> None:
        self.assertIn("code.password-hash-without-salt", self._rule_ids("a.py", "digest = hashlib.md5(password.encode()).hexdigest()\n"))
        self.assertNotIn("code.password-hash-without-salt", self._rule_ids("a.py", "digest = hashlib.sha256(file_bytes).hexdigest()\n"))
        self.assertNotIn("code.password-hash-without-salt", self._rule_ids("a.py", "hashed = bcrypt.hashpw(password, bcrypt.gensalt())\n"))

    def test_sensitive_comment_vulnerable_safe_and_redacted(self) -> None:
        findings = self._scan("a.py", "# password = SuperSecret99Value\n")
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("secret.sensitive-comment", rule_ids)
        for finding in findings:
            if finding.rule_id == "secret.sensitive-comment":
                self.assertNotIn("SuperSecret99Value", finding.evidence)
                self.assertEqual(finding.verification_status, "needs_review")
        # placeholder / descriptive comments do not fire
        self.assertNotIn("secret.sensitive-comment", self._rule_ids("b.py", "# password = changeme\n"))
        self.assertNotIn("secret.sensitive-comment", self._rule_ids("c.py", "# The password field is validated below.\n"))

    def test_generic_secret_assignment_is_review_only_but_provider_key_is_confirmed(self) -> None:
        generic = next(
            finding
            for finding in self._scan("a.py", 'password = "ThisMayBeOnlyFixtureData99"\n')
            if finding.rule_id == "secret.generic-assignment"
        )
        self.assertEqual(generic.verification_status, "needs_review")

        provider = next(
            finding
            for finding in self._scan("a.env", "AWS_ACCESS_KEY_ID=AK" + "IAABCDEFGHIJKLMNOP\n")
            if finding.rule_id == "secret.aws-access-key"
        )
        self.assertEqual(provider.verification_status, "confirmed")

    def test_generic_search_api_is_not_promoted_to_ldap_injection(self) -> None:
        content = 'query = request.args["q"]\nindex.search(query)\n'
        findings = [finding for finding in self._scan("a.py", content) if finding.rule_id == "code.ldap-injection"]
        self.assertTrue(all(finding.verification_status == "needs_review" for finding in findings))

    def test_unsupported_extensions_are_skipped(self) -> None:
        self.assertFalse(self._rule_ids("a.bin", "printf(user_input);\n") & {"code.format-string-user-input"})

    def test_per_file_finding_limit_holds(self) -> None:
        content = "requests.get(url, verify=False)\n" * 10
        findings = [f for f in self._scan("a.py", content) if f.rule_id == "code.tls-certificate-verification-disabled"]
        self.assertEqual(len(findings), 5)


class Sw49ReportTests(unittest.TestCase):
    def _payload(
        self,
        findings: list[Finding],
        standard_category: str = "all",
    ) -> dict[str, object]:
        return build_dashboard_payload(
            findings,
            ("t",),
            "ko",
            standard="sw-dev-security-49",
            standard_category=standard_category,
            scanned_categories=ALL_SCAN_CATEGORIES,
        )

    def test_dashboard_findings_include_sw49_standard_mappings(self) -> None:
        payload = self._payload([_finding("code.dangerous-c-buffer-api")])
        for language in ("en", "ko"):
            finding = payload["findings_by_language"][language][0]
            self.assertIn("standard_mappings", finding)
            mappings = [
                mapping
                for mapping in finding["standard_mappings"]
                if mapping.get("standard_id") == "sw-dev-security-49"
            ]
            self.assertEqual({mapping["official_id"] for mapping in mappings}, {"I-16", "A-02"})
            for mapping in mappings:
                expected = SW49_CANONICAL_BY_OFFICIAL_ID[mapping["official_id"]]
                self.assertEqual(mapping["guide_id"], expected[0])
                self.assertEqual(mapping["control_id"], expected[1])
                self.assertEqual(mapping["cwe_ids"], list(expected[4]))
                self.assertEqual(mapping["control_title"]["ko"], expected[3])

    def test_selected_category_filters_finding_mappings_and_round_trip_exports(self) -> None:
        payload = self._payload(
            [_finding("code.dangerous-c-buffer-api")],
            "input-validation-expression",
        )
        for language in ("en", "ko"):
            mappings = payload["findings_by_language"][language][0]["standard_mappings"]
            self.assertEqual({mapping["official_id"] for mapping in mappings}, {"I-16"})

        markdown = render_markdown_from_payload(payload, "ko")
        self.assertIn("전체 발견 항목: 1", markdown)
        criteria_start = markdown.index("- 공식 점검 기준:")
        criteria_text = markdown[criteria_start:markdown.index("- 중요한 이유:", criteria_start)]
        self.assertIn("소프트웨어 개발보안 49\n1.16 (I-16)", criteria_text)
        self.assertIn("1.16 (I-16)", criteria_text)
        self.assertNotIn("7.2 (A-02)", criteria_text)

        xlsx_bytes = render_xlsx(payload, "ko")
        with zipfile.ZipFile(io.BytesIO(xlsx_bytes)) as archive:
            findings_sheet = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
        self.assertIn("code.dangerous-c-buffer-api", findings_sheet)
        self.assertIn("1.16 (I-16)", findings_sheet)
        self.assertNotIn("7.2 (A-02)", findings_sheet)

        hwpx_bytes = render_hwpx(payload, "ko")
        with zipfile.ZipFile(io.BytesIO(hwpx_bytes)) as archive:
            hwpx_section = archive.read("Contents/section0.xml").decode("utf-8")
        finding_section = hwpx_section.split("소프트웨어 개발보안 49 기준 현황", 1)[0]
        self.assertIn("1.16 (I-16)", finding_section)
        self.assertNotIn("7.2 (A-02)", finding_section)

        html_zip = render_html_pair_zip_from_payload(payload, "ko")
        with zipfile.ZipFile(io.BytesIO(html_zip)) as archive:
            main_html = archive.read("report.html").decode("utf-8")
            detail_html = archive.read("report-detail.html").decode("utf-8")
        self.assertIn("code.dangerous-c-buffer-api", main_html)
        self.assertIn("code.dangerous-c-buffer-api", detail_html)
        self.assertIn("소프트웨어 개발보안 49\n1.16 (I-16)", detail_html)
        self.assertIn("1.16 (I-16)", detail_html)
        self.assertNotIn("7.2 (A-02)", detail_html)
        i16_row = re.search(r'<tr data-sw49-control="sw49\.i16"[^>]*>(.*?)</tr>', main_html)
        a02_row = re.search(r'<tr data-sw49-control="sw49\.a02"[^>]*>(.*?)</tr>', main_html)
        self.assertIsNotNone(i16_row)
        self.assertIsNotNone(a02_row)
        self.assertRegex(i16_row.group(1), r"<td>1</td>$")
        self.assertIn("<td>미실행</td>", a02_row.group(1))
        self.assertRegex(a02_row.group(1), r"<td>0</td>$")

    def test_selected_category_does_not_fallback_to_unrelated_mappings(self) -> None:
        payload = self._payload([_finding("secret.private-key", "secrets")], "input-validation-expression")
        for language in ("en", "ko"):
            self.assertEqual(payload["findings_by_language"][language][0]["standard_mappings"], [])

    def test_direct_cli_style_markdown_and_json_include_all_49_controls(self) -> None:
        finding = _finding("code.sql-dynamic-query")
        kwargs = {
            "standard": "sw-dev-security-49",
            "standard_category": "all",
            "scanned_categories": ALL_SCAN_CATEGORIES,
        }
        markdown = render_report([finding], "markdown", ("t",), "ko", **kwargs)
        rows = [line for line in markdown.splitlines() if re.match(r"^\| \d+\.\d+ \([ISTECPA]-\d{2}\) ", line)]
        self.assertEqual(len(rows), 49)
        self.assertIn("전체 발견 항목: 1", markdown)
        self.assertIn("1.1 (I-01)", markdown)
        self.assertIn("CWE-89", markdown)

        json_payload = json.loads(render_report([finding], "json", ("t",), "ko", **kwargs))
        self.assertEqual(len(json_payload["sw49"]["controls"]), 49)
        self.assertEqual(json_payload["findings"][0]["standard_mappings"][0]["official_id"], "I-01")

    def test_sw49_payload_has_complete_honest_rows(self) -> None:
        payload = self._payload([])
        controls = payload["sw49"]["controls"]
        self.assertEqual(len(controls), 49)
        for entry in controls:
            expected = SW49_CANONICAL_BY_OFFICIAL_ID[entry["official_id"]]
            self.assertEqual(entry["guide_id"], expected[0])
            self.assertEqual(entry["title"]["ko"], expected[3])
            self.assertEqual(tuple(entry["cwe_ids"]), expected[4])
            self.assertIn(entry["support_level"], SW49_SUPPORT_LEVELS)
            self.assertIn(entry["status"], SW49_STATUSES)
            if entry["support_level"] in {"partial", "manual-review", "unsupported"}:
                self.assertNotEqual(entry["status"], "PASS")
            if entry["support_level"] == "unsupported":
                self.assertEqual(entry["status"], "UNSUPPORTED")
            if entry["support_level"] == "manual-review":
                self.assertEqual(entry["status"], "NEEDS_REVIEW")

    def test_markdown_includes_all_49_rows_even_with_zero_findings(self) -> None:
        report = render_markdown_from_payload(self._payload([]), "ko")
        self.assertIn("소프트웨어 개발보안 49 기준 현황", report)
        for prefix, count in (("I-", 17), ("S-", 16), ("T-", 2), ("E-", 3), ("C-", 5), ("P-", 4), ("A-", 2)):
            rows = [line for line in report.splitlines() if line.startswith("| ") and f"({prefix}" in line]
            self.assertEqual(len(rows), count, prefix)
        self.assertIn("전체 49개 기준의 준수를 의미하지 않습니다", report)
        self.assertIn("미지원", report)
        self.assertIn("CWE-89", report)

    def test_markdown_partial_controls_are_not_shown_as_pass(self) -> None:
        report = render_markdown_from_payload(self._payload([]), "ko")
        c01_row = next(line for line in report.splitlines() if "(C-01)" in line)
        self.assertIn("부분 자동", c01_row)
        self.assertNotIn("통과", c01_row)
        c02_row = next(line for line in report.splitlines() if "(C-02)" in line)
        self.assertIn("부분 자동", c02_row)
        self.assertNotIn("통과", c02_row)

    def test_xlsx_and_hwpx_include_49_rows(self) -> None:
        payload = self._payload([])
        xlsx_bytes = render_xlsx(payload, "ko")
        with zipfile.ZipFile(io.BytesIO(xlsx_bytes)) as archive:
            sheet2 = archive.read("xl/worksheets/sheet2.xml").decode("utf-8")
        self.assertEqual(sheet2.count("<row "), 50)  # header + 49 controls
        self.assertIn("I-01", sheet2)
        self.assertIn("A-02", sheet2)

        hwpx_bytes = render_hwpx(payload, "ko")
        with zipfile.ZipFile(io.BytesIO(hwpx_bytes)) as archive:
            section = archive.read("Contents/section0.xml").decode("utf-8")
        for official_id in ("I-01", "S-16", "T-02", "E-03", "C-05", "P-04", "A-01"):
            self.assertIn(official_id, section)

    def test_all_exports_include_every_official_item_and_cwe(self) -> None:
        payload = self._payload([])
        expected_display_ids = {
            f"{guide_id} ({official_id})"
            for guide_id, _alias, official_id, _title, _cwes in SW49_CANONICAL_CONTROLS
        }

        for language in ("ko", "en"):
            markdown = render_markdown_from_payload(payload, language)
            for guide_id, _alias, official_id, _title, cwe_ids in SW49_CANONICAL_CONTROLS:
                self.assertIn(f"{guide_id} ({official_id})", markdown)
                for cwe_id in cwe_ids:
                    self.assertIn(cwe_id, markdown)

        xlsx_bytes = render_xlsx(payload, "ko")
        with zipfile.ZipFile(io.BytesIO(xlsx_bytes)) as archive:
            sheet2 = archive.read("xl/worksheets/sheet2.xml").decode("utf-8")
        self.assertEqual(sheet2.count("<row "), 50)
        for display_id in expected_display_ids:
            self.assertIn(display_id, sheet2)
        for _guide_id, _alias, _official_id, _title, cwe_ids in SW49_CANONICAL_CONTROLS:
            for cwe_id in cwe_ids:
                self.assertIn(cwe_id, sheet2)

        hwpx_bytes = render_hwpx(payload, "ko")
        with zipfile.ZipFile(io.BytesIO(hwpx_bytes)) as archive:
            section = archive.read("Contents/section0.xml").decode("utf-8")
        for display_id in expected_display_ids:
            self.assertIn(display_id, section)
        for _guide_id, _alias, _official_id, _title, cwe_ids in SW49_CANONICAL_CONTROLS:
            for cwe_id in cwe_ids:
                self.assertIn(cwe_id, section)

        html_zip = render_html_pair_zip_from_payload(payload, "ko")
        with zipfile.ZipFile(io.BytesIO(html_zip)) as archive:
            main_html = archive.read("report.html").decode("utf-8")
        self.assertEqual(main_html.count("data-sw49-control="), 49)
        for display_id in expected_display_ids:
            self.assertIn(display_id, main_html)

    def test_report_formats_use_same_control_count(self) -> None:
        payload = self._payload([_finding("code.sql-dynamic-query")])
        markdown = render_markdown_from_payload(payload, "ko")
        markdown_rows = sum(1 for line in markdown.splitlines() if re.match(r"^\| \d+\.\d+ \([ISTECPA]-\d{2}\) ", line))
        xlsx_bytes = render_xlsx(payload, "ko")
        with zipfile.ZipFile(io.BytesIO(xlsx_bytes)) as archive:
            sheet2 = archive.read("xl/worksheets/sheet2.xml").decode("utf-8")
        self.assertEqual(markdown_rows, 49)
        self.assertEqual(sheet2.count("<row ") - 1, 49)

    def test_finding_counts_are_accurate_per_control(self) -> None:
        payload = self._payload([_finding("code.sql-dynamic-query"), _finding("code.sql-dynamic-query")])
        controls = payload["sw49"]["controls"]
        i01 = next(entry for entry in controls if entry["official_id"] == "I-01")
        self.assertEqual(i01["finding_count"], 2)
        self.assertEqual(i01["status"], "VULNERABLE")

    def test_other_standard_payload_has_no_sw49_table(self) -> None:
        payload = build_dashboard_payload([], (), "ko", standard="owasp-top-10-2025", scanned_categories=ALL_SCAN_CATEGORIES)
        self.assertIsNone(payload["sw49"])

    def test_not_applicable_is_not_displayed_as_not_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "OnlyJava.java"
            source.write_text("final class OnlyJava {}\n", encoding="utf-8")
            result = SecurityScanner(ScannerConfig(
                targets=(TargetConfig("java", source),),
                standard="sw-dev-security-49",
            )).scan()
        report = render_report(
            list(result.findings),
            "markdown",
            ("java",),
            "ko",
            standard="sw-dev-security-49",
            scanned_categories=ALL_SCAN_CATEGORIES,
            source_analysis=result.source_analysis,
        )
        c03 = next(line for line in report.splitlines() if "(C-03)" in line)
        self.assertGreaterEqual(c03.count("해당 없음"), 2)
        self.assertNotIn("미실행", c03)

class Sw49SemanticRuleTests(unittest.TestCase):
    def _rules(self, suffix: str, source: str) -> set[str]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / f"sample{suffix}"
            path.write_text(source, encoding="utf-8")
            return {item.rule_id for item in code_patterns.check_file(path, TargetConfig(name="t", path=path))}

    def test_c02_resource_release_positive_and_safe_cases(self) -> None:
        self.assertIn("code.improper-resource-release", self._rules(".java", "Connection c = DriverManager.getConnection(url);\nreturn c;"))
        self.assertNotIn("code.improper-resource-release", self._rules(".java", "try (Connection c = DriverManager.getConnection(url)) { use(c); }"))
        self.assertNotIn("code.improper-resource-release", self._rules(".java", "Connection c = DriverManager.getConnection(url);\nc.close();"))
        self.assertIn(
            "code.improper-resource-release",
            self._rules(".java", "void first() { Connection in = getConnection(url); in.close(); }\nvoid second() { Connection in = getConnection(url); use(in); }"),
        )

    def test_c02_release_covers_exception_paths_and_url_connections(self) -> None:
        vulnerable_writer = """\
try {
    FileWriter renameFile = new FileWriter(path, true);
    Scanner scanner = new Scanner(tempFile, "UTF-8");
    PrintWriter out = new PrintWriter(renameFile, true);
    out.println(value);
    out.close();
} catch (Exception e) {
    throw e;
}
"""
        self.assertIn("code.improper-resource-release", self._rules(".java", vulnerable_writer))

        vulnerable_connection = "HttpURLConnection conn = (HttpURLConnection) url.openConnection();\nconn.getInputStream();"
        self.assertIn("code.improper-resource-release", self._rules(".java", vulnerable_connection))

        safe_connection = """\
HttpURLConnection conn = null;
try {
    conn = (HttpURLConnection) url.openConnection();
    use(conn);
} finally {
    if (conn != null) conn.disconnect();
}
"""
        self.assertNotIn("code.improper-resource-release", self._rules(".java", safe_connection))

    def test_c03_use_after_free_and_reset_or_reassign(self) -> None:
        self.assertIn("code.use-after-free", self._rules(".c", "int *p = malloc(4);\nfree(p);\nreturn *p;"))
        self.assertNotIn("code.use-after-free", self._rules(".c", "int *p = malloc(4);\nfree(p);\np = NULL;\nreturn 0;"))
        self.assertNotIn("code.use-after-free", self._rules(".c", "int *p = malloc(4);\nfree(p);\np = malloc(4);\nreturn *p;"))
        self.assertNotIn(
            "code.use-after-free",
            self._rules(".c", "void first() { int *p = malloc(4); free(p); }\nint second() { int *p = malloc(4); return *p; }"),
        )

    def test_c04_uninitialized_and_initialized_cases(self) -> None:
        self.assertIn("code.uninitialized-variable", self._rules(".c", "int value;\nreturn value;"))
        self.assertNotIn("code.uninitialized-variable", self._rules(".c", "int value = 1;\nreturn value;"))
        self.assertNotIn("code.uninitialized-variable", self._rules(".c", "int value;\nvalue = 1;\nreturn value;"))

    def test_a01_dns_security_decision_and_lookup_only(self) -> None:
        self.assertIn("code.dns-security-decision", self._rules(".py", "import socket\nhost = socket.gethostbyname(name)\nreturn trusted == host"))
        self.assertNotIn("code.dns-security-decision", self._rules(".py", "import socket\nhost = socket.gethostbyname(name)\nprint(host)"))
        self.assertNotIn(
            "code.dns-security-decision",
            self._rules(".py", "def resolve(name):\n    host = socket.gethostbyname(name)\n    return host\n\ndef authorize(host):\n    return trusted == host"),
        )

    def test_previously_manual_controls_have_bounded_positive_and_negative_rules(self) -> None:
        cases = (
            (
                "code.integer-overflow-user-input",
                ".c",
                'int count = atoi(argv[1]);\nint values[8];\nreturn values[count];',
                'int count = atoi(argv[1]);\nif (count < 0 || count >= 8) return -1;\nint values[8];\nreturn values[count];',
            ),
            (
                "code.security-decision-user-input",
                ".py",
                'price = request.args["price"]\nreturn quantity * price',
                'price = product_service.get_price(item_id)\nreturn quantity * price',
            ),
            (
                "code.authorization-check-missing",
                ".java",
                '@DeleteMapping("/admin/users/{id}")\npublic void deleteUser(String id) { repository.delete(id); }',
                '@PreAuthorize("hasRole(\'ADMIN\')")\n@DeleteMapping("/admin/users/{id}")\npublic void deleteUser(String id) { repository.delete(id); }',
            ),
            (
                "code.insecure-resource-permissions",
                ".py",
                'os.chmod(path, 0o777)',
                'os.chmod(path, 0o600)',
            ),
            (
                "code.weak-password-policy",
                ".py",
                'MIN_PASSWORD_LENGTH = 4',
                'MIN_PASSWORD_LENGTH = 12',
            ),
            (
                "code.uncontrolled-loop",
                ".py",
                'def worker():\n    while True:\n        process_next()',
                'def worker(items):\n    for item in items:\n        process(item)',
            ),
            (
                "code.session-shared-state",
                ".py",
                'current_user = None\ndef handle_request():\n    global current_user\n    current_user = session["user"]',
                'def handle_request():\n    current_user = session["user"]\n    return current_user',
            ),
            (
                "code.private-array-return",
                ".java",
                'private String[] roles;\npublic String[] getRoles() { return roles; }',
                'private String[] roles;\npublic String[] getRoles() { return roles.clone(); }',
            ),
            (
                "code.private-array-assignment",
                ".java",
                'private String[] roles;\npublic void setRoles(String[] values) { this.roles = values; }',
                'private String[] roles;\npublic void setRoles(String[] values) { this.roles = values.clone(); }',
            ),
        )
        for rule_id, suffix, positive, negative in cases:
            with self.subTest(rule_id=rule_id):
                self.assertIn(rule_id, self._rules(suffix, positive))
                self.assertNotIn(rule_id, self._rules(suffix, negative))

    def test_authorization_candidate_requires_an_endpoint_and_sensitive_mutation(self) -> None:
        vulnerable = """\
@PostMapping("/users/update")
@ResponseBody
public BaseMap updateUser(@RequestBody BaseMap params, HttpSession session) {
    return userDao.update(params);
}
"""
        self.assertIn("code.authorization-check-missing", self._rules(".java", vulnerable))

        service_only = """\
public BaseMap updateUser(BaseMap params) {
    return userDao.update(params);
}
"""
        self.assertNotIn("code.authorization-check-missing", self._rules(".java", service_only))

        protected = """\
@PreAuthorize("hasRole('ADMIN')")
@PostMapping("/users/update")
public BaseMap updateUser(@RequestBody BaseMap params) {
    return userDao.update(params);
}
"""
        self.assertNotIn("code.authorization-check-missing", self._rules(".java", protected))

    def test_a02_covers_managed_runtime_apis_from_the_guide(self) -> None:
        servlet_socket = (
            "class Handler extends HttpServlet {\n"
            "  void run() { Socket socket = new Socket(host, port); }\n"
            "}"
        )
        servlet_exit = (
            "class Handler extends HttpServlet {\n"
            "  void run() { System.exit(1); }\n"
            "}"
        )
        desktop_exit = "void CloseNow() { Application.Exit(); }"
        safe_java = (
            "class Handler extends HttpServlet {\n"
            "  void run() { URLConnection connection = url.openConnection(); }\n"
            "}"
        )
        self.assertIn("code.dangerous-managed-api", self._rules(".java", servlet_socket))
        self.assertIn("code.dangerous-managed-api", self._rules(".java", servlet_exit))
        self.assertIn("code.dangerous-managed-api", self._rules(".cs", desktop_exit))
        self.assertNotIn("code.dangerous-managed-api", self._rules(".java", safe_java))

    def test_e03_broad_exception_handler_only(self) -> None:
        self.assertIn(
            "code.broad-exception-handler",
            self._rules(".py", "try:\n    process()\nexcept Exception as exc:\n    logger.warning(exc)"),
        )
        self.assertNotIn(
            "code.broad-exception-handler",
            self._rules(".py", "try:\n    process()\nexcept ValueError as exc:\n    raise exc"),
        )
        self.assertNotIn(
            "code.broad-exception-handler",
            self._rules(
                ".java",
                "try { process(); } catch (Exception e) {\n"
                "  throw new BusinessException(\"failed\", e);\n"
                "}",
            ),
        )

    def test_s12_requires_sensitive_persistent_cookie(self) -> None:
        self.assertIn(
            "code.persistent-sensitive-cookie",
            self._rules(".js", 'res.cookie("access_token", token, { maxAge: 2592000000 });'),
        )
        self.assertNotIn(
            "code.persistent-sensitive-cookie",
            self._rules(".js", 'res.cookie("theme", "dark", { maxAge: 2592000000 });'),
        )
        self.assertNotIn(
            "code.persistent-sensitive-cookie",
            self._rules(".js", 'res.cookie("session", token, { secure: true, httpOnly: true });'),
        )

    def test_s16_requires_authentication_flow_without_protection(self) -> None:
        vulnerable = '''\
@app.post("/login")
def login(password: str):
    return authenticate(password)
'''
        protected = '''\
@app.post("/login")
@limiter.limit("5/minute")
def login(password: str):
    return authenticate(password)
'''
        self.assertIn("code.auth-attempt-protection-missing", self._rules(".py", vulnerable))
        self.assertNotIn("code.auth-attempt-protection-missing", self._rules(".py", protected))
        self.assertNotIn("code.auth-attempt-protection-missing", self._rules(".py", "app = FastAPI()"))


if __name__ == "__main__":
    unittest.main()
