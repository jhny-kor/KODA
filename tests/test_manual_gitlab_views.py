import io
import unittest
import zipfile
from html.parser import HTMLParser

from security_scanner.portal_views import gitlab_admin_page, new_scan_page, project_page, run_page, runs_page
from security_scanner.reporting import (
    file_scope_rows,
    render_html_pair_zip_from_payload,
    render_hwpx,
    render_markdown_from_payload,
    render_xlsx,
)


class _Elements(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.elements = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class ManualGitlabViewsTests(unittest.TestCase):
    def setUp(self):
        self.scope = {
            'requested_mode': 'changed', 'effective_mode': 'changed', 'reason': 'changed_files',
            'baseline_run_id': 'run-base', 'baseline_commit': 'aaa', 'current_commit': 'bbb',
            'files_total': 9, 'scanned_files': 2, 'new_files': 1, 'changed_files': 1,
            'deleted_files': 1, 'dependency_context_files': 1,
        }
        self.payload = {'scan': {'scope': 'source', 'file_scope': self.scope}, 'findings': []}
        self.run = {'run_id': 'run-now', 'round_number': 2, 'status': 'completed',
                    'policy_version': 1, 'snapshot': {'source_type': 'manual_gitlab', 'file_scope': self.scope},
                    'result': self.payload}

    def test_current_connections_preserve_filters_and_disconnect_without_scope_setting(self):
        projects = [{'project_id': 'one', 'name': '사업 <A>'}]
        mappings = [{'mapping_id': 'map1', 'project_id': 'one', 'project_name': '사업 <A>',
                     'path_with_namespace': 'group/<repo>', 'tracker_service_id': 'service',
                     'tracker_environment_id': 'env', 'enabled': True},
                    {'mapping_id': 'map2', 'project_id': 'one', 'project_name': '사업 <A>',
                     'path_with_namespace': 'group/second', 'tracker_service_id': 'service',
                     'tracker_environment_id': 'env', 'enabled': True}]
        html = gitlab_admin_page(projects, mappings)
        elements = _Elements(html).elements
        removals = [attrs for tag, attrs in elements if tag == 'button' and 'data-remove' in attrs]
        self.assertEqual([attrs['data-remove'] for attrs in removals], ['map1', 'map2'])
        self.assertNotIn('data-manual-scan-mode', html)
        self.assertNotIn('/scan-mode', html)
        self.assertNotIn('선택 즉시 저장', html)
        self.assertIn('<th>관리</th>', html)
        self.assertIn('group/&lt;repo&gt;', html)
        self.assertNotIn('group/<repo>', html)
        self.assertIn("id='gitlab-current-project'", html)
        self.assertIn("id='gitlab-current-repository'", html)
        self.assertIn("row.dataset.filtered=String(filtered)", html)
        self.assertIn('._paginate?.()', html)

    def test_manual_source_and_library_scan_choose_scope_only_for_gitlab(self):
        projects = [{'project_id': 'one', 'name': '사업', 'can_scan': True}]
        for scope in ('source', 'library'):
            with self.subTest(scope=scope):
                html = new_scan_page(projects, admin=True, scan_scope=scope)
                self.assertIn("for='gitlab-scan-mode'", html)
                self.assertIn("id='gitlab-scan-mode'", html)
                self.assertIn("<option value='full' selected>전체 점검</option>", html)
                self.assertIn("<option value='changed'>신규·변경 파일만 점검</option>", html)
                self.assertIn("id='sum-file-scope-row' hidden", html)
                self.assertIn("document.querySelector('#sum-file-scope-row').hidden=!isGitlab", html)
                self.assertIn("gitlabScanMode.addEventListener('change',syncSummary)", html)
                scan_script = html[html.index("document.querySelector('#scan')"):]
                branch = scan_script.split("if(inputSource()==='gitlab')Object.assign(payload,", 1)[1].split(');else payload.input_id=input.value;', 1)[0]
                self.assertIn('gitlab_scan_mode:gitlabScanMode.value', branch)
                common_payload = scan_script.split("if(inputSource()==='gitlab')", 1)[0]
                self.assertNotIn('gitlab_scan_mode', common_payload)

    def test_run_details_and_list_distinguish_requested_from_actual(self):
        self.scope.update(effective_mode='full', reason='no_baseline')
        detail = run_page(self.run, admin=True)
        self.assertIn('선택 점검 범위', detail)
        self.assertIn('실제 점검 범위', detail)
        self.assertIn('성공한 전체 점검 기준 없음', detail)
        self.assertEqual(dict(file_scope_rows({'requested_mode': 'full', 'effective_mode': 'full', 'reason': 'configured_full'}))['점검 범위 적용 사유'], '실행 시 선택한 전체 점검')
        listing = runs_page([({'project_id': 'one', 'name': '사업'}, [self.run])], admin=True)
        self.assertIn('선택: 신규·변경 파일만 점검 · 실제: 전체 점검', listing)

    def test_scope_escaping_and_zero_change_notice(self):
        self.scope.update(scanned_files=0, reason='<script>alert(1)</script>')
        html = run_page(self.run, admin=True)
        self.assertIn('신규·변경 파일 없음 — 검사 생략', html)
        self.assertIn('검사하지 않은 파일의 기존 취약점', html)
        self.assertIn("class='panel' data-file-scope", html)
        self.assertIn("class='summary-list file-scope-summary'", html)
        self.assertIn("class='file-scope-notice'><span>해석 주의", html)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', html)
        self.assertNotIn('<script>alert(1)</script>', html)

    def test_compact_listed_run_scope_renders_in_result_and_project_lists(self):
        project = {'project_id': 'one', 'name': '사업'}
        compact_run = {'run_id': 'run-now', 'round_number': 2, 'status': 'completed',
                       'file_scope': dict(self.scope)}
        expected = '선택: 신규·변경 파일만 점검 · 실제: 신규·변경 파일만 점검'
        self.assertIn(expected, runs_page([(project, [compact_run])], admin=True))
        self.assertIn(expected, project_page(project, [], [compact_run], can_upload=True, can_scan=True, admin=True))

    def test_report_formats_include_immutable_scope_and_coverage_caution(self):
        md = render_markdown_from_payload(self.payload)
        self.assertIn('선택 점검 범위: 신규·변경 파일만 점검', md)
        self.assertIn('비교 기준 점검 ID: run-base', md)
        self.assertIn('선택 파일 수: 2', md)
        self.assertIn('검사하지 않은 파일의 기존 취약점', md)
        with zipfile.ZipFile(io.BytesIO(render_html_pair_zip_from_payload(self.payload))) as archive:
            for name in ('report.html', 'report-detail.html'):
                html = archive.read(name).decode()
                self.assertIn('파일 점검 범위', html)
                self.assertIn('선택 점검 범위', html)
                self.assertIn('run-base', html)
                self.assertIn('검사하지 않은 파일의 기존 취약점', html)
        with zipfile.ZipFile(io.BytesIO(render_xlsx(self.payload))) as archive:
            self.assertIn('FileScope', archive.read('xl/workbook.xml').decode())
            self.assertIn('run-base', archive.read('xl/worksheets/sheet2.xml').decode())
        with zipfile.ZipFile(io.BytesIO(render_hwpx(self.payload))) as archive:
            self.assertIn('선택 파일 수: 2', archive.read('Contents/section0.xml').decode())
            self.assertIn('run-base', archive.read('Contents/section0.xml').decode())

    def test_library_html_includes_scope_after_special_report_renderer(self):
        payload = {**self.payload, 'scan': {'scope': 'library', 'file_scope': self.scope}, 'vulnerabilities': []}
        with zipfile.ZipFile(io.BytesIO(render_html_pair_zip_from_payload(payload))) as archive:
            for name in ('report.html', 'report-detail.html', 'report-vulnerabilities.html'):
                self.assertIn('실제 점검 범위', archive.read(name).decode())

    def test_legacy_reports_do_not_claim_new_coverage(self):
        legacy = {'scan': {'scope': 'source'}, 'findings': []}
        self.assertEqual(file_scope_rows(None), [])
        self.assertNotIn('선택 점검 범위', render_markdown_from_payload(legacy))
        with zipfile.ZipFile(io.BytesIO(render_xlsx(legacy))) as archive:
            self.assertNotIn('FileScope', archive.read('xl/workbook.xml').decode())

    def test_sw49_context_distinguished_from_reported_file_scope(self):
        self.scope.update(context_files=9, context_note='전체 프로젝트 문맥을 분석하며 선택 파일 결과만 표시합니다.')
        rows = dict(file_scope_rows(self.scope))
        self.assertEqual(rows['분석 문맥 파일 수'], '9')
        self.assertIn('선택 파일', rows['전체 프로젝트 분석 문맥'])


if __name__ == '__main__':
    unittest.main()
