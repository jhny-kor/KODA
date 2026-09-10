"""Run an isolated, loopback-only sample KODA UI. No real server credentials."""
import argparse
import base64
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=0)
    args = parser.parse_args()
    for key in list(os.environ):
        if key.startswith('KODA_'):
            os.environ.pop(key)
    from security_scanner.linux_portal import create_portal_server
    from security_scanner.schedule_api import _job_context
    root = tempfile.TemporaryDirectory(prefix='koda-sample-ui-')
    server = create_portal_server('127.0.0.1', args.port, db_path=Path(root.name)/'sample.sqlite3', input_dir=Path(root.name)/'inputs')
    store = server.portal_store
    admin = str(uuid.uuid4())
    store.bootstrap(admin)
    store.ensure_subject(admin, 'sample.admin')
    project = store.create_project('샘플 · 결제 서비스 보안 점검', admin)
    users = []
    for login in ('sample.uploader', 'sample.operator', 'sample.viewer'):
        subject = str(uuid.uuid4())
        store.ensure_subject(subject, login)
        store.set_subject(subject, status='enabled', actor=admin)
        store.set_membership(project, subject, 'admin' if login == 'sample.operator' else 'viewer', actor=admin)
        users.append(subject)
    source = Path(root.name)/'manual-sample.py'
    source.write_text('# Sample input')
    input_id = store.add_input(project, source.name, source, users[0])
    run = store.create_scan(users[1], project, input_id, 'local', 'all', 'source')
    store.complete_run(run['run_id'], result={'findings': [], 'summary': {'total': 0}})
    source.unlink(missing_ok=True)
    mapping = store.set_gitlab_repositories(project, [dict(gitlab_project_id=101, path_with_namespace='sample-platform/payment-service-security-inspection', name='샘플 결제 서비스', default_branch='main', tracker_service_id='sample-service', tracker_environment_id='sample-environment', tracker_token_ref='sample-no-token')])[0]
    connection = store.save_server_connection(dict(name='샘플 운영 서버', host='sample-production.example.invalid', port=22, username='sample-reader', ssh_key_ref='/run/koda/ssh/sample-key', known_hosts_file='/run/koda/ssh/sample-known-hosts', project_ids=[project]), admin)
    detail_ids = []
    for i, (name, kind, scope, status) in enumerate([
        ('GitLab 결제 API · 매주 월·수·금', 'gitlab', 'source', 'completed'),
        ('운영 웹 서버 · 매일 새벽', 'server', 'all', 'completed'),
        ('GitLab 릴리스 태그 · 변경 없음', 'gitlab', 'source', 'completed'),
        ('백업 서버 · SSH 연결 실패', 'server', 'source', 'failed'),
        ('분석 서버 · 4시간마다', 'server', 'library', 'queued'),
        ('배치 서버 · 임시 파일 정리 실패', 'server', 'source', 'failed'),
    ]):
        target = store.save_schedule_target(dict(project_id=project, name=name, source_kind=kind,
            server_connection_id=connection['connection_id'] if i==1 else None,
            host=f'sample-production-application-server-{i+1}.example.invalid', username='sample-reader',
            ssh_key_ref='/run/koda/ssh/sample-key', known_hosts_file='/run/koda/ssh/sample-known-hosts',
            remote_directory='/srv/applications/payment-service/releases/2026-09-09/current/source',
            source_gitlab_mapping_id=mapping['mapping_id'] if kind=='gitlab' else None,
            source_gitlab_ref='release/2026-09-payment-security-improvements' if i==0 else 'v2.4.0',
            source_gitlab_ref_type='branch' if i==0 else 'tag', source_gitlab_directory='services/payment-api/src',
            gitlab_mapping_id=mapping['mapping_id'], scan_scope=scope, enabled=False, order_index=i,
            schedule_frequency='weekly' if i==0 else 'hourly' if i==4 else 'daily',
            schedule_time='02:30' if i==0 else '01:00', schedule_weekdays=[0,2,4], schedule_interval_hours=4,
            exclude_paths=['node_modules','logs','dist']))
        scheduled=store.begin_schedule_run(target['target_id'],'2026-09-09','changed' if i==2 else 'full',target['config_version'])
        run_id=None
        if status=='completed':
            source=Path(root.name)/f'sample-{i}.py';source.write_text('# sample source; no credentials\n')
            input_id=store.add_input(project,source.name,source,'schedule-worker')
            snapshot=_job_context(store,target,scheduled)['snapshot']
            run=store.create_scheduled_scan(project,input_id,'local','all',scope,snapshot)
            run_id=run['run_id'];detail_ids.append(run_id)
            findings=[] if i==2 else [dict(rule_id='sample-sql-injection',category='code',severity='high',title='[샘플] SQL 매개변수 처리 확인',path='services/payment-api/src/controllers/payment_controller.py',line=42,evidence='query = "SELECT ..." + user_input',recommendation='매개변수화된 쿼리를 사용하세요.'),dict(rule_id='sample-configuration',category='configuration',severity='medium',title='[샘플] 운영 디버그 설정 확인',path='config/production/settings.py',line=18,evidence='DEBUG = True',recommendation='운영 환경에서는 디버그 모드를 비활성화하세요.')]
            store.complete_run(run_id,result=dict(findings=findings,sbom={'components':[]},summary={'total':len(findings),'high':1 if findings else 0,'medium':1 if findings else 0},analysis_stages={'source':{'status':'completed','finding_count':len(findings)},'library':{'status':'skipped' if scope=='source' else 'completed','finding_count':0},'quality':{'status':'skipped','finding_count':0}}))
            source.unlink(missing_ok=True)
            with store._db() as db:
                db.execute("UPDATE tracker_deliveries SET status=?,gitlab_result_status='completed' WHERE run_id=?",('skipped' if scope=='source' else 'completed',run_id))
                db.execute("UPDATE gitlab_issue_deliveries SET status='completed' WHERE run_id=?",(run_id,))
        store.update_schedule_run(scheduled['schedule_run_id'],run_id=run_id,status=status,stage=status,
            cleanup_status='failed' if i==5 else 'pending' if status=='queued' else 'completed',
            cleanup_error='[샘플] 임시 디렉토리 접근 거부 — 재정리 대기' if i==5 else '',
            tracker_status='skipped' if scope=='source' else 'completed' if status=='completed' else 'pending',
            gitlab_status='completed' if status=='completed' else 'pending',files_total=1248 if i<3 else 0,changed_files=0 if i==2 else 28 if i<3 else 0,
            error='[샘플] SSH 연결 시간 초과' if i==3 else '')
    # Sample identity exists only in this isolated server, never in production code.
    original = server.RequestHandlerClass
    class SampleHandler(original):
        def parse_request(self):
            if not super().parse_request(): return False
            for key in ('X-KODA-Identity-ID','X-KODA-Identity-Expires','X-KODA-Identity-Display'):
                if key in self.headers: del self.headers[key]
            self.headers['X-KODA-Identity-ID']=admin
            self.headers['X-KODA-Identity-Expires']=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)).isoformat()
            self.headers['X-KODA-Identity-Display']=base64.urlsafe_b64encode('sample.admin'.encode()).decode().rstrip('=')
            return True
        sample_branches = ['main', 'release/2026-09-payment-security-improvements']
        def do_GET(self):
            if '/gitlab/repositories/' in self.path and '/refs?' in self.path:
                names = ['v2.4.0'] if 'type=tag' in self.path else self.sample_branches
                return self._json(200, [{'name': name} for name in names])
            return super().do_GET()
        def do_POST(self):
            if self.path not in {'/koda/api/v1/admin/schedules', '/koda/api/v1/admin/schedule-settings', '/koda/api/v1/admin/memberships', '/koda/api/v1/admin/server-connections'}:
                return self._json(403, {'detail':'샘플 미리보기에서는 실제 점검·외부 연동 실행을 지원하지 않습니다.'})
            return super().do_POST()
        def do_DELETE(self):
            return self._json(403, {'detail':'샘플 미리보기입니다.'})
    server.RequestHandlerClass=SampleHandler
    output=Path('output/playwright');output.mkdir(parents=True,exist_ok=True)
    url=f'http://127.0.0.1:{server.server_address[1]}'
    (output/'sample-preview.json').write_text(json.dumps({'url':url,'details':detail_ids,'project_id':project},indent=2))
    print(url,flush=True)
    try: server.serve_forever()
    finally: server.server_close();root.cleanup()


if __name__=='__main__': main()
