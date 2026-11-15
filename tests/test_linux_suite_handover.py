"""Small host fixtures/fake commands only; never uses a Docker daemon."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1] / "platforms/linux/suite/handover"
SPEC=importlib.util.spec_from_file_location('handover',ROOT/'handover.py')
h=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(h)
RECOVERY_SPEC = importlib.util.spec_from_file_location('gateway_recovery', ROOT/'recover-gateway-proof.py')
gateway_recovery = importlib.util.module_from_spec(RECOVERY_SPEC)
RECOVERY_SPEC.loader.exec_module(gateway_recovery)

class FixtureRunner(h.Runner):
    def __init__(self,prefix,identity=None):
        self.prefix=prefix; self.calls=[]
        self.volumes={name:{'name':'qa-'+name} for name in (*h.VOLUMES,'postgres-data')}
        self.config={'name':'qa-suite','volumes':self.volumes,'services':{'portal-api':{'image':'qa-api:old'}}}
        self.containers=[]
        for service in ['postgres','portal-api','portal-worker']:
            mounts=[]
            if service=='postgres': mounts=[{'Type':'volume','Name':'qa-postgres-data','RW':True}]
            if service=='portal-worker': mounts=[{'Type':'volume','Name':'qa-'+name,'RW':True} for name in h.VOLUMES]
            if service=='portal-api': mounts=[{'Type':'bind','Source':str(prefix/'config'/name),'Destination':target,'RW':False} for name,target in [('data.pub','/run/secrets/tracker-data-update-verify.pub'),('provision.token','/run/secrets/koda-tracker-provisioning')]]
            self.containers.append({'Id':'id-'+service,'Name':'/qa-'+service,'Image':'sha256:old-'+service,'State':{'Running':True},'Mounts':mounts,
                'Config':{'Image':'qa-api:old','Labels':{'com.docker.compose.project':'qa-suite','com.docker.compose.project.working_dir':str(prefix/'tracker'),'com.docker.compose.service':service}}})
        self.containers.append({'Id':'id-koda','Name':'/koda-dashboard','Image':'sha256:koda-old','State':{'Running':True},
            'Mounts':[{'Type':'bind','Source':str(prefix/'data/koda-portal'),'RW':True}],
            'Config':{'Image':'qa-koda:old','User':identity or f'{os.getuid()}:{os.getgid()}','Labels':{}}})

    def run(self,args,**kwargs):
        args=list(map(str,args)); self.calls.append(args)
        if args[0]=='bash': return super().run(args,**kwargs)
        if args[:3]==['docker','ps','-aq']: value=' '.join(c['Id'] for c in self.containers).encode()
        elif args[:2]==['docker','inspect']: value=json.dumps([c for c in self.containers if c['Id'] in args[2:]]).encode()
        elif args[:2]==['docker','compose']: value=json.dumps(self.config).encode()
        elif args[:3] in (['docker','volume','inspect'],['docker','image','inspect']): value=b'[]'
        elif args[:3] == ['docker','volume','ls']: value=b''
        elif args[:4] == ['docker','exec','id-postgres','psql']: value=b'f\n'
        elif args[:4] == ['docker','exec','id-gateway','wget']: value=b''
        else: raise AssertionError('Unexpected Docker fixture command: '+repr(args))
        return subprocess.CompletedProcess(args,0,value,b'')

def fixture(root):
    prefix=root/'installed'
    for name in ['tracker','koda','config/tokens','data/koda-portal']: (prefix/name).mkdir(parents=True,exist_ok=True)
    for name in ['metadata.env','koda-suite','koda/koda-docker','tracker/compose.yaml','tracker/compose.airgap.yaml','tracker/compose.integration.yaml']: (prefix/name).write_text('fixture\n')
    (prefix/'koda/image-ref.txt').write_text('qa-koda:old\n')
    (prefix/'config/data.pub').write_text('PUBLIC QA FIXTURE')
    (prefix/'config/provision.token').write_text('private-fixture-sentinel')
    (prefix/'tracker/.env').write_text("COMPOSE_PROJECT_NAME=qa-suite\nTRACKER_DB_NAME=tracker\nPOSTGRES_SUPERUSER=postgres\nKODA_GATEWAY_PROOF=private-fixture-sentinel\nTRACKER_DATA_UPDATE_VERIFY_KEY_FILE='../config/data.pub'\nKODA_TRACKER_PROVISIONING_TOKEN_FILE='../config/provision.token'\nKODA_TRACKER_TOKEN_DIR='../config/tokens'\n")
    return prefix

class HandoverTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='koda-handover-unit-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.prefix=fixture(self.root)

    def test_default_is_fixed_home_user0_not_current_home(self):
        with mock.patch.dict(os.environ,{'HOME':'/root','KODA_SUITE_PREFIX':'/wrong'}):
            args=h.parser().parse_args(['update'])
        self.assertEqual(args.prefix,Path('/home/user0/koda-suite'))

    def test_streaming_digest_matches_sha256_without_newer_file_digest(self):
        for payload in [b'',bytes(range(256))*(2*1024*1024//256+123)]:
            with self.subTest(bytes=len(payload)):
                path=self.root/'hash-input'; path.write_bytes(payload)
                with mock.patch.object(h.hashlib,'file_digest',side_effect=AssertionError('Python 3.11 API used'),create=True):
                    self.assertEqual(h.digest(path),hashlib.sha256(payload).hexdigest())

    def test_missing_tar_data_filter_stops_before_host_or_commands(self):
        unsupported=type('TarWithoutSafeFilter',(),{'TarError':h.tarfile.TarError})
        for action in ['check','update','backup']:
            with self.subTest(action=action):
                runner=mock.Mock(); errors=io.StringIO()
                with mock.patch.object(h,'tarfile',unsupported),mock.patch.object(h,'Host') as host,mock.patch.object(h,'RecoveryHost') as recovery,contextlib.redirect_stderr(errors):
                    result=h.main([action],runner)
                self.assertEqual(result,2)
                self.assertIn('data_filter',errors.getvalue())
                host.assert_not_called(); recovery.assert_not_called(); runner.run.assert_not_called()

    def test_canonical_env_wins_scoped_ambient_and_other_process_settings_survive(self):
        values,keys=h.source_environment(self.prefix/'tracker/.env',h.Runner(),{'PATH':os.environ['PATH'],'HOME':'/root','TZ':'UTC','DOCKER_HOST':'unix:///preserved','KODA_GATEWAY_PROOF':'wrong','TRACKER_UNDECLARED_SECRET':'wrong','COMPOSE_PROJECT_NAME':'wrong'})
        self.assertEqual(values['COMPOSE_PROJECT_NAME'],'qa-suite')
        self.assertEqual(values['KODA_GATEWAY_PROOF'],'private-fixture-sentinel')
        self.assertNotIn('TRACKER_UNDECLARED_SECRET',values)
        self.assertEqual(values['HOME'],'/root')
        self.assertEqual(values['TZ'],'UTC')
        self.assertEqual(values['DOCKER_HOST'],'unix:///preserved')

    def test_omitted_runtime_keys_do_not_inherit_ambient_or_example_values(self):
        example=self.prefix/'tracker/config/.env.example'; example.parent.mkdir(exist_ok=True)
        example.write_text('PUBLIC_HTTP_PORT=9999\nEXAMPLE_ONLY_SETTING=not-an-operating-value\nPATH=/wrong\nDOCKER_HOST=unix:///wrong\n')
        names=h.managed_environment_names(self.prefix)
        ambient={'PATH':os.environ['PATH'],'TZ':'UTC','DOCKER_HOST':'unix:///preserved','DOCKER_CONTEXT':'operator-context',
                 'PUBLIC_HTTP_PORT':'12345','GATEWAY_APP_IP':'192.0.2.55','APP_NETWORK_SUBNET':'192.0.2.0/24',
                 'POSTGRES_SUPERUSER':'wrong','GRYPE_DB_DIR':'/wrong','VULN_DATA_VOLUME_NAME':'wrong',
                 'EXAMPLE_ONLY_SETTING':'wrong'}
        values,_=h.source_environment(self.prefix/'tracker/.env',h.Runner(),ambient,managed_names=names)
        for key in ['PUBLIC_HTTP_PORT','GATEWAY_APP_IP','APP_NETWORK_SUBNET','GRYPE_DB_DIR','VULN_DATA_VOLUME_NAME','EXAMPLE_ONLY_SETTING']:
            self.assertNotIn(key,values)
        self.assertEqual(values['POSTGRES_SUPERUSER'],'postgres')
        self.assertEqual(values['PATH'],os.environ['PATH'])
        self.assertEqual(values['DOCKER_HOST'],'unix:///preserved')
        self.assertEqual(values['DOCKER_CONTEXT'],'operator-context')
        self.assertEqual(values['TZ'],'UTC')

    def test_duplicate_env_fails_before_command(self):
        path=self.prefix/'tracker/.env'; path.write_text(path.read_text()+'COMPOSE_PROJECT_NAME=other\n')
        runner=mock.Mock()
        with self.assertRaisesRegex(h.Failure,'중복'): h.source_environment(path,runner)
        runner.run.assert_not_called()

    def test_host_canonicalizes_symlink_and_does_not_stop_anything(self):
        alias=self.root/'logical-prefix'; alias.symlink_to(self.prefix,target_is_directory=True)
        runner=FixtureRunner(self.prefix)
        host=h.Host(alias,alias/'tracker/.env',runner)
        self.assertEqual(host.prefix,self.prefix.resolve())
        self.assertEqual(host.env_file,(self.prefix/'tracker/.env').resolve())
        self.assertFalse(any(call[:2] in [['docker','stop'],['docker','start']] for call in runner.calls))

    def test_alternate_ldap_env_is_rejected_before_any_command(self):
        alternate=self.root/'different.env'
        alternate.write_text((self.prefix/'tracker/.env').read_text()+'TRACKER_LDAP_ENCRYPTION_KEY=different-secret\n')
        runner=mock.Mock()
        with self.assertRaisesRegex(h.Failure,'동일한 파일'): h.Host(self.prefix,alternate,runner)
        runner.run.assert_not_called()

    def test_samefile_env_alias_uses_canonical_relative_path_base(self):
        alias=self.root/'env-alias'; alias.symlink_to(self.prefix/'tracker/.env')
        host=h.Host(self.prefix,alias,FixtureRunner(self.prefix))
        self.assertEqual(host.env_file,(self.prefix/'tracker/.env').resolve())
        self.assertEqual(host.paths['TRACKER_DATA_UPDATE_VERIFY_KEY_FILE'],(self.prefix/'config/data.pub').resolve())

    def test_identity_mismatch_fails_before_stop_or_backup(self):
        runner=FixtureRunner(self.prefix,identity=f'{os.getuid()+1}:{os.getgid()}')
        with self.assertRaisesRegex(h.Failure,'실행 계정'): h.Host(self.prefix,self.prefix/'tracker/.env',runner)
        self.assertFalse(any(call[:2]==['docker','stop'] for call in runner.calls))

    def test_unrelated_container_with_null_labels_is_ignored(self):
        runner=FixtureRunner(self.prefix)
        runner.containers.append({'Id':'unrelated','Name':'/unrelated-manual-container','Image':'sha256:other',
            'Config':{'Labels':None,'Image':'unrelated:old'},'State':{'Running':False},'Mounts':[]})
        host=h.Host(self.prefix,self.prefix/'tracker/.env',runner)
        self.assertNotIn('unrelated',[item['Id'] for item in host.containers])
        self.assertFalse(any(call[:2]==['docker','stop'] for call in runner.calls))

    def test_shared_mount_conflicts_report_names_and_states_without_stopping_containers(self):
        runner = FixtureRunner(self.prefix)
        tracker = self.prefix / 'tracker'
        runner.containers.extend([
            {'Id': 'live-foreign', 'Name': '/foreign-data-writer', 'State': {'Running': True},
             'Config': {'Labels': {'com.docker.compose.project': 'qa-suite',
                                   'com.docker.compose.project.working_dir': '/different-install'},
                        'Env': ['PASSWORD=private-fixture-sentinel']},
             'Mounts': [{'Type': 'volume', 'Name': 'qa-postgres-data', 'RW': True}]},
            {'Id': 'stopped-foreign', 'Name': '/stopped-snapshot', 'State': {'Running': False},
             'Config': {'Labels': None},
             'Mounts': [{'Type': 'bind', 'Source': str(self.prefix / 'data/koda-portal'), 'RW': True}]},
            {'Id': 'read-only', 'Name': '/read-only-monitor', 'State': {'Running': True},
             'Config': {'Labels': None},
             'Mounts': [{'Type': 'volume', 'Name': 'qa-postgres-data', 'RW': False}]},
        ])
        with self.assertRaises(h.Failure) as caught:
            h.Host(self.prefix, tracker / '.env', runner)
        message = str(caught.exception)
        self.assertIn('foreign-data-writer [실행 중] · 쓰기 마운트: postgres-data', message)
        self.assertIn('Compose 프로젝트 일치, 작업 경로 다름', message)
        self.assertIn('stopped-snapshot [정지] · 쓰기 마운트: data/koda-portal', message)
        self.assertNotIn('read-only-monitor', message)
        self.assertNotIn('private-fixture-sentinel', message)
        self.assertFalse(any(call[:2] == ['docker', 'stop'] for call in runner.calls))

    def test_gateway_proof_recovery_checks_before_writing_and_creates_private_backup(self):
        env_file = self.prefix/'tracker/.env'
        original = b'TRACKER_DB_NAME=tracker\nKODA_GATEWAY_PROOF=\n'
        env_file.write_bytes(original)
        proof = 'test_gateway_proof_' + 'a' * 32
        output = io.StringIO()
        with mock.patch.object(gateway_recovery, 'live_proof', return_value=proof), contextlib.redirect_stdout(output):
            gateway_recovery.recover(self.prefix, False)
            self.assertEqual(env_file.read_bytes(), original)
            self.assertFalse(list(env_file.parent.glob('.env.gateway-proof-backup.*')))
            gateway_recovery.recover(self.prefix, True)
        backup, = env_file.parent.glob('.env.gateway-proof-backup.*')
        self.assertEqual(backup.read_bytes(), original)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(env_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(env_file.read_bytes(),
                         original.replace(b'KODA_GATEWAY_PROOF=', b'KODA_GATEWAY_PROOF=' + proof.encode()))
        self.assertNotIn(proof, output.getvalue())

    def test_gateway_proof_recovery_never_overwrites_a_conflicting_existing_value(self):
        env_file = self.prefix/'tracker/.env'
        original = env_file.read_bytes()
        proof = 'test_gateway_proof_' + 'a' * 32
        with mock.patch.object(gateway_recovery, 'live_proof', return_value=proof):
            with self.assertRaisesRegex(gateway_recovery.RecoveryError, '다른 gateway proof'):
                gateway_recovery.recover(self.prefix, True)
        self.assertEqual(env_file.read_bytes(), original)
        self.assertFalse(list(env_file.parent.glob('.env.gateway-proof-backup.*')))

    def legacy_gateway_fixture(self):
        env_file = self.prefix / 'tracker/.env'
        env_file.write_text(env_file.read_text().replace('KODA_GATEWAY_PROOF=private-fixture-sentinel\n', ''))
        runner = FixtureRunner(self.prefix)
        runner.containers.append({
            'Id': 'id-gateway', 'Name': '/qa-gateway', 'Image': 'sha256:gateway',
            'State': {'Running': True}, 'Mounts': [],
            'Config': {'Labels': {'com.docker.compose.service': 'gateway',
                                  'com.docker.compose.project': 'qa-suite',
                                  'com.docker.compose.project.working_dir': str(env_file.parent)}},
        })
        return env_file, runner

    def test_legacy_gateway_check_is_read_only_and_needs_an_explicit_flag(self):
        env_file, runner = self.legacy_gateway_fixture()
        original = env_file.read_bytes()
        with self.assertRaisesRegex(h.Failure, 'KODA_GATEWAY_PROOF'):
            h.Host(self.prefix, env_file, runner)
        with mock.patch.object(runner, 'run', wraps=runner.run) as calls:
            host = h.Host(self.prefix, env_file, runner, migrate_legacy_gateway_proof=True)
        compose_calls = [call for call in calls.call_args_list if call.args[0][:2] == ['docker', 'compose']]
        self.assertEqual(len(compose_calls), 1)
        self.assertIn(h.PROOF_KEY, compose_calls[0].kwargs['env'])
        self.assertNotIn(h.PROOF_KEY, host.env)
        self.assertEqual(env_file.read_bytes(), original)
        self.assertFalse(any(call[:2] in (['docker', 'stop'], ['docker', 'start']) for call in runner.calls))

        runner.containers[-1]['Config']['Env'] = [h.PROOF_KEY + '=existing']
        with self.assertRaisesRegex(h.Failure, '기존 값을 복구'):
            h.Host(self.prefix, env_file, runner, migrate_legacy_gateway_proof=True)

    def test_legacy_recheck_ignores_inspect_order_but_reports_real_changes(self):
        env_file, runner = self.legacy_gateway_fixture()
        host = h.Host(self.prefix, env_file, runner, migrate_legacy_gateway_proof=True)
        worker = next(item for item in runner.containers if item['Id'] == 'id-portal-worker')
        worker['Mounts'].reverse()
        runner.containers.reverse()
        host.recheck_legacy_gateway()

        for mapping, key, value, message in (
            (worker['Mounts'][0], 'RW', False, r'qa-portal-worker \(마운트\)'),
            (worker, 'Image', 'sha256:replacement', r'qa-portal-worker \(이미지\)'),
            (worker['State'], 'Running', False, r'qa-portal-worker \(실행 상태\)'),
            (worker, 'Id', 'replacement-id', '추가·제거·교체됐습니다: qa-portal-worker'),
        ):
            with self.subTest(field=key), mock.patch.dict(mapping, {key: value}):
                with self.assertRaisesRegex(h.Failure, message):
                    host.recheck_legacy_gateway()

    def test_legacy_migration_can_leave_a_finished_nonrestarting_grype_import_in_place(self):
        env_file, runner = self.legacy_gateway_fixture()
        importer = {
            'Id': 'id-grype', 'Name': '/koda-grype-db-import',
            'State': {'Running': False, 'Status': 'exited', 'ExitCode': 0, 'StartedAt': 'first'},
            'Config': {'Labels': None}, 'HostConfig': {'RestartPolicy': {'Name': 'no'}},
            'Mounts': [{'Type': 'volume', 'Name': 'qa-vuln-data', 'RW': True}],
        }
        runner.containers.append(importer)
        host = h.Host(self.prefix, env_file, runner, migrate_legacy_gateway_proof=True)
        self.assertNotIn('id-grype', {container['id'] for container in host.original})
        host.recheck_retired_grype_import()
        importer['State']['StartedAt'] = 'second'
        with self.assertRaisesRegex(h.Failure, '반입 작업의 상태가 바뀌었습니다'):
            host.recheck_retired_grype_import()
        importer['State'].update(Running=True, Status='running')
        with self.assertRaisesRegex(h.Failure, r'koda-grype-db-import \[실행 중\]'):
            h.Host(self.prefix, env_file, runner, migrate_legacy_gateway_proof=True)
        importer['State'].update(Running=False, Status='exited')
        importer['HostConfig']['RestartPolicy']['Name'] = 'always'
        with self.assertRaisesRegex(h.Failure, r'koda-grype-db-import \[정지\]'):
            h.Host(self.prefix, env_file, runner, migrate_legacy_gateway_proof=True)
        self.assertFalse(any(call[:2] in (['docker', 'stop'], ['docker', 'rm']) for call in runner.calls))

    def test_legacy_scheduler_with_matching_mounts_is_included_in_backup_writers(self):
        env_file, runner = self.legacy_gateway_fixture()
        env_file.write_text(env_file.read_text() + 'KODA_SCHEDULE_ENABLED=1\n')
        data = self.prefix / 'data/koda-portal'
        worker = {
            'Id': 'id-schedule', 'Name': '/koda-schedule-worker', 'Image': 'sha256:koda-old',
            'State': {'Running': True},
            'Config': {'Image': 'qa-koda:old', 'User': f'{os.getuid()}:{os.getgid()}',
                       'Labels': {'io.koda.offline': 'true'}, 'Cmd': ['schedule-worker']},
            'Mounts': [
                {'Type': 'bind', 'Source': str(data/'schedule-auth'), 'Destination': '/run/koda/schedule', 'RW': False},
                {'Type': 'bind', 'Source': str(data.with_name('koda-portal-schedule')),
                 'Destination': '/var/lib/koda-schedule', 'RW': True},
            ],
        }
        runner.containers.append(worker)
        host = h.Host(self.prefix, env_file, runner, migrate_legacy_gateway_proof=True)
        self.assertIn('id-schedule', {container['id'] for container in host.original})
        worker['Mounts'][1]['Source'] = '/foreign/schedule'
        with self.assertRaisesRegex(h.Failure, '고정 이름 컨테이너와 충돌.*koda-schedule-worker'):
            h.Host(self.prefix, env_file, runner, migrate_legacy_gateway_proof=True)

    def test_legacy_update_with_dependency_track_fails_before_backup_or_release(self):
        env_file, runner = self.legacy_gateway_fixture()
        runner.containers.append({
            'Id': 'id-dtrack', 'Name': '/qa-suite-dtrack-apiserver', 'Image': 'sha256:dtrack',
            'State': {'Running': True}, 'Config': {'Labels': {'com.docker.compose.project': 'qa-suite',
                       'com.docker.compose.service': 'dtrack-apiserver'}}, 'Mounts': [],
        })
        args = ['update', '--migrate-legacy-gateway-proof', '--prefix', str(self.prefix)]
        errors = io.StringIO()
        with (mock.patch.object(h.sys, 'platform', 'linux'), mock.patch.object(h, 'release') as release,
              mock.patch.object(h, 'backup_host') as backup, contextlib.redirect_stderr(errors)):
            self.assertEqual(h.main(args, runner), 2)
        self.assertIn('Dependency-Track의 전용 DB와 볼륨', errors.getvalue())
        release.assert_not_called()
        backup.assert_not_called()
        self.assertFalse(any(call[:2] == ['docker', 'stop'] for call in runner.calls))
        @contextlib.contextmanager
        def released(args, host):
            yield self.root/'signed/koda-suite', host.env
        output = io.StringIO()
        with (mock.patch.object(h.sys, 'platform', 'linux'), mock.patch.object(h, 'release', released),
              mock.patch.object(h, 'backup_host') as backup, contextlib.redirect_stdout(output)):
            self.assertEqual(h.main(['check', *args[1:]], runner), 0)
        self.assertIn('업데이트 보류: Dependency-Track 데이터 보존 방안을', output.getvalue().splitlines()[-1])
        backup.assert_not_called()

    def test_retirement_uses_signed_cleaner_and_refuses_tracker_database(self):
        env_file, runner = self.legacy_gateway_fixture()
        host = h.Host(self.prefix, env_file, runner, migrate_legacy_gateway_proof=True)
        suite = self.root/'signed/koda-suite'
        (suite.parent/'bundles').mkdir(parents=True)
        (suite.parent/'metadata.env').write_text('TRACKER_BUNDLE=bundles/tracker.tar.gz\n')
        source = b"""
def read_env(path):
    return dict(line.split('=', 1) for line in open(path).read().splitlines())
class Cleaner:
    project = 'qa-suite'
    def __init__(self, values): pass
    def plan(self): return [], ['qa-dtrack-data'], []
"""
        with h.tarfile.open(suite.parent/'bundles/tracker.tar.gz', 'w:gz') as archive:
            member = h.tarfile.TarInfo('./scripts/remove-retired-analysis.py'); member.size = len(source)
            archive.addfile(member, io.BytesIO(source))

        def run(command, **kwargs):
            if command[0] == 'python3':
                return h.Runner().run(command, **kwargs)
            return subprocess.CompletedProcess(command, 0, b'{"exists":true,"owned":true,"shared":false}', b'')

        with mock.patch.object(runner, 'run', side_effect=run):
            plan = host.dependency_track_plan(suite)
            self.assertEqual(plan['volumes'], ['qa-dtrack-data'])
            self.assertEqual(plan['database'], 'dtrack')
            with env_file.open('a') as output:
                output.write('DTRACK_DB_NAME=tracker\n')
            with self.assertRaisesRegex(h.Failure, 'Tracker·관리자 설정과 충돌'):
                host.dependency_track_plan(suite)

    def test_retirement_backup_archives_database_and_volume_before_cleanup(self):
        env_file, runner = self.legacy_gateway_fixture()
        host = h.Host(self.prefix, env_file, runner, migrate_legacy_gateway_proof=True)
        plan = {'database':'dtrack','role':'dtrack','admin':'postgres','exists':True,'volumes':['qa-dtrack-data']}
        folder = self.root/'backup'; folder.mkdir(mode=0o700)
        commands = []

        def run(command, **kwargs):
            commands.append(command)
            if 'pg_dump' in command:
                kwargs['output'].write(b'private database fixture')
            elif 'pg_restore' in command:
                self.assertIn('--file=/dev/null', command)
                self.assertEqual(kwargs['stdin'].read(), b'private database fixture')
            else:
                self.assertIn('type=volume,src=qa-dtrack-data,dst=/snapshot,readonly', command)
                with h.tarfile.open(fileobj=kwargs['output'], mode='w|gz') as archive:
                    archive.add(env_file, arcname='fixture')

        state = {'exists':True,'owned':True,'shared':False,'connected':False}
        with (mock.patch.object(host, 'dependency_track_database', return_value=state),
              mock.patch.object(runner, 'run', side_effect=run)):
            manifest = h.backup_dependency_track(host, folder, plan)
            self.assertEqual(manifest['dump'], 'dependency-track.dump')
            self.assertEqual(manifest['volumes'], {'qa-dtrack-data':'dependency-track-volume-1.tar.gz'})
            self.assertEqual((folder/manifest['dump']).stat().st_mode & 0o777, 0o600)
            self.assertTrue(any('--dbname=dtrack' in command for command in commands))
            self.assertFalse(any('--dbname=tracker' in command for command in commands))
            commands.clear()
            state['connected'] = True
            with self.assertRaisesRegex(h.Failure, '아직 연결이 남아'):
                h.backup_dependency_track(host, folder, plan)
            self.assertFalse(commands)

    def test_retirement_never_enters_installer_when_backup_fails(self):
        env_file, fixture_runner = self.legacy_gateway_fixture()
        host = h.Host(self.prefix, env_file, fixture_runner, migrate_legacy_gateway_proof=True)
        args = ['--prefix', str(self.prefix), '--migrate-legacy-gateway-proof', '--retire-dependency-track']

        @contextlib.contextmanager
        def released(_args, actual):
            yield self.root/'signed/koda-suite', actual.env

        runner = mock.Mock()
        with (mock.patch.object(h.sys, 'platform', 'linux'), mock.patch.object(h, 'Host', return_value=host),
              mock.patch.object(h, 'release', released), mock.patch.object(host, 'dependency_track_plan', return_value={'exists':True}),
              mock.patch.object(h, 'backup_host', side_effect=h.Failure('test backup failed')) as backup,
              contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO())):
            self.assertEqual(h.main(['check', *args], runner), 0)
            self.assertIn('정리 범위 확인 완료', output.getvalue())
            backup.assert_not_called()
            self.assertEqual(h.main(['update', *args], runner), 2)
            backup.assert_called_once()
            runner.run.assert_not_called()

    def test_legacy_gateway_update_backs_up_before_enabling_proof(self):
        env_file, fixture_runner = self.legacy_gateway_fixture()
        host = h.Host(self.prefix, env_file, fixture_runner, migrate_legacy_gateway_proof=True)
        original = env_file.read_bytes()
        folder = self.root / 'backup'
        folder.mkdir(mode=0o700)
        archive = self.root / 'suite.tar.gz'
        archive.write_bytes(b'fixture')
        events = []
        proof = 'legacy-migration-fixture-' + 'a' * 32

        @contextlib.contextmanager
        def released(args, actual):
            self.assertIs(actual, host)
            self.assertEqual(env_file.read_bytes(), original)
            for container in fixture_runner.containers:
                container['Mounts'].reverse()
            yield self.root / 'signed/koda-suite', actual.env

        def backup(actual, root, *, hold):
            self.assertTrue(hold)
            self.assertNotIn(h.PROOF_KEY, actual.env)
            self.assertEqual(env_file.read_bytes(), original)
            events.append('backup')
            return folder, ['id-old']

        runner = mock.Mock()
        def install_or_status(args, *, env):
            self.assertNotIn(h.PROOF_KEY, env)
            action = args[2]
            events.append(action)
            if action == 'install':
                env_file.write_bytes(original + f'{h.PROOF_KEY}={proof}\n'.encode())
                for container in h.gateway_pair(fixture_runner.containers):
                    container['Config']['Env'] = [f'{h.PROOF_KEY}={proof}']

        runner.run.side_effect = install_or_status
        with (mock.patch.object(h.sys, 'platform', 'linux'),
              mock.patch.object(h, 'Host', return_value=host),
              mock.patch.object(h, 'release', released),
              mock.patch.object(h, 'backup_host', side_effect=backup),
              contextlib.redirect_stdout(io.StringIO())):
            status = h.main(['update', '--migrate-legacy-gateway-proof', '--prefix', str(self.prefix),
                             '--archive', str(archive)], runner)
        self.assertEqual(status, 0)
        self.assertEqual(events, ['backup', 'install', 'status'])
        self.assertIn(['docker', 'exec', 'id-gateway', 'wget', '-q', '-T', '10', '-O', '/dev/null',
                       'http://127.0.0.1:8080/koda/ready'], fixture_runner.calls)
        fixture_runner.containers[-1]['Config']['Env'] = []
        with self.assertRaisesRegex(h.Failure, '두 실행 컨테이너에 일치하지'):
            host.check_preserved()

    def test_missing_install_does_not_create_default_or_run_commands(self):
        runner=mock.Mock()
        with mock.patch.object(h.sys,'platform','linux'),contextlib.redirect_stderr(io.StringIO()):
            status=h.main(['check','--prefix',str(self.root/'missing')],runner)
        self.assertEqual(status,2); runner.run.assert_not_called()
        self.assertFalse((self.root/'missing').exists())

    def test_check_flag_never_silently_runs_backup_or_restore(self):
        for action in ['backup','restore-config','rollback']:
            with self.subTest(action=action):
                runner=mock.Mock()
                args=[action,'--check']+(['--apply'] if action!='backup' else [])
                with mock.patch.object(h,'Host') as host,mock.patch.object(h,'RecoveryHost') as recovery,contextlib.redirect_stderr(io.StringIO()):
                    result=h.main(args,runner)
                self.assertEqual(result,2)
                host.assert_not_called(); recovery.assert_not_called(); runner.run.assert_not_called()

    def test_restore_can_inspect_stopped_postgres(self):
        runner=FixtureRunner(self.prefix)
        for item in runner.containers: item['State']['Running']=False
        host=h.Host(self.prefix,self.prefix/'tracker/.env',runner,allow_stopped=True)
        self.assertEqual(host.postgres,'id-postgres')

    def test_volume_backup_is_ro_offline_root_read_cap_only_and_root_cache_only(self):
        host=h.Host(self.prefix,self.prefix/'tracker/.env',FixtureRunner(self.prefix))
        command=host.volume_command('qa-tracker-artifacts',cache=True)
        self.assertIn('--pull',command); self.assertIn('never',command)
        self.assertIn('none',command); self.assertIn('ALL',command); self.assertIn('DAC_READ_SEARCH',command)
        self.assertIn('type=volume,src=qa-tracker-artifacts,dst=/snapshot,readonly',command)
        self.assertEqual(command[command.index('--entrypoint')+1],'python')
        source=self.root/'snapshot'; source.mkdir()
        (source/'.nvd-cache').mkdir(); (source/'.nvd-cache/derived').write_text('excluded')
        (source/'nested/.nvd-cache').mkdir(parents=True); (source/'nested/.nvd-cache/original').write_text('retained')
        (source/'.hidden').write_text('retained')
        script=command[-1].replace('/snapshot',str(source))
        output=self.root/'artifact.tar.gz'
        with output.open('wb') as stream: subprocess.run([os.sys.executable,'-c',script],stdout=stream,check=True)
        import tarfile
        with tarfile.open(output) as archive:
            names=set(archive.getnames())
        self.assertNotIn('./.nvd-cache',names)
        self.assertIn('./nested/.nvd-cache/original',names)
        self.assertIn('./.hidden',names)

    def test_check_calls_only_verify_preflight_and_never_backup_install(self):
        host=mock.Mock(prefix=self.prefix,env_file=self.prefix/'tracker/.env',env={})
        @contextlib.contextmanager
        def released(args,actual):
            self.assertIs(actual,host)
            yield self.root/'signed/koda-suite',{}
        with mock.patch.object(h.sys,'platform','linux'),mock.patch.object(h,'Host',return_value=host),mock.patch.object(h,'release',released),mock.patch.object(h,'backup_host') as backup,contextlib.redirect_stdout(io.StringIO()):
            status=h.main(['update','--check','--prefix',str(self.prefix)],mock.Mock())
        self.assertEqual(status,0); backup.assert_not_called(); host.resume.assert_not_called()

    def test_update_uses_existing_env_and_checkpoint_before_install(self):
        host=mock.Mock(prefix=self.prefix,env_file=self.prefix/'tracker/.env',env={})
        events=[]; folder=self.root/'backup'; folder.mkdir(mode=0o700)
        archive=self.root/'suite.tar.gz'; archive.write_bytes(b'QA')
        @contextlib.contextmanager
        def released(args,actual): yield self.root/'signed/koda-suite',{}
        def back(*args,**kwargs): events.append('backup'); self.assertTrue(kwargs['hold']); return folder,['old-worker']
        runner=mock.Mock()
        runner.run.side_effect=lambda args,**kwargs: events.append(list(map(str,args)))
        with mock.patch.object(h.sys,'platform','linux'),mock.patch.object(h,'Host',return_value=host),mock.patch.object(h,'release',released),mock.patch.object(h,'backup_host',side_effect=back),mock.patch.object(h,'operation_lock',lambda actual:contextlib.nullcontext()),contextlib.redirect_stdout(io.StringIO()):
            status=h.main(['update','--prefix',str(self.prefix),'--archive',str(archive)],runner)
        self.assertEqual(status,0)
        self.assertEqual(events[0],'backup')
        self.assertEqual(events[1],['bash',str(self.root/'signed/koda-suite'),'install','--prefix',str(self.prefix),'--env-file',str(self.prefix/'tracker/.env')])
        host.check_preserved.assert_called_once()
        self.assertFalse(any('down' in event or 'prune' in event for event in events if isinstance(event,list)))

    def test_failed_install_restarts_only_old_ids_and_never_prints_secrets(self):
        host=mock.Mock(prefix=self.prefix,env_file=self.prefix/'tracker/.env',env={'SECRET':'private-fixture-sentinel'})
        host.resume.return_value=['old-worker']
        folder=self.root/'backup'; folder.mkdir(mode=0o700)
        @contextlib.contextmanager
        def released(args,actual): yield self.root/'signed/koda-suite',host.env
        runner=mock.Mock(); runner.run.side_effect=h.Failure('실행 실패')
        out,err=io.StringIO(),io.StringIO()
        with mock.patch.object(h.sys,'platform','linux'),mock.patch.object(h,'Host',return_value=host),mock.patch.object(h,'release',released),mock.patch.object(h,'backup_host',return_value=(folder,['old-worker'])),mock.patch.object(h,'operation_lock',lambda actual:contextlib.nullcontext()),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            status=h.main(['update','--prefix',str(self.prefix)],runner)
        self.assertEqual(status,2); host.resume.assert_called_once_with(['old-worker'])
        self.assertNotIn('private-fixture-sentinel',out.getvalue()+err.getvalue())
        self.assertFalse(json.loads((self.root/'backup-update-result.json').read_text())['automaticDatabaseRestore'])

    def test_backup_verification_rejects_tamper(self):
        folder=self.root/'backup'; folder.mkdir(mode=0o700)
        h.private_json(folder/'checkpoint.json',{'phase':'complete','format':'koda-private-local-checkpoint-v1'})
        (folder/'manifest.sha256').write_text(h.digest(folder/'checkpoint.json')+'  checkpoint.json\n'); (folder/'manifest.sha256').chmod(0o600)
        h.verify_backup(folder)
        (folder/'checkpoint.json').write_text('tampered')
        with self.assertRaisesRegex(h.Failure,'무결성'): h.verify_backup(folder)

    def signed_release(self,fail_preflight=False):
        import tarfile
        source=self.root/'release/koda-suite-offline-x86_64-qa'
        source.mkdir(parents=True)
        (source/'koda-suite').write_text('#!/usr/bin/env bash\nset -eu\ncase "$1" in verify) exit 0;; preflight) exit '+('8' if fail_preflight else '0')+';; *) exit 9;; esac\n')
        archive=self.root/'koda-suite-offline-qa.tar.gz'
        with tarfile.open(archive,'w:gz') as stream: stream.add(source,arcname=source.name)
        key=self.root/'ephemeral-test-private.pem'; public=self.root/'test-public.pem'
        subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(key)],check=True,capture_output=True)
        subprocess.run(['openssl','pkey','-in',str(key),'-pubout','-out',str(public)],check=True,capture_output=True)
        subprocess.run(['openssl','dgst','-sha256','-sign',str(key),'-out',str(archive)+'.sig',str(archive)],check=True,capture_output=True)
        Path(str(archive)+'.sha256').write_text(h.digest(archive)+'  '+archive.name+'\n')
        return h.parser().parse_args(['check','--archive',str(archive),'--release-public-key',str(public)])

    def test_real_signature_and_single_topdir_preflight_change_no_install_files(self):
        args=self.signed_release()
        host=type('HostFixture',(),{'env':dict(os.environ),'runner':h.Runner(),'prefix':self.prefix,'env_file':self.prefix/'tracker/.env'})()
        before={str(p):h.digest(p) for p in self.prefix.rglob('*') if p.is_file()}
        with h.release(args,host) as (suite,env):
            self.assertEqual(suite.parent.name,'koda-suite-offline-x86_64-qa')
            self.assertEqual(env['KODA_ALLOW_UNSIGNED_ARTIFACTS'],'0')
        self.assertEqual(before,{str(p):h.digest(p) for p in self.prefix.rglob('*') if p.is_file()})

    def test_one_complete_preflight_without_repeating_separate_verify(self):
        args=self.signed_release()
        runner=h.Runner(); original=runner.run
        with mock.patch.object(runner,'run',wraps=original) as calls:
            host=type('HostFixture',(),{'env':dict(os.environ),'runner':runner,'prefix':self.prefix,'env_file':self.prefix/'tracker/.env'})()
            with h.release(args,host): pass
        suite_actions=[call.args[0][2] for call in calls.call_args_list if call.args[0][0]=='bash']
        self.assertEqual(suite_actions,['preflight'])

    def test_failed_inner_preflight_stops_update_before_backup(self):
        args=self.signed_release(fail_preflight=True)
        host=type('HostFixture',(),{'env':dict(os.environ),'runner':h.Runner(),'prefix':self.prefix,'env_file':self.prefix/'tracker/.env'})()
        with mock.patch.object(h.sys,'platform','linux'),mock.patch.object(h,'Host',return_value=host),mock.patch.object(h,'backup_host') as backup,contextlib.redirect_stderr(io.StringIO()):
            result=h.main(['update','--prefix',str(self.prefix),'--archive',str(args.archive),'--release-public-key',str(args.release_public_key)],host.runner)
        self.assertEqual(result,2); backup.assert_not_called()

    def test_corrupt_payload_fails_before_suite_execution(self):
        args=self.signed_release(); args.archive.write_bytes(b'tampered')
        runner=mock.Mock()
        host=type('HostFixture',(),{'env':dict(os.environ),'runner':runner})()
        with self.assertRaisesRegex(h.Failure,'SHA-256'):
            with h.release(args,host): self.fail('corrupt release yielded')
        runner.run.assert_not_called()

    def test_separate_verification_directory_and_mismatched_signature(self):
        args = self.signed_release()
        args.verification_dir = self.root/'verification'
        args.verification_dir.mkdir()
        for extension in ('.sha256', '.sig'):
            path = args.archive.with_name(args.archive.name+extension)
            path.rename(args.verification_dir/path.name)
        runner = h.Runner()
        host = type('HostFixture', (), {'env':dict(os.environ),'runner':runner,
                    'prefix':self.prefix,'env_file':self.prefix/'tracker/.env'})()
        with h.release(args, host): pass
        (args.verification_dir/(args.archive.name+'.sig')).write_bytes(b'incorrect signature')
        with self.assertRaisesRegex(h.Failure, 'SHA-256은 일치하지만 배포 서명이'):
            with h.release(args, host): self.fail('invalid release yielded')

    def recovery_backup(self):
        import tarfile
        folder=self.root/'recovery'; folder.mkdir(mode=0o700)
        with tarfile.open(folder/'installed-prefix.tar.gz','w:gz') as archive:
            for path in self.prefix.iterdir(): archive.add(path,arcname=path.name)
        h.private_json(folder/'checkpoint.json',{'format':'koda-private-local-checkpoint-v1','phase':'complete',
            'prefix':str(self.prefix.resolve()),'envFile':str((self.prefix/'tracker/.env').resolve()),
            'project':'qa-suite','volumes':{'postgres-data':'qa-postgres-data'},'externalPaths':[],
            'operatorUid':os.getuid(),'operatorGid':os.getgid()})
        for path in folder.iterdir(): path.chmod(0o600)
        (folder/'manifest.sha256').write_text(''.join(h.digest(path)+'  '+path.name+'\n' for path in sorted(folder.iterdir())))
        (folder/'manifest.sha256').chmod(0o600)
        return folder

    def test_verified_checkpoint_restores_missing_env_and_key_without_current_settings(self):
        folder=self.recovery_backup()
        env=self.prefix/'tracker/.env'; original=env.read_bytes(); env.unlink()
        key=self.prefix/'config/data.pub'; key.unlink()
        data=self.prefix/'data/koda-portal/customer.txt'; data.write_text('keep current customer data')
        runner=FixtureRunner(self.prefix)
        for item in runner.containers: item['State']['Running']=False
        host=h.RecoveryHost(self.prefix,folder,runner)
        with contextlib.redirect_stdout(io.StringIO()): h.restore_files(host,folder)
        self.assertFalse(env.exists()); self.assertFalse(key.exists())
        with contextlib.redirect_stdout(io.StringIO()): h.restore_files(host,folder,apply=True)
        self.assertEqual(env.read_bytes(),original)
        self.assertEqual(key.read_text(),'PUBLIC QA FIXTURE')
        self.assertEqual(data.read_text(),'keep current customer data')
        self.assertFalse(any(call[:2] in [['docker','start'],['docker','stop']] for call in runner.calls))

    def test_recovery_rejects_other_prefix_before_docker(self):
        folder=self.recovery_backup(); other=self.root/'other'; other.mkdir()
        runner=mock.Mock()
        with self.assertRaisesRegex(h.Failure,'prefix'): h.RecoveryHost(other,folder,runner)
        runner.run.assert_not_called()

    def test_backup_rejects_symlink_root_inside_prefix_before_mutation(self):
        inside=self.prefix/'recursive-backups'
        alias=self.root/'outside-looking-backups'; alias.symlink_to(inside)
        host=mock.Mock(prefix=self.prefix.resolve(),paths={})
        with self.assertRaisesRegex(h.Failure,'밖에'): h.backup_host(host,alias)
        self.assertFalse(inside.exists()); host.runner.run.assert_not_called()

    def test_backup_rejects_root_inside_external_snapshot_directory(self):
        external=self.root/'external-secrets'; external.mkdir()
        destination=external/'backups'
        host=mock.Mock(prefix=self.prefix.resolve(),paths={'KODA_TRACKER_TOKEN_DIR':external.resolve()})
        with self.assertRaisesRegex(h.Failure,'밖에'): h.backup_host(host,destination)
        self.assertFalse(destination.exists()); host.runner.run.assert_not_called()

    def test_backup_rejects_absolute_snapshot_link_before_stop(self):
        (self.prefix/'config/unsupported-link').symlink_to('/tmp/absolute-target')
        host=mock.Mock(prefix=self.prefix.resolve(),paths={})
        destination=self.root/'backups'
        with self.assertRaisesRegex(h.Failure,'심볼릭 링크'): h.backup_host(host,destination)
        self.assertFalse(destination.exists()); host.runner.run.assert_not_called()

    def keyless_host(self):
        env=self.prefix/'tracker/.env'
        env.write_text('\n'.join(line for line in env.read_text().splitlines() if not line.startswith('TRACKER_DATA_UPDATE_VERIFY_KEY_FILE='))+'\n')
        (self.prefix/'config/data.pub').unlink()
        runner=FixtureRunner(self.prefix)
        api=next(c for c in runner.containers if c['Id']=='id-portal-api')
        api['Mounts']=[m for m in api['Mounts'] if m.get('Destination')!='/run/secrets/tracker-data-update-verify.pub']
        return env,runner

    def test_legacy_token_only_install_needs_no_data_key(self):
        env,runner=self.keyless_host();before=env.read_bytes()
        host=h.Host(self.prefix,env,runner)
        self.assertNotIn('TRACKER_DATA_UPDATE_VERIFY_KEY_FILE',host.paths)
        self.assertNotIn('TRACKER_DATA_UPDATE_VERIFY_KEY_FILE',host.critical)
        self.assertEqual(env.read_bytes(),before)
        self.assertEqual(host.paths['KODA_TRACKER_PROVISIONING_TOKEN_FILE'],(self.prefix/'config/provision.token').resolve())
        self.assertFalse(any(call[:2] in [['docker','stop'],['docker','start']] for call in runner.calls))

    def test_keyless_install_cannot_discard_active_unrecorded_data_key(self):
        env,runner=self.keyless_host()
        api=next(c for c in runner.containers if c['Id']=='id-portal-api')
        api['Mounts'].append({'Type':'bind','Source':str(self.root/'existing-approved.pub'),'Destination':'/run/secrets/tracker-data-update-verify.pub','RW':False})
        with self.assertRaisesRegex(h.Failure,'기존 키를 보존'):h.Host(self.prefix,env,runner)

    def test_keyless_mode_keeps_provisioning_token_mandatory(self):
        env,runner=self.keyless_host()
        env.write_text('\n'.join(line for line in env.read_text().splitlines() if not line.startswith('KODA_TRACKER_PROVISIONING_TOKEN_FILE='))+'\n')
        with self.assertRaisesRegex(h.Failure,'KODA_TRACKER_PROVISIONING_TOKEN_FILE'):h.Host(self.prefix,env,runner)

    def test_configured_data_key_still_must_exist(self):
        env=self.prefix/'tracker/.env';(self.prefix/'config/data.pub').unlink()
        with self.assertRaisesRegex(h.Failure,'설정 경로'):h.Host(self.prefix,env,FixtureRunner(self.prefix))

    def test_optional_key_override_only_when_registered(self):
        override=self.prefix/'tracker/compose.data-key.yaml';override.write_text('services: {}\n')
        env,runner=self.keyless_host();host=h.Host(self.prefix,env,runner)
        self.assertNotIn(override.resolve(),host.compose)
        (self.prefix/'config/data.pub').write_text('fixture-public-key')
        env.write_text(env.read_text()+"TRACKER_DATA_UPDATE_VERIFY_KEY_FILE='../config/data.pub'\n")
        runner=FixtureRunner(self.prefix);host=h.Host(self.prefix,env,runner)
        self.assertIn(override.resolve(),host.compose)

    def test_keyless_host_preserves_ldap_database_gateway_and_token_settings(self):
        env,runner=self.keyless_host();env.write_text(env.read_text()+"TRACKER_LDAP_ENCRYPTION_KEY=fixture-encryption-key\nTRACKER_DB_PASSWORD=fixture-db-secret\n")
        host=h.Host(self.prefix,env,runner);before=env.read_bytes();host.check_preserved()
        self.assertEqual(env.read_bytes(),before)
        self.assertEqual(host.env['TRACKER_LDAP_ENCRYPTION_KEY'],'fixture-encryption-key')
        self.assertEqual(host.env['TRACKER_DB_PASSWORD'],'fixture-db-secret')

    def test_keyless_host_still_uses_automatic_bundled_release_public_key(self):
        env,runner=self.keyless_host();host=h.Host(self.prefix,env,runner);host.runner=h.Runner()
        signed=self.signed_release();bundled=self.root/'handover-bundle';bundled.mkdir()
        (bundled/'release-public.pem').write_bytes(signed.release_public_key.read_bytes())
        with mock.patch.object(h,'HERE',bundled):
            args=h.parser().parse_args(['check','--archive',str(signed.archive)])
        self.assertEqual(args.release_public_key,bundled/'release-public.pem')
        with h.release(args,host) as (suite,release_env):
            self.assertTrue(suite.is_file());self.assertEqual(release_env['KODA_ALLOW_UNSIGNED_ARTIFACTS'],'0')
        self.assertNotIn('TRACKER_DATA_UPDATE_VERIFY_KEY_FILE',host.paths)

    def test_action_wrappers_accept_posix_sh_without_manual_key_options(self):
        for action in ['check','update','status','backup','verify-backup','restore-config','rollback','patch']:
            result=subprocess.run(['sh',str(ROOT/(action+'.sh')),'--help'],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertNotIn('Illegal option',result.stderr)

if __name__=='__main__': unittest.main()
