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
