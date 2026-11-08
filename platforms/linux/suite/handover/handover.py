#!/usr/bin/env python3
"""Offline handover entry point. Reads the target host; ships no operator settings."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile

DEFAULT_PREFIX = Path('/home/user0/koda-suite')
HERE = Path(__file__).resolve().parent
PREFIXES = ('KODA_', 'TRACKER_', 'PORTAL_', 'COMPOSE_')
MANAGED_PREFIXES = PREFIXES+('PUBLIC_HTTP_', 'GATEWAY_', 'APP_NETWORK_', 'VULN_DATA_', 'POSTGRES_', 'GRYPE_', 'DATA_UPDATES_', 'ARTIFACT_', 'BACKUP_')
HOST_ENV_KEYS = {'PATH','HOME','DOCKER_HOST','DOCKER_CONTEXT','DOCKER_CONFIG','TZ','SSH_AUTH_SOCK','PYTHONDONTWRITEBYTECODE'}
IMAGE_KEYS = {'PORTAL_IMAGE_TAG', 'PORTAL_WEB_IMAGE', 'PORTAL_API_IMAGE', 'PORTAL_WORKER_IMAGE'}
PATH_KEYS = ('TRACKER_DATA_UPDATE_VERIFY_KEY_FILE', 'KODA_TRACKER_PROVISIONING_TOKEN_FILE', 'KODA_TRACKER_TOKEN_DIR', 'KODA_GITLAB_TOKEN_FILE', 'KODA_GITLAB_WRITE_TOKEN_FILE', 'KODA_GITLAB_CA_FILE', 'KODA_TRACKER_CA_FILE', 'KODA_SCHEDULE_SSH_DIR', 'KODA_SCHEDULE_STATE_DIR')
REQUIRED_PATHS = {'KODA_TRACKER_PROVISIONING_TOKEN_FILE', 'KODA_TRACKER_TOKEN_DIR'}
VOLUMES = ('tracker-artifacts', 'vuln-data', 'data-updates')

class Failure(RuntimeError):
    pass

def digest(path):
    checksum=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):
            checksum.update(chunk)
    return checksum.hexdigest()

def private_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())

class Runner:
    def run(self, args, *, env=None, output=None, stdin=None, check=True):
        # Tool output can contain local settings: capture it, never echo it.
        result = subprocess.run(list(map(str, args)), env=env, stdout=output or subprocess.PIPE,
                                stderr=subprocess.PIPE, stdin=stdin, check=False)
        if check and result.returncode:
            raise Failure(f'{Path(str(args[0])).name} 작업 실패 (종료 {result.returncode}); 운영 설정 값은 출력하지 않습니다.')
        return result

def managed_environment_names(prefix):
    names=set()
    for path in [prefix/'tracker/.env.example',prefix/'tracker/config/.env.example',prefix/'config/koda-suite.env.example']:
        if path.is_file():
            names.update(re.findall(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=',path.read_text(),re.M))
    return names

def source_environment(path, runner, ambient=None, managed_names=()):
    text = path.read_text()
    keys = re.findall(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=', text, re.M)
    if len(keys) != len(set(keys)):
        raise Failure('운영 env에 중복 설정이 있습니다. 변경 전에 정리하세요.')
    clean = {key: value for key, value in (os.environ if ambient is None else ambient).items()
             if key in HOST_ENV_KEYS or (not key.startswith(MANAGED_PREFIXES) and key not in keys and key not in managed_names)}
    script = 'set -e; set -a; source "$1" >/dev/null; exec python3 -c "import os,sys; sys.stdout.buffer.write(b\\\"\\\\0\\\".join((k+\\\"=\\\"+v).encode() for k,v in os.environ.items()))"'
    result = runner.run(['bash', '-c', script, 'handover-env', path], env=clean)
    values = dict(part.decode().split('=', 1) for part in result.stdout.split(b'\0') if part)
    return values, set(keys)

def fingerprint(container):
    return {'id': container['Id'], 'name': container['Name'].lstrip('/'), 'image': container['Image'],
            'running': bool(container['State']['Running']), 'mounts': container.get('Mounts', [])}

class Host:
    def __init__(self, prefix, env_file, runner, *, allow_stopped=False):
        self.prefix, self.env_file, self.runner = Path(prefix).resolve(strict=True), Path(env_file).resolve(strict=True), runner
        self.tracker = self.prefix / 'tracker'
        canonical=(self.tracker/'.env').resolve(strict=True)
        if not self.env_file.samefile(canonical):
            raise Failure('--env-file은 기존 <prefix>/tracker/.env와 동일한 파일이어야 합니다. 다른 LDAP/DB 비밀 설정으로 대체하지 않습니다.')
        self.env_file=canonical
        for path in [self.prefix/'metadata.env', self.prefix/'koda-suite', self.tracker/'.env', self.env_file,
                     self.prefix/'koda/koda-docker', self.prefix/'koda/image-ref.txt',
                     *[self.tracker/name for name in ('compose.yaml','compose.airgap.yaml','compose.integration.yaml')]]:
            if not path.is_file() or path.is_symlink():
                raise Failure(f'기존 설치 파일을 확인할 수 없습니다: {path}')
        if not (self.prefix/'data/koda-portal').is_dir():
            raise Failure('기존 KODA data/koda-portal 경로가 없습니다. 새 설치로 처리하지 않습니다.')
        self.managed_names=managed_environment_names(self.prefix)
        self.env, self.keys = source_environment(self.env_file, runner, managed_names=self.managed_names)
        self.paths = {}
        for key in PATH_KEYS:
            value = self.env.get(key, '')
            if not value:
                if key in REQUIRED_PATHS: raise Failure(f'기존 운영 설정이 필요합니다: {key}')
                continue
            path = Path(value)
            if not path.is_absolute(): path = self.env_file.parent/path
            if not path.exists(): raise Failure(f'설정 경로가 없습니다: {key}')
            self.paths[key] = path.resolve()
            self.env[key] = str(path.resolve())
        if not self.env.get('KODA_GATEWAY_PROOF'):
            raise Failure('기존 KODA_GATEWAY_PROOF가 없습니다. 임의 생성하지 않습니다.')
        self.compose = ['docker','compose','--project-directory',self.tracker,'--env-file',self.env_file]
        for name in ('compose.yaml','compose.airgap.yaml','compose.integration.yaml'): self.compose += ['-f',self.tracker/name]
        if 'TRACKER_DATA_UPDATE_VERIFY_KEY_FILE' in self.paths and (self.tracker/'compose.data-key.yaml').is_file():
            self.compose += ['-f',self.tracker/'compose.data-key.yaml']
        self.config = self.json(self.compose+['config','--format','json'])
        self.project = self.config.get('name')
        if not self.project: raise Failure('기존 Compose project를 확정할 수 없습니다.')
        self.volumes = {key:self.config['volumes'][key]['name'] for key in (*VOLUMES,'postgres-data')}
        self.api_image = self.config['services']['portal-api']['image']
        runner.run(['docker','image','inspect',self.api_image], env=self.env)
        self.containers = self.inventory()
        postgres = [item for item in self.containers if (item.get('Config',{}).get('Labels') or {}).get('com.docker.compose.service')=='postgres']
        if len(postgres)!=1 or (not allow_stopped and not postgres[0]['State']['Running']):
            raise Failure('실행 중인 해당 Suite PostgreSQL을 하나로 확인할 수 없습니다. 자동 기동하지 않습니다.')
        self.postgres = postgres[0]['Id']
        self.original = [fingerprint(item) for item in self.containers]
        self.critical = self.critical_hashes()

    def json(self, command):
        return json.loads(self.runner.run(command, env=self.env).stdout)

    def inventory(self):
        ids = self.runner.run(['docker','ps','-aq'], env=self.env).stdout.decode().split()
        all_containers = self.json(['docker','inspect',*ids]) if ids else []
        selected=[]
        koda_names={'koda-dashboard','koda-scan-worker','koda-delivery-worker'}
        koda_image=(self.prefix/'koda/image-ref.txt').read_text().strip()
        for item in all_containers:
            labels=item.get('Config',{}).get('Labels') or {}
            name=item['Name'].lstrip('/')
            working_dir=labels.get('com.docker.compose.project.working_dir','')
            owned=labels.get('com.docker.compose.project')==self.project and bool(working_dir) and Path(working_dir).resolve()==self.tracker.resolve()
            if name in koda_names:
                owned=any(m.get('Type')=='bind' and Path(m['Source']).resolve()==(self.prefix/'data/koda-portal').resolve() for m in item.get('Mounts',[]))
                if not owned or item['Config']['Image']!=koda_image:
                    raise Failure(f'다른 설치의 고정 이름 컨테이너와 충돌합니다: {name}')
                identity=item['Config'].get('User','')
                if identity!=f'{os.getuid()}:{os.getgid()}':
                    match=re.fullmatch(r'(\d+):(\d+)',identity)
                    instruction='기존 설치 계정'
                    if match:
                        try: instruction=pwd.getpwuid(int(match[1])).pw_name+' 계정'
                        except KeyError: instruction='UID:GID '+identity+' 설치 계정'
                    raise Failure(f'실행 계정이 기존 KODA UID:GID와 다릅니다. {instruction}으로 다시 실행하세요. 임의 sudo/root 전환·chown은 하지 않습니다.')
            touches=any((m.get('Type')=='volume' and m.get('Name') in self.volumes.values()) or
                        (m.get('Type')=='bind' and Path(m['Source']).resolve()==(self.prefix/'data/koda-portal').resolve())
                        for m in item.get('Mounts',[]) if m.get('RW'))
            if touches and not owned: raise Failure('다른 컨테이너가 대상 데이터를 쓰고 있습니다. 소유권을 확인하세요.')
            if owned: selected.append(item)
        services={(c.get('Config',{}).get('Labels') or {}).get('com.docker.compose.service') for c in selected}
        if not {'postgres','portal-api','portal-worker'}.issubset(services):
            raise Failure('기존 Suite 핵심 컨테이너 소유권을 확정할 수 없습니다.')
        if not any(c['Name'].lstrip('/')=='koda-dashboard' for c in selected):
            raise Failure('기존 KODA 실행 계정을 확인할 dashboard 컨테이너가 없습니다.')
        owner=(self.prefix/'data/koda-portal').stat()
        if (owner.st_uid,owner.st_gid)!=(os.getuid(),os.getgid()):
            raise Failure('KODA data 소유 UID:GID가 현재 설치 계정과 다릅니다. 기존 소유 계정으로 실행하세요.')
        for key,name in self.volumes.items():
            attached={mount.get('Name') for container in selected for mount in container.get('Mounts',[])
                      if mount.get('Type')=='volume' and mount.get('Name')==name}
            if attached!={name}: raise Failure(f'기존 컨테이너에 설정 볼륨이 연결되어 있지 않습니다: {key}')
        api=next(c for c in selected if (c.get('Config',{}).get('Labels') or {}).get('com.docker.compose.service')=='portal-api')
        for key,target in [('TRACKER_DATA_UPDATE_VERIFY_KEY_FILE','/run/secrets/tracker-data-update-verify.pub'),('KODA_TRACKER_PROVISIONING_TOKEN_FILE','/run/secrets/koda-tracker-provisioning')]:
            bound=[Path(m['Source']).resolve() for m in api.get('Mounts',[]) if m.get('Destination')==target and m.get('Type')=='bind']
            if key not in self.paths:
                if bound: raise Failure(f'실행 중인 키 등록이 env에 없습니다. 기존 키를 보존하도록 설정을 확인하세요: {key}')
                continue
            if bound!=[self.paths[key]]: raise Failure(f'실행 중인 등록 경로와 env가 다릅니다: {key}')
        for key,name in self.volumes.items(): self.runner.run(['docker','volume','inspect',name], env=self.env)
        return selected

    def critical_hashes(self):
        result={}
        for key,path in self.paths.items():
            if key=='KODA_SCHEDULE_STATE_DIR': continue
            candidates=[path] if path.is_file() else sorted(path.rglob('*'))
            result[key]={str(file):digest(file) for file in candidates if file.is_file()}
        return result

    def resume(self, ids):
        resumed=[]
        before={c['id']:c for c in self.original}
        for identity in ids:
            result=self.runner.run(['docker','inspect',identity],env=self.env,check=False)
            if result.returncode: continue
            current=fingerprint(json.loads(result.stdout)[0]); old=before[identity]
            if current['image']!=old['image'] or current['mounts']!=old['mounts']: continue
            if not current['running']:
                if not self.runner.run(['docker','start',identity],env=self.env,check=False).returncode: resumed.append(identity)
        return resumed

    def volume_command(self, volume, *, size=False, cache=False):
        command=['docker','run','--rm','--pull','never','--network','none','--read-only','--cap-drop','ALL','--cap-add','DAC_READ_SEARCH',
                 '--security-opt','no-new-privileges','--user','0:0','--mount',f'type=volume,src={volume},dst=/snapshot,readonly',
                 '--entrypoint','python',self.api_image,'-c']
        if size: return command+['import os; from pathlib import Path; print(sum(p.lstat().st_size for p in Path("/snapshot").rglob("*")))']
        script='import sys,tarfile; from pathlib import Path; a=tarfile.open(fileobj=sys.stdout.buffer,mode="w|gz",dereference=False); '
        script+='[a.add(p,arcname="./"+p.name) for p in sorted(Path("/snapshot").iterdir())'+(' if p.name!=".nvd-cache"' if cache else '')+']; a.close()'
        return command+[script]

    def check_preserved(self):
        after,keys=source_environment(self.tracker/'.env',self.runner,managed_names=self.managed_names)
        for key in self.keys-IMAGE_KEYS:
            if key in self.paths:
                value=Path(after.get(key,''))
                if not value.is_absolute(): value=self.tracker/value
                if value.resolve()!=self.paths[key]: raise Failure(f'운영 경로 보존 검사 실패: {key}')
            elif after.get(key)!=self.env.get(key): raise Failure(f'운영 설정 보존 검사 실패: {key}')
        current=self.critical_hashes()
        if any(current.get(key,{}).get(path)!=checksum for key,files in self.critical.items() for path,checksum in files.items()):
            raise Failure('등록 키·토큰 파일 보존 검사 실패')

class RecoveryHost:
    """Recover files using the verified checkpoint, even if current env is lost."""
    def __init__(self,prefix,folder,runner):
        checkpoint=verify_backup(folder)
        self.prefix=Path(prefix).resolve(strict=True); self.runner=runner
        if checkpoint['prefix']!=str(self.prefix): raise Failure('백업 prefix가 현재 대상과 다릅니다.')
        if (checkpoint.get('operatorUid'),checkpoint.get('operatorGid'))!=(os.getuid(),os.getgid()):
            raise Failure('백업을 만든 기존 설치 UID:GID 계정으로 복원하세요.')
        owner=(self.prefix/'data/koda-portal').stat()
        if (owner.st_uid,owner.st_gid)!=(os.getuid(),os.getgid()): raise Failure('기존 KODA data 소유 계정으로 복원하세요.')
        self.env={key:value for key,value in os.environ.items() if not key.startswith(MANAGED_PREFIXES)}
        self.project=checkpoint['project']; self.volumes=checkpoint['volumes']
        self.inventory()

    def inventory(self):
        ids=self.runner.run(['docker','ps','-aq'],env=self.env).stdout.decode().split()
        containers=json.loads(self.runner.run(['docker','inspect',*ids],env=self.env).stdout) if ids else []
        selected=[]
        for item in containers:
            labels=item.get('Config',{}).get('Labels') or {}; name=item['Name'].lstrip('/')
            owned=labels.get('com.docker.compose.project')==self.project and Path(labels.get('com.docker.compose.project.working_dir','/')).resolve()==self.prefix/'tracker'
            if name in {'koda-dashboard','koda-scan-worker','koda-delivery-worker'}:
                owned=any(m.get('Type')=='bind' and Path(m['Source']).resolve()==self.prefix/'data/koda-portal' for m in item.get('Mounts',[]))
                if not owned: raise Failure('다른 설치 KODA 고정 이름과 충돌합니다.')
                if item['Config'].get('User')!=f'{os.getuid()}:{os.getgid()}': raise Failure('현재 KODA 실행 UID:GID와 복원 계정이 다릅니다.')
            touches=any(m.get('RW') and m.get('Type')=='volume' and m.get('Name') in self.volumes.values() for m in item.get('Mounts',[]))
            if touches and not owned: raise Failure('다른 컨테이너가 복원 대상 데이터를 쓰고 있습니다.')
            if owned: selected.append(item)
        return selected

@contextmanager
def operation_lock(host):
    with (host.prefix/'.handover-operation.lock').open('a') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc: raise Failure('다른 Suite 작업이 진행 중입니다.') from exc
        yield

def backup_host(host, root, *, hold=False):
    root=Path(root).resolve()
    sources={host.prefix,*[path for path in host.paths.values() if path.is_dir()]}
    if any(root==source or source in root.parents for source in sources):
        raise Failure('백업은 설치 경로와 백업에 포함되는 외부 설정 디렉터리 밖에 보관하세요.')
    # tar's safe restoration filter cannot recreate absolute/outside links.
    # Refuse them before stopping writers or creating an unusable checkpoint.
    for source in sources:
        for path in source.rglob('*'):
            if path.is_symlink():
                target=Path(os.readlink(path))
                resolved=(path.parent/target).resolve()
                if target.is_absolute() or not (resolved==source or source in resolved.parents):
                    raise Failure('백업 복원이 지원되지 않는 절대/외부 심볼릭 링크가 있습니다. 실제 파일 또는 스냅샷 내부 상대 링크로 정리한 후 재시도하세요.')
    root.mkdir(parents=True,exist_ok=True,mode=0o700); root.chmod(0o700)
    folder=root/(dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+os.urandom(3).hex())
    folder.mkdir(mode=0o700)
    checkpoint={'format':'koda-private-local-checkpoint-v1','prefix':str(host.prefix),'envFile':str(host.env_file),
                'project':host.project,'volumes':host.volumes,'containers':host.original,'phase':'preparing',
                'backupTrust':'private local SHA-256 integrity; not a release signature',
                'externalPaths':[],'operatorUid':os.getuid(),'operatorGid':os.getgid(),
                'configPaths':sorted({str(host.env_file),*[str(path) for key,path in host.paths.items() if key!='KODA_SCHEDULE_STATE_DIR']}),
                'createdAt':dt.datetime.now(dt.timezone.utc).isoformat()}
    private_json(folder/'checkpoint.json',checkpoint)
    stopped=[]
    try:
        estimated=sum(int(host.runner.run(host.volume_command(name,size=True),env=host.env).stdout.split()[0]) for key,name in host.volumes.items() if key in VOLUMES)
        estimated+=sum(file.stat().st_size for file in host.prefix.rglob('*') if file.is_file() and not file.is_symlink())
        if shutil.disk_usage(root).free<estimated+1024**3: raise Failure('비공개 전체 백업을 위한 디스크 여유가 부족합니다.')
        for container in host.original:
            if container['running'] and container['id']!=host.postgres:
                stopped.append(container['id'])
                host.runner.run(['docker','stop','--time','120',container['id']],env=host.env)
        checkpoint['phase']='writers-stopped'; private_json(folder/'checkpoint.json',checkpoint)
        for file in (host.prefix/'data/koda-portal').rglob('*'):
            if file.is_file() and file.suffix in {'.db','.sqlite','.sqlite3'}:
                with file.open('rb') as stream: is_sqlite=stream.read(16)==b'SQLite format 3\0'
                if is_sqlite:
                    with sqlite3.connect(file.as_uri()+'?mode=ro',uri=True) as connection:
                        if connection.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise Failure('기존 KODA SQLite 무결성 검사 실패')
        database=host.env.get('TRACKER_DB_NAME'); username=host.env.get('POSTGRES_SUPERUSER')
        if not database or not username: raise Failure('기존 Tracker DB 이름·백업 사용자 설정이 없습니다.')
        with (folder/'tracker.dump').open('xb') as output:
            os.fchmod(output.fileno(),0o600)
            host.runner.run(['docker','exec',host.postgres,'pg_dump','-Fc',f'--username={username}',f'--dbname={database}'],env=host.env,output=output)
        with (folder/'tracker.dump').open('rb') as source:
            host.runner.run(['docker','exec','-i',host.postgres,'pg_restore','--list'],env=host.env,stdin=source)
        # Writers are stopped; preserve WAL companions and inputs together.
        with tarfile.open(folder/'installed-prefix.tar.gz','w:gz',dereference=False) as archive:
            for path in sorted(host.prefix.iterdir()):
                if path.name not in {'.koda-suite-operation.lock','.handover-operation.lock'}: archive.add(path,arcname=path.name)
        externals={path for path in host.paths.values() if host.prefix not in path.parents and path!=host.prefix}
        if host.env_file!=host.tracker/'.env': externals.add(host.env_file)
        for index,path in enumerate(sorted(externals)):
            name=f'external-{index}.tar.gz'
            with tarfile.open(folder/name,'w:gz',dereference=False) as archive: archive.add(path,arcname='payload')
            restore_config=path==host.env_file or any(value==path for key,value in host.paths.items() if key!='KODA_SCHEDULE_STATE_DIR')
            checkpoint['externalPaths'].append({'target':str(path),'archive':name,'restoreConfig':restore_config})
        for key in VOLUMES:
            with (folder/(key+'.tar.gz')).open('xb') as output:
                os.fchmod(output.fileno(),0o600)
                host.runner.run(host.volume_command(host.volumes[key],cache=key=='tracker-artifacts'),env=host.env,output=output)
        checkpoint.update(phase='complete',databaseName=database,databaseUser=username,
                          stopped=stopped,criticalHashes=host.critical)
        private_json(folder/'checkpoint.json',checkpoint)
        for file in folder.iterdir(): file.chmod(0o600)
        (folder/'manifest.sha256').write_text(''.join(f'{digest(file)}  {file.name}\n' for file in sorted(folder.iterdir()) if file.is_file()))
        (folder/'manifest.sha256').chmod(0o600)
        verify_backup(folder)
    except BaseException:
        host.resume(stopped)
        raise
    if not hold: host.resume(stopped)
    return folder,stopped

def verify_backup(folder):
    folder=Path(folder).absolute()
    if folder.is_symlink() or stat.S_IMODE(folder.stat().st_mode)&0o077: raise Failure('백업 디렉터리는 비공개 0700이어야 합니다.')
    expected=set()
    for line in (folder/'manifest.sha256').read_text().splitlines():
        match=re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9._-]+)',line)
        if not match: raise Failure('백업 manifest 경로가 올바르지 않습니다.')
        checksum,name=match.groups(); path=folder/name
        if name in expected or path.is_symlink() or not path.is_file() or digest(path)!=checksum: raise Failure('백업 무결성 검사 실패')
        if stat.S_IMODE(path.stat().st_mode)&0o077: raise Failure('백업 파일 권한은 0600이어야 합니다.')
        expected.add(name)
    if expected!={p.name for p in folder.iterdir() if p.name!='manifest.sha256'}: raise Failure('백업 파일 목록이 manifest와 다릅니다.')
    checkpoint=json.loads((folder/'checkpoint.json').read_text())
    if checkpoint.get('phase')!='complete' or checkpoint.get('format')!='koda-private-local-checkpoint-v1': raise Failure('완료된 백업 체크포인트가 아닙니다.')
    return checkpoint

@contextmanager
def release(args, host):
    candidates=[Path(args.archive).absolute()] if args.archive else sorted(HERE.glob('koda-suite-offline-*.tar.gz'))
    if len(candidates)!=1: raise Failure('Suite 압축파일을 하나로 확정할 수 없습니다. --archive를 지정하세요.')
    archive=candidates[0]; key=Path(args.release_public_key).absolute()
    sidecar=archive.with_name(archive.name+'.sha256')
    lines=sidecar.read_text().splitlines()
    if len(lines)!=1 or not re.fullmatch(r'[0-9a-fA-F]{64} [ *]'+re.escape(archive.name),lines[0]): raise Failure('Suite SHA-256 sidecar가 올바르지 않습니다.')
    if digest(archive)!=lines[0][:64].lower(): raise Failure('Suite SHA-256이 다릅니다.')
    env=host.env|{'KODA_RELEASE_VERIFY_KEY':str(key),'KODA_ALLOW_UNSIGNED_ARTIFACTS':'0'}
    host.runner.run(['openssl','dgst','-sha256','-verify',key,'-signature',str(archive)+'.sig',archive],env=env)
    with tempfile.TemporaryDirectory(prefix='koda-signed-handover-') as temporary:
        stage=Path(temporary)
        with tarfile.open(archive,'r:gz') as packed: packed.extractall(stage,filter='data')
        candidates=[path for path in [stage/'koda-suite',*stage.glob('*/koda-suite')] if path.is_file()]
        if len(candidates)!=1: raise Failure('검증한 Suite 진입점이 하나가 아닙니다.')
        suite=candidates[0]
        # Main7347 preflight calls prepare_payloads -> verify_release, including
        # every inner manifest. A separate verify command repeats that full pass.
        host.runner.run(['bash',suite,'preflight','--prefix',host.prefix,'--env-file',host.env_file],env=env)
        yield suite,env

def restore_files(host, folder, *, runtime=False, apply=False):
    checkpoint=verify_backup(folder)
    if checkpoint['prefix']!=str(host.prefix): raise Failure('백업 prefix가 현재 대상과 다릅니다.')
    if not apply:
        print('검증 완료. 원래 환경/등록 키·토큰'+(' 및 이전 실행 파일' if runtime else '')+' 복원 계획입니다. DB·볼륨은 덮어쓰지 않습니다.')
        print('실행하려면 모든 해당 Suite 컨테이너를 정지한 뒤 --apply --confirm-prefix '+str(host.prefix)+'를 지정하세요.')
        return
    if any(c['State']['Running'] for c in host.inventory()): raise Failure('파일 복원 전에 해당 Suite 전체를 정지해야 합니다.')
    with tempfile.TemporaryDirectory(prefix='koda-restore-files-') as temporary:
        staged=Path(temporary)
        with tarfile.open(Path(folder)/'installed-prefix.tar.gz','r:gz') as archive: archive.extractall(staged,filter='data')
        paths=[p for p in staged.iterdir() if p.name!='data'] if runtime else [staged/'tracker/.env',staged/'config']
        if not runtime:
            for value in checkpoint.get('configPaths',[]):
                path=Path(value)
                if host.prefix in path.parents:
                    candidate=staged/path.relative_to(host.prefix)
                    if not any(parent==candidate or parent in candidate.parents for parent in paths): paths.append(candidate)
        for source in paths:
            if not source.exists(): continue
            relative=source.relative_to(staged); target=host.prefix/relative
            if source.is_dir(): shutil.copytree(source,target,dirs_exist_ok=True,copy_function=shutil.copy2)
            else: target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(source,target)
        for item in checkpoint['externalPaths']:
            if not item.get('restoreConfig',True): continue
            area=staged/('external-'+str(len(list(staged.glob('external-*'))))); area.mkdir()
            with tarfile.open(Path(folder)/item['archive'],'r:gz') as archive: archive.extractall(area,filter='data')
            source=area/'payload'; target=Path(item['target'])
            if source.is_dir(): shutil.copytree(source,target,dirs_exist_ok=True,copy_function=shutil.copy2)
            else: target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(source,target)
    print('파일 복원 완료. DB·볼륨은 변경하지 않았습니다. 이전 이미지와 DB 호환성을 검토한 후 기존 koda-suite start를 실행하세요.')

def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['update','check','status','backup','verify-backup','restore-config','rollback','patch'])
    p.add_argument('--prefix',type=Path,default=DEFAULT_PREFIX)
    p.add_argument('--env-file',type=Path)
    p.add_argument('--archive',type=Path)
    p.add_argument('--release-public-key',type=Path,default=HERE/'release-public.pem')
    p.add_argument('--backup-root',type=Path)
    p.add_argument('--backup',type=Path)
    p.add_argument('--check',action='store_true',help='update/patch의 변경 없는 사전 검사; 다른 작업에는 사용할 수 없음')
    p.add_argument('--apply',action='store_true')
    p.add_argument('--confirm-prefix',type=Path)
    p.add_argument('--group',choices=['koda','gateway','portal-web','portal-api-worker'])
    return p

def main(argv=None,runner=None):
    args=parser().parse_args(argv); runner=runner or Runner()
    try:
        if args.check and args.action not in {'check','update','patch'}:
            raise Failure('--check는 update/check/patch에서만 사용할 수 있습니다. 백업/복원 작업은 실행하지 않았습니다.')
        if not hasattr(tarfile,'data_filter'):
            raise Failure('안전한 TAR data_filter 기능이 있는 Python이 필요합니다. Python 3.10.12 이상 보안 패치 버전을 사용하세요. 필터 없이 진행하지 않습니다.')
        if args.action=='verify-backup':
            if not args.backup: raise Failure('--backup DIR이 필요합니다.')
            verify_backup(args.backup); print('비공개 로컬 백업 무결성 확인 완료'); return 0
        if sys.platform!='linux': raise Failure('이 도구는 대상 Linux 서버에서 실행하세요.')
        if args.action in {'restore-config','rollback'}:
            if not args.backup: raise Failure('--backup DIR이 필요합니다.')
            host=RecoveryHost(args.prefix,args.backup,runner)
        else:
            host=Host(args.prefix,args.env_file or args.prefix/'tracker/.env',runner)
        if args.action=='status':
            runner.run(['bash',host.prefix/'koda-suite','status','--prefix',host.prefix],env=host.env)
            print('설치된 Suite 상태·health 확인 완료'); return 0
        if args.action in {'restore-config','rollback'}:
            if not args.backup: raise Failure('--backup DIR이 필요합니다.')
            if args.apply and (args.confirm_prefix is None or args.confirm_prefix.resolve()!=host.prefix): raise Failure('--confirm-prefix가 실제 대상과 같아야 합니다.')
            with operation_lock(host): restore_files(host,args.backup,runtime=args.action=='rollback',apply=args.apply)
            return 0
        if args.action=='backup':
            with operation_lock(host): folder,_=backup_host(host,args.backup_root or args.prefix.parent/(args.prefix.name+'-backups'))
            print('비공개 백업 완료: '+str(folder)); return 0
        with release(args,host) as (suite,env):
            if args.action=='check' or args.check:
                print('서명·무결성·기존 설정·Suite preflight 확인 완료; 서비스/이미지/설치 파일 변경 없음'); return 0
            if args.action=='patch' and not args.group: raise Failure('patch에는 --group이 필요합니다.')
            with operation_lock(host):
                folder,stopped=backup_host(host,args.backup_root or args.prefix.parent/(args.prefix.name+'-backups'),hold=args.action!='patch')
                print('검증한 비공개 백업: '+str(folder),flush=True)
                try:
                    command=['bash',suite,'patch','--group',args.group,'--prefix',host.prefix] if args.action=='patch' else ['bash',suite,'install','--prefix',host.prefix,'--env-file',host.env_file]
                    runner.run(command,env=env)
                    host.check_preserved()
                    runner.run(['bash',host.prefix/'koda-suite','status','--prefix',host.prefix],env=host.env)
                    private_json(folder.parent/(folder.name+'-update-result.json'),{'state':'completed','action':args.action,'suiteSha256':digest(Path(args.archive)) if args.archive else digest(next(HERE.glob('koda-suite-offline-*.tar.gz'))),'dataRestorePerformed':False})
                except BaseException:
                    resumed=host.resume(stopped)
                    private_json(folder.parent/(folder.name+'-update-result.json'),{'state':'failed','action':args.action,'oldContainersRestarted':len(resumed),'automaticDatabaseRestore':False,'backup':str(folder)})
                    print('갱신 중단. 동일 ID의 기존 컨테이너만 재기동을 시도했습니다. 교체된 컨테이너/DB/볼륨은 자동 복원하지 않습니다. 백업: '+str(folder),file=sys.stderr)
                    raise
        print('기존 설정·키 보존 및 Suite health 확인 완료'); return 0
    except (Failure,OSError,ValueError,tarfile.TarError,sqlite3.Error) as error:
        if isinstance(error,Failure): print('오류: '+str(error),file=sys.stderr)
        else: print('오류: 파일/검증 작업 실패 ('+type(error).__name__+'). 비밀 설정 값은 출력하지 않습니다.',file=sys.stderr)
        return 2

if __name__=='__main__': raise SystemExit(main())
