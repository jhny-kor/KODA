import hashlib
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class LinuxSuiteContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.launcher = (ROOT / "platforms/linux/suite/koda-suite").read_text()
        cls.reset_installer = (ROOT / "platforms/linux/suite/reset-install.sh").read_text()
        cls.docker_wrapper = (ROOT / "platforms/linux/docker/koda-docker.sh").read_text()
        cls.compose = (ROOT / "platforms/linux/suite/compose.integration.yaml").read_text()
        cls.gateway = (ROOT / "platforms/linux/suite/gateway.conf.template").read_text()
        cls.suite_env = (ROOT / "platforms/linux/suite/koda-suite.env.example").read_text()

    def test_all_three_products_are_routed_and_health_checked(self) -> None:
        self.assertIn('/koda/live', self.launcher)
        self.assertIn('/api/v1/healthz', self.launcher)
        self.assertIn('/dependency-track/api/version', self.launcher)
        self.assertIn('/dependency-track/static/config.json', self.launcher)
        self.assertIn('location ^~ /koda/', self.gateway)
        self.assertIn('location /api/', self.gateway)
        self.assertIn('location /dependency-track/', self.gateway)
        self.assertIn('location = /dependency-track/static/config.json', self.gateway)
        self.assertIn('add_header Cache-Control "no-store" always;', self.gateway)
        self.assertIn('proxy_pass http://${DTRACK_FRONTEND_UPSTREAM}/;', self.gateway)
        self.assertNotIn('proxy_pass http://${DTRACK_FRONTEND_UPSTREAM}${DTRACK_BASE_PATH}/;', self.gateway)

    def test_env_parser_is_quiet_on_linux_awk(self) -> None:
        self.assertIn('value="$(awk -F= -v key="$key"', self.launcher)
        self.assertNotIn('\\047\\"', self.launcher)

    def test_lifecycle_uses_one_integrated_offline_compose_contract(self) -> None:
        self.assertIn('suite_compose "$prefix" up -d --no-build --pull never', self.launcher)

    def test_tracker_transfer_uses_gateway_only_koda_network(self) -> None:
        self.assertIn("KODA_TRACKER_URL=http://koda-sbom-gateway:8080", self.suite_env)
        self.assertIn("KODA_TRACKER_PROVISIONING_TOKEN_FILE=", self.suite_env)
        self.assertIn("TRACKER_KODA_PROVISIONING_TOKEN_FILE", self.compose)
        self.assertIn("ensure_tracker_integration_secrets", self.launcher)
        self.assertIn("os.chmod(secret_file, 0o444)", self.launcher)
        self.assertIn("os.chmod(token_dir, 0o733)", self.launcher)
        self.assertIn("custom integration secret parent must be private", self.launcher)
        self.assertIn("/run/koda/tracker-tokens:rw", self.docker_wrapper)
        self.assertIn("/run/secrets/koda-tracker-provisioning:ro", self.docker_wrapper)
        self.assertNotIn("KODA_TRACKER_NETWORK", self.suite_env + self.launcher + self.docker_wrapper)
        self.assertIn("- koda_dashboard", self.compose)
        self.assertIn(
            'suite_compose "$prefix" up -d --no-build --pull never --force-recreate',
            self.launcher,
        )
        self.assertIn('suite_compose "$prefix" ps', self.launcher)
        self.assertIn('suite_compose "$prefix" stop', self.launcher)
        self.assertIn('compose.airgap.yaml', self.launcher)
        self.assertIn('compose.integration.yaml', self.launcher)

    def test_destructive_preflight_runs_suite_network_and_runtime_guards(self) -> None:
        validate_preflight = self.launcher.split('validate_preflight() {', 1)[1].split(
            '\n}\n\npreflight_suite()', 1
        )[0]
        self.assertIn('runtime_values "$env_file"', validate_preflight)
        self.assertIn('KODA_DASHBOARD_NETWORK must remain koda-dashboard', self.launcher)
        self.assertIn('KODA_BASE_PATH must remain /koda/', self.launcher)
        self.assertIn('ipaddress.ip_network', self.launcher)

    def test_destructive_reset_is_flagged_scoped_and_never_prunes(self) -> None:
        self.assertIn('--delete-all-koda-data', self.reset_installer)
        self.assertIn('down --volumes --remove-orphans', self.reset_installer)
        self.assertIn('com.docker.compose.project', self.reset_installer)
        self.assertIn('io.koda.offline', self.reset_installer)
        self.assertIn('refusing to delete foreign container', self.reset_installer)
        self.assertIn('refusing to delete foreign network', self.reset_installer)
        self.assertIn('refusing to delete foreign volume', self.reset_installer)
        self.assertLess(
            self.reset_installer.index('refusing to delete foreign container'),
            self.reset_installer.index('down --volumes --remove-orphans'),
        )
        first_delete = self.reset_installer.index('down --volumes --remove-orphans')
        pre_audit = self.reset_installer[:first_delete]
        for marker in (
            'refusing to delete foreign container',
            'refusing to delete foreign network',
            'refusing to delete foreign volume',
            'foreign container attached',
        ):
            self.assertIn(marker, pre_audit)
        self.assertNotIn('docker system prune', self.reset_installer)
        self.assertNotIn('docker image rm', self.reset_installer)

    def test_ownership_mismatch_aborts_before_any_deletion(self) -> None:
        fake_docker = '''#!/usr/bin/env bash
printf '%s\n' "$*" >> "$DOCKER_LOG"
case "$1" in
  info) exit 0 ;;
  compose) [[ "$2" == version ]] && exit 0; exit 0 ;;
  container)
    [[ "$2" == inspect ]] || exit 1
    [[ "$FAKE_KIND" == container && "$3" == koda-sbom-gateway ]] && exit 0
    [[ "$FAKE_KIND" == dashboard && "$3" == koda-dashboard ]] && exit 0
    exit 1
    ;;
  inspect)
    target="${@: -1}"
    [[ "$FAKE_KIND" == container && "$target" == koda-sbom-gateway ]] && { echo foreign-project; exit 0; }
    [[ "$FAKE_KIND" == dashboard && "$target" == koda-dashboard ]] && { echo false; exit 0; }
    exit 1
    ;;
  network)
    target="${@: -1}"
    if [[ "$2" == inspect && "$FAKE_KIND" == network && "$target" == koda-sbom-edge ]]; then
      [[ "$3" == -f ]] && echo foreign-project
      exit 0
    fi
    exit 1
    ;;
  volume)
    target="${@: -1}"
    if [[ "$2" == inspect && "$FAKE_KIND" == volume && "$target" == koda-sbom-postgres-data ]]; then
      [[ "$3" == -f ]] && echo foreign-project
      exit 0
    fi
    exit 1
    ;;
esac
exit 1
'''
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            release = root / 'release'
            prefix = root / 'installed'
            fake_bin = root / 'bin'
            (prefix / 'tracker').mkdir(parents=True)
            (prefix / 'koda').mkdir()
            fake_bin.mkdir()
            release.mkdir()
            reset = release / 'reset-install.sh'
            reset.write_text(self.reset_installer)
            reset.chmod(0o755)
            launcher = release / 'koda-suite'
            launcher.write_text('#!/usr/bin/env bash\n[[ "$1" == preflight ]] && exit 0\nexit 99\n')
            launcher.chmod(0o755)
            (release / '.env').write_text('COMPOSE_PROJECT_NAME=koda-sbom\nPOSTGRES_PASSWORD=secret\n')
            (release / 'koda-suite.env').write_text('PUBLIC_HTTP_PORT=8088\n')
            (prefix / 'metadata.env').write_text('SUITE_VERSION=test\n')
            (prefix / 'tracker/compose.yaml').write_text('services: {}\n')
            wrapper = prefix / 'koda/koda-docker'
            wrapper.write_text('#!/usr/bin/env bash\nexit 0\n')
            wrapper.chmod(0o755)
            docker = fake_bin / 'docker'
            docker.write_text(fake_docker)
            docker.chmod(0o755)
            flock = fake_bin / 'flock'
            flock.write_text('#!/usr/bin/env bash\nexit 0\n')
            flock.chmod(0o755)
            log = root / 'docker.log'
            base_env = {
                **os.environ,
                'PATH': f'{fake_bin}:{os.environ["PATH"]}',
                'DOCKER_LOG': str(log),
                'HOME': str(root / 'home'),
            }
            for kind in ('container', 'dashboard', 'network', 'volume'):
                with self.subTest(kind=kind):
                    log.write_text('')
                    result = subprocess.run(
                        [str(reset), '--delete-all-koda-data', '--prefix', str(prefix)],
                        cwd=release, text=True, capture_output=True,
                        env={**base_env, 'FAKE_KIND': kind}, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('refusing to delete', result.stderr)
                    commands = log.read_text().splitlines()
                    self.assertFalse(any(' down ' in f' {line} ' for line in commands))
                    self.assertFalse(any(line.startswith(('rm ', 'network rm ', 'volume rm ')) for line in commands))

    def test_reset_env_merge_allows_suite_keys_and_rejects_secret_retargeting(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            release = Path(temp) / 'release'
            fake_bin = Path(temp) / 'bin'
            release.mkdir()
            fake_bin.mkdir()
            reset = release / 'reset-install.sh'
            reset.write_text(self.reset_installer)
            reset.chmod(0o755)
            capture = Path(temp) / 'merged.env'
            launcher = release / 'koda-suite'
            launcher.write_text(
                '#!/usr/bin/env bash\n'
                'if [[ "$1" == preflight ]]; then\n'
                '  while [[ $# -gt 0 ]]; do\n'
                '    if [[ "$1" == --env-file ]]; then cp "$2" "$CAPTURE"; exit 9; fi\n'
                '    shift\n'
                '  done\n'
                'fi\n'
                'exit 99\n'
            )
            launcher.chmod(0o755)
            docker = fake_bin / 'docker'
            docker.write_text('#!/usr/bin/env bash\nexit 0\n')
            docker.chmod(0o755)
            flock = fake_bin / 'flock'
            flock.write_text('#!/usr/bin/env bash\nexit 0\n')
            flock.chmod(0o755)
            base = '''COMPOSE_PROJECT_NAME=koda-sbom
POSTGRES_PASSWORD=secret
PUBLIC_HTTP_PORT=8088
DTRACK_APISERVER_IMAGE=dependencytrack/apiserver:5.0.3
'''
            (release / '.env').write_text(base)
            (release / 'koda-suite.env').write_text(
                'PUBLIC_HTTP_PORT=9443\n'
                'DTRACK_APISERVER_IMAGE=dependencytrack/apiserver:5.0.3@sha256:old-release\n'
            )
            env = {
                **os.environ,
                'PATH': f'{fake_bin}:{os.environ["PATH"]}',
                'CAPTURE': str(capture),
                'HOME': str(Path(temp) / 'home'),
            }
            result = subprocess.run(
                [str(reset), '--delete-all-koda-data'], cwd=release,
                text=True, capture_output=True, env=env, check=False,
            )
            self.assertEqual(result.returncode, 9, result.stderr)
            merged = capture.read_text()
            self.assertIn('PUBLIC_HTTP_PORT=9443\n', merged)
            self.assertEqual(merged.count('PUBLIC_HTTP_PORT='), 1)
            self.assertIn('POSTGRES_PASSWORD=secret\n', merged)
            self.assertIn('DTRACK_APISERVER_IMAGE=dependencytrack/apiserver:5.0.3\n', merged)

            (release / 'koda-suite.env').write_text('POSTGRES_PASSWORD=retargeted\n')
            capture.unlink()
            result = subprocess.run(
                [str(reset), '--delete-all-koda-data'], cwd=release,
                text=True, capture_output=True, env=env, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('may not override POSTGRES_PASSWORD', result.stderr)
            self.assertFalse(capture.exists())

    def test_patch_groups_are_explicit_and_preserve_dependencies(self) -> None:
        self.assertIn('koda|gateway|portal-web|portal-api-worker|dependency-track', self.launcher)
        self.assertIn('services=(portal-api portal-worker)', self.launcher)
        self.assertIn('services=(dtrack-apiserver dtrack-frontend)', self.launcher)
        self.assertIn('--no-deps --force-recreate "${services[@]}"', self.launcher)
        self.assertIn('PostgreSQL is not patchable in place', self.launcher)
        self.assertIn("safe_name=\"$(printf '%s' \"$archive_ref\"", self.launcher)
        self.assertNotIn('suite_compose "$prefix" down', self.launcher)

    def test_patch_rejects_changed_image_ref_before_docker_load(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            release = root / 'release'
            prefix = root / 'installed'
            fake_bin = root / 'bin'
            koda_root = root / 'koda-payload/koda'
            tracker_root = root / 'tracker-payload'
            for path in (
                release / 'bundles', release / 'gateway', prefix / 'tracker',
                prefix / 'koda', fake_bin, koda_root, tracker_root / 'scripts',
                tracker_root / 'config', tracker_root / 'images',
            ):
                path.mkdir(parents=True, exist_ok=True)

            koda_install = koda_root / 'install.sh'
            koda_install.write_text('#!/usr/bin/env bash\nexit 0\n')
            koda_install.chmod(0o755)
            (koda_root / 'manifest.sha256').write_text(
                f'{hashlib.sha256(koda_install.read_bytes()).hexdigest()}  install.sh\n'
            )
            koda_bundle = release / 'bundles/koda.tar.gz'
            with tarfile.open(koda_bundle, 'w:gz') as archive:
                archive.add(koda_root, arcname='koda')

            for script_name in ('install-airgap.sh', 'preflight-airgap.sh'):
                script = tracker_root / f'scripts/{script_name}'
                script.write_text('#!/usr/bin/env bash\nexit 0\n')
                script.chmod(0o755)
            (tracker_root / 'compose.yaml').write_text('services: {}\n')
            (tracker_root / 'compose.airgap.yaml').write_text('services: {}\n')
            (tracker_root / 'metadata.env').write_text('VULNERABILITY_BUNDLE=absent\n')
            (tracker_root / 'manifest.sha256').write_text('')
            (tracker_root / 'config/.env.example').write_text('NGINX_IMAGE=nginx:2\n')
            (tracker_root / 'images/nginx_2.tar').write_bytes(b'not-loaded')
            tracker_bundle = release / 'bundles/tracker.tar.gz'
            with tarfile.open(tracker_bundle, 'w:gz') as archive:
                for path in tracker_root.iterdir():
                    archive.add(path, arcname=path.name)

            metadata = '''TARGET_PLATFORM=linux/amd64
DISTRIBUTION_SCOPE=internal-only
KODA_BUNDLE=bundles/koda.tar.gz
TRACKER_BUNDLE=bundles/tracker.tar.gz
TRACKER_VULNERABILITY_BUNDLE=absent
AUTHORITY=tracker
AUTH_CONTRACT_VERSION=1
AUTH_COOKIE_NAME=__Host-koda_session
AUTH_COOKIE_SCHEMA_VERSION=2
TRACKER_SESSION_ENDPOINT=/api/v1/auth/session
KODA_BASE_PATH=/koda/
GATEWAY_AUTH_MODE=auth_request
KODA_PORTAL_SCHEMA_VERSION=1
KODA_RBAC_CATALOG_VERSION=koda-rbac-v1
'''
            (release / 'metadata.env').write_text(metadata)
            (prefix / 'metadata.env').write_text(metadata)
            for relative, content in (
                ('compose.integration.yaml', 'services: {}\n'),
                ('gateway/gateway.conf.template', 'server {}\n'),
                ('.env.example', 'COMPOSE_PROJECT_NAME=koda-sbom\n'),
                ('koda-suite.env.example', 'PUBLIC_HTTP_PORT=8088\n'),
                ('reset-install.sh', '#!/usr/bin/env bash\nexit 0\n'),
            ):
                path = release / relative
                path.write_text(content)
                if relative == 'reset-install.sh':
                    path.chmod(0o755)
            (prefix / 'tracker/.env').write_text('NGINX_IMAGE=nginx:1\n')
            (prefix / 'tracker/compose.yaml').write_text('services: {}\n')
            (prefix / 'tracker/compose.airgap.yaml').write_text('services: {}\n')
            (prefix / 'tracker/compose.integration.yaml').write_text('services: {}\n')
            wrapper = prefix / 'koda/koda-docker'
            wrapper.write_text('#!/usr/bin/env bash\nexit 0\n')
            wrapper.chmod(0o755)
            suite = release / 'koda-suite'
            suite.write_text(self.launcher)
            suite.chmod(0o755)
            files = sorted(path for path in release.rglob('*') if path.is_file())
            (release / 'manifest.sha256').write_text(''.join(
                f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(release)}\n'
                for path in files
            ))

            docker_log = root / 'docker.log'
            docker = fake_bin / 'docker'
            docker.write_text(
                '#!/usr/bin/env bash\n'
                'printf "%s\\n" "$*" >> "$DOCKER_LOG"\n'
                '[[ "$1" == info ]] && exit 0\n'
                '[[ "$1" == compose && "$2" == version ]] && exit 0\n'
                'exit 99\n'
            )
            docker.chmod(0o755)
            uname = fake_bin / 'uname'
            uname.write_text('#!/usr/bin/env bash\necho x86_64\n')
            uname.chmod(0o755)
            flock = fake_bin / 'flock'
            flock.write_text('#!/usr/bin/env bash\nexit 0\n')
            flock.chmod(0o755)
            result = subprocess.run(
                [str(suite), 'patch', '--group', 'gateway', '--prefix', str(prefix)],
                cwd=release, text=True, capture_output=True, check=False,
                env={
                    **os.environ,
                    'PATH': f'{fake_bin}:{os.environ["PATH"]}',
                    'DOCKER_LOG': str(docker_log),
                    'HOME': str(root / 'home'),
                },
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('NGINX_IMAGE image reference changed', result.stderr)
            self.assertFalse(any(line.startswith('load ') for line in docker_log.read_text().splitlines()))

    def test_koda_has_no_direct_host_port(self) -> None:
        self.assertIn('KODA_PUBLISH_DASHBOARD=0', self.launcher)
        self.assertIn('.HostConfig.PortBindings', self.launcher)
        self.assertIn('KODA dashboard network must be internal when GitLab egress is configured.', self.launcher)
        self.assertNotIn('ports:', self.compose)
        self.assertIn('external: true', self.compose)

    def test_gitlab_network_is_the_dashboard_default_gateway(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_bin = root / 'bin'
            fake_bin.mkdir()
            wrapper = root / 'koda-docker'
            wrapper.write_text(self.docker_wrapper)
            wrapper.chmod(0o755)
            (root / 'image-ref.txt').write_text('local/koda:test\n')
            docker_log = root / 'docker.log'
            docker = fake_bin / 'docker'
            docker.write_text(
                '#!/usr/bin/env bash\n'
                'printf "%s\\n" "$*" >> "$DOCKER_LOG"\n'
                '[[ "$1" == container && "$2" == inspect ]] && exit 1\n'
                '[[ "$1" == network && "$2" == inspect && "${@: -1}" == koda-dashboard ]] && exit 1\n'
                '[[ "$1" == network && "$2" == inspect ]] && exit 0\n'
                '[[ "$1" == network && "$2" == create ]] && exit 0\n'
                '[[ "$1" == version ]] && { echo "${FAKE_DOCKER_VERSION:-27.5.1}"; exit 0; }\n'
                '[[ "$1" == run ]] && exit 0\n'
                '[[ "$1" == network && "$2" == connect ]] && exit 0\n'
                'exit 99\n'
            )
            docker.chmod(0o755)
            result = subprocess.run(
                [str(wrapper), 'dashboard', 'start'],
                text=True,
                capture_output=True,
                env={
                    **os.environ,
                    'PATH': f'{fake_bin}:{os.environ["PATH"]}',
                    'DOCKER_LOG': str(docker_log),
                    'KODA_GITLAB_NETWORK': 'koda-gitlab-egress',
                    'KODA_PUBLISH_DASHBOARD': '0',
                    'KODA_PORTAL_DATA_DIR': str(root / 'portal'),
                },
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            commands = docker_log.read_text().splitlines()
            self.assertTrue(any(
                line.startswith('run ') and '--network koda-gitlab-egress' in line
                for line in commands
            ))
            self.assertIn('network connect koda-dashboard koda-dashboard', commands)
            self.assertTrue(any(
                line.startswith('network create ')
                and '--internal' in line
                and line.endswith(' koda-dashboard')
                for line in commands
            ))

            docker_log.write_text('')
            result = subprocess.run(
                [str(wrapper), 'dashboard', 'start'],
                text=True,
                capture_output=True,
                env={
                    **os.environ,
                    'PATH': f'{fake_bin}:{os.environ["PATH"]}',
                    'DOCKER_LOG': str(docker_log),
                    'FAKE_DOCKER_VERSION': '28.0.0',
                    'KODA_GITLAB_NETWORK': 'koda-gitlab-egress',
                    'KODA_PUBLISH_DASHBOARD': '0',
                    'KODA_PORTAL_DATA_DIR': str(root / 'portal'),
                },
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(any(
                line.startswith('run ')
                and '--network name=koda-gitlab-egress,gw-priority=1' in line
                for line in docker_log.read_text().splitlines()
            ))

    def test_enabling_schedule_preserves_running_dashboard_and_isolates_worker(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_bin = root / 'bin'
            fake_bin.mkdir()
            wrapper = root / 'koda-docker'
            wrapper.write_text(self.docker_wrapper)
            wrapper.chmod(0o755)
            (root / 'image-ref.txt').write_text('local/koda:test\n')
            ssh_dir = root / 'ssh'
            ssh_dir.mkdir()
            (ssh_dir / 'known_hosts').write_text('test\n')
            docker_log = root / 'docker.log'
            docker = fake_bin / 'docker'
            docker.write_text(
                '#!/usr/bin/env bash\n'
                'printf "%s\\n" "$*" >> "$DOCKER_LOG"\n'
                'if [[ "$1" == container && "$2" == inspect ]]; then\n'
                '  [[ "$3" == koda-dashboard ]] && exit 0\n'
                '  exit 1\n'
                'fi\n'
                'if [[ "$1" == inspect ]]; then echo true; exit 0; fi\n'
                'if [[ "$1" == ps ]]; then echo koda-dashboard; exit 0; fi\n'
                'if [[ "$1" == network && "$2" == inspect ]]; then exit 0; fi\n'
                'if [[ "$1" == network && "$2" == connect ]]; then exit 0; fi\n'
                'if [[ "$1" == run ]]; then exit 0; fi\n'
                'exit 99\n'
            )
            docker.chmod(0o755)
            env = {
                **os.environ,
                'PATH': f'{fake_bin}:{os.environ["PATH"]}',
                'DOCKER_LOG': str(docker_log),
                'KODA_SCHEDULE_ENABLED': '1',
                'KODA_SCHEDULE_SSH_DIR': str(ssh_dir),
                'KODA_PORTAL_DATA_DIR': str(root / 'portal'),
                'KODA_GITLAB_TOKEN_FILE': str(root / 'gitlab-token'),
                'KODA_TRACKER_TOKEN_DIR': str(root / 'tracker-tokens'),
            }
            (root / 'gitlab-token').write_text('secret\n')
            (root / 'tracker-tokens').mkdir()
            result = subprocess.run(
                [str(wrapper), 'dashboard', 'start'], text=True,
                capture_output=True, env=env, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            commands = docker_log.read_text().splitlines()
            self.assertFalse(any(line.startswith('rm ') for line in commands))
            self.assertFalse(any(
                line.startswith('run ') and '--name koda-dashboard' in line
                for line in commands
            ))
            worker_runs = [
                line for line in commands
                if line.startswith('run ') and '--name koda-schedule-worker' in line
            ]
            self.assertEqual(len(worker_runs), 1)
            worker = worker_runs[0]
            self.assertIn('--network koda-dashboard-schedule', worker)
            self.assertNotIn('--network koda-dashboard ', worker)
            self.assertIn('network connect koda-dashboard koda-schedule-worker', commands)
            for forbidden in (
                '/var/lib/koda:', '/run/secrets/koda-gitlab-token',
                '/run/koda/tracker-tokens', 'KODA_GITLAB_TOKEN_FILE=',
                'KODA_TRACKER_TOKEN_DIR=', 'KODA_GITLAB_URL=',
                'KODA_TRACKER_URL=',
            ):
                self.assertNotIn(forbidden, worker)
            for required in (
                '/var/lib/koda-schedule:rw', '/run/koda/schedule:ro',
                '/run/koda/ssh:ro', '--cpus 1', '--memory 4g',
                '--read-only', '--cap-drop ALL',
            ):
                self.assertIn(required, worker)

    def test_dashboard_start_and_stop_refuse_a_foreign_named_container(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_bin = root / 'bin'
            fake_bin.mkdir()
            wrapper = root / 'koda-docker'
            wrapper.write_text(self.docker_wrapper)
            wrapper.chmod(0o755)
            (root / 'image-ref.txt').write_text('local/koda:test\n')
            docker_log = root / 'docker.log'
            docker = fake_bin / 'docker'
            docker.write_text(
                '#!/usr/bin/env bash\n'
                'printf "%s\\n" "$*" >> "$DOCKER_LOG"\n'
                '[[ "$1" == container && "$2" == inspect ]] && exit 0\n'
                '[[ "$1" == inspect ]] && { echo false; exit 0; }\n'
                'exit 99\n'
            )
            docker.chmod(0o755)
            env = {
                **os.environ,
                'PATH': f'{fake_bin}:{os.environ["PATH"]}',
                'DOCKER_LOG': str(docker_log),
            }
            for command in (['dashboard', 'start'], ['dashboard', 'stop']):
                with self.subTest(command=command[-1]):
                    docker_log.write_text('')
                    result = subprocess.run(
                        [str(wrapper), *command], text=True, capture_output=True,
                        env=env, check=False,
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertIn('refusing to replace foreign container', result.stderr)
                    self.assertFalse(any(
                        line.startswith('rm ') for line in docker_log.read_text().splitlines()
                    ))

    def test_koda_upload_is_streamed_and_limited_to_two_gibibytes(self) -> None:
        api_location = self.gateway.split('location ^~ /koda/api/', 1)[1].split('location ^~ /koda/', 1)[0]
        self.assertIn('client_max_body_size 2049m;', api_location)
        self.assertIn('client_body_timeout 1h;', api_location)
        self.assertIn('proxy_connect_timeout 30s;', api_location)
        self.assertIn('proxy_send_timeout 1h;', api_location)
        self.assertIn('proxy_read_timeout 1h;', api_location)
        self.assertIn('proxy_request_buffering off;', api_location)
        self.assertIn('error_page 500 = @koda_auth_unavailable;', api_location)
        self.assertNotIn('error_page 500 502 503 504 = @koda_auth_unavailable;', api_location)

    def test_large_json_limit_reaches_dashboard_and_schedule_worker(self) -> None:
        self.assertIn('KODA_JSON_MAX_BYTES=524288000', self.suite_env)
        self.assertIn('KODA_JSON_MAX_BYTES="$json_max_bytes"', self.launcher)
        self.assertGreaterEqual(self.docker_wrapper.count('KODA_JSON_MAX_BYTES'), 3)

    def test_packager_requires_both_verified_offline_payloads(self) -> None:
        packager = (ROOT / "platforms/linux/package-suite-offline.sh").read_text()

        self.assertIn('KODA_DOCKER_BUNDLE', packager)
        self.assertIn('KODA_TRACKER_BUNDLE', packager)
        self.assertIn('"$tracker_verifier" "$tracker_bundle"', packager)
        self.assertIn('KODA_BUNDLE=bundles/', packager)
        self.assertIn('TRACKER_BUNDLE=bundles/', packager)
        self.assertIn('Tracker release must include fresh vulnerability data', packager)
        self.assertIn('reset-install.sh', packager)
        self.assertIn('"$stage/.env.example"', packager)
        self.assertIn('"$stage/koda-suite.env.example"', packager)
        self.assertIn('tar --no-xattrs', packager)
        self.assertIn('TROUBLESHOOTING.ko.md', packager)
        self.assertIn('"$script_dir/TROUBLESHOOTING.ko.md"', self.launcher)
        self.assertIn('status --porcelain --untracked-files=all', packager)
        self.assertIn('KODA bundle provenance does not match', packager)
        self.assertIn('Tracker bundle provenance does not match', packager)

    def test_packager_accepts_flat_tracker_release_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            tracker_repo = work / 'tracker'
            (tracker_repo / 'scripts').mkdir(parents=True)
            verifier = tracker_repo / 'scripts/verify-airgap-release.sh'
            verifier.write_text('#!/usr/bin/env bash\nexit 0\n')
            verifier.chmod(0o755)
            (tracker_repo / '.env.example').write_text('PUBLIC_HTTP_PORT=8088\n')
            subprocess.run(['git', 'init', '-q', tracker_repo], check=True)
            subprocess.run(['git', '-C', tracker_repo, 'add', '.'], check=True)
            subprocess.run([
                'git', '-C', tracker_repo, '-c', 'user.name=KODA Test',
                '-c', 'user.email=koda@example.invalid', 'commit', '-qm', 'fixture',
            ], check=True)
            tracker_revision = subprocess.check_output(
                ['git', '-C', tracker_repo, 'rev-parse', 'HEAD'], text=True,
            ).strip()
            koda_revision = subprocess.check_output(
                ['git', '-C', ROOT, 'rev-parse', 'HEAD'], text=True,
            ).strip()
            koda_dirty = bool(subprocess.check_output(
                ['git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=all'],
                text=True,
            ).strip())

            koda_root = work / 'koda-payload'
            koda_root.mkdir()
            for name in ('manifest.sha256', 'install.sh', 'koda-docker.sh', 'image-ref.txt'):
                (koda_root / name).write_text('fixture\n')
            (koda_root / 'versions.txt').write_text(
                f'git_revision={koda_revision}\ngit_worktree_dirty={str(koda_dirty).lower()}\n'
            )
            koda_bundle = work / 'koda.tar.gz'
            with tarfile.open(koda_bundle, 'w:gz') as archive:
                archive.add(koda_root, arcname='koda')

            tracker_metadata = work / 'metadata.env'
            tracker_metadata.write_text(
                f'TRACKER_GIT_REVISION={tracker_revision}\n'
                'TRACKER_WORKTREE_DIRTY=false\nVULNERABILITY_BUNDLE=included\n'
            )
            tracker_bundle = work / 'tracker.tar.gz'
            with tarfile.open(tracker_bundle, 'w:gz') as archive:
                archive.add(tracker_metadata, arcname='./metadata.env')
            output = work / 'suite.tar.gz'
            result = subprocess.run(
                ['bash', str(ROOT / 'platforms/linux/package-suite-offline.sh'), str(output)],
                text=True, capture_output=True, check=False, env={
                    **os.environ,
                    'KODA_SUITE_VERSION': 'test',
                    'KODA_DOCKER_BUNDLE': str(koda_bundle),
                    'KODA_TRACKER_BUNDLE': str(tracker_bundle),
                    'KODA_TRACKER_VERIFIER': str(verifier),
                    'KODA_SUITE_ALLOW_DIRTY': '1',
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())

    def test_vulnerability_seed_reuses_koda_offline_datasets(self) -> None:
        builder = (ROOT / 'platforms/linux/build-suite-vuln-bundle.sh').read_text()
        self.assertIn('grype-db/incoming/', builder)
        self.assertIn('vuln-data/nvd/', builder)
        self.assertIn('known_exploited_vulnerabilities.json', builder)
        self.assertIn('grype_db_checksum', builder)
        self.assertIn('build-vuln-bundle.sh', builder)

    def test_verify_command_accepts_intact_release_and_rejects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            release = Path(temp)
            (release / 'bundles').mkdir()
            (release / 'gateway').mkdir()
            for archive_path, root_name in (
                (release / 'bundles/koda.tar.gz', 'koda'),
                (release / 'bundles/tracker.tar.gz', ''),
            ):
                with tarfile.open(archive_path, 'w:gz') as archive:
                    info = tarfile.TarInfo(
                        f'{root_name + "/" if root_name else ""}manifest.sha256'
                    )
                    info.size = 0
                    archive.addfile(info)
            (release / 'compose.integration.yaml').write_text('services: {}\n')
            (release / 'gateway/gateway.conf.template').write_text('server {}\n')
            (release / '.env.example').write_text('COMPOSE_PROJECT_NAME=koda-sbom\n')
            (release / 'koda-suite.env.example').write_text('PUBLIC_HTTP_PORT=8088\n')
            reset = release / 'reset-install.sh'
            reset.write_text('#!/usr/bin/env bash\nexit 0\n')
            reset.chmod(0o755)
            metadata = '''TARGET_PLATFORM=linux/amd64
DISTRIBUTION_SCOPE=internal-only
KODA_BUNDLE=bundles/koda.tar.gz
TRACKER_BUNDLE=bundles/tracker.tar.gz
TRACKER_VULNERABILITY_BUNDLE=included
AUTHORITY=tracker
AUTH_CONTRACT_VERSION=1
AUTH_COOKIE_NAME=__Host-koda_session
AUTH_COOKIE_SCHEMA_VERSION=2
TRACKER_SESSION_ENDPOINT=/api/v1/auth/session
KODA_BASE_PATH=/koda/
GATEWAY_AUTH_MODE=auth_request
KODA_PORTAL_SCHEMA_VERSION=1
KODA_RBAC_CATALOG_VERSION=koda-rbac-v1
'''
            (release / 'metadata.env').write_text(metadata)
            script = release / 'koda-suite'
            script.write_text(self.launcher)
            script.chmod(0o755)
            files = sorted(path for path in release.rglob('*') if path.is_file())
            manifest = ''.join(
                f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(release)}\n'
                for path in files
            )
            (release / 'manifest.sha256').write_text(manifest)

            result = subprocess.run(
                [str(script), 'verify'], cwd=release, text=True, capture_output=True,
                env={**os.environ, 'HOME': temp}, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('release integrity OK', result.stdout)

            (release / 'bundles/koda.tar.gz').write_bytes(b'tampered')
            result = subprocess.run(
                [str(script), 'verify'], cwd=release, text=True, capture_output=True,
                env={**os.environ, 'HOME': temp}, check=False,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
