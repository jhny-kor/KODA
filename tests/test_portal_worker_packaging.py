"""Launcher tests with a stateful Docker stand-in, without a Docker daemon."""
import json
import copy
import importlib.util
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from security_scanner import cli

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "platforms/linux/docker/koda-docker.sh"
SPEC = importlib.util.spec_from_file_location("portal_worker_preflight", ROOT / "platforms/linux/scheduled-release/preflight.py")
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)

# Record argument boundaries and model running containers across start/stop.
DOCKER_STUB = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
path = pathlib.Path(os.environ['DOCKER_STATE'])
state = json.loads(path.read_text())
with open(os.environ['DOCKER_LOG'], 'a') as stream:
    stream.write(json.dumps(args) + '\n')
def finish(code=0):
    path.write_text(json.dumps(state))
    raise SystemExit(code)
command = args[0]
if command == 'container' and args[1] == 'inspect':
    finish(0 if args[-1] in state['containers'] else 1)
if command == 'image' and args[1] == 'inspect':
    print(os.environ.get('DOCKER_IMAGE_ID', 'sha256:new'))
    finish()
if command == 'inspect':
    container = state['containers'].get(args[-1])
    if container is None:
        finish(1)
    template = args[args.index('-f') + 1]
    if 'io.koda.offline' in template:
        print(container.get('owner', 'true'))
    elif 'io.koda.portal-role' in template:
        print(container.get('role', '<no value>'))
    elif template == '{{.Image}}':
        print(container['image'])
    elif '.State.Health' in template:
        print('healthy' if container.get('running') else 'stopped')
    finish()
if command == 'ps':
    names = [name for name, value in state['containers'].items()
             if '--all' in args or value.get('running')]
    if '--filter' in args:
        selected = args[args.index('--filter') + 1].removeprefix('name=^').removesuffix('$')
        names = [name for name in names if name == selected]
    print('\n'.join(names))
    finish()
if command == 'network':
    if args[1] == 'inspect':
        finish(0 if args[-1] in state['networks'] else 1)
    if args[1] == 'create':
        state['networks'].append(args[-1])
        finish()
    if args[1] == 'connect':
        state['containers'][args[-1]].setdefault('networks', []).append(args[-2])
        finish()
if command == 'volume' and args[1] == 'inspect':
    finish()
if command == 'version':
    print('28.0.0')
    finish()
if command == 'run':
    name = args[args.index('--name') + 1]
    if name in state['containers'] or name == os.environ.get('FAIL_RUN_NAME'):
        finish(1)
    role = next((arg.split('=', 1)[1] for arg in args if arg.startswith('io.koda.portal-role=')), '')
    state['containers'][name] = {'owner': 'true', 'running': True,
        'role': role, 'image': os.environ.get('DOCKER_IMAGE_ID', 'sha256:new'), 'args': args}
    print(name)
    finish()
if command == 'stop':
    state['containers'][args[-1]]['running'] = False
    finish()
if command == 'rm':
    for name in args[1:]:
        if not name.startswith('-'):
            state['containers'].pop(name, None)
    finish()
finish(99)
'''


class PortalWorkerPackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        docker = self.bin / "docker"
        docker.write_text(DOCKER_STUB)
        docker.chmod(0o755)
        self.wrapper = self.root / "koda-docker"
        self.wrapper.write_text(WRAPPER.read_text())
        self.wrapper.chmod(0o755)
        (self.root / "image-ref.txt").write_text("local/koda:test\n")
        self.state_file = self.root / "state.json"
        self.log_file = self.root / "docker.jsonl"
        self.state_file.write_text(json.dumps({"containers": {}, "networks": []}))
        self.env = {**os.environ,
                    "PATH": f'{self.bin}:{os.environ["PATH"]}',
                    "DOCKER_STATE": str(self.state_file), "DOCKER_LOG": str(self.log_file),
                    "KODA_PORTAL_DATA_DIR": str(self.root / "portal"),
                    "KODA_PUBLISH_DASHBOARD": "0", "KODA_SCHEDULE_ENABLED": "0"}
        for name in tuple(self.env):
            if name.startswith("KODA_") and name not in {
                "KODA_PORTAL_DATA_DIR", "KODA_PUBLISH_DASHBOARD", "KODA_SCHEDULE_ENABLED"
            }:
                self.env.pop(name)

    def invoke(self, command="start", **environment):
        result = subprocess.run([str(self.wrapper), "dashboard", command],
                                env={**self.env, **environment}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def commands(self):
        return [json.loads(line) for line in self.log_file.read_text().splitlines()]

    def test_cli_dispatches_worker_and_healthcheck(self):
        main = mock.Mock(return_value=0)
        module = types.ModuleType("security_scanner.portal_worker")
        module.main = main
        with mock.patch.dict(sys.modules, {"security_scanner.portal_worker": module}):
            self.assertEqual(cli.main(["portal-worker", "--db", "/var/lib/koda/portal.sqlite3", "--healthcheck"]), 0)
        main.assert_called_once_with(["--db", "/var/lib/koda/portal.sqlite3", "--healthcheck"])

    def test_start_isolates_scan_and_delivery_resources_mounts_and_network(self):
        for name in ("gitlab-token", "gitlab-write-token", "tracker-provisioning", "gitlab-ca", "tracker-ca"):
            (self.root / name).write_text("test-only\n")
        (self.root / "tracker-tokens").mkdir()
        self.state_file.write_text(json.dumps({"containers": {}, "networks": ["gitlab-egress"]}))
        self.invoke(KODA_GITLAB_NETWORK="gitlab-egress", KODA_VULN_DATA_VOLUME="koda-vuln",
                    KODA_GITLAB_TOKEN_FILE=str(self.root / "gitlab-token"),
                    KODA_GITLAB_WRITE_TOKEN_FILE=str(self.root / "gitlab-write-token"),
                    KODA_TRACKER_TOKEN_DIR=str(self.root / "tracker-tokens"),
                    KODA_TRACKER_PROVISIONING_TOKEN_FILE=str(self.root / "tracker-provisioning"),
                    KODA_GITLAB_CA_FILE=str(self.root / "gitlab-ca"),
                    KODA_TRACKER_CA_FILE=str(self.root / "tracker-ca"),
                    KODA_GITLAB_URL="https://gitlab.internal", KODA_TRACKER_URL="http://koda-sbom-gateway:8080",
                    KODA_GATEWAY_PROOF="test-proof", KODA_SCAN_CPUS="1.5", KODA_SCAN_MEMORY="3g",
                    KODA_DELIVERY_CPUS="0.75", KODA_DELIVERY_MEMORY="768m",
                    KODA_PORTAL_REPORT_TIMEOUT_SECONDS="120", KODA_PORTAL_REPORT_MEMORY_BYTES="1073741824",
                    KODA_DOCKER_EXTRA_ARGS="-p 9999:9999")
        containers = json.loads(self.state_file.read_text())["containers"]
        self.assertEqual(set(containers), {"koda-dashboard", "koda-scan-worker", "koda-delivery-worker"})
        web = containers["koda-dashboard"]["args"]
        self.assertIn("KODA_PORTAL_EXTERNAL_WORKER=1", web)
        self.assertIn("KODA_PORTAL_REPORT_TIMEOUT_SECONDS=120", web)
        self.assertIn("KODA_PORTAL_REPORT_MEMORY_BYTES=1073741824", web)
        scan = containers["koda-scan-worker"]["args"]
        delivery = containers["koda-delivery-worker"]["args"]
        for args, role, cpus, memory in ((scan, "scan", "1.5", "3g"), (delivery, "delivery", "0.75", "768m")):
            self.assertEqual(args[args.index("--cpus") + 1], cpus)
            self.assertEqual(args[args.index("--memory") + 1], memory)
            self.assertEqual(args[args.index("--restart") + 1], "unless-stopped")
            self.assertIn("--init", args)
            self.assertIn("--read-only", args)
            self.assertIn("KODA_PORTAL_WORKER_ROLE=" + role, args)
            self.assertIn(f"{self.root}/portal:/var/lib/koda:rw", args)
            self.assertIn("KODA_PORTAL_DB=/var/lib/koda/portal.sqlite3", args)
            self.assertIn("/opt/koda/bin/koda portal-worker --healthcheck", args)
            self.assertEqual(args[-2:], ["local/koda:test", "portal-worker"])
            self.assertNotIn("-p", args)
            self.assertFalse(any("KODA_GATEWAY_PROOF=" in arg for arg in args))
            self.assertFalse(any("KODA_PORTAL_REPORT_" in arg for arg in args))
        self.assertEqual(scan[scan.index("--network") + 1], "none")
        self.assertIn("koda-vuln:/var/lib/koda-vuln-data:ro", scan)
        self.assertIn("KODA_SCAN_TIMEOUT_SECONDS=21600", scan)
        self.assertFalse(any("/run/secrets" in arg or "tracker-tokens" in arg for arg in scan))
        self.assertEqual(delivery[delivery.index("--network") + 1], "name=gitlab-egress,gw-priority=1")
        self.assertIn("koda-dashboard", containers["koda-delivery-worker"]["networks"])
        self.assertIn("KODA_GITLAB_WRITE_TOKEN_FILE=/run/secrets/koda-gitlab-write-token", delivery)
        self.assertIn("KODA_TRACKER_TOKEN_DIR=/run/koda/tracker-tokens", delivery)
        self.assertNotIn("KODA_VULN_DATA_ROOT=/var/lib/koda-vuln-data", delivery)

    def test_repeated_start_preserves_current_containers_without_duplicate_workers(self):
        self.invoke()
        self.log_file.write_text("")
        self.invoke()
        self.assertFalse(any(args[0] in {"run", "rm", "stop"} for args in self.commands()))

    def test_image_tag_update_replaces_web_and_workers_together(self):
        self.invoke()
        self.log_file.write_text("")
        self.invoke(DOCKER_IMAGE_ID="sha256:updated")
        containers = json.loads(self.state_file.read_text())["containers"]
        self.assertEqual({item["image"] for item in containers.values()}, {"sha256:updated"})
        self.assertEqual(len([args for args in self.commands() if args[0] == "run"]), 3)
        self.assertIn(["stop", "--time", "20", "koda-scan-worker"], self.commands())
        self.assertIn(["stop", "--time", "20", "koda-delivery-worker"], self.commands())

    def test_legacy_internal_worker_web_is_replaced_before_external_workers_start(self):
        self.state_file.write_text(json.dumps({"containers": {
            "koda-dashboard": {"running": True, "owner": "true", "image": "sha256:new"}}, "networks": []}))
        self.invoke()
        commands = self.commands()
        remove = commands.index(["rm", "-f", "koda-dashboard"])
        worker_runs = [i for i, args in enumerate(commands) if args[0] == "run" and "portal-worker" in args]
        self.assertTrue(worker_runs and all(i > remove for i in worker_runs))

    def test_stop_gracefully_stops_workers_before_removing_web_and_preserves_data(self):
        self.invoke()
        marker = self.root / "portal" / "must-survive"
        marker.write_text("retained")
        self.log_file.write_text("")
        self.invoke("stop")
        commands = self.commands()
        scan_stop = commands.index(["stop", "--time", "20", "koda-scan-worker"])
        web_remove = commands.index(["rm", "-f", "koda-dashboard"])
        self.assertLess(scan_stop, web_remove)
        self.assertTrue(marker.is_file())
        self.assertFalse(json.loads(self.state_file.read_text())["containers"])

    def test_foreign_worker_blocks_start_and_stop_before_mutation(self):
        self.invoke()
        state = json.loads(self.state_file.read_text())
        state["containers"]["koda-delivery-worker"]["owner"] = "false"
        self.state_file.write_text(json.dumps(state))
        for command in ("start", "stop"):
            with self.subTest(command=command):
                self.log_file.write_text("")
                result = subprocess.run([str(self.wrapper), "dashboard", command], env=self.env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn("foreign container named koda-delivery-worker", result.stderr)
                self.assertFalse(any(args[0] in {"rm", "run", "stop"} for args in self.commands()))

    def test_failed_worker_start_is_reported_and_retry_recovers(self):
        result = subprocess.run([str(self.wrapper), "dashboard", "start"],
                                env={**self.env, "FAIL_RUN_NAME": "koda-delivery-worker"},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("could not start koda-delivery-worker", result.stderr)
        self.invoke()
        self.assertEqual(len(json.loads(self.state_file.read_text())["containers"]), 3)

    def test_contract_copies_match_and_launchers_parse(self):
        pairs = ((WRAPPER, ROOT / "platforms/linux/scheduled-release/contract/koda/koda-docker"),
                 (ROOT / "platforms/linux/suite/koda-suite", ROOT / "platforms/linux/scheduled-release/contract/koda-suite"))
        for source, contract in pairs:
            self.assertEqual(source.read_bytes(), contract.read_bytes())
        for source in (WRAPPER, ROOT / "platforms/linux/suite/koda-suite", ROOT / "platforms/linux/suite/reset-install.sh",
                       ROOT / "platforms/linux/scheduled-release/rollback.sh"):
            result = subprocess.run(["bash", "-n", str(source)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


class PortalWorkerPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.prefix = Path(self.temp.name)
        (self.prefix / "data/koda-portal").mkdir(parents=True)
        self.dashboard = {"Image": "sha256:koda", "Config": {"Env": ["KODA_PORTAL_EXTERNAL_WORKER=1"]}}
        self.records = {
            f"koda-{role}-worker": {
                "Image": "sha256:koda",
                "Config": {"Labels": {"io.koda.offline": "true", "io.koda.portal-role": role}},
                "State": {"Status": "running"},
                "HostConfig": {"PortBindings": {}, "NetworkMode": "none" if role == "scan" else "koda-dashboard"},
                "Mounts": [{"Type": "bind", "RW": True, "Source": str(self.prefix / "data/koda-portal"),
                            "Destination": "/var/lib/koda"}],
            } for role in ("scan", "delivery")
        }

    def test_legacy_dashboard_requires_no_external_workers_and_new_dashboard_checks_both(self):
        with mock.patch.object(preflight, "inspect_json") as inspect:
            preflight.check_portal_workers(self.prefix, {"Config": {"Env": []}})
            inspect.assert_not_called()
        with mock.patch.object(preflight, "inspect_json", side_effect=lambda name: self.records[name]) as inspect:
            preflight.check_portal_workers(self.prefix, self.dashboard)
            self.assertEqual(inspect.call_count, 2)

    def test_incompatible_worker_configuration_blocks_patch(self):
        variants = ("image", "owner", "role", "stopped", "port", "network", "data", "credentials")
        for variant in variants:
            with self.subTest(variant=variant):
                records = copy.deepcopy(self.records)
                scan = records["koda-scan-worker"]
                if variant == "image":
                    scan["Image"] = "sha256:other"
                elif variant in {"owner", "role"}:
                    key = "io.koda.offline" if variant == "owner" else "io.koda.portal-role"
                    scan["Config"]["Labels"][key] = "unexpected"
                elif variant == "stopped":
                    scan["State"]["Status"] = "exited"
                elif variant == "port":
                    scan["HostConfig"]["PortBindings"] = {"8765/tcp": [{"HostPort": "8765"}]}
                elif variant == "network":
                    scan["HostConfig"]["NetworkMode"] = "bridge"
                elif variant == "data":
                    scan["Mounts"][0]["RW"] = False
                elif variant == "credentials":
                    scan["Mounts"].append({"Type": "bind", "RW": False, "Source": str(self.prefix),
                                           "Destination": "/run/secrets/gitlab"})
                with mock.patch.object(preflight, "inspect_json", side_effect=lambda name: records[name]):
                    with self.assertRaises(preflight.PreflightError):
                        preflight.check_portal_workers(self.prefix, self.dashboard)


if __name__ == "__main__":
    unittest.main()
