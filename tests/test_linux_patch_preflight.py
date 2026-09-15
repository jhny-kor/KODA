import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "platforms" / "linux" / "patch"))
import preflight  # noqa: E402


KEYS = {
    "AUTHORITY": "tracker", "AUTH_CONTRACT_VERSION": "1",
    "AUTH_COOKIE_NAME": "__Host-koda_session", "AUTH_COOKIE_SCHEMA_VERSION": "2",
    "TRACKER_SESSION_ENDPOINT": "/api/v1/auth/session", "KODA_BASE_PATH": "/koda/",
    "GATEWAY_AUTH_MODE": "auth_request", "KODA_PORTAL_SCHEMA_VERSION": "1",
    "KODA_RBAC_CATALOG_VERSION": "koda-rbac-v1",
}


class PatchPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.contract = self.root / "contract"
        (self.contract / "tracker" / "gateway").mkdir(parents=True)
        (self.contract / "koda").mkdir()
        self.prefix = self.root / "installed" / "tracker"
        self.prefix.mkdir(parents=True)
        (self.root / "installed" / "koda").mkdir()
        metadata = "\n".join(f"{k}={v}" for k, v in KEYS.items()) + "\n"
        (self.contract / "metadata.env").write_text(metadata)
        (self.root / "installed" / "metadata.env").write_text(metadata)
        (self.prefix / ".env").write_text("COMPOSE_PROJECT_NAME=koda-sbom\n")
        for name in ("compose.yaml", "compose.airgap.yaml", "compose.integration.yaml"):
            (self.contract / "tracker" / name).write_text("services: {}\n")
            (self.prefix / name).write_text("services: {}\n")
        (self.contract / "tracker" / "gateway" / "gateway.conf.template").write_text("server {}\n")
        (self.prefix / "gateway").mkdir()
        (self.prefix / "gateway" / "gateway.conf.template").write_text("server {}\n")
        (self.contract / "koda" / "koda-docker").write_text("#!/bin/sh\n")
        (self.root / "installed" / "koda" / "koda-docker").write_text("#!/bin/sh\n")
        (self.contract / "koda-suite").write_text("#!/bin/sh\n")
        (self.root / "installed" / "koda-suite").write_text("#!/bin/sh\n")
        (self.root / "installed" / "koda" / "image-ref.txt").write_text("koda:test\n")
        (self.root / "installed" / "data" / "koda-portal").mkdir(parents=True)
        (self.contract / "tracker-backend-sha256.json").write_text(json.dumps({"koda_tracker/app.py": "digest"}))

    def tearDown(self):
        self.tmp.cleanup()

    def test_contract_mismatch_aborts_before_docker(self):
        (self.root / "installed" / "metadata.env").write_text(
            "\n".join(f"{k}={('wrong' if k == 'KODA_BASE_PATH' else v)}" for k, v in KEYS.items()) + "\n"
        )
        with patch.object(preflight, "contract_root", return_value=self.contract), patch.object(
            preflight, "command", side_effect=AssertionError("docker must not run")
        ):
            with self.assertRaises(preflight.PreflightError):
                preflight.main(["--prefix", str(self.root / "installed")])

    def test_success_prints_compatibility(self):
        rendered = {"name": "koda-sbom", "services": {name: {"image": f"local/{name}:new"} for name in preflight.APP_SERVICES}}
        records = {
            name: {"Image": "sha256:test", "State": {"Status": "running"}, "Config": {"Image": f"local/{name}:new"}, "Mounts": []}
            for name in preflight.APP_SERVICES
        }
        records["postgres"] = {"State": {"Status": "running"}, "Mounts": []}
        records["koda-dashboard"] = {
            "Image": "sha256:koda", "State": {"Status": "running"},
            "Config": {"Image": "koda:test"},
            "Mounts": [{"Type": "bind", "Source": str((self.root / "installed" / "data" / "koda-portal").resolve()), "Destination": "/var/lib/koda"}],
        }
        def fake_command(args, **kwargs):
            if args[-3:] == ["config", "--format", "json"]:
                return json.dumps(rendered)
            if args[1:4] == ["image", "inspect", "local/portal-web:new"] or args[1:4] == ["image", "inspect", "koda:test"]:
                return json.dumps([{"Os": "linux", "Architecture": "amd64"}])
            if len(args) >= 4 and args[1:3] == ["image", "inspect"]:
                return json.dumps([{"Os": "linux", "Architecture": "amd64"}])
            if args[1] == "exec":
                return json.dumps({"koda_tracker/app.py": "digest"})
            return f"{args[-1]}-id\n"

        with patch.object(preflight, "contract_root", return_value=self.contract), patch.object(
            preflight, "command", side_effect=fake_command
        ), patch.object(preflight, "inspect_json", side_effect=lambda name: records["koda-dashboard"] if name == "koda-dashboard" else records[name.removesuffix("-id")]):
            with patch("builtins.print") as output:
                self.assertEqual(preflight.main(["--prefix", str(self.root / "installed")]), 0)
                self.assertIn("compatibility=passed", [call.args[0] for call in output.call_args_list])

if __name__ == "__main__":
    unittest.main()
