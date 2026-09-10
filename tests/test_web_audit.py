from __future__ import annotations

import base64
import json
import io
import os
import threading
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from security_scanner.web_audit import (
    ApprovalError,
    BudgetExceeded,
    NetworkContext,
    ProfileError,
    ScenarioRunner,
    _run_zap_strategy,
    _zap_scenario_result,
    aggregate_results,
    approve_request,
    build_approval_request,
    canonical_json,
    _finding_payload,
    _read_bounded,
    run_web_audit,
    validate_profile,
    verify_approval,
)
from security_scanner.integrations import build_zap_plan, zap_automation_command
from security_scanner.reporting import (
    render_html_pair_zip_from_payload,
    render_hwpx,
    render_markdown_from_payload,
    render_xlsx,
)


def _profile(origin: str, *, scenarios: list[dict] | None = None) -> dict:
    return {
        "schema_version": 1,
        "target": {
            "environment": "fixture",
            "origins": [origin],
            "include_paths": ["/"],
            "scopes": ["passive", "state_change_free"],
        },
        "limits": {"requests": 40, "timeout_seconds": 10},
        "accounts": {},
        "auth": {},
        "resources": [{"id": "home", "path": "/", "methods": ["GET"], "read_only": True}],
        "scenarios": scenarios or [],
        "oast": {},
        "applicability": {},
    }


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"koda-fixture"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


class _BoastHandler(BaseHTTPRequestHandler):
    calls = 0

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] != "/events":
            self.send_error(404)
            return
        type(self).calls += 1
        payload = {"id": "test-1", "canary": "test-1.callbacks.example.test", "events": []}
        if type(self).calls > 1:
            payload = {"events": [{"testID": "test-1", "receiver": "dns"}]}
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


class _AccessHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        authorization = self.headers.get("Authorization", "")
        if self.path == "/state" and authorization == "Bearer user-a":
            body = b"unchanged-state"
            status = 200
        elif self.path == "/private" and authorization == "Bearer user-a":
            body = b"private-user-a"
            status = 200
        elif self.path == "/private":
            body = b"denied"
            status = 403
        else:
            body = b"ok"
            status = 200
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


class _JsonAuthHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/login":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if payload != {"username": "tester", "password": "correct"}:
            self.send_error(401)
            return
        body = b'{"access_token":"audit-token-not-for-report"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/private":
            self.send_error(404)
            return
        if self.headers.get("Authorization") != "Bearer audit-token-not-for-report":
            self.send_error(401)
            return
        body = b"authenticated"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


class _UploadHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        status = 201 if self.headers.get("Content-Type", "").startswith("multipart/form-data; boundary=") else 400
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_DELETE(self) -> None:  # noqa: N802
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(403)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        return


class _StatefulHandler(BaseHTTPRequestHandler):
    value = 0

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/state":
            self.send_error(404)
            return
        body = str(type(self).value).encode("ascii")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/unsafe":
            type(self).value += 1
        self.send_response(403)
        self.end_headers()

    def do_DELETE(self) -> None:  # noqa: N802
        type(self).value = 0
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        return


class _MethodHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.end_headers()

    def do_TRACE(self) -> None:  # noqa: N802
        self.send_response(405)
        self.end_headers()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.end_headers()

    def do_PUT(self) -> None:  # noqa: N802
        self.send_response(204)
        self.end_headers()

    def do_DELETE(self) -> None:  # noqa: N802
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        return


class WebAuditTests(unittest.TestCase):
    def test_response_body_deadline_fails_closed(self) -> None:
        class SlowBody:
            def read1(self, _amount):
                return b"x"

        with patch("security_scanner.web_audit.time.monotonic", side_effect=[0.0, 0.04, 0.08]):
            with self.assertRaises(BudgetExceeded):
                _read_bounded(SlowBody(), 10, timeout=0.05)

    def test_all_declared_strategies_are_executed(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            profile = validate_profile(_profile(origin, scenarios=[{
                "id": "multi-strategy",
                "control_id": "web.authentication",
                "strategies": ["koda-scenario", "timing"],
                "steps": [
                    {
                        "id": "baseline",
                        "resource": "home",
                        "method": "GET",
                        "state_snapshot": True,
                        "assertions": [{"type": "status", "equals": 200}],
                    },
                    {
                        "resource": "home",
                        "method": "GET",
                        "assertions": [{"type": "response_time_delta_max_ms", "max_ms": 5000}],
                    },
                ],
            }]))
            request = build_approval_request(profile)
            approval = approve_request(request, "operator", key="test-key")
            with TemporaryDirectory() as directory:
                audit = run_web_audit(profile, approval, confirm_origin=origin, key="test-key", state_dir=Path(directory))
            result = next(item for item in audit["controls"] if item["id"] == "web.authentication")["strategy_results"][0]
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["coverage"], {"required": 2, "completed": 2})
            self.assertEqual({item["strategy"] for item in result["strategy_results"]}, {"koda-scenario", "timing"})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_state_oracle_without_a_baseline_needs_review(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            profile = validate_profile(_profile(origin, scenarios=[{
                "id": "missing-state-baseline",
                "control_id": "web.process-validation",
                "steps": [{"resource": "home", "method": "GET"}],
                "oracle": {"state_unchanged": True},
            }]))
            result = ScenarioRunner(profile, NetworkContext(profile, build_approval_request(profile))).run(profile["scenarios"][0])
            self.assertEqual(result["status"], "NEEDS_REVIEW")
            self.assertEqual(result["reason_code"], "oracle_incomplete")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_state_strategy_compares_named_snapshot_before_and_after_mutation(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _StatefulHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            for action, expected in (("/safe", "PASS"), ("/unsafe", "VULNERABLE")):
                _StatefulHandler.value = 0
                profile = _profile(origin, scenarios=[{
                    "id": f"state-{action[1:]}",
                    "control_id": "web.csrf",
                    "strategies": ["state"],
                    "steps": [{
                        "id": "baseline",
                        "resource": "state",
                        "method": "GET",
                        "state_snapshot": True,
                        "assertions": [{"type": "status", "equals": 200}],
                    }],
                    "mutations": [{
                        "resource": "action",
                        "method": "POST",
                        "assertions": [{"type": "status", "equals": 403}],
                    }, {
                        "resource": "state",
                        "method": "GET",
                        "assertions": [{"type": "state_unchanged", "snapshot": "baseline"}],
                    }],
                    "cleanup": [{"resource": "state", "method": "DELETE"}],
                }])
                profile["target"]["scopes"] = ["state_change"]
                profile["resources"] = [
                    {"id": "state", "path": "/state", "methods": ["GET", "DELETE"]},
                    {"id": "action", "path": action, "methods": ["POST"]},
                ]
                profile = validate_profile(profile)
                runner = ScenarioRunner(profile, NetworkContext(profile, build_approval_request(profile)))
                result = runner.run_state(profile["scenarios"][0])
                self.assertEqual(result["status"], expected)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_http_method_strategy_uses_declared_probe_methods(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _MethodHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            for probe_method, expected in (("TRACE", "PASS"), ("OPTIONS", "PASS"), ("PUT", "VULNERABLE")):
                profile = _profile(origin, scenarios=[{
                    "id": f"method-{probe_method.lower()}",
                    "control_id": "web.http-methods",
                    "strategies": ["http-methods"],
                    "steps": [{"resource": "method", "method": "GET"}],
                    "cleanup": [{"resource": "method", "method": "DELETE"}],
                }])
                profile["target"]["scopes"] = ["state_change"]
                profile["resources"] = [{
                    "id": "method", "path": "/", "methods": ["GET", "DELETE"], "probe_methods": [probe_method],
                }]
                profile = validate_profile(profile)
                runner = ScenarioRunner(profile, NetworkContext(profile, build_approval_request(profile)))
                result = runner.run_http_methods(profile["scenarios"][0])
                self.assertEqual(result["status"], expected)
                self.assertEqual(result["coverage"]["required"], 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_access_matrix_and_multipart_upload_are_executable(self) -> None:
        access_server = ThreadingHTTPServer(("127.0.0.1", 0), _AccessHandler)
        upload_server = ThreadingHTTPServer(("127.0.0.1", 0), _UploadHandler)
        access_thread = threading.Thread(target=access_server.serve_forever, daemon=True)
        upload_thread = threading.Thread(target=upload_server.serve_forever, daemon=True)
        access_thread.start()
        upload_thread.start()
        try:
            access_origin = f"http://127.0.0.1:{access_server.server_port}"
            access_profile = _profile(access_origin, scenarios=[{
                "id": "access-matrix",
                "control_id": "web.authorization",
                "strategies": ["access-control"],
                "steps": [{"resource": "private", "method": "GET"}],
            }])
            access_profile["accounts"] = {"userA": {"id": "userA", "role": "user", "headers": {"Authorization": "${ENV:KODA_USER_A_AUTH}"}}}
            access_profile["resources"] = [{
                "id": "private", "path": "/private", "methods": ["GET"],
                "actors": ["anonymous", "userA"],
                "access": {
                    "anonymous": {
                        "status": "deny",
                        "state_unchanged": True,
                        "state_resource": "state",
                        "state_account": "userA",
                    },
                    "userA": "allow",
                },
            }, {
                "id": "state", "path": "/state", "methods": ["GET"], "read_only": True,
            }]
            access_profile = validate_profile(access_profile)
            access_runner = ScenarioRunner(access_profile, NetworkContext(access_profile, build_approval_request(access_profile)))
            with patch.dict(os.environ, {"KODA_USER_A_AUTH": "Bearer user-a"}):
                access_result = access_runner.run_access_matrix(access_profile["scenarios"][0])
            self.assertEqual(access_result["status"], "PASS")
            self.assertEqual(access_result["coverage"], {"required": 2, "completed": 2})

            upload_origin = f"http://127.0.0.1:{upload_server.server_port}"
            upload_profile = _profile(upload_origin, scenarios=[{
                "id": "inert-upload",
                "control_id": "web.file-upload",
                "strategies": ["upload"],
                "steps": [{
                    "resource": "upload", "method": "POST", "body_type": "multipart",
                    "body": {"fields": {"label": "canary"}, "file": {
                        "field": "file", "filename": "probe.jpg.php", "content_type": "image/jpeg", "content": "KODA-INERT-CANARY",
                    }},
                    "assertions": [{"type": "status", "equals": 201}, {"type": "body_contains", "value": "probe.jpg.php"}],
                }, {
                    "resource": "upload", "method": "GET",
                    "assertions": [{"type": "status", "equals": 403}],
                }],
                "cleanup": [{"resource": "upload", "method": "DELETE"}],
            }])
            upload_profile["target"]["scopes"] = ["state_change"]
            upload_profile["resources"] = [{"id": "upload", "path": "/upload", "methods": ["GET", "POST", "DELETE"]}]
            upload_profile = validate_profile(upload_profile)
            upload_runner = ScenarioRunner(upload_profile, NetworkContext(upload_profile, build_approval_request(upload_profile)))
            upload_result = upload_runner.run_upload(upload_profile["scenarios"][0])
            self.assertEqual(upload_result["status"], "PASS")
        finally:
            access_server.shutdown()
            access_server.server_close()
            upload_server.shutdown()
            upload_server.server_close()
            access_thread.join(timeout=2)
            upload_thread.join(timeout=2)

    def test_json_authentication_is_used_by_scenarios_and_redacted(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _JsonAuthHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            profile = _profile(origin, scenarios=[{
                "id": "authenticated-resource",
                "control_id": "web.authentication",
                "strategies": ["koda-scenario"],
                "steps": [{"resource": "private", "method": "GET", "assertions": [{"type": "status", "equals": 200}]}],
            }])
            profile["target"]["scopes"] = ["state_change"]
            profile["target"]["include_paths"] = ["/private"]
            profile["resources"] = [{"id": "private", "path": "/private", "methods": ["GET"], "read_only": True}]
            profile["auth"] = {
                "method": "json", "login_url": f"{origin}/login", "username_env": "KODA_TEST_USER",
                "password_env": "KODA_TEST_PASSWORD", "token_json_path": "access_token",
            }
            profile = validate_profile(profile)
            request = build_approval_request(profile)
            approval = approve_request(request, "operator", key="test-key")
            with TemporaryDirectory() as directory, patch.dict(os.environ, {"KODA_TEST_USER": "tester", "KODA_TEST_PASSWORD": "correct"}):
                result = run_web_audit(profile, approval, confirm_origin=origin, key="test-key", state_dir=Path(directory))
            self.assertEqual(result["auth"]["status"], "PASS")
            self.assertEqual(result["controls"][9]["status"], "PASS")
            self.assertNotIn("audit-token-not-for-report", json.dumps(result))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_zap_active_scan_uses_declared_envelope(self) -> None:
        plan = build_zap_plan(
            "https://fixture.example",
            minutes=15,
            active_scan=True,
            zap_rps=2,
            zap_threads_per_host=1,
            zap_rule_minutes=2,
            max_response_bytes=2097152,
        )
        active = next(job for job in plan["jobs"] if job["type"] == "activeScan")
        self.assertEqual(
            active["parameters"],
            {
                "context": "koda",
                "maxScanDurationInMins": 15,
                "delayInMs": 500,
                "threadPerHost": 1,
                "maxRuleDurationInMins": 2,
            },
        )
        spider = next(job for job in plan["jobs"] if job["type"] == "spider")
        self.assertEqual(spider["parameters"]["threadCount"], 1)
        self.assertEqual(spider["parameters"]["maxParseSizeBytes"], 2097152)
        exit_status = next(job for job in plan["jobs"] if job["type"] == "exitStatus")
        self.assertEqual(exit_status["parameters"]["warnLevel"], "Low")
        self.assertIn("--pull never", zap_automation_command("/tmp/zap", pull_never=True))

    def test_zap_auth_uses_container_environment_references(self) -> None:
        plan = build_zap_plan(
            "https://fixture.example",
            auth={
                "method": "json",
                "login_url": "https://fixture.example/login",
                "username_env": "KODA_ZAP_USER",
                "password_env": "KODA_ZAP_PASSWORD",
                "token_json_path": "access_token",
                "session_header": "Authorization",
                "token_prefix": "Bearer ",
            },
        )
        context = plan["env"]["contexts"][0]
        self.assertEqual(context["authentication"]["method"], "json")
        self.assertEqual(context["users"][0]["credentials"]["username"], "${KODA_ZAP_USER}")
        self.assertEqual(context["users"][0]["credentials"]["password"], "${KODA_ZAP_PASSWORD}")
        self.assertEqual(
            context["sessionManagement"],
            {"method": "headers", "parameters": {"Authorization": "Bearer {%json:access_token%}"}},
        )

        header_plan = build_zap_plan(
            "https://fixture.example",
            auth={"method": "header", "header_envs": {"Authorization": "KODA_ZAP_AUTH"}},
        )
        header_context = header_plan["env"]["contexts"][0]
        self.assertEqual(header_context["authentication"]["method"], "manual")
        self.assertEqual(
            header_context["sessionManagement"],
            {"method": "headers", "parameters": {"Authorization": "{%env:KODA_ZAP_AUTH%}"}},
        )
        command = zap_automation_command(
            "/tmp/zap",
            environment_vars=("KODA_ZAP_AUTH", "KODA_ZAP_PASSWORD"),
            pull_never=True,
        )
        self.assertIn("-e KODA_ZAP_AUTH", command)
        self.assertIn("-e KODA_ZAP_PASSWORD", command)

    def test_oast_requires_an_approved_control_plane_ip(self) -> None:
        profile = _profile("https://example.test")
        profile["target"]["scopes"] = ["oast"]
        profile["oast"] = {
            "control_plane_origin": "https://boast.example.test",
            "callback_domain": "callbacks.example.test",
        }
        with self.assertRaises(ProfileError):
            validate_profile(profile)

    def test_app_store_never_runs_external_zap(self) -> None:
        profile = _profile("https://127.0.0.1", scenarios=[{
            "id": "app-store-zap",
            "control_id": "web.information-disclosure",
            "strategies": ["zap-passive"],
            "steps": [{"resource": "home", "method": "GET"}],
        }])
        profile["target"]["distribution"] = "app_store"
        profile["target"]["zap"] = {
            "enabled": True,
            "image": "ghcr.io/zaproxy/zaproxy@sha256:" + "a" * 64,
            "addon_manifest": {"automation": "sha256:" + "b" * 64},
        }
        profile = validate_profile(profile)
        network = NetworkContext(profile, build_approval_request(profile))
        findings, zap_result = _run_zap_strategy(
            profile,
            network,
            {"zap": {"available": True}},
            output_dir=None,
        )
        self.assertEqual(findings, [])
        self.assertEqual(zap_result["reason_code"], "distribution_read_only")
        scenario_result = _zap_scenario_result(
            profile["scenarios"][0],
            "zap-passive",
            zap_result,
            findings,
            {"zap": {"available": True}},
        )
        self.assertEqual(scenario_result["status"], "UNSUPPORTED")

    def test_profile_is_strict_and_canonical(self) -> None:
        profile = validate_profile(_profile("https://example.test"))
        self.assertEqual(profile["schema_version"], 1)
        self.assertEqual(canonical_json(profile), canonical_json(json.loads(json.dumps(profile))))

        profile["resources"][0]["probe_methods"] = ["TRACE"]
        self.assertEqual(validate_profile(profile)["resources"][0]["probe_methods"], ["TRACE"])
        profile["resources"][0]["methods"] = ["GET", "TRACE"]
        with self.assertRaises(ProfileError):
            validate_profile(profile)

        with self.assertRaises(ProfileError):
            validate_profile({**_profile("https://example.test"), "unexpected": True})
        with self.assertRaises(ProfileError):
            validate_profile({**_profile("https://example.test"), "auth": {"password": "plaintext"}})
        with self.assertRaises(ProfileError):
            validate_profile({**_profile("https://example.test"), "scenarios": [{"shell": "id"}]})

    def test_approval_is_signed_and_one_time(self) -> None:
        profile = _profile("http://127.0.0.1:8765")
        now = datetime(2026, 8, 2, tzinfo=timezone.utc)
        request = build_approval_request(profile, now=now)
        approval = approve_request(request, "operator", key="test-key", now=now + timedelta(minutes=1))
        with TemporaryDirectory() as directory:
            state_dir = Path(directory)
            verified = verify_approval(
                profile,
                approval,
                confirm_origin="http://127.0.0.1:8765",
                key="test-key",
                state_dir=state_dir,
                now=now + timedelta(minutes=2),
            )
            self.assertEqual(verified["profile_sha256"], request["profile_sha256"])
            with self.assertRaises(ApprovalError):
                verify_approval(
                    profile,
                    approval,
                    confirm_origin="http://127.0.0.1:8765",
                    key="test-key",
                    state_dir=state_dir,
                    now=now + timedelta(minutes=3),
                )

    def test_approval_expiry_is_signed(self) -> None:
        origin = "http://127.0.0.1:1"
        profile = _profile(origin)
        issued = datetime(2026, 1, 1, tzinfo=timezone.utc)
        request = build_approval_request(profile, now=issued)
        approval = approve_request(request, "tester", key="test-key", now=issued + timedelta(minutes=1))
        approval["expires_at"] = "2036-01-01T00:00:00Z"
        with self.assertRaises(ApprovalError):
            verify_approval(
                profile,
                approval,
                confirm_origin=origin,
                key="test-key",
                consume=False,
                now=issued + timedelta(minutes=2),
            )

    def test_pinned_opener_and_declared_oracle(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            scenario = {
                "id": "home-oracle",
                "control_id": "web.authentication",
                "strategies": ["koda-scenario"],
                "steps": [{
                    "id": "read-home",
                    "resource": "home",
                    "method": "GET",
                    "assertions": [{"type": "status", "equals": 200}, {"type": "body_contains", "value": "koda-fixture"}],
                }],
            }
            profile = validate_profile(_profile(origin, scenarios=[scenario]))
            request = build_approval_request(profile)
            network = NetworkContext(profile, request)
            result = ScenarioRunner(profile, network).run(profile["scenarios"][0])
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["coverage"], {"required": 1, "completed": 1})
            self.assertGreaterEqual(network.request_count, 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_clean_without_declared_oracle_is_not_pass(self) -> None:
        profile = validate_profile(_profile("https://example.test"))
        controls = aggregate_results(profile, passive_completed=True)
        self.assertEqual(len(controls), 21)
        self.assertTrue(all(item["status"] == "NOT_SCANNED" for item in controls))

    def test_passive_strategy_without_oracle_is_not_pass(self) -> None:
        profile = validate_profile(_profile("https://example.test", scenarios=[{
            "id": "passive-without-oracle",
            "control_id": "web.information-disclosure",
            "strategies": ["passive"],
            "steps": [{"resource": "home", "method": "GET", "assertions": []}],
        }]))
        info = next(item for item in aggregate_results(profile, passive_completed=True) if item["id"] == "web.information-disclosure")
        self.assertEqual(info["status"], "NOT_SCANNED")

    def test_unknown_assertion_requires_review(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            scenario = {
                "id": "unknown-oracle",
                "control_id": "web.authentication",
                "strategies": ["koda-scenario"],
                "steps": [{
                    "resource": "home",
                    "method": "GET",
                    "assertions": [{"type": "future_assertion"}],
                }],
            }
            profile = validate_profile(_profile(origin, scenarios=[scenario]))
            result = ScenarioRunner(profile, NetworkContext(profile, build_approval_request(profile))).run(profile["scenarios"][0])
            self.assertEqual(result["status"], "NEEDS_REVIEW")
            self.assertEqual(result["reason_code"], "oracle_incomplete")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_source_only_is_unsupported_without_traffic(self) -> None:
        profile = validate_profile(_profile("http://127.0.0.1:8765"))
        request = build_approval_request(profile)
        approval = approve_request(request, "operator", key="test-key")
        with TemporaryDirectory() as directory, patch.dict(os.environ, {"KODA_SOURCE_ONLY": "1"}):
            result = run_web_audit(
                profile,
                approval,
                confirm_origin="http://127.0.0.1:8765",
                key="test-key",
                state_dir=Path(directory),
            )
        self.assertEqual(result["status"], "UNSUPPORTED")
        self.assertEqual(result["traffic"]["requests"], 0)
        self.assertTrue(all(item["status"] == "UNSUPPORTED" for item in result["controls"]))

    def test_boast_callback_is_vulnerable_and_is_pinned(self) -> None:
        target_server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        boast_server = ThreadingHTTPServer(("127.0.0.1", 0), _BoastHandler)
        target_thread = threading.Thread(target=target_server.serve_forever, daemon=True)
        boast_thread = threading.Thread(target=boast_server.serve_forever, daemon=True)
        target_thread.start()
        boast_thread.start()
        try:
            _BoastHandler.calls = 0
            target_origin = f"http://127.0.0.1:{target_server.server_port}"
            boast_origin = f"http://127.0.0.1:{boast_server.server_port}"
            profile = _profile(target_origin, scenarios=[{
                "id": "ssrf-callback",
                "control_id": "web.ssrf",
                "strategies": ["oast"],
                "steps": [{
                    "resource": "home",
                    "method": "GET",
                    "query": {"url": "http://${CAPTURE:OAST_PAYLOAD}"},
                    "assertions": [{"type": "status", "equals": 200}],
                }],
            }])
            profile["target"]["scopes"] = ["passive", "oast", "state_change_free"]
            profile["limits"].update({"requests": 40, "timeout_seconds": 5, "max_rps": 20, "oast_poll_seconds": 1})
            profile["oast"] = {
                "control_plane_origin": boast_origin,
                "callback_domain": "callbacks.example.test",
                "allowed_ips": ["127.0.0.1"],
                "poll_seconds": 1,
            }
            profile = validate_profile(profile)
            request = build_approval_request(profile)
            approval = approve_request(request, "operator", key="test-key")
            encoded_oast_secret = base64.b64encode(b"test-secret").decode("ascii")
            with TemporaryDirectory() as directory, patch.dict(
                os.environ, {"KODA_OAST_SECRET": encoded_oast_secret}
            ):
                result = run_web_audit(
                    profile,
                    approval,
                    confirm_origin=target_origin,
                    key="test-key",
                    state_dir=Path(directory),
                )
            self.assertEqual(result["status"], "VULNERABLE")
            self.assertEqual(result["traffic"]["oast_callbacks"], 1)
            ssrf = next(item for item in result["controls"] if item["id"] == "web.ssrf")
            self.assertEqual(ssrf["status"], "VULNERABLE")
            self.assertNotIn(encoded_oast_secret, json.dumps(result))
        finally:
            target_server.shutdown()
            target_server.server_close()
            boast_server.shutdown()
            boast_server.server_close()
            target_thread.join(timeout=2)
            boast_thread.join(timeout=2)

    def test_dynamic_finding_redacts_secret_and_query(self) -> None:
        secret = "s" * 64
        safe = _finding_payload({
            "rule_id": "web.test",
            "path": f"https://example.test/account?token={secret}#secret",
            "evidence": f"Authorization: Bearer {secret}",
            "headers": {"Authorization": secret},
            "raw": "request/response",
        })
        self.assertEqual(safe["path"], "https://example.test/account")
        self.assertNotIn(secret, json.dumps(safe))
        self.assertNotIn("headers", safe)
        self.assertNotIn("raw", safe)

    def test_explicit_not_applicable_is_preserved(self) -> None:
        profile = _profile("https://example.test")
        profile["applicability"] = {"web.ssrf": {"status": "NOT_APPLICABLE", "reason": "no URL input exists"}}
        controls = aggregate_results(validate_profile(profile))
        ssrf = next(item for item in controls if item["id"] == "web.ssrf")
        self.assertEqual(ssrf["status"], "NOT_APPLICABLE")
        self.assertEqual(ssrf["reason_code"], "profile_not_applicable")

    def test_all_export_formats_keep_the_21_control_surface(self) -> None:
        controls = aggregate_results(validate_profile(_profile("https://example.test")))
        payload = {
            "findings": [],
            "web_audit": {
                "kind": "koda.web-audit.result",
                "status": "NOT_SCANNED",
                "controls": controls,
                "traffic": {"requests": 0, "pages": 0},
            },
        }
        markdown = render_markdown_from_payload(payload, "ko")
        self.assertEqual(markdown.count("`web."), 21)
        self.assertIn("웹취약점 21개 항목 자동 점검", markdown)

        with zipfile.ZipFile(io.BytesIO(render_html_pair_zip_from_payload(payload, "ko"))) as archive:
            self.assertIn("web-audit-results", archive.read("report.html").decode("utf-8"))
            self.assertIn("web.file-upload", archive.read("report-detail.html").decode("utf-8"))

        with zipfile.ZipFile(io.BytesIO(render_xlsx(payload, "ko"))) as archive:
            workbook = archive.read("xl/workbook.xml").decode("utf-8")
            self.assertIn("WebAudit", workbook)
            self.assertIn("web.file-upload", archive.read("xl/worksheets/sheet2.xml").decode("utf-8"))

        with zipfile.ZipFile(io.BytesIO(render_hwpx(payload, "ko"))) as archive:
            section = archive.read("Contents/section0.xml").decode("utf-8")
            self.assertIn("web.file-upload", section)


if __name__ == "__main__":
    unittest.main()
