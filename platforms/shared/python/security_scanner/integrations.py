from __future__ import annotations

import json
import math
import os
import re
import shlex
import uuid
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


# Default image; override via KODA_ZAP_IMAGE to pin a reproducible tag or, for
# closed networks, a locally-imported digest (e.g. ghcr.io/zaproxy/zaproxy@sha256:...).
_DEFAULT_ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
# Docker image reference: repo:tag, or repo@sha256:<64 hex>.
_ZAP_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*(:[A-Za-z0-9._-]+|@sha256:[0-9a-f]{64})$")


def zap_image(image: str | None = None) -> str:
    """The ZAP Docker image, overridable via ``KODA_ZAP_IMAGE`` for pinning/offline."""
    selected = (image or os.environ.get("KODA_ZAP_IMAGE", "").strip() or _DEFAULT_ZAP_IMAGE).strip()
    if not _ZAP_IMAGE_RE.match(selected):
        raise ValueError(f"Invalid ZAP image reference: {selected!r}")
    return selected


# ZAP packaged-scan scripts. baseline = passive spider; full = active attack
# scan; api = spec-driven (OpenAPI/GraphQL/SOAP) active scan.
_ZAP_SCRIPTS = {"baseline": "zap-baseline.py", "full": "zap-full-scan.py", "api": "zap-api-scan.py"}
ZAP_REPORT_PREFIX = {"baseline": "zap-baseline", "full": "zap-full-scan", "api": "zap-api-scan"}
_ZAP_ACTIVE_MODES = {"full", "api"}
_ZAP_MIN_LEVELS = {"PASS", "IGNORE", "INFO", "WARN", "FAIL"}
_ZAP_API_FORMATS = {"openapi", "soap", "graphql"}
_ZAP_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


def zap_scan_command(
    target_url: str,
    *,
    mode: str = "baseline",
    output_dir: str = "reports/zap",
    minutes: int = 1,
    context_file: str | None = None,
    user: str | None = None,
    min_level: str | None = None,
    api_format: str | None = None,
    fail_on_warn: bool = True,
) -> str:
    """Build a ZAP Docker command for the given scan mode.

    ``context_file`` (a ZAP .context filename that must already sit in
    ``output_dir``, which is mounted as /zap/wrk) plus ``user`` drive
    authenticated scanning. ``mode='api'`` runs ``zap-api-scan.py`` against an
    OpenAPI/GraphQL/SOAP spec (``api_format``). Active modes (full/api) send
    attack traffic — callers must gate them behind explicit authorization.
    """

    if mode not in _ZAP_SCRIPTS:
        raise ValueError(f"Unsupported ZAP mode: {mode}")
    _require_http_url(target_url, label="target URL")
    if mode in {"baseline", "full"} and minutes <= 0:
        raise ValueError("minutes must be positive")
    output_path = output_dir.rstrip("/") or "reports/zap"
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", output_path):
        raise ValueError("output_dir may only contain letters, numbers, slash, dot, dash, and underscore")
    mount_path = output_path if output_path.startswith("/") else f"$PWD/{output_path}"
    prefix = ZAP_REPORT_PREFIX[mode]

    scan_args: list[str] = ["-t", shlex.quote(target_url)]
    if mode in {"baseline", "full"}:
        scan_args += ["-m", str(minutes)]
    if mode == "api":
        fmt = api_format or "openapi"
        if fmt not in _ZAP_API_FORMATS:
            raise ValueError(f"Unsupported api_format: {fmt}")
        scan_args += ["-f", fmt]
    if context_file:
        if not _ZAP_SAFE_NAME.match(context_file):
            raise ValueError("context_file must be a bare filename placed in output_dir")
        scan_args += ["-n", shlex.quote(context_file)]
    if user:
        scan_args += ["-U", shlex.quote(user)]
    if min_level:
        if min_level not in _ZAP_MIN_LEVELS:
            raise ValueError(f"min_level must be one of {sorted(_ZAP_MIN_LEVELS)}")
        scan_args += ["-l", min_level]
    if not fail_on_warn:
        scan_args += ["-I"]
    scan_args += ["-r", f"{prefix}.html", "-w", f"{prefix}.md", "-J", f"{prefix}.json"]

    return " ".join(
        [
            "mkdir", "-p", shlex.quote(output_path), "&&",
            "docker", "run", "--rm", "-t",
            "-v", f'"{mount_path}:/zap/wrk:rw"',
            shlex.quote(zap_image()),
            _ZAP_SCRIPTS[mode],
            *scan_args,
        ]
    )


def zap_baseline_command(target_url: str, *, output_dir: str = "reports/zap", minutes: int = 1) -> str:
    """Passive baseline scan (back-compat wrapper over :func:`zap_scan_command`)."""
    return zap_scan_command(target_url, mode="baseline", output_dir=output_dir, minutes=minutes)


# --- ZAP Automation Framework (YAML plan) -------------------------------------

ZAP_AUTOMATION_REPORT_PREFIX = "zap-automation"
_ZAP_AF_AUTH_METHODS = {"form", "json", "header"}
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def build_zap_plan(
    target_url: str,
    *,
    minutes: int = 1,
    ajax_spider: bool = False,
    active_scan: bool = False,
    include_paths: tuple[str, ...] = (),
    exclude_paths: tuple[str, ...] = (),
    openapi_url: str | None = None,
    openapi_file: str | None = None,
    auth: dict[str, object] | None = None,
    zap_rps: float | None = None,
    zap_threads_per_host: int | None = None,
    zap_rule_minutes: int | None = None,
    max_response_bytes: int | None = None,
    fail_on_error: bool = True,
) -> dict:
    """Build a ZAP Automation Framework plan (a dict; emit as JSON — valid YAML).

    Sequences spider (+ optional ajaxSpider), passive scan, and an optional
    activeScan inside a context. ``auth`` (form/json/header) enables
    authenticated scanning; ``openapi_url``/``openapi_file`` import an OpenAPI
    definition as a job. Reports are written to /zap/wrk for the caller to parse.
    """

    _require_http_url(target_url, label="target URL")
    context: dict = {"name": "koda", "urls": [target_url]}
    if include_paths:
        context["includePaths"] = list(include_paths)
    if exclude_paths:
        context["excludePaths"] = list(exclude_paths)

    user_name = None
    if auth:
        method = auth.get("method", "form")
        if method not in _ZAP_AF_AUTH_METHODS:
            raise ValueError(f"auth method must be one of {sorted(_ZAP_AF_AUTH_METHODS)}")
        if method == "header":
            header_envs = auth.get("header_envs")
            if not isinstance(header_envs, dict) or not header_envs:
                raise ValueError("header auth requires header_envs")
            parameters: dict[str, str] = {}
            for header_name, env_name in header_envs.items():
                if not _ENV_NAME_RE.fullmatch(str(env_name)):
                    raise ValueError("header auth environment names are invalid")
                parameters[str(header_name)] = f"{{%env:{env_name}%}}"
            context["authentication"] = {"method": "manual", "parameters": {}, "verification": {"method": "response"}}
            context["sessionManagement"] = {"method": "headers", "parameters": parameters}
        else:
            login_url = auth.get("login_url") or ""
            if not login_url:
                raise ValueError("auth requires 'login_url'")
            user_name = "koda-user"
            context["authentication"] = {
                "method": method,
                "parameters": {
                    "loginPageUrl": login_url,
                    "loginRequestUrl": auth.get("login_request_url") or login_url,
                    "loginRequestBody": auth.get("login_body")
                    or (
                        '{"username":"{%username%}","password":"{%password%}"}'
                        if method == "json"
                        else "username={%username%}&password={%password%}"
                    ),
                },
                "verification": {
                    "method": "response",
                    "loggedInRegex": auth.get("logged_in_regex") or "",
                    "loggedOutRegex": auth.get("logged_out_regex") or "",
                },
            }
            token_json_path = str(auth.get("token_json_path") or "")
            if token_json_path:
                session_header = str(auth.get("session_header") or "Authorization")
                token_prefix = str(auth.get("token_prefix") or "Bearer ")
                context["sessionManagement"] = {
                    "method": "headers",
                    "parameters": {
                        session_header: f"{token_prefix}{{%json:{token_json_path}%}}",
                    },
                }
            else:
                context["sessionManagement"] = {"method": "cookie"}
            context["users"] = [
                {
                    "name": user_name,
                    "credentials": {
                        "username": (
                            f"${{{auth['username_env']}}}"
                            if auth.get("username_env")
                            else auth.get("username") or ""
                        ),
                        "password": (
                            f"${{{auth['password_env']}}}"
                            if auth.get("password_env")
                            else auth.get("password") or ""
                        ),
                    },
                }
            ]

    def _with_user(params: dict) -> dict:
        if user_name:
            params["user"] = user_name
        return params

    jobs: list[dict] = []
    if openapi_url or openapi_file:
        params = {"targetUrl": target_url}
        if openapi_url:
            params["apiUrl"] = openapi_url
        if openapi_file:
            if not _ZAP_SAFE_NAME.match(openapi_file):
                raise ValueError("openapi_file must be a bare filename placed in output_dir")
            params["apiFile"] = openapi_file
        jobs.append({"type": "openapi", "parameters": params})

    if zap_threads_per_host is not None and zap_threads_per_host <= 0:
        raise ValueError("zap_threads_per_host must be positive")
    if max_response_bytes is not None and max_response_bytes <= 0:
        raise ValueError("max_response_bytes must be positive")
    spider_parameters = {"context": "koda", "url": target_url, "maxDuration": minutes}
    if zap_threads_per_host is not None:
        spider_parameters["threadCount"] = int(zap_threads_per_host)
    if max_response_bytes is not None:
        spider_parameters["maxParseSizeBytes"] = int(max_response_bytes)
    jobs.append({"type": "spider", "parameters": _with_user(spider_parameters)})
    if ajax_spider:
        ajax_parameters = {
            "context": "koda",
            "url": target_url,
            "maxDuration": minutes,
            "inScopeOnly": True,
        }
        if zap_threads_per_host is not None:
            ajax_parameters["numberOfBrowsers"] = int(zap_threads_per_host)
        jobs.append({"type": "spiderAjax", "parameters": _with_user(ajax_parameters)})
    jobs.append({"type": "passiveScan-wait", "parameters": {}})
    if active_scan:
        active_parameters = {"context": "koda", "maxScanDurationInMins": minutes}
        if zap_rps is not None:
            if zap_rps <= 0:
                raise ValueError("zap_rps must be positive")
            active_parameters["delayInMs"] = max(1, math.ceil(1000 / float(zap_rps)))
        if zap_threads_per_host is not None:
            active_parameters["threadPerHost"] = int(zap_threads_per_host)
        if zap_rule_minutes is not None:
            if zap_rule_minutes <= 0:
                raise ValueError("zap_rule_minutes must be positive")
            active_parameters["maxRuleDurationInMins"] = int(zap_rule_minutes)
        jobs.append({"type": "activeScan", "parameters": _with_user(active_parameters)})
    for template in ("traditional-json", "traditional-html", "traditional-md"):
        jobs.append(
            {
                "type": "report",
                "parameters": {
                    "template": template,
                    "reportDir": "/zap/wrk",
                    "reportFile": ZAP_AUTOMATION_REPORT_PREFIX,
                },
            }
        )
    jobs.append(
        {
            "type": "exitStatus",
            "parameters": {
                "warnLevel": "Low",
                "errorLevel": "High",
                "okExitValue": 0,
                "errorExitValue": 1,
                "warnExitValue": 2,
            },
        }
    )

    return {
        "env": {
            "contexts": [context],
            "parameters": {"failOnError": fail_on_error, "failOnWarning": False, "progressToStdout": True},
        },
        "jobs": jobs,
    }


def render_zap_plan(plan: dict) -> str:
    """Serialize a plan as JSON (a valid YAML document ZAP's parser accepts)."""
    return json.dumps(plan, indent=2, ensure_ascii=False)


def zap_automation_command(
    output_dir: str = "reports/zap",
    *,
    plan_filename: str = "koda-zap-plan.yaml",
    image: str | None = None,
    host_mappings: tuple[tuple[str, str], ...] = (),
    environment_vars: tuple[str, ...] = (),
    pull_never: bool = False,
) -> str:
    """Docker command that runs a ZAP Automation Framework plan from ``output_dir``."""
    output_path = output_dir.rstrip("/") or "reports/zap"
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", output_path):
        raise ValueError("output_dir may only contain letters, numbers, slash, dot, dash, and underscore")
    if not _ZAP_SAFE_NAME.match(plan_filename):
        raise ValueError("plan_filename must be a bare filename")
    mount_path = output_path if output_path.startswith("/") else f"$PWD/{output_path}"
    docker_args = ["docker", "run", "--rm", "-t"]
    if pull_never:
        docker_args.extend(["--pull", "never"])
    for name in environment_vars:
        if not _ENV_NAME_RE.fullmatch(name):
            raise ValueError("environment_vars must contain valid environment variable names")
        docker_args.extend(["-e", shlex.quote(name)])
    for host, address in host_mappings:
        if not _ZAP_SAFE_NAME.match(host) or not re.fullmatch(r"[0-9A-Fa-f:.]+", address):
            raise ValueError("host_mappings must contain a hostname and an IP address")
        docker_args.extend(["--add-host", f"{shlex.quote(host)}:{shlex.quote(address)}"])
    return " ".join(
        [
            "mkdir", "-p", shlex.quote(output_path), "&&",
            *docker_args,
            "-v", f'"{mount_path}:/zap/wrk:rw"',
            shlex.quote(zap_image(image)),
            "zap.sh", "-cmd", "-autorun", f"/zap/wrk/{plan_filename}",
        ]
    )


def dependency_track_upload_command(
    *,
    server_url: str,
    project_name: str,
    project_version: str,
    sbom_path: str,
    api_key_env: str = "DEPENDENCY_TRACK_API_KEY",
    auto_create: bool = True,
) -> str:
    endpoint = _dependency_track_bom_endpoint(server_url)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", api_key_env):
        raise ValueError("api_key_env must be a valid environment variable name")
    return " ".join(
        [
            "curl",
            "-X",
            "POST",
            shlex.quote(endpoint),
            "-H",
            f'"X-Api-Key: ${{{api_key_env}}}"',
            "-F",
            shlex.quote(f"autoCreate={str(auto_create).lower()}"),
            "-F",
            shlex.quote(f"projectName={project_name}"),
            "-F",
            shlex.quote(f"projectVersion={project_version}"),
            "-F",
            shlex.quote(f"bom=@{sbom_path}"),
        ]
    )


def upload_sbom_to_dependency_track(
    *,
    server_url: str,
    api_key: str,
    project_name: str,
    project_version: str,
    sbom_path: Path,
    auto_create: bool = True,
    timeout_seconds: float = 30.0,
) -> dict[str, object]:
    if not api_key.strip():
        raise ValueError("Dependency-Track API key is required")
    if not project_name.strip():
        raise ValueError("project_name is required")
    if not project_version.strip():
        raise ValueError("project_version is required")
    if not sbom_path.exists() or not sbom_path.is_file():
        raise ValueError(f"SBOM file does not exist: {sbom_path}")

    endpoint = _dependency_track_bom_endpoint(server_url)
    boundary = f"----KODAFormBoundary{uuid.uuid4().hex}"
    body = _multipart_body(
        boundary,
        fields={
            "autoCreate": str(auto_create).lower(),
            "projectName": project_name,
            "projectVersion": project_version,
        },
        file_field="bom",
        file_path=sbom_path,
    )
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-Api-Key": api_key,
            "User-Agent": "koda-local-security-scanner",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            text = response.read().decode("utf-8", errors="replace")
            if not text.strip():
                return {"status": response.status, "body": ""}
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = {"body": text}
            if isinstance(payload, dict):
                payload.setdefault("status", response.status)
                return payload
            return {"status": response.status, "body": payload}
    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Dependency-Track upload failed ({exc.code}): {details}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Dependency-Track upload failed: {exc}") from exc


def api_key_from_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ValueError(f"Environment variable is not set: {name}")
    return value


def _dependency_track_bom_endpoint(server_url: str) -> str:
    parsed = _require_http_url(server_url, label="Dependency-Track server URL")
    base = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))
    if base.endswith("/api/v1/bom"):
        return base
    if base.endswith("/api"):
        return f"{base}/v1/bom"
    if base.endswith("/api/v1"):
        return f"{base}/bom"
    return f"{base}/api/v1/bom"


def _require_http_url(value: str, *, label: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{label} must be an http(s) URL")
    return parsed


def _multipart_body(boundary: str, *, fields: dict[str, str], file_field: str, file_path: Path) -> bytes:
    chunks: list[bytes] = []
    for key, value in fields.items():
        chunks.extend(
            [
                f"--{boundary}\r\n".encode("utf-8"),
                f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode("utf-8"),
                value.encode("utf-8"),
                b"\r\n",
            ]
        )
    chunks.extend(
        [
            f"--{boundary}\r\n".encode("utf-8"),
            f'Content-Disposition: form-data; name="{file_field}"; filename="{file_path.name}"\r\n'.encode("utf-8"),
            b"Content-Type: application/json\r\n\r\n",
            file_path.read_bytes(),
            b"\r\n",
            f"--{boundary}--\r\n".encode("utf-8"),
        ]
    )
    return b"".join(chunks)
