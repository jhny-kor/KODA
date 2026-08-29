"""Fail-closed, profile-driven web vulnerability audit engine.

The existing ``web`` module remains the lightweight crawler.  This module is
the policy boundary around it: profiles are strict JSON, active execution is
approval-gated, requests are budgeted, and a clean result is only PASS when
the profile supplied a completed oracle for that control.

The implementation deliberately uses only the Python standard library.  ZAP,
Playwright, and OAST are optional capabilities and are never downloaded by
this module.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import http.client
import http.cookiejar
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
STATUS_VALUES = (
    "VULNERABLE",
    "PASS",
    "NEEDS_REVIEW",
    "UNSUPPORTED",
    "NOT_APPLICABLE",
    "NOT_SCANNED",
)

CONTROL_DEFINITIONS: tuple[dict[str, str], ...] = (
    {"id": "web.code-injection", "title": "코드 삽입"},
    {"id": "web.ssrf", "title": "SSRF"},
    {"id": "web.file-download", "title": "파일 다운로드"},
    {"id": "web.sql-injection", "title": "SQL 삽입"},
    {"id": "web.session-management", "title": "세션 관리"},
    {"id": "web.directory-indexing", "title": "디렉터리 인덱싱"},
    {"id": "web.password-policy", "title": "비밀번호 정책"},
    {"id": "web.plaintext-transmission", "title": "평문 전송"},
    {"id": "web.error-pages", "title": "오류 페이지"},
    {"id": "web.authentication", "title": "인증"},
    {"id": "web.cookie-tampering", "title": "쿠키 변조"},
    {"id": "web.information-disclosure", "title": "정보 노출"},
    {"id": "web.authorization", "title": "권한 부여"},
    {"id": "web.admin-exposure", "title": "관리자 페이지 노출"},
    {"id": "web.xss", "title": "XSS"},
    {"id": "web.password-recovery", "title": "비밀번호 복구"},
    {"id": "web.automated-attacks", "title": "자동화 공격"},
    {"id": "web.csrf", "title": "CSRF"},
    {"id": "web.process-validation", "title": "절차 검증"},
    {"id": "web.http-methods", "title": "HTTP 메서드"},
    {"id": "web.file-upload", "title": "파일 업로드"},
)
CONTROL_IDS = tuple(item["id"] for item in CONTROL_DEFINITIONS)
CONTROL_TITLES = {item["id"]: item["title"] for item in CONTROL_DEFINITIONS}

DEFAULT_LIMITS: dict[str, int | float] = {
    "requests": 1000,
    "max_response_bytes": 2 * 1024 * 1024,
    "max_upload_bytes": 1 * 1024 * 1024,
    "timeout_seconds": 900,
    "max_rps": 5,
    "redirects": 3,
    "idempotent_retries": 1,
    "state_change_retries": 0,
    "oast_poll_seconds": 120,
    "cleanup_seconds": 30,
    "zap_rps": 2,
    "zap_threads_per_host": 1,
    "zap_minutes": 15,
    "zap_rule_minutes": 2,
}
MAX_LIMITS: dict[str, int | float] = {
    "requests": 5000,
    "max_response_bytes": 8 * 1024 * 1024,
    "max_upload_bytes": 5 * 1024 * 1024,
    "timeout_seconds": 3600,
    "max_rps": 20,
    "redirects": 5,
    "idempotent_retries": 1,
    "state_change_retries": 0,
    "oast_poll_seconds": 600,
    "cleanup_seconds": 120,
    "zap_rps": 5,
    "zap_threads_per_host": 2,
    "zap_minutes": 60,
    "zap_rule_minutes": 5,
}

TOP_LEVEL_KEYS = {
    "schema_version",
    "target",
    "limits",
    "accounts",
    "auth",
    "resources",
    "scenarios",
    "oast",
    "applicability",
}
TARGET_KEYS = {
    "environment",
    "origins",
    "base_url",
    "include_paths",
    "exclude_paths",
    "allowed_cidrs",
    "scopes",
    "read_only_resources",
    "platform",
    "distribution",
    "zap",
}
LIMIT_KEYS = set(DEFAULT_LIMITS)
RESOURCE_KEYS = {"id", "origin", "path", "methods", "probe_methods", "actors", "access", "read_only", "state_change_free"}
SCENARIO_KEYS = {
    "id",
    "title",
    "control_id",
    "control",
    "required",
    "strategies",
    "steps",
    "mutations",
    "cleanup",
    "oracle",
    "applicability",
}
STEP_KEYS = {
    "id",
    "resource",
    "method",
    "headers",
    "query",
    "body",
    "body_type",
    "account",
    "capture",
    "assertions",
    "mutation",
    "state_snapshot",
    "delay_seconds",
    "timeout",
}
OAST_KEYS = {"control_plane_origin", "callback_domain", "allowed_ips", "poll_seconds"}
AUTH_KEYS = {
    "method", "login_url", "login_request_url", "username", "username_env", "password", "password_env",
    "headers", "user_field", "pass_field", "token_json_path", "session_header", "token_prefix",
}
ACCOUNT_KEYS = {"id", "role", "headers", "username", "username_env", "password", "password_env"}
SENSITIVE_KEY_RE = re.compile(r"(?:password|passwd|passphrase|secret|token|cookie|authorization|api[_-]?key)", re.I)
NON_SECRET_METADATA_KEYS = {"token_json_path", "token_prefix"}
ENV_REF_RE = re.compile(r"^\$\{ENV:([A-Za-z_][A-Za-z0-9_]*)\}$")
SECRET_REF_RE = re.compile(r"^\$\{(?:ENV:[A-Za-z_][A-Za-z0-9_]*|CAPTURE:[A-Za-z_][A-Za-z0-9_.-]*)\}$")
INTERPOLATION_RE = re.compile(r"\$\{([^{}]+)\}")
CONTROL_ALIAS_RE = re.compile(r"^web\.[a-z0-9-]+$")
HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"}
READ_ONLY_METHODS = {"GET", "HEAD"}
NON_MUTATING_METHODS = READ_ONLY_METHODS | {"OPTIONS", "TRACE"}
SAFE_SCOPES = {"passive", "state_change_free", "browser", "oast", "zap"}
ACTIVE_SCOPES = {"active", "state_change"}
SCENARIO_STRATEGIES = {
    "koda-scenario",
    "passive",
    "browser",
    "playwright",
    "dom",
    "browser-canary",
    "oast",
    "ssrf-oast",
    "callback",
    "zap",
    "zap-active",
    "zap-passive",
    "access-control",
    "authorization",
    "matrix",
    "timing",
    "state",
    "http-methods",
    "upload",
}
ORACLE_KEYS = {
    "assertions",
    "status",
    "status_in",
    "body_contains",
    "body_not_contains",
    "forbidden_patterns",
    "headers",
    "response_time_max_ms",
    "response_time_delta_max_ms",
    "state_unchanged",
}
ACCESS_EXPECTATION_KEYS = {
    "status",
    "statuses",
    "body_contains",
    "body_not_contains",
    "headers",
    "state_unchanged",
    "state_resource",
    "state_account",
}


class ProfileError(ValueError):
    """Raised when a profile cannot be safely interpreted."""


class ApprovalError(ValueError):
    """Raised when an approval is absent, invalid, expired, or replayed."""


class NetworkPolicyError(RuntimeError):
    """Raised when a request would leave the approved network boundary."""


class BudgetExceeded(NetworkPolicyError):
    """Raised when a run would exceed its declared request budget."""


def _valid_oast_secret(value: str) -> bool:
    if not value or "\r" in value or "\n" in value:
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error):
        return False
    return 0 < len(decoded) <= 44


def _utc(now: datetime | None = None) -> datetime:
    value = now or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(now: datetime | None = None) -> str:
    return _utc(now).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ApprovalError("timestamp must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApprovalError("invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise ApprovalError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def canonical_json(value: object) -> bytes:
    """Return the stable JSON representation used for hashes and signatures."""
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProfileError(f"value is not canonical JSON: {exc}") from exc


def profile_hash(profile: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_json(profile)).hexdigest()


def _json_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ProfileError(f"{label} must be a JSON object")
    return value


def _string(value: object, label: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value.strip()):
        raise ProfileError(f"{label} must be a non-empty string")
    return value


def _string_list(value: object, label: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ProfileError(f"{label} must be a {'non-empty ' if not allow_empty else ''}JSON string array")
    result = []
    for item in value:
        result.append(_string(item, label))
    return result


def _reject_unknown(mapping: Mapping[str, object], allowed: set[str], label: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ProfileError(f"{label} contains unsupported key(s): {', '.join(unknown)}")


def _contains_forbidden(value: object, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if lowered in {"shell", "eval", "exec", "script", "command", "python_callback", "callback"}:
                raise ProfileError(f"{path or 'profile'} uses forbidden field {key_text!r}")
            if SENSITIVE_KEY_RE.search(key_text) and lowered not in NON_SECRET_METADATA_KEYS:
                env_name = isinstance(item, str) and bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item.strip()))
                if not (isinstance(item, str) and (SECRET_REF_RE.fullmatch(item.strip()) or (lowered.endswith("_env") and env_name))):
                    raise ProfileError(f"{path or 'profile'}.{key_text} must use an environment or capture reference")
            _contains_forbidden(item, f"{path}.{key_text}" if path else key_text)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _contains_forbidden(item, f"{path}[{index}]")
    elif isinstance(value, str) and "${" in value:
        for match in INTERPOLATION_RE.finditer(value):
            expression = match.group(1)
            if not (
                expression == "RUN_ID"
                or expression.startswith("ENV:")
                or expression.startswith("CAPTURE:")
            ):
                raise ProfileError(f"unsupported interpolation {match.group(0)!r} at {path}")


def _origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ProfileError(f"target origin must be an exact http(s) origin: {value!r}")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ProfileError(f"origin must not include a path, query, or fragment: {value!r}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ProfileError(f"invalid origin port: {value!r}") from exc
    default_port = 443 if parsed.scheme == "https" else 80
    host = parsed.hostname.lower()
    formatted_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{parsed.scheme}://{formatted_host}:{port or default_port}"


def _relative_path(value: object, label: str) -> str:
    path = _string(value, label)
    parsed = urllib.parse.urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or not path.startswith("/"):
        raise ProfileError(f"{label} must be an origin-relative path")
    normalized = urllib.parse.urlsplit(urllib.parse.urljoin("http://koda.invalid", path)).path
    if any(part == ".." for part in normalized.split("/")) or "\\" in path:
        raise ProfileError(f"{label} must not contain traversal")
    return path


def _validate_target(raw: object) -> dict[str, object]:
    target = _json_object(raw, "target")
    _reject_unknown(target, TARGET_KEYS, "target")
    origins_raw = target.get("origins")
    if origins_raw is None and target.get("base_url"):
        origins_raw = [_origin(_string(target["base_url"], "target.base_url"))]
    origins = [_origin(item) for item in _string_list(origins_raw, "target.origins", allow_empty=False)]
    if len(set(origins)) != len(origins):
        raise ProfileError("target.origins must not contain duplicates")
    environment = _string(target.get("environment", "unknown"), "target.environment")
    include_paths = [_relative_path(item, "target.include_paths item") for item in _string_list(target.get("include_paths", ["/"]), "target.include_paths")]
    exclude_paths = [_relative_path(item, "target.exclude_paths item") for item in _string_list(target.get("exclude_paths", []), "target.exclude_paths")]
    cidrs: list[str] = []
    for item in _string_list(target.get("allowed_cidrs", []), "target.allowed_cidrs"):
        try:
            cidrs.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError as exc:
            raise ProfileError(f"invalid target.allowed_cidrs entry: {item!r}") from exc
    scopes = _string_list(target.get("scopes", ["passive"]), "target.scopes", allow_empty=False)
    unknown_scopes = sorted(set(scopes) - SAFE_SCOPES - ACTIVE_SCOPES)
    if unknown_scopes:
        raise ProfileError(f"unsupported target scope(s): {', '.join(unknown_scopes)}")
    platform = str(target.get("platform", "shared"))
    distribution = str(target.get("distribution", ""))
    if distribution == "app_store":
        if set(scopes) & ACTIVE_SCOPES:
            raise ProfileError("app_store profiles may not request active or state_change scopes")
        if set(scopes) - {"passive", "state_change_free"}:
            raise ProfileError("app_store profiles only support passive/state_change_free scopes")
    zap = target.get("zap", {})
    if not isinstance(zap, dict):
        raise ProfileError("target.zap must be an object")
    zap = copy.deepcopy(zap)
    _reject_unknown(zap, {"enabled", "active", "image", "addon_manifest", "include_paths", "exclude_paths"}, "target.zap")
    if "image" in zap and not isinstance(zap["image"], str):
        raise ProfileError("target.zap.image must be a string")
    if "enabled" in zap and not isinstance(zap["enabled"], bool):
        raise ProfileError("target.zap.enabled must be a boolean")
    if "active" in zap and not isinstance(zap["active"], bool):
        raise ProfileError("target.zap.active must be a boolean")
    zap["include_paths"] = [_relative_path(item, "target.zap.include_paths item") for item in _string_list(zap.get("include_paths", []), "target.zap.include_paths")]
    zap["exclude_paths"] = [_relative_path(item, "target.zap.exclude_paths item") for item in _string_list(zap.get("exclude_paths", []), "target.zap.exclude_paths")]
    addon_manifest = zap.get("addon_manifest", {})
    if not isinstance(addon_manifest, dict):
        raise ProfileError("target.zap.addon_manifest must map add-on names to sha256 digests")
    for addon, digest in addon_manifest.items():
        if not isinstance(addon, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", addon):
            raise ProfileError("target.zap.addon_manifest contains an invalid add-on name")
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ProfileError(f"target.zap.addon_manifest[{addon!r}] must be a sha256 digest")
    zap["addon_manifest"] = copy.deepcopy(addon_manifest)
    return {
        "environment": environment,
        "origins": origins,
        "include_paths": include_paths,
        "exclude_paths": exclude_paths,
        "allowed_cidrs": cidrs,
        "scopes": list(dict.fromkeys(scopes)),
        "read_only_resources": _string_list(target.get("read_only_resources", []), "target.read_only_resources"),
        "platform": platform,
        "distribution": distribution,
        "zap": zap,
    }


def _validate_limits(raw: object) -> dict[str, int | float]:
    if raw is None:
        return dict(DEFAULT_LIMITS)
    limits = _json_object(raw, "limits")
    _reject_unknown(limits, LIMIT_KEYS, "limits")
    result: dict[str, int | float] = dict(DEFAULT_LIMITS)
    for key, default in DEFAULT_LIMITS.items():
        if key not in limits:
            continue
        value = limits[key]
        if isinstance(default, int):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ProfileError(f"limits.{key} must be an integer")
        elif isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ProfileError(f"limits.{key} must be numeric")
        if value < 0 or (MAX_LIMITS[key] > 0 and value <= 0) or value > MAX_LIMITS[key]:
            lower = "0" if MAX_LIMITS[key] == 0 else "0, exclusive"
            raise ProfileError(f"limits.{key} must be in [{lower}, {MAX_LIMITS[key]}]")
        result[key] = value
    if result["state_change_retries"] != 0:
        raise ProfileError("limits.state_change_retries must remain zero")
    return result


def _validate_resources(raw: object, origins: Sequence[str]) -> list[dict[str, object]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ProfileError("resources must be a JSON array")
    result: list[dict[str, object]] = []
    identifiers: set[str] = set()
    for index, item in enumerate(raw):
        resource = _json_object(item, f"resources[{index}]")
        _reject_unknown(resource, RESOURCE_KEYS, f"resources[{index}]")
        identifier = _string(resource.get("id"), f"resources[{index}].id")
        if identifier in identifiers:
            raise ProfileError(f"duplicate resource id: {identifier}")
        identifiers.add(identifier)
        methods = [method.upper() for method in _string_list(resource.get("methods", ["GET"]), f"resources[{index}].methods", allow_empty=False)]
        if set(methods) - HTTP_METHODS:
            raise ProfileError(f"resources[{index}].methods contains an unsupported HTTP method")
        probe_methods = [method.upper() for method in _string_list(resource.get("probe_methods", []), f"resources[{index}].probe_methods")]
        if set(probe_methods) - HTTP_METHODS:
            raise ProfileError(f"resources[{index}].probe_methods contains an unsupported HTTP method")
        if set(methods) & set(probe_methods):
            raise ProfileError(f"resources[{index}] must not duplicate methods and probe_methods")
        path = _relative_path(resource.get("path"), f"resources[{index}].path")
        resource_origin = resource.get("origin")
        if resource_origin is not None:
            resource_origin = _origin(_string(resource_origin, f"resources[{index}].origin"))
            if resource_origin not in set(origins):
                raise ProfileError(f"resources[{index}].origin is not in target.origins")
        actors = _string_list(resource.get("actors", []), f"resources[{index}].actors")
        access = resource.get("access", {})
        if not isinstance(access, dict):
            raise ProfileError(f"resources[{index}].access must be an object")
        for actor, expectation in access.items():
            if not isinstance(actor, str) or not isinstance(expectation, (str, dict, bool)):
                raise ProfileError(f"resources[{index}].access must map actor names to expectations")
            _validate_access_expectation(expectation, f"resources[{index}].access.{actor}")
        read_only = bool(resource.get("read_only", False))
        if read_only and set(methods) - READ_ONLY_METHODS:
            raise ProfileError(f"resources[{index}] marked read_only but declares a non-GET/HEAD method")
        result.append({
            "id": identifier,
            "origin": resource_origin or str(origins[0]),
            "path": path,
            "methods": list(dict.fromkeys(methods)),
            "probe_methods": list(dict.fromkeys(probe_methods)),
            "actors": actors,
            "access": copy.deepcopy(access),
            "read_only": read_only,
            "state_change_free": bool(resource.get("state_change_free", False)),
        })
    resource_ids = {str(item["id"]) for item in result}
    for resource in result:
        for actor, expectation in resource["access"].items():
            if not isinstance(expectation, dict) or "state_resource" not in expectation:
                continue
            state_resource = _string(
                expectation["state_resource"],
                f"resources.{resource['id']}.access.{actor}.state_resource",
            )
            if state_resource not in resource_ids:
                raise ProfileError(
                    f"resources.{resource['id']}.access.{actor}.state_resource references undeclared resource {state_resource!r}"
                )
    return result


def _validate_accounts(raw: object) -> dict[str, object]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        items = list(raw.items())
    elif isinstance(raw, list):
        items = []
        for index, item in enumerate(raw):
            account = _json_object(item, f"accounts[{index}]")
            items.append((account.get("id"), account))
    else:
        raise ProfileError("accounts must be an object or array")
    result: dict[str, object] = {}
    for key, raw_account in items:
        account = _json_object(raw_account, f"accounts.{key}")
        _reject_unknown(account, ACCOUNT_KEYS, f"accounts.{key}")
        identifier = _string(account.get("id", key), f"accounts.{key}.id")
        if identifier in result:
            raise ProfileError(f"duplicate account id: {identifier}")
        headers = account.get("headers", {})
        if not isinstance(headers, dict):
            raise ProfileError(f"accounts.{identifier}.headers must be an object")
        result[identifier] = copy.deepcopy({**account, "id": identifier, "headers": headers})
    return result


def _validate_scenarios(raw: object, resource_ids: set[str]) -> list[dict[str, object]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ProfileError("scenarios must be a JSON array")
    result: list[dict[str, object]] = []
    identifiers: set[str] = set()
    for index, item in enumerate(raw):
        scenario = _json_object(item, f"scenarios[{index}]")
        _reject_unknown(scenario, SCENARIO_KEYS, f"scenarios[{index}]")
        identifier = _string(scenario.get("id"), f"scenarios[{index}].id")
        if identifier in identifiers:
            raise ProfileError(f"duplicate scenario id: {identifier}")
        identifiers.add(identifier)
        control = scenario.get("control_id", scenario.get("control"))
        control_id = _string(control, f"scenarios[{index}].control_id")
        if not CONTROL_ALIAS_RE.fullmatch(control_id) or control_id not in CONTROL_IDS:
            raise ProfileError(f"scenarios[{index}] references an unknown web control: {control_id}")
        steps = _validate_steps(scenario.get("steps", []), resource_ids, f"scenarios[{index}].steps")
        if not steps:
            raise ProfileError(f"scenarios[{index}].steps must not be empty")
        mutations = _validate_steps(scenario.get("mutations", []), resource_ids, f"scenarios[{index}].mutations", allow_empty=True)
        cleanup = _validate_steps(scenario.get("cleanup", []), resource_ids, f"scenarios[{index}].cleanup", allow_empty=True)
        strategies = _string_list(scenario.get("strategies", ["koda-scenario"]), f"scenarios[{index}].strategies", allow_empty=False)
        strategies = [item.lower() for item in strategies]
        unknown_strategies = sorted(set(strategies) - SCENARIO_STRATEGIES)
        if unknown_strategies:
            raise ProfileError(f"scenarios[{index}].strategies contains unsupported strategy(s): {', '.join(unknown_strategies)}")
        oracle = scenario.get("oracle", {})
        if not isinstance(oracle, dict):
            raise ProfileError(f"scenarios[{index}].oracle must be an object")
        _reject_unknown(oracle, ORACLE_KEYS, f"scenarios[{index}].oracle")
        if "assertions" in oracle and not isinstance(oracle["assertions"], list):
            raise ProfileError(f"scenarios[{index}].oracle.assertions must be an array")
        if "headers" in oracle and not isinstance(oracle["headers"], dict):
            raise ProfileError(f"scenarios[{index}].oracle.headers must be an object")
        applicability = scenario.get("applicability", "").strip() if isinstance(scenario.get("applicability", ""), str) else ""
        result.append({
            "id": identifier,
            "title": str(scenario.get("title", identifier)),
            "control_id": control_id,
            "required": bool(scenario.get("required", True)),
            "strategies": strategies,
            "steps": steps,
            "mutations": mutations,
            "cleanup": cleanup,
            "oracle": copy.deepcopy(oracle),
            "applicability": applicability,
        })
    return result


def _validate_access_expectation(value: object, label: str) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, str):
        if value.lower() not in {"allow", "deny"}:
            raise ProfileError(f"{label} must be allow or deny")
        return
    if not isinstance(value, dict):
        raise ProfileError(f"{label} must be allow, deny, or an expectation object")
    _reject_unknown(value, ACCESS_EXPECTATION_KEYS, label)
    if "status" in value and str(value["status"]).lower() not in {"allow", "deny"}:
        raise ProfileError(f"{label}.status must be allow or deny")
    if "statuses" in value:
        statuses = value["statuses"]
        if not isinstance(statuses, list) or not statuses or any(
            isinstance(item, bool) or not isinstance(item, int) or item < 100 or item > 599
            for item in statuses
        ):
            raise ProfileError(f"{label}.statuses must be a non-empty HTTP status array")
    for key in ("body_contains", "body_not_contains"):
        if key in value and (not isinstance(value[key], list) or any(not isinstance(item, str) for item in value[key])):
            raise ProfileError(f"{label}.{key} must be a string array")
    if "headers" in value:
        headers = value["headers"]
        if not isinstance(headers, dict):
            raise ProfileError(f"{label}.headers must be an object")
        for name, expectation in headers.items():
            if not isinstance(name, str) or not isinstance(expectation, (str, dict, bool)):
                raise ProfileError(f"{label}.headers must map names to expectations")
            if isinstance(expectation, dict):
                _reject_unknown(expectation, {"equals", "contains", "absent"}, f"{label}.headers.{name}")
    if "state_resource" in value:
        _string(value["state_resource"], f"{label}.state_resource")
    if "state_account" in value:
        _string(value["state_account"], f"{label}.state_account")


def _validate_steps(raw: object, resource_ids: set[str], label: str, *, allow_empty: bool = False) -> list[dict[str, object]]:
    if not isinstance(raw, list) or (not allow_empty and not raw):
        raise ProfileError(f"{label} must be a {'non-empty ' if not allow_empty else ''}JSON array")
    result: list[dict[str, object]] = []
    for index, item in enumerate(raw):
        step = _json_object(item, f"{label}[{index}]")
        _reject_unknown(step, STEP_KEYS, f"{label}[{index}]")
        resource = _string(step.get("resource"), f"{label}[{index}].resource")
        if resource not in resource_ids:
            raise ProfileError(f"{label}[{index}] references undeclared resource {resource!r}")
        method = str(step.get("method", "GET")).upper()
        if method not in HTTP_METHODS:
            raise ProfileError(f"{label}[{index}].method is not supported")
        body_type = str(step.get("body_type", ""))
        if body_type and body_type not in {"json", "form", "raw", "multipart"}:
            raise ProfileError(f"{label}[{index}].body_type is not supported")
        headers = step.get("headers", {})
        query = step.get("query", {})
        if not isinstance(headers, dict) or not isinstance(query, dict):
            raise ProfileError(f"{label}[{index}].headers/query must be objects")
        assertions = step.get("assertions", [])
        if not isinstance(assertions, list):
            raise ProfileError(f"{label}[{index}].assertions must be an array")
        captures = step.get("capture", [])
        if isinstance(captures, dict):
            captures = [captures]
        if not isinstance(captures, list):
            raise ProfileError(f"{label}[{index}].capture must be an object or array")
        delay_seconds = step.get("delay_seconds", 0)
        if isinstance(delay_seconds, bool) or not isinstance(delay_seconds, (int, float)) or not 0 <= delay_seconds <= 3600:
            raise ProfileError(f"{label}[{index}].delay_seconds must be between 0 and 3600 seconds")
        timeout = step.get("timeout")
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
            or timeout > 3600
        ):
            raise ProfileError(f"{label}[{index}].timeout must be greater than 0 and at most 3600 seconds")
        result.append(copy.deepcopy({
            "id": str(step.get("id", f"step-{index + 1}")),
            "resource": resource,
            "method": method,
            "headers": headers,
            "query": query,
            "body": step.get("body"),
            "body_type": body_type,
            "account": step.get("account", ""),
            "capture": captures,
            "assertions": assertions,
            "mutation": step.get("mutation", {}),
            "state_snapshot": bool(step.get("state_snapshot", False)),
            "delay_seconds": delay_seconds,
            "timeout": step.get("timeout"),
        }))
    return result


def _validate_oast(raw: object) -> dict[str, object]:
    if raw is None:
        return {}
    oast = _json_object(raw, "oast")
    _reject_unknown(oast, OAST_KEYS, "oast")
    if not oast:
        return {}
    if oast and ("control_plane_origin" not in oast or "callback_domain" not in oast):
        raise ProfileError("oast requires control_plane_origin and callback_domain together")
    result = copy.deepcopy(oast)
    if "control_plane_origin" in result:
        result["control_plane_origin"] = _origin(_string(result["control_plane_origin"], "oast.control_plane_origin"))
    if "callback_domain" in result:
        domain = _string(result["callback_domain"], "oast.callback_domain").lower().rstrip(".")
        try:
            ipaddress.ip_address(domain)
            is_ip = True
        except ValueError:
            is_ip = False
        if is_ip or "." not in domain or any(not part or not re.fullmatch(r"[a-z0-9-]+", part) for part in domain.split(".")):
            raise ProfileError("oast.callback_domain must be a DNS name")
        result["callback_domain"] = domain
    allowed_ips = _string_list(result.get("allowed_ips", []), "oast.allowed_ips", allow_empty=False)
    normalized_ips: list[str] = []
    for value in allowed_ips:
        try:
            normalized_ips.append(str(ipaddress.ip_address(value)))
        except ValueError:
            try:
                normalized_ips.append(str(ipaddress.ip_network(value, strict=False)))
            except ValueError as exc:
                raise ProfileError(f"oast.allowed_ips contains an invalid IP or CIDR: {value!r}") from exc
    result["allowed_ips"] = normalized_ips
    if "poll_seconds" in result:
        if not isinstance(result["poll_seconds"], int) or result["poll_seconds"] <= 0 or result["poll_seconds"] > 600:
            raise ProfileError("oast.poll_seconds must be between 1 and 600")
    return result


def _validate_auth(raw: object, origins: Sequence[str]) -> dict[str, object]:
    if raw is None:
        return {}
    auth = _json_object(raw, "auth")
    _reject_unknown(auth, AUTH_KEYS, "auth")
    result = copy.deepcopy(auth)
    method = str(result.get("method", "form"))
    if method not in {"form", "json", "header"}:
        raise ProfileError("auth.method must be form, json, or header")
    for key in ("login_url", "login_request_url"):
        if key not in result:
            continue
        value = _string(result[key], f"auth.{key}")
        parsed = urllib.parse.urlsplit(value)
        if not parsed.hostname:
            raise ProfileError(f"auth.{key} must be an absolute URL on an approved origin")
        host = parsed.hostname
        if ":" in host:
            host = f"[{host}]"
        exact = _origin(f"{parsed.scheme}://{host}{':' + str(parsed.port) if parsed.port else ''}")
        if exact not in set(origins):
            raise ProfileError(f"auth.{key} is outside target.origins")
        if parsed.fragment:
            raise ProfileError(f"auth.{key} must not contain a fragment")
    for key in ("username_env", "password_env"):
        if key in result and (not isinstance(result[key], str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", result[key])):
            raise ProfileError(f"auth.{key} must be an environment variable name")
    headers = result.get("headers", {})
    if not isinstance(headers, dict):
        raise ProfileError("auth.headers must be an object")
    if method == "header" and not headers:
        raise ProfileError("header authentication requires at least one header reference")
    for key in ("token_json_path", "session_header", "token_prefix"):
        if key in result:
            value = _string(result[key], f"auth.{key}")
            if "\r" in value or "\n" in value:
                raise ProfileError(f"auth.{key} may not contain CR/LF")
    if "session_header" in result and result["session_header"].lower() in {"host", "content-length"}:
        raise ProfileError("auth.session_header may not override Host or Content-Length")
    result["headers"] = headers
    return result


def _validate_applicability(raw: object) -> dict[str, dict[str, str]]:
    if raw is None:
        return {}
    applicability = _json_object(raw, "applicability")
    result: dict[str, dict[str, str]] = {}
    for control_id, item in applicability.items():
        if control_id not in CONTROL_IDS:
            raise ProfileError(f"applicability references an unknown web control: {control_id}")
        if not isinstance(item, dict):
            raise ProfileError(f"applicability.{control_id} must be an object")
        _reject_unknown(item, {"status", "reason"}, f"applicability.{control_id}")
        status = str(item.get("status", ""))
        reason = str(item.get("reason", "")).strip()
        if status != "NOT_APPLICABLE" or not reason:
            raise ProfileError(f"applicability.{control_id} requires status NOT_APPLICABLE and a reason")
        result[control_id] = {"status": status, "reason": reason}
    return result


def validate_profile(profile: Mapping[str, object]) -> dict[str, object]:
    """Validate and normalize a strict JSON profile.

    The returned object is detached from the caller and is the exact object used
    for hashing.  That makes approval signatures stable across CLI/API paths.
    """
    if not isinstance(profile, dict):
        raise ProfileError("profile must be a JSON object")
    _reject_unknown(profile, TOP_LEVEL_KEYS, "profile")
    if profile.get("schema_version") != SCHEMA_VERSION:
        raise ProfileError(f"schema_version must be {SCHEMA_VERSION}")
    _contains_forbidden(profile)
    target = _validate_target(profile.get("target"))
    limits = _validate_limits(profile.get("limits"))
    accounts = _validate_accounts(profile.get("accounts"))
    auth = _validate_auth(profile.get("auth"), target["origins"])
    resources = _validate_resources(profile.get("resources"), target["origins"])
    resource_ids = {item["id"] for item in resources}
    unknown_read_only = set(target["read_only_resources"]) - resource_ids
    if unknown_read_only:
        raise ProfileError(f"target.read_only_resources references unknown resource(s): {', '.join(sorted(unknown_read_only))}")
    scenarios = _validate_scenarios(profile.get("scenarios"), {item["id"] for item in resources})
    if target["distribution"] == "app_store":
        for scenario in scenarios:
            for step in [*scenario["steps"], *scenario["mutations"], *scenario["cleanup"]]:
                if str(step.get("method", "GET")).upper() not in READ_ONLY_METHODS:
                    raise ProfileError("app_store profiles may only declare GET/HEAD scenario steps")
    oast = _validate_oast(profile.get("oast"))
    applicability = _validate_applicability(profile.get("applicability"))
    normalized = {
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "limits": limits,
        "accounts": copy.deepcopy(accounts),
        "auth": auth,
        "resources": resources,
        "scenarios": scenarios,
        "oast": oast,
        "applicability": applicability,
    }
    return json.loads(canonical_json(normalized).decode("utf-8"))


def load_profile(source: str | Path | Mapping[str, object]) -> dict[str, object]:
    if isinstance(source, Mapping):
        return validate_profile(dict(source))
    path = Path(source).expanduser()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ProfileError(f"profile could not be read: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ProfileError(f"profile is not valid JSON: {exc}") from exc
    return validate_profile(value)


def _resolve_host(host: str, port: int) -> list[str]:
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ApprovalError(f"could not resolve target host {host!r}: {exc}") from exc
    values: list[str] = []
    for item in addresses:
        address = item[4][0]
        if address not in values:
            values.append(address)
    if not values:
        raise ApprovalError(f"target host {host!r} resolved to no addresses")
    return sorted(values, key=lambda value: (":" not in value, value))


def _origin_parts(origin: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(origin)
    return parsed.scheme, parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80)


def _ip_allowed(address: str, cidrs: Sequence[str]) -> bool:
    if not cidrs:
        return True
    ip = ipaddress.ip_address(address)
    return any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in cidrs)


def _resolved_origins(profile: Mapping[str, object]) -> list[dict[str, object]]:
    target = profile["target"]
    assert isinstance(target, dict)
    cidrs = [str(item) for item in target.get("allowed_cidrs", [])]
    result: list[dict[str, object]] = []
    for origin in target["origins"]:
        scheme, host, port = _origin_parts(str(origin))
        try:
            ipaddress.ip_address(host)
            addresses = [host]
        except ValueError:
            addresses = _resolve_host(host, port)
        if not all(_ip_allowed(address, cidrs) for address in addresses):
            raise ApprovalError(f"resolved target IP is outside target.allowed_cidrs for {origin}")
        result.append({"kind": "target", "origin": str(origin), "scheme": scheme, "host": host, "port": port, "resolved_ips": addresses})
    oast = profile.get("oast") if isinstance(profile.get("oast"), dict) else {}
    if oast:
        oast_origin = str(oast["control_plane_origin"])
        if oast_origin in {str(item["origin"]) for item in result}:
            raise ApprovalError("oast.control_plane_origin must be different from target.origins")
        scheme, host, port = _origin_parts(oast_origin)
        try:
            ipaddress.ip_address(host)
            addresses = [host]
        except ValueError:
            addresses = _resolve_host(host, port)
        allowed_ips = [str(item) for item in oast.get("allowed_ips", [])]
        if allowed_ips and not all(_ip_allowed(address, allowed_ips) for address in addresses):
            raise ApprovalError(f"resolved OAST control-plane IP is outside oast.allowed_ips for {oast_origin}")
        result.append({
            "kind": "oast",
            "origin": oast_origin,
            "scheme": scheme,
            "host": host,
            "port": port,
            "resolved_ips": addresses,
            "path_prefixes": ["/events"],
        })
    return result


def _envelope(profile: Mapping[str, object]) -> dict[str, object]:
    limits = profile["limits"]
    assert isinstance(limits, dict)
    return {
        "native_requests": int(limits["requests"]),
        "timeout_seconds": int(limits["timeout_seconds"]),
        "max_response_bytes": int(limits["max_response_bytes"]),
        "max_upload_bytes": int(limits["max_upload_bytes"]),
        "redirects": int(limits["redirects"]),
        "max_rps": float(limits["max_rps"]),
        "oast_poll_seconds": int(limits["oast_poll_seconds"]),
        "cleanup_seconds": int(limits["cleanup_seconds"]),
        "zap": {
            "rps": float(limits["zap_rps"]),
            "threads_per_host": int(limits["zap_threads_per_host"]),
            "minutes": int(limits["zap_minutes"]),
            "rule_minutes": int(limits["zap_rule_minutes"]),
        },
    }


def build_approval_request(profile: Mapping[str, object] | str | Path, *, now: datetime | None = None) -> dict[str, object]:
    normalized = load_profile(profile)
    issued = _utc(now)
    expires = issued + timedelta(hours=24)
    request = {
        "schema_version": SCHEMA_VERSION,
        "kind": "koda.web-audit.approval-request",
        "request_id": secrets.token_urlsafe(18),
        "nonce": secrets.token_urlsafe(24),
        "profile_sha256": profile_hash(normalized),
        "origins": _resolved_origins(normalized),
        "scopes": list(normalized["target"]["scopes"]),
        "control_ids": list(CONTROL_IDS),
        "limits": copy.deepcopy(normalized["limits"]),
        "envelope": _envelope(normalized),
        "issued_at": _iso(issued),
        "expires_at": _iso(expires),
    }
    return request


def _approval_signing_payload(request: Mapping[str, object], approver: str, approved_at: str) -> dict[str, object]:
    return {"request": request, "approver": approver, "approved_at": approved_at}


def _key_bytes(key: str | bytes | None) -> bytes:
    value = key if key is not None else os.environ.get("KODA_APPROVAL_KEY", "")
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not value:
        raise ApprovalError("KODA_APPROVAL_KEY is required")
    return value


def approve_request(
    request: Mapping[str, object],
    approver: str,
    *,
    key: str | bytes | None = None,
    now: datetime | None = None,
) -> dict[str, object]:
    if not isinstance(request, dict) or request.get("kind") != "koda.web-audit.approval-request":
        raise ApprovalError("invalid approval request")
    approver = _string(approver, "approver")
    expires = _parse_time(request.get("expires_at"))
    issued = _parse_time(request.get("issued_at"))
    current = _utc(now)
    if expires <= current or expires - issued > timedelta(hours=24):
        raise ApprovalError("approval request is expired or exceeds the 24-hour window")
    approved_at = _iso(current)
    signature = hmac.new(_key_bytes(key), canonical_json(_approval_signing_payload(request, approver, approved_at)), hashlib.sha256).hexdigest()
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "koda.web-audit.approval",
        "request_id": request["request_id"],
        "nonce": request["nonce"],
        "profile_sha256": request["profile_sha256"],
        "approver": approver,
        "approved_at": approved_at,
        "expires_at": request["expires_at"],
        "request": copy.deepcopy(dict(request)),
        "signature": signature,
    }


def _approval_request(approval: Mapping[str, object]) -> dict[str, object]:
    nested = approval.get("request")
    if isinstance(nested, dict):
        return nested
    # Accept the flat shape only for future-compatible imported approvals.
    return {key: copy.deepcopy(approval[key]) for key in ("schema_version", "kind", "request_id", "nonce", "profile_sha256", "origins", "scopes", "control_ids", "limits", "envelope", "issued_at", "expires_at") if key in approval}


def _current_resolution(origin_entry: Mapping[str, object]) -> list[str]:
    origin = str(origin_entry.get("origin", ""))
    scheme, host, port = _origin_parts(origin)
    del scheme
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        return _resolve_host(host, port)


def consume_nonce(nonce: str, *, state_dir: Path | None = None, consumed_at: datetime | None = None) -> None:
    state = state_dir or Path.home() / ".koda"
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        state.chmod(0o700)
    except OSError:
        pass
    database = state / "web-audit-nonces.sqlite3"
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS used_nonces (nonce TEXT PRIMARY KEY, consumed_at TEXT NOT NULL)")
        connection.execute("INSERT INTO used_nonces(nonce, consumed_at) VALUES (?, ?)", (nonce, _iso(consumed_at)))
        connection.commit()
    except sqlite3.IntegrityError as exc:
        connection.rollback()
        raise ApprovalError("approval nonce has already been consumed") from exc
    finally:
        connection.close()


def verify_approval(
    profile: Mapping[str, object] | str | Path,
    approval: Mapping[str, object] | str | Path,
    *,
    confirm_origin: str,
    key: str | bytes | None = None,
    state_dir: Path | None = None,
    now: datetime | None = None,
    consume: bool = True,
) -> dict[str, object]:
    normalized = load_profile(profile)
    if isinstance(approval, (str, Path)):
        try:
            approval_value = json.loads(Path(approval).expanduser().read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ApprovalError("approval file could not be read") from exc
    else:
        approval_value = dict(approval)
    if not isinstance(approval_value, dict) or approval_value.get("kind") != "koda.web-audit.approval":
        raise ApprovalError("invalid approval document")
    request = _approval_request(approval_value)
    if request.get("profile_sha256") != profile_hash(normalized):
        raise ApprovalError("approval profile hash does not match the supplied profile")
    if approval_value.get("request_id") != request.get("request_id") or approval_value.get("nonce") != request.get("nonce"):
        raise ApprovalError("approval request identity is inconsistent")
    approver = _string(approval_value.get("approver"), "approval.approver")
    approved_at = _string(approval_value.get("approved_at"), "approval.approved_at")
    expected = hmac.new(_key_bytes(key), canonical_json(_approval_signing_payload(request, approver, approved_at)), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(approval_value.get("signature", ""))):
        raise ApprovalError("approval signature is invalid")
    current = _utc(now)
    request_expires = _parse_time(request.get("expires_at"))
    expires = _parse_time(approval_value.get("expires_at"))
    if expires != request_expires:
        raise ApprovalError("approval expiry does not match the signed request")
    approved_at_time = _parse_time(approved_at)
    issued_at_time = _parse_time(request.get("issued_at"))
    if approved_at_time < issued_at_time or approved_at_time > expires:
        raise ApprovalError("approval timestamp is outside the signed request window")
    if expires <= current:
        raise ApprovalError("approval has expired")
    if expires - issued_at_time > timedelta(hours=24):
        raise ApprovalError("approval exceeds the 24-hour window")
    exact_origin = _origin(confirm_origin)
    approved_origins = {str(item.get("origin")) for item in request.get("origins", []) if isinstance(item, dict)}
    if exact_origin not in approved_origins:
        raise ApprovalError("--confirm-origin is not present in the approval")
    for item in request.get("origins", []):
        if not isinstance(item, dict):
            raise ApprovalError("approval origin entry is invalid")
        old_ips = sorted(str(value) for value in item.get("resolved_ips", []))
        current_ips = sorted(_current_resolution(item))
        if old_ips != current_ips:
            raise ApprovalError(f"target DNS/IP changed for {item.get('origin')}")
    if consume:
        consume_nonce(str(request.get("nonce", "")), state_dir=state_dir, consumed_at=current)
    return {
        "request_id": str(request["request_id"]),
        "nonce": str(request["nonce"]),
        "profile_sha256": str(request["profile_sha256"]),
        "confirm_origin": exact_origin,
        "expires_at": str(approval_value["expires_at"]),
        "approver": approver,
        "envelope": copy.deepcopy(request.get("envelope", {})),
        "origins": copy.deepcopy(request.get("origins", [])),
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401,N802
        return None


def _host_only(value: str) -> str:
    text = str(value).strip()
    if text.startswith("["):
        end = text.find("]")
        return text[1:end] if end > 0 else text.strip("[]")
    if text.count(":") == 1:
        host, port = text.rsplit(":", 1)
        if port.isdigit():
            return host
    return text


def _port_only(value: str) -> int | None:
    text = str(value).strip()
    if text.startswith("["):
        end = text.find("]")
        if end >= 0 and text[end + 1 :].startswith(":") and text[end + 2 :].isdigit():
            return int(text[end + 2 :])
        return None
    if text.count(":") == 1:
        _, port = text.rsplit(":", 1)
        if port.isdigit():
            return int(port)
    return None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, *, approved_ips: Sequence[str], **kwargs: object) -> None:
        self._original_host = _host_only(host)
        self._approved_ips = tuple(approved_ips)
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        if not self._approved_ips:
            raise NetworkPolicyError(f"no approved IP for {self._original_host}")
        self.sock = socket.create_connection((self._approved_ips[0], self.port), self.timeout)
        peer = self.sock.getpeername()[0]
        if peer not in self._approved_ips:
            self.sock.close()
            raise NetworkPolicyError(f"HTTP peer IP {peer} is not approved")


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, *, approved_ips: Sequence[str], context: ssl.SSLContext, **kwargs: object) -> None:
        self._original_host = _host_only(host)
        self._approved_ips = tuple(approved_ips)
        super().__init__(host, context=context, **kwargs)

    def connect(self) -> None:
        if not self._approved_ips:
            raise NetworkPolicyError(f"no approved IP for {self._original_host}")
        raw = socket.create_connection((self._approved_ips[0], self.port), self.timeout)
        peer = raw.getpeername()[0]
        if peer not in self._approved_ips:
            raw.close()
            raise NetworkPolicyError(f"TLS peer IP {peer} is not approved")
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self._original_host)
        except Exception:
            raw.close()
            raise


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, network: "NetworkContext", *, oast_only: bool = False) -> None:
        super().__init__()
        self.network = network
        self.oast_only = oast_only

    def http_open(self, req):
        self.network.authorize_url(
            req.full_url,
            method=req.get_method(),
            body_length=len(getattr(req, "data", None) or b""),
            oast=self.oast_only,
        )
        return self.do_open(self._connection, req)

    def _connection(self, host, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, **kwargs):
        return _PinnedHTTPConnection(host, approved_ips=self.network.approved_ips(host, oast=self.oast_only), timeout=timeout, **kwargs)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, network: "NetworkContext", *, oast_only: bool = False) -> None:
        super().__init__(context=network.tls_context)
        self.network = network
        self.oast_only = oast_only

    def https_open(self, req):
        self.network.authorize_url(
            req.full_url,
            method=req.get_method(),
            body_length=len(getattr(req, "data", None) or b""),
            oast=self.oast_only,
        )
        return self.do_open(self._connection, req)

    def _connection(self, host, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, **kwargs):
        return _PinnedHTTPSConnection(host, approved_ips=self.network.approved_ips(host, oast=self.oast_only), context=self.network.tls_context, timeout=timeout, **kwargs)


class NetworkContext:
    """Target-bound request factory shared by stdlib web checks and scenarios."""

    def __init__(self, profile: Mapping[str, object], approval: Mapping[str, object]) -> None:
        self.profile = load_profile(profile)
        self.approval = dict(approval)
        target = self.profile["target"]
        assert isinstance(target, dict)
        self.origins = tuple(str(item) for item in target["origins"])
        self.include_paths = tuple(str(item) for item in target["include_paths"])
        self.exclude_paths = tuple(str(item) for item in target["exclude_paths"])
        auth = self.profile.get("auth") if isinstance(self.profile.get("auth"), dict) else {}
        auth_paths: list[str] = []
        for key in ("login_url", "login_request_url"):
            value = str(auth.get(key, ""))
            if value:
                path = urllib.parse.urlsplit(value).path or "/"
                if path not in auth_paths:
                    auth_paths.append(path)
        self.auth_paths = tuple(auth_paths)
        self.read_only_resources = frozenset(str(item) for item in target.get("read_only_resources", []))
        self.scopes = frozenset(str(item) for item in target["scopes"])
        self.distribution = str(target.get("distribution", ""))
        self.limits = dict(self.profile["limits"])
        self._origin_entries = {str(item.get("origin")): item for item in self.approval.get("origins", []) if isinstance(item, dict)}
        self._used_requests = 0
        self._run_id = secrets.token_hex(10)
        self.tls_context = ssl.create_default_context()
        self._last_request_at = 0.0
        self._deadline = time.monotonic() + float(self.limits["timeout_seconds"])

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def request_count(self) -> int:
        return self._used_requests

    def remaining_timeout(self) -> float:
        return max(0.0, self._deadline - time.monotonic())

    def reserve(self, method: str = "GET", count: int = 1) -> None:
        if count < 1:
            return
        if self.remaining_timeout() <= 0:
            raise BudgetExceeded("web-audit time budget exceeded")
        if self._used_requests + count > int(self.limits["requests"]):
            raise BudgetExceeded("web-audit request budget exceeded")
        if self.distribution == "app_store" and method.upper() not in READ_ONLY_METHODS:
            raise NetworkPolicyError("App Store web-audit profiles only permit GET/HEAD")
        if method.upper() not in NON_MUTATING_METHODS and not (self.scopes & ACTIVE_SCOPES):
            raise NetworkPolicyError("state-changing requests require an active/state_change scope")
        rps = float(self.limits.get("max_rps", 0) or 0)
        if rps > 0 and self._last_request_at:
            wait = (1.0 / rps) - (time.monotonic() - self._last_request_at)
            if wait > 0:
                if wait >= self.remaining_timeout():
                    raise BudgetExceeded("web-audit time budget exceeded")
                time.sleep(wait)
        if self.remaining_timeout() <= 0:
            raise BudgetExceeded("web-audit time budget exceeded")
        self._last_request_at = time.monotonic()
        self._used_requests += count

    def delay(self, seconds: float) -> None:
        if seconds <= 0:
            return
        if seconds >= self.remaining_timeout():
            raise BudgetExceeded("web-audit time budget exceeded")
        time.sleep(seconds)

    def _entry_for_url(self, url: str, *, oast: bool = False) -> dict[str, object]:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise NetworkPolicyError("only absolute http(s) URLs are permitted")
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        exact = _origin(f"{parsed.scheme}://{host}{':' + str(parsed.port) if parsed.port else ''}")
        entry = self._origin_entries.get(exact)
        if entry is None:
            raise NetworkPolicyError(f"URL origin is outside the approved profile: {exact}")
        if (str(entry.get("kind", "target")) == "oast") != oast:
            raise NetworkPolicyError("OAST control-plane URLs are restricted to the OAST client")
        if parsed.username or parsed.password or parsed.fragment:
            raise NetworkPolicyError("userinfo and fragments are not permitted in target URLs")
        path = parsed.path or "/"
        decoded_path = urllib.parse.unquote(path)
        if "\x00" in decoded_path or "\\" in decoded_path or any(part == ".." for part in decoded_path.split("/")):
            raise NetworkPolicyError("URL path contains traversal")
        allowed_paths = tuple(str(item) for item in entry.get("path_prefixes", [])) if oast else (*self.include_paths, *self.auth_paths)
        if allowed_paths and not any(path == item or path.startswith(item.rstrip("/") + "/") for item in allowed_paths):
            raise NetworkPolicyError(f"URL path is outside target.include_paths: {path}")
        if not oast and any(path == item or path.startswith(item.rstrip("/") + "/") for item in self.exclude_paths):
            raise NetworkPolicyError(f"URL path is excluded by the profile: {path}")
        return entry

    def authorize_url(
        self,
        url: str,
        *,
        method: str = "GET",
        reserve: bool = True,
        body_length: int = 0,
        oast: bool = False,
    ) -> None:
        self._entry_for_url(url, oast=oast)
        if body_length < 0 or body_length > int(self.limits["max_upload_bytes"]):
            raise BudgetExceeded("request body exceeds the profile upload limit")
        if reserve:
            self.reserve(method)

    def approved_ips(self, host: str, *, port: int | None = None, oast: bool = False) -> tuple[str, ...]:
        normalized = _host_only(host).lower()
        expected_port = port if port is not None else _port_only(host)
        for entry in self._origin_entries.values():
            if (str(entry.get("kind", "target")) == "oast") != oast:
                continue
            if str(entry.get("host", "")).strip("[]").lower() == normalized and (
                expected_port is None or int(entry.get("port", 0)) == expected_port
            ):
                return tuple(str(item) for item in entry.get("resolved_ips", []))
        raise NetworkPolicyError(f"host is not approved: {host}")

    def build_opener(self, jar: http.cookiejar.CookieJar | None = None, *, oast: bool = False) -> urllib.request.OpenerDirector:
        cookie_jar = jar if jar is not None else http.cookiejar.CookieJar()
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _PinnedHTTPHandler(self, oast_only=oast),
            _PinnedHTTPSHandler(self, oast_only=oast),
            urllib.request.HTTPCookieProcessor(cookie_jar),
            _NoRedirect(),
        )

    def connect_tls(self, host: str, port: int, timeout: float):
        timeout = min(float(timeout), self.remaining_timeout())
        if timeout <= 0:
            raise BudgetExceeded("web-audit time budget exceeded")
        ips = self.approved_ips(host, port=port)
        raw = socket.create_connection((ips[0], port), timeout)
        peer = raw.getpeername()[0]
        if peer not in ips:
            raw.close()
            raise NetworkPolicyError(f"TLS peer IP {peer} is not approved")
        return self.tls_context.wrap_socket(raw, server_hostname=host)

    def browser_context_options(self) -> dict[str, object]:
        return {"service_workers": "block", "bypass_csp": False, "ignore_https_errors": False}

    def browser_launch_options(self) -> dict[str, object]:
        return {
            "headless": True,
            "args": [
                "--no-proxy-server",
                "--disable-quic",
                "--disable-application-cache",
                "--disk-cache-size=0",
                "--disable-features=AlternateProtocol,AsyncDns,UseDnsHttpsSvcb,UseDnsHttpsSvcbAlpn",
            ],
        }

    def validate_browser_response(self, response: object) -> bool:
        url = getattr(response, "url", "")
        try:
            entry = self._entry_for_url(str(url))
            server_addr = getattr(response, "server_addr")()
            address = str(server_addr.get("ipAddress", "")) if isinstance(server_addr, dict) else ""
            return address in {str(value) for value in entry.get("resolved_ips", [])}
        except Exception:
            return False


class OastClient:
    """Minimal BOAST /events client using the same pinned network factory."""

    def __init__(self, profile: Mapping[str, object], network: NetworkContext) -> None:
        self.profile = load_profile(profile)
        self.network = network
        oast = self.profile.get("oast") if isinstance(self.profile.get("oast"), dict) else {}
        self.oast = oast
        secret = os.environ.get("KODA_OAST_SECRET", "")
        if not _valid_oast_secret(secret):
            raise NetworkPolicyError("KODA_OAST_SECRET must be valid base64 for BOAST")
        origin = str(oast.get("control_plane_origin", ""))
        if not origin:
            raise NetworkPolicyError("OAST control-plane is not configured")
        self.events_url = origin.rstrip("/") + "/events"
        self.authorization = f"Secret {secret}"
        self.opener = network.build_opener(oast=True)
        self.poll_interval = max(1, int(oast.get("poll_seconds", 10)))
        self.test_id = ""
        self._seen_events: set[str] = set()

    def _get_payload(self) -> dict[str, object]:
        timeout = min(float(self.network.limits["timeout_seconds"]), self.network.remaining_timeout())
        if timeout <= 0:
            raise BudgetExceeded("web-audit time budget exceeded")
        request = urllib.request.Request(
            self.events_url,
            headers={"Accept": "application/json", "Authorization": self.authorization},
            method="GET",
        )
        try:
            with self.opener.open(request, timeout=timeout) as response:
                body = _read_bounded(response, int(self.network.limits["max_response_bytes"]), timeout)
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            raise NetworkPolicyError(f"OAST control-plane returned HTTP {code}") from exc
        except (urllib.error.URLError, OSError, ssl.SSLError, socket.timeout, NetworkPolicyError) as exc:
            raise NetworkPolicyError(f"OAST control-plane request failed: {type(exc).__name__}") from exc
        try:
            payload = json.loads(body.decode("utf-8", "replace"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise NetworkPolicyError("OAST control-plane returned invalid JSON") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("events", []), list):
            raise NetworkPolicyError("OAST control-plane response has an invalid events array")
        return payload

    @staticmethod
    def _event_keys(events: Sequence[object]) -> set[str]:
        return {hashlib.sha256(canonical_json(event)).hexdigest() for event in events}

    def _matching_events(self, events: Sequence[object]) -> list[object]:
        return [
            event for event in events
            if isinstance(event, dict) and str(event.get("testID", "")) == self.test_id
        ]

    def register(self) -> str:
        payload = self._get_payload()
        # BOAST returns the test id as ``id``.  Do not expose it in reports; it
        # is used only to construct the callback payload for this run.
        test_id = str(payload.get("id", ""))
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", test_id):
            raise NetworkPolicyError("OAST control-plane returned an invalid test id")
        self.test_id = test_id
        self._seen_events = self._event_keys(self._matching_events(payload["events"]))
        domain = str(self.oast.get("callback_domain", ""))
        return f"{test_id}.{domain}"

    def poll(self) -> tuple[int, bool]:
        deadline = time.monotonic() + float(self.network.limits["oast_poll_seconds"])
        while True:
            if self.network.remaining_timeout() <= 0:
                return 0, False
            try:
                payload = self._get_payload()
            except (BudgetExceeded, NetworkPolicyError):
                return 0, False
            current = self._event_keys(self._matching_events(payload["events"]))
            new_events = current - self._seen_events
            self._seen_events.update(current)
            if new_events:
                return len(new_events), True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return 0, True
            delay = min(float(self.poll_interval), remaining, self.network.remaining_timeout())
            if delay <= 0:
                return 0, False
            time.sleep(delay)


def _interpolate(value: object, captures: Mapping[str, str], run_id: str) -> object:
    if isinstance(value, dict):
        return {str(key): _interpolate(item, captures, run_id) for key, item in value.items()}
    if isinstance(value, list):
        return [_interpolate(item, captures, run_id) for item in value]
    if not isinstance(value, str):
        return value

    def replace(match: re.Match[str]) -> str:
        expression = match.group(1)
        if expression == "RUN_ID":
            return run_id
        if expression.startswith("ENV:"):
            name = expression[4:]
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise ProfileError(f"invalid environment variable reference: {expression}")
            return os.environ.get(name, "")
        if expression.startswith("CAPTURE:"):
            name = expression[8:]
            if name not in captures:
                raise ProfileError(f"capture is not available: {name}")
            return captures[name]
        raise ProfileError(f"unsupported interpolation: {expression}")

    return INTERPOLATION_RE.sub(replace, value)


def _safe_header_items(headers: Mapping[str, object]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in headers.items():
        name = _string(key, "header name")
        text = str(value)
        if "\r" in name or "\n" in name or "\r" in text or "\n" in text:
            raise ProfileError("scenario headers may not contain CR/LF")
        if name.lower() in {"host", "content-length"}:
            raise ProfileError(f"scenario may not set {name} header")
        result[name] = text
    return result


def _body_bytes(body: object, body_type: str, limits: Mapping[str, object]) -> tuple[bytes | None, str | None]:
    if body is None:
        return None, None
    if body_type == "json" or (not body_type and isinstance(body, (dict, list))):
        data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        content_type = "application/json"
    elif body_type == "form":
        if not isinstance(body, dict):
            raise ProfileError("form body must be an object")
        data = urllib.parse.urlencode({str(k): str(v) for k, v in body.items()}).encode("utf-8")
        content_type = "application/x-www-form-urlencoded"
    elif body_type == "multipart":
        if not isinstance(body, dict):
            raise ProfileError("multipart body must be an object")
        fields = body.get("fields", {})
        file_value = body.get("file")
        if not isinstance(fields, dict) or not isinstance(file_value, dict):
            raise ProfileError("multipart body requires fields and file objects")
        filename = _string(file_value.get("filename"), "multipart.file.filename")
        content = file_value.get("content", "")
        if not isinstance(content, str):
            raise ProfileError("multipart.file.content must be a string")
        content_type_value = _string(file_value.get("content_type", "application/octet-stream"), "multipart.file.content_type")
        field_name = _string(file_value.get("field", "file"), "multipart.file.field")
        if any(char in filename or char in field_name or char in content_type_value for char in ("\r", "\n", "\x00")):
            raise ProfileError("multipart metadata may not contain CR/LF or NUL")
        boundary = "----KODAWebAudit" + secrets.token_hex(12)
        chunks: list[bytes] = []
        for key, value in fields.items():
            name = _string(key, "multipart field name")
            text = str(value)
            chunks.extend([
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                text.encode("utf-8"),
                b"\r\n",
            ])
        chunks.extend([
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode(),
            f"Content-Type: {content_type_value}\r\n\r\n".encode(),
            content.encode("utf-8"),
            b"\r\n",
            f"--{boundary}--\r\n".encode(),
        ])
        data = b"".join(chunks)
        content_type = f"multipart/form-data; boundary={boundary}"
    elif body_type == "raw":
        if not isinstance(body, str):
            raise ProfileError("raw body must be a string")
        data = body.encode("utf-8")
        content_type = "application/octet-stream"
    else:
        data = str(body).encode("utf-8")
        content_type = "text/plain; charset=utf-8"
    if len(data) > int(limits["max_upload_bytes"]):
        raise BudgetExceeded("scenario upload exceeds the profile limit")
    return data, content_type


def _response_digest(status: int, headers: Mapping[str, str], body: bytes) -> str:
    normalized_headers = {key.lower(): value for key, value in headers.items() if key.lower() not in {"date", "set-cookie", "x-request-id"}}
    return hashlib.sha256(canonical_json({"status": status, "headers": normalized_headers, "body": hashlib.sha256(body).hexdigest()})).hexdigest()


def _read_bounded(response: object, max_bytes: int, timeout: float | None = None) -> bytes:
    reader = getattr(response, "read1", None) or getattr(response, "read", None)
    if not callable(reader):
        raise NetworkPolicyError("response body is not readable")
    deadline = None if timeout is None else time.monotonic() + max(0.01, timeout)
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining > 0:
        if deadline is not None and time.monotonic() >= deadline:
            raise BudgetExceeded("response body read exceeded the time budget")
        chunk = reader(min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    body = b"".join(chunks)
    if len(body) > max_bytes:
        raise BudgetExceeded("response exceeds the profile limit")
    return body


def _redact(value: str) -> str:
    if not value:
        return ""
    def strip_url(match: re.Match[str]) -> str:
        raw = match.group(0).rstrip(".,;:)]}")
        suffix = match.group(0)[len(raw):]
        parsed = urllib.parse.urlsplit(raw)
        if parsed.scheme and parsed.netloc:
            return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", "")) + suffix
        return match.group(0)

    value = re.sub(r"https?://[^\s<>\"']+", strip_url, value)
    value = re.sub(
        r"(?i)\b(authorization|cookie|token|password|secret|api[-_]?key)\s*[:=]\s*([^&\s,;)]+)",
        r"\1=[redacted]",
        value,
    )
    return re.sub(r"\b[A-Za-z0-9+/=_-]{40,}\b", "[redacted]", value)


def _oracle_assertions(oracle: Mapping[str, object]) -> list[dict[str, object]]:
    """Expand the small declarative scenario-oracle shorthand into assertions."""
    assertions: list[dict[str, object]] = []
    raw = oracle.get("assertions", [])
    if isinstance(raw, list):
        assertions.extend(copy.deepcopy(item) for item in raw if isinstance(item, dict))
    if "status" in oracle:
        assertions.append({"type": "status_equals", "equals": oracle["status"]})
    if "status_in" in oracle:
        assertions.append({"type": "status_in", "values": oracle["status_in"]})
    for key, assertion_type in (("body_contains", "body_contains"), ("body_not_contains", "body_not_contains")):
        values = oracle.get(key, [])
        if isinstance(values, str):
            values = [values]
        if isinstance(values, list):
            assertions.extend({"type": assertion_type, "value": value} for value in values)
    forbidden = oracle.get("forbidden_patterns", [])
    if isinstance(forbidden, list):
        assertions.append({"type": "body_forbidden_patterns", "patterns": forbidden})
    headers = oracle.get("headers", {})
    if isinstance(headers, dict):
        for name, expectation in headers.items():
            if isinstance(expectation, dict):
                assertions.append({"type": "header", "name": name, **expectation})
            elif isinstance(expectation, bool):
                assertions.append({"type": "header", "name": name, "absent": not expectation})
            else:
                assertions.append({"type": "header", "name": name, "equals": expectation})
    if "response_time_max_ms" in oracle:
        assertions.append({"type": "response_time_max_ms", "max_ms": oracle["response_time_max_ms"]})
    if "response_time_delta_max_ms" in oracle:
        assertions.append({"type": "response_time_delta_max_ms", "max_ms": oracle["response_time_delta_max_ms"]})
    if oracle.get("state_unchanged"):
        assertions.append({"type": "state_unchanged"})
    return assertions


class ScenarioRunner:
    """Execute only declared resource steps; no shell or callback escape hatch."""

    def __init__(self, profile: Mapping[str, object], network: NetworkContext, *, base_headers: Mapping[str, str] | None = None) -> None:
        self.profile = load_profile(profile)
        self.network = network
        self.resources = {item["id"]: item for item in self.profile["resources"]}
        self.accounts = self.profile.get("accounts", {})
        self.captures: dict[str, str] = {}
        self.base_headers = dict(base_headers or {})
        self.evidence_counter = 0
        self.opener = network.build_opener()

    def _evidence(self, scenario_id: str, label: str) -> str:
        self.evidence_counter += 1
        return f"web-audit:{scenario_id}:{self.evidence_counter}:{label}"

    def _account_headers(self, account_name: object) -> dict[str, str]:
        if not account_name:
            return {}
        name = str(account_name)
        if isinstance(self.accounts, dict):
            account = self.accounts.get(name)
        else:
            account = next((item for item in self.accounts if isinstance(item, dict) and item.get("id") == name), None)
        if not isinstance(account, dict):
            raise ProfileError(f"scenario references unknown account {name!r}")
        headers = account.get("headers", {})
        if not isinstance(headers, dict):
            raise ProfileError(f"account {name!r}.headers must be an object")
        return _safe_header_items(_interpolate(headers, self.captures, self.network.run_id))

    def _request(self, scenario_id: str, step: Mapping[str, object]) -> dict[str, object]:
        resource = self.resources[str(step["resource"])]
        self.network.delay(float(step.get("delay_seconds", 0) or 0))
        method = str(step.get("method", "GET")).upper()
        if method not in {*resource["methods"], *resource.get("probe_methods", [])}:
            raise ProfileError(f"method {method} is not declared for resource {resource['id']}")
        if str(resource["id"]) in self.network.read_only_resources and method not in READ_ONLY_METHODS:
            raise NetworkPolicyError(f"resource {resource['id']} is read-only")
        path = str(_interpolate(resource["path"], self.captures, self.network.run_id))
        query = _interpolate(step.get("query", {}), self.captures, self.network.run_id)
        if query:
            if not isinstance(query, dict):
                raise ProfileError("scenario query must be an object")
            query_text = urllib.parse.urlencode({str(key): str(value) for key, value in query.items()}, doseq=True)
            path = f"{path}?{query_text}"
        origin = str(resource.get("origin") or self.network.origins[0])
        url = urllib.parse.urljoin(origin, path)
        headers = {**self.base_headers, **self._account_headers(step.get("account"))}
        headers.update(_safe_header_items(_interpolate(step.get("headers", {}), self.captures, self.network.run_id)))
        body = _interpolate(step.get("body"), self.captures, self.network.run_id)
        data, content_type = _body_bytes(body, str(step.get("body_type", "")), self.network.limits)
        if data is not None and not any(key.lower() == "content-type" for key in headers):
            headers["Content-Type"] = content_type or "application/octet-stream"
        timeout = float(step.get("timeout") or self.network.limits["timeout_seconds"])
        timeout = min(timeout, float(self.network.limits["timeout_seconds"]), self.network.remaining_timeout())
        if timeout <= 0:
            raise BudgetExceeded("web-audit time budget exceeded")
        request = urllib.request.Request(url, headers=headers, data=data, method=method)
        started = time.monotonic()
        try:
            with self.opener.open(request, timeout=timeout) as response:
                response_headers = {str(key): str(value) for key, value in response.headers.items()}
                body_bytes = _read_bounded(response, int(self.network.limits["max_response_bytes"]), timeout)
                status = int(response.status)
                final_url = str(response.geturl())
        except urllib.error.HTTPError as exc:
            try:
                response_headers = {str(key): str(value) for key, value in (exc.headers.items() if exc.headers else [])}
                body_bytes = _read_bounded(exc, int(self.network.limits["max_response_bytes"]), timeout)
                status = int(exc.code)
                final_url = str(exc.geturl())
            finally:
                exc.close()
        except (urllib.error.URLError, OSError, ssl.SSLError, socket.timeout, NetworkPolicyError) as exc:
            raise NetworkPolicyError(f"scenario request failed: {type(exc).__name__}") from exc
        body_text = body_bytes.decode("utf-8", "replace")
        return {
            "status": status,
            "headers": response_headers,
            "body": body_text,
            "body_bytes": body_bytes,
            "digest": _response_digest(status, response_headers, body_bytes),
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
            "url": final_url,
            "resource": resource["id"],
        }

    def _browser_request(self, scenario_id: str, step: Mapping[str, object]) -> dict[str, object]:
        page = getattr(self, "_browser_page", None)
        if page is None:
            raise NetworkPolicyError("browser scenario is not initialized")
        resource = self.resources[str(step["resource"])]
        self.network.delay(float(step.get("delay_seconds", 0) or 0))
        method = str(step.get("method", "GET")).upper()
        if method != "GET":
            raise NetworkPolicyError("browser scenarios only support GET navigation steps")
        if method not in {*resource["methods"], *resource.get("probe_methods", [])}:
            raise ProfileError(f"method {method} is not declared for resource {resource['id']}")
        if str(resource["id"]) in self.network.read_only_resources and method not in READ_ONLY_METHODS:
            raise NetworkPolicyError(f"resource {resource['id']} is read-only")
        path = str(_interpolate(resource["path"], self.captures, self.network.run_id))
        query = _interpolate(step.get("query", {}), self.captures, self.network.run_id)
        if query:
            if not isinstance(query, dict):
                raise ProfileError("scenario query must be an object")
            path = f"{path}?{urllib.parse.urlencode({str(key): str(value) for key, value in query.items()}, doseq=True)}"
        url = urllib.parse.urljoin(str(resource.get("origin") or self.network.origins[0]), path)
        headers = {**self.base_headers, **self._account_headers(step.get("account"))}
        headers.update(_safe_header_items(_interpolate(step.get("headers", {}), self.captures, self.network.run_id)))
        started = time.monotonic()
        try:
            page.set_extra_http_headers({key: value for key, value in headers.items() if key.lower() != "user-agent"})
            timeout = min(
                float(step.get("timeout") or self.network.limits["timeout_seconds"]),
                float(self.network.limits["timeout_seconds"]),
                self.network.remaining_timeout(),
            )
            if timeout <= 0:
                raise BudgetExceeded("web-audit time budget exceeded")
            response = page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
        except (BudgetExceeded, NetworkPolicyError):
            raise
        except Exception as exc:
            raise NetworkPolicyError(f"browser scenario request failed: {type(exc).__name__}") from exc
        if getattr(self, "_browser_invalid_request", False):
            raise NetworkPolicyError("browser request left the approved origin/path/method scope")
        if getattr(self, "_browser_invalid_response", False):
            raise NetworkPolicyError("browser response IP could not be validated")
        if response is None:
            raise NetworkPolicyError("browser navigation returned no response")
        body_text = page.content()
        body_bytes = body_text.encode("utf-8")
        if len(body_bytes) > int(self.network.limits["max_response_bytes"]):
            raise BudgetExceeded("browser response exceeds the profile limit")
        response_headers = {str(key): str(value) for key, value in response.headers.items()}
        return {
            "status": int(response.status),
            "headers": response_headers,
            "body": body_text,
            "body_bytes": body_bytes,
            "digest": _response_digest(int(response.status), response_headers, body_bytes),
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
            "url": str(response.url),
            "resource": resource["id"],
        }

    def _capture(self, scenario_id: str, step: Mapping[str, object], response: Mapping[str, object]) -> None:
        captures = step.get("capture", [])
        if isinstance(captures, dict):
            captures = [captures]
        for capture in captures:
            if not isinstance(capture, dict):
                raise ProfileError("capture must be an object")
            name = _string(capture.get("name"), "capture.name")
            source = str(capture.get("from", "body"))
            value = ""
            if source == "header":
                key = _string(capture.get("key"), "capture.key").lower()
                value = next((str(item) for item_key, item in response["headers"].items() if item_key.lower() == key), "")
            elif source == "status":
                value = str(response["status"])
            elif source == "body_regex":
                pattern = _string(capture.get("pattern"), "capture.pattern")
                match = re.search(pattern, str(response["body"]))
                value = match.group(1) if match and match.groups() else (match.group(0) if match else "")
            else:
                value = str(response["body"])
            if not value:
                raise NetworkPolicyError(f"capture {name!r} was empty")
            self.captures[name] = value

    def _assertions(
        self,
        step: Mapping[str, object],
        response: Mapping[str, object],
        baseline: Mapping[str, object] | None,
        snapshots: Mapping[str, Mapping[str, object]] | None = None,
    ) -> tuple[bool, bool, bool, list[str]]:
        assertions = step.get("assertions", [])
        if not assertions:
            return False, False, True, []
        violated = False
        complete = True
        evidence: list[str] = []
        for assertion in assertions:
            if not isinstance(assertion, dict):
                raise ProfileError("assertions must contain objects")
            kind = str(assertion.get("type", assertion.get("kind", "")))
            passed = False
            if kind in {"status", "status_equals"}:
                expected = assertion.get("equals", assertion.get("value"))
                passed = int(response["status"]) == int(expected)
            elif kind == "status_in":
                expected_values = assertion.get("values", [])
                passed = int(response["status"]) in {int(value) for value in expected_values}
            elif kind == "header":
                name = str(assertion.get("name", "")).lower()
                actual = next((str(value) for key, value in response["headers"].items() if key.lower() == name), "")
                if "equals" in assertion:
                    passed = actual == str(assertion["equals"])
                elif "contains" in assertion:
                    passed = str(assertion["contains"]) in actual
                elif "absent" in assertion:
                    passed = (not actual) == bool(assertion["absent"])
            elif kind in {"body_contains", "contains"}:
                passed = str(assertion.get("value", "")) in str(response["body"])
            elif kind in {"body_not_contains", "not_contains"}:
                passed = str(assertion.get("value", "")) not in str(response["body"])
            elif kind == "body_regex":
                try:
                    passed = re.search(str(assertion.get("pattern", "")), str(response["body"])) is not None
                except re.error:
                    complete = False
                    evidence.append("assertion:body_regex:invalid_pattern")
                    continue
            elif kind == "body_not_regex":
                try:
                    passed = re.search(str(assertion.get("pattern", "")), str(response["body"])) is None
                except re.error:
                    complete = False
                    evidence.append("assertion:body_not_regex:invalid_pattern")
                    continue
            elif kind in {"state_unchanged", "state_unchanged_after"}:
                snapshot_name = assertion.get("snapshot", assertion.get("baseline"))
                expected = snapshots.get(str(snapshot_name)) if snapshot_name and snapshots else baseline
                if expected is None:
                    complete = False
                    evidence.append("assertion:state_unchanged:baseline_missing")
                    continue
                passed = response.get("digest") == expected.get("digest")
            elif kind in {"response_time_max_ms", "response_time_not_greater_than"}:
                passed = float(response.get("elapsed_ms", 0.0)) <= float(assertion.get("max_ms", assertion.get("value")))
            elif kind in {"response_time_delta_max_ms", "response_time_not_delta"}:
                if baseline is None:
                    complete = False
                    evidence.append("assertion:response_time_delta:baseline_missing")
                    continue
                passed = abs(float(response.get("elapsed_ms", 0.0)) - float(baseline.get("elapsed_ms", 0.0))) <= float(
                    assertion.get("max_ms", assertion.get("value"))
                )
            elif kind == "header_not_contains":
                name = str(assertion.get("name", "")).lower()
                actual = next((str(value) for key, value in response["headers"].items() if key.lower() == name), "")
                passed = str(assertion.get("value", "")) not in actual
            elif kind == "body_forbidden_patterns":
                patterns = assertion.get("patterns", [])
                if not isinstance(patterns, list):
                    complete = False
                    evidence.append("assertion:body_forbidden_patterns:unsupported")
                    continue
                try:
                    passed = all(re.search(str(pattern), str(response["body"]), re.I) is None for pattern in patterns)
                except re.error:
                    complete = False
                    evidence.append("assertion:body_forbidden_patterns:invalid_pattern")
                    continue
            else:
                complete = False
                evidence.append(f"assertion:{kind}:unsupported")
                continue
            if passed:
                evidence.append(f"assertion:{kind}:pass")
            else:
                violated = True
                evidence.append(f"assertion:{kind}:fail")
        return True, violated, complete, evidence

    def _run_with_requester(
        self,
        scenario: Mapping[str, object],
        requester: Any,
        *,
        include_mutations: bool = True,
        include_cleanup: bool = True,
    ) -> dict[str, object]:
        scenario_id = str(scenario["id"])
        control_id = str(scenario["control_id"])
        result: dict[str, object] = {
            "id": scenario_id,
            "control_id": control_id,
            "title": str(scenario.get("title", scenario_id)),
            "required": bool(scenario.get("required", True)),
            "status": "NOT_SCANNED",
            "executed": False,
            "reason_code": "not_started",
            "coverage": {"required": 1, "completed": 0},
            "surfaces_tested": [],
            "strategy_results": [],
            "evidence_ids": [],
            "cleanup_completed": False,
        }
        run_cleanup = list(scenario.get("cleanup", [])) if include_cleanup else []
        try:
            baseline: dict[str, object] | None = None
            snapshots: dict[str, dict[str, object]] = {}
            last_response: dict[str, object] | None = None
            assertion_seen = False
            assertions_complete = True
            violation = False
            all_passed = True
            for step in scenario["steps"]:
                response = requester(scenario_id, step)
                last_response = response
                result["executed"] = True
                snapshot_after_assertions = bool(step.get("state_snapshot")) or (
                    baseline is None and str(step.get("id")) == "baseline"
                )
                self._capture(scenario_id, step, response)
                seen, failed, complete, evidence = self._assertions(step, response, baseline, snapshots)
                if snapshot_after_assertions:
                    baseline = response
                snapshots[str(step.get("id", ""))] = response
                assertion_seen = assertion_seen or seen
                assertions_complete = assertions_complete and complete
                violation = violation or failed
                if seen:
                    all_passed = all_passed and complete and not failed
                result["surfaces_tested"].append(str(step["resource"]))
                result["evidence_ids"].extend(self._evidence(scenario_id, item) for item in evidence)
            for mutation in scenario.get("mutations", []) if include_mutations else []:
                if not (self.network.scopes & ACTIVE_SCOPES):
                    result["status"] = "NOT_SCANNED"
                    result["reason_code"] = "active_scope_missing"
                    return result
                if not isinstance(mutation, dict):
                    raise ProfileError("scenario mutation must be an object")
                mutation_steps = mutation.get("steps", [mutation])
                if not isinstance(mutation_steps, list):
                    raise ProfileError("scenario mutation steps must be an array")
                mutation_failed = False
                mutation_seen = False
                for raw_step in mutation_steps:
                    if not isinstance(raw_step, dict):
                        raise ProfileError("scenario mutation step must be an object")
                    step = copy.deepcopy(raw_step)
                    if "resource" not in step:
                        step["resource"] = mutation.get("resource")
                    if "resource" not in step:
                        raise ProfileError("mutation must identify a declared resource")
                    response = requester(scenario_id, step)
                    last_response = response
                    seen, failed, complete, evidence = self._assertions(step, response, baseline, snapshots)
                    if step.get("state_snapshot"):
                        baseline = response
                    snapshots[str(step.get("id", ""))] = response
                    mutation_seen = mutation_seen or seen
                    assertions_complete = assertions_complete and complete
                    mutation_failed = mutation_failed or failed
                    result["surfaces_tested"].append(str(step["resource"]))
                    result["evidence_ids"].extend(self._evidence(scenario_id, item) for item in evidence)
                assertion_seen = assertion_seen or mutation_seen
                violation = violation or mutation_failed
                if mutation_seen:
                    all_passed = all_passed and not mutation_failed
            oracle = scenario.get("oracle", {})
            if isinstance(oracle, dict) and oracle and last_response is not None:
                oracle_step = {"assertions": _oracle_assertions(oracle)}
                seen, failed, complete, evidence = self._assertions(oracle_step, last_response, baseline, snapshots)
                assertion_seen = assertion_seen or seen
                assertions_complete = assertions_complete and complete
                violation = violation or failed
                if seen:
                    all_passed = all_passed and not failed and complete
                    result["evidence_ids"].extend(self._evidence(scenario_id, item) for item in evidence)
            result["executed"] = True
            if violation:
                result["status"] = "VULNERABLE"
                result["reason_code"] = "oracle_violation"
            elif not assertion_seen:
                result["status"] = "NEEDS_REVIEW"
                result["reason_code"] = "oracle_missing"
            elif not assertions_complete:
                result["status"] = "NEEDS_REVIEW"
                result["reason_code"] = "oracle_incomplete"
            elif all_passed:
                result["status"] = "PASS"
                result["reason_code"] = "declared_oracle_passed"
                result["coverage"] = {"required": 1, "completed": 1}
            else:
                result["status"] = "NEEDS_REVIEW"
                result["reason_code"] = "oracle_incomplete"
        except (ProfileError, NetworkPolicyError, BudgetExceeded, TypeError, ValueError, re.error) as exc:
            result["status"] = "NOT_SCANNED" if not result["executed"] else "NEEDS_REVIEW"
            result["reason_code"] = type(exc).__name__.lower()
        finally:
            cleanup_errors = self._cleanup(scenario_id, run_cleanup, requester)
            result["cleanup_completed"] = not cleanup_errors
            if cleanup_errors:
                result["cleanup_error"] = cleanup_errors[0]
                if result["status"] != "VULNERABLE":
                    result["status"] = "NEEDS_REVIEW"
                    result["reason_code"] = "cleanup_incomplete"
        result["surfaces_tested"] = sorted(set(str(item) for item in result["surfaces_tested"]))
        result["evidence_ids"] = list(dict.fromkeys(str(item) for item in result["evidence_ids"]))
        return result

    def run(self, scenario: Mapping[str, object]) -> dict[str, object]:
        return self._run_with_requester(scenario, self._request)

    def _cleanup(self, scenario_id: str, steps: Sequence[Mapping[str, object]], requester: Any) -> list[str]:
        errors: list[str] = []
        deadline = time.monotonic() + min(
            float(self.network.limits["cleanup_seconds"]),
            self.network.remaining_timeout(),
        )
        for raw_step in steps:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                errors.append("cleanup_timeout")
                break
            try:
                step = copy.deepcopy(raw_step)
                step["timeout"] = min(float(step.get("timeout") or remaining), remaining)
                requester(scenario_id, step)
            except Exception as exc:  # cleanup evidence must affect the final status
                errors.append(type(exc).__name__.lower())
        return errors

    @staticmethod
    def _scenario_assertion_types(scenario: Mapping[str, object]) -> set[str]:
        kinds: set[str] = set()
        for step in [*scenario.get("steps", []), *scenario.get("mutations", [])]:
            if not isinstance(step, dict):
                continue
            for assertion in step.get("assertions", []):
                if isinstance(assertion, dict):
                    kinds.add(str(assertion.get("type", assertion.get("kind", ""))))
        oracle = scenario.get("oracle", {})
        if isinstance(oracle, dict):
            kinds.update(
                str(item.get("type", item.get("kind", "")))
                for item in oracle.get("assertions", [])
                if isinstance(item, dict)
            )
            if "response_time_delta_max_ms" in oracle:
                kinds.add("response_time_delta_max_ms")
            if oracle.get("state_unchanged"):
                kinds.add("state_unchanged")
        return kinds

    def run_timing(self, scenario: Mapping[str, object]) -> dict[str, object]:
        result = self.run(scenario)
        kinds = self._scenario_assertion_types(scenario)
        has_baseline = any(
            isinstance(step, dict) and (step.get("state_snapshot") or str(step.get("id")) == "baseline")
            for step in scenario.get("steps", [])
        )
        if result["status"] == "PASS" and (
            not has_baseline or not kinds.intersection({"response_time_delta_max_ms", "response_time_not_delta"})
        ):
            result["status"] = "NEEDS_REVIEW"
            result["reason_code"] = "timing_baseline_oracle_missing"
            result["coverage"] = {"required": 1, "completed": 0}
        return result

    def run_state(self, scenario: Mapping[str, object]) -> dict[str, object]:
        state_changing = any(
            isinstance(step, dict) and str(step.get("method", "GET")).upper() not in NON_MUTATING_METHODS
            for step in scenario.get("mutations", [])
        )
        if state_changing and not scenario.get("cleanup"):
            return _scenario_not_run(scenario, "NOT_SCANNED", "state_cleanup_not_declared")
        result = self.run(scenario)
        kinds = self._scenario_assertion_types(scenario)
        has_baseline = any(
            isinstance(step, dict) and (step.get("state_snapshot") or str(step.get("id")) == "baseline")
            for step in scenario.get("steps", [])
        )
        if result["status"] == "PASS" and (
            not scenario.get("mutations")
            or not has_baseline
            or not kinds.intersection({"state_unchanged", "state_unchanged_after"})
        ):
            result["status"] = "NEEDS_REVIEW"
            result["reason_code"] = "state_contract_incomplete"
            result["coverage"] = {"required": 1, "completed": 0}
        return result

    def run_upload(self, scenario: Mapping[str, object]) -> dict[str, object]:
        if not scenario.get("cleanup"):
            return _scenario_not_run(scenario, "NOT_SCANNED", "upload_cleanup_not_declared")
        all_steps = [*scenario.get("steps", []), *scenario.get("mutations", [])]
        upload_indexes: list[int] = []
        for index, step in enumerate(all_steps):
            if not isinstance(step, dict) or step.get("body_type") != "multipart":
                continue
            body = step.get("body")
            file_part = body.get("file") if isinstance(body, dict) else None
            content = file_part.get("content") if isinstance(file_part, dict) else None
            if not isinstance(content, str) or not content.startswith("KODA-INERT-CANARY"):
                return _scenario_not_run(scenario, "NOT_SCANNED", "unsafe_upload_canary")
            upload_indexes.append(index)
        if not upload_indexes:
            return _scenario_not_run(scenario, "NOT_SCANNED", "upload_canary_missing")
        result = self.run(scenario)
        has_verification = any(
            index > upload_indexes[0]
            and isinstance(step, dict)
            and str(step.get("method", "GET")).upper() in READ_ONLY_METHODS
            and bool(step.get("assertions"))
            for index, step in enumerate(all_steps)
        )
        if result["status"] == "PASS" and not has_verification:
            result["status"] = "NEEDS_REVIEW"
            result["reason_code"] = "upload_contract_incomplete"
            result["coverage"] = {"required": 1, "completed": 0}
        return result

    def run_http_methods(self, scenario: Mapping[str, object]) -> dict[str, object]:
        result = _scenario_not_run(scenario, "NEEDS_REVIEW", "method_probe_not_declared")
        result["executed"] = False
        result["cleanup_completed"] = True
        result["coverage"] = {"required": 0, "completed": 0}
        scenario_id = str(scenario["id"])
        try:
            for template in scenario.get("steps", []):
                if not isinstance(template, dict):
                    continue
                resource = self.resources[str(template["resource"])]
                for method in resource.get("probe_methods", []):
                    if method not in NON_MUTATING_METHODS and not (self.network.scopes & ACTIVE_SCOPES):
                        raise NetworkPolicyError("active scope is required for state-changing method probes")
                    if method not in NON_MUTATING_METHODS and not scenario.get("cleanup"):
                        raise NetworkPolicyError("cleanup is required for state-changing method probes")
                    step = copy.deepcopy(template)
                    step.update({"method": method, "body": None, "body_type": "", "assertions": []})
                    response = self._request(scenario_id, step)
                    status = int(response["status"])
                    result["executed"] = True
                    result["coverage"]["required"] += 1
                    result["surfaces_tested"].append(str(resource["id"]))
                    allowed = {str(item).upper() for item in resource.get("methods", [])}
                    if "GET" in allowed:
                        allowed.add("HEAD")
                    allow_header = next(
                        (str(value) for key, value in response["headers"].items() if key.lower() == "allow"),
                        "",
                    )
                    advertised = {item.strip().upper() for item in allow_header.split(",") if item.strip()}
                    unexpected_advertised = advertised - allowed - {"OPTIONS"}
                    if method == "OPTIONS" and 200 <= status < 400 and not unexpected_advertised:
                        result["coverage"]["completed"] += 1
                        if result["status"] != "VULNERABLE":
                            result["status"] = "PASS"
                            result["reason_code"] = "options_response_allowed"
                        label = f"method:{resource['id']}:{method}:allowed"
                    elif method == "OPTIONS" and unexpected_advertised:
                        result["status"] = "VULNERABLE"
                        result["reason_code"] = "unexpected_method_advertised"
                        label = f"method:{resource['id']}:{method}:unexpected-advertisement"
                    elif 200 <= status < 400:
                        result["status"] = "VULNERABLE"
                        result["reason_code"] = "forbidden_method_accepted"
                        label = f"method:{resource['id']}:{method}:accepted"
                    elif status in {401, 403, 405, 501}:
                        result["coverage"]["completed"] += 1
                        if result["status"] != "VULNERABLE":
                            result["status"] = "PASS"
                            result["reason_code"] = "forbidden_methods_rejected"
                        label = f"method:{resource['id']}:{method}:rejected"
                    else:
                        if result["status"] != "VULNERABLE":
                            result["status"] = "NEEDS_REVIEW"
                            result["reason_code"] = "method_response_ambiguous"
                        label = f"method:{resource['id']}:{method}:ambiguous"
                    result["evidence_ids"].append(self._evidence(scenario_id, label))
        except (ProfileError, NetworkPolicyError, BudgetExceeded, TypeError, ValueError, re.error) as exc:
            result["status"] = "NOT_SCANNED" if not result["executed"] else "NEEDS_REVIEW"
            result["reason_code"] = type(exc).__name__.lower()
        cleanup_errors = self._cleanup(scenario_id, scenario.get("cleanup", []), self._request)
        if cleanup_errors:
            result["cleanup_completed"] = False
            result["cleanup_error"] = cleanup_errors[0]
            if result["status"] != "VULNERABLE":
                result["status"] = "NEEDS_REVIEW"
                result["reason_code"] = "cleanup_incomplete"
        result["surfaces_tested"] = sorted(set(result["surfaces_tested"]))
        result["evidence_ids"] = list(dict.fromkeys(result["evidence_ids"]))
        return result

    @staticmethod
    def _access_expectation(value: object) -> tuple[str, set[int] | None, list[str], list[str], dict[str, object]]:
        if isinstance(value, bool):
            return ("allow" if value else "deny", None, [], [], {})
        if isinstance(value, str):
            return (value.lower(), None, [], [], {})
        if not isinstance(value, dict):
            raise ProfileError("access expectation is invalid")
        status = str(value.get("status", "")).lower()
        statuses = value.get("statuses")
        status_set = {int(item) for item in statuses} if isinstance(statuses, list) else None
        if not status:
            status = "allow" if status_set and any(200 <= item < 400 for item in status_set) else "deny"
        return (
            status,
            status_set,
            [str(item) for item in value.get("body_contains", [])] if isinstance(value.get("body_contains"), list) else [],
            [str(item) for item in value.get("body_not_contains", [])] if isinstance(value.get("body_not_contains"), list) else [],
            value.get("headers", {}) if isinstance(value.get("headers"), dict) else {},
        )

    @classmethod
    def _access_matches(cls, response: Mapping[str, object], expectation: object) -> tuple[bool, bool]:
        """Return (matches, forbidden_access_observed)."""
        status, status_set, contains, not_contains, headers = cls._access_expectation(expectation)
        actual_status = int(response["status"])
        if status_set is not None:
            status_match = actual_status in status_set
        elif status == "allow":
            status_match = 200 <= actual_status < 400
        else:
            status_match = actual_status in {401, 403, 404}
        body = str(response["body"])
        body_match = all(value in body for value in contains) and all(value not in body for value in not_contains)
        header_match = True
        for name, rule in headers.items():
            actual = next((str(value) for key, value in response["headers"].items() if key.lower() == str(name).lower()), "")
            if isinstance(rule, dict):
                if "equals" in rule and actual != str(rule["equals"]):
                    header_match = False
                if "contains" in rule and str(rule["contains"]) not in actual:
                    header_match = False
                if "absent" in rule and ((not actual) != bool(rule["absent"])):
                    header_match = False
            elif isinstance(rule, bool):
                header_match = header_match and ((not actual) == rule)
            else:
                header_match = header_match and actual == str(rule)
        matches = status_match and body_match and header_match
        forbidden_access = status == "deny" and 200 <= actual_status < 400
        return matches, forbidden_access

    def run_access_matrix(self, scenario: Mapping[str, object]) -> dict[str, object]:
        result = _scenario_not_run(scenario, "NEEDS_REVIEW", "access_matrix_not_declared")
        result["executed"] = False
        result["cleanup_completed"] = True
        resources = self.resources
        matrix_targets: list[tuple[dict[str, object], dict[str, object]]] = []
        for step in scenario.get("steps", []):
            if not isinstance(step, dict):
                continue
            resource = resources[str(step["resource"])]
            if resource.get("access"):
                matrix_targets.append((resource, step))
        if not matrix_targets:
            return result
        result["status"] = "PASS"
        result["reason_code"] = "access_matrix_passed"
        result["coverage"] = {"required": 0, "completed": 0}
        try:
            for resource, template in matrix_targets:
                access = resource.get("access", {})
                actors = list(resource.get("actors", [])) or list(access)
                if not actors or any(actor not in access for actor in actors):
                    raise ProfileError(f"resource {resource['id']} has incomplete actor access expectations")
                for actor in actors:
                    expectation = access[actor]
                    state_oracle_requested = isinstance(expectation, dict) and bool(expectation.get("state_unchanged"))
                    state_before: dict[str, object] | None = None
                    state_step: dict[str, object] | None = None
                    if state_oracle_requested and expectation.get("state_resource"):
                        state_step = {
                            "resource": expectation["state_resource"],
                            "method": "GET",
                            "account": expectation.get("state_account", "" if actor == "anonymous" else actor),
                            "headers": {},
                            "query": {},
                            "body": None,
                            "body_type": "",
                            "delay_seconds": 0,
                        }
                        state_before = self._request(str(scenario["id"]), state_step)
                    step = copy.deepcopy(template)
                    step["account"] = "" if actor == "anonymous" else actor
                    response = self._request(str(scenario["id"]), step)
                    matches, forbidden_access = self._access_matches(response, expectation)
                    state_changed = False
                    state_complete = not state_oracle_requested
                    if state_before is not None and state_step is not None:
                        state_after = self._request(str(scenario["id"]), state_step)
                        state_changed = state_before.get("digest") != state_after.get("digest")
                        state_complete = True
                    result["executed"] = True
                    result["coverage"]["required"] += 1
                    result["surfaces_tested"].append(str(resource["id"]))
                    label = f"access:{resource['id']}:{actor}:{'pass' if matches else 'fail'}"
                    result["evidence_ids"].append(self._evidence(str(scenario["id"]), label))
                    if forbidden_access:
                        result["status"] = "VULNERABLE"
                        result["reason_code"] = "access_matrix_forbidden_access"
                    elif state_changed:
                        result["status"] = "VULNERABLE"
                        result["reason_code"] = "access_matrix_state_changed"
                    elif state_oracle_requested and not state_complete:
                        result["status"] = "NEEDS_REVIEW"
                        result["reason_code"] = "access_matrix_state_oracle_requires_baseline"
                    elif matches:
                        result["coverage"]["completed"] += 1
                    elif result["status"] != "VULNERABLE":
                        result["status"] = "NEEDS_REVIEW"
                        result["reason_code"] = "access_matrix_expectation_mismatch"
        except (ProfileError, NetworkPolicyError, BudgetExceeded, TypeError, ValueError, re.error) as exc:
            result["status"] = "NOT_SCANNED" if not result["executed"] else "NEEDS_REVIEW"
            result["reason_code"] = type(exc).__name__.lower()
        cleanup_errors = self._cleanup(str(scenario["id"]), scenario.get("cleanup", []), self._request)
        if cleanup_errors:
            result["cleanup_completed"] = False
            result["cleanup_error"] = cleanup_errors[0]
            if result["status"] != "VULNERABLE":
                result["status"] = "NEEDS_REVIEW"
                result["reason_code"] = "cleanup_incomplete"
        result["surfaces_tested"] = sorted(set(result["surfaces_tested"]))
        result["evidence_ids"] = list(dict.fromkeys(result["evidence_ids"]))
        return result

    def run_browser(self, scenario: Mapping[str, object]) -> dict[str, object]:
        steps = [step for step in scenario.get("steps", []) if isinstance(step, dict)]
        if not steps or any(str(step.get("method", "GET")).upper() != "GET" for step in steps):
            return _scenario_not_run(scenario, "UNSUPPORTED", "browser_navigation_supports_get_only")
        try:
            from .web import _USER_AGENT, _ensure_bundled_browsers_path, _merge_browser_cookies, _opener_cookies
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import sync_playwright
        except ImportError:
            return _scenario_not_run(scenario, "UNSUPPORTED", "package_capability_missing")
        _ensure_bundled_browsers_path()
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**self.network.browser_launch_options())
                try:
                    context = browser.new_context(user_agent=_USER_AGENT, **self.network.browser_context_options())
                    cookies = _opener_cookies(self.opener)
                    if cookies:
                        context.add_cookies(cookies)
                    page = context.new_page()
                    self._browser_page = page
                    self._browser_invalid_request = False
                    self._browser_invalid_response = False

                    def validate_request(route) -> None:
                        request = route.request
                        if request.url.startswith(("http://", "https://")):
                            try:
                                post_data = getattr(request, "post_data_buffer", None)
                                body_length = len(post_data or b"") if isinstance(post_data, (bytes, bytearray)) else 0
                                self.network.authorize_url(
                                    request.url,
                                    method=request.method,
                                    body_length=body_length,
                                )
                            except Exception:
                                self._browser_invalid_request = True
                                try:
                                    route.abort()
                                except Exception:
                                    pass
                                return
                        try:
                            route.continue_()
                        except Exception:
                            self._browser_invalid_request = True

                    def validate_response(response) -> None:
                        if response.url.startswith(("http://", "https://")) and not self.network.validate_browser_response(response):
                            self._browser_invalid_response = True

                    page.route("**/*", validate_request)
                    page.on("response", validate_response)

                    def request_with_browser_cleanup(scenario_id: str, step: Mapping[str, object]) -> dict[str, object]:
                        if str(step.get("method", "GET")).upper() == "GET":
                            return self._browser_request(scenario_id, step)
                        _merge_browser_cookies(self.opener, context.cookies())
                        response = self._request(scenario_id, step)
                        cookies_after = _opener_cookies(self.opener)
                        if cookies_after:
                            context.add_cookies(cookies_after)
                        return response

                    result = self._run_with_requester(scenario, request_with_browser_cleanup)
                    _merge_browser_cookies(self.opener, context.cookies())
                    return result
                finally:
                    self._browser_page = None
                    browser.close()
        except PlaywrightError:
            return _scenario_not_run(scenario, "NOT_SCANNED", "playwright_runtime_unavailable")
        except (OSError, RuntimeError):
            return _scenario_not_run(scenario, "NOT_SCANNED", "playwright_runtime_unavailable")


def _combine_strategy_results(scenario: Mapping[str, object], strategy_results: Sequence[Mapping[str, object]]) -> dict[str, object]:
    result = {
        "id": str(scenario["id"]),
        "control_id": str(scenario["control_id"]),
        "title": str(scenario.get("title", scenario["id"])),
        "required": bool(scenario.get("required", True)),
        "status": "NOT_SCANNED",
        "executed": any(bool(item.get("executed")) for item in strategy_results),
        "reason_code": "strategy_not_run",
        "coverage": {
            "required": len(strategy_results),
            "completed": sum(1 for item in strategy_results if item.get("status") == "PASS"),
        },
        "surfaces_tested": sorted({str(surface) for item in strategy_results for surface in item.get("surfaces_tested", [])}),
        "strategy_results": [copy.deepcopy(dict(item)) for item in strategy_results],
        "evidence_ids": list(dict.fromkeys(str(evidence) for item in strategy_results for evidence in item.get("evidence_ids", []))),
        "cleanup_completed": all(bool(item.get("cleanup_completed", True)) for item in strategy_results),
    }
    if not strategy_results:
        return result
    vulnerable = next((item for item in strategy_results if item.get("status") == "VULNERABLE"), None)
    review = next((item for item in strategy_results if item.get("status") == "NEEDS_REVIEW"), None)
    not_scanned = next((item for item in strategy_results if item.get("status") == "NOT_SCANNED"), None)
    unsupported = next((item for item in strategy_results if item.get("status") == "UNSUPPORTED"), None)
    if vulnerable is not None:
        result["status"] = "VULNERABLE"
        result["reason_code"] = str(vulnerable.get("reason_code", "strategy_vulnerable"))
    elif review is not None:
        result["status"] = "NEEDS_REVIEW"
        result["reason_code"] = str(review.get("reason_code", "strategy_review"))
    elif not_scanned is not None:
        result["status"] = "NOT_SCANNED"
        result["reason_code"] = str(not_scanned.get("reason_code", "strategy_not_scanned"))
    elif unsupported is not None:
        result["status"] = "UNSUPPORTED"
        result["reason_code"] = str(unsupported.get("reason_code", "package_capability_missing"))
    elif result["coverage"]["completed"] == result["coverage"]["required"]:
        result["status"] = "PASS"
        result["reason_code"] = "all_declared_strategies_passed"
    return result


def _zap_scenario_result(
    scenario: Mapping[str, object],
    strategy: str,
    zap_result: Mapping[str, object],
    zap_findings: Sequence[Mapping[str, object]],
    capabilities: Mapping[str, object],
) -> dict[str, object]:
    if not capabilities.get("zap", {}).get("available", False):
        reason = str(capabilities.get("zap", {}).get("reason_code", "zap_unavailable"))
        status = "UNSUPPORTED" if reason in {"package_capability_missing", "distribution_read_only"} else "NOT_SCANNED"
        return _scenario_not_run(scenario, status, reason)
    if strategy == "zap-active" and not zap_result.get("active_scan"):
        return _scenario_not_run(scenario, "NOT_SCANNED", "zap_active_not_enabled")
    if not zap_result.get("executed"):
        status = str(zap_result.get("status", "NOT_SCANNED"))
        if status not in STATUS_VALUES:
            status = "NOT_SCANNED"
        return _scenario_not_run(scenario, status, str(zap_result.get("reason_code", "zap_not_run")))
    relevant = [item for item in zap_findings if str(item.get("control_id", "")) == str(scenario["control_id"])]
    if relevant:
        result = _scenario_not_run(scenario, "VULNERABLE", "verified_alert")
        result["executed"] = True
        result["cleanup_completed"] = True
        result["evidence_ids"] = [str(item.get("evidence_id")) for item in relevant if item.get("evidence_id")]
        result["surfaces_tested"] = sorted({str(item.get("path", "")) for item in relevant})
        return result
    if zap_result.get("status") == "PASS":
        result = _scenario_not_run(scenario, "PASS", "zap_completed_without_alert")
        result["executed"] = True
        result["cleanup_completed"] = True
        result["coverage"] = {"required": 1, "completed": 1}
        return result
    return _scenario_not_run(scenario, "NEEDS_REVIEW", str(zap_result.get("reason_code", "zap_incomplete")))


def _finding_control(rule_id: str) -> str | None:
    direct = {
        "web.reflected-xss-verified": "web.xss",
        "web.sql-injection-error-verified": "web.sql-injection",
        "web.path-traversal-lfi": "web.file-download",
        "web.form-missing-csrf-token": "web.csrf",
        "web.http-trace-enabled": "web.http-methods",
        "web.http-methods-exposed": "web.http-methods",
        "web.no-https-redirect": "web.plaintext-transmission",
        "web.password-input-over-http": "web.plaintext-transmission",
        "web.mixed-content": "web.plaintext-transmission",
        "web.directory-listing": "web.directory-indexing",
        "web.information-disclosure": "web.information-disclosure",
        "web.sensitive-file-exposed": "web.information-disclosure",
        "web.cookie-missing-secure": "web.session-management",
        "web.cookie-missing-httponly": "web.session-management",
        "web.session-not-rotated": "web.session-management",
        "web.jwt-alg-none": "web.authentication",
        "web.jwt-missing-expiry": "web.session-management",
        "web.broken-access-control-unauth": "web.authorization",
        "web.broken-access-control-cross-account": "web.authorization",
        "web.cors-null-origin": "web.authorization",
        "web.cors-origin-reflection": "web.authorization",
        "web.cors-origin-reflection-credentials": "web.authorization",
        "web.cors-wildcard": "web.authorization",
        "web.cors-wildcard-credentials": "web.authorization",
        "web.database-error-disclosure": "web.error-pages",
        "web.error-stack-trace": "web.error-pages",
        "web.graphql-introspection-enabled": "web.information-disclosure",
        "web.host-header-injection": "web.information-disclosure",
        "web.open-redirect-verified": "web.information-disclosure",
        "web.server-version-disclosure": "web.information-disclosure",
        "web.x-powered-by-disclosure": "web.information-disclosure",
        "web.sensitive-path-exposed": "web.information-disclosure",
        "web.missing-csp": "web.plaintext-transmission",
        "web.weak-csp": "web.plaintext-transmission",
        "web.missing-frame-protection": "web.plaintext-transmission",
        "web.missing-hsts": "web.plaintext-transmission",
        "web.weak-hsts": "web.plaintext-transmission",
        "web.missing-permissions-policy": "web.plaintext-transmission",
        "web.missing-referrer-policy": "web.plaintext-transmission",
        "web.missing-x-content-type-options": "web.plaintext-transmission",
        "web.subresource-integrity-missing": "web.plaintext-transmission",
        "web.tls-certificate-expired": "web.plaintext-transmission",
        "web.tls-certificate-expiring": "web.plaintext-transmission",
        "web.tls-certificate-invalid": "web.plaintext-transmission",
        "web.weak-tls-version": "web.plaintext-transmission",
        "web.cookie-samesite-missing": "web.session-management",
    }
    if rule_id in direct:
        return direct[rule_id]
    if rule_id.startswith("dast.zap."):
        return None
    if rule_id.startswith("web.") and rule_id != "web.connection-failed":
        return "web.information-disclosure"
    return None


def _zap_control_id(title: str) -> str:
    lowered = title.lower()
    keywords = (
        (("xss", "cross-site scripting", "script"), "web.xss"),
        (("sql", "injection"), "web.sql-injection"),
        (("ssrf", "server-side request"), "web.ssrf"),
        (("csrf", "cross-site request"), "web.csrf"),
        (("path traversal", "directory traversal", "local file"), "web.file-download"),
        (("cookie", "session"), "web.session-management"),
        (("method", "trace"), "web.http-methods"),
        (("authentication", "login"), "web.authentication"),
        (("directory listing", "index of"), "web.directory-indexing"),
        (("admin", "management"), "web.admin-exposure"),
    )
    for needles, control_id in keywords:
        if any(needle in lowered for needle in needles):
            return control_id
    return "web.information-disclosure"


def _run_zap_strategy(
    profile: Mapping[str, object],
    network: NetworkContext,
    capabilities: Mapping[str, object],
    *,
    output_dir: Path | None,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    target = profile["target"]
    assert isinstance(target, dict)
    zap = target.get("zap") if isinstance(target.get("zap"), dict) else {}
    if not zap.get("enabled"):
        return [], {"executed": False, "status": "NOT_SCANNED", "reason_code": "not_configured"}
    if str(target.get("distribution", "")) == "app_store":
        return [], {"executed": False, "status": "UNSUPPORTED", "reason_code": "distribution_read_only"}
    if "zap" not in network.scopes:
        return [], {"executed": False, "status": "NOT_SCANNED", "reason_code": "zap_scope_missing"}
    capability = capabilities.get("zap") if isinstance(capabilities.get("zap"), dict) else {}
    if not capability.get("available"):
        return [], {"executed": False, "status": "NOT_SCANNED", "reason_code": str(capability.get("reason_code", "zap_unavailable"))}
    if zap.get("active") and not (network.scopes & ACTIVE_SCOPES):
        return [], {"executed": False, "status": "NOT_SCANNED", "reason_code": "active_scope_missing"}
    image = str(zap.get("image") or os.environ.get("KODA_ZAP_IMAGE", ""))
    origins = tuple(str(item) for item in target["origins"])
    include_source = zap.get("include_paths") or target.get("include_paths", [])
    exclude_source = [*target.get("exclude_paths", []), *zap.get("exclude_paths", [])]
    include_paths = tuple(".*" + re.escape(str(path)) for path in include_source)
    exclude_paths = tuple(".*" + re.escape(str(path)) for path in exclude_source)
    host_mappings: list[tuple[str, str]] = []
    for entry in network._origin_entries.values():
        if str(entry.get("kind", "target")) != "target":
            continue
        host = str(entry.get("host", ""))
        ips = [str(item) for item in entry.get("resolved_ips", [])]
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if host and ips and "." in host:
                host_mappings.append((host, ips[0]))
    from .dast import run_zap_automation

    destination = output_dir or Path("reports") / "web-audit" / network.run_id
    addon_manifest = zap.get("addon_manifest", {})
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "zap-addon-manifest.json").write_text(
        json.dumps(addon_manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    zap_auth: dict[str, object] | None = None
    zap_env_vars: set[str] = set()
    auth = profile.get("auth") if isinstance(profile.get("auth"), dict) else {}
    if auth:
        auth_method = str(auth.get("method", "form"))
        if auth_method in {"form", "json"}:
            username_env = str(auth.get("username_env", ""))
            password_env = str(auth.get("password_env", ""))
            username_ref = str(auth.get("username", ""))
            password_ref = str(auth.get("password", ""))
            username_match = ENV_REF_RE.fullmatch(username_ref)
            password_match = ENV_REF_RE.fullmatch(password_ref)
            username_env = username_env or (username_match.group(1) if username_match else "")
            password_env = password_env or (password_match.group(1) if password_match else "")
            if not username_env or not password_env:
                return [], {"executed": False, "status": "NOT_SCANNED", "reason_code": "zap_auth_reference_missing"}
            if not os.environ.get(username_env) or not os.environ.get(password_env):
                return [], {"executed": False, "status": "NOT_SCANNED", "reason_code": "zap_auth_credential_missing"}
            zap_env_vars.update((username_env, password_env))
            zap_auth = {
                "method": auth_method,
                "login_url": str(auth.get("login_url", "")),
                "login_request_url": str(auth.get("login_request_url", "")),
                "username_env": username_env,
                "password_env": password_env,
                "user_field": str(auth.get("user_field", "username")),
                "pass_field": str(auth.get("pass_field", "password")),
            }
            if auth_method == "json" and auth.get("token_json_path"):
                zap_auth.update({
                    "token_json_path": str(auth.get("token_json_path")),
                    "session_header": str(auth.get("session_header", "Authorization")),
                    "token_prefix": str(auth.get("token_prefix", "Bearer ")),
                })
        elif auth_method == "header":
            header_envs: dict[str, str] = {}
            raw_headers = auth.get("headers", {})
            if not isinstance(raw_headers, dict):
                return [], {"executed": False, "status": "NOT_SCANNED", "reason_code": "zap_header_auth_reference_missing"}
            for header_name, value in raw_headers.items():
                match = ENV_REF_RE.fullmatch(str(value).strip())
                if not match:
                    return [], {"executed": False, "status": "NOT_SCANNED", "reason_code": "zap_header_auth_reference_missing"}
                env_name = match.group(1)
                if not os.environ.get(env_name):
                    return [], {"executed": False, "status": "NOT_SCANNED", "reason_code": "zap_auth_credential_missing"}
                header_envs[str(header_name)] = env_name
                zap_env_vars.add(env_name)
            if not header_envs:
                return [], {"executed": False, "status": "NOT_SCANNED", "reason_code": "zap_header_auth_reference_missing"}
            zap_auth = {"method": "header", "header_envs": header_envs}
    mapped: list[dict[str, object]] = []
    exit_codes: list[int] = []
    run_errors: list[str] = []
    scanned_origins: list[str] = []
    for index, target_origin in enumerate(origins):
        origin = target_origin
        parsed_origin = urllib.parse.urlsplit(origin)
        default_port = 443 if parsed_origin.scheme == "https" else 80
        if parsed_origin.port == default_port:
            host = parsed_origin.hostname or ""
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            origin = urllib.parse.urlunsplit((parsed_origin.scheme, host, "", "", ""))
        run_destination = destination if len(origins) == 1 else destination / f"origin-{index + 1}"
        try:
            run = run_zap_automation(
                origin,
                output_dir=run_destination,
                minutes=int(profile["limits"]["zap_minutes"]),
                active_scan=bool(zap.get("active")),
                include_paths=include_paths,
                exclude_paths=exclude_paths,
                image=image,
                host_mappings=tuple(host_mappings),
                environment_vars=tuple(sorted(zap_env_vars)),
                zap_rps=float(profile["limits"]["zap_rps"]),
                zap_threads_per_host=int(profile["limits"]["zap_threads_per_host"]),
                zap_rule_minutes=int(profile["limits"]["zap_rule_minutes"]),
                max_response_bytes=int(profile["limits"]["max_response_bytes"]),
                auth=zap_auth,
                pull_never=True,
                dry_run=False,
                timeout_seconds=min(
                    int(profile["limits"]["timeout_seconds"]),
                    int(profile["limits"]["zap_minutes"]) * 60 + 30,
                ),
            )
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            run_errors.append(type(exc).__name__.lower())
            continue
        scanned_origins.append(target_origin)
        exit_codes.append(int(run.exit_code))
        for finding in run.findings:
            control_id = _zap_control_id(str(finding.title))
            evidence_id = f"web-audit:zap:{hashlib.sha256(canonical_json({'title': finding.title, 'target': str(finding.target), 'origin': target_origin})).hexdigest()[:16]}"
            mapped.append({
                "rule_id": "web.zap-alert",
                "control_id": control_id,
                "category": "web",
                "severity": str(finding.severity),
                "title": "검증된 동적 웹 취약점 경고",
                "path": str(finding.target or target_origin),
                "evidence_id": evidence_id,
                "evidence": "ZAP Automation Framework verified an alert; raw plugin identifiers and request data are withheld.",
            })
    status = "VULNERABLE" if mapped else ("NEEDS_REVIEW" if run_errors or any(code != 0 for code in exit_codes) or len(scanned_origins) != len(origins) else "PASS")
    return mapped, {
        "executed": bool(scanned_origins),
        "status": status,
        "reason_code": "verified_alert" if mapped else ("zap_execution_incomplete" if status == "NEEDS_REVIEW" else "zap_completed"),
        "exit_code": max(exit_codes, default=1 if run_errors else 0),
        "exit_codes": exit_codes,
        "origins_scanned": scanned_origins,
        "output_dir": str(destination),
        "active_scan": bool(zap.get("active")),
        "envelope": {
            "rps": float(profile["limits"]["zap_rps"]),
            "threads_per_host": int(profile["limits"]["zap_threads_per_host"]),
            "scan_minutes": int(profile["limits"]["zap_minutes"]),
            "rule_minutes": int(profile["limits"]["zap_rule_minutes"]),
        },
        "addon_manifest": copy.deepcopy(addon_manifest),
    }


def _capability_snapshot(profile: Mapping[str, object], *, dry_run: bool = False) -> dict[str, object]:
    target = profile["target"]
    assert isinstance(target, dict)
    oast = profile.get("oast") if isinstance(profile.get("oast"), dict) else {}
    oast_secret = os.environ.get("KODA_OAST_SECRET", "")
    oast_secret_ready = _valid_oast_secret(oast_secret)
    oast_ready = bool(oast.get("control_plane_origin") and oast.get("callback_domain") and oast_secret_ready and "oast" in set(target.get("scopes", [])))
    capabilities: dict[str, object] = {
        "native": {"available": True, "reason_code": "stdlib"},
        "playwright": {"available": False, "reason_code": "not_checked"},
        "zap": {"available": False, "reason_code": "not_configured"},
        "oast": {
            "available": oast_ready,
            "reason_code": (
                "profile_declared"
                if oast_ready
                else (
                    "scope_missing"
                    if oast and "oast" not in set(target.get("scopes", []))
                    else ("secret_invalid" if oast and oast_secret else ("secret_missing" if oast else "not_configured"))
                )
            ),
        },
    }
    if target.get("distribution") == "source_only" or os.environ.get("KODA_SOURCE_ONLY") == "1":
        capabilities["native"] = {"available": False, "reason_code": "package_capability_missing"}
    try:
        import importlib.util

        if importlib.util.find_spec("playwright") is not None:
            try:
                from .web import _ensure_bundled_browsers_path
                from playwright.sync_api import sync_playwright

                _ensure_bundled_browsers_path()
                with sync_playwright() as playwright:
                    executable = Path(playwright.chromium.executable_path)
                capabilities["playwright"] = {
                    "available": executable.is_file(),
                    "reason_code": "installed" if executable.is_file() else "browser_missing",
                }
            except (ImportError, OSError, RuntimeError, AttributeError):
                capabilities["playwright"] = {"available": False, "reason_code": "browser_missing"}
        else:
            capabilities["playwright"] = {"available": False, "reason_code": "package_capability_missing"}
    except (ImportError, ModuleNotFoundError):
        capabilities["playwright"] = {"available": False, "reason_code": "package_capability_missing"}
    zap = target.get("zap", {})
    if isinstance(zap, dict) and bool(zap.get("enabled")):
        image = str(zap.get("image") or os.environ.get("KODA_ZAP_IMAGE", ""))
        if "@sha256:" not in image:
            capabilities["zap"] = {"available": False, "reason_code": "digest_required"}
        elif not zap.get("addon_manifest"):
            capabilities["zap"] = {"available": False, "reason_code": "addon_manifest_required"}
        elif dry_run:
            capabilities["zap"] = {"available": True, "reason_code": "digest_declared_dry_run"}
        else:
            try:
                daemon = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=20, check=False)
                if daemon.returncode != 0:
                    capabilities["zap"] = {"available": False, "reason_code": "docker_unavailable"}
                else:
                    image_check = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True, timeout=20, check=False)
                    capabilities["zap"] = {
                        "available": image_check.returncode == 0,
                        "reason_code": "docker_ready" if image_check.returncode == 0 else "zap_image_missing",
                    }
            except (OSError, subprocess.SubprocessError):
                capabilities["zap"] = {"available": False, "reason_code": "docker_unavailable"}
    return capabilities


def plan_profile(profile: Mapping[str, object] | str | Path) -> dict[str, object]:
    normalized = load_profile(profile)
    request = build_approval_request(normalized)
    capabilities = _capability_snapshot(normalized, dry_run=True)
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "koda.web-audit.plan",
        "profile_sha256": profile_hash(normalized),
        "approval_request": request,
        "capabilities": capabilities,
        "traffic": {"target_requests": 0, "dns_resolution": True, "network_connections": 0},
        "controls": [
            {
                "id": control_id,
                "title": CONTROL_TITLES[control_id],
                "declared": any(item.get("control_id") == control_id for item in normalized["scenarios"]),
                "applicability": normalized["applicability"].get(control_id),
            }
            for control_id in CONTROL_IDS
        ],
    }


def _control_result(control_id: str) -> dict[str, object]:
    return {
        "id": control_id,
        "title": CONTROL_TITLES[control_id],
        "status": "NOT_SCANNED",
        "executed": False,
        "reason_code": "strategy_not_declared",
        "coverage": {"required": 1, "completed": 0},
        "surfaces_tested": [],
        "strategy_results": [],
        "evidence_ids": [],
    }


def _scenario_not_run(scenario: Mapping[str, object], status: str, reason: str) -> dict[str, object]:
    return {
        "id": str(scenario["id"]),
        "control_id": str(scenario["control_id"]),
        "title": str(scenario.get("title", scenario["id"])),
        "required": bool(scenario.get("required", True)),
        "status": status,
        "executed": False,
        "reason_code": reason,
        "coverage": {"required": 1, "completed": 0},
        "surfaces_tested": sorted({str(step.get("resource", "")) for step in scenario.get("steps", []) if isinstance(step, dict)}),
        "strategy_results": [],
        "evidence_ids": [],
        "cleanup_completed": False,
    }


def aggregate_results(
    profile: Mapping[str, object],
    *,
    scenario_results: Sequence[Mapping[str, object]] = (),
    findings: Sequence[Mapping[str, object]] = (),
    capabilities: Mapping[str, object] | None = None,
    passive_completed: bool = False,
) -> list[dict[str, object]]:
    normalized = load_profile(profile)
    results = {control_id: _control_result(control_id) for control_id in CONTROL_IDS}
    applicability = normalized["applicability"]
    for control_id, item in applicability.items():
        results[control_id].update({"status": "NOT_APPLICABLE", "executed": False, "reason_code": "profile_not_applicable", "reason": item["reason"]})
    for scenario in scenario_results:
        control_id = str(scenario.get("control_id", ""))
        if control_id not in results:
            continue
        if results[control_id]["status"] == "NOT_APPLICABLE":
            continue
        entry = results[control_id]
        entry["executed"] = bool(entry["executed"]) or bool(scenario.get("executed"))
        entry["strategy_results"].append(copy.deepcopy(dict(scenario)))
        entry["surfaces_tested"] = sorted(set(entry["surfaces_tested"]) | set(scenario.get("surfaces_tested", [])))
        entry["evidence_ids"] = list(dict.fromkeys([*entry["evidence_ids"], *scenario.get("evidence_ids", [])]))
        if scenario.get("status") == "VULNERABLE":
            entry.update({"status": "VULNERABLE", "reason_code": "scenario_oracle_violation"})
    # A control closes only after every required scenario for that control has
    # completed.  Optional scenarios enrich evidence but cannot manufacture a
    # PASS on their own.
    results_by_scenario = {
        str(item.get("id")): item
        for item in scenario_results
        if isinstance(item, Mapping)
    }
    for control_id, entry in results.items():
        if entry["status"] == "VULNERABLE" or entry["status"] == "NOT_APPLICABLE":
            continue
        required_definitions = [
            item for item in normalized["scenarios"]
            if item.get("control_id") == control_id and bool(item.get("required", True))
        ]
        if not required_definitions:
            continue
        required_results = [results_by_scenario.get(str(item["id"])) for item in required_definitions]
        completed = sum(1 for item in required_results if isinstance(item, Mapping) and item.get("status") == "PASS")
        entry["coverage"] = {"required": len(required_definitions), "completed": completed}
        review = next((item for item in required_results if isinstance(item, Mapping) and item.get("status") == "NEEDS_REVIEW"), None)
        unsupported = next((item for item in required_results if isinstance(item, Mapping) and item.get("status") == "UNSUPPORTED"), None)
        not_scanned = next((item for item in required_results if not isinstance(item, Mapping) or item.get("status") == "NOT_SCANNED"), None)
        if review is not None:
            entry.update({"status": "NEEDS_REVIEW", "reason_code": str(review.get("reason_code", "scenario_review"))})
        elif unsupported is not None:
            entry.update({"status": "UNSUPPORTED", "reason_code": str(unsupported.get("reason_code", "package_capability_missing"))})
        elif not_scanned is not None:
            entry.update({"status": "NOT_SCANNED", "reason_code": str(not_scanned.get("reason_code", "scenario_not_scanned"))})
        elif completed == len(required_definitions):
            entry.update({"status": "PASS", "reason_code": "declared_oracle_passed"})
    for finding in findings:
        control_id = str(finding.get("control_id", "")) or _finding_control(str(finding.get("rule_id", "")))
        if not control_id or control_id not in results or results[control_id]["status"] == "NOT_APPLICABLE":
            continue
        entry = results[control_id]
        evidence_id = str(finding.get("evidence_id") or f"finding:{hashlib.sha256(canonical_json(finding)).hexdigest()[:16]}")
        entry["evidence_ids"] = list(dict.fromkeys([*entry["evidence_ids"], evidence_id]))
        entry["surfaces_tested"] = list(dict.fromkeys([*entry["surfaces_tested"], str(finding.get("path", ""))]))
        entry["executed"] = True
        entry["strategy_results"].append({"strategy": "koda-web", "finding_evidence_id": evidence_id, "status": "VULNERABLE"})
        entry.update({"status": "VULNERABLE", "reason_code": "verified_finding"})
    # A completed crawl is evidence that the passive engine ran, not an oracle
    # for every control.  Passive scenarios are closed only by their own
    # declared strategy result above.
    for control_id, entry in results.items():
        if entry["status"] == "PASS":
            if not entry["executed"] or entry["coverage"]["completed"] < entry["coverage"]["required"]:
                entry.update({"status": "NEEDS_REVIEW", "reason_code": "coverage_incomplete"})
        if entry["status"] == "NOT_SCANNED" and capabilities:
            if isinstance(capabilities.get("native"), dict) and not capabilities["native"].get("available", True):
                entry.update({"status": "UNSUPPORTED", "reason_code": "package_capability_missing"})
    return [results[control_id] for control_id in CONTROL_IDS]


def _finding_payload(finding: object) -> dict[str, object]:
    if isinstance(finding, Mapping):
        result = dict(finding)
    else:
        result = {
            "rule_id": str(getattr(finding, "rule_id", "")),
            "category": str(getattr(finding, "category", "host")),
            "severity": str(getattr(finding, "severity", "info")),
            "path": str(getattr(finding, "path", "")),
            "title": str(getattr(finding, "title", "")),
            "evidence": str(getattr(finding, "evidence", "")),
            "description": str(getattr(finding, "description", "")),
            "recommendation": str(getattr(finding, "recommendation", "")),
            "target": str(getattr(finding, "target", "")),
            "evidence_id": str(getattr(finding, "evidence_id", "")),
        }
    # Dynamic reports never expose headers, cookies, credentials, or raw bodies.
    for key in ("request", "response", "headers", "cookies", "token", "password", "secret", "raw"):
        result.pop(key, None)
    for key in ("evidence", "description", "recommendation", "target"):
        if key in result:
            result[key] = _redact(str(result[key]))
    for key in ("path", "target"):
        if key in result:
            parsed = urllib.parse.urlsplit(str(result[key]))
            if parsed.scheme and parsed.netloc:
                result[key] = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
            else:
                result[key] = _redact(str(result[key]))
    return result


def _auth_value(auth: Mapping[str, object], value_key: str, env_key: str) -> str:
    env_name = str(auth.get(env_key, ""))
    if env_name:
        return os.environ.get(env_name, "")
    raw = auth.get(value_key, "")
    return str(raw) if raw is not None else ""


def _json_path(value: object, path: str) -> object:
    current = value
    for part in path.split("."):
        if not part or not re.fullmatch(r"[A-Za-z0-9_-]+", part) or not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _opener_cookie_count(opener: urllib.request.OpenerDirector) -> int:
    for handler in getattr(opener, "handlers", ()):
        jar = getattr(handler, "cookiejar", None)
        if jar is not None:
            return len(jar)
    return 0


def _perform_authentication(
    auth: Mapping[str, object],
    network: NetworkContext,
    opener: urllib.request.OpenerDirector,
    *,
    run_id: str,
) -> tuple[dict[str, str], list[str], list[object], dict[str, object]]:
    """Authenticate without putting credentials in the audit result or ZAP plan."""
    if not auth:
        return {}, [], [], {"status": "NOT_CONFIGURED"}
    method = str(auth.get("method", "form")).lower()
    extra_headers = _safe_header_items(_interpolate(auth.get("headers", {}), {}, run_id))
    if method == "header":
        raw_headers = auth.get("headers", {})
        if isinstance(raw_headers, dict):
            for value in raw_headers.values():
                match = ENV_REF_RE.fullmatch(str(value).strip())
                if match and not os.environ.get(match.group(1)):
                    return extra_headers, ["web-audit authentication was not completed: header credential reference is empty"], [], {
                        "status": "NOT_SCANNED", "method": method, "reason_code": "credential_reference_empty",
                    }
        return extra_headers, [], [], {"status": "PASS", "method": "header"}
    username = _auth_value(auth, "username", "username_env")
    password = _auth_value(auth, "password", "password_env")
    if not username or not password:
        return extra_headers, ["web-audit authentication was not completed: credential reference is empty"], [], {
            "status": "NOT_SCANNED", "method": method, "reason_code": "credential_reference_empty",
        }
    login_url = str(_interpolate(auth.get("login_url", ""), {}, run_id) or "")
    request_url = str(_interpolate(auth.get("login_request_url", ""), {}, run_id) or "") or login_url
    if not request_url:
        return extra_headers, ["web-audit authentication was not completed: login URL is missing"], [], {
            "status": "NOT_SCANNED", "method": method, "reason_code": "login_url_missing",
        }
    from .web import login

    if method == "form":
        login_result: dict[str, object] = {}
        warnings, findings = login(
            opener,
            login_url,
            username,
            password,
            user_field=str(auth.get("user_field") or "") or None,
            pass_field=str(auth.get("pass_field") or "") or None,
            request_url=str(auth.get("login_request_url") or "") or None,
            extra_headers=extra_headers,
            timeout=min(float(network.limits["timeout_seconds"]), network.remaining_timeout()),
            result=login_result,
        )
        login_result["method"] = method
        return extra_headers, warnings, findings, login_result

    if method != "json":
        return extra_headers, [f"web-audit authentication was not completed: unsupported method {method}"], [], {
            "status": "NOT_SCANNED", "method": method, "reason_code": "auth_method_unsupported",
        }
    user_field = str(auth.get("user_field") or "username")
    pass_field = str(auth.get("pass_field") or "password")
    body = json.dumps({user_field: username, pass_field: password}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    headers = {"User-Agent": "KODA-web-scanner (+https://gitlab.aigov.go.kr/y2kthr/koda)", **extra_headers, "Content-Type": "application/json"}
    request = urllib.request.Request(request_url, data=body, headers=headers, method="POST")
    timeout = min(float(network.limits["timeout_seconds"]), network.remaining_timeout())
    if timeout <= 0:
        return extra_headers, ["web-audit authentication was not completed: time budget exceeded"], [], {
            "status": "NOT_SCANNED", "method": method, "reason_code": "time_budget_exceeded",
        }
    cookies_before = _opener_cookie_count(opener)
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(response.status)
            response_body = _read_bounded(response, int(network.limits["max_response_bytes"]), timeout)
    except urllib.error.HTTPError as exc:
        try:
            status = int(exc.code)
            response_body = _read_bounded(exc, int(network.limits["max_response_bytes"]), timeout)
        finally:
            exc.close()
    except (urllib.error.URLError, OSError, ssl.SSLError, socket.timeout, NetworkPolicyError) as exc:
        return extra_headers, [f"web-audit authentication was not completed: {type(exc).__name__}"], [], {
            "status": "NOT_SCANNED", "method": method, "reason_code": "auth_request_failed",
        }
    cookie_observed = _opener_cookie_count(opener) > cookies_before
    auth_result: dict[str, object] = {
        "status": "PASS" if 200 <= status < 400 else "NOT_SCANNED",
        "method": method,
        "http_status": status,
        "session_cookie_observed": cookie_observed,
    }
    token_path = str(auth.get("token_json_path", ""))
    if token_path:
        try:
            parsed = json.loads(response_body.decode("utf-8", "replace"))
        except (UnicodeError, json.JSONDecodeError):
            parsed = None
        token = _json_path(parsed, token_path)
        if isinstance(token, (str, int, float)) and str(token):
            header_name = str(auth.get("session_header", "Authorization"))
            prefix = str(auth.get("token_prefix", "Bearer "))
            extra_headers[header_name] = prefix + str(token)
            auth_result["session_header_set"] = True
        else:
            auth_result["status"] = "NEEDS_REVIEW"
            auth_result["reason_code"] = "token_json_path_not_found"
    elif 200 <= status < 400 and not cookie_observed:
        auth_result["status"] = "NEEDS_REVIEW"
        auth_result["reason_code"] = "session_not_observed"
    return extra_headers, [], [], auth_result


def _public_auth_result(value: Mapping[str, object]) -> dict[str, object]:
    allowed = {
        "status", "method", "http_status", "reason_code", "session_cookie_observed",
        "session_header_set", "session_cookie_received", "session_rotated",
    }
    return {key: copy.deepcopy(value[key]) for key in allowed if key in value}


def run_web_audit(
    profile: Mapping[str, object] | str | Path,
    approval: Mapping[str, object] | str | Path | None,
    *,
    confirm_origin: str,
    key: str | bytes | None = None,
    state_dir: Path | None = None,
    output_dir: Path | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    normalized = load_profile(profile)
    if approval is None:
        raise ApprovalError("web-audit run requires a signed approval")
    if dry_run:
        approval_info = verify_approval(normalized, approval, confirm_origin=confirm_origin, key=key, state_dir=state_dir, consume=False)
    else:
        approval_info = verify_approval(normalized, approval, confirm_origin=confirm_origin, key=key, state_dir=state_dir, consume=True)
    capabilities = _capability_snapshot(normalized, dry_run=dry_run)
    if not capabilities["native"]["available"]:
        controls = aggregate_results(normalized, capabilities=capabilities)
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "koda.web-audit.result",
            "status": "UNSUPPORTED",
            "profile_sha256": profile_hash(normalized),
            "approval": approval_info,
            "capabilities": capabilities,
            "controls": controls,
            "traffic": {"requests": 0, "pages": 0, "oast_callbacks": 0},
            "findings": [],
        }
    if dry_run:
        controls = aggregate_results(normalized, capabilities=capabilities)
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "koda.web-audit.result",
            "status": "NOT_SCANNED",
            "profile_sha256": profile_hash(normalized),
            "approval": approval_info,
            "capabilities": capabilities,
            "controls": controls,
            "traffic": {"requests": 0, "pages": 0, "oast_callbacks": 0},
            "findings": [],
        }
    network = NetworkContext(normalized, {"origins": approval_info.get("origins", []), "envelope": approval_info.get("envelope", {})})
    findings: list[object] = []
    warnings: list[str] = []
    pages = 0
    passive_completed = False
    scopes = set(normalized["target"]["scopes"])
    opener = network.build_opener()
    auth_config = normalized.get("auth") if isinstance(normalized.get("auth"), dict) else {}
    extra_headers: dict[str, str] = {}
    auth_result: dict[str, object] = {"status": "NOT_CONFIGURED"}
    if auth_config:
        auth_method = str(auth_config.get("method", "form")).lower()
        if auth_method in {"form", "json"} and not (scopes & ACTIVE_SCOPES):
            auth_result = {"status": "NOT_SCANNED", "method": auth_method, "reason_code": "active_scope_missing"}
            warnings.append("web-audit authentication was not completed: state_change scope is required for login")
        else:
            try:
                extra_headers, auth_warnings, auth_findings, auth_result = _perform_authentication(
                    auth_config, network, opener, run_id=network.run_id,
                )
                warnings.extend(auth_warnings)
                findings.extend(auth_findings)
            except (ProfileError, NetworkPolicyError, OSError, ValueError) as exc:
                auth_result = {"status": "NOT_SCANNED", "method": auth_method, "reason_code": type(exc).__name__.lower()}
                warnings.append(f"web-audit authentication was not completed: {type(exc).__name__}")
    first_origin = str(normalized["target"]["origins"][0])
    include_paths = normalized["target"].get("include_paths", ["/"])
    seed_url = urllib.parse.urljoin(first_origin, str(include_paths[0]))
    if "passive" in scopes:
        from .web import crawl_web

        try:
            crawl_timeout = min(float(normalized["limits"]["timeout_seconds"]), network.remaining_timeout())
            if crawl_timeout <= 0:
                raise BudgetExceeded("web-audit time budget exceeded")
            crawl_findings, crawl_warnings, pages = crawl_web(
                seed_url,
                timeout=crawl_timeout,
                max_pages=int(normalized["limits"]["requests"]),
                max_depth=3,
                delay=0.0,
                opener=opener,
                extra_headers=extra_headers or None,
                render="browser" in scopes,
                active="active" in scopes,
                probe_paths="active" in scopes,
                allowed_origins=tuple(str(item) for item in normalized["target"]["origins"]),
                network_context=network,
            )
            findings.extend(crawl_findings)
            warnings.extend(crawl_warnings)
            passive_completed = pages > 0
        except (BudgetExceeded, NetworkPolicyError, OSError, ValueError) as exc:
            warnings.append(f"web-audit passive strategy not completed: {type(exc).__name__}")
    zap_findings, zap_result = _run_zap_strategy(
        normalized,
        network,
        capabilities,
        output_dir=output_dir,
    )
    if zap_result.get("executed") and zap_result.get("status") == "NEEDS_REVIEW":
        warnings.append("ZAP strategy did not produce a complete result")
    scenario_runner = ScenarioRunner(normalized, network, base_headers=extra_headers)
    scenario_results: list[dict[str, object]] = []
    oast_client: OastClient | None = None
    oast_callbacks = 0
    for scenario in normalized["scenarios"]:
        strategy_results: list[dict[str, object]] = []
        for strategy in [str(item).lower() for item in scenario.get("strategies", [])]:
            if strategy in {"browser", "playwright", "dom", "browser-canary"}:
                if "browser" not in scopes:
                    item = _scenario_not_run(scenario, "NOT_SCANNED", "browser_scope_missing")
                elif not capabilities["playwright"]["available"]:
                    capability_reason = str(capabilities["playwright"].get("reason_code", "playwright_unavailable"))
                    capability_status = "UNSUPPORTED" if capability_reason == "package_capability_missing" else "NOT_SCANNED"
                    item = _scenario_not_run(scenario, capability_status, capability_reason)
                else:
                    item = scenario_runner.run_browser(scenario)
            elif strategy in {"oast", "ssrf-oast", "callback"}:
                if not capabilities["oast"]["available"]:
                    capability_reason = str(capabilities["oast"].get("reason_code", "oast_unavailable"))
                    capability_status = "UNSUPPORTED" if capability_reason == "package_capability_missing" else "NOT_SCANNED"
                    item = _scenario_not_run(scenario, capability_status, capability_reason)
                else:
                    try:
                        if oast_client is None:
                            oast_client = OastClient(normalized, network)
                        scenario_runner.captures["OAST_PAYLOAD"] = oast_client.register()
                        item = scenario_runner.run(scenario)
                        if item["executed"]:
                            callback_count, polling_complete = oast_client.poll()
                            oast_callbacks += callback_count
                            item["oast_callbacks"] = callback_count
                            if callback_count:
                                item["status"] = "VULNERABLE"
                                item["reason_code"] = "oast_callback_received"
                                item["evidence_ids"].append(f"web-audit:{scenario['id']}:oast-callback:{callback_count}")
                            elif not polling_complete and item["status"] == "PASS":
                                item["status"] = "NEEDS_REVIEW"
                                item["reason_code"] = "oast_poll_incomplete"
                            elif polling_complete and item["status"] == "PASS":
                                item["reason_code"] = "oast_callback_absent"
                    except (NetworkPolicyError, BudgetExceeded, ProfileError):
                        item = _scenario_not_run(scenario, "NOT_SCANNED", "oast_registration_failed")
            elif strategy in {"zap", "zap-active", "zap-passive"}:
                item = _zap_scenario_result(scenario, strategy, zap_result, zap_findings, capabilities)
            elif strategy in {"access-control", "authorization", "matrix"}:
                item = scenario_runner.run_access_matrix(scenario)
            elif strategy == "timing":
                item = scenario_runner.run_timing(scenario)
            elif strategy == "state":
                item = scenario_runner.run_state(scenario)
            elif strategy == "http-methods":
                item = scenario_runner.run_http_methods(scenario)
            elif strategy == "upload":
                item = scenario_runner.run_upload(scenario)
            elif strategy == "passive":
                item = scenario_runner._run_with_requester(scenario, scenario_runner._request, include_mutations=False, include_cleanup=False)
                if not passive_completed and item["status"] == "PASS":
                    item["status"] = "NOT_SCANNED"
                    item["reason_code"] = "passive_strategy_not_completed"
            else:
                item = scenario_runner.run(scenario)
            item["strategy"] = strategy
            strategy_results.append(item)
        scenario_results.append(_combine_strategy_results(scenario, strategy_results))
    control_results = aggregate_results(
        normalized,
        scenario_results=scenario_results,
        findings=[_finding_payload(item) for item in [*findings, *zap_findings]],
        capabilities=capabilities,
        passive_completed=passive_completed,
    )
    vulnerable = any(item["status"] == "VULNERABLE" for item in control_results)
    unresolved = any(item["status"] in {"NEEDS_REVIEW", "NOT_SCANNED"} for item in control_results)
    unsupported = any(item["status"] == "UNSUPPORTED" for item in control_results)
    result_status = "VULNERABLE" if vulnerable else ("NEEDS_REVIEW" if unresolved else ("UNSUPPORTED" if unsupported else "PASS"))
    result: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "koda.web-audit.result",
        "status": result_status,
        "profile_sha256": profile_hash(normalized),
        "approval": approval_info,
        "capabilities": capabilities,
        "controls": control_results,
        "traffic": {"requests": network.request_count, "pages": pages, "oast_callbacks": oast_callbacks},
        "auth": _public_auth_result(auth_result),
        "warnings": [_redact(str(item)) for item in warnings],
        "findings": [_finding_payload(item) for item in [*findings, *zap_findings]],
    }
    if zap_result.get("executed") or zap_result.get("reason_code") != "not_configured":
        result["zap"] = zap_result
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "web-audit-result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def attach_to_dashboard_payload(payload: dict[str, object], result: Mapping[str, object]) -> dict[str, object]:
    """Attach a redacted web audit result without leaking dynamic secrets."""
    payload["web_audit"] = {
        key: copy.deepcopy(result[key])
        for key in ("schema_version", "kind", "status", "profile_sha256", "capabilities", "controls", "traffic", "warnings")
        if key in result
    }
    return payload
