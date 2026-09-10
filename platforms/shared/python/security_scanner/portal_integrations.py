"""Small stdlib-only clients for the Linux portal's trusted integrations."""
from __future__ import annotations

import base64
from collections import Counter
import hashlib
import json
import os
import re
import ssl
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


MAX_GITLAB_PROJECTS = 50_000
MAX_GITLAB_REFS = 10_000
MAX_GITLAB_MARKER_ITEMS = 50_000
MAX_GITLAB_PAGES = 500
MAX_GITLAB_JSON_BYTES = 32 * 1024 * 1024
MAX_GITLAB_CA_BYTES = 1024 * 1024
_GITLAB_CONFIG = "gitlab.json"
_GITLAB_TOKEN = "gitlab.token"
_GITLAB_WRITE_TOKEN = "gitlab-write.token"
_GITLAB_CA = "gitlab-ca.pem"


class IntegrationError(RuntimeError):
    def __init__(self, message: str, *, status: int = 0):
        super().__init__(message)
        self.status = status


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        return None


def _secret(path: str) -> str:
    target = Path(path).expanduser()
    if not target.is_file():
        raise IntegrationError("연동 토큰 파일을 찾을 수 없습니다")
    if target.stat().st_size > 16 * 1024:
        raise IntegrationError("연동 토큰 파일이 너무 큽니다")
    value = target.read_text(encoding="utf-8").strip()
    if not value:
        raise IntegrationError("연동 토큰 파일이 비어 있습니다")
    return value


def _ssl_context(ca_file: str = "") -> ssl.SSLContext:
    try:
        return ssl.create_default_context(cafile=str(Path(ca_file).expanduser())) if ca_file else ssl.create_default_context()
    except OSError as exc:
        raise IntegrationError("연동 CA 인증서를 읽을 수 없습니다") from exc


def _validate_gitlab_url(value: str) -> str:
    base = str(value or "").strip().rstrip("/")
    if len(base) > 2048 or any(ord(char) < 32 for char in base):
        raise IntegrationError("GitLab URL이 올바르지 않습니다")
    parsed = urlparse(base)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise IntegrationError("GitLab URL은 인증정보가 없는 HTTPS URL이어야 합니다")
    return base


def _validate_gitlab_token(value: str) -> str:
    token = str(value or "").strip()
    if not token or len(token) > 16 * 1024 or not token.isascii() or any(char.isspace() for char in token):
        raise IntegrationError("GitLab PAT가 올바르지 않습니다")
    return token


def _gitlab_environment_locked() -> bool:
    return any(os.environ.get(name, "").strip() for name in (
        "KODA_GITLAB_URL", "KODA_GITLAB_TOKEN_FILE", "KODA_GITLAB_WRITE_TOKEN_FILE", "KODA_GITLAB_CA_FILE",
    ))


def gitlab_configuration(settings_dir: str | Path) -> dict[str, object]:
    if _gitlab_environment_locked():
        base = os.environ.get("KODA_GITLAB_URL", "").strip().rstrip("/")
        token_file = os.environ.get("KODA_GITLAB_TOKEN_FILE", "").strip()
        write_token_file = os.environ.get("KODA_GITLAB_WRITE_TOKEN_FILE", "").strip()
        try:
            configured = bool(_validate_gitlab_url(base) and token_file and Path(token_file).expanduser().is_file())
        except IntegrationError:
            configured = False
        return {
            "configured": configured,
            "locked": True, "source": "environment", "url": base,
            "write_configured": bool(write_token_file and Path(write_token_file).expanduser().is_file()),
            "ca_configured": bool(os.environ.get("KODA_GITLAB_CA_FILE", "").strip()),
        }
    directory = Path(settings_dir)
    config_file, token_file = directory / _GITLAB_CONFIG, directory / _GITLAB_TOKEN
    try:
        payload = json.loads(config_file.read_text(encoding="utf-8")) if config_file.is_file() else {}
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        payload = {}
    base = str(payload.get("url") or "").strip().rstrip("/") if isinstance(payload, dict) else ""
    try:
        configured = bool(_validate_gitlab_url(base) and token_file.is_file() and token_file.stat().st_size)
    except (IntegrationError, OSError):
        configured = False
    try:
        write_configured = bool((directory / _GITLAB_WRITE_TOKEN).is_file() and (directory / _GITLAB_WRITE_TOKEN).stat().st_size)
    except OSError:
        write_configured = False
    return {
        "configured": configured,
        "locked": False, "source": "web", "url": base,
        "write_configured": write_configured,
        "ca_configured": (directory / _GITLAB_CA).is_file(),
    }


def _atomic_secret(path: Path, value: str, mode: int = 0o600) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as output:
            os.chmod(temporary, mode)
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def resolve_gitlab_configuration_tokens(
    settings_dir: str | Path, token: str = "", write_token: str = "",
) -> tuple[str, str]:
    """Use write-only form values, preserving stored PATs when fields are blank."""
    directory = Path(settings_dir)
    read_secret = str(token or "").strip()
    write_secret = str(write_token or "").strip()
    if not read_secret and (directory / _GITLAB_TOKEN).is_file():
        read_secret = _secret(str(directory / _GITLAB_TOKEN))
    if not write_secret and (directory / _GITLAB_WRITE_TOKEN).is_file():
        write_secret = _secret(str(directory / _GITLAB_WRITE_TOKEN))
    return _validate_gitlab_token(read_secret), (_validate_gitlab_token(write_secret) if write_secret else "")


def save_gitlab_configuration(settings_dir: str | Path, url: str, token: str, ca_pem: str = "", write_token: str = "") -> dict[str, object]:
    if _gitlab_environment_locked():
        raise IntegrationError("서버 환경변수로 설정되어 웹에서 변경할 수 없습니다")
    base, ca_value = _validate_gitlab_url(url), str(ca_pem or "").strip()
    secret, write_secret = resolve_gitlab_configuration_tokens(settings_dir, token, write_token)
    if len(ca_value.encode("utf-8")) > MAX_GITLAB_CA_BYTES:
        raise IntegrationError("GitLab CA 인증서가 너무 큽니다")
    if ca_value:
        try:
            ssl.create_default_context(cadata=ca_value)
        except ssl.SSLError as exc:
            raise IntegrationError("GitLab CA 인증서가 올바르지 않습니다") from exc
    directory = Path(settings_dir)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    ca_file = directory / _GITLAB_CA
    if ca_value:
        _atomic_secret(ca_file, ca_value + "\n")
    _atomic_secret(directory / _GITLAB_TOKEN, secret + "\n")
    if write_secret:
        _atomic_secret(directory / _GITLAB_WRITE_TOKEN, write_secret + "\n")
    _atomic_secret(directory / _GITLAB_CONFIG, json.dumps({"url": base}, ensure_ascii=False) + "\n")
    return gitlab_configuration(directory)


def remove_gitlab_configuration(settings_dir: str | Path) -> None:
    if _gitlab_environment_locked():
        raise IntegrationError("서버 환경변수로 설정되어 웹에서 삭제할 수 없습니다")
    directory = Path(settings_dir)
    for name in (_GITLAB_CONFIG, _GITLAB_TOKEN, _GITLAB_WRITE_TOKEN, _GITLAB_CA):
        (directory / name).unlink(missing_ok=True)


def _gitlab_settings(settings_dir: str | Path | None = None) -> tuple[str, str, ssl.SSLContext]:
    if _gitlab_environment_locked():
        base = os.environ.get("KODA_GITLAB_URL", "").strip().rstrip("/")
        token_file = os.environ.get("KODA_GITLAB_TOKEN_FILE", "").strip()
        if not base or not token_file:
            raise IntegrationError("GitLab URL 또는 토큰 파일이 설정되지 않았습니다")
        return _validate_gitlab_url(base), _secret(token_file), _ssl_context(os.environ.get("KODA_GITLAB_CA_FILE", "").strip())
    if settings_dir is None:
        raise IntegrationError("GitLab 연결이 설정되지 않았습니다")
    directory = Path(settings_dir)
    configuration = gitlab_configuration(directory)
    if not configuration["configured"]:
        raise IntegrationError("GitLab 연결이 설정되지 않았습니다")
    base = _validate_gitlab_url(str(configuration["url"]))
    ca_file = directory / _GITLAB_CA
    return base, _secret(str(directory / _GITLAB_TOKEN)), _ssl_context(str(ca_file) if ca_file.is_file() else "")


def _gitlab_write_settings(settings_dir: str | Path | None = None) -> tuple[str, str, ssl.SSLContext]:
    base, _, context = _gitlab_settings(settings_dir)
    token_file = os.environ.get("KODA_GITLAB_WRITE_TOKEN_FILE", "").strip() if _gitlab_environment_locked() else ""
    if not token_file and settings_dir is not None:
        token_file = str(Path(settings_dir) / _GITLAB_WRITE_TOKEN)
    if not token_file:
        raise IntegrationError("GitLab 결과 저장용 API 토큰이 설정되지 않았습니다")
    return base, _secret(token_file), context


def _gitlab_open(path: str, query: dict[str, object] | None = None, *, timeout: float = 30, settings_dir: str | Path | None = None, settings=None, method: str = "GET", payload: dict | None = None, write: bool = False):
    base, token, context = settings or (_gitlab_write_settings(settings_dir) if write else _gitlab_settings(settings_dir))
    suffix = path if path.startswith("/") else "/" + path
    url = base + "/api/v4" + suffix
    if query:
        url += "?" + urlencode(query)
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode() if payload is not None else None
    headers = {"PRIVATE-TOKEN": token, "Accept": "application/json", "User-Agent": "KODA-Portal/1"}
    if raw is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, data=raw, method=method, headers=headers)
    opener = build_opener(_NoRedirect(), HTTPSHandler(context=context))
    try:
        return opener.open(request, timeout=timeout)
    except HTTPError as exc:
        detail = exc.read(2048).decode("utf-8", "replace").strip()
        raise IntegrationError(f"GitLab 요청 실패 ({exc.code}): {detail or exc.reason}", status=exc.code) from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise IntegrationError(f"GitLab 연결 실패: {exc.reason if isinstance(exc, URLError) else exc}") from exc


def _gitlab_json(path: str, query: dict[str, object] | None = None, *, settings_dir: str | Path | None = None, settings=None, method: str = "GET", payload: dict | None = None, write: bool = False) -> tuple[object, object]:
    with _gitlab_open(path, query, settings_dir=settings_dir, settings=settings, method=method, payload=payload, write=write) as response:
        raw = response.read(MAX_GITLAB_JSON_BYTES + 1)
        if len(raw) > MAX_GITLAB_JSON_BYTES:
            raise IntegrationError("GitLab 응답이 너무 큽니다")
        try:
            return json.loads(raw), response.headers
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise IntegrationError("GitLab이 올바른 JSON을 반환하지 않았습니다") from exc


def _gitlab_status(settings) -> dict[str, object]:
    payload, _ = _gitlab_json("/user", settings=settings)
    if not isinstance(payload, dict):
        raise IntegrationError("GitLab 계정 응답 형식이 올바르지 않습니다")
    return {key: payload.get(key) for key in ("id", "username", "name", "state", "web_url")}


def test_gitlab_configuration(url: str, token: str, ca_pem: str = "", *, existing_ca_file: str | Path | None = None) -> dict[str, object]:
    base, secret, ca_value = _validate_gitlab_url(url), _validate_gitlab_token(token), str(ca_pem or "").strip()
    if len(ca_value.encode("utf-8")) > MAX_GITLAB_CA_BYTES:
        raise IntegrationError("GitLab CA 인증서가 너무 큽니다")
    if ca_value:
        try:
            context = ssl.create_default_context(cadata=ca_value)
        except ssl.SSLError as exc:
            raise IntegrationError("GitLab CA 인증서가 올바르지 않습니다") from exc
    elif existing_ca_file and Path(existing_ca_file).is_file():
        context = _ssl_context(str(existing_ca_file))
    else:
        context = ssl.create_default_context()
    settings = (base, secret, context)
    account = _gitlab_status(settings)
    token_info, _ = _gitlab_json("/personal_access_tokens/self", settings=settings)
    scopes = token_info.get("scopes") if isinstance(token_info, dict) else None
    if not isinstance(scopes, list) or "read_api" not in scopes:
        raise IntegrationError("GitLab 저장소 조회 PAT에 read_api 범위가 필요합니다")
    return account


def test_gitlab_write_configuration(
    url: str, read_token: str, write_token: str, ca_pem: str = "", *, existing_ca_file: str | Path | None = None,
) -> dict[str, object]:
    account = test_gitlab_configuration(url, read_token, ca_pem, existing_ca_file=existing_ca_file)
    base, secret = _validate_gitlab_url(url), _validate_gitlab_token(write_token)
    if str(ca_pem or "").strip():
        try:
            context = ssl.create_default_context(cadata=str(ca_pem).strip())
        except ssl.SSLError as exc:
            raise IntegrationError("GitLab CA 인증서가 올바르지 않습니다") from exc
    elif existing_ca_file and Path(existing_ca_file).is_file():
        context = _ssl_context(str(existing_ca_file))
    else:
        context = ssl.create_default_context()
    settings = (base, secret, context)
    write_account = _gitlab_status(settings)
    token, _ = _gitlab_json("/personal_access_tokens/self", settings=settings)
    scopes = token.get("scopes") if isinstance(token, dict) else None
    if not isinstance(scopes, list) or "api" not in scopes:
        raise IntegrationError("GitLab 결과 저장 PAT에 api 범위가 필요합니다")
    if account.get("id") != write_account.get("id"):
        raise IntegrationError("GitLab 조회 PAT와 결과 저장 PAT는 같은 계정이어야 합니다")
    return write_account


def gitlab_status(settings_dir: str | Path | None = None) -> dict[str, object]:
    return _gitlab_status(_gitlab_settings(settings_dir))


def list_gitlab_projects(settings_dir: str | Path | None = None) -> list[dict[str, object]]:
    projects: list[dict[str, object]] = []
    page, seen = "1", set()
    while page:
        if page in seen:
            raise IntegrationError("GitLab 페이지 응답이 반복되었습니다")
        seen.add(page)
        payload, headers = _gitlab_json("/projects", {
            "membership": "true", "min_access_level": 30, "archived": "false",
            "simple": "true", "order_by": "id", "sort": "asc", "per_page": 100, "page": page,
        }, settings_dir=settings_dir)
        if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
            raise IntegrationError("GitLab 프로젝트 목록 형식이 올바르지 않습니다")
        for item in payload:
            projects.append({key: item.get(key) for key in (
                "id", "name", "path_with_namespace", "namespace", "default_branch", "web_url", "last_activity_at",
            )})
        if len(projects) > MAX_GITLAB_PROJECTS:
            raise IntegrationError(f"GitLab 프로젝트가 {MAX_GITLAB_PROJECTS}개를 초과합니다")
        page = str(headers.get("X-Next-Page", "")).strip()
    return projects


def list_gitlab_refs(project_id: int, ref_type: str, settings_dir: str | Path | None = None) -> list[dict[str, str]]:
    endpoint = {"branch": "branches", "tag": "tags"}.get(ref_type)
    if not endpoint:
        raise ValueError("ref_type은 branch 또는 tag여야 합니다")
    refs: list[dict[str, str]] = []
    page, seen = "1", set()
    while page:
        if page in seen:
            raise IntegrationError("GitLab ref 페이지 응답이 반복되었습니다")
        seen.add(page)
        payload, headers = _gitlab_json(f"/projects/{int(project_id)}/repository/{endpoint}", {
            "per_page": 100, "page": page,
        }, settings_dir=settings_dir)
        if not isinstance(payload, list):
            raise IntegrationError("GitLab ref 목록 형식이 올바르지 않습니다")
        for item in payload:
            commit = item.get("commit") if isinstance(item, dict) else None
            name, sha = item.get("name") if isinstance(item, dict) else None, commit.get("id") if isinstance(commit, dict) else None
            if isinstance(name, str) and isinstance(sha, str):
                refs.append({"name": name, "commit_sha": sha})
        if len(refs) > MAX_GITLAB_REFS:
            raise IntegrationError(f"GitLab ref가 {MAX_GITLAB_REFS}개를 초과합니다")
        page = str(headers.get("X-Next-Page", "")).strip()
    return refs


def resolve_gitlab_ref(project_id: int, ref_type: str, ref_name: str, settings_dir: str | Path | None = None) -> str:
    endpoint = {"branch": "branches", "tag": "tags"}.get(ref_type)
    if not endpoint or not isinstance(ref_name, str) or not 1 <= len(ref_name) <= 255:
        raise ValueError("올바른 branch 또는 tag를 선택하세요")
    payload, _ = _gitlab_json(f"/projects/{int(project_id)}/repository/{endpoint}/{quote(ref_name, safe='')}", settings_dir=settings_dir)
    commit = payload.get("commit") if isinstance(payload, dict) else None
    sha = commit.get("id") if isinstance(commit, dict) else None
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40,64}", sha):
        raise IntegrationError("GitLab ref에서 commit SHA를 확인할 수 없습니다")
    return sha.lower()


def download_gitlab_archive(project_id: int, commit_sha: str, target: Path, *, max_bytes: int, settings_dir: str | Path | None = None) -> tuple[str, int]:
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit_sha):
        raise ValueError("올바른 commit SHA가 아닙니다")
    temporary = target.with_name("." + target.name + ".part")
    digest, size = hashlib.sha256(), 0
    try:
        with _gitlab_open(
            f"/projects/{int(project_id)}/repository/archive.tar.gz",
            {"sha": commit_sha, "include_lfs_blobs": "false"}, timeout=900, settings_dir=settings_dir,
        ) as response:
            content_type = str(response.headers.get("Content-Type", "")).lower()
            if content_type.startswith("text/") or "json" in content_type:
                raise IntegrationError("GitLab이 저장소 압축파일 대신 오류 응답을 반환했습니다")
            try:
                declared = int(response.headers.get("Content-Length", "0") or 0)
            except ValueError as exc:
                raise IntegrationError("GitLab 압축파일 크기 응답이 올바르지 않습니다") from exc
            if declared > max_bytes:
                raise IntegrationError("GitLab 저장소 압축파일이 허용 크기를 초과합니다")
            with temporary.open("xb") as output:
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > max_bytes:
                        raise IntegrationError("GitLab 저장소 압축파일이 허용 크기를 초과합니다")
                    output.write(chunk)
                    digest.update(chunk)
        temporary.replace(target)
        return digest.hexdigest(), size
    except Exception:
        temporary.unlink(missing_ok=True)
        target.unlink(missing_ok=True)
        raise


def _tracker_request_json(path: str, token: str, *, method: str = "GET", payload: dict | None = None, timeout: float = 60) -> dict:
    base = (os.environ.get("KODA_TRACKER_URL") or os.environ.get("KODA_SSBOM_TRACKER_URL") or "").strip().rstrip("/")
    parsed = urlparse(base)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise IntegrationError("Tracker URL이 올바르지 않습니다")
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode() if payload is not None else None
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "KODA-Portal/1"}
    if raw is not None:
        headers["Content-Type"] = "application/json"
    request = Request(base + path, data=raw, method=method, headers=headers)
    context = _ssl_context(os.environ.get("KODA_TRACKER_CA_FILE", "").strip()) if parsed.scheme == "https" else None
    opener = build_opener(_NoRedirect(), *([HTTPSHandler(context=context)] if context else []))
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_GITLAB_JSON_BYTES + 1)
            if len(body) > MAX_GITLAB_JSON_BYTES:
                raise IntegrationError("Tracker 응답이 너무 큽니다")
            value = json.loads(body)
            if not isinstance(value, dict):
                raise IntegrationError("Tracker 응답 형식이 올바르지 않습니다")
            return value
    except HTTPError as exc:
        raise IntegrationError(f"Tracker 요청 실패 ({exc.code})", status=exc.code) from exc
    except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise IntegrationError(f"Tracker 연결 실패: {exc}") from exc


def provision_tracker_repository(gitlab_url: str, project: dict) -> dict[str, str]:
    provisioning_file = os.environ.get("KODA_TRACKER_PROVISIONING_TOKEN_FILE", "").strip()
    token_dir_value = os.environ.get("KODA_TRACKER_TOKEN_DIR", "").strip()
    if not provisioning_file or not token_dir_value:
        raise IntegrationError("Tracker 자동 생성 설정이 없습니다")
    token_dir = Path(token_dir_value).expanduser()
    provisioning_token = _secret(provisioning_file)
    project_id = int(project.get("id") or 0)
    path = str(project.get("path_with_namespace") or "").strip()
    if project_id <= 0 or not path:
        raise IntegrationError("GitLab 저장소 정보가 올바르지 않습니다")
    result = _tracker_request_json("/api/v1/integrations/koda/repositories", provisioning_token, method="POST", payload={
        "gitlabUrl": _validate_gitlab_url(gitlab_url),
        "gitlabProjectId": project_id,
        "pathWithNamespace": path,
    })
    service_id = str(result.get("serviceId") or "")
    environment_id = str(result.get("environmentId") or "")
    upload_token = str(result.get("uploadToken") or "")
    if not service_id or not environment_id or not upload_token:
        raise IntegrationError("Tracker 자동 생성 응답이 올바르지 않습니다")
    token_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    token_ref = f"gitlab-{project_id}.token"
    _atomic_secret(token_dir / token_ref, upload_token + "\n")
    return {
        "tracker_service_id": service_id,
        "tracker_environment_id": environment_id,
        "tracker_token_ref": token_ref,
    }


def fetch_tracker_result(mapping: dict, tracker_run_id: str, *, timeout_seconds: int | None = None) -> dict:
    token_dir = Path(os.environ.get("KODA_TRACKER_TOKEN_DIR", "").strip()).expanduser()
    token_ref = str(mapping.get("tracker_token_ref") or "")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", token_ref):
        raise IntegrationError("Tracker 서비스 토큰 참조가 올바르지 않습니다")
    token = _secret(str(token_dir / token_ref))
    timeout_value = timeout_seconds if timeout_seconds is not None else int(os.environ.get("KODA_TRACKER_RESULT_TIMEOUT_SECONDS", "900"))
    deadline = time.monotonic() + max(1, min(timeout_value, 3600))
    while True:
        result = _tracker_request_json(f"/api/v1/integrations/koda/runs/{quote(str(tracker_run_id), safe='')}", token)
        run = result.get("run") if isinstance(result.get("run"), dict) else {}
        if run.get("state") in {"completed", "partial", "failed", "archived"} and run.get("analysisState") in {"completed", "failed"}:
            return result
        if time.monotonic() >= deadline:
            raise IntegrationError("Tracker 분석 결과 대기 시간이 초과되었습니다")
        time.sleep(min(2, max(0.1, deadline - time.monotonic())))


def _gitlab_write_json(path: str, query: dict[str, object] | None = None, *, settings_dir: str | Path, method: str = "GET", payload: dict | None = None):
    return _gitlab_json(path, query, settings_dir=settings_dir, method=method, payload=payload, write=True)[0]


def _gitlab_optional_json(path: str, query: dict[str, object] | None = None, *, settings_dir: str | Path):
    try:
        return _gitlab_write_json(path, query, settings_dir=settings_dir)
    except IntegrationError as exc:
        if exc.status == 404:
            return None
        raise


def _gitlab_write_list_pages(
    path: str, query: dict[str, object], *, settings_dir: str | Path, label: str,
) -> list[dict]:
    items: list[dict] = []
    page, seen = "1", set()
    while page:
        if page in seen:
            raise IntegrationError(f"GitLab {label} 페이지 응답이 반복되었습니다")
        seen.add(page)
        if len(seen) > MAX_GITLAB_PAGES:
            raise IntegrationError(f"GitLab {label} 페이지가 {MAX_GITLAB_PAGES}개를 초과합니다")
        payload, headers = _gitlab_json(path, {**query, "per_page": 100, "page": page}, settings_dir=settings_dir, write=True)
        if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
            raise IntegrationError(f"GitLab {label} 목록 형식이 올바르지 않습니다")
        items.extend(payload)
        if len(items) > MAX_GITLAB_MARKER_ITEMS:
            raise IntegrationError(f"GitLab {label}가 {MAX_GITLAB_MARKER_ITEMS}개를 초과합니다")
        page = str(headers.get("X-Next-Page", "")).strip()
    return items


def get_gitlab_issue(project_id: int, issue_iid: int, *, settings_dir: str | Path) -> dict | None:
    payload = _gitlab_optional_json(f"/projects/{int(project_id)}/issues/{int(issue_iid)}", settings_dir=settings_dir)
    if payload is not None and not isinstance(payload, dict):
        raise IntegrationError("GitLab 이슈 응답 형식이 올바르지 않습니다")
    return payload


def find_gitlab_issue(project_id: int, marker: str, *, state: str = "all", settings_dir: str | Path) -> dict | None:
    if state not in {"all", "opened", "closed"} or not marker:
        raise ValueError("invalid GitLab issue search")
    search = next(iter(re.findall(r"[0-9a-f]{40,64}", marker)), marker)
    payload = _gitlab_write_list_pages(f"/projects/{int(project_id)}/issues", {
        "state": state, "search": search, "in": "description",
    }, settings_dir=settings_dir, label="이슈")
    return next((item for item in payload if isinstance(item, dict) and marker in str(item.get("description") or "")), None)


def create_gitlab_issue(project_id: int, title: str, description: str, *, settings_dir: str | Path) -> dict:
    payload = _gitlab_write_json(
        f"/projects/{int(project_id)}/issues", settings_dir=settings_dir, method="POST",
        payload={"title": str(title)[:255], "description": str(description)[:65535], "confidential": True},
    )
    if not isinstance(payload, dict) or not payload.get("iid") or not payload.get("web_url"):
        raise IntegrationError("GitLab 이슈 생성 응답 형식이 올바르지 않습니다")
    return payload


def add_gitlab_issue_note(project_id: int, issue_iid: int, body: str, *, settings_dir: str | Path) -> dict:
    payload = _gitlab_write_json(
        f"/projects/{int(project_id)}/issues/{int(issue_iid)}/notes", settings_dir=settings_dir,
        method="POST", payload={"body": str(body)[:65535]},
    )
    if not isinstance(payload, dict) or not payload.get("id"):
        raise IntegrationError("GitLab 이슈 댓글 응답 형식이 올바르지 않습니다")
    return payload


def find_gitlab_issue_note(project_id: int, issue_iid: int, marker: str, *, settings_dir: str | Path) -> dict | None:
    payload = _gitlab_write_list_pages(
        f"/projects/{int(project_id)}/issues/{int(issue_iid)}/notes",
        {"sort": "desc", "order_by": "created_at"}, settings_dir=settings_dir, label="이슈 댓글",
    )
    return next((item for item in payload if isinstance(item, dict) and marker in str(item.get("body") or "")), None)


def _gitlab_scan_report(run: dict, tracker_run_id: str, tracker_result: dict) -> dict:
    snapshot, result = run.get("snapshot") or {}, run.get("result") or {}
    # Export report fields, never the integration snapshot (token refs) or
    # internal analyzer trace. Evidence/source_context are report-redacted.
    finding_fields = {
        "rule_id", "category", "severity", "title", "target", "path", "line",
        "evidence", "description", "recommendation", "resource", "reachable",
        "verification_status", "verification_note", "triage_verdict", "triage_confidence",
        "triage_note", "analyzer", "analyzer_version", "analyzer_rule_id", "cwe_ids",
        "evidence_kind", "evidence_id", "issue_key", "standard_mappings", "source_context",
    }
    findings = result.get("findings", (result.get("findings_by_language") or {}).get("ko", [])) or []
    koda_result = {key: result[key] for key in (
        "scan", "summary", "scanner", "generated_at", "analysis_stages", "analysis_overall",
        "source_analysis", "rule_mappings", "sw49", "components", "sbom",
    ) if key in result}
    koda_result["findings"] = [
        {key: value for key, value in item.items() if key in finding_fields}
        for item in findings if isinstance(item, dict)
    ]
    return {
        "schemaVersion": 2,
        "source": {
            "gitlabProjectId": snapshot.get("gitlab_project_id"),
            "pathWithNamespace": snapshot.get("gitlab_path_with_namespace"),
            "refType": snapshot.get("gitlab_ref_type"), "refName": snapshot.get("gitlab_ref_name"),
            "commitSha": snapshot.get("gitlab_commit_sha"),
        },
        "inspection": {
            "projectId": run.get("project_id"), "projectName": snapshot.get("project_name"),
            "accountId": run.get("requested_by") or snapshot.get("requested_by"),
            "accountDisplay": snapshot.get("requested_by_display"),
            "date": snapshot.get("gitlab_result_date"), "timezone": "Asia/Seoul",
            "version": snapshot.get("gitlab_result_version"), "branch": snapshot.get("gitlab_result_branch"),
            "roundNumber": run.get("round_number"), "scope": snapshot.get("scan_scope", "all"),
            "status": run.get("status"), "createdAt": run.get("created_at"), "completedAt": run.get("completed_at"),
            "standard": snapshot.get("standard"), "standardCategory": snapshot.get("standard_category"),
            "disabledRules": snapshot.get("disabled_rules", []),
            "rulePolicyVersion": snapshot.get("rule_policy_version"), "rulePolicyHash": snapshot.get("rule_policy_hash"),
            "scannerVersion": snapshot.get("scanner_version"), "inputHash": snapshot.get("input_hash"),
        },
        "kodaRunId": run.get("run_id"), "trackerRunId": tracker_run_id,
        "kodaResult": koda_result, "trackerResult": tracker_result,
    }


def _gitlab_report_cell(value, limit: int = 180) -> str:
    # One escaped line also prevents repository-controlled quick actions.
    value = " ".join(str(value if value is not None else "—").split())[:limit]
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "&#124;").replace("`", "&#96;")


def _gitlab_mr_summary(report: dict, file_path: str) -> tuple[str, str, list[str]]:
    inspection, source = report["inspection"], report["source"]
    result, tracker = report["kodaResult"], report["trackerResult"]
    local = result["findings"]
    remote = [item for item in ((tracker.get("analysis") or {}).get("findings") or []) if isinstance(item, dict)]
    source_findings = [item for item in local if item.get("category") != "dependencies"]
    library_findings = [item for item in local if item.get("category") == "dependencies"]
    cell = _gitlab_report_cell
    scope = {"source": "소스코드", "library": "라이브러리", "all": "소스코드·라이브러리"}.get(inspection["scope"], inspection["scope"])
    title = f"[KODA] {inspection.get('date') or ''} {inspection.get('projectName') or source.get('pathWithNamespace') or '점검'} {scope} 점검"
    if inspection.get("version"):
        title += f" v{inspection['version']}"
    lines = [
        "<!-- koda-scan-summary:start -->", "## KODA 보안점검 요약", "",
        f"- 프로젝트: {cell(inspection.get('projectName'))} / `{cell(inspection.get('projectId'))}`",
        f"- 실행 계정 ID: `{cell(inspection.get('accountId'))}` · {cell(inspection.get('accountDisplay'))}",
        f"- 점검일: {cell(inspection.get('date'))} (Asia/Seoul) · 버전: {cell(inspection.get('version'))}",
        f"- 시작 / 완료: {cell(inspection.get('createdAt'))} / {cell(inspection.get('completedAt'))}",
        f"- 범위: {cell(scope)} · 기준: {cell(inspection.get('standard'))} / {cell(inspection.get('standardCategory'))}",
        f"- 원본 Ref: {cell(source.get('refType'))} / {cell(source.get('refName'))} · SHA: `{cell(source.get('commitSha'))}`",
        f"- KODA 회차: `{cell(report['kodaRunId'])}` · Tracker 회차: `{cell(report['trackerRunId'])}`",
        f"- KODA 상태: {cell(inspection.get('status'))} · 분석 상태: {cell(result.get('analysis_overall'))}",
        f"- Tracker 상태: {cell((tracker.get('run') or {}).get('state'))} / {cell((tracker.get('analysis') or {}).get('state'))}",
        f"- 전체 결과 JSON: [{cell(file_path)}]({quote(file_path, safe='/')})", "",
        "각 분석기의 결과를 별도로 집계합니다. 검토 필요 항목은 확정 취약점과 구분하며, 0건도 점검 범위·단계 상태와 함께 확인하세요.",
    ]
    severities = ("critical", "high", "medium", "low", "info", "unknown")
    for label, items in (("KODA 소스코드", source_findings), ("KODA 라이브러리", library_findings), ("Tracker 라이브러리", remote)):
        counts = Counter(str(item.get("severity") or "unknown").lower() for item in items)
        counts["unknown"] += sum(count for severity, count in counts.items() if severity not in severities)
        lines += ["", f"### {label}: {len(items)}건", " · ".join(f"{severity}: {counts[severity]}" for severity in severities)]
        if label.startswith("KODA"):
            lines += ["| 심각도 | 확인 상태 | 규칙 | 제목 | 위치 |", "| --- | --- | --- | --- | --- |"]
        else:
            lines += ["| CVE | 심각도 | CVSS | 구성요소 | 설치 버전 | 수정 버전 |", "| --- | --- | --- | --- | --- | --- |"]
        ordered = sorted(items, key=lambda item: (severities.index(str(item.get("severity") or "unknown").lower()) if str(item.get("severity") or "unknown").lower() in severities else 5, str(item.get("rule_id") or item.get("canonicalId") or "")))
        for item in ordered[:50]:
            values = (
                (item.get("severity"), item.get("verification_status", "unknown"), item.get("rule_id"), item.get("title"), f"{item.get('path') or item.get('resource') or '—'}:{item.get('line') or '—'}")
                if label.startswith("KODA") else
                (item.get("canonicalId") or item.get("id"), item.get("severity"), item.get("cvssScore"), item.get("component"), item.get("version") or item.get("installedVersion"), item.get("fixedIn") or item.get("fixVersions") or item.get("fixedVersion"))
            )
            lines.append("| " + " | ".join(cell(value, 100) for value in values) + " |")
        if len(items) > 50:
            lines.append(f"전체 {len(items)}건 중 {len(items) - 50}건 생략. 전체 상세는 결과 JSON에 있습니다.")
    lines += ["", "### 점검 단계 및 경고", cell(json.dumps(result.get("analysis_stages") or {}, ensure_ascii=False), 3000),
              cell(json.dumps((result.get("scan") or {}).get("warnings") or [], ensure_ascii=False), 3000),
              "Tracker 오류: " + cell((tracker.get("analysis") or {}).get("error"), 1000),
              "", "결과 JSON에는 소스/라이브러리 상세 근거·권장 조치와 전체 SBOM이 포함됩니다.",
              "<!-- koda-scan-summary:end -->"]
    labels = {"KODA", "security-scan", f"scan:{inspection['scope']}"}
    for key, value in (("standard", inspection.get("standard")), ("project", inspection.get("projectName"))):
        if value:
            labels.add(f"{key}:" + re.sub(r"[^\w.-]+", "-", str(value))[:80])
    for item in local + remote:
        severity = str(item.get("severity") or "unknown").lower()
        labels.add(f"severity:{severity if severity in severities else 'unknown'}")
        if item.get("category") in {"code", "secrets", "configuration", "prevention", "dependencies", "quality"}:
            labels.add(f"category:{item['category']}")
    # Fixed-category labels stay manageable; individual CVEs remain searchable
    # in the MR tables/JSON instead of creating thousands of project labels.
    if remote or result.get("sbom"):
        labels.add("SBOM")
    return " ".join(title.split())[:255], "\n".join(lines), sorted(labels)


def publish_tracker_result(mapping: dict, run: dict, tracker_run_id: str, tracker_result: dict, *, settings_dir: str | Path) -> dict:
    snapshot = run.get("snapshot") or {}
    project_id = int(snapshot.get("gitlab_project_id") or mapping.get("gitlab_project_id") or 0)
    commit_sha = str(snapshot.get("gitlab_commit_sha") or "")
    target_branch = str(mapping.get("default_branch") or "").strip()
    if project_id <= 0 or not re.fullmatch(r"[0-9a-f]{40,64}", commit_sha) or not target_branch:
        raise IntegrationError("GitLab 결과 저장 대상 정보가 올바르지 않습니다")
    short_sha = commit_sha[:12]
    # Old runs keep their original branch/path; newly snapshotted runs get a
    # date/project/account/version branch and an immutable per-run report path.
    source_branch = snapshot.get("gitlab_result_branch") or f"koda/sbom-results/{short_sha}"
    file_path = f".koda/scan-results/{run['run_id']}.json" if snapshot.get("gitlab_result_branch") else f".koda/sbom-tracker/{commit_sha}.json"
    report = _gitlab_scan_report(run, tracker_run_id, tracker_result)
    report["source"]["gitlabProjectId"] = project_id
    content = (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    file_endpoint = f"/projects/{project_id}/repository/files/{quote(file_path, safe='')}"
    source_file = _gitlab_optional_json(file_endpoint, {"ref": source_branch}, settings_dir=settings_dir)

    def decoded_file(value) -> bytes:
        if value is None:
            return b""
        if not isinstance(value, dict) or value.get("encoding") != "base64" or not isinstance(value.get("content"), str):
            raise IntegrationError("GitLab 결과 파일 응답 형식이 올바르지 않습니다")
        try:
            return base64.b64decode(value["content"], validate=True)
        except ValueError as exc:
            raise IntegrationError("GitLab 결과 파일의 base64 내용이 올바르지 않습니다") from exc

    existing_content = decoded_file(source_file)
    if source_file is None:
        existing_content = decoded_file(_gitlab_optional_json(file_endpoint, {"ref": target_branch}, settings_dir=settings_dir))
    commit = None
    if existing_content != content:
        branch = _gitlab_optional_json(
            f"/projects/{project_id}/repository/branches/{quote(source_branch, safe='')}",
            settings_dir=settings_dir,
        )
        commit_payload = {
            "branch": source_branch,
            "commit_message": f"chore(koda): store security scan {run.get('run_id')} for {short_sha}",
            "actions": [{
                "action": "update" if source_file is not None else "create",
                "file_path": file_path,
                "content": content.decode("utf-8"),
            }],
        }
        if branch is None:
            commit_payload["start_sha"] = commit_sha
        commit = _gitlab_write_json(
            f"/projects/{project_id}/repository/commits", settings_dir=settings_dir,
            method="POST", payload=commit_payload,
        )
    merge_requests = _gitlab_write_json(f"/projects/{project_id}/merge_requests", {
        "state": "opened" if commit is not None else "all", "source_branch": source_branch, "target_branch": target_branch,
        "order_by": "updated_at", "sort": "desc", "per_page": 1,
    }, settings_dir=settings_dir)
    mr_title, mr_description, mr_labels = _gitlab_mr_summary(report, file_path)
    if isinstance(merge_requests, list) and merge_requests:
        merge_request = merge_requests[0]
        if merge_request.get("iid"):
            old_description = str(merge_request.get("description") or "")
            block = re.compile(r"<!-- koda-scan-summary:start -->.*?<!-- koda-scan-summary:end -->", re.S)
            description = block.sub(lambda _: mr_description, old_description, count=1) if block.search(old_description) else mr_description + ("\n\n" + old_description if old_description else "")
            missing_labels = sorted(set(mr_labels) - set(merge_request.get("labels") or []))
            if description != old_description or missing_labels:
                merge_request = _gitlab_write_json(
                    f"/projects/{project_id}/merge_requests/{int(merge_request['iid'])}",
                    settings_dir=settings_dir, method="PUT",
                    payload={"description": description, "add_labels": ",".join(missing_labels)},
                )
    else:
        merge_request = _gitlab_write_json(
            f"/projects/{project_id}/merge_requests", settings_dir=settings_dir, method="POST", payload={
                "source_branch": source_branch,
                "target_branch": target_branch,
                "title": mr_title,
                "description": mr_description,
                "labels": ",".join(mr_labels),
                "remove_source_branch": False,
            },
        )
    findings = ((tracker_result.get("analysis") or {}).get("findings") or []) if isinstance(tracker_result, dict) else []
    tracker_run = tracker_result.get("run") if isinstance(tracker_result, dict) else None
    tracker_run_url = str((tracker_run or {}).get("runUrl") or "").strip() if isinstance(tracker_run, dict) else ""
    parsed_tracker_url = urlparse(tracker_run_url) if tracker_run_url else None
    tracker_reference = f"Tracker 회차 `{tracker_run_id}`"
    if (
        parsed_tracker_url and parsed_tracker_url.scheme in {"http", "https"}
        and parsed_tracker_url.hostname and not any(char.isspace() for char in tracker_run_url)
        and ">" not in tracker_run_url and len(tracker_run_url) <= 2048
    ):
        tracker_reference += f" · 실행 화면: <{tracker_run_url}>"
    # Keep component/version distinctions: one CVE can affect multiple
    # dependencies in the same SBOM.
    cves = {}
    for finding in findings:
        cve = str(finding.get("canonicalId") or finding.get("id") or "") if isinstance(finding, dict) else ""
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            component = str(finding.get("component") or finding.get("dependency") or "-")
            version = str(finding.get("version") or finding.get("installedVersion") or "-")
            severity = str(finding.get("severity") or "unknown").lower()
            cvss = str(finding.get("cvssScore") or "-")
            key = (cve, component, version, severity, cvss)
            current = cves.setdefault(key, {**finding, "fixedIn": set()})
            fixed = finding.get("fixedIn") or finding.get("fixVersions") or finding.get("fixedVersion")
            values = fixed if isinstance(fixed, list) else [fixed]
            current["fixedIn"].update(str(value) for value in values if value)
    issue_urls = []
    if cves:
        marker = f"<!-- koda-sbom-tracker:{commit_sha} -->"
        run_marker = f"<!-- koda-sbom-tracker-run:{tracker_run_id} -->"
        issue = find_gitlab_issue(project_id, marker, settings_dir=settings_dir)
        if issue is None:
            def cell(value) -> str:
                return str(value or "-").replace("\r", " ").replace("\n", " ").replace("|", "\\|")

            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
            ordered = sorted(cves.items(), key=lambda item: (
                severity_order.get(item[0][3], 5), item[0][0], item[0][1], item[0][2], item[0][4],
            ))
            rows = ["| CVE | 심각도 | CVSS | 구성요소 | 설치 버전 | 수정 버전 |", "| --- | --- | ---: | --- | --- | --- |"]
            for (cve, component, version, _severity, _cvss), finding in ordered[:200]:
                fixed = ", ".join(sorted(finding["fixedIn"])) or "-"
                rows.append(f"| {cve} | {cell(finding.get('severity'))} | {cell(finding.get('cvssScore'))} | {cell(component)} | {cell(version)} | {cell(fixed)} |")
            omitted = max(0, len(ordered) - 200)
            if omitted:
                rows.append(f"\n나머지 {omitted}건은 MR의 결과 JSON에서 확인하세요.")
            issue = _gitlab_write_json(
                f"/projects/{project_id}/issues", settings_dir=settings_dir, method="POST", payload={
                    "title": f"[KODA] SBOM 취약점 {short_sha} ({len(cves)}건)",
                    "description": marker + "\n" + run_marker + f"\n{tracker_reference}에서 CVE 취약점이 확인되었습니다.\n\n" + "\n".join(rows) + f"\n\n전체 {len(ordered)}건 · 생략 {omitted}건\n분석 결과 MR: {merge_request.get('web_url') or '-'}",
                    "labels": "KODA,SBOM,vulnerability",
                    "confidential": True,
                },
            )
        elif issue is not None and isinstance(issue, dict):
            if run_marker not in str(issue.get("description") or "") and not find_gitlab_issue_note(
                project_id, int(issue["iid"]), run_marker, settings_dir=settings_dir,
            ):
                add_gitlab_issue_note(
                    project_id, int(issue["iid"]),
                    run_marker + f"\n{tracker_reference}가 동일 commit 결과를 확인했습니다.\n분석 결과 MR: {merge_request.get('web_url') or '-'}",
                    settings_dir=settings_dir,
                )
        if isinstance(issue, dict) and issue.get("web_url"):
            issue_urls.append(str(issue["web_url"]))
    return {
        "commitUrl": commit.get("web_url") if isinstance(commit, dict) else None,
        "mergeRequestUrl": merge_request.get("web_url") if isinstance(merge_request, dict) else None,
        "issueUrls": issue_urls,
        "resultFile": file_path,
    }


def send_tracker_sbom(mapping: dict, run: dict) -> str:
    base = (os.environ.get("KODA_TRACKER_URL") or os.environ.get("KODA_SSBOM_TRACKER_URL") or "").strip().rstrip("/")
    token_dir = os.environ.get("KODA_TRACKER_TOKEN_DIR", "").strip()
    token_ref = str(mapping.get("tracker_token_ref") or "")
    if not base or not token_dir or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", token_ref):
        raise IntegrationError("Tracker URL 또는 토큰 참조가 설정되지 않았습니다")
    parsed = urlparse(base)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise IntegrationError("Tracker URL이 올바르지 않습니다")
    token = _secret(str(Path(token_dir).expanduser() / token_ref))
    result, snapshot = run.get("result") or {}, run.get("snapshot") or {}
    sbom = result.get("sbom")
    if not isinstance(sbom, dict):
        raise IntegrationError("전송할 CycloneDX SBOM이 없습니다")
    raw = (json.dumps(sbom, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    ref_type, ref_name, commit_sha = snapshot.get("gitlab_ref_type"), snapshot.get("gitlab_ref_name"), str(snapshot.get("gitlab_commit_sha") or "")
    release = str(ref_name) if ref_type == "tag" else f"{ref_name}@{commit_sha[:12]}"
    boundary = "koda-" + uuid.uuid4().hex
    fields = {
        "serviceId": str(mapping["tracker_service_id"]),
        "environmentId": str(mapping["tracker_environment_id"]),
        "releaseVersion": release,
        "note": f"KODA run {run['run_id']} · {mapping['path_with_namespace']} · {commit_sha}",
    }
    if any("\r" in value or "\n" in value for value in fields.values()):
        raise IntegrationError("Tracker 전송 값에 허용되지 않는 문자가 있습니다")
    parts = []
    for name, value in fields.items():
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode())
    parts.append(
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"sbom\"; filename=\"koda.cdx.json\"\r\nContent-Type: application/vnd.cyclonedx+json\r\n\r\n".encode()
        + raw + f"\r\n--{boundary}--\r\n".encode()
    )
    body = b"".join(parts)
    request = Request(
        base + "/api/v1/sbom-runs", data=body, method="POST",
        headers={
            "Authorization": f"Bearer {token}", "Idempotency-Key": f"koda:{run['run_id']}:{digest}",
            "Content-Type": f"multipart/form-data; boundary={boundary}", "Accept": "application/json",
        },
    )
    context = _ssl_context(os.environ.get("KODA_TRACKER_CA_FILE", "").strip()) if parsed.scheme == "https" else None
    opener = build_opener(_NoRedirect(), *([HTTPSHandler(context=context)] if context else []))
    for attempt in range(3):
        try:
            with opener.open(request, timeout=60) as response:
                payload = json.loads(response.read(MAX_GITLAB_JSON_BYTES))
                run_id = payload.get("runId") if isinstance(payload, dict) else None
                if not run_id:
                    raise IntegrationError("Tracker 응답에 runId가 없습니다")
                return str(run_id)
        except HTTPError as exc:
            if exc.code < 500 and exc.code != 429:
                raise IntegrationError(f"Tracker 요청 실패 ({exc.code})", status=exc.code) from exc
            if attempt == 2:
                raise IntegrationError(f"Tracker 요청 실패 ({exc.code})", status=exc.code) from exc
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            if attempt == 2:
                raise IntegrationError(f"Tracker 연결 실패: {exc}") from exc
        time.sleep(2**attempt)
    raise IntegrationError("Tracker 전송에 실패했습니다")
