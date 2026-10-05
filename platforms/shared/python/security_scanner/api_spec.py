"""Parse an API description (OpenAPI / HAR / Postman) into scannable GET URLs.

Standard-library only (JSON). The extracted URLs are fed to the web crawler as
seeds so header, TLS, cookie, and active checks run against the real API
surface. Only GET endpoints are emitted — issuing POST/PUT/DELETE from a spec
could change state, so those are enumerated as a warning instead of called.
"""

from __future__ import annotations

import json
import urllib.parse


def parse_api_spec(content: str, base_url: str) -> tuple[list[str], list[str]]:
    """Return ``(get_urls, warnings)`` for an OpenAPI/HAR/Postman JSON document.

    ``base_url`` resolves relative paths (and supplies the host when the spec
    omits a server). YAML is not supported — export the spec as JSON.
    """

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return [], ["API spec is not valid JSON (YAML is unsupported; export the spec as JSON)."]

    if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
        return _from_openapi(data, base_url)
    if isinstance(data, dict) and isinstance(data.get("log"), dict) and "entries" in data["log"]:
        return _from_har(data["log"]), []
    if isinstance(data, dict) and "item" in data and "info" in data:
        return _from_postman(data, base_url), []
    return [], ["Unrecognized API spec (expected OpenAPI, HAR, or Postman JSON)."]


def _from_openapi(data: dict, base_url: str) -> tuple[list[str], list[str]]:
    base = _openapi_base(data, base_url)
    urls: list[str] = []
    warnings: list[str] = []
    non_get = 0
    paths = data.get("paths")
    if not isinstance(paths, dict):
        return [], ["OpenAPI document has no 'paths'."]
    for raw_path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared_params = item.get("parameters") if isinstance(item.get("parameters"), list) else []
        for method, operation in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            if method.lower() != "get":
                non_get += 1
                continue
            params = list(shared_params)
            if isinstance(operation, dict) and isinstance(operation.get("parameters"), list):
                params += operation["parameters"]
            urls.append(_build_openapi_url(base, str(raw_path), params))
    if non_get:
        warnings.append(f"Skipped {non_get} non-GET operation(s) for safety (they may change state).")
    return _dedupe(urls), warnings


def parse_api_spec_json_bodies(content: str, base_url: str) -> list[tuple[str, str, dict]]:
    """Return ``(method, url, json_body_skeleton)`` for OpenAPI POST/PUT/PATCH
    operations that take a JSON request body.

    Feeds ``json_active_probe`` so API write-endpoints get fuzzed. These issue
    non-GET requests, so the caller must gate them behind intrusive authorization.
    Only OpenAPI is supported (HAR/Postman carry concrete bodies the caller can use
    directly). ponytail: top-level ``properties`` only; ``$ref`` schemas resolve to
    an empty body (no string fields to fuzz) — expand to a $ref walk if needed.
    """

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    if not (isinstance(data, dict) and ("openapi" in data or "swagger" in data)):
        return []
    paths = data.get("paths")
    if not isinstance(paths, dict):
        return []
    base = _openapi_base(data, base_url)
    out: list[tuple[str, str, dict]] = []
    for raw_path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters") if isinstance(item.get("parameters"), list) else []
        for method, operation in item.items():
            if method.lower() not in {"post", "put", "patch"} or not isinstance(operation, dict):
                continue
            skeleton = _json_body_skeleton(operation)
            if skeleton is None:
                continue
            params = list(shared)
            if isinstance(operation.get("parameters"), list):
                params += operation["parameters"]
            out.append((method.upper(), _build_openapi_url(base, str(raw_path), params), skeleton))
    return out


def _json_body_skeleton(operation: dict) -> dict | None:
    """Minimal JSON object from an operation's ``application/json`` schema, or None
    when the operation has no JSON request body."""
    body = operation.get("requestBody")
    content = body.get("content") if isinstance(body, dict) else None
    media = content.get("application/json") if isinstance(content, dict) else None
    if not isinstance(media, dict):
        return None
    schema = media.get("schema")
    props = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(props, dict):
        return {}
    skeleton: dict = {}
    for key, spec in props.items():
        kind = spec.get("type") if isinstance(spec, dict) else None
        if kind in ("integer", "number"):
            skeleton[key] = 1
        elif kind == "boolean":
            skeleton[key] = True
        elif kind == "object":
            skeleton[key] = {}
        elif kind == "array":
            skeleton[key] = []
        else:
            skeleton[key] = "test"
    return skeleton


def _openapi_base(data: dict, base_url: str) -> str:
    servers = data.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        server_url = str(servers[0].get("url") or "").strip()
        if server_url:
            return urllib.parse.urljoin(base_url, server_url)
    # Swagger 2.0 host/basePath
    host = str(data.get("host") or "").strip()
    if host:
        scheme = "https" if "https" in (data.get("schemes") or ["https"]) else "http"
        return f"{scheme}://{host}{data.get('basePath') or ''}"
    return base_url


def _build_openapi_url(base: str, path: str, params: list) -> str:
    # Fill path templates ({id}) with a sample so the endpoint is requestable.
    filled = path
    for param in params:
        if isinstance(param, dict) and param.get("in") == "path" and param.get("name"):
            filled = filled.replace("{" + str(param["name"]) + "}", "1")
    filled = _fill_remaining_templates(filled)
    query = {
        str(param["name"]): "1"
        for param in params
        if isinstance(param, dict) and param.get("in") == "query" and param.get("name")
    }
    url = urllib.parse.urljoin(base.rstrip("/") + "/", filled.lstrip("/"))
    if query:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(query)
    return url


def _fill_remaining_templates(path: str) -> str:
    result: list[str] = []
    depth = 0
    for char in path:
        if char == "{":
            depth += 1
        elif char == "}":
            if depth:
                depth -= 1
                result.append("1")
        elif depth == 0:
            result.append(char)
    return "".join(result)


def _from_har(log: dict) -> list[str]:
    urls: list[str] = []
    entries = log.get("entries")
    if isinstance(entries, list):
        for entry in entries:
            request = entry.get("request") if isinstance(entry, dict) else None
            if isinstance(request, dict) and str(request.get("method", "")).upper() == "GET":
                url = str(request.get("url") or "")
                if url:
                    urls.append(url)
    return _dedupe(urls)


def _from_postman(data: dict, base_url: str) -> list[str]:
    urls: list[str] = []

    def walk(items: object) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            if "item" in item:
                walk(item["item"])
            request = item.get("request")
            if isinstance(request, dict) and str(request.get("method", "GET")).upper() == "GET":
                url = request.get("url")
                raw = url.get("raw") if isinstance(url, dict) else url
                if isinstance(raw, str) and raw:
                    urls.append(urllib.parse.urljoin(base_url, _strip_postman_vars(raw)))

    walk(data.get("item"))
    return _dedupe(urls)


def _strip_postman_vars(raw: str) -> str:
    # Replace {{baseUrl}} style variables with nothing so urljoin uses base_url.
    while "{{" in raw and "}}" in raw:
        start = raw.index("{{")
        end = raw.index("}}", start) + 2
        raw = raw[:start] + raw[end:]
    return raw


def _dedupe(urls: list[str]) -> list[str]:
    return list(dict.fromkeys(u for u in urls if u))
