"""Inspect recorded HTTP responses without contacting their origins."""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from urllib.parse import urlsplit

HAR_MAX_BYTES = 32 * 1024 * 1024
HAR_MAX_ENTRIES = 20_000
_HEADER_NAMES = {
    "content-type", "content-security-policy", "strict-transport-security",
    "x-content-type-options", "x-frame-options", "referrer-policy",
    "permissions-policy", "server", "x-powered-by", "set-cookie",
    "access-control-allow-origin", "access-control-allow-credentials",
}
_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _has_credential_header(request: dict) -> bool:
    headers = request.get("headers")
    if not isinstance(headers, list):
        return False
    return any(
        isinstance(row, dict)
        and isinstance(row.get("name"), str)
        and row["name"].lower() in {"authorization", "cookie"}
        and isinstance(row.get("value"), str)
        and bool(row["value"].strip())
        for row in headers
    )


def _http_origin(url: object) -> str | None:
    if not isinstance(url, str) or len(url) > 8192:
        return None
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
        if parts.scheme not in {"http", "https"} or not host or "%" in host:
            return None
        if ":" in host:
            host = f"[{ipaddress.IPv6Address(host).compressed}]"
        else:
            host = host.encode("idna").decode("ascii")
            if not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", host):
                return None
    except (ValueError, UnicodeError):
        return None
    if port is not None and port != (443 if parts.scheme == "https" else 80):
        host = f"{host}:{port}"
    return f"{parts.scheme}://{host}"


def review_har(raw: bytes) -> dict[str, object]:
    """Report rule counts and entry numbers. Raw request and response data stay in the HAR."""
    if len(raw) > HAR_MAX_BYTES:
        raise ValueError("HAR file exceeds 32 MiB.")
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, RecursionError) as exc:
        raise ValueError("HAR must be a UTF-8 JSON document.") from exc
    log = document.get("log") if isinstance(document, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise ValueError("HAR must contain a log.entries array.")
    if len(entries) > HAR_MAX_ENTRIES:
        raise ValueError("HAR contains more than 20,000 entries.")

    from .web import _cookie_flags, _cors, _information_disclosure, _lower_headers, _security_headers

    inspected = 0
    html_responses = 0
    cookie_responses = 0
    credentialed_requests = 0
    credentialed_writes = 0
    credential_headers_over_http: dict[str, list[int]] = {}
    methods: Counter[str] = Counter()
    findings: dict[tuple[str, str], dict[str, object]] = {}
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            continue
        request, response = entry.get("request"), entry.get("response")
        if not isinstance(request, dict):
            continue
        origin = _http_origin(request.get("url"))
        if not origin:
            continue
        method = request.get("method")
        method = method.upper() if isinstance(method, str) else ""
        methods[method if method in _METHODS else "OTHER"] += 1
        if _has_credential_header(request):
            credentialed_requests += 1
            credentialed_writes += method in _WRITE_METHODS
            if origin.startswith("http://"):
                credential_headers_over_http.setdefault(origin, []).append(index)
        if not isinstance(response, dict):
            continue
        status, header_list = response.get("status"), response.get("headers")
        if type(status) is not int or not 200 <= status <= 599 or not isinstance(header_list, list) or not header_list:
            continue
        if any(not isinstance(row, dict) or not isinstance(row.get("name"), str)
               or not isinstance(row.get("value"), str) for row in header_list):
            continue
        observed = [(row["name"].lower(), row["value"]) for row in header_list
                    if row["name"].lower() in _HEADER_NAMES]
        headers = _lower_headers((name, value) for name, value in observed if name != "set-cookie")
        cookies = [value for name, value in observed if name == "set-cookie" and value]
        content = response.get("content")
        mime_type = content.get("mimeType") if isinstance(content, dict) else None
        if not isinstance(mime_type, str) or not mime_type.strip():
            mime_type = headers.get("content-type", "")
        inspected += 1
        checks = _information_disclosure(origin, headers, origin) + _cors(origin, headers, origin)
        is_https = origin.startswith("https:")
        media_type = mime_type.split(";", 1)[0].strip().lower()
        complete_document = 200 <= status < 300 and status not in {204, 205, 206} and method != "HEAD"
        hsts = headers.get("strict-transport-security", "")
        if complete_document and media_type in {"text/html", "application/xhtml+xml"} and len(hsts) <= 4096:
            html_responses += 1
            checks.extend(_security_headers(origin, headers, is_https, origin))
        if cookies:
            cookie_responses += 1
            checks.extend(_cookie_flags(origin, cookies, is_https, origin))
        for finding in checks:
            key = (origin, finding.rule_id)
            if key not in findings:
                findings[key] = {
                    "origin": origin,
                    "rule_id": finding.rule_id,
                    "severity": finding.severity,
                    "title": finding.title,
                    "recommendation": finding.recommendation,
                    "entries": [],
                }
            findings[key]["entries"].append(index)

    return {
        "format": "koda.har-review.v1",
        "status": "REVIEWED" if inspected else "NO_RESPONSES",
        "entries": len(entries),
        "responses_reviewed": inspected,
        "html_responses_reviewed": html_responses,
        "responses_with_set_cookie": cookie_responses,
        "request_methods": dict(sorted(methods.items())),
        "credential_header_observations": {
            "requests": credentialed_requests,
            "write_requests": credentialed_writes,
            "over_http": [
                {"origin": origin, "entries": indices}
                for origin, indices in sorted(credential_headers_over_http.items())
            ],
        },
        "findings": [findings[key] for key in sorted(findings)],
    }


def render_review_page(language: str) -> str:
    korean = language == "ko"
    title = "HAR 기록 검토" if korean else "Review HAR recording"
    instructions = (
        "저장된 응답의 보안 헤더·쿠키 속성과 요청에 인증 헤더가 기록됐는지 확인합니다."
        if korean else "Review recorded response headers and check whether requests carried credential headers."
    )
    action = "검토" if korean else "Review"
    save = "JSON 저장" if korean else "Save JSON"
    return f"""<!doctype html><html lang="{'ko' if korean else 'en'}">
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KODA · {title}</title>
<style>body{{font:16px system-ui;max-width:65rem;margin:2rem auto;padding:0 1rem}}
label,button{{margin-right:.5rem}} input,button{{font:inherit}}
table{{border-collapse:collapse;width:100%;overflow-wrap:anywhere}} th,td{{padding:.5rem;text-align:left;border-bottom:1px solid #9995}}
</style>
<a href="/security-dashboard.html">← KODA</a><h1>{title}</h1><p>{instructions}</p>
<form><label>HAR <input type="file" id="file" accept=".har,.json" required></label>
<button id="review">{action}</button><button type="button" id="save" hidden>{save}</button></form>
<p id="status" role="status"></p><p id="methods"></p><p id="credentials"></p><ul id="http-credentials"></ul>
<table hidden><thead><tr>
<th scope="col">{'출처' if korean else 'Origin'}</th><th scope="col">{'발견 항목' if korean else 'Finding'}</th>
<th scope="col">{'심각도' if korean else 'Severity'}</th><th scope="col">{'응답 수' if korean else 'Responses'}</th>
</tr></thead><tbody></tbody></table>
<script>
const ko = {json.dumps(korean)}, limit = {HAR_MAX_BYTES};
const file = document.querySelector('#file'), review = document.querySelector('#review');
const save = document.querySelector('#save'), table = document.querySelector('table');
const methods = document.querySelector('#methods'), findings = document.querySelector('tbody');
const credentials = document.querySelector('#credentials'), httpCredentials = document.querySelector('#http-credentials');
const status = document.querySelector('#status');
let report;
document.querySelector('form').addEventListener('submit', async event => {{
  event.preventDefault();
  findings.replaceChildren(); methods.textContent = ''; status.textContent = '';
  credentials.textContent = ''; httpCredentials.replaceChildren();
  table.hidden = true; save.hidden = true;
  const selected = file.files[0];
  if (!selected || selected.size > limit) {{
    status.textContent = ko ? '32 MiB 이하의 HAR 파일을 선택하세요.' : 'Select a HAR file of up to 32 MiB.';
    return;
  }}
  review.disabled = true;
  try {{
    const health = await fetch('/api/health');
    const response = await fetch('/api/har-review', {{
      method: 'POST', headers: {{'Content-Type': 'application/octet-stream',
        'X-KODA-Session': health.headers.get('X-KODA-Session')}}, body: selected
    }});
    const data = await response.json();
    if (!response.ok) throw Error(data.error || response.statusText);
    status.textContent = data.status === 'NO_RESPONSES'
      ? (ko ? '검토할 응답 헤더가 기록에 없습니다.' : 'No recorded response headers to review.')
      : (ko ? '검토한 응답 ' : 'Responses reviewed ') + data.responses_reviewed + ' / ' + data.entries;
    methods.textContent = Object.entries(data.request_methods).map(([method, count]) => method + ' ' + count).join(' · ');
    const counts = data.credential_header_observations;
    credentials.textContent = ko
      ? `인증 헤더가 기록된 요청 ${{counts.requests}}건 · 이 중 쓰기 메서드 ${{counts.write_requests}}건`
      : `Requests with credential headers ${{counts.requests}} · Write methods ${{counts.write_requests}}`;
    for (const entry of counts.over_http) {{
      const item = document.createElement('li');
      item.textContent = (ko ? 'HTTP에서 인증 헤더 관측 ' : 'Credential headers recorded over HTTP ')
        + entry.origin + ' · ' + entry.entries.length;
      httpCredentials.append(item);
    }}
    for (const finding of data.findings.slice(0, 200)) {{
      const row = findings.insertRow();
      for (const value of [finding.origin, finding.title, finding.severity, finding.entries.length]) {{
        row.insertCell().textContent = value;
      }}
    }}
    if (data.findings.length > 200) {{
      status.textContent += ko ? ' · 처음 200개 표시. 전체 결과는 JSON에 있습니다.'
                               : ' · Showing the first 200 findings. All results are in the JSON file.';
    }}
    table.hidden = !data.findings.length;
    report = data;
    save.hidden = false;
  }} catch (error) {{
    status.textContent = error.message;
  }} finally {{
    review.disabled = false;
  }}
}});
save.addEventListener('click', () => {{
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2) + '\\n'], {{type:'application/json'}}));
  const link = document.createElement('a');
  link.href = url; link.download = 'koda-har-review.json'; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}});
</script></html>"""
