"""Cross-confirm static (source) findings with live web (DAST) findings.

Two independent signals agreeing on the same weakness are much stronger
evidence than either alone: a code sink that a live probe also exploited is no
longer a candidate, and a live finding whose sink is located in code can be
fixed at the exact line. This module reads a source-scan JSON report and a
web-scan JSON report and pairs them:

- by weakness (``_PAIRS``: code rule family <-> web rule family, with CWE / SW49),
- and, when the code file declares a route whose path matches the probed URL,
  by endpoint as well (``same_endpoint``) — the strongest match.

It also lists the static-only weaknesses (worth a targeted live test) and the
dynamic-only ones (live issue whose sink was not located in this source tree).
Deterministic post-processing over report files; no scan is re-run.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

# weakness -> (CWE, SW49 control, code rule ids, web rule ids)
_PAIRS: dict[str, tuple[str, str, frozenset[str], frozenset[str]]] = {
    "SQL injection": ("CWE-89", "I-01", frozenset({"code.sql-dynamic-query"}), frozenset({
        "web.sql-injection-error-verified", "web.sql-injection-time-blind",
        "web.sql-injection-boolean-blind", "web.sql-injection-exploited",
    })),
    "Code / template injection": ("CWE-94", "I-02", frozenset({"code.eval-user-input"}), frozenset({
        "web.ssti-verified", "web.ssti-exploited",
    })),
    "Path traversal": ("CWE-22", "I-03", frozenset({"code.path-traversal"}), frozenset({"web.path-traversal-lfi"})),
    "Cross-site scripting": ("CWE-79", "I-04", frozenset({"code.xss-dom-sink"}), frozenset({
        "web.reflected-xss-verified", "web.xss-js-context", "web.stored-xss", "web.dom-xss",
    })),
    "OS command injection": ("CWE-78", "I-05", frozenset({"code.command-injection"}), frozenset({
        "web.command-injection-time-blind", "web.command-injection-oob", "web.command-injection-exploited",
    })),
    "Open redirect": ("CWE-601", "I-07", frozenset({"code.open-redirect-user-input"}), frozenset({
        "web.open-redirect-verified",
    })),
    "SSRF": ("CWE-918", "I-12", frozenset({"code.ssrf-user-url"}), frozenset({
        "web.ssrf-oob-verified", "web.ssrf-cloud-metadata",
    })),
}

# Route declarations: Flask/FastAPI/Starlette decorators, Django path(), Express.
_ROUTE_RE = re.compile(
    r"""(?:@\s*[\w.]+\.(?:route|get|post|put|delete|patch|api_route)\s*\(\s*|"""
    r"""\b(?:re_)?path\s*\(\s*r?|\b(?:app|router)\.(?:get|post|put|delete|patch|all)\s*\(\s*)"""
    r"""["']([^"']+)["']""",
)
_PARAM_SEGMENT = re.compile(r"^(?:<[^>]+>|\{[^}]+\}|:\w+)$")
# Web findings store their URL as a filesystem Path, which collapses "//" after
# the scheme ("http:/host/x"); restore it so urlparse sees the host.
_COLLAPSED_SCHEME = re.compile(r"^(https?):/(?!/)", re.IGNORECASE)


def _web_url(finding: dict) -> str:
    return _COLLAPSED_SCHEME.sub(r"\1://", str(finding.get("path", "")))


def load_findings(path: Path) -> list[dict]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = payload.get("findings", []) if isinstance(payload, dict) else []
    return [f for f in findings if isinstance(f, dict) and f.get("rule_id")]


def _segments(route: str) -> list[str]:
    return [s for s in route.strip().strip("^$").split("/") if s]


def _route_matches(route: str, url_path: str) -> bool:
    route_parts, url_parts = _segments(route), _segments(url_path)
    if len(route_parts) != len(url_parts):
        return False
    return all(_PARAM_SEGMENT.match(r) or r == u for r, u in zip(route_parts, url_parts, strict=True))


def _route_for(finding: dict, cache: dict[str, list[tuple[int, str]]]) -> str | None:
    """Nearest route declared at or above the finding's line in its source file."""
    file_path, line = str(finding.get("path", "")), finding.get("line")
    if not file_path or not isinstance(line, int):
        return None
    if file_path not in cache:
        try:
            text = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            cache[file_path] = []
        else:
            cache[file_path] = [
                (number, match.group(1))
                for number, source in enumerate(text.splitlines(), start=1)
                for match in _ROUTE_RE.finditer(source)
            ]
    above = [route for number, route in cache[file_path] if number <= line]
    return above[-1] if above else None


def _loc(finding: dict) -> str:
    line = finding.get("line")
    return f"{finding.get('path', '')}:{line}" if line else str(finding.get("path", ""))


def correlate(code_findings: list[dict], web_findings: list[dict]) -> dict[str, object]:
    route_cache: dict[str, list[tuple[int, str]]] = {}
    corroborated, static_only, dynamic_only = [], [], []
    for weakness, (cwe, control, code_rules, web_rules) in _PAIRS.items():
        code = [f for f in code_findings if f["rule_id"] in code_rules]
        web = [f for f in web_findings if f["rule_id"] in web_rules]
        if code and web:
            endpoints = []
            for c in code:
                route = _route_for(c, route_cache)
                if route is None:
                    continue
                for w in web:
                    if _route_matches(route, urlparse(_web_url(w)).path):
                        endpoints.append({"route": route, "code": _loc(c), "web": _web_url(w)})
            corroborated.append({
                "weakness": weakness, "cwe": cwe, "sw49": control,
                "same_endpoint": bool(endpoints), "endpoints": endpoints,
                "code": [_loc(c) for c in code], "web": sorted({_web_url(w) for w in web}),
                "web_rules": sorted({w["rule_id"] for w in web}),
            })
        elif code:
            static_only.append({"weakness": weakness, "cwe": cwe, "sw49": control, "code": [_loc(c) for c in code]})
        elif web:
            dynamic_only.append({"weakness": weakness, "cwe": cwe, "sw49": control,
                                 "web": sorted({_web_url(w) for w in web})})
    corroborated.sort(key=lambda item: (not item["same_endpoint"], item["weakness"]))
    return {
        "summary": {
            "corroborated": len(corroborated),
            "same_endpoint": sum(1 for item in corroborated if item["same_endpoint"]),
            "static_only": len(static_only),
            "dynamic_only": len(dynamic_only),
        },
        "corroborated": corroborated,
        "static_only": static_only,
        "dynamic_only": dynamic_only,
    }


def render_markdown(result: dict[str, object], *, language: str = "ko") -> str:
    ko = language == "ko"
    s = result["summary"]
    lines = [
        "# " + ("정적·동적 교차확증 결과" if ko else "Static / dynamic cross-confirmation"),
        "",
        (f"- 교차확증 약점: {s['corroborated']}개 (동일 엔드포인트 {s['same_endpoint']}개)" if ko
         else f"- Corroborated weaknesses: {s['corroborated']} ({s['same_endpoint']} on the same endpoint)"),
        (f"- 정적만 탐지: {s['static_only']}개 · 동적만 탐지: {s['dynamic_only']}개" if ko
         else f"- Static only: {s['static_only']} · Dynamic only: {s['dynamic_only']}"),
        "",
        "## " + ("교차확증 (우선 조치)" if ko else "Corroborated (fix first)"),
    ]
    for item in result["corroborated"]:
        tag = ("동일 엔드포인트" if ko else "same endpoint") if item["same_endpoint"] else ("동일 약점" if ko else "same weakness")
        lines.append(f"- **{item['weakness']}** ({item['cwe']}, SW49 {item['sw49']}) — {tag}")
        for endpoint in item["endpoints"]:
            lines.append(f"  - `{endpoint['route']}`: {endpoint['code']} ↔ {endpoint['web']}")
        if not item["endpoints"]:
            lines.append(f"  - code: {', '.join(item['code'][:5])}")
            lines.append(f"  - web: {', '.join(item['web'][:5])}")
    lines += ["", "## " + ("정적만 탐지 (동적 재현 시험 권장)" if ko else "Static only (worth a targeted live test)")]
    lines += [f"- {item['weakness']} ({item['cwe']}): {', '.join(item['code'][:5])}" for item in result["static_only"]]
    lines += ["", "## " + ("동적만 탐지 (코드 위치 미확인)" if ko else "Dynamic only (sink not located in this source)")]
    lines += [f"- {item['weakness']} ({item['cwe']}): {', '.join(item['web'][:5])}" for item in result["dynamic_only"]]
    return "\n".join(lines) + "\n"
