"""End-of-life (EOL) lookup via endoflife.date.

Opt-in network call. Mirrors the OSV/vuln-intel pattern: failures degrade to
warnings, never exceptions. Used to flag operating systems (and, later, apps)
that no longer receive security support.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import date

ENDOFLIFE_CYCLE_URL = "https://endoflife.date/api/{product}/{cycle}.json"


@dataclass(frozen=True)
class EolResult:
    product: str
    cycle: str
    eol_date: str = ""  # ISO date, or "" if unknown
    latest: str = ""
    is_eol: bool = False
    support_unknown: bool = False

    @property
    def summary(self) -> str:
        if self.support_unknown:
            return f"{self.product} {self.cycle}: EOL date unknown"
        state = "end-of-life" if self.is_eol else "supported"
        date_text = f" (EOL {self.eol_date})" if self.eol_date else ""
        return f"{self.product} {self.cycle}: {state}{date_text}"


def query_cycle_eol(
    product: str,
    cycle: str,
    *,
    timeout_seconds: float = 12.0,
    today: date | None = None,
) -> tuple[EolResult | None, list[str]]:
    """Look up EOL status for a product release cycle (e.g. macos/14, windows/11)."""

    if not product or not cycle:
        return None, []
    # Prefer the approved local snapshot in every mode, before constructing URLs.
    from .intelligence_enrichment import load_document, records
    from .network_policy import offline_mode
    local, local_status, local_error = load_document()
    if local is not None:
        matches = [(row, source) for row, source in records(local, "lifecycle")
                   if row.get("product") == product and row.get("cycle") == cycle]
        if matches:
            row, source = matches[-1]
            result = _result_from_payload(product, cycle, {"eol": row.get("eolDate") or row.get("isEol"),
                                                          "latest": row.get("latestVersion")}, today or date.today())
            if source.get("status") != "fresh":
                return EolResult(product, cycle, result.eol_date, result.latest, result.is_eol, True), ["반입한 지원 종료 자료가 오래되었거나 기준일을 확인할 수 없습니다."]
            return result, []
    if offline_mode():
        return None, [local_error or f"반입 자료에 {product}/{cycle} 지원 종료 정보가 없습니다 ({local_status})."]
    url = ENDOFLIFE_CYCLE_URL.format(product=urllib_quote(product), cycle=urllib_quote(cycle))
    try:
        payload = _fetch(url, timeout_seconds)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None, [f"endoflife.date has no cycle {product}/{cycle}"]
        return None, [f"endoflife.date query failed: {exc}"]
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return None, [f"endoflife.date query failed: {exc}"]

    if not isinstance(payload, dict):
        return None, ["endoflife.date returned an unexpected response shape."]
    return _result_from_payload(product, cycle, payload, today or date.today()), []


def _result_from_payload(product: str, cycle: str, payload: dict, today: date) -> EolResult:
    raw_eol = payload.get("eol")
    latest = str(payload.get("latest", "") or "")
    if isinstance(raw_eol, bool):
        return EolResult(product=product, cycle=cycle, is_eol=raw_eol, latest=latest)
    if isinstance(raw_eol, str) and raw_eol:
        parsed = _parse_date(raw_eol)
        if parsed is None:
            return EolResult(product=product, cycle=cycle, eol_date=raw_eol, support_unknown=True, latest=latest)
        return EolResult(product=product, cycle=cycle, eol_date=raw_eol, is_eol=parsed < today, latest=latest)
    return EolResult(product=product, cycle=cycle, support_unknown=True, latest=latest)


def _parse_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        return None


def _fetch(url: str, timeout_seconds: float) -> object:
    from .network_policy import require_online
    require_online("endoflife.date")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "endoflife.date":
        raise ValueError("unexpected endoflife.date URL")
    request = urllib.request.Request(url, headers={"User-Agent": "koda-local-security-scanner"})
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        return json.loads(response.read().decode("utf-8"))


def urllib_quote(value: str) -> str:
    import urllib.parse

    return urllib.parse.quote(value, safe="")
