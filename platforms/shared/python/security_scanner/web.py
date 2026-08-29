"""Live website security posture checks using only the Python standard library.

This is the lightweight, dependency-free counterpart to the Docker/OWASP-ZAP
path in ``dast.py``. The request footprint depends on the options:

- Default single-page scan: one GET plus one TLS handshake, inspecting security
  headers, TLS/certificate posture, cookie flags, HTTP→HTTPS enforcement,
  information disclosure, CORS, mixed content, SRI, and CSRF-less forms.
- ``crawl``/``render``/``discover_assets``/``capture_network``/``interact``:
  fetch many same-host pages, download JS bundles, and (with Playwright) render
  and click in a headless browser to discover routes.
- ``probe_paths``: actively request well-known sensitive paths and POST a
  GraphQL introspection query.

None of these send attack payloads or fuzz parameters, but crawling and probing
do issue many requests and touch non-linked paths, so run it only against
systems you own or are authorized to test. The analysis helpers
(``analyze_response``/``analyze_body``/``check_tls``) are separated from the
network fetch so they can be unit tested without a live server.
"""

from __future__ import annotations

import base64
import difflib
import http.cookiejar
import json
import os
import re
import secrets
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

from .models import Finding

_USER_AGENT = "KODA-web-scanner (+https://gitlab.aigov.go.kr/y2kthr/koda)"
# Certificates expiring within this window are surfaced before they break TLS.
_CERT_EXPIRY_WARN_DAYS = 21
_WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
# Only parse HTML bodies below this size for links (crawl); larger responses are
# still analyzed for headers but not followed.
_MAX_BODY_BYTES = 2 * 1024 * 1024
_USER_FIELD_RE = re.compile(r"user|email|login|\bid\b|userid|username", re.IGNORECASE)
_PASS_FIELD_RE = re.compile(r"pass|pwd", re.IGNORECASE)


class ResponseBodyLimitError(Exception):
    """The response exceeded the scanner's safe inspection size."""


def check_web(
    url: str,
    *,
    timeout: float = 15.0,
    opener: urllib.request.OpenerDirector | None = None,
    extra_headers: Mapping[str, str] | None = None,
    network_context: object | None = None,
) -> tuple[list[Finding], list[str]]:
    """Run all live web checks against a single ``url``.

    Returns ``(findings, warnings)``. Thin wrapper over :func:`crawl_web` with a
    one-page budget, so single-page behaviour and crawl share one code path.
    """

    findings, warnings, _ = crawl_web(
        url,
        timeout=timeout,
        max_pages=1,
        max_depth=0,
        delay=0.0,
        opener=opener,
        extra_headers=extra_headers,
        network_context=network_context,
    )
    return findings, warnings


def crawl_web(
    seed_url: str,
    *,
    timeout: float = 15.0,
    max_pages: int | None = None,
    max_depth: int | None = None,
    delay: float = 0.3,
    opener: urllib.request.OpenerDirector | None = None,
    extra_headers: Mapping[str, str] | None = None,
    render: bool = False,
    seeds: Sequence[str] = (),
    discover_assets: bool = False,
    capture_network: bool = False,
    interact: bool = False,
    max_clicks: int = 20,
    max_assets: int = 20,
    scan_js_secrets: bool = False,
    ingest_sitemap: bool = False,
    probe_paths: bool = False,
    active: bool = False,
    compare_unauth: bool = False,
    secondary_headers: Mapping[str, str] | None = None,
    scanned_pages: list[str] | None = None,
    page_results: list[dict[str, object]] | None = None,
    allowed_origins: Sequence[str] = (),
    network_context: object | None = None,
) -> tuple[list[Finding], list[str], int]:
    """Crawl same-host pages from ``seed_url`` and run web checks on each.

    Breadth-first over links that stay on the seed's host with a ``delay`` between
    requests. Optional explicit limits are retained for single-page callers. Header,
    cookie and CORS checks run per page; TLS is checked once per host. Findings
    that repeat across pages (e.g. a missing CSP header) are collapsed to one
    representative each. Returns ``(findings, warnings, pages_scanned)``.

    Link discovery combines several sources so JavaScript-heavy apps (SPAs) that
    expose no ``<a href>`` links are still reached:

    - ``render``: load each page in a headless browser (Playwright extra) to see
      JS-rendered anchors.
    - ``capture_network``: while rendering, record same-host URLs the page
      fetches (its API/route surface). Requires ``render``.
    - ``interact``: while rendering, click bounded candidate elements and record
      routes they navigate to (``max_clicks`` cap). Requires ``render``.
    - ``discover_assets``: fetch the page's same-host JS bundles and extract
      path-like route/endpoint strings (``max_assets`` cap). Works without a
      browser.
    - ``seeds``: extra same-host URLs to enqueue up front (known routes, a
      sitemap dump, an OpenAPI path list).
    - ``scan_js_secrets``: scan fetched same-host JS bundles for leaked secrets
      (API keys, tokens) using the shared secret rules.
    - ``ingest_sitemap``: read ``/robots.txt`` and ``/sitemap.xml`` and enqueue
      the same-host URLs (and Disallow paths) they list.
    - ``probe_paths``: probe a fixed list of well-known sensitive paths
      (``/.env``, ``/.git/config``, ``/openapi.json`` …) and flag exposed ones,
      guarding against SPA catch-all 200s.

    Falls back to stdlib link extraction with a one-time warning when the
    browser-based options are requested but Playwright is unavailable.
    """

    parsed = urllib.parse.urlparse(seed_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return [], [f"Web scan skipped: not an http(s) URL: {seed_url}"], 0

    target = parsed.netloc
    allowed = {_origin(seed_url), *(_origin(origin) for origin in allowed_origins)}
    if opener is None:
        opener = network_context.build_opener() if network_context is not None else build_auth_opener()
    headers = {"User-Agent": _USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)

    warnings: list[str] = []
    collected: list[Finding] = []
    tls_checked_hosts: set[str] = set()
    host_probed: set[str] = set()
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(seed_url, 0)])
    queued = {_canonical(seed_url)}
    # E: enqueue caller-supplied same-host seeds (known routes / sitemap / API paths).
    for seed in seeds:
        absolute = urllib.parse.urljoin(seed_url, seed)
        key = _canonical(absolute)
        if _is_allowed_origin(absolute, allowed) and key not in queued:
            queue.append((absolute, 0))
            queued.add(key)
    pages_scanned = 0
    processed_urls = 0
    max_attempts = None if max_pages is None else max_pages * 2
    depth_limited = False
    render_warned = False
    assets_seen: set[str] = set()  # A: JS bundles already scraped (global budget)
    asset_failures = 0
    asset_limit_reached = False

    if ingest_sitemap:
        for url in _ingest_sitemaps(seed_url, opener, headers, timeout):
            key = _canonical(url)
            if _is_allowed_origin(url, allowed) and key not in queued:
                queue.append((url, 0))
                queued.add(key)
    if probe_paths:
        collected.extend(_probe_sensitive_paths(seed_url, opener, headers, timeout, target))
        collected.extend(_probe_graphql(seed_url, opener, headers, timeout, target))

    while (
        queue
        and (max_pages is None or pages_scanned < max_pages)
        and (max_attempts is None or processed_urls < max_attempts)
    ):
        current, depth = queue.popleft()
        canonical = _canonical(current)
        if canonical in visited:
            continue
        visited.add(canonical)
        processed_urls += 1

        if pages_scanned and delay:
            time.sleep(delay)

        try:
            fetched = _fetch(opener, current, headers, timeout, allowed, network_context=network_context)
        except ResponseBodyLimitError as exc:
            warnings.append(f"Web scan left {current} unscanned: {exc}")
            if page_results is not None:
                page_results.append(_page_result(current, current, 0, "", True, "", False, str(exc)))
            continue
        if fetched is None:
            # Only the seed's unreachability is worth a finding; sub-pages degrade
            # to a warning so one dead link never dominates the report.
            if pages_scanned == 0:
                collected.append(
                    _finding(
                        "web.connection-failed",
                        "info",
                        "Website could not be reached",
                        current,
                        target=target,
                        evidence="request failed",
                        recommendation="Confirm the URL, that the service is running, and that TLS is valid.",
                    )
                )
            warnings.append(f"Web scan could not reach {current}")
            if page_results is not None:
                page_results.append(_page_result(current, current, 0, "", False, "", False, "request failed"))
            continue

        final_url, status, content_type, header_items, set_cookies, body = fetched
        if not _is_allowed_origin(final_url, allowed):
            warnings.append(f"Web scan skipped cross-host redirect from {current} to {final_url}")
            if page_results is not None:
                page_results.append(_page_result(
                    current, final_url, status, content_type, False, "", False, "redirected to an unapproved origin"
                ))
            continue
        login_redirect = _canonical(current) != _canonical(final_url) and _looks_like_login(body.decode("utf-8", "replace"))
        if login_redirect:
            warnings.append(f"Web scan could not inspect protected page {current}; it redirected to login page {final_url}")
            if page_results is not None:
                page_results.append(_page_result(
                    current, final_url, status, content_type, True, "login-page", False,
                    "redirected to login page; protected content was not scanned",
                ))
            continue
        pages_scanned += 1
        if scanned_pages is not None:
            scanned_pages.append(final_url)

        checks = ["headers", "cookies"]
        if body:
            checks.append("html-body")
        active_executed = active and (bool(urllib.parse.urlparse(final_url).query) or bool(body))
        if page_results is not None:
            page_results.append(_page_result(
                current, final_url, status, content_type, True, "authenticated" if _cookie_count(opener) else "not-requested",
                active_executed, "", checks,
            ))

        collected.extend(analyze_response(final_url, header_items, set_cookies, target=target))
        if body:
            collected.extend(analyze_body(final_url, body, target=target))
        if active and urllib.parse.urlparse(final_url).query:
            # Opt-in active verification of this URL's query parameters.
            collected.extend(active_probe(final_url, opener, headers, timeout, target))
        if active and body:
            # Opt-in active verification of this page's form fields (GET/POST).
            collected.extend(form_active_probe(final_url, body, opener, headers, timeout, target))
        if (compare_unauth or secondary_headers) and not _is_static_asset(final_url):
            # Access-control comparison: does a lower-privileged context get the
            # same authenticated content? (IDOR/BOLA/BFLA heuristic.)
            collected.extend(
                _access_control_check(
                    final_url, opener, headers, timeout, target,
                    compare_unauth=compare_unauth, secondary_headers=secondary_headers,
                    network_context=network_context,
                )
            )

        if urllib.parse.urlparse(current).scheme == "http" and urllib.parse.urlparse(final_url).scheme != "https":
            collected.append(
                _finding(
                    "web.no-https-redirect",
                    "medium",
                    "HTTP is not redirected to HTTPS",
                    final_url,
                    target=target,
                    evidence=f"GET {current} did not upgrade to https (final URL {final_url}).",
                    recommendation="Redirect all HTTP traffic to HTTPS and serve HSTS on the HTTPS response.",
                )
            )

        final = urllib.parse.urlparse(final_url)
        if final.scheme == "https" and final.hostname and final.hostname not in tls_checked_hosts:
            tls_checked_hosts.add(final.hostname)
            tls_findings, tls_warnings = check_tls(
                final.hostname, final.port or 443, timeout=timeout, target=target, url=final_url,
                network_context=network_context,
            )
            collected.extend(tls_findings)
            warnings.extend(tls_warnings)

        if final.hostname and final.hostname not in host_probed and not _is_static_asset(final_url):
            # Per-host active probes (once each): dynamic CORS (origin reflection /
            # 'null'), advertised HTTP methods (TRACE/write), and Host-header
            # reflection. GET/OPTIONS only, no payloads.
            host_probed.add(final.hostname)
            collected.extend(_cors_reflection_probe(final_url, opener, headers, timeout, target))
            collected.extend(_http_methods_probe(final_url, opener, headers, timeout, target))
            collected.extend(_host_header_probe(final_url, headers, timeout, target, opener=opener))

        candidates: set[str] = set()
        link_source = body
        if render:
            rendered, extra_urls, browser_cookies, render_error = _render_page(
                final_url,
                timeout=timeout,
                extra_headers=headers,
                capture_network=capture_network,
                interact=interact,
                max_clicks=max_clicks,
                cookies=_opener_cookies(opener),
                network_context=network_context,
            )
            if rendered is not None:
                # Rendered DOM is a superset of the raw HTML for link discovery.
                link_source = rendered
                # Sync any cookie the SPA rotated back into the jar so later
                # stdlib requests keep the fresh session (bidirectional sync).
                _merge_browser_cookies(opener, browser_cookies)
                candidates.update(extra_urls)  # C/D: network + interaction URLs
            elif render_error and not render_warned:
                warnings.append(render_error)
                render_warned = True
        if link_source:
            candidates.update(_extract_links(final_url, link_source))
        if (discover_assets or scan_js_secrets) and body:
            # A: mine same-host JS bundles for routes and/or leaked secrets.
            routes, secret_findings, failed_assets, limit_reached = _scan_assets(
                final_url, body, opener, headers, timeout, assets_seen, max_assets, target,
                extract_routes=discover_assets, scan_secrets=scan_js_secrets,
            )
            candidates.update(routes)
            collected.extend(secret_findings)
            asset_failures += failed_assets
            asset_limit_reached = asset_limit_reached or limit_reached
        for link in candidates:
            key = _canonical(link)
            if _is_allowed_origin(link, allowed) and not _is_static_asset(link) and key not in queued:
                if max_depth is None or depth < max_depth:
                    queue.append((link, depth + 1))
                    queued.add(key)
                elif max_depth > 0:
                    depth_limited = True

    if queue and max_pages is not None:
        limit = f"max_pages={max_pages}" if pages_scanned >= max_pages else f"request safety limit={max_attempts}"
        warnings.append(f"Web crawl stopped at {limit}; {len(queue)} queued URL(s) remain unscanned.")
    if depth_limited:
        warnings.append(
            f"Web crawl reached max_depth={max_depth}; deeper same-host links remain unscanned."
        )
    if asset_failures:
        warnings.append(
            f"Web scan could not inspect {asset_failures} JavaScript asset(s); route and secret coverage is incomplete."
        )
    if asset_limit_reached:
        warnings.append(
            f"Web scan reached max_assets={max_assets}; remaining JavaScript assets were not inspected."
        )

    findings = _dedupe_findings(collected)
    findings.sort(key=lambda finding: finding.sort_key())
    return findings, warnings, pages_scanned


def analyze_response(
    url: str,
    headers: Mapping[str, str] | Iterable[tuple[str, str]],
    set_cookies: Sequence[str] = (),
    *,
    target: str = "",
) -> list[Finding]:
    """Analyze already-fetched response headers/cookies (no network).

    ``headers`` may be a mapping or an iterable of ``(name, value)`` pairs, as
    returned by ``http.client.HTTPMessage.items()``.
    """

    lowered = _lower_headers(headers)
    is_https = urllib.parse.urlparse(url).scheme == "https"
    findings: list[Finding] = []
    findings.extend(_security_headers(url, lowered, is_https, target))
    findings.extend(_cookie_flags(url, set_cookies, is_https, target))
    findings.extend(_information_disclosure(url, lowered, target))
    findings.extend(_cors(url, lowered, target))
    findings.extend(_jwt_findings(url, set_cookies, target))
    return findings


class _BodyParser(HTMLParser):
    """Collect subresources and forms from HTML for Tier-2 body checks."""

    def __init__(self) -> None:
        super().__init__()
        # (tag, url, has_integrity, is_subresource_needing_sri)
        self.subresources: list[tuple[str, str, bool, bool]] = []
        self.forms: list[dict[str, object]] = []
        self._form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {k: (v or "") for k, v in attrs}
        if tag == "script" and data.get("src"):
            self.subresources.append(("script", data["src"], "integrity" in data, True))
        elif tag == "link" and data.get("href") and "stylesheet" in data.get("rel", "").lower():
            self.subresources.append(("link", data["href"], "integrity" in data, True))
        elif tag in {"img", "iframe", "source", "audio", "video"} and data.get("src"):
            # Mixed-content matters; SRI does not apply to these.
            self.subresources.append((tag, data["src"], True, False))
        elif tag == "form":
            self._form = {"method": data.get("method", "get").lower(), "has_password": False, "has_token": False}
        elif tag == "input" and self._form is not None:
            itype = data.get("type", "text").lower()
            name = data.get("name", "").lower()
            if itype == "password":
                self._form["has_password"] = True
            if any(token in name for token in ("csrf", "xsrf", "authenticity", "nonce", "_token", "token")):
                self._form["has_token"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def analyze_body(url: str, body: bytes | str, *, target: str = "") -> list[Finding]:
    """Tier-2 passive HTML checks: mixed content, missing SRI, and CSRF-less forms."""
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    parser = _BodyParser()
    try:
        parser.feed(text)
    except Exception:
        return []

    page = urllib.parse.urlparse(url)
    is_https = page.scheme == "https"
    findings: list[Finding] = []
    findings.extend(_error_disclosure(url, text, target))

    mixed: list[str] = []
    sri_missing: list[str] = []
    for _tag, src, has_integrity, needs_sri in parser.subresources:
        absolute = urllib.parse.urljoin(url, src)
        parsed = urllib.parse.urlparse(absolute)
        if is_https and parsed.scheme == "http":
            mixed.append(absolute)
        if needs_sri and not has_integrity and parsed.scheme in {"http", "https"} and parsed.netloc and parsed.netloc != page.netloc:
            sri_missing.append(absolute)

    if mixed:
        findings.append(
            _finding(
                "web.mixed-content", "medium", "HTTPS page loads resources over HTTP (mixed content)",
                url, target=target, evidence="; ".join(sorted(set(mixed))[:5]),
                recommendation="Serve every subresource over HTTPS; upgrade or remove http:// script/style/media URLs.",
            )
        )
    if sri_missing:
        findings.append(
            _finding(
                "web.subresource-integrity-missing", "low", "Cross-origin script/style without Subresource Integrity",
                url, target=target, evidence="; ".join(sorted(set(sri_missing))[:5]),
                recommendation="Add an 'integrity' (and 'crossorigin') attribute to third-party <script>/<link> tags.",
            )
        )

    for form in parser.forms:
        if form["method"] == "post" and not form["has_token"]:
            findings.append(
                _finding(
                    "web.form-missing-csrf-token", "low", "POST form has no visible CSRF token field",
                    url, target=target,
                    evidence="A <form method=post> exposed no csrf/token hidden field.",
                    recommendation="Include an anti-CSRF token in state-changing forms (or rely on SameSite cookies + a verified header).",
                )
            )
            break
    if not is_https and any(form["has_password"] for form in parser.forms):
        findings.append(
            _finding(
                "web.password-input-over-http", "high", "Password field served over plain HTTP",
                url, target=target, evidence="A password <input> was served on an http:// page.",
                recommendation="Serve any page with a password field exclusively over HTTPS.",
            )
        )
    return findings


def check_tls(
    host: str,
    port: int = 443,
    *,
    timeout: float = 15.0,
    target: str = "",
    url: str = "",
    network_context: object | None = None,
) -> tuple[list[Finding], list[str]]:
    """Inspect certificate expiry and negotiated protocol via one TLS handshake."""

    location = url or f"https://{host}"
    context = ssl.create_default_context()
    try:
        if network_context is not None:
            with network_context.connect_tls(host, port, timeout) as tls:
                cert = tls.getpeercert()
                version = tls.version() or ""
        else:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    version = tls.version() or ""
    except ssl.SSLCertVerificationError as exc:
        return (
            [
                _finding(
                    "web.tls-certificate-invalid",
                    "high",
                    "TLS certificate did not validate",
                    location,
                    target=target,
                    evidence=str(exc),
                    recommendation="Install a valid certificate chain trusted for this hostname.",
                )
            ],
            [],
        )
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        return [], [f"TLS check could not complete for {host}:{port}: {exc}"]

    findings: list[Finding] = []
    findings.extend(_certificate_expiry(location, cert, target))
    if version in _WEAK_TLS_VERSIONS:
        findings.append(
            _finding(
                "web.weak-tls-version",
                "medium",
                f"Server negotiated a weak TLS version ({version})",
                location,
                target=target,
                evidence=f"Negotiated protocol: {version}",
                recommendation="Disable TLS 1.1 and earlier; require TLS 1.2 or TLS 1.3.",
            )
        )
    return findings, []


# --- analysis helpers -------------------------------------------------------


def _csp_quality(url: str, csp: str, target: str) -> list[Finding]:
    """Flag a present-but-weak Content-Security-Policy (not just its absence)."""
    lowered = csp.lower()
    directives = {
        part.split()[0]: part for part in (seg.strip() for seg in lowered.split(";")) if part
    }
    # The source list that actually governs script execution.
    script = directives.get("script-src") or directives.get("default-src") or ""
    weaknesses: list[str] = []
    if "'unsafe-inline'" in script:
        weaknesses.append("script-src allows 'unsafe-inline'")
    if "'unsafe-eval'" in script:
        weaknesses.append("script-src allows 'unsafe-eval'")
    # A bare '*' (or http(s): scheme source) as a script source defeats the policy.
    tokens = script.split()[1:] if script else []
    if any(tok in {"*", "http:", "https:"} for tok in tokens):
        weaknesses.append("script-src allows a wildcard/scheme source")
    if "object-src" not in directives and "default-src" not in directives:
        weaknesses.append("no object-src/default-src to block plugins")
    if not weaknesses:
        return []
    return [
        _finding(
            "web.weak-csp", "medium", "Content-Security-Policy is present but weak",
            url, target=target, evidence="; ".join(weaknesses),
            recommendation="Remove 'unsafe-inline'/'unsafe-eval' and wildcard sources; use nonces/hashes and set object-src 'none' and base-uri 'self'.",
        )
    ]


def _hsts_quality(url: str, hsts: str, target: str) -> list[Finding]:
    """Flag a present-but-weak HSTS header (short max-age / no includeSubDomains)."""
    lowered = hsts.lower()
    max_age = 0
    match = re.search(r"max-age\s*=\s*(\d+)", lowered)
    if match:
        max_age = int(match.group(1))
    issues: list[str] = []
    if max_age < 15552000:  # < 180 days is too short to matter
        issues.append(f"max-age={max_age} is under 180 days")
    if "includesubdomains" not in lowered:
        issues.append("no includeSubDomains")
    if not issues:
        return []
    return [
        _finding(
            "web.weak-hsts", "low", "HSTS header is present but weak",
            url, target=target, evidence="; ".join(issues),
            recommendation="Use 'Strict-Transport-Security: max-age=31536000; includeSubDomains' (add 'preload' once verified).",
        )
    ]


def _security_headers(url: str, headers: dict[str, str], is_https: bool, target: str) -> list[Finding]:
    findings: list[Finding] = []
    csp = headers.get("content-security-policy", "")

    if is_https and "strict-transport-security" not in headers:
        findings.append(
            _finding(
                "web.missing-hsts",
                "medium",
                "Missing HTTP Strict-Transport-Security (HSTS) header",
                url,
                target=target,
                recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            )
        )
    elif is_https:
        findings.extend(_hsts_quality(url, headers["strict-transport-security"], target))
    if not csp:
        findings.append(
            _finding(
                "web.missing-csp",
                "medium",
                "Missing Content-Security-Policy header",
                url,
                target=target,
                recommendation="Define a Content-Security-Policy to limit script/style/connect sources.",
            )
        )
    else:
        findings.extend(_csp_quality(url, csp, target))
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(
            _finding(
                "web.missing-x-content-type-options",
                "low",
                "Missing 'X-Content-Type-Options: nosniff' header",
                url,
                target=target,
                recommendation="Send 'X-Content-Type-Options: nosniff' to stop MIME sniffing.",
            )
        )
    if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
        findings.append(
            _finding(
                "web.missing-frame-protection",
                "medium",
                "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
                url,
                target=target,
                recommendation="Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
            )
        )
    if "referrer-policy" not in headers:
        findings.append(
            _finding(
                "web.missing-referrer-policy",
                "low",
                "Missing Referrer-Policy header",
                url,
                target=target,
                recommendation="Send a Referrer-Policy such as 'strict-origin-when-cross-origin'.",
            )
        )
    if "permissions-policy" not in headers:
        findings.append(
            _finding(
                "web.missing-permissions-policy",
                "info",
                "Missing Permissions-Policy header",
                url,
                target=target,
                recommendation="Send a Permissions-Policy to restrict powerful browser features.",
            )
        )
    return findings


def _cookie_flags(url: str, set_cookies: Sequence[str], is_https: bool, target: str) -> list[Finding]:
    if not set_cookies:
        return []
    missing_secure: list[str] = []
    missing_httponly: list[str] = []
    missing_samesite: list[str] = []
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip() or "(unnamed)"
        attributes = {part.strip().lower() for part in raw.split(";")[1:]}
        has_secure = "secure" in attributes
        has_httponly = "httponly" in attributes
        has_samesite = any(attr.startswith("samesite") for attr in attributes)
        if is_https and not has_secure:
            missing_secure.append(name)
        if not has_httponly:
            missing_httponly.append(name)
        if not has_samesite:
            missing_samesite.append(name)

    findings: list[Finding] = []
    if missing_secure:
        findings.append(
            _finding(
                "web.cookie-missing-secure",
                "medium",
                "Cookie set without the Secure flag over HTTPS",
                url,
                target=target,
                evidence=f"Cookies: {', '.join(missing_secure)}",
                recommendation="Add the 'Secure' attribute so cookies are only sent over HTTPS.",
            )
        )
    if missing_httponly:
        findings.append(
            _finding(
                "web.cookie-missing-httponly",
                "low",
                "Cookie set without the HttpOnly flag",
                url,
                target=target,
                evidence=f"Cookies: {', '.join(missing_httponly)}",
                recommendation="Add 'HttpOnly' to keep cookies out of reach of JavaScript.",
            )
        )
    if missing_samesite:
        findings.append(
            _finding(
                "web.cookie-missing-samesite",
                "low",
                "Cookie set without a SameSite attribute",
                url,
                target=target,
                evidence=f"Cookies: {', '.join(missing_samesite)}",
                recommendation="Add 'SameSite=Lax' or 'SameSite=Strict' to reduce CSRF exposure.",
            )
        )
    return findings


def _information_disclosure(url: str, headers: dict[str, str], target: str) -> list[Finding]:
    findings: list[Finding] = []
    server = headers.get("server", "")
    if server and any(char.isdigit() for char in server):
        findings.append(
            _finding(
                "web.server-version-disclosure",
                "low",
                "Server header discloses software version",
                url,
                target=target,
                evidence=f"Server: {server}",
                recommendation="Suppress or generalize the 'Server' header so it omits version details.",
            )
        )
    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        findings.append(
            _finding(
                "web.x-powered-by-disclosure",
                "low",
                "X-Powered-By header discloses technology stack",
                url,
                target=target,
                evidence=f"X-Powered-By: {powered_by}",
                recommendation="Remove the 'X-Powered-By' header.",
            )
        )
    return findings


def _cors(url: str, headers: dict[str, str], target: str) -> list[Finding]:
    origin = headers.get("access-control-allow-origin", "").strip()
    if origin != "*":
        return []
    credentials = headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    if credentials:
        return [
            _finding(
                "web.cors-wildcard-credentials",
                "high",
                "CORS allows any origin together with credentials",
                url,
                target=target,
                evidence="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                recommendation="Never combine a wildcard origin with credentials; echo an explicit allowlisted origin.",
            )
        ]
    return [
        _finding(
            "web.cors-wildcard",
            "low",
            "CORS allows any origin (Access-Control-Allow-Origin: *)",
            url,
            target=target,
            evidence="Access-Control-Allow-Origin: *",
            recommendation="Restrict CORS to the specific origins that need cross-site access.",
        )
    ]


def _without_credentials(headers: Mapping[str, str]) -> dict[str, str]:
    """Drop the operator's own credentials. Per-host / cross-origin probes must
    never forward them: the probed host may differ from the seed (redirect /
    allowed origin), and forwarding would leak the credentials there."""
    return {name: value for name, value in headers.items() if name.lower() not in {"cookie", "authorization"}}


# A syntactically valid but attacker-controlled origin no real allowlist matches.
_CORS_PROBE_ORIGIN = "https://koda-cors-probe.example"


def _cors_acao(
    opener: urllib.request.OpenerDirector,
    url: str,
    headers: Mapping[str, str],
    timeout: float,
    origin: str,
) -> tuple[str, bool] | None:
    """GET ``url`` with a test ``Origin`` header; return the server's
    (Access-Control-Allow-Origin, credentials-allowed) or ``None`` on error."""
    # Reflection is flagged by the server's ACAC response header, not our request,
    # so send no credentials (and avoid leaking them to a cross-origin host).
    request = urllib.request.Request(url, headers={**_without_credentials(headers), "Origin": origin}, method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            response_headers = response.headers
    except urllib.error.HTTPError as exc:
        response_headers = exc.headers
        exc.close()
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError):
        return None
    if response_headers is None:
        return None
    acao = (response_headers.get("Access-Control-Allow-Origin") or "").strip()
    acac = (response_headers.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true"
    return acao, acac


def _cors_reflection_probe(
    url: str,
    opener: urllib.request.OpenerDirector,
    headers: Mapping[str, str],
    timeout: float,
    target: str,
) -> list[Finding]:
    """Actively verify dynamic CORS misconfigurations the passive ``*`` check
    misses: reflecting an arbitrary request Origin, and allowing ``null``.
    Sends one GET per test Origin (no payloads, no state change)."""

    findings: list[Finding] = []

    reflected = _cors_acao(opener, url, headers, timeout, _CORS_PROBE_ORIGIN)
    if reflected is not None and reflected[0] == _CORS_PROBE_ORIGIN:
        if reflected[1]:
            findings.append(
                _finding(
                    "web.cors-origin-reflection-credentials", "high",
                    "CORS reflects an arbitrary Origin together with credentials",
                    url, target=target,
                    evidence=f"Origin: {_CORS_PROBE_ORIGIN} was echoed in Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true",
                    recommendation="Validate Origin against a strict allowlist; never reflect the request Origin when credentials are allowed.",
                )
            )
        else:
            findings.append(
                _finding(
                    "web.cors-origin-reflection", "medium",
                    "CORS reflects any request Origin",
                    url, target=target,
                    evidence=f"Origin: {_CORS_PROBE_ORIGIN} was echoed back in Access-Control-Allow-Origin",
                    recommendation="Reflecting an unvalidated Origin lets any site read cross-origin responses; use a strict allowlist.",
                )
            )

    null_probe = _cors_acao(opener, url, headers, timeout, "null")
    if null_probe is not None and null_probe[0] == "null":
        findings.append(
            _finding(
                "web.cors-null-origin", "high" if null_probe[1] else "medium",
                "CORS allows the 'null' origin",
                url, target=target,
                evidence="Origin: null was echoed in Access-Control-Allow-Origin"
                + (" with credentials" if null_probe[1] else ""),
                recommendation="Do not allow the 'null' origin; sandboxed iframes and some redirects can force it.",
            )
        )

    return findings


# --- Passive: server error / stack trace disclosure ---------------------------

_STACKTRACE_RE = re.compile(
    r"Traceback \(most recent call last\)"                       # Python
    r"|Werkzeug Debugger|The debugger caught an exception"       # Flask/Werkzeug
    r"|\bat [\w.$]+\([\w.$]+\.java:\d+\)"                        # Java stack frame
    r"|\borg\.springframework\.\w"                               # Spring
    r"|(?:Fatal error|Parse error|Uncaught \w+): .+ in .+ on line \d+"  # PHP
    r"|Stack trace:\s*#0\s"                                       # PHP stack trace
    r"|ActionController::\w+Error"                               # Rails
    r"|\bat [\w.<>]+ \([^)\n]*\.js:\d+:\d+\)"                    # Node
    r"|System\.\w+(?:\.\w+)*Exception"                          # .NET
    r"|Server Error in '.+?' Application",                       # ASP.NET
    re.IGNORECASE,
)


def _error_disclosure(url: str, text: str, target: str) -> list[Finding]:
    """Passive: a framework stack trace / debug page or a raw DB error in the body."""
    if _STACKTRACE_RE.search(text):
        return [
            _finding(
                "web.error-stack-trace", "medium",
                "Server error or stack trace exposed in the response",
                url, target=target,
                evidence="A framework stack trace / debug error page was returned to the client.",
                recommendation="Disable debug mode in production; return generic error pages and log details server-side only.",
            )
        ]
    if _SQL_ERROR_RE.search(text):
        return [
            _finding(
                "web.database-error-disclosure", "medium",
                "Database error message exposed in the response",
                url, target=target,
                evidence="A database engine error string was present in the response body.",
                recommendation="Catch database errors and return a generic message; never surface raw DB errors to clients.",
            )
        ]
    return []


# --- Passive: JWT misconfiguration (server-issued cookies) --------------------

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")


def _decode_jwt_json(segment: str) -> object | None:
    try:
        return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except (ValueError, TypeError):
        return None


def _jwt_findings(url: str, set_cookies: Sequence[str], target: str) -> list[Finding]:
    """Passive: decode JWTs the server sets in cookies; flag 'alg: none' and no expiry."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for raw in set_cookies or ():
        for token in _JWT_RE.findall(raw):
            if token in seen:
                continue
            seen.add(token)
            parts = token.split(".")
            header = _decode_jwt_json(parts[0])
            if not isinstance(header, dict):
                continue
            if str(header.get("alg", "")).lower() == "none":
                findings.append(
                    _finding(
                        "web.jwt-alg-none", "high",
                        "JWT issued with 'alg: none' (unsigned tokens accepted)",
                        url, target=target,
                        evidence="A Set-Cookie JWT header declared alg=none.",
                        recommendation="Reject 'none'; require a strong signing algorithm (RS256/ES256) and verify signatures server-side.",
                    )
                )
                continue
            payload = _decode_jwt_json(parts[1])
            if isinstance(payload, dict) and "exp" not in payload:
                findings.append(
                    _finding(
                        "web.jwt-missing-expiry", "low",
                        "JWT in a cookie has no expiry ('exp') claim",
                        url, target=target,
                        evidence="A Set-Cookie JWT payload had no 'exp' claim.",
                        recommendation="Set a short 'exp' so a leaked or stolen token expires.",
                    )
                )
    return findings


# --- Per-host active probes: HTTP methods and Host-header injection ------------

_DANGEROUS_METHODS = frozenset({"PUT", "DELETE", "PATCH", "CONNECT"})
_HOST_PROBE = "koda-host-probe.example"


def _http_methods_probe(
    url: str, opener: urllib.request.OpenerDirector, headers: Mapping[str, str], timeout: float, target: str
) -> list[Finding]:
    """OPTIONS once per host: flag TRACE (cross-site tracing) and advertised write methods."""
    request = urllib.request.Request(url, headers=_without_credentials(headers), method="OPTIONS")
    try:
        with opener.open(request, timeout=timeout) as response:
            allow = response.headers.get("Allow", "")
    except urllib.error.HTTPError as exc:
        allow = exc.headers.get("Allow", "") if exc.headers else ""
        exc.close()
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError):
        return []
    methods = {method.strip().upper() for method in allow.split(",") if method.strip()}
    if not methods:
        return []
    findings: list[Finding] = []
    if "TRACE" in methods:
        findings.append(
            _finding(
                "web.http-trace-enabled", "medium",
                "HTTP TRACE method is enabled (cross-site tracing risk)",
                url, target=target, evidence=f"OPTIONS Allow: {allow}",
                recommendation="Disable the TRACE method at the web server or proxy.",
            )
        )
    if methods & _DANGEROUS_METHODS:
        findings.append(
            _finding(
                "web.http-methods-exposed", "low",
                "Server advertises state-changing HTTP methods",
                url, target=target, evidence=f"OPTIONS Allow: {allow}",
                recommendation="Restrict each endpoint to the methods it needs; block PUT/DELETE/PATCH/CONNECT where unused.",
            )
        )
    return findings


def _host_header_probe(
    url: str,
    headers: Mapping[str, str],
    timeout: float,
    target: str,
    *,
    opener: urllib.request.OpenerDirector | None = None,
) -> list[Finding]:
    """Send a spoofed Host header (once per host); flag when the app reflects it into
    a redirect Location or the body (cache / password-reset poisoning risk)."""
    opener = opener or urllib.request.build_opener(_NoRedirect())
    request = urllib.request.Request(url, headers={**_without_credentials(headers), "Host": _HOST_PROBE}, method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            location = response.headers.get("Location", "")
            body = _read_bounded_body(response, 4096, timeout).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        location = exc.headers.get("Location", "") if exc.headers else ""
        try:
            body = _read_bounded_body(exc, 4096, timeout).decode("utf-8", "replace")
        except Exception:
            body = ""
        finally:
            exc.close()
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError):
        return []
    if _HOST_PROBE in location or _HOST_PROBE in body:
        where = "redirect Location" if _HOST_PROBE in location else "response body"
        return [
            _finding(
                "web.host-header-injection", "medium",
                "Application reflects an attacker-controlled Host header",
                url, target=target,
                evidence=f"Host: {_HOST_PROBE} was reflected in the {where}.",
                recommendation="Validate Host against an allow-list; build absolute URLs from a fixed, trusted host.",
            )
        ]
    return []


def _certificate_expiry(url: str, cert: Mapping[str, object] | None, target: str) -> list[Finding]:
    if not cert:
        # Verified connection but no cert detail (rare); nothing actionable to report.
        return []
    not_after = cert.get("notAfter")
    if not isinstance(not_after, str):
        return []
    try:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
    except ValueError:
        return []
    days_left = (expires - datetime.now(timezone.utc)).days
    if days_left < 0:
        return [
            _finding(
                "web.tls-certificate-expired",
                "critical",
                "TLS certificate has expired",
                url,
                target=target,
                evidence=f"notAfter: {not_after}",
                recommendation="Renew and deploy a valid certificate immediately.",
            )
        ]
    if days_left <= _CERT_EXPIRY_WARN_DAYS:
        return [
            _finding(
                "web.tls-certificate-expiring",
                "medium",
                f"TLS certificate expires in {days_left} day(s)",
                url,
                target=target,
                evidence=f"notAfter: {not_after}",
                recommendation="Renew the certificate before it expires and automate renewal.",
            )
        ]
    return []


def _lower_headers(headers: Mapping[str, str] | Iterable[tuple[str, str]]) -> dict[str, str]:
    items = headers.items() if isinstance(headers, Mapping) else headers
    lowered: dict[str, str] = {}
    for name, value in items:
        key = name.lower()
        # Preserve the first value; join duplicates so evidence stays informative.
        lowered[key] = f"{lowered[key]}, {value}" if key in lowered else value
    return lowered


# --- crawling / auth helpers ------------------------------------------------


def _fetch(
    opener: urllib.request.OpenerDirector,
    url: str,
    headers: Mapping[str, str],
    timeout: float,
    allowed_origins: set[str],
    *,
    network_context: object | None = None,
) -> tuple[str, int, str, list[tuple[str, str]], list[str], bytes] | None:
    current_url = url
    current_headers = dict(headers)
    current_opener = opener
    max_redirects = 5
    if network_context is not None:
        max_redirects = int(getattr(network_context, "limits", {}).get("redirects", max_redirects))
    for _ in range(max_redirects + 1):
        request = urllib.request.Request(current_url, headers=current_headers, method="GET")
        try:
            if network_context is not None:
                network_context.authorize_url(current_url, method="GET", reserve=False)
                request_timeout = min(float(timeout), float(network_context.remaining_timeout()))
                if request_timeout <= 0:
                    return None
            else:
                request_timeout = timeout
            with current_opener.open(request, timeout=request_timeout) as response:
                header_items = list(response.headers.items())
                set_cookies = response.headers.get_all("Set-Cookie") or []
                return response.geturl(), response.status, response.headers.get("Content-Type") or "", header_items, set_cookies, _read_safe_body(response, _response_limit(current_opener), request_timeout)
        except urllib.error.HTTPError as exc:
            header_items = list(exc.headers.items()) if exc.headers else []
            set_cookies = exc.headers.get_all("Set-Cookie") if exc.headers else []
            content_type = exc.headers.get("Content-Type") if exc.headers else ""
            location = exc.headers.get("Location") if exc.headers else None
            if 300 <= exc.code < 400 and location:
                next_url = urllib.parse.urljoin(current_url, location)
                if not _is_allowed_origin(next_url, allowed_origins):
                    exc.close()
                    return next_url, exc.code, content_type or "", header_items, set_cookies, b""
                if _origin(next_url) != _origin(url):
                    current_headers = _without_credentials(current_headers)
                exc.close()
                current_url = next_url
                continue
            final_url = exc.geturl() if hasattr(exc, "geturl") else current_url
            status = exc.code
            try:
                body = _read_safe_body(exc, _response_limit(current_opener), request_timeout)
            except (socket.timeout, OSError):
                return None
            finally:
                exc.close()
            return final_url, status, content_type or "", header_items, set_cookies, body
        except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError):
            return None
    return current_url, 0, "", [], [], b""


def _response_limit(opener: urllib.request.OpenerDirector) -> int:
    for handler in getattr(opener, "handlers", ()):
        network = getattr(handler, "network", None)
        limits = getattr(network, "limits", None)
        if isinstance(limits, Mapping) and "max_response_bytes" in limits:
            try:
                return max(1, int(limits["max_response_bytes"]))
            except (TypeError, ValueError):
                break
    return _MAX_BODY_BYTES


def _read_safe_body(response, max_bytes: int = _MAX_BODY_BYTES, timeout: float = 15.0) -> bytes:
    content_type = (response.headers.get("Content-Type") or "").lower()
    if "html" not in content_type and not content_type.startswith("text/"):
        return b""
    return _read_bounded_body(response, max_bytes, timeout)


def _read_bounded_body(response, max_bytes: int, timeout: float) -> bytes:
    deadline = time.monotonic() + max(0.01, timeout)
    read = getattr(response, "read1", response.read)
    chunks: list[bytes] = []
    remaining = max_bytes
    while remaining > 0:
        if time.monotonic() >= deadline:
            raise socket.timeout("response body read exceeded the time budget")
        try:
            chunk = read(min(65_536, remaining))
        except (socket.timeout, OSError) as exc:
            raise socket.timeout("response body read exceeded the time budget") from exc
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    if remaining == 0:
        if time.monotonic() >= deadline:
            raise socket.timeout("response body read exceeded the time budget")
        try:
            extra = read(1)
        except (socket.timeout, OSError) as exc:
            raise socket.timeout("response body read exceeded the time budget") from exc
        if extra:
            raise ResponseBodyLimitError(f"response body exceeds the {max_bytes}-byte inspection limit")
    return b"".join(chunks)


def _without_credentials(headers: Mapping[str, str]) -> dict[str, str]:
    return {name: value for name, value in headers.items() if name.lower() not in {"authorization", "cookie", "proxy-authorization"}}


def _page_result(
    requested_url: str,
    final_url: str,
    status: int,
    content_type: str,
    same_host: bool,
    auth_state: str,
    active_checks_executed: bool,
    skip_reason: str,
    checks_executed: list[str] | None = None,
) -> dict[str, object]:
    return {
        "requested_url": requested_url,
        "final_url": final_url,
        "status": status,
        "content_type": content_type,
        "redirected": _canonical(requested_url) != _canonical(final_url),
        "same_host": same_host,
        "auth_state": auth_state,
        "checks_executed": checks_executed or [],
        "active_checks_executed": active_checks_executed,
        "skip_reason": skip_reason,
    }


def _ensure_bundled_browsers_path() -> None:
    """Point Playwright at a browser bundled with the install, if one ships.

    The Windows/Linux installers place the Chromium build under an
    ``ms-playwright`` folder so rendering works offline without a separate
    ``playwright install``. An explicit ``PLAYWRIGHT_BROWSERS_PATH`` always wins;
    otherwise use the first bundled folder found next to the frozen executable or
    the installed package tree.
    """

    if os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        return
    candidates: list[str] = []
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
        candidates.append(os.path.join(base, "ms-playwright"))
    # .../<app_root>/security_scanner/web.py -> app_root, and its parent (install prefix).
    app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates.append(os.path.join(app_root, "ms-playwright"))
    candidates.append(os.path.join(os.path.dirname(app_root), "ms-playwright"))
    for path in candidates:
        if os.path.isdir(path):
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = path
            return


# Injected before interaction (D): record every route the SPA router pushes so
# clicks that navigate via history.pushState are captured without leaving the page.
_ROUTE_HOOK_JS = """
window.__koda_routes = [];
for (const fn of ['pushState', 'replaceState']) {
  const orig = history[fn];
  history[fn] = function(state, title, url) {
    try { if (url) window.__koda_routes.push(new URL(url, location.href).href); } catch (e) {}
    return orig.apply(this, arguments);
  };
}
"""


def _render_page(
    url: str,
    *,
    timeout: float,
    extra_headers: Mapping[str, str] | None = None,
    capture_network: bool = False,
    interact: bool = False,
    max_clicks: int = 20,
    cookies: Sequence[dict[str, object]] = (),
    network_context: object | None = None,
) -> tuple[str | None, set[str], list[dict[str, object]], str]:
    """Render ``url`` in headless Chromium; return ``(html, extra_urls, cookies, error)``.

    ``cookies`` (Playwright cookie dicts) seed the browser context so a form-login
    session held in the crawl's cookie jar is carried into rendering; the browser's
    cookies after rendering are returned so the caller can sync back any the SPA
    rotated. ``extra_urls`` holds URLs discovered beyond the DOM anchors: same-origin
    requests the page made (``capture_network``) and routes reached by clicking
    bounded candidate elements (``interact``). Returns ``(None, set(), [], message)``
    when Playwright is unavailable or rendering fails, so the caller falls back to
    stdlib extraction.
    """

    _ensure_bundled_browsers_path()
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None, set(), [], (
            "JS 렌더링 크롤을 건너뜁니다: Playwright 미설치. "
            "설치: pip install \"local-security-scanner[render]\" && python -m playwright install chromium"
        )

    headers = {k: v for k, v in (extra_headers or {}).items() if k.lower() != "user-agent"}
    captured: set[str] = set()
    try:
        with sync_playwright() as p:
            launch_options = network_context.browser_launch_options() if network_context is not None else {"headless": True}
            browser = p.chromium.launch(**launch_options)
            try:
                context_options = network_context.browser_context_options() if network_context is not None else {}
                context = browser.new_context(user_agent=_USER_AGENT, **context_options)
                if cookies:
                    try:
                        context.add_cookies(list(cookies))
                    except Exception:
                        pass  # malformed cookie must never abort rendering
                if headers:
                    context.set_extra_http_headers(headers)
                page = context.new_page()
                invalid_response = False
                invalid_request = False

                def validate_request(route) -> None:
                    nonlocal invalid_request
                    request = route.request
                    if network_context is not None and request.url.startswith(("http://", "https://")):
                        try:
                            network_context.authorize_url(request.url, method=request.method)
                        except Exception:
                            invalid_request = True
                            try:
                                route.abort()
                            except Exception:
                                pass
                            return
                    try:
                        route.continue_()
                    except Exception:
                        invalid_request = True

                def validate_response(response) -> None:
                    nonlocal invalid_response
                    if network_context is not None and response.url.startswith(("http://", "https://")):
                        if not network_context.validate_browser_response(response):
                            invalid_response = True

                if network_context is not None:
                    page.route("**/*", validate_request)
                    page.on("response", validate_response)
                if capture_network:
                    page.on("request", lambda req: captured.add(req.url))
                if interact:
                    page.add_init_script(_ROUTE_HOOK_JS)
                render_timeout = float(timeout)
                if network_context is not None:
                    render_timeout = min(render_timeout, float(network_context.remaining_timeout()))
                if render_timeout <= 0:
                    return None, set(), [], "JS 렌더링을 건너뜁니다: 웹 점검 시간 제한을 초과했습니다."
                page.goto(url, wait_until="networkidle", timeout=render_timeout * 1000)
                if invalid_request:
                    return None, set(), [], "JS 렌더링을 건너뜁니다: 브라우저 요청이 승인된 origin/path/메서드 범위를 벗어났습니다."
                if invalid_response:
                    return None, set(), [], "JS 렌더링을 건너뜁니다: 브라우저 응답의 승인 IP를 검증하지 못했습니다."
                html = page.content()
                if interact:
                    captured.update(_interact_page(page, max_clicks))
                try:
                    browser_cookies = list(context.cookies())
                except Exception:
                    browser_cookies = []
                return html, captured, browser_cookies, ""
            finally:
                browser.close()
    except PlaywrightError as exc:
        return None, set(), [], f"JS 렌더링 실패 {url}: {exc}"
    except Exception as exc:  # defensive: rendering must never abort the scan
        return None, set(), [], f"JS 렌더링 오류 {url}: {exc}"


def _interact_page(page, max_clicks: int) -> set[str]:
    """D: click bounded candidate elements, collecting routes they navigate to.

    Best-effort and defensive — a single click that throws, opens a dialog, or
    navigates away never aborts the crawl. Records router pushes (via the init
    hook) and any full URL change, resetting back to the start page after a
    hard navigation so later candidates start from the same state.
    """

    found: set[str] = set()
    start = page.url
    try:
        elements = page.query_selector_all("a:not([href]), button, [role=button], [onclick]")
    except Exception:
        return found
    for element in elements[:max_clicks]:
        try:
            element.click(timeout=1000, no_wait_after=True)
            page.wait_for_timeout(150)
        except Exception:
            continue
        try:
            if page.url != start:
                found.add(page.url)
                page.go_back(wait_until="domcontentloaded", timeout=2000)
        except Exception:
            pass
    try:
        routes = page.evaluate("window.__koda_routes || []")
        found.update(routes)
    except Exception:
        pass
    return found


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = dict(attrs)
        if tag == "a" and data.get("href"):
            self.hrefs.append(data["href"])
        elif tag == "script" and data.get("src"):
            self.scripts.append(data["src"])


def _parse_html(base_url: str, body: bytes | str) -> _LinkParser | None:
    parser = _LinkParser()
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    try:
        parser.feed(text)
    except Exception:
        return None
    return parser


def _extract_links(base_url: str, body: bytes | str) -> set[str]:
    parser = _parse_html(base_url, body)
    if parser is None:
        return set()
    links: set[str] = set()
    for href in parser.hrefs:
        absolute = urllib.parse.urljoin(base_url, href)
        links.add(urllib.parse.urldefrag(absolute).url)
    return links


# Path-like string literals inside JS bundles (route tables, fetch() calls).
_ROUTE_LITERAL_RE = re.compile(r"""["'`](/[A-Za-z0-9][\w\-/\[\]]*)["'`]""")
# Segments that are framework/asset noise, not app routes/endpoints.
_ROUTE_NOISE_RE = re.compile(r"(^/_)|(/node_modules/)|(\.[A-Za-z0-9]{1,5}$)")


def _read_asset(
    opener: urllib.request.OpenerDirector,
    url: str,
    headers: Mapping[str, str],
    timeout: float,
) -> str | None:
    """Read a JS/text asset in full (not just HTML like ``_fetch``) for scraping."""
    request = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            return _read_bounded_body(response, _response_limit(opener), timeout).decode("utf-8", "replace")
    except (ResponseBodyLimitError, urllib.error.HTTPError, urllib.error.URLError, ssl.SSLError, socket.timeout, OSError):
        return None


def _scan_assets(
    page_url: str,
    body: bytes | str,
    opener: urllib.request.OpenerDirector,
    headers: Mapping[str, str],
    timeout: float,
    assets_seen: set[str],
    max_assets: int,
    target: str,
    *,
    extract_routes: bool,
    scan_secrets: bool,
) -> tuple[set[str], list[Finding], int, bool]:
    """Fetch same-host JS bundles once and mine them for routes (A) and secrets.

    Fetches each not-yet-seen same-host ``<script src>`` (bounded by
    ``max_assets`` across the whole crawl). ``extract_routes`` pulls quoted path
    literals (dropping framework/asset noise); ``scan_secrets`` runs the shared
    secret rules over the bundle text. Returns routes, findings, failed count,
    and whether the global asset limit left work unscanned.
    """

    parser = _parse_html(page_url, body)
    if parser is None:
        return set(), [], 0, False
    routes: set[str] = set()
    findings: list[Finding] = []
    failed_assets = 0
    limit_reached = False
    for src in parser.scripts:
        asset_url = urllib.parse.urldefrag(urllib.parse.urljoin(page_url, src)).url
        if not _same_host(page_url, asset_url) or asset_url in assets_seen:
            continue
        if len(assets_seen) >= max_assets:
            limit_reached = True
            break
        assets_seen.add(asset_url)
        text = _read_asset(opener, asset_url, headers, timeout)
        if text is None:
            failed_assets += 1
            continue
        if extract_routes:
            for path in _ROUTE_LITERAL_RE.findall(text):
                if path == "/" or _ROUTE_NOISE_RE.search(path):
                    continue
                routes.add(urllib.parse.urljoin(page_url, path))
        if scan_secrets:
            findings.extend(_scan_text_for_secrets(text, asset_url, target))
    return routes, findings, failed_assets, limit_reached


def _scan_text_for_secrets(text: str, asset_url: str, target: str) -> list[Finding]:
    """#1: run the shared secret rules over JS-bundle text; redacted, deduped."""
    from .checks.secrets import SECRET_RULES, _looks_like_placeholder, _redact_line

    findings: list[Finding] = []
    counts: dict[str, int] = {}
    for rule in SECRET_RULES:
        for match in rule.pattern.finditer(text):
            if counts.get(rule.rule_id, 0) >= 3:
                break
            secret = match.group(rule.secret_group)
            if _looks_like_placeholder(secret):
                continue
            snippet = text[max(0, match.start() - 24): match.end() + 24]
            findings.append(
                _finding(
                    f"web.js-{rule.rule_id}",
                    rule.severity,
                    f"Secret exposed in client JS: {rule.title}",
                    asset_url,
                    target=target,
                    evidence=_redact_line(snippet, secret),
                    recommendation="Remove the secret from client-side JavaScript and rotate it; keep secrets server-side.",
                )
            )
            counts[rule.rule_id] = counts.get(rule.rule_id, 0) + 1
    return findings


# --- #2: robots.txt / sitemap.xml ingestion --------------------------------


def _ingest_sitemaps(
    seed_url: str,
    opener: urllib.request.OpenerDirector,
    headers: Mapping[str, str],
    timeout: float,
) -> set[str]:
    """Read robots.txt + sitemap.xml from the seed origin; return listed URLs.

    robots.txt yields ``Sitemap:`` locations (followed, bounded) and same-host
    ``Disallow`` paths (worth scanning). sitemap.xml / sitemap-index ``<loc>``
    entries are collected. Best-effort; failures are ignored.
    """

    origin = _origin(seed_url)
    found: set[str] = set()
    sitemaps: list[str] = [urllib.parse.urljoin(origin, "/sitemap.xml")]

    robots = _read_asset(opener, urllib.parse.urljoin(origin, "/robots.txt"), headers, timeout)
    if robots:
        for line in robots.splitlines():
            key, _, value = line.partition(":")
            key, value = key.strip().lower(), value.strip()
            if key == "sitemap" and value:
                sitemaps.append(urllib.parse.urljoin(origin, value))
            elif key == "disallow" and value and value != "/":
                found.add(urllib.parse.urljoin(origin, value.split()[0]))

    seen_sitemaps: set[str] = set()
    index = 0
    while index < len(sitemaps) and len(seen_sitemaps) < 10:
        sitemap_url = sitemaps[index]
        index += 1
        if sitemap_url in seen_sitemaps:
            continue
        seen_sitemaps.add(sitemap_url)
        xml = _read_asset(opener, sitemap_url, headers, timeout)
        if not xml:
            continue
        for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", xml):
            absolute = urllib.parse.urljoin(origin, loc.strip())
            if absolute.endswith(".xml"):
                sitemaps.append(absolute)  # sitemap index -> nested sitemap
            else:
                found.add(absolute)
    return found


# --- #3: sensitive-path probing --------------------------------------------

_SENSITIVE_PATHS: tuple[tuple[str, str, str], ...] = (
    # (path, severity, signature the body must contain to count as a real hit)
    ("/.env", "high", "="),
    ("/.git/config", "high", "[core]"),
    ("/.git/HEAD", "high", "ref:"),
    ("/.svn/entries", "high", "dir"),
    ("/.aws/credentials", "high", "aws_access_key_id"),
    ("/.npmrc", "high", "_authtoken"),
    ("/openapi.json", "medium", "openapi"),
    ("/swagger.json", "medium", "swagger"),
    ("/actuator", "medium", "_links"),
    ("/actuator/env", "high", "propertysources"),
    ("/actuator/health", "low", "status"),
    ("/server-status", "medium", "apache server status"),
    ("/phpinfo.php", "medium", "phpinfo"),
    ("/.well-known/security.txt", "info", "contact"),
    ("/.DS_Store", "low", "Bud1"),
    ("/config.json", "low", "{"),
)


def _probe_sensitive_paths(
    seed_url: str,
    opener: urllib.request.OpenerDirector,
    headers: Mapping[str, str],
    timeout: float,
    target: str,
) -> list[Finding]:
    """Probe well-known sensitive paths, guarding against SPA catch-all 200s.

    Fetches a random nonexistent path first as a baseline; a path only counts as
    exposed when it returns 200, differs from that baseline (or the host 404s
    unknown paths), and its body carries the expected signature.
    """

    origin = _origin(seed_url)
    baseline = _fetch_meta(opener, urllib.parse.urljoin(origin, f"/koda-probe-{int(time.time())}-nope"), headers, timeout)
    baseline_is_catch_all = baseline is not None and baseline[0] == 200

    findings: list[Finding] = []
    for path, severity, signature in _SENSITIVE_PATHS:
        meta = _fetch_meta(opener, urllib.parse.urljoin(origin, path), headers, timeout)
        if meta is None or meta[0] != 200:
            continue
        status, body = meta
        # On SPA catch-all hosts, only trust a hit whose body carries the signature
        # (and isn't just the same HTML shell the baseline returned).
        if baseline_is_catch_all and (signature.lower() not in body.lower() or body == baseline[1]):
            continue
        if signature and signature.lower() not in body.lower():
            continue
        findings.append(
            _finding(
                "web.sensitive-path-exposed",
                severity,
                f"Sensitive path is publicly accessible: {path}",
                urllib.parse.urljoin(origin, path),
                target=target,
                evidence=f"GET {path} returned {status} with expected content.",
                recommendation="Block public access to this path (deny rule / auth) and remove it from the web root.",
            )
        )
    return findings


_GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql")
_GRAPHQL_INTROSPECTION = b'{"query":"{__schema{queryType{name}}}"}'


def _probe_graphql(
    seed_url: str,
    opener: urllib.request.OpenerDirector,
    headers: Mapping[str, str],
    timeout: float,
    target: str,
) -> list[Finding]:
    """Active check: POST an introspection query to common GraphQL endpoints."""
    origin = _origin(seed_url)
    findings: list[Finding] = []
    for path in _GRAPHQL_PATHS:
        url = urllib.parse.urljoin(origin, path)
        post_headers = {**dict(headers), "Content-Type": "application/json"}
        request = urllib.request.Request(url, data=_GRAPHQL_INTROSPECTION, headers=post_headers, method="POST")
        try:
            with opener.open(request, timeout=timeout) as response:
                body = _read_bounded_body(response, 8192, timeout).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            try:
                try:
                    body = _read_bounded_body(exc, 8192, timeout).decode("utf-8", "replace") if exc.fp else ""
                except (socket.timeout, OSError):
                    continue
            finally:
                exc.close()
        except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError):
            continue
        if '"__schema"' in body or ('"queryType"' in body and '"data"' in body):
            findings.append(
                _finding(
                    "web.graphql-introspection-enabled", "medium",
                    "GraphQL introspection is enabled", url, target=target,
                    evidence=f"POST {path} returned a populated __schema.",
                    recommendation="Disable introspection in production so the schema is not publicly enumerable.",
                )
            )
            break
    return findings


def _fetch_meta(
    opener: urllib.request.OpenerDirector,
    url: str,
    headers: Mapping[str, str],
    timeout: float,
) -> tuple[int, str] | None:
    """GET returning ``(status, body_prefix)`` for probe comparison."""
    request = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, _read_bounded_body(response, 4096, timeout).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, ""
        finally:
            exc.close()
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError):
        return None


def _origin(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


# --- Active verification (opt-in): sends bounded, non-destructive payloads -----

# DB error signatures used for error-based SQL injection detection.
_SQL_ERROR_RE = re.compile(
    r"(SQL syntax|mysql_fetch|valid MySQL result|ORA-\d{5}|Oracle error|"
    r"PostgreSQL.*ERROR|PG::SyntaxError|SQLite/JDBC|SQLite3::|"
    r"Unclosed quotation mark|quoted string not properly terminated|"
    r"Microsoft OLE DB Provider|ODBC SQL Server Driver|syntax error at or near)",
    re.IGNORECASE,
)
_REDIRECT_PARAM_NAMES = {
    "redirect", "redirect_uri", "redirecturl", "url", "next", "return", "returnurl",
    "returnto", "return_to", "dest", "destination", "continue", "redir", "goto", "u", "r",
}
_ACTIVE_OOB_HOST = "koda-open-redirect.example"
# System-file signatures for path-traversal / LFI: /etc/passwd and win.ini.
_LFI_RE = re.compile(r"root:.*?:0:0:|\bfor 16-bit app support\b", re.IGNORECASE)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stops urllib from following redirects so open-redirect can be observed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401,N802
        return None


def active_probe(
    url: str,
    opener: urllib.request.OpenerDirector,
    headers: Mapping[str, str],
    timeout: float,
    target: str,
    *,
    max_params: int = 15,
) -> list[Finding]:
    """Send bounded, non-destructive attack payloads to a URL's query params.

    Verifies (not just guesses) reflected XSS, error-based SQL injection, and
    open redirect by observing the server's response. GET-only, no data-changing
    requests, capped per parameter. Opt-in and authorization-gated by the caller;
    comprehensive active scanning belongs to the ZAP full/api modes.
    """

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    findings: list[Finding] = []
    token = secrets.token_hex(4)
    # The caller's opener is already policy-bound and configured not to follow
    # redirects.  Creating a fresh opener here would bypass NetworkContext.
    no_redirect_opener = opener
    for name in list(params)[:max_params]:
        original = params[name][0] if params[name] else ""

        # Reflected XSS: a unique marker with HTML-significant chars reflected raw.
        # No single quote, so it does not collide with the SQL-quote probe below.
        marker = f"koda{token}\"><kdx>"
        body = _probe_body(opener, _with_query_param(parsed, name, marker), headers, timeout)
        if body and marker in body:
            findings.append(
                _finding(
                    "web.reflected-xss-verified", "medium",
                    "Unencoded reflected input detected; XSS context review required",
                    url, target=target,
                    evidence=f"param '{name}': marker reflected without encoding ({marker})",
                    recommendation="Context-encode all user input on output and add a strict CSP.",
                )
            )

        # Error-based SQL injection: a single quote provokes a DB error the
        # unmodified request did not.
        injected = _probe_body(opener, _with_query_param(parsed, name, original + "'"), headers, timeout)
        if injected and _SQL_ERROR_RE.search(injected):
            baseline = _probe_body(opener, _with_query_param(parsed, name, original), headers, timeout)
            if not (baseline and _SQL_ERROR_RE.search(baseline)):
                findings.append(
                    _finding(
                        "web.sql-injection-error-verified", "high",
                        "Input change triggers a database error; SQL injection is likely",
                        url, target=target,
                        evidence=f"param '{name}': SQL error signature appeared only with a trailing quote",
                        recommendation="Use parameterized queries / prepared statements; never build SQL from raw input.",
                    )
                )

        # Path traversal / LFI: a traversal payload returns a known system file.
        lfi_body = _probe_body(
            opener, _with_query_param(parsed, name, "../../../../../../../../etc/passwd"), headers, timeout
        )
        if lfi_body and _LFI_RE.search(lfi_body):
            findings.append(
                _finding(
                    "web.path-traversal-lfi", "high",
                    "Path traversal / local file inclusion (system file contents returned)",
                    url, target=target,
                    evidence=f"param '{name}': a directory-traversal payload returned system file content",
                    recommendation="Never build filesystem paths from user input; use an allow-list of identifiers and canonicalize before use.",
                )
            )

        # Open redirect: a redirect-like param that sends the browser off-site.
        if name.lower() in _REDIRECT_PARAM_NAMES:
            location = _probe_location(
                no_redirect_opener, _with_query_param(parsed, name, f"https://{_ACTIVE_OOB_HOST}/"), headers, timeout
            )
            if location and _ACTIVE_OOB_HOST in location:
                findings.append(
                    _finding(
                        "web.open-redirect-verified", "medium",
                        "Redirect parameter sends users to an external site (verified open redirect)",
                        url, target=target,
                        evidence=f"param '{name}' -> Location: {location}",
                        recommendation="Allow only relative paths or an allow-list of destinations for redirect parameters.",
                    )
                )
    return findings


class _FormsParser(HTMLParser):
    """Collect every <form>: action, method, and its input fields."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, object]] = []
        self._form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self._form = {"action": data.get("action", ""), "method": data.get("method", "get").lower(),
                          "fields": {}, "has_password": False, "has_file": False}
        elif tag in {"input", "textarea", "select"} and self._form is not None:
            itype = data.get("type", "text").lower()
            name = data.get("name", "")
            if itype == "password":
                self._form["has_password"] = True
            if itype == "file":
                self._form["has_file"] = True
            if name and itype not in {"submit", "button", "image", "reset", "file"}:
                self._form["fields"][name] = (itype, data.get("value", ""))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def form_active_probe(
    page_url: str,
    body: bytes | str,
    opener: urllib.request.OpenerDirector,
    headers: Mapping[str, str],
    timeout: float,
    target: str,
    *,
    max_forms: int = 5,
    max_fields: int = 10,
) -> list[Finding]:
    """Active verification of HTML form fields (GET and POST), mirroring the
    query-param checks. Skips login/register (password) and file-upload forms to
    avoid credential submission and uploads. Opt-in, capped, non-destructive-ish."""

    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    parser = _FormsParser()
    try:
        parser.feed(text)
    except Exception:
        return []

    findings: list[Finding] = []
    token = secrets.token_hex(4)
    for form in parser.forms[:max_forms]:
        if form["has_password"] or form["has_file"]:
            continue  # avoid submitting credentials or uploading files
        fields: dict[str, tuple[str, str]] = form["fields"]  # type: ignore[assignment]
        if not fields:
            continue
        method = "post" if form["method"] == "post" else "get"
        action_url = urllib.parse.urljoin(page_url, str(form["action"])) if form["action"] else page_url
        base = {name: (value or "test") for name, (_type, value) in fields.items()}
        # Only fuzz visible-ish fields (not hidden tokens) to limit noise.
        testable = [name for name, (itype, _v) in fields.items() if itype in {"text", "search", "email", "url", "", "textarea"}]

        for name in testable[:max_fields]:
            marker = f"koda{token}\"><kdx>"
            body_x = _submit_form(opener, action_url, method, {**base, name: marker}, headers, timeout)
            if body_x and marker in body_x:
                findings.append(
                    _finding(
                        "web.reflected-xss-verified", "medium",
                        "Unencoded reflected input detected; XSS context review required",
                        action_url, target=target,
                        evidence=f"form field '{name}' ({method.upper()}) reflected the marker unencoded",
                        recommendation="Context-encode all user input on output and add a strict CSP.",
                    )
                )
            body_s = _submit_form(opener, action_url, method, {**base, name: base[name] + "'"}, headers, timeout)
            if body_s and _SQL_ERROR_RE.search(body_s):
                baseline = _submit_form(opener, action_url, method, base, headers, timeout)
                if not (baseline and _SQL_ERROR_RE.search(baseline)):
                    findings.append(
                        _finding(
                            "web.sql-injection-error-verified", "high",
                            "Input change triggers a database error; SQL injection is likely",
                            action_url, target=target,
                            evidence=f"form field '{name}' ({method.upper()}) produced a SQL error only with a trailing quote",
                            recommendation="Use parameterized queries / prepared statements; never build SQL from raw input.",
                        )
                    )
    return findings


def _submit_form(
    opener: urllib.request.OpenerDirector, action_url: str, method: str,
    fields: Mapping[str, str], headers: Mapping[str, str], timeout: float,
) -> str | None:
    encoded = urllib.parse.urlencode(fields)
    if method == "post":
        request = urllib.request.Request(
            action_url, data=encoded.encode("utf-8"),
            headers={**dict(headers), "Content-Type": "application/x-www-form-urlencoded"}, method="POST",
        )
    else:
        sep = "&" if urllib.parse.urlparse(action_url).query else "?"
        request = urllib.request.Request(action_url + sep + encoded, headers=dict(headers), method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            return _read_bounded_body(response, _response_limit(opener), timeout).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            return _read_bounded_body(exc, _response_limit(opener), timeout).decode("utf-8", "replace")
        except Exception:
            return None
        finally:
            exc.close()
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError):
        return None


def _with_query_param(parsed: urllib.parse.ParseResult, name: str, value: str) -> str:
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query[name] = [value]
    new_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _probe_body(
    opener: urllib.request.OpenerDirector, url: str, headers: Mapping[str, str], timeout: float
) -> str | None:
    request = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            return _read_bounded_body(response, _response_limit(opener), timeout).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        # A 500 with a SQL error in the body is exactly what we want to inspect.
        try:
            return _read_bounded_body(exc, _response_limit(opener), timeout).decode("utf-8", "replace")
        except Exception:
            return None
        finally:
            exc.close()
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError):
        return None


def _probe_location(
    opener: urllib.request.OpenerDirector, url: str, headers: Mapping[str, str], timeout: float
) -> str | None:
    request = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.headers.get("Location")
    except urllib.error.HTTPError as exc:
        try:
            return exc.headers.get("Location") if exc.headers else None
        finally:
            exc.close()
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError):
        return None


# --- Access-control comparison (IDOR/BOLA/BFLA heuristic) ----------------------


def _access_control_check(
    url: str,
    opener: urllib.request.OpenerDirector,
    headers: Mapping[str, str],
    timeout: float,
    target: str,
    *,
    compare_unauth: bool,
    secondary_headers: Mapping[str, str] | None,
    network_context: object | None = None,
) -> list[Finding]:
    """Compare an authenticated response against lower-privileged contexts.

    If an unauthenticated request, or a second account, receives content similar
    to the primary (authenticated) response, access control may be broken.
    Heuristic and non-destructive (GET only); findings are flagged for review.
    """

    primary = _fetch_meta(opener, url, headers, timeout)
    if not primary or primary[0] != 200 or _looks_like_login(primary[1]):
        return []  # only meaningful when the authenticated context truly has access

    findings: list[Finding] = []
    base_headers = {k: v for k, v in headers.items() if k.lower() != "cookie"}

    if compare_unauth:
        unauth_opener = network_context.build_opener() if network_context is not None else urllib.request.build_opener()
        meta = _fetch_meta(unauth_opener, url, base_headers, timeout)
        if meta and meta[0] == 200 and not _looks_like_login(meta[1]) and _responses_equivalent(primary[1], meta[1]):
            findings.append(
                _finding(
                    "web.broken-access-control-unauth", "medium",
                    "Authenticated content is also served without authentication (review)",
                    url, target=target,
                    evidence="authenticated and unauthenticated GET both returned 200 with structurally equivalent content",
                    recommendation="Require authentication/authorization server-side for this resource; verify it is not meant to be public.",
                )
            )

    if secondary_headers:
        secondary_opener = network_context.build_opener() if network_context is not None else urllib.request.build_opener()
        meta = _fetch_meta(secondary_opener, url, {**base_headers, **secondary_headers}, timeout)
        if meta and meta[0] == 200 and not _looks_like_login(meta[1]) and _responses_equivalent(primary[1], meta[1]):
            findings.append(
                _finding(
                    "web.broken-access-control-cross-account", "high",
                    "A second account receives the first account's content (possible IDOR/BOLA, review)",
                    url, target=target,
                    evidence="the secondary account's GET returned 200 with content structurally equivalent to the primary account",
                    recommendation="Enforce per-object and per-function authorization so one user cannot read another's resource.",
                )
            )
    return findings


def _looks_like_login(body: str) -> bool:
    lowered = body.lower()
    if 'type="password"' in lowered or "type='password'" in lowered:
        return True
    return ("login" in lowered or "sign in" in lowered or "로그인" in body) and "<form" in lowered


# Keys and tokens that legitimately differ between two requests for the SAME
# data (per-request CSRF, session, and time values); stripped before comparison
# so they neither hide a real access-control match nor fabricate a false one.
_VOLATILE_JSON_KEY_RE = re.compile(r"csrf|xsrf|token|nonce|session|request[_-]?id|trace|timestamp|_at$|_time$", re.IGNORECASE)
_HTML_VOLATILE_RE = re.compile(
    r"""(?ix)
    <input[^>]*\b(?:csrf|xsrf|token|nonce|authenticity)[^>]*> # CSRF hidden fields
    | \b[A-Fa-f0-9]{24,}\b                                    # long hex tokens
    | \b[A-Za-z0-9+/_-]{32,}={0,2}\b                          # long base64-ish tokens
    | \d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}(?::\d{2})?             # ISO timestamps
    """
)


def _strip_volatile_json(node: object) -> object:
    if isinstance(node, dict):
        return {k: _strip_volatile_json(v) for k, v in node.items() if not _VOLATILE_JSON_KEY_RE.search(k)}
    if isinstance(node, list):
        return [_strip_volatile_json(item) for item in node]
    return node


def _canonical_json(text: str) -> str | None:
    """Canonical JSON (sorted keys, volatile keys dropped) or ``None`` if not JSON."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, (dict, list)):
        return None
    return json.dumps(_strip_volatile_json(data), sort_keys=True, separators=(",", ":"))


def _normalize_body(text: str) -> str:
    """Lower-cased, whitespace-collapsed text with volatile tokens removed."""
    return re.sub(r"\s+", " ", _HTML_VOLATILE_RE.sub("", text)).strip().lower()


def _responses_equivalent(a: str, b: str, threshold: float = 0.90) -> bool:
    """Structural/content equivalence of two responses for access-control checks.

    Stronger than a raw length ratio: JSON is compared by canonical keys+values
    (volatile keys dropped), other bodies by normalized-content similarity after
    removing CSRF tokens, nonces, and timestamps. This cuts both false positives
    (two different-content pages of similar size) and false negatives (identical
    data whose per-request token shifts the length).
    """
    if not a or not b:
        return a == b
    na = _canonical_json(a) or _normalize_body(a)
    nb = _canonical_json(b) or _normalize_body(b)
    if not na or not nb:
        return na == nb
    if na == nb:
        return True
    return difflib.SequenceMatcher(None, na, nb).ratio() >= threshold


def _same_host(seed_url: str, candidate: str) -> bool:
    seed = urllib.parse.urlparse(seed_url)
    other = urllib.parse.urlparse(candidate)
    return other.scheme in {"http", "https"} and other.netloc == seed.netloc


def _is_allowed_origin(candidate: str, allowed_origins: set[str]) -> bool:
    return _origin(candidate) in allowed_origins


# Static assets carry the same per-host headers as pages, so scanning them adds
# noise and wasted requests (and rendering a font/image errors). Discover them,
# but keep them out of the scan frontier.
_STATIC_ASSET_RE = re.compile(
    r"\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|otf|eot|mp4|webm|pdf|zip|gz)(?:$|\?)",
    re.IGNORECASE,
)


def _is_static_asset(url: str) -> bool:
    return bool(_STATIC_ASSET_RE.search(urllib.parse.urlparse(url).path))


def _canonical(url: str) -> str:
    """Strip the fragment so ``/a`` and ``/a#x`` are not scanned twice."""
    return urllib.parse.urldefrag(url).url


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse repeats of the same rule to one representative.

    A missing-CSP header appears on every page; keep the first occurrence but
    record the actual affected URLs in the evidence (up to a cap) so remediation
    has the real list instead of just a page count.
    """

    seen: dict[tuple[str, str], Finding] = {}
    instances: dict[tuple[str, str], list[str]] = {}
    for finding in findings:
        key = (finding.rule_id, finding.target)
        seen.setdefault(key, finding)
        instances.setdefault(key, []).append(str(finding.path))

    result: list[Finding] = []
    for key, finding in seen.items():
        urls = list(dict.fromkeys(instances[key]))  # de-dup, preserve order
        if len(urls) > 1:
            shown = ", ".join(urls[:8])
            more = f" (+{len(urls) - 8} more)" if len(urls) > 8 else ""
            suffix = f"affected URLs: {shown}{more}"
            evidence = f"{finding.evidence}; {suffix}" if finding.evidence else suffix
            finding = replace(finding, evidence=evidence)
        result.append(finding)
    return result


def build_auth_opener() -> urllib.request.OpenerDirector:
    """Build a cookie-aware opener that keeps a form-login session across requests.

    A pasted browser ``Cookie`` header is applied separately via the crawl's
    ``extra_headers`` (see :func:`crawl_web`), so no login is needed to reuse an
    existing session.
    """

    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), _NoRedirect())


class _FormParser(HTMLParser):
    """Collect the first <form> plus its <input> name/value pairs."""

    def __init__(self) -> None:
        super().__init__()
        self.in_form = False
        self.done = False
        self.action = ""
        self.method = "get"
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {name: (value or "") for name, value in attrs}
        if tag == "form" and not self.done:
            self.in_form = True
            self.action = data.get("action", "")
            self.method = (data.get("method") or "get").lower()
        elif tag == "input" and self.in_form:
            name = data.get("name")
            if name:
                self.fields[name] = data.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self.in_form:
            self.in_form = False
            self.done = True


def login(
    opener: urllib.request.OpenerDirector,
    login_url: str,
    username: str,
    password: str,
    *,
    user_field: str | None = None,
    pass_field: str | None = None,
    request_url: str | None = None,
    extra_headers: Mapping[str, str] | None = None,
    timeout: float = 15.0,
    result: dict[str, object] | None = None,
) -> tuple[list[str], list[Finding]]:
    """Perform a best-effort form login, keeping the session in ``opener``'s jar.

    Parses the login form (preserving hidden/CSRF inputs), fills the username and
    password fields (auto-detected by name when not given), and POSTs to the
    form action. Also checks session management: if the session ID is unchanged
    after login, that is session fixation. Returns ``(warnings, findings)``;
    failures degrade to a warning so the scan proceeds unauthenticated.
    """

    warnings: list[str] = []
    if result is not None:
        result.update({
            "status": "uncertain",
            "login_url": login_url,
            "final_url": login_url,
            "session_cookie_received": False,
            "session_rotated": False,
            "message": "Login success could not yet be confirmed.",
        })
    target = urllib.parse.urlparse(login_url).netloc
    page_headers = {"User-Agent": _USER_AGENT, **dict(extra_headers or {})}
    request = urllib.request.Request(login_url, headers=page_headers)
    try:
        with opener.open(request, timeout=timeout) as response:
            page_url = response.geturl()
            body = _read_bounded_body(response, _response_limit(opener), timeout).decode("utf-8", "replace")
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError) as exc:
        if result is not None:
            result.update({"status": "failed", "message": "Login page could not be loaded."})
        return [f"Login page could not be loaded ({login_url}): {getattr(exc, 'reason', exc)}"], []

    parser = _FormParser()
    parser.feed(body)
    if not parser.done:
        if result is not None:
            result.update({"status": "failed", "message": "No login form was found."})
        return [f"No login form found at {login_url}; scanning unauthenticated."], []

    user_key = user_field or _match_field(parser.fields, _USER_FIELD_RE)
    pass_key = pass_field or _match_field(parser.fields, _PASS_FIELD_RE)
    if not user_key or not pass_key:
        if result is not None:
            result.update({"status": "failed", "message": "Login fields could not be identified."})
        return [f"Could not identify login fields at {login_url}; scanning unauthenticated."], []

    fields = dict(parser.fields)
    fields[user_key] = username
    fields[pass_key] = password
    action_url = request_url or (urllib.parse.urljoin(page_url, parser.action) if parser.action else page_url)
    cookies_before = _cookie_count(opener)
    sessions_before = _session_cookie_values(opener)

    data = urllib.parse.urlencode(fields).encode("utf-8")
    post_headers = {
        **page_headers,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    post = urllib.request.Request(
        action_url,
        data=data,
        headers=post_headers,
        method="POST",
    )
    try:
        with opener.open(post, timeout=timeout) as response:
            final_url = response.geturl()
            response_body = _read_safe_body(response, _response_limit(opener), timeout).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        final_url = exc.geturl() if hasattr(exc, "geturl") else action_url
        try:
            try:
                response_body = _read_safe_body(exc, _response_limit(opener), timeout).decode("utf-8", "replace")
            except (socket.timeout, OSError) as read_error:
                if result is not None:
                    result.update({"status": "failed", "message": "Login response timed out."})
                return [f"Login response timed out ({action_url}): {read_error}"], []
        finally:
            exc.close()
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError) as exc:
        if result is not None:
            result.update({"status": "failed", "message": "Login request failed."})
        return [f"Login POST failed ({action_url}): {getattr(exc, 'reason', exc)}"], []

    got_cookie = _cookie_count(opener) > cookies_before
    redirected_away = _canonical(final_url) != _canonical(action_url)
    if not (got_cookie or redirected_away):
        warnings.append(f"Login may have failed at {login_url}; no session cookie set. Scanning may be unauthenticated.")
    if result is not None:
        result.update({
            "status": "uncertain" if got_cookie and not _looks_like_login(response_body) else "failed",
            "final_url": final_url,
            "session_cookie_received": got_cookie,
            "session_rotated": False,
            "message": "Login requires protected-content confirmation." if got_cookie else "Login success could not be confirmed.",
        })

    findings: list[Finding] = []
    if got_cookie or redirected_away:
        sessions_after = _session_cookie_values(opener)
        unchanged = [name for name, value in sessions_before.items() if sessions_after.get(name) == value]
        if unchanged:
            findings.append(
                _finding(
                    "web.session-not-rotated", "medium",
                    "Session ID is not rotated after login (session fixation)",
                    login_url, target=target,
                    evidence=f"session cookie(s) kept the same value across login: {', '.join(unchanged)}",
                    recommendation="Issue a fresh session identifier immediately after successful authentication.",
                )
            )
        elif result is not None:
            result["session_rotated"] = bool(sessions_before)
    return warnings, findings


_SESSION_COOKIE_NAMES = {
    "session", "sessionid", "sid", "sess", "jsessionid", "phpsessid",
    "asp.net_sessionid", "connect.sid", "laravel_session", "_session_id",
}


def _session_cookie_values(opener: urllib.request.OpenerDirector) -> dict[str, str]:
    values: dict[str, str] = {}
    for handler in opener.handlers:
        jar = getattr(handler, "cookiejar", None)
        if jar is None:
            continue
        for cookie in jar:
            if cookie.name.lower() in _SESSION_COOKIE_NAMES:
                values[cookie.name.lower()] = cookie.value or ""
    return values


def _match_field(fields: Mapping[str, str], pattern: re.Pattern[str]) -> str | None:
    for name in fields:
        if pattern.search(name):
            return name
    return None


def _cookie_count(opener: urllib.request.OpenerDirector) -> int:
    for handler in opener.handlers:
        jar = getattr(handler, "cookiejar", None)
        if jar is not None:
            return len(jar)
    return 0


def _opener_cookies(opener: urllib.request.OpenerDirector) -> list[dict[str, object]]:
    """Convert the opener's cookie jar to Playwright cookie dicts.

    Lets a form-login session (stored in the urllib jar) carry into the headless
    browser so authenticated SPA pages render logged-in rather than anonymous.
    """
    cookies: list[dict[str, object]] = []
    for handler in opener.handlers:
        jar = getattr(handler, "cookiejar", None)
        if jar is None:
            continue
        for cookie in jar:
            entry: dict[str, object] = {
                "name": cookie.name,
                "value": cookie.value or "",
                "domain": cookie.domain,
                "path": cookie.path or "/",
                "secure": bool(cookie.secure),
            }
            cookies.append(entry)
    return cookies


def _merge_browser_cookies(
    opener: urllib.request.OpenerDirector,
    browser_cookies: Sequence[Mapping[str, object]],
) -> None:
    """Sync Playwright browser cookies back into the opener's jar.

    Completes the bidirectional sync: a session the SPA rotated inside the
    headless browser is written back so subsequent stdlib crawl requests use the
    fresh cookie instead of a stale one.
    """
    jar = None
    for handler in opener.handlers:
        candidate = getattr(handler, "cookiejar", None)
        if candidate is not None:
            jar = candidate
            break
    if jar is None:
        return
    for cookie in browser_cookies:
        name = str(cookie.get("name") or "")
        domain = str(cookie.get("domain") or "")
        if not name or not domain:
            continue
        expires = cookie.get("expires")
        try:
            expires_val = int(expires) if expires not in (None, -1) else None
        except (TypeError, ValueError):
            expires_val = None
        jar.set_cookie(
            http.cookiejar.Cookie(
                version=0,
                name=name,
                value=str(cookie.get("value") or ""),
                port=None,
                port_specified=False,
                domain=domain,
                domain_specified=bool(domain),
                domain_initial_dot=domain.startswith("."),
                path=str(cookie.get("path") or "/"),
                path_specified=True,
                secure=bool(cookie.get("secure")),
                expires=expires_val,
                discard=expires_val is None,
                comment=None,
                comment_url=None,
                rest={"HttpOnly": ""} if cookie.get("httpOnly") else {},
            )
        )


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    url: str,
    *,
    target: str = "",
    evidence: str = "",
    recommendation: str = "",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category="web",
        severity=severity,
        title=title,
        path=Path(url),
        target=target,
        evidence=evidence,
        description="Live web posture check (non-destructive HTTP/TLS inspection).",
        recommendation=recommendation,
    )
