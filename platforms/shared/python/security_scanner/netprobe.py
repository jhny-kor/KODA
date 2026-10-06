"""Bounded, authorized active probes for non-web network services.

Standard-library only (``socket`` / ``ssl``). These are active but non-destructive:

- ``port_scan``: TCP-connect to a curated common-port list and grab a short banner.
- ``active_tls_probe``: try to negotiate deprecated TLS versions / weak ciphers and
  flag a certificate a default context rejects.
- ``default_credential_check``: try a *small, published* set of vendor default
  credentials over HTTP Basic auth. Authorized targets only, hard-capped at the
  published list — this is a default-credential check, NOT a brute forcer or a
  credential-stuffing/wordlist tool.

ponytail: all three are opt-in and authorization-gated by the caller; findings use
the ``web`` category so they group with the other live-posture results.
"""

from __future__ import annotations

import base64
import socket
import ssl
import urllib.error
import urllib.request
import warnings
from collections.abc import Mapping
from pathlib import Path

from .models import Finding

# Curated ports worth checking for exposure (service name for the report).
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 110: "pop3", 143: "imap",
    80: "http", 443: "https", 445: "smb", 2375: "docker", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5984: "couchdb", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}
# Ports whose mere exposure to the probe is notable (admin/data-plane services
# that are usually not meant to face an untrusted network).
_SENSITIVE_PORTS = {23, 445, 2375, 3306, 3389, 5432, 5984, 6379, 9200, 11211, 27017}
# Published vendor defaults only. Kept tiny on purpose: a default-credential
# check, not a brute forcer.
_DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"), ("admin", "password"), ("admin", ""),
    ("root", "root"), ("tomcat", "tomcat"),
)


def _finding(rule_id: str, severity: str, title: str, target: str, *,
             evidence: str = "", recommendation: str = "") -> Finding:
    return Finding(
        rule_id=rule_id, category="web", severity=severity, title=title,
        path=Path(target), target=target, evidence=evidence,
        description="Live network-service posture check (non-destructive).",
        recommendation=recommendation, resource=f"net/{target}",
    )


def port_scan(host: str, *, ports: Mapping[int, str] | None = None,
              timeout: float = 1.0, banner_bytes: int = 64) -> list[Finding]:
    """TCP-connect to each port; report the open ones with a short banner."""
    findings: list[Finding] = []
    for port, service in (ports or COMMON_PORTS).items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((host, port)) != 0:
                continue
            banner = ""
            try:
                sock.settimeout(0.5)
                banner = sock.recv(banner_bytes).decode("latin-1", "replace").strip()
            except OSError:
                pass
        finally:
            sock.close()
        severity = "medium" if port in _SENSITIVE_PORTS else "info"
        evidence = f"port {port} ({service}) is open"
        if banner:
            evidence += f"; banner: {banner[:80]}"
        findings.append(_finding(
            "net.port-exposed", severity, f"Open network port {port}/{service}", host,
            evidence=evidence,
            recommendation="Close or firewall services that do not need to face this network; restrict by source address.",
        ))
    return findings


def _handshake_ok(host: str, port: int, context: ssl.SSLContext, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout) as sock, \
                context.wrap_socket(sock, server_hostname=host):
            return True
    except (ssl.SSLError, OSError):
        return False


def active_tls_probe(host: str, port: int = 443, *, timeout: float = 5.0) -> list[Finding]:
    """Negotiate deprecated TLS versions / weak ciphers and check cert validity."""
    findings: list[Finding] = []
    # We intentionally probe deprecated versions; silence Python's own deprecation
    # warning for naming them (that warning is for app code, not a protocol tester).
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        deprecated = {"TLS 1.0": ssl.TLSVersion.TLSv1, "TLS 1.1": ssl.TLSVersion.TLSv1_1}
        for name, version in deprecated.items():
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                context.minimum_version = version
                context.maximum_version = version
            except ValueError:
                continue  # this OpenSSL build no longer offers that version at all
            if _handshake_ok(host, port, context, timeout):
                findings.append(_finding(
                    "net.tls-weak-protocol", "medium", f"Deprecated {name} accepted", host,
                    evidence=f"the server completed a {name} handshake on port {port}",
                    recommendation="Disable TLS 1.0/1.1 at the server; require TLS 1.2+.",
                ))

    weak = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    weak.check_hostname = False
    weak.verify_mode = ssl.CERT_NONE
    try:
        weak.set_ciphers("RC4:3DES:DES:MD5:aNULL:eNULL:EXPORT")
        weak_available = True
    except ssl.SSLError:
        weak_available = False  # local OpenSSL will not even offer weak ciphers
    if weak_available and _handshake_ok(host, port, weak, timeout):
        findings.append(_finding(
            "net.tls-weak-cipher", "medium", "Weak TLS cipher accepted", host,
            evidence=f"the server negotiated a weak/export/NULL cipher on port {port}",
            recommendation="Restrict the server to strong, forward-secret cipher suites.",
        ))

    verify = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout) as sock, \
                verify.wrap_socket(sock, server_hostname=host):
            pass
    except ssl.SSLCertVerificationError as exc:
        findings.append(_finding(
            "net.tls-cert-invalid", "medium", "TLS certificate fails validation", host,
            evidence=f"a default-verifying client rejected the certificate on port {port}: {exc.verify_message or exc}",
            recommendation="Serve a valid certificate chain trusted by standard roots and matching the hostname.",
        ))
    except (ssl.SSLError, OSError):
        pass  # not TLS, or unreachable; the deprecated-protocol checks already tried
    return findings


def default_credential_check(url: str, *, timeout: float = 5.0, authorize: bool = False) -> list[Finding]:
    """Try published default credentials against an HTTP Basic-auth endpoint.

    Does nothing unless ``authorize`` is set. Only runs when the endpoint actually
    challenges with Basic auth, and only tries the fixed published-defaults list.
    """
    if not authorize:
        return []
    challenge = _basic_auth_challenge(url, timeout)
    if not challenge:
        return []
    for username, password in _DEFAULT_CREDS:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        request = urllib.request.Request(url, headers={"Authorization": f"Basic {token}"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        except (urllib.error.URLError, OSError):
            return []
        if status and status < 400:
            shown = f"{username}:{password}" if password else f"{username}:(empty)"
            return [_finding(
                "net.default-credentials", "high",
                "Default credentials accepted on an HTTP Basic-auth endpoint", url,
                evidence=f"published default '{shown}' was accepted (HTTP {status})",
                recommendation="Change all default credentials; disable or restrict the exposed admin endpoint.",
            )]
    return []


def service_auth_probe(host: str, *, timeout: float = 2.0) -> list[Finding]:
    """Check common data/admin services for *unauthenticated* access.

    Non-destructive: each probe issues a read-only status command (Redis PING/INFO,
    an HTTP status endpoint) and flags the service only when it answers without
    requiring credentials. Nothing is written or deleted.
    """
    findings: list[Finding] = []
    findings += _redis_unauth(host, timeout)
    findings += _http_unauth(host, 9200, "/", "elasticsearch", "cluster_name", timeout)
    findings += _http_unauth(host, 2375, "/version", "docker", "ApiVersion", timeout)
    findings += _http_unauth(host, 5984, "/_all_dbs", "couchdb", "[", timeout)
    return findings


def _redis_unauth(host: str, timeout: float, port: int = 6379) -> list[Finding]:
    try:
        with socket.create_connection((host, port), timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"PING\r\n")
            if not sock.recv(64).decode("latin-1", "replace").startswith("+PONG"):
                return []  # auth required (-NOAUTH) or not Redis
            sock.sendall(b"INFO server\r\n")
            info = sock.recv(2048).decode("latin-1", "replace")
    except OSError:
        return []
    if "redis_version" not in info:
        return []
    return [_finding(
        "net.redis-unauth", "high", "Redis is reachable without authentication", host,
        evidence="Redis answered PING and INFO with no AUTH required",
        recommendation="Set requirepass / ACLs and bind Redis to localhost or a private network.",
    )]


def _http_unauth(host: str, port: int, path: str, service: str, signature: str, timeout: float) -> list[Finding]:
    url = f"http://{host}:{port}{path}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            if response.status != 200:
                return []
            body = response.read(4096).decode("latin-1", "replace")
    except (urllib.error.URLError, OSError):
        return []
    if signature not in body:
        return []
    return [_finding(
        f"net.{service}-unauth", "high", f"{service} API reachable without authentication", url,
        evidence=f"{service} returned a {signature!r} response on {port} without credentials",
        recommendation=f"Require authentication for {service} and restrict it to a private network.",
    )]


def _basic_auth_challenge(url: str, timeout: float) -> bool:
    """True when the URL responds 401 with a Basic-auth challenge."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            header = response.headers.get("WWW-Authenticate", "")
            return "basic" in header.lower()
    except urllib.error.HTTPError as exc:
        return exc.code == 401 and "basic" in (exc.headers.get("WWW-Authenticate", "") or "").lower()
    except (urllib.error.URLError, OSError):
        return False
