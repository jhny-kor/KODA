"""Inspect one public X.509 certificate locally without performing trust checks."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

MAX_CERTIFICATE_BYTES = 256 * 1024
_PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----")
_LEGACY_SIGNATURES = {
    "1.2.840.113549.1.1.2",  # MD2 with RSA
    "1.2.840.113549.1.1.3",  # MD4 with RSA
    "1.2.840.113549.1.1.4",  # MD5 with RSA
    "1.2.840.113549.1.1.5",  # SHA-1 with RSA
    "1.2.840.10040.4.3",  # DSA with SHA-1
    "1.2.840.10045.4.1",  # ECDSA with SHA-1
    "1.3.14.3.2.27",  # DSA with SHA-1, alternate OID
    "1.3.14.3.2.29",  # SHA-1 with RSA, alternate OID
}

_WINDOWS_PARSE = r"""
$ErrorActionPreference = 'Stop'
$type = [System.Security.Cryptography.X509Certificates.X509Certificate2]
$der = [Convert]::FromBase64String([Console]::In.ReadToEnd())
if ($type::GetCertContentType($der).ToString() -ne 'Cert') {
    throw 'Expected a public certificate'
}
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
try {
    $format = "yyyy-MM-dd'T'HH:mm:ss'Z'"
    $culture = [Globalization.CultureInfo]::InvariantCulture
    @{
        not_before = $cert.NotBefore.ToUniversalTime().ToString($format, $culture)
        not_after = $cert.NotAfter.ToUniversalTime().ToString($format, $culture)
    } | ConvertTo-Json -Compress
} finally {
    $cert.Dispose()
}
"""


def _element(data: bytes, offset: int, tag: int) -> tuple[bytes, int]:
    """Read a bounded, definite-length DER element."""
    if offset + 2 > len(data) or data[offset] != tag:
        raise ValueError("Expected a single X.509 certificate.")
    size = data[offset + 1]
    offset += 2
    if size >= 128:
        length_bytes = size & 0x7F
        if not 1 <= length_bytes <= 3 or offset + length_bytes > len(data) or not data[offset]:
            raise ValueError("Invalid DER element length.")
        size = int.from_bytes(data[offset:offset + length_bytes], "big")
        if size < 128:
            raise ValueError("Invalid DER element length.")
        offset += length_bytes
    end = offset + size
    if end > len(data):
        raise ValueError("Truncated DER element.")
    return data[offset:end], end


def _signature_oid(der: bytes) -> str:
    certificate, end = _element(der, 0, 0x30)
    if end != len(der):
        raise ValueError("The file must contain exactly one certificate.")
    _, offset = _element(certificate, 0, 0x30)
    algorithm, offset = _element(certificate, offset, 0x30)
    signature, offset = _element(certificate, offset, 0x03)
    if offset != len(certificate) or len(signature) < 2 or signature[0] > 7:
        raise ValueError("Invalid certificate signature field.")
    oid, _ = _element(algorithm, 0, 0x06)
    if not oid or len(oid) > 32 or oid[-1] & 0x80:
        raise ValueError("Invalid certificate signature identifier.")
    parts: list[int] = []
    number = 0
    for byte in oid:
        if not number and byte == 0x80:
            raise ValueError("Invalid certificate signature identifier.")
        number = (number << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(number)
            number = 0
    first = min(parts[0] // 40, 2)
    return ".".join(map(str, [first, parts[0] - first * 40, *parts[1:]]))


def _run_parser(arguments: list[str], data: bytes, *, environment: dict[str, str] | None = None) -> str:
    try:
        result = subprocess.run(arguments, input=data, capture_output=True, timeout=10, env=environment, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("The operating system certificate parser is unavailable.") from exc
    if result.returncode:
        raise ValueError("The file could not be parsed as a public X.509 certificate.")
    return result.stdout.decode("utf-8-sig", errors="replace")


def _openssl_validity(der: bytes) -> tuple[datetime, datetime]:
    output = _run_parser(
        ["/usr/bin/openssl", "x509", "-inform", "DER", "-noout", "-startdate", "-enddate"],
        der,
        environment={"LC_ALL": "C", "OPENSSL_CONF": os.devnull},
    )
    fields = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    try:
        return parsedate_to_datetime(fields["notBefore"]), parsedate_to_datetime(fields["notAfter"])
    except (KeyError, ValueError) as exc:
        raise ValueError("The certificate validity dates could not be read.") from exc


def _windows_validity(der: bytes, executable: str) -> tuple[datetime, datetime]:
    output = _run_parser(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_PARSE],
        base64.b64encode(der),
    )
    try:
        fields = json.loads(output)
        return (
            datetime.fromisoformat(fields["not_before"].replace("Z", "+00:00")),
            datetime.fromisoformat(fields["not_after"].replace("Z", "+00:00")),
        )
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise ValueError("The certificate validity dates could not be read.") from exc


def _certificate_validity(der: bytes) -> tuple[datetime, datetime]:
    if sys.platform in ("darwin", "linux"):
        return _openssl_validity(der)
    if sys.platform == "win32":
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        pwsh = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        return _windows_validity(der, str(pwsh))
    raise RuntimeError("Offline certificate review requires macOS, Windows or OpenSSL on Linux.")


def review_certificate(raw: bytes, *, now: datetime | None = None) -> dict[str, object]:
    """Report declared validity dates, signature algorithm and certificate fingerprint."""
    if not raw or len(raw) > MAX_CERTIFICATE_BYTES:
        raise ValueError("Choose one nonempty X.509 certificate of up to 256 KiB.")
    pem = _PEM.fullmatch(raw.strip())
    try:
        der = base64.b64decode(b"".join(pem[1].split()), validate=True) if pem else raw
    except binascii.Error as exc:
        raise ValueError("The PEM certificate is invalid.") from exc
    oid = _signature_oid(der)
    not_before, not_after = _certificate_validity(der)
    if not_before.utcoffset() is None or not_after.utcoffset() is None or not_before > not_after:
        raise ValueError("Invalid certificate validity interval.")
    current = now or datetime.now(timezone.utc)
    if current < not_before:
        validity = "NOT_YET_VALID"
    elif current > not_after:
        validity = "EXPIRED"
    else:
        validity = "VALID"
    return {
        "format": "koda.certificate-review.v1",
        "input_format": "PEM" if pem else "DER",
        "sha256": hashlib.sha256(der).hexdigest(),
        "not_before": not_before.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "not_after": not_after.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "remaining_days": (not_after - current).days,
        "validity": validity,
        "signature_oid": oid,
        "weak_signature": oid in _LEGACY_SIGNATURES,
    }
