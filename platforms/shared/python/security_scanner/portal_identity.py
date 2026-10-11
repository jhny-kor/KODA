"""Trusted identity boundary for the Linux portal.

The gateway is the authentication authority.  This module deliberately accepts
only its three injected headers; it never parses cookies or credentials.
"""
from __future__ import annotations

import base64
import datetime as dt
import hmac
import uuid
from dataclasses import dataclass


class IdentityError(ValueError):
    pass


class IdentityUnavailable(IdentityError):
    """A valid gateway session projected malformed display data."""


@dataclass(frozen=True)
class PortalIdentity:
    subject_id: str
    expires: dt.datetime
    display: str

    @property
    def uuid(self) -> uuid.UUID:
        return uuid.UUID(self.subject_id)


def _display(value: str) -> str:
    if not value:
        raise IdentityUnavailable("missing identity display")
    try:
        if "=" in value:
            raise ValueError
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        text = raw.decode("utf-8")
    except (ValueError, UnicodeError):
        raise IdentityUnavailable("invalid identity display")
    if not 1 <= len(text) <= 128 or len(raw) > 512 or len(value) > 683:
        raise IdentityUnavailable("identity display is out of bounds")
    return text


def _one_header(headers, name: str) -> str:
    # email.message.Message (used by BaseHTTPRequestHandler) retains duplicate
    # fields; dicts are accepted for direct callers and tests.
    values = headers.get_all(name, []) if hasattr(headers, "get_all") else [
        value for key, value in headers.items() if key.lower() == name.lower()
    ]
    if len(values) != 1 or not isinstance(values[0], str):
        raise IdentityError("invalid trusted identity")
    return values[0]


def identity_from_headers(headers, expected_proof: str = "") -> PortalIdentity:
    if len(expected_proof) < 32:
        raise IdentityUnavailable("gateway identity proof is not configured")
    supplied_proof = _one_header(headers, "X-KODA-Gateway-Proof")
    if not hmac.compare_digest(supplied_proof, expected_proof):
        raise IdentityError("invalid trusted identity")
    subject = _one_header(headers, "X-KODA-Identity-ID").strip()
    expires_text = _one_header(headers, "X-KODA-Identity-Expires").strip()
    display = _display(_one_header(headers, "X-KODA-Identity-Display"))
    try:
        subject = str(uuid.UUID(subject))
        expires = dt.datetime.fromisoformat(expires_text.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        raise IdentityError("invalid trusted identity")
    if expires.tzinfo is None or expires <= dt.datetime.now(dt.timezone.utc):
        raise IdentityError("identity expired")
    return PortalIdentity(subject, expires.astimezone(dt.timezone.utc), display)
