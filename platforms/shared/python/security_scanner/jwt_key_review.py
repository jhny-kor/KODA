"""Evaluate an explicitly supplied JWS HMAC key length against RFC 7518 §3.2."""

from __future__ import annotations

import base64
import binascii
import re

HMAC_MINIMUM_BITS = {"HS256": 256, "HS384": 384, "HS512": 512}


def key_bit_length(value: str, encoding: str) -> int:
    """Measure the configured value as bytes, without signing or verifying a token."""
    if encoding == "utf8":
        return len(value.encode("utf-8")) * 8
    if encoding not in {"base64", "base64url"}:
        raise ValueError("Choose utf8, base64 or base64url key encoding.")
    alphabet = r"[A-Za-z0-9+/]" if encoding == "base64" else r"[A-Za-z0-9_-]"
    if not re.fullmatch(alphabet + r"*={0,2}", value):
        raise ValueError("Key value does not match the selected encoding.")
    unpadded = value.rstrip("=")
    padded = unpadded + "=" * (-len(unpadded) % 4)
    if "=" in value and value != padded:
        raise ValueError("Key value has invalid base64 padding.")
    alternative = b"-_" if encoding == "base64url" else None
    try:
        decoded = base64.b64decode(padded, altchars=alternative, validate=True)
    except binascii.Error as exc:
        raise ValueError("Key value does not match the selected encoding.") from exc
    if base64.b64encode(decoded, altchars=alternative).decode("ascii") != padded:
        raise ValueError("Key value has invalid base64 padding bits.")
    return len(decoded) * 8


def review_jwt_key(algorithm: str, key_bits: int) -> dict[str, object]:
    if algorithm not in HMAC_MINIMUM_BITS:
        raise ValueError("Choose HS256, HS384 or HS512.")
    if type(key_bits) is not int or key_bits < 0:
        raise ValueError("Key size must be a non-negative integer in bits.")
    minimum = HMAC_MINIMUM_BITS[algorithm]
    return {
        "format": "koda.jwt-key-length-review.v1",
        "algorithm": algorithm,
        "key_bits": key_bits,
        "minimum_bits": minimum,
        "status": "MEETS_MINIMUM_LENGTH" if key_bits >= minimum else "TOO_SHORT",
    }
