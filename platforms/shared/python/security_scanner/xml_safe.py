"""Small dependency-free XML boundary for untrusted metadata."""

from __future__ import annotations

import re

# The scanner intentionally remains standard-library-only. DTD and entity
# declarations are rejected before the stdlib tree parser sees untrusted XML.
import xml.etree.ElementTree as _ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml


class XmlInputError(ValueError):
    """Raised when XML is unsafe or malformed for metadata extraction."""


_UNSAFE_DECLARATION_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


def parse_xml(payload: str | bytes) -> _ET.Element:
    """Parse metadata XML after rejecting DTD/entity expansion controls."""
    text = payload.decode("utf-8", errors="ignore") if isinstance(payload, bytes) else payload
    if _UNSAFE_DECLARATION_RE.search(text):
        raise XmlInputError("DTD and entity declarations are not allowed")
    try:
        return _ET.fromstring(payload)
    except _ET.ParseError as exc:
        raise XmlInputError("malformed XML") from exc
