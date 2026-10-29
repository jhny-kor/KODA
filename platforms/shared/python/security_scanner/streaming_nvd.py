"""Validate NVD JSON without retaining its complete vulnerability catalogue.

Callbacks receive one decoded entry at a time. Their events are provisional until
the entire document, including trailing input, has been checked successfully.
Object entry callbacks may repeat a key: consumers must preserve JSON's usual
last-value-wins rule, and its first insertion position, when building an index.
"""
from __future__ import annotations

import gzip
import json
import re
from collections.abc import Callable, Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TextIO

Kind = Literal["dict", "list"]
SectionSelector = Collection[str] | Callable[[str, Kind | None], bool]
_CHUNK_SIZE = 64 * 1024
_NONSPACE = re.compile(r"[^ \t\r\n]")
_STRING_SPECIAL = re.compile(r'["\\\x00-\x1f]')
_SCALAR_END = re.compile(r"[ \t\r\n,\]}:]")
_HEX = frozenset("0123456789abcdefABCDEF")
_DECODER = json.JSONDecoder()


class NvdShapeError(ValueError):
    """Valid JSON has a root or final vulnerability section of the wrong type."""


@dataclass(frozen=True)
class SectionInfo:
    kind: Kind | None
    # Entry events, rather than distinct object keys; no key set is retained.
    count: int | None
    truthy: bool


@dataclass(frozen=True)
class JsonSections:
    root_kind: Kind
    sections: dict[str | None, SectionInfo]


class _Reader:
    def __init__(self, source: TextIO):
        self.source = source
        self.buffer = ""
        self.position = 0
        self.offset = 0
        self.eof = False
        self.capture: list[str] | None = None
        self.capture_limit: int | None = None
        self.capture_size = 0
        self.capture_exceeded = False

    def peek(self) -> str:
        if self.position == len(self.buffer) and not self.eof:
            self.offset += self.position
            self.position = 0
            self.buffer = self.source.read(_CHUNK_SIZE)
            self.eof = not self.buffer
        return self.buffer[self.position:self.position + 1]

    def advance(self, count: int) -> None:
        if self.capture is not None and not self.capture_exceeded:
            self.capture_size += count
            if self.capture_limit is not None and self.capture_size > self.capture_limit:
                self.capture.clear()
                self.capture_exceeded = True
            else:
                self.capture.append(self.buffer[self.position:self.position + count])
        self.position += count

    def error(self, message: str) -> None:
        # Keeping only the current chunk also bounds malformed-input diagnostics.
        raise json.JSONDecodeError(
            f"{message} (stream character {self.offset + self.position})",
            self.buffer,
            self.position,
        )

    def whitespace(self) -> None:
        while self.peek():
            match = _NONSPACE.search(self.buffer, self.position)
            if match is not None:
                self.advance(match.start() - self.position)
                return
            self.advance(len(self.buffer) - self.position)

    def expect(self, expected: str) -> None:
        if self.peek() != expected:
            self.error(f"Expecting {expected!r}")
        self.advance(1)

    def start_capture(self, limit: int | None = None) -> None:
        assert self.capture is None
        self.capture = []
        self.capture_limit = limit
        self.capture_size = 0
        self.capture_exceeded = False

    def finish_capture(self) -> str | None:
        result = None if self.capture_exceeded else "".join(self.capture or ())
        self.capture = None
        self.capture_limit = None
        return result

    def string(self) -> bool:
        """Skip a complete string and return its truthiness, without decoding it."""
        self.expect('"')
        nonempty = False
        while self.peek():
            match = _STRING_SPECIAL.search(self.buffer, self.position)
            if match is None:
                nonempty = nonempty or self.position < len(self.buffer)
                self.advance(len(self.buffer) - self.position)
                continue
            if match.start() != self.position:
                nonempty = True
                self.advance(match.start() - self.position)
            token = self.peek()
            if token == '"':
                self.advance(1)
                return nonempty
            if token != "\\":
                self.error("Invalid control character in string")
            self.advance(1)
            escape = self.peek()
            if escape == "u":
                self.advance(1)
                for _ in range(4):
                    if self.peek() not in _HEX:
                        self.error("Invalid \\uXXXX escape")
                    self.advance(1)
            elif escape and escape in '"\\/bfnrt':
                self.advance(1)
            else:
                self.error("Invalid escape")
            nonempty = True
        self.error("Unterminated string")

    def key(self, *, decode: bool, limit: int | None = None) -> str | None:
        if not decode:
            self.string()
            return None
        self.start_capture(limit)
        self.string()
        raw = self.finish_capture()
        return json.loads(raw) if raw is not None else None

    def scalar(self):
        pieces: list[str] = []
        while self.peek():
            match = _SCALAR_END.search(self.buffer, self.position)
            end = match.start() if match is not None else len(self.buffer)
            pieces.append(self.buffer[self.position:end])
            self.advance(end - self.position)
            if match is not None:
                break
        # This retains the standard decoder's number rules, integer conversion
        # limits and accepted NaN/Infinity constants, rather than new substitutes.
        return json.loads("".join(pieces))

    def value(self) -> None:
        """Check a whole value with a stack of grammar states, not a JSON tree."""
        states = ["value"]
        while states:
            state = states.pop()
            self.whitespace()
            token = self.peek()
            if state == "value":
                if token == "{":
                    self.advance(1)
                    states.append("object-first")
                elif token == "[":
                    self.advance(1)
                    states.append("array-first")
                elif token == '"':
                    self.string()
                else:
                    self.scalar()
            elif state in {"object-first", "object-key"}:
                if state == "object-first" and token == "}":
                    self.advance(1)
                    continue
                if token != '"':
                    self.error("Expecting property name enclosed in double quotes")
                self.string()
                self.whitespace()
                self.expect(":")
                states.extend(("object-after", "value"))
            elif state == "object-after":
                if token == "}":
                    self.advance(1)
                elif token == ",":
                    self.advance(1)
                    states.append("object-key")
                else:
                    self.error("Expecting ',' delimiter")
            elif state in {"array-first", "array-next"}:
                if state == "array-first" and token == "]":
                    self.advance(1)
                else:
                    states.extend(("array-after", "value"))
            elif state == "array-after":
                if token == "]":
                    self.advance(1)
                elif token == ",":
                    self.advance(1)
                    states.append("array-next")
                else:
                    self.error("Expecting ',' delimiter")

    def decoded_value(self):
        self.whitespace()
        complete, value = self.try_decoded_value()
        if complete:
            return value
        self.start_capture()
        self.value()
        raw = self.finish_capture()
        return json.loads(raw)

    def try_decoded_value(self) -> tuple[bool, object]:
        """Use the C decoder only when a complete value fits in this chunk."""
        token = self.peek()
        try:
            value, end = _DECODER.raw_decode(self.buffer, self.position)
        except json.JSONDecodeError:
            return False, None
        # A number at the end of a chunk may continue in the next one. Require
        # a delimiter for all scalars; strings and containers have explicit ends.
        if token not in {'"', "{", "["} and (end == len(self.buffer) or self.buffer[end] not in " \t\r\n,]}:"):
            return False, None
        self.advance(end - self.position)
        return True, value

    def discard_value(self) -> None:
        self.whitespace()
        complete, _ = self.try_decoded_value()
        if not complete:
            # A very large entry is syntax-checked without collecting its text.
            self.value()

    def entries(self, kind: Kind, callback: Callable[[str | int, object], None] | None) -> int:
        self.expect("{" if kind == "dict" else "[")
        close = "}" if kind == "dict" else "]"
        count = 0
        self.whitespace()
        if self.peek() == close:
            self.advance(1)
            return count
        while True:
            self.whitespace()
            if kind == "dict":
                if self.peek() != '"':
                    self.error("Expecting property name enclosed in double quotes")
                key = self.key(decode=callback is not None)
                self.whitespace()
                self.expect(":")
            else:
                key = count
            if callback is None:
                self.discard_value()
            else:
                callback(key, self.decoded_value())
            count += 1
            self.whitespace()
            if self.peek() == close:
                self.advance(1)
                return count
            self.expect(",")


def read_json_sections(
    path: str | Path,
    *,
    section_names: SectionSelector,
    on_section: Callable[[str | None, Kind | None], None] | None = None,
    on_entry: Callable[[str | None, str | int, object], None] | None = None,
    on_field: Callable[[str, object], None] | None = None,
    field_names: Collection[str] | None = None,
    allow_root_list: bool = False,
    allow_gzip: bool = False,
) -> JsonSections:
    """Check JSON and optionally stream selected root containers.

    ``on_section`` announces every root field, including scalar fields (kind
    ``None``), so duplicate fields can reset prior state. ``on_entry`` receives
    selected dict/list entries. ``on_field`` receives scalar fields only, never
    whole unselected containers, and can be restricted with ``field_names``.
    A root list uses the section name ``None``. Returned section information is
    final, after duplicate fields; object counts include repeated key events.
    A selector predicate allows callers to stream additional top-level lists
    without retaining large unrecognized metadata objects.
    """
    def selected(name: str, kind: Kind | None) -> bool:
        return section_names(name, kind) if callable(section_names) else name in section_names

    # When no callback needs arbitrary root names, a longer key cannot match a
    # requested name. Discarding that key is an allocation optimization, not an
    # input limit: its complete string syntax is still checked.
    bounded_names = not callable(section_names) and on_section is None and (on_field is None or field_names is not None)
    names = set(section_names) if not callable(section_names) else set()
    if field_names is not None:
        names.update(field_names)
    key_limit = max((12 * len(name) + 2 for name in names), default=2) if bounded_names else None
    opener = gzip.open if allow_gzip and str(path).lower().endswith(".gz") else open
    sections: dict[str | None, SectionInfo] = {}
    with opener(path, "rt", encoding="utf-8") as source:
        reader = _Reader(source)
        reader.whitespace()
        token = reader.peek()
        root_kind: Kind | None = "dict" if token == "{" else "list" if token == "[" else None
        if root_kind == "dict":
            reader.advance(1)
            reader.whitespace()
            if reader.peek() == "}":
                reader.advance(1)
            else:
                while True:
                    reader.whitespace()
                    if reader.peek() != '"':
                        reader.error("Expecting property name enclosed in double quotes")
                    name = reader.key(decode=True, limit=key_limit)
                    reader.whitespace()
                    reader.expect(":")
                    reader.whitespace()
                    token = reader.peek()
                    kind: Kind | None = "dict" if token == "{" else "list" if token == "[" else None
                    wanted = name is not None and selected(name, kind)
                    if on_section is not None:
                        on_section(name, kind)
                    if kind is not None:
                        callback = None
                        if wanted and on_entry is not None:
                            callback = lambda key, value: on_entry(name, key, value)
                        count = reader.entries(kind, callback)
                        info = SectionInfo(kind, count, bool(count))
                    elif on_field is not None and name is not None and (field_names is None or name in field_names):
                        value = reader.decoded_value()
                        on_field(name, value)
                        info = SectionInfo(None, None, bool(value))
                    elif token == '"':
                        info = SectionInfo(None, None, reader.string())
                    else:
                        info = SectionInfo(None, None, bool(reader.scalar()))
                    if wanted:
                        sections[name] = info
                    else:
                        sections.pop(name, None)
                    reader.whitespace()
                    if reader.peek() == "}":
                        reader.advance(1)
                        break
                    reader.expect(",")
        elif root_kind == "list":
            if on_section is not None:
                on_section(None, "list")
            callback = None if on_entry is None else lambda key, value: on_entry(None, key, value)
            count = reader.entries("list", callback)
            sections[None] = SectionInfo("list", count, bool(count))
        else:
            reader.value()
        reader.whitespace()
        if reader.peek():
            reader.error("Extra data")
        if root_kind is None or (root_kind == "list" and not allow_root_list):
            raise NvdShapeError("JSON root must be an object" + (" or list" if allow_root_list else ""))
    return JsonSections(root_kind, sections)


def read_nvd(
    path: str | Path,
    *,
    on_section: Callable[[Kind | None], None] | None = None,
    on_entry: Callable[[str | int, object], None] | None = None,
    allow_root_list: bool = False,
) -> JsonSections:
    """Check a complete NVD document, optionally decoding individual records.

    The final root ``vulnerabilities`` value must be a dict/list. Earlier values
    of a duplicate field do not decide validity. The ordinary JSON decoder is
    used for callback records, preserving duplicate nested keys and constants.
    Without callbacks, record strings and containers are only syntax-checked.
    """
    result = read_json_sections(
        path,
        section_names={"vulnerabilities"},
        on_section=(lambda name, kind: on_section(kind) if name in {None, "vulnerabilities"} else None) if on_section is not None else None,
        on_entry=(lambda name, key, value: on_entry(key, value)) if on_entry is not None else None,
        allow_root_list=allow_root_list,
    )
    if result.root_kind == "dict":
        section = result.sections.get("vulnerabilities")
        if section is None or section.kind not in {"dict", "list"}:
            raise NvdShapeError("NVD data must contain vulnerabilities")
    return result
