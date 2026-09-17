from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, replace
from io import BytesIO
from typing import Iterable
from urllib.parse import quote

from .java_archives import ArchiveArtifact, ArchiveScan
from .xml_safe import XmlInputError, parse_xml


@dataclass(frozen=True, slots=True)
class JavaComponent:
    group: str
    name: str
    version: str
    purl: str
    sha256: str
    size: int
    archive_type: str
    modified_at: str
    locations: tuple[str, ...]
    identification_source: str
    identity_status: str
    manual_review_required: bool
    version_source: str = ""
    confidence: str = "unresolved"
    filename_version: str = ""
    filename_version_mismatch: bool = False

    def payload(self) -> dict[str, object]:
        return {
            "group": self.group,
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "sha256": self.sha256,
            "size": self.size,
            "archive_type": self.archive_type,
            "modified_at": self.modified_at,
            "locations": list(self.locations),
            "identification_source": self.identification_source,
            "identity_status": self.identity_status,
            "manual_review_required": self.manual_review_required,
            "version_source": self.version_source,
            "confidence": self.confidence,
            "filename_version": self.filename_version,
            "filename_version_mismatch": self.filename_version_mismatch,
        }


def inventory_components(artifacts: ArchiveScan | Iterable[ArchiveArtifact]) -> tuple[JavaComponent, ...]:
    candidates = artifacts.artifacts if isinstance(artifacts, ArchiveScan) else tuple(artifacts)
    by_sha: dict[str, JavaComponent] = {}
    for artifact in candidates:
        component = identify_archive(artifact)
        existing = by_sha.get(component.sha256)
        if existing is None:
            by_sha[component.sha256] = component
            continue
        locations = tuple(dict.fromkeys((*existing.locations, *component.locations)))
        by_sha[component.sha256] = replace(existing, locations=locations)
    return tuple(sorted(by_sha.values(), key=lambda item: (item.name.lower(), item.version, item.sha256)))


def identify_archive(artifact: ArchiveArtifact) -> JavaComponent:
    group = ""
    name = artifact.filename
    version = ""
    filename_name, filename_version = _filename_coordinates(artifact.filename)
    name = filename_name or name
    source = "filename-unresolved"
    status = "unresolved"
    try:
        with zipfile.ZipFile(BytesIO(artifact.payload)) as archive:
            names = sorted(name for name in archive.namelist() if not name.endswith("/"))
            properties = next((name for name in names if _is_pom_properties(name)), None)
            if properties:
                values = _properties(archive.read(properties).decode("utf-8", errors="replace"))
                group, name, version = _coordinates(values)
                if group and name and version:
                    source, status = "pom.properties", "resolved"
            if status == "unresolved":
                pom = next((entry for entry in names if _is_pom_xml(entry)), None)
                if pom:
                    group, name, version = _pom_xml_coordinates(archive.read(pom))
                    if group and name and version:
                        source, status = "pom.xml", "resolved"
            if status == "unresolved":
                manifest = next((entry for entry in names if entry.upper() == "META-INF/MANIFEST.MF"), None)
                if manifest:
                    values = _properties(archive.read(manifest).decode("utf-8", errors="replace"))
                    name = values.get("Implementation-Title") or values.get("Bundle-SymbolicName") or name
                    version = values.get("Implementation-Version") or values.get("Bundle-Version") or ""
                    # A version explicitly declared by MANIFEST.MF is a confirmed
                    # version, even when the archive does not carry full Maven
                    # coordinates. Do not downgrade this to a filename guess or
                    # leave it in the review queue.
                    if version:
                        source, status = "manifest", "resolved"
    except (OSError, zipfile.BadZipFile, UnicodeError, XmlInputError):
        source = "filename-unresolved"

    if not version and filename_version:
        version = filename_version
        source, status = "filename", "inferred"
    version_source = source if version else ""
    confidence = "high" if source in {"pom.properties", "pom.xml"} else "medium" if source == "manifest" else "low" if source == "filename" else "unresolved"
    filename_version_mismatch = bool(filename_version and version and filename_version != version)

    purl = _maven_purl(group, name, version) if status == "resolved" else ""
    return JavaComponent(
        group=group,
        name=name,
        version=version,
        purl=purl,
        sha256=artifact.sha256,
        size=artifact.size,
        archive_type=artifact.archive_type,
        modified_at=artifact.modified_at,
        locations=(artifact.location.display(),),
        identification_source=source,
        identity_status=status,
        manual_review_required=status not in {"resolved", "inferred"} or filename_version_mismatch,
        version_source=version_source,
        confidence=confidence,
        filename_version=filename_version,
        filename_version_mismatch=filename_version_mismatch,
    )


def _is_pom_properties(name: str) -> bool:
    return name.startswith("META-INF/maven/") and name.endswith("/pom.properties")


def _is_pom_xml(name: str) -> bool:
    return name.startswith("META-INF/maven/") and name.endswith("/pom.xml")


def _properties(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    pending = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            pending += line[:-1]
            continue
        line = pending + line
        pending = ""
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "!")):
            continue
        match = re.match(r"([^:=\s]+)\s*[:=]\s*(.*)$", stripped)
        if match:
            values[match.group(1)] = match.group(2).strip()
    return values


def _coordinates(values: dict[str, str]) -> tuple[str, str, str]:
    return values.get("groupId", ""), values.get("artifactId", ""), values.get("version", "")


def _filename_coordinates(filename: str) -> tuple[str, str]:
    stem = filename.rsplit(".", 1)[0]
    match = re.match(r"^(?P<name>.+?)-(?P<version>\d[^-]*?(?:[-.][A-Za-z0-9]+)*)$", stem)
    if not match:
        return stem, ""
    return match.group("name"), match.group("version")


def _pom_xml_coordinates(payload: bytes) -> tuple[str, str, str]:
    root = parse_xml(payload)
    values: dict[str, str] = {}
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1]
        if local_name in {"groupId", "artifactId", "version"} and element.text:
            values.setdefault(local_name, element.text.strip())
    return _coordinates(values)


def _maven_purl(group: str, name: str, version: str) -> str:
    return f"pkg:maven/{quote(group, safe='.')}/{quote(name, safe='.-_')}@{quote(version, safe='.-_+')}"
