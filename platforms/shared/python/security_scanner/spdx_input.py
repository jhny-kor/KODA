"""Bounded SPDX 2.3 JSON input normalization, with original evidence retained.

Only explicit package dependency edges become CycloneDX dependency edges.
Containment, file/external relationships and licensing conclusions remain in
source properties. URLs are evidence strings and are never fetched.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime
from urllib.parse import urlsplit

_ID = re.compile(r"^SPDXRef-[A-Za-z0-9.-]+$")
_CHECKSUMS = {"SHA1": ("SHA-1", 40), "SHA224": ("SHA-224", 56), "SHA256": ("SHA-256", 64),
              "SHA384": ("SHA-384", 96), "SHA512": ("SHA-512", 128), "MD5": ("MD5", 32),
              "SHA3-256": ("SHA3-256", 64), "SHA3-384": ("SHA3-384", 96), "SHA3-512": ("SHA3-512", 128),
              "BLAKE2b-256": ("BLAKE2b-256", 64), "BLAKE2b-384": ("BLAKE2b-384", 96),
              "BLAKE2b-512": ("BLAKE2b-512", 128), "BLAKE3": ("BLAKE3", 64)}


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _array(value, name):
    if not isinstance(value, list):
        raise ValueError(f"SPDX {name} must be an array")
    return value


def _identifier(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Invalid local SPDX identifier")
    return value


def to_cyclonedx(document: dict) -> dict:
    if not isinstance(document, dict) or document.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("Only SPDX 2.3 JSON is supported")
    if document.get("SPDXID") != "SPDXRef-DOCUMENT" or document.get("dataLicense") != "CC0-1.0":
        raise ValueError("SPDX document identifier and CC0-1.0 dataLicense are required")
    if not isinstance(document.get("name"), str) or not document["name"].strip():
        raise ValueError("SPDX document name is required")
    namespace = document.get("documentNamespace")
    if not isinstance(namespace, str) or not urlsplit(namespace).scheme or "#" in namespace:
        raise ValueError("SPDX documentNamespace must be an absolute URI without fragment")
    creation = document.get("creationInfo")
    if not isinstance(creation, dict) or not isinstance(creation.get("created"), str):
        raise ValueError("SPDX creationInfo.created is required")
    created = datetime.fromisoformat(creation["created"].replace("Z", "+00:00"))
    if created.tzinfo is None or not isinstance(creation.get("creators"), list) or not creation["creators"] or any(not isinstance(item, str) or not item.startswith(("Tool: ", "Person: ", "Organization: ")) for item in creation["creators"]):
        raise ValueError("SPDX timezone and creators are required")
    packages = _array(document.get("packages", []), "packages")
    if len(packages) > 50000:
        raise ValueError("SPDX package limit exceeded")
    components, by_id, known = [], {}, {"SPDXRef-DOCUMENT"}
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("SPDX package must be an object")
        identifier = _identifier(package.get("SPDXID"))
        if identifier in known:
            raise ValueError("Duplicate SPDX identifier")
        known.add(identifier)
        name = package.get("name")
        if not isinstance(name, str) or not name.strip() or not isinstance(package.get("downloadLocation"), str):
            raise ValueError("SPDX package name and downloadLocation are required")
        if "filesAnalyzed" in package and not isinstance(package["filesAnalyzed"], bool):
            raise ValueError("SPDX filesAnalyzed must be a boolean")
        component = {"type": {"APPLICATION": "application", "FRAMEWORK": "framework", "LIBRARY": "library", "CONTAINER": "container", "OPERATING-SYSTEM": "operating-system", "DEVICE": "device", "FIRMWARE": "firmware", "FILE": "file"}.get(package.get("primaryPackagePurpose"), "library"),
                     "bom-ref": identifier, "name": name,
                     "properties": [{"name": "koda:spdx:package", "value": _json(package)}]}
        version = package.get("versionInfo")
        if version is not None:
            if not isinstance(version, str):
                raise ValueError("SPDX versionInfo must be a string")
            component["version"] = version
        purls, cpes = set(), set()
        for reference in _array(package.get("externalRefs", []), "externalRefs"):
            if not isinstance(reference, dict) or not all(isinstance(reference.get(key), str) for key in ("referenceCategory", "referenceType", "referenceLocator")):
                raise ValueError("Invalid SPDX external reference")
            if reference["referenceCategory"] == "PACKAGE-MANAGER" and reference["referenceType"] == "purl":
                if not reference["referenceLocator"].startswith("pkg:"):
                    raise ValueError("SPDX purl reference must contain a package URL")
                purls.add(reference["referenceLocator"])
            if reference["referenceCategory"] == "SECURITY" and reference["referenceType"] in {"cpe23Type", "cpe22Type"}:
                cpes.add(reference["referenceLocator"])
        if len(purls) > 1 or len(cpes) > 1:
            raise ValueError("Multiple conflicting package identity references require review")
        if purls:
            component["purl"] = next(iter(purls))
        if cpes:
            component["cpe"] = next(iter(cpes))
        checksums = []
        for checksum in _array(package.get("checksums", []), "checksums"):
            if not isinstance(checksum, dict) or not isinstance(checksum.get("algorithm"), str) or not isinstance(checksum.get("checksumValue"), str):
                raise ValueError("Invalid SPDX checksum")
            mapping = _CHECKSUMS.get(checksum["algorithm"])
            if mapping:
                if not re.fullmatch(r"[a-fA-F0-9]{" + str(mapping[1]) + "}", checksum["checksumValue"]):
                    raise ValueError("Invalid SPDX checksum digest")
                checksums.append({"alg": mapping[0], "content": checksum["checksumValue"].lower()})
        if checksums:
            component["hashes"] = checksums
        declared = package.get("licenseDeclared")
        if declared is not None and not isinstance(declared, str):
            raise ValueError("SPDX licenseDeclared must be a string")
        if declared and declared not in {"NOASSERTION", "NONE"}:
            component["licenses"] = [{"expression": declared}]
        if isinstance(package.get("supplier"), str) and package["supplier"].startswith("Organization: "):
            component["supplier"] = {"name": package["supplier"][14:]}
        for source, target in (("description", "description"), ("copyrightText", "copyright")):
            value = package.get(source)
            if isinstance(value, str) and value not in {"NOASSERTION", "NONE"}:
                component[target] = value
        component["externalReferences"] = []
        for source, kind in (("downloadLocation", "distribution"), ("homepage", "website")):
            value = package.get(source)
            if isinstance(value, str) and value not in {"NOASSERTION", "NONE", ""}:
                component["externalReferences"].append({"type": kind, "url": value})
        if not component["externalReferences"]:
            component.pop("externalReferences")
        components.append(component)
        by_id[identifier] = component
    for key in ("files", "snippets"):
        for item in _array(document.get(key, []), key):
            if not isinstance(item, dict):
                raise ValueError(f"SPDX {key} entry must be an object")
            identifier = _identifier(item.get("SPDXID"))
            if identifier in known:
                raise ValueError("Duplicate SPDX identifier")
            known.add(identifier)
    external_ids = set()
    for reference in _array(document.get("externalDocumentRefs", []), "externalDocumentRefs"):
        if not isinstance(reference, dict) or not isinstance(reference.get("externalDocumentId"), str) or not re.fullmatch(r"DocumentRef-[A-Za-z0-9.+-]+", reference["externalDocumentId"]):
            raise ValueError("Invalid SPDX external document reference")
        external_ids.add(reference["externalDocumentId"])

    def known_id(value):
        if not isinstance(value, str):
            return False
        if value in known or value in {"NONE", "NOASSERTION"}:
            return True
        prefix, marker, suffix = value.partition(":")
        return bool(marker and prefix in external_ids and _ID.fullmatch(suffix))

    relationships = _array(document.get("relationships", []), "relationships")
    dependencies = {key: set() for key in by_id}
    if len(relationships) > 500000:
        raise ValueError("SPDX relationship limit exceeded")
    for relation in relationships:
        if not isinstance(relation, dict) or not known_id(relation.get("spdxElementId")) or not known_id(relation.get("relatedSpdxElement")):
            raise ValueError("SPDX relationship references an unknown element")
        kind = relation.get("relationshipType")
        if not isinstance(kind, str) or not re.fullmatch(r"[A-Z][A-Z_]*", kind):
            raise ValueError("Invalid SPDX relationship type")
        source, target = relation["spdxElementId"], relation["relatedSpdxElement"]
        if kind == "DEPENDENCY_OF":
            source, target = target, source
        if kind in {"DEPENDS_ON", "DEPENDENCY_OF"} and source in by_id and target in by_id:
            dependencies[source].add(target)
    for identifier in _array(document.get("documentDescribes", []), "documentDescribes"):
        if not known_id(identifier):
            raise ValueError("SPDX documentDescribes references an unknown element")
    original_metadata = {key: value for key, value in document.items() if key not in {"packages", "relationships"}}
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, namespace)),
            "metadata": {"timestamp": creation["created"], "properties": [
                {"name": "koda:source-format", "value": "SPDX-2.3"},
                {"name": "koda:spdx:document", "value": _json(original_metadata)},
                {"name": "koda:spdx:relationships", "value": _json(relationships)}]},
            "components": components,
            "dependencies": [{"ref": key, "dependsOn": sorted(values)} for key, values in dependencies.items()]}
