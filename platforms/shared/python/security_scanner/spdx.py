"""SPDX 2.3 JSON export from CycloneDX evidence, using only the standard library.

Package identity and supplied relationships are preserved. Missing license,
supplier, copyright and download conclusions remain NOASSERTION. Retaining a
declared license never asserts that package files were analyzed or that a legal
license conclusion was reached.
"""
from __future__ import annotations

import hashlib
import base64
import json
import re
import uuid
from datetime import datetime, timezone

from . import __version__

_TOKEN = re.compile(r"\(|\)|[A-Za-z0-9][A-Za-z0-9.+-]*")
_HASHES = {"MD5": ("MD5", 32), "SHA-1": ("SHA1", 40), "SHA1": ("SHA1", 40),
           "SHA-224": ("SHA224", 56), "SHA-256": ("SHA256", 64), "SHA256": ("SHA256", 64),
           "SHA-384": ("SHA384", 96), "SHA384": ("SHA384", 96),
           "SHA-512": ("SHA512", 128), "SHA512": ("SHA512", 128),
           "SHA3-256": ("SHA3-256", 64), "SHA3-384": ("SHA3-384", 96), "SHA3-512": ("SHA3-512", 128),
           "BLAKE2b-256": ("BLAKE2b-256", 64), "BLAKE2b-384": ("BLAKE2b-384", 96),
           "BLAKE2b-512": ("BLAKE2b-512", 128), "BLAKE3": ("BLAKE3", 64)}


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _text(value, default="") -> str:
    return " ".join(str(value).split()) if value is not None else default


def _expression(value: str) -> bool:
    """Validate expression structure; SPDX IDs supplied by the source stay IDs."""
    if not value or len(value) > 4096 or "DocumentRef-" in value:
        return False
    tokens = _TOKEN.findall(value)
    if "".join(tokens) != re.sub(r"\s", "", value):
        return False
    if any(token.startswith("LicenseRef-") and not re.fullmatch(r"LicenseRef-[A-Za-z0-9.-]+", token) for token in tokens):
        return False
    position = 0

    def term():
        nonlocal position
        if position >= len(tokens):
            raise ValueError
        token = tokens[position]
        position += 1
        if token == "(":
            expression()
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError
            position += 1
        elif token in {"AND", "OR", "WITH", ")", "NONE", "NOASSERTION"}:
            raise ValueError
        if position < len(tokens) and tokens[position] == "WITH":
            if token == "(":
                raise ValueError
            position += 1
            if position >= len(tokens) or tokens[position] in {"AND", "OR", "WITH", "(", ")"}:
                raise ValueError
            position += 1

    def expression():
        nonlocal position
        term()
        while position < len(tokens) and tokens[position] in {"AND", "OR"}:
            position += 1
            term()

    try:
        expression()
        return position == len(tokens)
    except (ValueError, RecursionError):
        return False


def from_cyclonedx(bom: dict, *, product_name: str = "KODA scan") -> dict:
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX":
        raise ValueError("CycloneDX SBOM required for SPDX export")
    metadata = bom.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise ValueError("SBOM metadata must be an object")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    timestamp = metadata.get("timestamp")
    if isinstance(timestamp, str):
        try:
            source_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if source_time.tzinfo is not None:
                now = source_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass
    document = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
                "name": _text(metadata.get("component", {}).get("name") if isinstance(metadata.get("component"), dict) else product_name) or product_name,
                "documentNamespace": f"https://koda.invalid/spdx/{uuid.uuid4()}",
                "creationInfo": {"created": now, "creators": [f"Tool: KODA-{__version__}"]},
                "packages": [], "relationships": [], "documentDescribes": []}
    packages, references, relationships, extracted = document["packages"], {}, set(), {}

    def annotation(value):
        return {"annotationDate": now, "annotationType": "OTHER", "annotator": f"Tool: KODA-{__version__}", "comment": _json(value)}

    def register_reference(identifier, source=None):
        if identifier in extracted:
            return
        value = source or {}
        text = value.get("text")
        license_text = text.get("content") if isinstance(text, dict) and not text.get("encoding") else None
        if isinstance(text, dict) and text.get("encoding") == "base64" and isinstance(text.get("content"), str):
            try:
                license_text = base64.b64decode(text["content"], validate=True).decode("utf-8")
            except (ValueError, UnicodeError):
                license_text = None
        if not isinstance(license_text, str) or not license_text.strip():
            license_text = str(value.get("name") or identifier)
        extracted[identifier] = {"licenseId": identifier, "name": str(value.get("name") or identifier),
                                 "extractedText": license_text,
                                 "comment": "Source CycloneDX license reference; full license text is unavailable unless supplied in extractedText."}
        if isinstance(value.get("url"), str):
            extracted[identifier]["seeAlsos"] = [value["url"]]

    def declared(licenses):
        entries = []
        for value in licenses if isinstance(licenses, list) else []:
            if not isinstance(value, dict):
                continue
            expression = value.get("expression")
            license_value = value.get("license")
            if isinstance(expression, str) and expression in {"NONE", "NOASSERTION"}:
                entries.append(expression)
            elif isinstance(expression, str) and _expression(expression):
                entries.append(expression)
                for identifier in _TOKEN.findall(expression):
                    if identifier.startswith("LicenseRef-"):
                        register_reference(identifier)
            elif isinstance(license_value, dict):
                identifier = license_value.get("id")
                name = license_value.get("name")
                if any(isinstance(item, str) and item.strip().lower() in {"unknown", "noassertion", "unspecified", "unidentified", "n/a"} for item in (identifier, name)):
                    entries.append("NOASSERTION")
                elif (isinstance(identifier, str) and identifier == "NONE") or (isinstance(name, str) and name == "NONE"):
                    entries.append("NONE")
                elif isinstance(identifier, str) and _expression(identifier) and " " not in identifier and not any(token in identifier for token in ("(", ")")):
                    entries.append(identifier)
                    if identifier.startswith("LicenseRef-"):
                        register_reference(identifier, license_value)
                elif isinstance(name, str) and name.strip():
                    identifier = "LicenseRef-KODA-" + hashlib.sha256(_json(license_value).encode()).hexdigest()[:24]
                    register_reference(identifier, license_value)
                    entries.append(identifier)
        entries = list(dict.fromkeys(entries))
        # Independent entries do not specify AND versus OR. Keep their complete
        # source in annotations rather than inventing a license expression.
        return entries[0] if len(entries) == 1 else "NOASSERTION"

    by_occurrence = {}
    descriptions = []

    def add(component, path, parent=None):
        if not isinstance(component, dict):
            raise ValueError("SBOM component must be an object")
        if len(packages) >= 50000 or len(path) > 128:
            raise ValueError("SPDX export component limit exceeded")
        original = {key: value for key, value in component.items() if key != "components"}
        ref = component.get("bom-ref")
        identity = _json({"ref": ref, "purl": component.get("purl"), "group": component.get("group"),
                          "name": component.get("name"), "version": component.get("version"), "hashes": component.get("hashes")})
        occurrence = (str(ref) if ref else "", _json(original))
        identifier = by_occurrence.get(occurrence)
        if identifier is None:
            identifier = "SPDXRef-Package-" + hashlib.sha256((identity + "/" + "/".join(path)).encode()).hexdigest()[:32]
            by_occurrence[occurrence] = identifier
            package = {"SPDXID": identifier, "name": _text(component.get("name")) or "NOASSERTION",
                       "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                       "licenseConcluded": "NOASSERTION", "licenseDeclared": declared(component.get("licenses")),
                       "copyrightText": component.get("copyright") if isinstance(component.get("copyright"), str) and component["copyright"] else "NOASSERTION",
                       "supplier": "NOASSERTION", "annotations": [annotation({"cyclonedxComponent": original})]}
            if component.get("version"):
                package["versionInfo"] = str(component["version"])
            supplier = component.get("supplier")
            if isinstance(supplier, dict) and supplier.get("name"):
                package["supplier"] = "Organization: " + _text(supplier["name"])
            if isinstance(component.get("description"), str):
                package["description"] = component["description"]
            purpose = {"application": "APPLICATION", "framework": "FRAMEWORK", "library": "LIBRARY", "container": "CONTAINER", "operating-system": "OPERATING-SYSTEM", "device": "DEVICE", "firmware": "FIRMWARE", "file": "FILE"}.get(component.get("type")) if isinstance(component.get("type"), str) else None
            if purpose:
                package["primaryPackagePurpose"] = purpose
            checksums = []
            for checksum in component.get("hashes", []) if isinstance(component.get("hashes", []), list) else []:
                if not isinstance(checksum, dict):
                    continue
                mapping, digest = _HASHES.get(checksum.get("alg")) if isinstance(checksum.get("alg"), str) else None, checksum.get("content")
                if mapping and isinstance(digest, str) and re.fullmatch(r"[a-fA-F0-9]{" + str(mapping[1]) + "}", digest):
                    checksums.append({"algorithm": mapping[0], "checksumValue": digest.lower()})
            if checksums:
                package["checksums"] = checksums
            external = []
            if isinstance(component.get("purl"), str) and component["purl"]:
                external.append({"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": component["purl"]})
            cpe = component.get("cpe")
            if isinstance(cpe, str) and cpe.startswith(("cpe:2.3:", "cpe:/")):
                external.append({"referenceCategory": "SECURITY", "referenceType": "cpe23Type" if cpe.startswith("cpe:2.3:") else "cpe22Type", "referenceLocator": cpe})
            if external:
                package["externalRefs"] = external
            for reference in component.get("externalReferences", []) if isinstance(component.get("externalReferences", []), list) else []:
                if not isinstance(reference, dict) or not isinstance(reference.get("url"), str):
                    continue
                if reference.get("type") == "distribution" and package["downloadLocation"] == "NOASSERTION":
                    package["downloadLocation"] = reference["url"]
                if reference.get("type") == "website":
                    package["homepage"] = reference["url"]
            packages.append(package)
            if isinstance(ref, str) and ref:
                references.setdefault(ref, []).append(identifier)
        if parent:
            relationships.add((parent, "CONTAINS", identifier))
        children = component.get("components", [])
        if not isinstance(children, list):
            raise ValueError("Nested SBOM components must be a list")
        for index, child in enumerate(children):
            add(child, (*path, str(index)), identifier)
        return identifier

    root = metadata.get("component")
    if isinstance(root, dict):
        descriptions.append(add(root, ("metadata",)))
    components = bom.get("components", [])
    if not isinstance(components, list):
        raise ValueError("SBOM components must be a list")
    top_level = [add(component, ("components", str(index))) for index, component in enumerate(components)]
    if not descriptions:
        descriptions = top_level
    for identifier in descriptions:
        relationships.add(("SPDXRef-DOCUMENT", "DESCRIBES", identifier))
    document["documentDescribes"] = list(dict.fromkeys(descriptions))
    dependencies = bom.get("dependencies", [])
    unresolved = []
    for relation in dependencies if isinstance(dependencies, list) else []:
        if not isinstance(relation, dict):
            unresolved.append(relation)
            continue
        source = references.get(relation.get("ref"), []) if isinstance(relation.get("ref"), str) else []
        for target in relation.get("dependsOn", []) if isinstance(relation.get("dependsOn", []), list) else []:
            destination = references.get(target, []) if isinstance(target, str) else []
            if len(source) == 1 and len(destination) == 1:
                relationships.add((source[0], "DEPENDS_ON", destination[0]))
            else:
                unresolved.append({"ref": relation.get("ref"), "dependsOn": target})
    document["relationships"] = [{"spdxElementId": source, "relationshipType": kind, "relatedSpdxElement": destination} for source, kind, destination in sorted(relationships)]
    document["annotations"] = [annotation({"cyclonedxMetadata": metadata, "cyclonedxSerialNumber": bom.get("serialNumber"),
                                          "cyclonedxDependencies": dependencies, "unresolvedRelationships": unresolved})]
    if extracted:
        document["hasExtractedLicensingInfos"] = [extracted[key] for key in sorted(extracted)]
    return document
