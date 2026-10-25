"""Versioned offline intelligence interchange. Standard library only; no HTTP.

Publisher formats are deliberately limited. Unsupported OVAL constructs and
unresolved supplier products are retained as unknown evidence, never as fixes.
"""
from __future__ import annotations

import bz2
import base64
import copy
import csv
import gzip
import hashlib
import io
import json
import math
import re
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

FORMAT = "koda-offline-intelligence-v1"
KINDS = frozenset({"epss", "vulnrichment", "csaf", "vex", "ubuntu-oval", "lifecycle", "cpe-dictionary", "cpe-match", "cwe", "spdx", "package-metadata"})
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 512 * 1024 * 1024
MAX_RECORDS = 1_000_000
MAX_SOURCES = 4096
CVE = re.compile(r"CVE-\d{4}-\d{4,}")
DEFAULT_AGES = {"epss": 7, "vulnrichment": 30, "csaf": 90, "vex": 90, "ubuntu-oval": 30, "lifecycle": 30,
                "cpe-dictionary": 365, "cpe-match": 30, "cwe": 365, "spdx": 365, "package-metadata": 30}


def _day(value) -> str:
    if not isinstance(value, str):
        raise ValueError("data date is required")
    if len(value) == 10:
        return date.fromisoformat(value).isoformat()
    return _time(value).date().isoformat()


def _time(value) -> datetime:
    result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamp requires timezone")
    return result.astimezone(timezone.utc)


def source_status(source: dict, *, at=None) -> dict:
    at = at or datetime.now(timezone.utc)
    result = copy.deepcopy(source)
    try:
        age = (at.date() - date.fromisoformat(_day(source["dataDate"]))).days
        result.update(ageDays=age, status="future" if age < -1 else "fresh" if age <= source["maxAgeDays"] else "stale")
    except (ValueError, TypeError, KeyError):
        result.update(ageDays=None, status="unknown")
    return result


def _expanded(raw: bytes) -> bytes:
    if not raw or len(raw) > MAX_FILE_BYTES:
        raise ValueError("source size limit exceeded")
    if raw.startswith(b"\x1f\x8b"):
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    elif raw.startswith(b"BZh"):
        with bz2.BZ2File(io.BytesIO(raw)) as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("expanded source size limit exceeded")
    return raw


def _json(raw: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON number")))


def _xml(raw: bytes):
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("XML entities and DTDs are not supported")
    root = ET.fromstring(raw)
    stack = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > 64:
            raise ValueError("XML nesting limit exceeded")
        stack.extend((child, depth + 1) for child in node)
    return root


def _tag(node):
    return node.tag.rsplit("}", 1)[-1]


def _children(node, name):
    return [child for child in node if _tag(child) == name]


def _text(node, name):
    child = next(iter(_children(node, name)), None)
    return "".join(child.itertext()).strip() if child is not None else ""


def _walk(value, depth=0):
    if depth > 64:
        raise ValueError("JSON nesting limit exceeded")
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from _walk(nested, depth + 1)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk(nested, depth + 1)


def _epss(raw):
    first, sep, body = raw.decode("utf-8-sig").partition("\n")
    parts = first.removeprefix("#").strip().split(",")
    metadata = dict(part.split(":", 1) for part in parts)
    if not sep or not first.startswith("#") or len(parts) != 2 or set(metadata) != {"model_version", "score_date"}:
        raise ValueError("FIRST daily EPSS metadata required")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", metadata["model_version"]):
        raise ValueError("invalid EPSS model version")
    day = _day(metadata["score_date"])
    rows = csv.DictReader(io.StringIO(body), strict=True)
    if rows.fieldnames != ["cve", "epss", "percentile"]:
        raise ValueError("invalid EPSS columns")
    records, seen = [], set()
    for row in rows:
        cve = str(row.get("cve", "")).upper()
        if None in row or not CVE.fullmatch(cve) or cve in seen:
            raise ValueError("invalid or duplicate EPSS CVE")
        values = [float(row[key]) for key in ("epss", "percentile")]
        if not all(math.isfinite(value) and 0 <= value <= 1 for value in values):
            raise ValueError("invalid EPSS probability")
        seen.add(cve)
        records.append({"cve": cve, "epss": values[0], "percentile": values[1], "date": day, "modelVersion": metadata["model_version"]})
        if len(records) > MAX_RECORDS:
            raise ValueError("EPSS record limit exceeded")
    return records, day


def _vulnrichment(payload):
    documents = payload if isinstance(payload, list) else payload.get("vulnerabilities", [payload])
    records = []
    for document in documents:
        cve = str(document.get("cveMetadata", {}).get("cveId", "")).upper()
        if not CVE.fullmatch(cve):
            raise ValueError("CVE5 cveMetadata.cveId is required")
        for container in document.get("containers", {}).get("adp", []):
            provider = container.get("providerMetadata", {})
            if provider.get("shortName", "").upper() not in {"CISA-ADP", "CISA"} and provider.get("orgId") != "85b1779b-9628-4f52-b2d3-68c9b58f9abb":
                continue
            for metric in container.get("metrics", []):
                other = metric.get("other", {})
                if str(other.get("type", "")).lower() != "ssvc":
                    continue
                content = other.get("content", {})
                options = {}
                for option in content.get("options", []):
                    for key, value in option.items():
                        if key in options:
                            raise ValueError("duplicate SSVC option")
                        options[key] = str(value).lower()
                row = {"cve": cve, "exploitation": options.get("Exploitation"), "automatable": options.get("Automatable"),
                       "technicalImpact": options.get("Technical Impact"), "timestamp": content.get("timestamp"),
                       "ssvcVersion": content.get("version"), "role": content.get("role"), "organization": provider.get("shortName", "CISA-ADP")}
                if row["exploitation"] not in {"none", "poc", "active"} or row["automatable"] not in {"yes", "no"} or row["technicalImpact"] not in {"partial", "total"}:
                    raise ValueError("unsupported SSVC option value")
                if row["timestamp"]:
                    _time(row["timestamp"])
                records.append(row)
    return records, max((_day(row["timestamp"]) for row in records if row.get("timestamp")), default=None)


def _csaf(payload):
    document = payload.get("document", {})
    if document.get("csaf_version") not in {"2.0", "2.1"}:
        raise ValueError("CSAF 2.0/2.1 is required")
    products = {}
    for item in _walk(payload.get("product_tree", {})):
        if "product_id" in item and "name" in item:
            if item["product_id"] in products and products[item["product_id"]] != item:
                raise ValueError("conflicting CSAF product ID")
            products[item["product_id"]] = item
    records = []
    for vulnerability in payload.get("vulnerabilities", []):
        cve = vulnerability.get("cve")
        if not isinstance(cve, str) or not CVE.fullmatch(cve):
            continue
        for status, identifiers in vulnerability.get("product_status", {}).items():
            for identifier in identifiers:
                product = products.get(identifier, {})
                helper = product.get("product_identification_helper", {})
                purl = helper.get("purl") or next(iter(helper.get("purls", [])), "")
                cpe = helper.get("cpe", "")
                remedies = [item for item in vulnerability.get("remediations", []) if identifier in item.get("product_ids", [])]
                records.append({"advisoryId": document.get("tracking", {}).get("id"), "cve": cve, "productId": identifier,
                                "productName": product.get("name", ""), "purl": purl, "cpe": cpe, "status": status,
                                "justification": "", "remediation": remedies, "issuedAt": document.get("tracking", {}).get("current_release_date"),
                                "supported": bool(purl or cpe) and status in {"known_affected", "known_not_affected", "fixed", "under_investigation"}})
    return records, document.get("tracking", {}).get("current_release_date")


def _vex(payload):
    if payload.get("bomFormat") == "CycloneDX":
        products = {item.get("bom-ref"): item for item in payload.get("components", [])}
        records = []
        for item in payload.get("vulnerabilities", []):
            for affect in item.get("affects", []):
                product = products.get(affect.get("ref"), {})
                records.append({"advisoryId": payload.get("serialNumber", ""), "cve": item.get("id"), "productId": affect.get("ref", ""),
                                "productName": product.get("name", ""), "purl": product.get("purl", ""), "cpe": product.get("cpe", ""),
                                "status": item.get("analysis", {}).get("state", "under_investigation"),
                                "justification": item.get("analysis", {}).get("justification", ""), "remediation": item.get("analysis", {}).get("detail", ""),
                                "issuedAt": item.get("updated") or item.get("published"), "supported": bool(product.get("purl") or product.get("cpe")) and not affect.get("versions")})
        return records, payload.get("metadata", {}).get("timestamp")
    if not str(payload.get("@context", "")).startswith("https://openvex.dev/ns/v0.2"):
        raise ValueError("OpenVEX v0.2 or CycloneDX VEX required")
    records = []
    for statement in payload.get("statements", []):
        for product in statement.get("products", []):
            identifier = product.get("@id", "")
            identifiers = product.get("identifiers", {})
            records.append({"advisoryId": payload.get("@id", ""), "cve": statement.get("vulnerability", {}).get("name") or statement.get("vulnerability", {}).get("@id"),
                            "productId": identifier, "productName": "", "purl": identifiers.get("purl") or (identifier if identifier.startswith("pkg:") else ""),
                            "cpe": identifiers.get("cpe23") or (identifier if identifier.startswith("cpe:2.3:") else ""),
                            "status": statement.get("status"), "justification": statement.get("justification", ""),
                            "remediation": statement.get("action_statement", ""), "issuedAt": statement.get("timestamp") or payload.get("timestamp"),
                            "supported": bool(identifiers.get("purl") or identifiers.get("cpe23") or identifier.startswith(("pkg:", "cpe:2.3:")))})
    return records, payload.get("timestamp")


def _lifecycle(payload):
    result = payload.get("result")
    if not str(payload.get("schema_version", "")).startswith("1.") or not isinstance(result, dict) or not isinstance(result.get("releases"), list):
        raise ValueError("endoflife.date v1 product detail required")
    records = []
    for release in result["releases"]:
        latest = release.get("latest") or {}
        records.append({"product": result.get("name"), "cycle": str(release.get("name", "")), "identifiers": result.get("identifiers", []),
                        "eolDate": release.get("eolFrom"), "isEol": release.get("isEol"), "latestVersion": latest.get("name"),
                        "latestDate": latest.get("date"), "eoasDate": release.get("eoasFrom")})
    return records, payload.get("generated_at") or payload.get("last_modified")


def _references(kind, raw, payload):
    if kind == "cpe-match":
        records = []
        for item in payload.get("matchStrings", []):
            value = item.get("matchString", item)
            records.append({key: value[key] for key in ("matchCriteriaId", "criteria", "status", "matches", "versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding") if key in value})
        return records, payload.get("timestamp")
    if kind == "cpe-dictionary":
        if payload is not None:
            return [{"cpeName": item["cpe"]["cpeName"], "cpeNameId": item["cpe"].get("cpeNameId"), "deprecated": item["cpe"].get("deprecated", False), "titles": item["cpe"].get("titles", [])} for item in payload.get("products", [])], payload.get("timestamp")
        root = _xml(raw)
        records = []
        for item in root.iter():
            if _tag(item) != "cpe-item":
                continue
            names = [node.attrib.get("name") for node in item if _tag(node) == "cpe23-item"]
            if names:
                records.append({"cpeName": names[0], "cpeNameId": "", "deprecated": item.attrib.get("deprecated") == "true", "titles": [node.text or "" for node in item if _tag(node) == "title"]})
        return records, None
    if kind == "cwe":
        root = _xml(raw)
        records = []
        for item in root.iter():
            if _tag(item) != "Weakness":
                continue
            mappings = [(node.text or "").strip() for node in item.iter() if _tag(node) == "Usage"]
            records.append({"id": int(item.attrib["ID"]), "name": item.attrib.get("Name", ""), "status": item.attrib.get("Status", ""),
                            "abstraction": item.attrib.get("Abstraction", ""), "description": _text(item, "Description"), "mappingUsage": mappings})
        return records, root.attrib.get("Date")
    if kind == "spdx":
        values = [(value, "license") for value in payload.get("licenses", [])] + [(value, "exception") for value in payload.get("exceptions", [])]
        return [{"id": value.get("licenseId") or value.get("licenseExceptionId"), "name": value.get("name", ""), "licenseType": kind,
                 "isDeprecatedLicenseId": value.get("isDeprecatedLicenseId", False), "isOsiApproved": value.get("isOsiApproved", False),
                 "reference": value.get("reference", "")} for value, kind in values], payload.get("releaseDate")
    if kind == "package-metadata":
        if payload.get("format") != "koda-package-metadata-v1" or not isinstance(payload.get("items"), list):
            raise ValueError("existing koda-package-metadata-v1 export required")
        return payload["items"], payload.get("exportedAt")
    raise ValueError("unsupported reference format")


def _oval(raw):
    root = _xml(raw)
    objects, states, tests = {}, {}, {}
    for node in root.iter():
        name = _tag(node)
        if name == "dpkginfo_object":
            objects[node.attrib["id"]] = {"package": _text(node, "name"), "supported": len(node) == 1 and all(child.attrib.get("operation", "equals") == "equals" and child.attrib.get("datatype", "string") == "string" and "var_ref" not in child.attrib for child in node)}
        elif name == "dpkginfo_state":
            fields = {_tag(child): child for child in node}
            evr = fields.get("evr")
            states[node.attrib["id"]] = {"version": evr.text if evr is not None else "", "operation": evr.attrib.get("operation", "equals") if evr is not None else "equals",
                                        "supported": set(fields) == {"evr"} and evr is not None and evr.attrib.get("datatype", "evr_string") == "evr_string" and "var_ref" not in evr.attrib}
        elif name.endswith("_test"):
            obj = next(iter(_children(node, "object")), None)
            st = _children(node, "state")
            tests[node.attrib["id"]] = {"type": name, "objectRef": obj.attrib.get("object_ref") if obj is not None else None,
                                        "stateRefs": [item.attrib.get("state_ref") for item in st], "check": node.attrib.get("check", "all"),
                                        "checkExistence": node.attrib.get("check_existence", "at_least_one_exists"), "stateOperator": node.attrib.get("state_operator", "AND")}
    for test in tests.values():
        obj = objects.get(test["objectRef"], {})
        selected = [states.get(ref, {}) for ref in test["stateRefs"]]
        test.update(package=obj.get("package", ""), states=selected)
        test["supported"] = test["type"] == "dpkginfo_test" and obj.get("supported") is True and bool(selected) and all(state.get("supported") is True and state["operation"] in {"equals", "less than", "less than or equal", "greater than", "greater than or equal", "not equal"} for state in selected) and test["check"] in {"all", "at least one"} and test["checkExistence"] == "at_least_one_exists" and test["stateOperator"] in {"AND", "OR"}
    def criteria(node):
        result = {"operator": node.attrib.get("operator", "AND"), "negate": node.attrib.get("negate", "false") == "true", "children": [], "tests": [], "supported": True}
        if result["operator"] not in {"AND", "OR"}:
            result["supported"] = False
        for child in node:
            name = _tag(child)
            if name == "criteria":
                value = criteria(child)
                result["children"].append(value)
                result["supported"] = result["supported"] and value["supported"]
            elif name == "criterion":
                ref = child.attrib.get("test_ref", "")
                result["tests"].append({"id": ref, "negate": child.attrib.get("negate", "false") == "true"})
                result["supported"] = result["supported"] and tests.get(ref, {}).get("supported", False) and not (set(child.attrib) - {"test_ref", "negate", "comment"})
            else:
                result["supported"] = False
        result["supported"] = bool(result["supported"] and (result["tests"] or result["children"]))
        return result
    records = []
    for definition in root.iter():
        if _tag(definition) != "definition":
            continue
        references = [node.attrib.get("ref_id", "") for node in definition.iter() if _tag(node) == "reference" and node.attrib.get("source", "").upper() == "CVE"]
        platforms = [node.text or "" for node in definition.iter() if _tag(node) == "platform"]
        node = next(iter(_children(definition, "criteria")), None)
        parsed = criteria(node) if node is not None else {"supported": False}
        def refs(value):
            return {item["id"] for item in value.get("tests", [])} | set().union(*(refs(child) for child in value.get("children", []))) if value.get("children") else {item["id"] for item in value.get("tests", [])}
        selected_tests = {ref: tests[ref] for ref in sorted(refs(parsed)) if ref in tests}
        records.append({"id": definition.attrib.get("id"), "cves": references, "platforms": platforms, "criteria": parsed,
                        "tests": selected_tests, "supported": parsed["supported"] and bool(platforms), "unsupportedReasons": [] if parsed["supported"] else ["unsupported OVAL test, variable, object, or criterion"]})
    return records, next((node.text for node in root.iter() if _tag(node) == "timestamp"), None)


def _normalize_source(kind: str, raw: bytes, source: dict) -> dict:
    if kind not in KINDS:
        raise ValueError("unsupported dataset kind")
    original = raw
    raw = _expanded(raw)
    payload = None if kind in {"cwe", "ubuntu-oval"} or raw.removeprefix(b"\xef\xbb\xbf").lstrip().startswith(b"<") else (_json(raw) if kind != "epss" else None)
    if kind == "epss": records, publisher_date = _epss(raw)
    elif kind == "vulnrichment": records, publisher_date = _vulnrichment(payload)
    elif kind == "csaf": records, publisher_date = _csaf(payload)
    elif kind == "vex": records, publisher_date = _vex(payload)
    elif kind == "lifecycle": records, publisher_date = _lifecycle(payload)
    elif kind == "ubuntu-oval": records, publisher_date = _oval(raw)
    else: records, publisher_date = _references(kind, raw, payload)
    if not records or len(records) > MAX_RECORDS:
        raise ValueError("empty or oversized dataset")
    source = {key: value for key, value in source.items() if key not in {"status", "ageDays"}}
    publisher_day = _day(publisher_date) if publisher_date else None
    supplied_day = source.get("dataDate")
    if publisher_day and supplied_day and _day(supplied_day) != publisher_day:
        raise ValueError("source dataDate differs from publisher date")
    envelope = payload if isinstance(payload, dict) else {}
    versions = {"epss": "FIRST-EPSS-daily-CSV", "vulnrichment": "CVE5-CISA-ADP", "csaf": "CSAF-" + str(envelope.get("document", {}).get("csaf_version", "unknown")),
                "vex": "CycloneDX-" + str(envelope.get("specVersion", "unknown")) if envelope.get("bomFormat") == "CycloneDX" else "OpenVEX-0.2",
                "ubuntu-oval": "OVAL5-dpkginfo-subset", "lifecycle": "endoflife-v" + str(envelope.get("schema_version", "unknown")),
                "cpe-dictionary": "NVD-CPE-2.0" if payload is not None else "CPE-Dictionary-2.3", "cpe-match": "NVD-CPEMatch-2.0",
                "cwe": "CWE-Catalog-XML", "spdx": "SPDX-LicenseList-" + str(envelope.get("licenseListVersion", "unknown")), "package-metadata": "koda-package-metadata-v1"}
    source.update(dataDate=publisher_day or _day(supplied_day), dateBasis="publisher" if publisher_day else "operator", schemaVersion=versions[kind],
                  sha256=hashlib.sha256(original).hexdigest(), sizeBytes=len(original), recordCount=len(records))
    if kind == "epss":
        source["sourceVersion"] = records[0]["modelVersion"]
    source.setdefault("maxAgeDays", DEFAULT_AGES[kind])
    for record in records:
        record["sourceId"] = source["id"]
    return {"sources": [source], "records": records}


def normalize_source(kind: str, raw: bytes, source: dict) -> dict:
    try:
        return _normalize_source(kind, raw, source)
    except (KeyError, TypeError, AttributeError, OSError, EOFError, UnicodeError, csv.Error, ET.ParseError, RecursionError) as exc:
        raise ValueError(f"invalid {kind} source document") from exc


def _validate_record(kind, row):
    if kind in {"epss", "vulnrichment", "csaf", "vex"}:
        if not isinstance(row.get("cve"), str) or not CVE.fullmatch(row["cve"]):
            raise ValueError("record CVE is invalid")
    if kind == "epss":
        for key in ("epss", "percentile"):
            value = row.get(key)
            if type(value) not in {float, int} or not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError("record EPSS probability is invalid")
        _day(row.get("date"))
    elif kind == "vulnrichment":
        if row.get("exploitation") not in {"none", "poc", "active"} or row.get("automatable") not in {"yes", "no"} or row.get("technicalImpact") not in {"partial", "total"}:
            raise ValueError("invalid normalized SSVC evidence")
    elif kind in {"csaf", "vex"}:
        if not isinstance(row.get("status"), str) or type(row.get("supported")) is not bool:
            raise ValueError("invalid supplier status")
        if row["supported"] and not (str(row.get("purl", "")).startswith("pkg:") or str(row.get("cpe", "")).startswith("cpe:2.3:")):
            raise ValueError("supplier products require exact identifiers")
    elif kind == "lifecycle":
        if not isinstance(row.get("product"), str) or not row["product"] or not isinstance(row.get("cycle"), str):
            raise ValueError("invalid lifecycle identity")
        if row.get("eolDate") is not None:
            _day(row["eolDate"])
        if row.get("isEol") is not None and type(row["isEol"]) is not bool:
            raise ValueError("invalid lifecycle EOL status")
    elif kind == "cpe-dictionary":
        if not str(row.get("cpeName", "")).startswith("cpe:2.3:"):
            raise ValueError("invalid dictionary CPE")
    elif kind == "cpe-match":
        if not str(row.get("criteria", "")).startswith("cpe:2.3:") or not row.get("matchCriteriaId"):
            raise ValueError("invalid CPE match criteria")
    elif kind == "cwe":
        if type(row.get("id")) is not int or not 0 < row["id"] < 100000 or not isinstance(row.get("name"), str):
            raise ValueError("invalid CWE reference")
    elif kind == "spdx":
        if not isinstance(row.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9.+-]{1,128}", row["id"]):
            raise ValueError("invalid SPDX license identifier")
    elif kind == "package-metadata":
        if not str(row.get("purl", "")).startswith("pkg:") or not row.get("currentVersion"):
            raise ValueError("invalid package metadata identity")
    elif kind == "ubuntu-oval":
        if not isinstance(row.get("cves"), list) or not isinstance(row.get("criteria"), dict) or not isinstance(row.get("tests"), dict) or type(row.get("supported")) is not bool:
            raise ValueError("invalid OVAL definition")


def validate_document(document: dict, root: Path | None = None, *, at=None) -> dict:
    if not isinstance(document, dict) or document.get("format") != FORMAT or not isinstance(document.get("datasets"), dict):
        raise ValueError("koda-offline-intelligence-v1 document required")
    _time(document.get("createdAt"))
    result = copy.deepcopy(document)
    total = total_bytes = total_records = 0
    at = at or datetime.now(timezone.utc)
    for kind, dataset in result["datasets"].items():
        if kind not in KINDS or not isinstance(dataset, dict) or not isinstance(dataset.get("sources"), list) or not isinstance(dataset.get("records"), list):
            raise ValueError("invalid dataset kind or collection")
        sources = {}
        for source in dataset["sources"]:
            if not isinstance(source, dict) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", str(source.get("id", ""))) or source["id"] in sources:
                raise ValueError("invalid or duplicate source ID")
            if set(source) - {"id", "sourceUrl", "resolvedSourceUrl", "redirectChain", "dataDate", "fetchedAt", "sha256", "sizeBytes", "sourceFile", "maxAgeDays", "recordCount", "dateBasis", "rawBase64", "originalVerified", "status", "ageDays", "sourceVersion", "schemaVersion"}:
                raise ValueError("unknown source metadata field")
            parsed = urlsplit(str(source.get("sourceUrl", "")))
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
                raise ValueError("sourceUrl must be credential-free HTTPS")
            if "redirectChain" in source:
                chain = source["redirectChain"]
                if not isinstance(chain, list) or not 1 <= len(chain) <= 6 or chain[0] != source["sourceUrl"] or chain[-1] != source.get("resolvedSourceUrl"):
                    raise ValueError("invalid source redirect trace")
                for link in chain:
                    target = urlsplit(link)
                    if target.scheme != "https" or not target.hostname or target.username or target.password or target.fragment:
                        raise ValueError("invalid source redirect URL")
            _day(source.get("dataDate"))
            if (_time(source.get("fetchedAt")) - at).total_seconds() > 86400:
                raise ValueError("source fetchedAt is in the future")
            if not re.fullmatch(r"[a-f0-9]{64}", str(source.get("sha256", ""))) or type(source.get("sizeBytes")) is not int or not 0 < source["sizeBytes"] <= MAX_FILE_BYTES:
                raise ValueError("invalid source hash or size")
            if type(source.get("maxAgeDays")) is not int or not 0 <= source["maxAgeDays"] <= 3650:
                raise ValueError("invalid maxAgeDays")
            total_bytes += source["sizeBytes"]
            if total_bytes > MAX_TOTAL_SOURCE_BYTES:
                raise ValueError("total original source size limit exceeded")
            path = source.get("sourceFile")
            raw = None
            if path:
                if not isinstance(path, str) or not re.fullmatch(r"intelligence-sources/[a-f0-9]{64}\.[a-z0-9.]+", path):
                    raise ValueError("unsafe sourceFile")
                if root is not None:
                    original_path = root / path
                    target = original_path.resolve()
                    if root.resolve() not in target.parents or not target.is_file() or original_path.is_symlink() or (root / "intelligence-sources").is_symlink():
                        raise ValueError("source file is missing or unsafe")
                    if target.stat().st_size != source["sizeBytes"]:
                        raise ValueError("source size mismatch")
                    raw = target.read_bytes()
            elif root is not None:
                raise ValueError("bundled intelligence requires original sourceFile")
            if root is None:
                inline = source.get("rawBase64")
                if not isinstance(inline, str) or len(inline) > MAX_FILE_BYTES * 4 // 3 + 8:
                    raise ValueError("JSON import requires original rawBase64 source evidence")
                try:
                    raw = base64.b64decode(inline, validate=True)
                except (ValueError, TypeError) as exc:
                    raise ValueError("invalid inline source bytes") from exc
            if raw is not None:
                if len(raw) != source["sizeBytes"] or hashlib.sha256(raw).hexdigest() != source["sha256"]:
                    raise ValueError("source hash or size mismatch")
                normalized = normalize_source(kind, raw, source)
                expected = normalized["records"]
                regenerated = normalized["sources"][0]
                for field in ("dataDate", "dateBasis", "schemaVersion", "sourceVersion"):
                    if source.get(field) != regenerated.get(field):
                        raise ValueError(f"source {field} differs from original")
                observed = [row for row in dataset["records"] if row.get("sourceId") == source["id"]]
                if expected != observed:
                    raise ValueError("normalized records differ from source")
                if source.get("recordCount") != len(expected):
                    raise ValueError("source recordCount mismatch")
                source["originalVerified"] = True
            sources[source["id"]] = source
            total += 1
        if not sources or total > MAX_SOURCES or not dataset["records"] or len(dataset["records"]) > MAX_RECORDS:
            raise ValueError("dataset limits exceeded")
        total_records += len(dataset["records"])
        if total_records > MAX_RECORDS:
            raise ValueError("document record limit exceeded")
        for record in dataset["records"]:
            if not isinstance(record, dict) or record.get("sourceId") not in sources:
                raise ValueError("record references unknown source")
            _validate_record(kind, record)
            # Bounds and finite values apply to imported normalized JSON as well.
            encoded = json.dumps(record, allow_nan=False)
            if len(encoded) > 2 * 1024 * 1024:
                raise ValueError("record size limit exceeded")
        dataset["sources"] = [source_status(source, at=at) for source in sources.values()]
    return result


def load_intelligence(root: Path, index="intelligence.json", *, at=None) -> dict:
    root = Path(root)
    if index != "intelligence.json":
        raise ValueError("invalid intelligence index filename")
    path = root / index
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("intelligence index missing or oversized")
    return validate_document(_json(path.read_bytes()), root, at=at)
