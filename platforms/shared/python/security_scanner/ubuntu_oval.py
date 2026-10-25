"""Bounded review-only evaluator for the imported dpkginfo OVAL subset.

No network, scripts, shell expansion, package installation, or scanner verdict changes.
Exact Ubuntu platform and inventory names are mandatory; incomplete constructs stay unknown.
"""
from __future__ import annotations
import re
import shutil
import subprocess
from urllib.parse import parse_qs, unquote

OPERATIONS = {"equals": "eq", "not equal": "ne", "less than": "lt", "less than or equal": "le", "greater than": "gt", "greater than or equal": "ge"}

def evaluate_definition(record, components, *, platform=None, comparator=None):
    budget = [128]
    inventory = {}
    platforms = set()
    for component in components:
        purl = str(component.get("purl") or "")
        if not purl.startswith("pkg:deb/ubuntu/"): continue
        path, _, query = purl.partition("?")
        name, marker, version = path.rpartition("/")[2].rpartition("@")
        if marker and name and version: inventory.setdefault(unquote(name), set()).add(unquote(version))
        distro = parse_qs(query).get("distro", [])
        for value in distro:
            match = re.fullmatch(r"ubuntu-(\d{2}\.\d{2})", value)
            if match: platforms.add("Ubuntu " + match[1] + " LTS")
    if platform: platforms.add(platform)
    allowed = set(record.get("platforms") or [])
    if len(platforms) != 1 or not allowed.intersection(platforms): return {"status": "unknown", "reason": "exact_ubuntu_platform_required"}
    if not record.get("supported"): return {"status": "unknown", "reason": "unsupported_oval_construct"}
    binary = shutil.which("dpkg") if comparator is None else None
    if comparator is None and not binary: return {"status": "unknown", "reason": "dpkg_unavailable"}
    def compare(left, operation, right):
        if operation not in OPERATIONS: return None
        if comparator is not None: return comparator(left, operation, right)
        if not all(isinstance(value, str) and len(value) <= 255 and re.fullmatch(r"[A-Za-z0-9.+:~_-]+", value) for value in (left,right)): return None
        try:
            process = subprocess.run([binary, "--compare-versions", left, OPERATIONS[operation], right], capture_output=True, timeout=1, check=False)
            return True if process.returncode == 0 else False if process.returncode == 1 else None
        except (OSError, subprocess.TimeoutExpired): return None
    def combine(values, operator):
        if not values or operator not in {"AND", "OR"}: return None
        if operator == "AND": return False if False in values else None if None in values else True
        return True if True in values else None if None in values else False
    def test(identifier):
        budget[0] -= 1
        if budget[0] < 0: return None
        item = record.get("tests", {}).get(identifier, {})
        if not item.get("supported") or item.get("checkExistence") != "at_least_one_exists": return None
        versions = inventory.get(item.get("package"), set())
        # Missing inventory is incomplete evidence, never an absent-package proof.
        if len(versions) != 1 or not item.get("states"): return None
        version = next(iter(versions))
        values = [compare(version, state.get("operation"), state.get("version")) if state.get("supported") else None for state in item["states"]]
        return combine(values, item.get("stateOperator", "AND"))
    def criterion(node, depth=0):
        budget[0] -= 1
        if depth > 16 or budget[0] < 0 or not node.get("supported"): return None
        values = [criterion(child, depth+1) for child in node.get("children", [])]
        for item in node.get("tests", []):
            value = test(item.get("id"))
            values.append(not value if value is not None and item.get("negate") else value)
        value = combine(values, node.get("operator", "AND"))
        return not value if value is not None and node.get("negate") else value
    result = criterion(record.get("criteria", {}))
    return {"status": "affected_review" if result is True else "not_affected_review" if result is False else "unknown", "reason": "dpkginfo_subset_evaluated" if result is not None else "unsupported_or_incomplete_inventory", "platform": next(iter(platforms)), "changesScannerVerdict": False}
