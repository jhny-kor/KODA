"""Conservative local NVD 2.0 applicability evaluation, contract v1.

No network or package-name inference. Only supplied CPE 2.3 product identities
are matched. Missing inventory, unsupported versions and malformed conditions
remain unknown. Numeric dotted ranges are supported; vendor version schemes
are deliberately not approximated with digit stripping or SemVer coercion.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

CONTRACT_VERSION = "koda-offline-cpe-v1"
MAX_NODES = 4096
MAX_DEPTH = 24
GLOBAL_PRODUCT = ("*", "*", "*")
_NUMERIC = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")


def _fields(value: str) -> tuple[str, ...]:
    if not isinstance(value, str) or len(value) > 2048 or any(c.isspace() for c in value):
        raise ValueError("Invalid CPE formatted string")
    fields, current, escaped = [], [], False
    for char in value:
        if escaped:
            current.extend(("\\", char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        raise ValueError("Incomplete CPE escape")
    fields.append("".join(current))
    if len(fields) != 13 or fields[:2] != ["cpe", "2.3"] or fields[2] not in {"a", "o", "h", "*"}:
        raise ValueError("Invalid CPE 2.3 part")
    if any(not field or len(field) > 256 for field in fields[2:]):
        raise ValueError("Invalid CPE field")
    return tuple(fields[2:])


def _literal(field: str) -> str | None:
    output, escaped = [], False
    for char in field:
        if escaped:
            output.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char in "*?":
            return None
        else:
            output.append(char)
    return "".join(output).lower()


def product_key(cpe: str) -> tuple[str, str, str]:
    fields = _fields(cpe)
    vendor, product = _literal(fields[1]), _literal(fields[2])
    if fields[0] == "*" or vendor in {None, "-"} or product in {None, "-"}:
        raise ValueError("Concrete part, vendor and product required")
    return fields[0], vendor, product


def _attribute(criteria: str, actual: str) -> bool | None:
    if criteria == "*":
        return True
    if actual == "*":
        return None
    if criteria == "-" or actual == "-":
        return criteria == actual
    pattern, escaped = [], False
    for char in criteria:
        if escaped:
            pattern.append(("literal", char.lower()))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "*":
            pattern.append(("many", ""))
        elif char == "?":
            pattern.append(("one", ""))
        else:
            pattern.append(("literal", char.lower()))
    literal = _literal(actual)
    if literal is None:
        return None
    # Bounded dynamic matching avoids regex backtracking on imported criteria.
    states = {0}
    for kind, char in pattern:
        if kind == "many":
            states = set(range(min(states), len(literal) + 1)) if states else set()
        else:
            states = {index + 1 for index in states if index < len(literal) and (kind == "one" or literal[index] == char)}
    return len(literal) in states


def _compare(actual: str, boundary: str) -> int | None:
    if len(actual) > 256 or len(boundary) > 256:
        return None
    if actual == boundary:
        return 0
    if not _NUMERIC.fullmatch(actual) or not _NUMERIC.fullmatch(boundary):
        return None
    a, b = [int(x) for x in actual.split(".")], [int(x) for x in boundary.split(".")]
    width = max(len(a), len(b))
    a += [0] * (width - len(a))
    b += [0] * (width - len(b))
    return (a > b) - (a < b)


def _one(match: dict, actual: tuple[str, ...]) -> bool | None:
    try:
        criteria = _fields(match["criteria"])
    except (KeyError, ValueError, TypeError):
        return None
    results = [_attribute(c, a) for c, a in zip(criteria, actual)]
    if False in results:
        return False
    version = _literal(actual[3])
    for key, compare in (("versionStartIncluding", lambda x: x >= 0),
                         ("versionStartExcluding", lambda x: x > 0),
                         ("versionEndIncluding", lambda x: x <= 0),
                         ("versionEndExcluding", lambda x: x < 0)):
        if key not in match:
            continue
        boundary = match[key]
        if version in {None, "-"} or not isinstance(boundary, str):
            results.append(None)
            continue
        comparison = _compare(version, boundary.lower())
        results.append(compare(comparison) if comparison is not None else None)
    if False in results:
        return False
    return None if None in results else True


@dataclass(frozen=True)
class Applicability:
    status: str
    matched_cpes: tuple[str, ...] = ()
    reason: str = ""

    def payload(self) -> dict:
        return {"version": CONTRACT_VERSION, "status": self.status,
                "matchedCpes": list(self.matched_cpes), "reason": self.reason}


@dataclass(frozen=True)
class PreparedInventory:
    products: dict[tuple[str, str, str], list[tuple[str, tuple[str, ...]]]]
    valid: bool = True


def prepare_inventory(cpes: Iterable[str]) -> PreparedInventory:
    products = {}
    try:
        for value in dict.fromkeys(cpes):
            products.setdefault(product_key(value), []).append((value, _fields(value)))
    except (TypeError, ValueError):
        return PreparedInventory({}, False)
    return PreparedInventory(products)


def evaluate(configurations: object, cpes: Iterable[str] | PreparedInventory, *, complete_inventory: bool = False) -> Applicability:
    """Evaluate NVD applicability using three-valued logic and matched evidence.

    ``complete_inventory`` is a caller assertion, never inferred from an SBOM.
    Absent environmental prerequisites otherwise stay unknown, including under
    negation. Only true, non-negated vulnerable leaves produce affected assets.
    """
    if not isinstance(configurations, list) or not configurations:
        return Applicability("unknown", reason="NVD applicability conditions unavailable")
    inventory = cpes if isinstance(cpes, PreparedInventory) else prepare_inventory(cpes)
    if not inventory.valid:
        return Applicability("unknown", reason="Invalid or ambiguous CPE inventory")
    if not inventory.products:
        return Applicability("unknown", reason="No concrete CPE inventory supplied")
    count = 0

    def combine(values, operator):
        if not values or not isinstance(operator, str) or operator not in {"AND", "OR"}:
            return None, set()
        states = [value[0] for value in values]
        if operator == "AND":
            state = False if False in states else None if None in states else True
        else:
            state = True if True in states else None if None in states else False
        evidence = set().union(*(value[1] for value in values if value[0] is True)) if state is True else set()
        return state, evidence

    def leaf(match):
        if not isinstance(match, dict) or not isinstance(match.get("vulnerable"), bool):
            return None, set()
        try:
            target = product_key(match["criteria"])
        except (KeyError, ValueError, TypeError):
            try:
                criteria = _fields(match["criteria"])
            except (KeyError, ValueError, TypeError):
                return None, set()
            candidates = [item for values in inventory.products.values() for item in values
                          if all(_attribute(c, a) is True for c, a in zip(criteria[:3], item[1][:3]))]
        else:
            candidates = inventory.products.get(target, [])
        if not candidates:
            return (False if complete_inventory else None), set()
        values = [(text, _one(match, fields)) for text, fields in candidates]
        state = True if any(x is True for _, x in values) else None if any(x is None for _, x in values) else False
        evidence = {text for text, value in values if value is True and match["vulnerable"] and _literal(_fields(text)[3]) not in {None, "-"}}
        return state, evidence

    def node(value, depth=0):
        nonlocal count
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH or not isinstance(value, dict):
            return None, set()
        operator = value.get("operator")
        if "negate" in value and not isinstance(value["negate"], bool):
            return None, set()
        values = []
        for key in ("nodes", "children", "cpeMatch"):
            if key not in value:
                continue
            if not isinstance(value[key], list):
                return None, set()
            for child in value[key]:
                count += 1
                if count > MAX_NODES:
                    return None, set()
                values.append(leaf(child) if key == "cpeMatch" else node(child, depth + 1))
        # A missing operator is unambiguous only for a single child.
        state, evidence = combine(values, operator if operator is not None else "OR" if len(values) == 1 else None)
        if value.get("negate") is True:
            state, evidence = (None if state is None else not state), set()
        return state, evidence

    values = []
    for value in configurations:
        values.append(node(value))
        if count > MAX_NODES:
            break
    state, evidence = combine(values, "OR")
    if count > MAX_NODES:
        return Applicability("unknown", reason="NVD applicability complexity limit exceeded")
    if state is True and evidence:
        return Applicability("affected", tuple(sorted(evidence)), "Satisfied NVD conditions with matching vulnerable product")
    if state is False:
        return Applicability("not_affected", reason="Supplied inventory fails the NVD applicability conditions")
    return Applicability("unknown", reason="Incomplete inventory, unsupported version comparison or no positive vulnerable evidence")


def candidate_index(records: dict[str, dict], *, issues: dict[str, str] | None = None) -> dict[tuple[str, str, str], set[str]]:
    """Index products once, preserving all unindexable records as unknown.

    Any truncated/malformed tree enters the global bucket as well as ``issues``.
    A normal record for the same product must never hide an omitted condition.
    Callers may count these issues without repeatedly evaluating their trees.
    """
    index = {}
    for identifier, record in records.items():
        if isinstance(record, dict) and str(record.get("vulnStatus", "")).lower() == "rejected":
            continue
        configurations = record.get("configurations") if isinstance(record, dict) else None
        problem = ""
        if not isinstance(configurations, list) or not configurations:
            problem = "NVD applicability conditions unavailable"
            stack = []
        elif len(configurations) > MAX_NODES:
            problem = "NVD applicability complexity limit exceeded"
            stack = []
        else:
            stack = [("node", item, 0) for item in configurations]
        visited = 0
        while stack and not problem:
            kind, value, depth = stack.pop()
            visited += 1
            if visited > MAX_NODES or depth > MAX_DEPTH:
                problem = "NVD applicability complexity limit exceeded"
                break
            if not isinstance(value, dict):
                problem = "Malformed NVD applicability condition"
                break
            if kind == "leaf":
                try:
                    _fields(value["criteria"])
                    if not isinstance(value.get("vulnerable"), bool):
                        raise ValueError("Missing vulnerable flag")
                    for boundary in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
                        if boundary in value and (not isinstance(value[boundary], str) or not value[boundary] or len(value[boundary]) > 256):
                            raise ValueError("Invalid version boundary")
                except (KeyError, TypeError, ValueError):
                    problem = "Malformed NVD CPE match condition"
                    break
                if value["vulnerable"]:
                    try:
                        key = product_key(value["criteria"])
                    except ValueError:
                        key = GLOBAL_PRODUCT
                    index.setdefault(key, set()).add(identifier)
                continue
            operator = value.get("operator")
            if (operator is not None and (not isinstance(operator, str) or operator not in {"AND", "OR"})) or ("negate" in value and not isinstance(value["negate"], bool)):
                problem = "Malformed NVD applicability operator"
                break
            children = []
            for key in ("nodes", "children", "cpeMatch"):
                if key not in value:
                    continue
                if not isinstance(value[key], list):
                    problem = "Malformed NVD applicability children"
                    break
                if visited + len(stack) + len(children) + len(value[key]) > MAX_NODES:
                    problem = "NVD applicability complexity limit exceeded"
                    break
                children.extend(("leaf" if key == "cpeMatch" else "node", item, depth + 1) for item in value[key])
            if problem:
                break
            if not children or (value.get("operator") is None and len(children) != 1):
                problem = "Empty or ambiguous NVD applicability condition"
                break
            stack.extend(children)
        if problem:
            index.setdefault(GLOBAL_PRODUCT, set()).add(identifier)
            if issues is not None:
                issues[identifier] = problem
    return index
