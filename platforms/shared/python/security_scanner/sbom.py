from __future__ import annotations

import csv
import io
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Iterable, Mapping

from . import __version__
from .dependency_inventory import unique_components
from .models import DependencyComponent


NIS_SBOM_COLUMNS = (
    "SBOM Standard",
    "SBOM Type",
    "CycloneDXNo.",
    "SPDX Doc. ID",
    "SBOM ID",
    "Product Name",
    "Product Version",
    "Component Name",
    "Component Alias",
    "Component Version",
    "Component Supplier Name",
    "Component Hash",
    "Component Path",
    "SBOM Author Name",
    "Unique Identifier",
    "Dependency Relationship",
    "Timestamp",
    "License Name·Version",
    "Vul. DB",
    "Vul. Info",
)


_CSV_FORMULA_PREFIX = re.compile(r"^[\s\ufeff\x00]*[=+\-@＝＋－＠]")


def safe_csv_cell(value: object) -> str:
    """Keep spreadsheet formulas inert in CSV exports intended for people."""
    text = str(value or "")
    if _CSV_FORMULA_PREFIX.match(text):
        return "\t" + text
    return text


def cyclonedx_payload(components: tuple[DependencyComponent, ...] | list[DependencyComponent]) -> dict[str, object]:
    unique = unique_components(tuple(components))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "KODA",
                        "version": __version__,
                    }
                ]
            },
        },
        "components": [_component_payload(component) for component in unique],
    }


def render_cyclonedx(components: tuple[DependencyComponent, ...] | list[DependencyComponent]) -> str:
    return json.dumps(cyclonedx_payload(components), indent=2, ensure_ascii=False)


def nis_sbom_payload(
    components: tuple[DependencyComponent, ...] | list[DependencyComponent],
    *,
    product_name: str = "KODA scan",
    sbom_type: str = "Analyzed",
) -> dict[str, object]:
    rows = [
        {
            "Component Name": component.name,
            "Component Version": component.version,
            "Component Path": str(component.path),
            "Unique Identifier": component.purl,
        }
        for component in unique_components(tuple(components))
    ]
    return _nis_sbom_payload(rows, product_name=product_name, sbom_type=sbom_type)


def render_nis_sbom(
    components: tuple[DependencyComponent, ...] | list[DependencyComponent],
    *,
    product_name: str = "KODA scan",
    sbom_type: str = "Analyzed",
) -> str:
    return render_nis_sbom_rows(
        (
            {
                "Component Name": component.name,
                "Component Version": component.version,
                "Component Path": str(component.path),
                "Unique Identifier": component.purl,
            }
            for component in unique_components(tuple(components))
        ),
        product_name=product_name,
        sbom_type=sbom_type,
    )


def render_nis_sbom_rows(
    rows: Iterable[Mapping[str, object]],
    *,
    product_name: str,
    product_version: str = "",
    author_name: str = "KODA",
    sbom_type: str = "Analyzed",
) -> str:
    payload = _nis_sbom_payload(
        rows,
        product_name=product_name,
        product_version=product_version,
        author_name=author_name,
        sbom_type=sbom_type,
    )
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=NIS_SBOM_COLUMNS, lineterminator="\r\n", quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows({column: safe_csv_cell(row[column]) for column in NIS_SBOM_COLUMNS} for row in payload["rows"])
    return "\ufeff" + output.getvalue()


def _nis_sbom_payload(
    rows: Iterable[Mapping[str, object]],
    *,
    product_name: str,
    product_version: str = "",
    author_name: str = "KODA",
    sbom_type: str = "Analyzed",
) -> dict[str, object]:
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    sbom_id = f"KODA-{timestamp[:10].replace('-', '')}-{uuid.uuid4().int % 1_000_000:06d}"
    common = {
        "SBOM Standard": "NIS 1.0",
        "SBOM Type": sbom_type,
        "SBOM ID": sbom_id,
        "Product Name": product_name,
        "Product Version": product_version,
        "SBOM Author Name": author_name,
        "Timestamp": timestamp,
    }
    normalized = [
        {column: str({**common, **row}.get(column) or "") for column in NIS_SBOM_COLUMNS}
        for row in rows
    ]
    return {"columns": list(NIS_SBOM_COLUMNS), "rows": normalized}


def _component_payload(component: DependencyComponent) -> dict[str, object]:
    payload: dict[str, object] = {
        "type": "container" if component.ecosystem == "Docker" else "library",
        "bom-ref": component.purl or f"{component.ecosystem}:{component.name}@{component.version}",
        "name": component.name,
        "version": component.version,
        "scope": component.scope,
        "properties": [
            {"name": "koda:ecosystem", "value": component.ecosystem},
            {"name": "koda:target", "value": component.target},
            {"name": "koda:source", "value": component.source},
            {"name": "koda:path", "value": str(component.path)},
        ],
    }
    if component.purl:
        payload["purl"] = component.purl
    if component.line is not None:
        payload["properties"].append({"name": "koda:line", "value": str(component.line)})  # type: ignore[index]
    return payload
