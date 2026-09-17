from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .checks.common import find_line_containing, read_text_lines
from .models import DependencyComponent, TargetConfig
from .xml_safe import XmlInputError, parse_xml


PYTHON_EXACT_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9][^\s;#]*)")
POETRY_LOCK_KEY_VALUE_RE = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=\s*(.+?)\s*$")
PNPM_PACKAGE_KEY_RE = re.compile(r"^\s*['\"]?/(.+?)['\"]?:\s*$")
GO_REQUIRE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-~/]+(?:/[A-Za-z0-9_.\-~]+)+)\s+(v?[0-9][^\s]+)")
GO_SUM_RE = re.compile(r"^\s*([A-Za-z0-9_.\-~/]+(?:/[A-Za-z0-9_.\-~]+)+)\s+(v?[0-9][^\s/]+)(?:/go\.mod)?\s+")
GEM_LOCK_RE = re.compile(r"^\s{4}([A-Za-z0-9_.\-]+)\s+\(([^()\s]+)\)")
NUGET_PACKAGE_RE = re.compile(r"<package\b[^>]*\bid=[\"']([^\"']+)[\"'][^>]*\bversion=[\"']([^\"']+)[\"']", re.IGNORECASE)
NUGET_REFERENCE_RE = re.compile(r"<PackageReference\b([^>]*)>(.*?)</PackageReference>|<PackageReference\b([^>]*)/?>", re.IGNORECASE | re.DOTALL)
XML_ATTR_RE = re.compile(r"([A-Za-z_:][A-Za-z0-9_.:-]*)=[\"']([^\"']+)[\"']")
XML_VERSION_RE = re.compile(r"<Version>\s*([^<\s]+)\s*</Version>", re.IGNORECASE)
NODE_RANGE_PREFIXES = ("^", "~", ">", "<", "=", "*")
SUPPORTED_OSV_ECOSYSTEMS = {"npm", "PyPI", "Maven", "Go", "crates.io", "RubyGems", "Packagist", "NuGet"}


def components_from_file(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    if path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
        return _components_from_package_lock(path, target)
    if path.name == "package.json":
        return _components_from_package_json(path, target)
    if path.name == "yarn.lock":
        return _components_from_yarn_lock(path, target)
    if path.name == "pnpm-lock.yaml":
        return _components_from_pnpm_lock(path, target)
    if path.name in {"requirements.txt", "requirements.in"} or path.name.endswith("-requirements.txt"):
        return _components_from_requirements(path, target)
    if path.name == "pyproject.toml":
        return _components_from_pyproject(path, target)
    if path.name == "poetry.lock":
        return _components_from_poetry_lock(path, target)
    if path.name == "Pipfile.lock":
        return _components_from_pipfile_lock(path, target)
    if path.name in {"go.mod", "go.sum"}:
        return _components_from_go_modules(path, target)
    if path.name == "Cargo.lock":
        return _components_from_cargo_lock(path, target)
    if path.name == "Gemfile.lock":
        return _components_from_gemfile_lock(path, target)
    if path.name == "composer.lock":
        return _components_from_composer_lock(path, target)
    if path.name == "pom.xml":
        return _components_from_pom(path, target)
    if path.name == "packages.config" or path.suffix.lower() in {".csproj", ".fsproj", ".vbproj"}:
        return _components_from_nuget(path, target)
    if path.name == "Dockerfile" or path.name.startswith("Dockerfile."):
        return _components_from_dockerfile(path, target)
    return []


def unique_components(components: list[DependencyComponent] | tuple[DependencyComponent, ...]) -> tuple[DependencyComponent, ...]:
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[DependencyComponent] = []
    for component in components:
        key = component.key()
        if key in seen:
            continue
        seen.add(key)
        unique.append(component)
    return tuple(sorted(unique, key=lambda item: (item.target, item.ecosystem.lower(), item.name.lower(), item.version)))


def queryable_osv_components(components: list[DependencyComponent] | tuple[DependencyComponent, ...]) -> tuple[DependencyComponent, ...]:
    return tuple(
        component
        for component in unique_components(components)
        if component.ecosystem in SUPPORTED_OSV_ECOSYSTEMS and _is_exact_version(component.version)
    )


def component_payload(component: DependencyComponent) -> dict[str, object]:
    return {
        "name": component.name,
        "ecosystem": component.ecosystem,
        "version": component.version,
        "purl": component.purl,
        "target": component.target,
        "path": str(component.path),
        "line": component.line,
        "scope": component.scope,
        "source": component.source,
        "osv_queryable": bool(queryable_osv_components((component,))),
    }


def _components_from_package_json(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []
    try:
        data = json.loads("\n".join(lines))
    except json.JSONDecodeError:
        return []

    components: list[DependencyComponent] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        scope = "excluded" if section == "devDependencies" else "required"
        for name, version in deps.items():
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            components.append(
                _component(
                    name=name,
                    ecosystem="npm",
                    version=version.strip(),
                    path=path,
                    target=target,
                    line=find_line_containing(lines, f'"{name}"'),
                    scope=scope,
                    source=section,
                )
            )
    return components


def _components_from_package_lock(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []
    try:
        data = json.loads("\n".join(lines))
    except json.JSONDecodeError:
        return []

    components: list[DependencyComponent] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for package_path, package_data in packages.items():
            if not package_path or not isinstance(package_data, dict):
                continue
            version = package_data.get("version")
            if not isinstance(version, str) or not version:
                continue
            name = package_data.get("name")
            if not isinstance(name, str) or not name:
                name = _name_from_node_modules_path(str(package_path))
            if not name:
                continue
            components.append(
                _component(
                    name=name,
                    ecosystem="npm",
                    version=version,
                    path=path,
                    target=target,
                    line=find_line_containing(lines, f'"{name}"') or find_line_containing(lines, f'"{package_path}"'),
                    source="package-lock",
                )
            )

    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        _collect_lock_dependencies(dependencies, path, target, lines, components)
    return components


def _components_from_yarn_lock(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    components: list[DependencyComponent] = []
    pending_names: tuple[str, ...] = ()
    pending_line: int | None = None
    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not raw_line.startswith((" ", "\t")) and stripped.endswith(":"):
            pending_names = _yarn_descriptor_names(stripped[:-1])
            pending_line = line_number
            continue
        if not pending_names:
            continue
        if stripped.startswith("version "):
            version = _strip_quotes(stripped.removeprefix("version").strip())
        elif stripped.startswith("version:"):
            version = _strip_quotes(stripped.removeprefix("version:").strip())
        else:
            continue
        if not version:
            continue
        for name in pending_names:
            components.append(
                _component(
                    name=name,
                    ecosystem="npm",
                    version=version,
                    path=path,
                    target=target,
                    line=pending_line,
                    source="yarn.lock",
                )
            )
        pending_names = ()
        pending_line = None
    return components


def _components_from_pnpm_lock(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    components: list[DependencyComponent] = []
    in_packages = False
    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if stripped == "packages:":
            in_packages = True
            continue
        if in_packages and raw_line and not raw_line.startswith((" ", "\t")):
            in_packages = False
        if not in_packages:
            continue
        match = PNPM_PACKAGE_KEY_RE.match(raw_line)
        if not match:
            continue
        parsed = _pnpm_name_version(match.group(1))
        if parsed is None:
            continue
        name, version = parsed
        components.append(
            _component(
                name=name,
                ecosystem="npm",
                version=version,
                path=path,
                target=target,
                line=line_number,
                source="pnpm-lock",
            )
        )
    return components


def _collect_lock_dependencies(
    dependencies: dict[str, Any],
    path: Path,
    target: TargetConfig,
    lines: list[str],
    components: list[DependencyComponent],
) -> None:
    for name, payload in dependencies.items():
        if not isinstance(name, str) or not isinstance(payload, dict):
            continue
        version = payload.get("version")
        if isinstance(version, str) and version:
            components.append(
                _component(
                    name=name,
                    ecosystem="npm",
                    version=version,
                    path=path,
                    target=target,
                    line=find_line_containing(lines, f'"{name}"'),
                    source="package-lock",
                )
            )
        nested = payload.get("dependencies")
        if isinstance(nested, dict):
            _collect_lock_dependencies(nested, path, target, lines, components)


def _components_from_requirements(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    components: list[DependencyComponent] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(("-", "--")):
            continue
        match = PYTHON_EXACT_RE.match(line)
        if not match:
            continue
        name = _normalize_python_name(match.group(1))
        version = match.group(2).strip()
        components.append(
            _component(
                name=name,
                ecosystem="PyPI",
                version=version,
                path=path,
                target=target,
                line=line_number,
                source=path.name,
            )
        )
    return components


def _components_from_pyproject(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python 3.11+ provides tomllib
        return []
    try:
        data = tomllib.loads("\n".join(lines))
    except tomllib.TOMLDecodeError:
        return []

    components: list[DependencyComponent] = []
    project = data.get("project", {})
    if isinstance(project, dict):
        for item in _dependency_strings(project.get("dependencies")):
            _append_python_requirement_component(components, item, path, target, lines, "project.dependencies")
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for group, values in optional.items():
                for item in _dependency_strings(values):
                    _append_python_requirement_component(components, item, path, target, lines, f"project.optional-dependencies.{group}", "excluded")

    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    if isinstance(poetry, dict):
        deps = poetry.get("dependencies", {})
        if isinstance(deps, dict):
            for name, version in deps.items():
                if name.lower() == "python":
                    continue
                if isinstance(version, str):
                    components.append(
                        _component(
                            name=_normalize_python_name(name),
                            ecosystem="PyPI",
                            version=version.strip(),
                            path=path,
                            target=target,
                            line=find_line_containing(lines, name),
                            source="tool.poetry.dependencies",
                        )
                    )
    return components


def _components_from_poetry_lock(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    components: list[DependencyComponent] = []
    current: dict[str, str] = {}
    current_line: int | None = None

    def flush() -> None:
        name = current.get("name", "").strip()
        version = current.get("version", "").strip()
        if not name or not version:
            return
        groups = current.get("groups", "")
        category = current.get("category", "")
        scope = "excluded" if "dev" in groups.lower() or category.lower() == "dev" else "required"
        components.append(
            _component(
                name=name,
                ecosystem="PyPI",
                version=version,
                path=path,
                target=target,
                line=current_line,
                scope=scope,
                source="poetry.lock",
            )
        )

    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if stripped == "[[package]]":
            flush()
            current = {}
            current_line = line_number
            continue
        match = POETRY_LOCK_KEY_VALUE_RE.match(raw_line)
        if not match or current_line is None:
            continue
        key, raw_value = match.groups()
        if key in {"name", "version", "category", "groups"}:
            current[key] = _strip_toml_value(raw_value)
    flush()
    return components


def _components_from_pipfile_lock(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []
    try:
        data = json.loads("\n".join(lines))
    except json.JSONDecodeError:
        return []

    components: list[DependencyComponent] = []
    for section, scope in (("default", "required"), ("develop", "excluded")):
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        for name, payload in deps.items():
            if not isinstance(name, str) or not isinstance(payload, dict):
                continue
            raw_version = payload.get("version")
            if not isinstance(raw_version, str):
                continue
            version = raw_version.strip()
            if version.startswith("=="):
                version = version[2:].strip()
            if not version:
                continue
            components.append(
                _component(
                    name=name,
                    ecosystem="PyPI",
                    version=version,
                    path=path,
                    target=target,
                    line=find_line_containing(lines, f'"{name}"'),
                    scope=scope,
                    source="Pipfile.lock",
                )
            )
    return components


def _components_from_dockerfile(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []
    components: list[DependencyComponent] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or not line.upper().startswith("FROM "):
            continue
        image = line.split(maxsplit=1)[1].split(" AS ", maxsplit=1)[0].strip()
        if "@" in image:
            name, version = image.split("@", maxsplit=1)
        elif ":" in image and "/" not in image.rsplit(":", maxsplit=1)[1]:
            name, version = image.rsplit(":", maxsplit=1)
        else:
            name, version = image, "latest"
        components.append(
            _component(
                name=name,
                ecosystem="Docker",
                version=version,
                path=path,
                target=target,
                line=line_number,
                source="Dockerfile",
            )
        )
    return components


def _components_from_go_modules(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    components: list[DependencyComponent] = []
    in_require_block = False
    regex = GO_SUM_RE if path.name == "go.sum" else GO_REQUIRE_RE
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.split("//", maxsplit=1)[0].strip()
        if not line:
            continue
        if path.name == "go.mod":
            if line == "require (":
                in_require_block = True
                continue
            if in_require_block and line == ")":
                in_require_block = False
                continue
            if line.startswith("require "):
                line = line.removeprefix("require ").strip()
            elif not in_require_block:
                continue
        match = regex.match(line)
        if not match:
            continue
        name, version = match.groups()
        components.append(
            _component(
                name=name,
                ecosystem="Go",
                version=version,
                path=path,
                target=target,
                line=line_number,
                source=path.name,
            )
        )
    return components


def _components_from_cargo_lock(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    components: list[DependencyComponent] = []
    current: dict[str, str] = {}
    current_line: int | None = None

    def flush() -> None:
        name = current.get("name", "").strip()
        version = current.get("version", "").strip()
        if not name or not version:
            return
        components.append(
            _component(
                name=name,
                ecosystem="crates.io",
                version=version,
                path=path,
                target=target,
                line=current_line,
                source="Cargo.lock",
            )
        )

    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if stripped == "[[package]]":
            flush()
            current = {}
            current_line = line_number
            continue
        match = POETRY_LOCK_KEY_VALUE_RE.match(raw_line)
        if not match or current_line is None:
            continue
        key, raw_value = match.groups()
        if key in {"name", "version"}:
            current[key] = _strip_toml_value(raw_value)
    flush()
    return components


def _components_from_gemfile_lock(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []

    components: list[DependencyComponent] = []
    in_specs = False
    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if stripped == "GEM":
            in_specs = False
            continue
        if stripped == "specs:":
            in_specs = True
            continue
        if in_specs and raw_line and not raw_line.startswith((" ", "\t")):
            in_specs = False
        if not in_specs:
            continue
        match = GEM_LOCK_RE.match(raw_line)
        if not match:
            continue
        name, version = match.groups()
        components.append(
            _component(
                name=name,
                ecosystem="RubyGems",
                version=version,
                path=path,
                target=target,
                line=line_number,
                source="Gemfile.lock",
            )
        )
    return components


def _components_from_composer_lock(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []
    try:
        data = json.loads("\n".join(lines))
    except json.JSONDecodeError:
        return []

    components: list[DependencyComponent] = []
    for section, scope in (("packages", "required"), ("packages-dev", "excluded")):
        packages = data.get(section, [])
        if not isinstance(packages, list):
            continue
        for package in packages:
            if not isinstance(package, dict):
                continue
            name = package.get("name")
            version = package.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            components.append(
                _component(
                    name=name,
                    ecosystem="Packagist",
                    version=version.lstrip("v"),
                    path=path,
                    target=target,
                    line=find_line_containing(lines, f'"{name}"'),
                    scope=scope,
                    source=section,
                )
            )
    return components


def _components_from_pom(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    try:
        root = parse_xml(text)
    except XmlInputError:
        return []

    components: list[DependencyComponent] = []
    for dependency in root.iter():
        if _xml_tag_name(dependency.tag) != "dependency":
            continue
        values = {_xml_tag_name(child.tag): (child.text or "").strip() for child in list(dependency)}
        group_id = values.get("groupId", "")
        artifact_id = values.get("artifactId", "")
        version = values.get("version", "")
        if not group_id or not artifact_id or not version or version.startswith("${"):
            continue
        name = f"{group_id}:{artifact_id}"
        components.append(
            _component(
                name=name,
                ecosystem="Maven",
                version=version,
                path=path,
                target=target,
                line=_line_number_for_text(text, f"<artifactId>{artifact_id}</artifactId>"),
                scope="excluded" if values.get("scope", "").lower() == "test" else "required",
                source="pom.xml",
            )
        )
    return components


def _components_from_nuget(path: Path, target: TargetConfig) -> list[DependencyComponent]:
    lines = read_text_lines(path, target.max_file_size_bytes)
    if lines is None:
        return []
    text = "\n".join(lines)
    components: list[DependencyComponent] = []

    if path.name == "packages.config":
        for match in NUGET_PACKAGE_RE.finditer(text):
            name, version = match.groups()
            components.append(
                _component(
                    name=name,
                    ecosystem="NuGet",
                    version=version,
                    path=path,
                    target=target,
                    line=_line_number_at_offset(text, match.start()),
                    source="packages.config",
                )
            )
        return components

    for match in NUGET_REFERENCE_RE.finditer(text):
        attributes = _xml_attributes(match.group(1) or match.group(3) or "")
        body = match.group(2) or ""
        name = attributes.get("Include") or attributes.get("Update")
        version = attributes.get("Version") or _version_from_xml_body(body)
        if not name or not version:
            continue
        components.append(
            _component(
                name=name,
                ecosystem="NuGet",
                version=version,
                path=path,
                target=target,
                line=_line_number_at_offset(text, match.start()),
                source=path.name,
            )
        )
    return components


def _append_python_requirement_component(
    components: list[DependencyComponent],
    requirement: str,
    path: Path,
    target: TargetConfig,
    lines: list[str],
    source: str,
    scope: str = "required",
) -> None:
    match = PYTHON_EXACT_RE.match(requirement)
    if not match:
        return
    name = _normalize_python_name(match.group(1))
    components.append(
        _component(
            name=name,
            ecosystem="PyPI",
            version=match.group(2).strip(),
            path=path,
            target=target,
            line=find_line_containing(lines, requirement) or find_line_containing(lines, name),
            scope=scope,
            source=source,
        )
    )


def _dependency_strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _yarn_descriptor_names(value: str) -> tuple[str, ...]:
    names: list[str] = []
    for descriptor in value.split(","):
        descriptor = _strip_quotes(descriptor.strip())
        if not descriptor or descriptor == "__metadata":
            continue
        name = _yarn_name_from_descriptor(descriptor)
        if name and name not in names:
            names.append(name)
    return tuple(names)


def _yarn_name_from_descriptor(descriptor: str) -> str:
    if descriptor.startswith("@"):
        slash = descriptor.find("/")
        if slash == -1:
            return ""
        marker = descriptor.find("@", slash + 1)
        return descriptor[:marker] if marker != -1 else descriptor
    marker = descriptor.find("@")
    return descriptor[:marker] if marker != -1 else descriptor


def _pnpm_name_version(value: str) -> tuple[str, str] | None:
    cleaned = value.split("(", maxsplit=1)[0].strip()
    if "/" in cleaned and "@" not in cleaned:
        name, version = cleaned.rsplit("/", maxsplit=1)
    elif "@" in cleaned:
        name, version = cleaned.rsplit("@", maxsplit=1)
    else:
        return None
    version = version.split("_", maxsplit=1)[0].strip()
    if not name or not version:
        return None
    return name, version


def _strip_quotes(value: str) -> str:
    return value.strip().strip("\"'")


def _strip_toml_value(value: str) -> str:
    stripped = value.split("#", maxsplit=1)[0].strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        return stripped.strip("[]")
    return _strip_quotes(stripped)


def _component(
    *,
    name: str,
    ecosystem: str,
    version: str,
    path: Path,
    target: TargetConfig,
    line: int | None = None,
    scope: str = "required",
    source: str = "",
) -> DependencyComponent:
    normalized_name = _normalize_component_name(name, ecosystem)
    normalized_version = version.strip()
    return DependencyComponent(
        name=normalized_name,
        ecosystem=ecosystem,
        version=normalized_version,
        path=path,
        target=target.name,
        line=line,
        scope=scope,
        source=source,
        purl=_purl(ecosystem, normalized_name, normalized_version),
    )


def _name_from_node_modules_path(value: str) -> str:
    marker = "node_modules/"
    if marker not in value:
        return ""
    tail = value.rsplit(marker, maxsplit=1)[1]
    parts = tail.split("/")
    if len(parts) >= 2 and parts[0].startswith("@"):
        return f"{parts[0]}/{parts[1]}"
    return parts[0] if parts else ""


def _normalize_component_name(name: str, ecosystem: str) -> str:
    if ecosystem == "PyPI":
        return _normalize_python_name(name)
    return name.strip()


def _normalize_python_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def _is_exact_version(version: str) -> bool:
    cleaned = version.strip()
    if cleaned.startswith("v") and len(cleaned) > 1 and cleaned[1].isdigit():
        cleaned = cleaned[1:]
    if not cleaned or cleaned.startswith(NODE_RANGE_PREFIXES):
        return False
    return not any(token in cleaned for token in ("*", "||", " - ", "x", "X", "${", "[", "]"))


def _purl(ecosystem: str, name: str, version: str) -> str:
    if ecosystem == "Maven" and ":" in name:
        group, artifact = name.split(":", maxsplit=1)
        quoted_group = quote(group, safe=".")
        quoted_artifact = quote(artifact, safe="")
        quoted_version = quote(version, safe="")
        return f"pkg:maven/{quoted_group}/{quoted_artifact}@{quoted_version}" if quoted_version else f"pkg:maven/{quoted_group}/{quoted_artifact}"
    purl_type = {
        "npm": "npm",
        "PyPI": "pypi",
        "Docker": "docker",
        "Go": "golang",
        "crates.io": "cargo",
        "RubyGems": "gem",
        "Packagist": "composer",
        "NuGet": "nuget",
    }.get(ecosystem, ecosystem.lower())
    quoted_name = quote(name, safe="/")
    quoted_version = quote(version, safe="")
    return f"pkg:{purl_type}/{quoted_name}@{quoted_version}" if quoted_version else f"pkg:{purl_type}/{quoted_name}"


def _xml_tag_name(tag: str) -> str:
    return tag.rsplit("}", maxsplit=1)[-1] if "}" in tag else tag


def _xml_attributes(value: str) -> dict[str, str]:
    return {key: raw_value for key, raw_value in XML_ATTR_RE.findall(value)}


def _version_from_xml_body(value: str) -> str:
    match = XML_VERSION_RE.search(value)
    return match.group(1).strip() if match else ""


def _line_number_for_text(text: str, needle: str) -> int | None:
    offset = text.find(needle)
    return _line_number_at_offset(text, offset) if offset != -1 else None


def _line_number_at_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1
