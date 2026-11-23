"""Run user-installed analyzers and hand bounded SARIF to the ordinary scanner."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from .sarif_import import MAX_SARIF_BYTES, load_sarif


def require_local_path(path: Path) -> Path:
    """Reject Windows network and device paths before checking the filesystem."""
    expanded = path.expanduser()
    if str(expanded).startswith(("\\\\", "//")):
        raise ValueError("Select a path on a local drive.")
    return expanded


def resolve_local_path(path: Path) -> Path:
    return require_local_path(require_local_path(path).resolve())


def _installed_launcher(name: str) -> str | None:
    # Discover installed tools from explicit PATH directories, including on Windows.
    for directory in map(Path, os.get_exec_path()):
        if not directory.is_absolute():
            continue
        try:
            launcher_path = require_local_path(directory / name)
        except ValueError:
            continue
        launcher = shutil.which(str(launcher_path))
        if launcher is not None:
            return launcher
    return None


def _configured_path(variable: str, fallback: str | Path | None = None) -> Path:
    value = os.environ.get(variable) or fallback
    if not value:
        raise ValueError(f"Set {variable} to the installed tool's absolute path before starting KODA.")
    path = require_local_path(Path(value))
    if not path.is_absolute() or not path.is_file():
        raise ValueError(f"{variable} must point to an existing installed tool at an absolute path.")
    return path


def prepare_local_sast(
    source: Path, work_dir: Path, *, spotbugs_input: Path | None = None,
    spotbugs_source_root: Path | None = None, semgrep_rules: Path | None = None,
) -> Path:
    for item in (spotbugs_input, spotbugs_source_root, semgrep_rules):
        if item is not None:
            require_local_path(item)
    source = resolve_local_path(source)
    work_dir = resolve_local_path(work_dir)
    if not source.is_dir():
        raise ValueError("Local SAST requires one source directory.")
    if spotbugs_input is None and semgrep_rules is None:
        raise ValueError("Choose at least one local analyzer.")
    if spotbugs_source_root is not None and spotbugs_input is None:
        raise ValueError("A SpotBugs source root requires compiled Java input.")
    outputs = []
    if spotbugs_input is not None:
        from .spotbugs_local import run_spotbugs

        java_name = "java.exe" if os.name == "nt" else "java"
        java_home = os.environ.get("JAVA_HOME")
        java = Path(java_home) / "bin" / java_name if java_home else _installed_launcher(java_name)
        tool = _configured_path("KODA_SPOTBUGS_JAR")
        jre = _configured_path("KODA_JAVA_BIN", java)
        standard_root = source / "src" / "main" / "java"
        package_root = resolve_local_path(spotbugs_source_root or (standard_root if standard_root.is_dir() else source))
        if not package_root.is_dir() or not package_root.is_relative_to(source):
            raise ValueError("The SpotBugs source root must be inside the selected source directory.")
        output = work_dir / "spotbugs.sarif"
        run_spotbugs(spotbugs_input, package_root, output, tool=tool, java=jre)
        outputs.append(output)
    if semgrep_rules is not None:
        from .semgrep_local import run_semgrep

        semgrep_name = "semgrep.exe" if os.name == "nt" else "semgrep"
        executable = _configured_path("KODA_SEMGREP_BIN", _installed_launcher(semgrep_name))
        output = work_dir / "semgrep.sarif"
        run_semgrep(source, semgrep_rules, output, executable=executable)
        outputs.append(output)
    if len(outputs) == 1:
        return outputs[0]
    runs = [run for output in outputs for run in load_sarif(output)["runs"]]
    serialized = json.dumps({"version": "2.1.0", "runs": runs}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(serialized) > MAX_SARIF_BYTES:
        raise ValueError("The combined SARIF output exceeds KODA's 8 MiB limit.")
    report = work_dir / "local-sast.sarif"
    report.write_bytes(serialized)
    return report
