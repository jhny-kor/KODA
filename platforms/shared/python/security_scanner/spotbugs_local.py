"""Run a user-installed SpotBugs distribution on existing Java bytecode."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from .local_sast import require_local_path, resolve_local_path
from .sarif_import import MAX_SARIF_BYTES

_TIMEOUT_SECONDS = 120
_RUNTIME_ENVIRONMENT = {"SYSTEMROOT", "WINDIR", "LANG", "LC_ALL", "TEMP", "TMP", "TMPDIR"}


def run_spotbugs(target: Path, source_root: Path, output: Path, *, tool: Path, java: Path) -> None:
    """Analyze a JAR, class file, or directory of classes and write a SARIF report.

    Supply the launcher JAR from an installed SpotBugs distribution, plus its
    Java executable. SpotBugs inspects bytecode and uses source_root for source
    locations. It does not compile the project.
    """
    target, source_root, tool, java = map(resolve_local_path, (target, source_root, tool, java))
    output = require_local_path(require_local_path(output).absolute())

    if not (target.is_dir() or (target.is_file() and target.suffix.lower() in {".jar", ".class"})):
        raise ValueError("Select an existing JAR, class file, or compiled classes directory.")
    if not source_root.is_dir() or os.pathsep in str(source_root):
        raise ValueError("Select one existing Java source directory for mapping file locations.")
    if not tool.is_file() or tool.suffix.lower() != ".jar" or tool == target:
        raise ValueError("Select the SpotBugs distribution's launcher JAR separately from the scan target.")
    if not java.is_file() or java.name.lower() not in {"java", "java.exe"} or not os.access(java, os.X_OK):
        raise ValueError("Select the Java runtime's java executable.")
    if resolve_local_path(output) in {target, tool, java} or output.is_dir():
        raise ValueError("Select a separate output file for the SpotBugs report.")

    env = {key: value for key, value in os.environ.items() if key.upper() in _RUNTIME_ENVIRONMENT}
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".koda-spotbugs-", dir=output.parent) as scratch:
        report = Path(scratch) / "spotbugs.sarif"
        arguments = [
            str(java), "-Xmx768m", "-XX:ActiveProcessorCount=2", "-Djava.awt.headless=true",
            f"-Duser.home={scratch}", f"-Djava.io.tmpdir={scratch}", "-jar", str(tool), "-textui",
            "-exitcode", "-nested:false", f"-sarif={report}", "-sourcepath", str(source_root), str(target),
        ]
        try:
            process = subprocess.run(
                arguments, cwd=scratch, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=_TIMEOUT_SECONDS, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"SpotBugs did not finish within {_TIMEOUT_SECONDS} seconds.") from exc
        except OSError as exc:
            raise RuntimeError("Could not start Java for SpotBugs.") from exc

        # Bit 1 reports findings, bit 2 missing classes, and bit 4 execution
        # errors. Keep findings with missing classes for review. The SARIF
        # invocation retains SpotBugs' own description of the partial result.
        if process.returncode not in {0, 1, 2, 3} or not report.is_file():
            raise RuntimeError(f"SpotBugs could not analyze the selected bytecode (exit {process.returncode}).")
        if not 0 < report.stat().st_size <= MAX_SARIF_BYTES:
            raise RuntimeError("SpotBugs produced an empty report or exceeded KODA's SARIF size limit.")
        if os.name != "nt":
            report.chmod(0o600)
        report.replace(output)
