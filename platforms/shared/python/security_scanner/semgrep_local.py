"""Run a locally installed Semgrep CE with a local rules file."""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import tempfile
from pathlib import Path

from .local_sast import resolve_local_path
from .sarif_import import MAX_SARIF_RESULTS, SarifImportError, load_sarif

MAX_RULES_BYTES = 1024 * 1024
SCAN_TIMEOUT_SECONDS = 180


def _scan_environment(home: Path) -> dict[str, str]:
    inherited = {"PATH", "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "PATHEXT", "LANG", "LC_ALL", "LC_CTYPE"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in inherited}
    environment.update(
        HOME=str(home),
        USERPROFILE=str(home),
        XDG_CONFIG_HOME=str(home),
        XDG_CACHE_HOME=str(home),
        APPDATA=str(home),
        LOCALAPPDATA=str(home),
        TMPDIR=str(home),
        TEMP=str(home),
        TMP=str(home),
        SEMGREP_SETTINGS_FILE=str(home / "settings.yml"),
        PYTHONUTF8="1",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_OPTIONAL_LOCKS="0",
    )
    return environment


def _stop_scan(process: subprocess.Popen) -> None:
    if os.name == "nt":
        taskkill = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
        try:
            subprocess.run(
                [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5, check=False, creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait()


def run_semgrep(target: Path, rules: Path, output: Path, *, executable: Path) -> None:
    """Run CE on source files and publish a size-limited SARIF report."""
    target, rules, output, executable = map(resolve_local_path, (target, rules, output, executable))
    if not target.is_file() and not target.is_dir():
        raise ValueError("Select an existing source file or directory.")
    if rules.suffix.lower() not in {".yml", ".yaml"} or not rules.is_file():
        raise ValueError("Select a local Semgrep YAML rules file.")
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("Select an installed Semgrep executable.")
    if os.name == "nt" and executable.suffix.lower() != ".exe":
        raise ValueError("Select the native Semgrep .exe launcher.")
    if output in (target, rules, executable):
        raise ValueError("Choose a separate path for the SARIF report.")
    try:
        with rules.open("rb") as stream:
            config = stream.read(MAX_RULES_BYTES + 1)
    except OSError as exc:
        raise ValueError("The local Semgrep rules file could not be opened.") from exc
    if not config or len(config) > MAX_RULES_BYTES:
        raise ValueError("Choose a nonempty Semgrep rules file up to 1 MiB.")

    source_root = target if target.is_dir() else target.parent
    source = "." if target.is_dir() else target.name
    with tempfile.TemporaryDirectory(prefix=".koda-semgrep-", dir=output.parent) as directory:
        work = Path(directory)
        config_path = work / "rules.yml"
        config_path.write_bytes(config)
        staged = work / "semgrep.sarif"
        command = [
            str(executable), "scan", "--config", str(config_path), "--oss-only",
            "--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids",
            "--strict", "--dataflow-traces", "--quiet", "--sarif", "--output", str(staged),
            "--exclude", work.name, "--", source,
        ]
        process_options = (
            {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}
        )
        try:
            with subprocess.Popen(
                command, cwd=source_root, env=_scan_environment(work), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **process_options,
            ) as process:
                try:
                    exit_code = process.wait(timeout=SCAN_TIMEOUT_SECONDS)
                except (subprocess.TimeoutExpired, KeyboardInterrupt):
                    _stop_scan(process)
                    raise
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Semgrep exceeded the time limit.") from exc
        except OSError as exc:
            raise RuntimeError("Semgrep could not start.") from exc
        if exit_code:
            raise RuntimeError(f"Semgrep stopped with exit code {exit_code}. Check the selected source and rules.")
        try:
            if not stat.S_ISREG(staged.lstat().st_mode):
                raise SarifImportError("sarif_unreadable")
            report = load_sarif(staged)
            runs = report.get("runs")
            if report.get("version") != "2.1.0" or not isinstance(runs, list) or not runs:
                raise SarifImportError("sarif_invalid_document")
            total = 0
            for run in runs:
                results = run.get("results", []) if isinstance(run, dict) else None
                if not isinstance(results, list):
                    raise SarifImportError("sarif_invalid_results")
                total += len(results)
            if total > MAX_SARIF_RESULTS:
                raise SarifImportError("sarif_too_many_results")
        except (ValueError, RecursionError, OSError) as exc:
            raise RuntimeError("Semgrep did not produce an importable SARIF report.") from exc
        staged.replace(output)
