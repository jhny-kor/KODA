from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "platforms" / "windows" / "scripts"

PACKAGING_BOOT = r'''
import http.client
import importlib.abc
import re
import runpy
import sys
import threading
from pathlib import Path

scripts = Path(sys.argv[1])
source_only = sys.argv[2] == "source-only"
excluded = set()
if source_only:
    build = (scripts / "build-koda-windows-installer.ps1").read_text(encoding="utf-8")
    block = re.search(r'\$SourceOnlyExcludedModules = @\((.*?)\n\)', build, re.S).group(1)
    excluded = set(re.findall(r'"([^"]+)"', block))
class ExcludedModuleFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname in excluded:
            raise ModuleNotFoundError(f"SourceOnly excluded {fullname}", name=fullname)
sys.meta_path.insert(0, ExcludedModuleFinder())
sys.path.insert(0, str(scripts.parents[2] / "platforms" / "shared" / "python"))
entry = scripts / "koda-desktop.py"
sys.argv = [str(entry), "--smoke-test"]
if source_only:
    from security_scanner.server import create_dashboard_server
    with create_dashboard_server(port=0) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        try:
            connection.request("GET", "/")
            response = connection.getresponse()
            session = response.getheader("X-KODA-Session")
            html = response.read()
            assert b'<body class="source-only">' in html
            assert b'.source-only [data-live-web] { display: none; }' in html
            assert html.count(b'<div class="scan-web-form" data-live-scan data-live-web>') == 2
            for path in ("/api/web-scan", "/api/zap-scan"):
                connection.request("POST", path, "{}", headers={
                    "Content-Type": "application/json", "Origin": origin, "X-KODA-Session": session,
                })
                response = connection.getresponse()
                assert response.status == 501, (path, response.status)
                assert b"Full desktop distribution" in response.read()
        finally:
            connection.close()
            server.shutdown()
            thread.join(timeout=5)
    runpy.run_path(str(entry), run_name="__main__")
else:
    sys.frozen = True
    shallow_bundle_entry = "/KODA/_internal/koda-desktop.py"
    exec(compile(entry.read_bytes(), shallow_bundle_entry, "exec"), {
        "__name__": "__main__",
        "__file__": shallow_bundle_entry,
    })
'''


class WindowsPackagingTests(unittest.TestCase):
    def test_source_only_desktop_starts_and_serves_dashboard_with_packaged_modules(self):
        environment = os.environ.copy()
        environment["KODA_SOURCE_ONLY"] = "1"
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [sys.executable, "-c", PACKAGING_BOOT, str(SCRIPTS), "source-only"],
            env=environment, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_full_desktop_serves_local_har_from_a_shallow_frozen_bundle(self):
        environment = os.environ.copy()
        environment["KODA_SOURCE_ONLY"] = ""
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [sys.executable, "-c", PACKAGING_BOOT, str(SCRIPTS), "full"],
            env=environment, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_installer_runs_gui_smoke_and_rejects_nonzero_exit(self):
        script = (SCRIPTS / "build-koda-windows-installer.ps1").read_text(encoding="utf-8")
        self.assertRegex(script, r'(?s)Start-Process\s+.*?-FilePath \$GuiExecutable.*?-ArgumentList "--smoke-test"')
        self.assertIn("$guiSmokeProcess.ExitCode -ne 0", script)

    def test_runtime_hook_sets_the_packaged_distribution(self):
        script = (SCRIPTS / "build-koda-windows-installer.ps1").read_text(encoding="utf-8")
        self.assertIn('$sourceOnlyFlag = if ($SourceOnly) { "1" } else { "0" }', script)
        self.assertIn("os.environ['KODA_SOURCE_ONLY'] = '$sourceOnlyFlag'", script)


if __name__ == "__main__":
    unittest.main()
