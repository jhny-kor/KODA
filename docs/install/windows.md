# KODA Windows Install

> As of **2026-10-11**, this guide describes source included in this GitHub publication;
> it was uncommitted at validation. Windows-specific packaging/process regression
> tests and PowerShell syntax checks passed on the Mac host; actual Windows EXE,
> installer, WebView2, and native Syft execution were excluded at the user's request.
> See the [verification summary](../verification-2026-10-11.md).

Windows uses the shared Python engine from `platforms/shared/python/` and packages it through the Windows scripts under `platforms/windows/`.

## Build Installer

Run on Windows 10/11 with Python 3.10 or newer and Inno Setup 6 installed:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\platforms\windows\scripts\build-koda-windows-installer.ps1
```

The build creates:

- `dist\KODA\KODA.exe`
- `dist\Windows\KODASetup.exe`

Target users install with `KODASetup.exe`. It installs to `%LOCALAPPDATA%\KODA` and creates Start Menu shortcuts for `KODA` and `KODA (Browser Mode)`.

The builder runs the completed `KODA.exe --smoke-test` and rejects a nonzero exit
or 30-second timeout after checking dashboard HTTP startup. This does not test
the WebView2 window. `-SourceOnly` creates a source-scan test installer without
Java/live-web tool assets; rebuild without that switch for those features. See
the [installer build guide](../../platforms/windows/README.md) for capabilities.

## Vulnerability Data Package

The full installer bundles Syft, Grype, Grype DB, and Chromium, but not the NVD and CISA
KEV feeds. Those change daily while the application does not, so they ship as a
separate package that is refreshed without rebuilding or redistributing the
installer.

Build it on a connected macOS/Linux host (it reuses the same download cache and
`.meta` verification as the Linux offline bundle):

```bash
bash platforms/linux/package-offline.sh --vuln-data-only
# → dist/Windows/koda-vuln-data-<date>.zip  (about 210 MB, NVD 2002-current + KEV)
```

You can also build the package directly on an internet-connected Windows PC.
This does not require Python, Docker, or the KODA installer build tools; it
uses PowerShell 5.1 or PowerShell 7:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\platforms\windows\scripts\build-koda-vuln-data.ps1
# → dist\Windows\koda-vuln-data-<date>.zip
```

The Windows script caches yearly NVD feeds under
`.build\koda-vuln-data-cache\` and verifies each cached feed against its
downloaded `.meta` SHA-256 before using it. The
`recent` and `modified` NVD feeds and the CISA KEV catalog are downloaded and
verified on every run. Add `-Refresh` to download all yearly feeds again. To
limit the data range, use for example `-StartYear 2025 -EndYear 2026`; the
default is the complete NVD range from 2002 through the current UTC year.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\platforms\windows\scripts\build-koda-vuln-data.ps1 `
  -Refresh -StartYear 2025 -EndYear 2026
```

The script prints the archive SHA-256; compare it on the target machine with
`Get-FileHash` before extracting. Extract the zip into the install directory so
that the folders line up:

```powershell
Expand-Archive -Path koda-vuln-data-<date>.zip -DestinationPath $env:LOCALAPPDATA\KODA -Force
# → %LOCALAPPDATA%\KODA\vuln-data\nvd\...
#   %LOCALAPPDATA%\KODA\vuln-data\known_exploited_vulnerabilities.json
#   %LOCALAPPDATA%\KODA\vuln-data\versions.txt   (feed 기준일)
```

`KODA.exe` and `KODA-CLI.exe` detect `vuln-data\` on startup and set
`KODA_NVD_DATA` and `KODA_CISA_KEV` automatically, exactly as they already do
for `tools\`. No path arguments are needed:

```bat
koda jar-scan --target D:\apps ^
  --target D:\worker-apps ^
  --output-dir reports --fail-on high --fail-on-kev
```

`--target` may be repeated. The supplied roots are scanned together and produce
one combined library report pair and SBOM.

The installer keeps `KODA-CLI.cmd` as a compatibility alias and adds
`%LOCALAPPDATA%\KODA` to the per-user `PATH`. Open a new Command Prompt after
installation and type `koda --help` (existing shells must be restarted).

For source-code static analysis, choose one configured standard explicitly. The
HTML output path is the summary page and a `-detail.html` sibling is written for
the complete findings table:

```bat
koda scan --target D:\src\project --standard sw-dev-security-49 ^
  --format html --output reports\source.html
```

The supported profiles include `owasp-asvs-5`, `owasp-proactive-controls`,
`owasp-top-10-2025`, `sw-dev-security-49`, and
`sw-dev-security-7-types`. Use `koda scan --help` to see the complete list and
its issuer/release date, and use `--standard-category` to narrow a profile to
one category.

Java HTML and Markdown reports are currently generated in Korean; `--language`
accepts only `ko`. Findings are grouped by library and installed version, with
`Fixed` advisory candidates and a DB-verified `Final` candidate when available.

Without the data package `jar-scan` still runs on Grype alone, but reports carry
no CVSS or exploited-vulnerability detail, and `--fail-on-kev` exits `2` rather
than passing a gate it cannot evaluate.

Refresh the data by extracting a newer zip over the old one. Upgrading KODA does
not delete `vuln-data\`; uninstalling KODA removes it with the rest of the
install directory.

## Run From Source

```bat
platforms\windows\scripts\koda.bat
```

The source-tree launcher sets `PYTHONPATH` to `platforms\shared\python` before running the scanner.

## Notes

- The macOS Swift app is not cross-compiled to Windows.
- Windows installer metadata lives in `platforms/windows/packaging/KODA.iss`.
- Windows assets live in `platforms/windows/assets/`.

## Scan exit codes

A missing source `--target` exits `2` instead of producing a clean report.
For Java scans, `--fail-on` or `--fail-on-kev` requires a configured, usable
Grype comparison; missing Grype (including `--no-grype`) exits `2` rather than
passing the gate. A successfully evaluated gate exits `1` for matching findings
and `0` when none match. Explicit SBOM-only use with `--no-grype` and no gate
remains supported; exit `0` is not a vulnerability-free determination. A KEV gate
also exits `2` when missing CISA data prevents evaluation.
