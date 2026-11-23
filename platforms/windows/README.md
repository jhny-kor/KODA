# KODA Windows EXE installer build

> The Windows launcher passed Full and SourceOnly loopback dashboard tests and
> both build scripts passed PowerShell syntax checks on Apple Silicon. Local
> SpotBugs and Semgrep runs were verified on macOS. Native Windows installation,
> WebView2, Syft, and analyzer execution still require Windows validation.
> [Earlier verification record](../../docs/verification-2026-10-11.md)

This folder contains the Inno Setup script used to build the direct-download
KODA Windows installer.

The native macOS App Store build is SwiftUI and cannot be compiled into a
Windows executable on macOS. Build the Windows installer on a Windows PC so
PyInstaller can produce a real Windows `.exe`.

## HAR review and local TCP listeners

Select **Review HAR recording** in the Full desktop dashboard to inspect
recorded response headers and cookie attributes and save the review as JSON.
The review counts recorded write requests that carried credential headers and
identifies observations over plain HTTP by origin and entry number.

Select **Local TCP listeners** in the dashboard or run
`KODA-CLI.exe local-listeners --format markdown` to list this PC's listening
addresses and ports. Run `KODA-CLI.exe approval-review --help` for options to
verify an existing audit approval's signature, expiry and recorded local use.

**Review certificates and JWT key length** checks the validity dates and
SHA-256 fingerprint of a PEM or DER certificate and compares a known HMAC key
length against the HS256, HS384 or HS512 minimum. The CLI provides the same
checks through `KODA-CLI.exe tls-cert-review --certificate server.cer` and
`KODA-CLI.exe jwt-key-review --algorithm HS256 --key-bits 256`.

## Local SpotBugs and Semgrep CE

Select **SpotBugs · Semgrep CE** in the local desktop dashboard and enter the
full input paths for one source directory. Set the tool variables before
starting KODA so the dashboard process inherits them. Keep the selected source,
compiled input, and rules on this PC.

- SpotBugs reads an existing Java JAR, `.class` file, or classes directory.
  Set `KODA_SPOTBUGS_JAR` to the installed distribution's `lib\spotbugs.jar`.
  KODA locates Java through `KODA_JAVA_BIN`, `JAVA_HOME`, then `PATH`. Use
  `--spotbugs-source-root` to point to the Java package root inside the selected
  source directory when it differs from the inferred root.
- Semgrep CE uses a local YAML rules file. Put its native Windows launcher
  `semgrep.exe` on `PATH` or set `KODA_SEMGREP_BIN` to its full path.
  KODA uses local rules with metrics disabled.

After installation, the same inputs can be passed to `koda scan`. For example,
run this in PowerShell after setting the tool paths:

```powershell
koda scan --target .\project --spotbugs-input .\project\build\classes --semgrep-rules .\team-rules.yml --format json --output .\koda-report.json
```

SpotBugs Java null-dereference findings can appear as C-01 review candidates
for SW49. Use the **Local baseline** to review other SpotBugs findings and
Semgrep rule matches. Use the external SARIF file field or
`--source-analyzer-sarif` in a separate scan to load previously generated
results. CodeQL results enter through supported SARIF mappings, and an empty
external report leaves control coverage unproven. [Analyzer setup and limits](../../docs/usage.md)

## Local AI fix candidates

Open **Local AI fix candidate** in the personal dashboard and choose an OpenAI-compatible server running on this PC. **List models** retrieves its available models. **Save connection** stores the endpoint and model as a user profile. Windows Credential Manager holds the optional API key.

Select a UTF-8 Python, Java, XML, or JavaScript file of up to 12 KiB, then select a finding and generate a candidate. KODA checks syntax and interfaces and rescans the proposed source, allowing up to three attempts. Review the diff, proposed impact, and test plan. **Download candidate** saves the proposed source as a separate file.

JavaScript validation requires Node.js. Java validation requires a source file that compiles on its own and JDK tools `javac` and `javap` on PATH.

## Result

The build creates:

```text
dist\KODA\KODA.exe
dist\Windows\KODASetup.exe
```

After installation, the Start Menu shortcut runs `KODA.exe`. The executable
starts the local dashboard server and opens it in one native Edge WebView2
window, with no console window and no separate browser tab.

If a PC does not have a working Edge WebView2 Runtime, KODA automatically opens
the dashboard in the default browser instead. Users can also force this path
from the Start Menu shortcut named `KODA (Browser Mode)`.

## Requirements on the build PC

- Windows
- Python 3.10 or newer
- Inno Setup 6

Target users do **not** need to clone the repository. They only need
`KODASetup.exe`.

The installer places both `koda.cmd` and the legacy `KODA-CLI.cmd` in the
per-user install directory and adds that directory to the user `PATH`. Open a
new Command Prompt after installation and run `koda --help` or, for example:

```bat
koda scan --target C:\src\project --standard owasp-asvs-5 --format html --output reports\source.html
```

The requested HTML path is the source main report. KODA also writes the
standalone `-detail.html` source evidence report beside it. For Java archives,
run `koda jar-scan`; it writes `server-library-report.html` and
`server-library-report-detail.html` in the same output directory. The desktop
program's **Report → HTML (main + detail)** action downloads the source pair as
one ZIP so the relative detail file stays together. `--standard-category` can
narrow the selected OWASP or Korean software-development-security profile.

To combine two or more deployment roots into one library report, repeat
`--target`. Archives, components, vulnerabilities, and SBOM entries from all
roots are deduplicated and written to the same report pair:

```bat
koda jar-scan ^
  --target C:\deploy\api ^
  --target C:\deploy\worker ^
  --output-dir reports\java-scan
```

## Build

Run from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\platforms\windows\scripts\build-koda-windows-installer.ps1
```

For a double-clickable wrapper, run `platforms\windows\scripts\build-koda-windows-installer.bat`.

Optional version override:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\platforms\windows\scripts\build-koda-windows-installer.ps1 -Version 0.1.1
```

If Inno Setup is installed in a custom path:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\platforms\windows\scripts\build-koda-windows-installer.ps1 -InnoCompilerPath "C:\Path\To\ISCC.exe"
```

For fast SW49 source-code testing, build the same `KODASetup.exe` without
Java/library scanning, live-web scanning, Playwright/Chromium, Syft, Grype, or
the Grype database. On the first build, omit `-SkipDependencyInstall` once to
install PyInstaller; keep it for subsequent source-only rebuilds:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\platforms\windows\scripts\build-koda-windows-installer.ps1 `
  -SourceOnly -SkipDependencyInstall
```

This profile keeps the dashboard, `koda scan --standard sw-dev-security-49`,
HTML/JSON/Markdown source reports, and the packaged SW49 smoke test. The
lightweight `grype_adapter` Python module remains included because dashboard
imports depend on it; the Grype executable/database are still excluded. The
builder additionally runs the produced `KODA.exe --smoke-test`, verifies a real
local dashboard HTTP response, and rejects nonzero exit or a 30-second timeout.
This startup check does not exercise WebView2. It is a
test installer, not a replacement for the full production installer; rebuild
without `-SourceOnly` for `jar-scan`, `web-scan`, or `web-audit`. The 21-control
`web-audit` command reports `UNSUPPORTED(package_capability_missing)` in this
profile instead of making live requests.

The full installer includes the shared web-audit engine, but external capabilities
remain preflight requirements. The full build installs Playwright and downloads
Chromium on the build PC, then includes Chromium in the GUI bundle for offline
use; the CLI reuses that browser payload. Docker with a digest-pinned ZAP image
and add-on manifest, plus BOAST, must be provided/configured separately. The
installed scanner does not automatically download these external capabilities. Validate an
approval without target traffic first:

```powershell
$env:KODA_APPROVAL_KEY = "operator-managed-secret"
koda web-audit run `
  --profile .\profile.json `
  --approval .\approval.json `
  --confirm-origin https://staging.example.com `
  --dry-run
```

Only a complete required scenario/oracle/cleanup set produces `PASS`. Keep
`UNSUPPORTED` (package capability missing) separate from `NOT_SCANNED` (approval,
credential, or preflight prevented execution) in release gates.

## Microsoft Store path

`KODASetup.exe` is an Inno Setup desktop installer for direct download.
Microsoft Store distribution should use an MSIX package or `.msixupload` file
through Partner Center, not the Inno installer.

Recommended Store lane:

1. Reserve the app name in Partner Center.
2. Convert or package the desktop app as MSIX.
3. Generate a Store upload package (`.msixupload`) with Visual Studio or MSIX tooling.
4. Validate the package locally where possible.
5. Submit the upload package, screenshots, privacy details, age rating, and notes in Partner Center.

Useful Microsoft references:

- [MSIX documentation](https://learn.microsoft.com/en-us/windows/msix/)
- [Package a desktop or UWP app in Visual Studio](https://learn.microsoft.com/en-us/windows/msix/package/packaging-uwp-apps)
- [Create an app submission for your MSIX app](https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msix/create-app-submission?pivots=store-installer-msix)

## Scan exit codes

A missing source `--target` exits `2` instead of producing a clean report.
For Java scans, `--fail-on` or `--fail-on-kev` requires a configured, usable
Grype comparison; missing Grype (including `--no-grype`) exits `2` rather than
passing the gate. A successfully evaluated gate exits `1` for matching findings
and `0` when none match. Explicit SBOM-only use with `--no-grype` and no gate
remains supported; exit `0` is not a vulnerability-free determination. A KEV gate
also exits `2` when missing CISA data prevents evaluation.
