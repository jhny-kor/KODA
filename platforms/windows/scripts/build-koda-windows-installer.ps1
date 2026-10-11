[CmdletBinding()]
param(
    [string]$Version = "0.1.0",
    [switch]$SkipDependencyInstall,
    [switch]$SourceOnly,
    [string]$InnoCompilerPath,

    # Pinned security-tool versions. Override these parameters when upgrading.
    [string]$SyftVersion = "1.46.0",
    [string]$GrypeVersion = "0.115.0",

    # Use these only when the build cache already contains the required files.
    [switch]$SkipSecurityToolDownload,
    [switch]$SkipGrypeDatabaseUpdate
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") {
    throw "This build script must be run on Windows. PyInstaller should build Windows executables on Windows."
}

$AppName = "KODA"
$CliAppName = "KODA-CLI"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$SharedPythonRoot = Join-Path $RepoRoot "platforms\shared\python"

$BuildRoot = Join-Path $RepoRoot ".build\koda-windows-installer"
$VenvDir = Join-Path $BuildRoot ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

# Playwright Chromium is downloaded once and bundled into the GUI application.
$BrowsersDir = Join-Path $BuildRoot "ms-playwright"

# Syft, Grype and the Grype vulnerability database are staged here.
$SecurityToolsCacheDir = Join-Path $BuildRoot "security-tools"
$SecurityToolsDownloadDir = Join-Path $BuildRoot "security-tool-downloads"
$SyftExe = Join-Path $SecurityToolsCacheDir "syft.exe"
$GrypeExe = Join-Path $SecurityToolsCacheDir "grype.exe"
$GrypeDbDir = Join-Path $SecurityToolsCacheDir "grype-db"
$SecurityToolLicensesDir = Join-Path $SecurityToolsCacheDir "licenses"

# The source-only installer keeps the dashboard and SW49 source scan, but does
# not ship Java/library or live-web scanner modules, Playwright, or Grype data.
# Keep the lightweight Grype adapter: the dashboard imports its Python API
# even when no Grype executable or database is bundled.
$SourceOnlyExcludedModules = @(
    "security_scanner.web",
    "security_scanner.api_spec",
    "security_scanner.dast",
    "security_scanner.java_vulnerability_scan",
    "security_scanner.java_vulnerability_reporting",
    "security_scanner.java_archives",
    "security_scanner.java_inventory",
    "security_scanner.syft_adapter",
    "security_scanner.offline_vuln_data",
    "security_scanner.sbom_verification"
)

$GuiEntryPoint = Join-Path $RepoRoot "platforms\windows\scripts\koda-desktop.py"
$CliEntryPoint = Join-Path $BuildRoot "koda-cli-entry.py"
$RuntimeHook = Join-Path $BuildRoot "koda-runtime-env.py"
$Sw49ResourcesDir = Join-Path $SharedPythonRoot "security_scanner\resources\sw49"
$Sw49ContractsSource = Join-Path $Sw49ResourcesDir "contracts.json"
$Sw49ResourcesData = $Sw49ResourcesDir + ";security_scanner\resources\sw49"

$DistDir = Join-Path $RepoRoot "dist"
$AppDistDir = Join-Path $DistDir $AppName
$CliDistDir = Join-Path $AppDistDir $CliAppName
$GuiExecutable = Join-Path $AppDistDir "KODA.exe"
$CliExecutable = Join-Path $CliDistDir "$CliAppName.exe"
$InstalledToolsDir = Join-Path $AppDistDir "tools"

$InstallerOutDir = Join-Path $DistDir "Windows"
$InnoScript = Join-Path $RepoRoot "platforms\windows\packaging\KODA.iss"
$IconPath = Join-Path $RepoRoot "platforms\windows\assets\KODA.ico"

if (-not (Test-Path -LiteralPath $Sw49ContractsSource -PathType Leaf)) {
    throw "Missing SW49 contract resource: $Sw49ContractsSource"
}

function Find-Python310 {
    $candidates = @(
        [pscustomobject]@{ Command = "py"; Args = @("-3") },
        [pscustomobject]@{ Command = "python"; Args = @() },
        [pscustomobject]@{ Command = "python3"; Args = @() }
    )

    foreach ($candidate in $candidates) {
        $command = $candidate.Command
        $prefixArgs = @($candidate.Args)

        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
            continue
        }

        $testArgs = $prefixArgs + @(
            "-c",
            "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
        )

        & $command @testArgs *> $null

        if ($LASTEXITCODE -eq 0) {
            return $candidate
        }
    }

    throw "Python 3.10 or newer was not found. Install Python 3.10+ and run this build script again."
}

function Find-InnoCompiler {
    param([string]$RequestedPath)

    if ($RequestedPath) {
        if (Test-Path -LiteralPath $RequestedPath -PathType Leaf) {
            return (Resolve-Path -LiteralPath $RequestedPath).Path
        }

        throw "Inno Setup compiler was not found at: $RequestedPath"
    }

    $candidates = @()

    if (${env:ProgramFiles(x86)}) {
        $candidates += (
            Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"
        )
    }

    if ($env:ProgramFiles) {
        $candidates += (
            Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"
        )
    }

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return $candidate
        }
    }

    $command = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue

    if ($command) {
        return $command.Source
    }

    throw "Inno Setup 6 compiler was not found. Install Inno Setup 6 or pass -InnoCompilerPath."
}

function Ensure-VenvPip {
    param([string]$PythonPath)

    & $PythonPath -m pip --version *> $null

    if ($LASTEXITCODE -eq 0) {
        return
    }

    Write-Host "pip is missing from the build virtual environment. Running ensurepip."

    & $PythonPath -m ensurepip --upgrade

    if ($LASTEXITCODE -ne 0) {
        throw @"
The virtual environment does not contain pip, and ensurepip failed.
Delete this directory and run the build again:

$VenvDir

If the problem continues, repair or reinstall Python with pip and venv enabled.
"@
    }

    & $PythonPath -m pip --version *> $null

    if ($LASTEXITCODE -ne 0) {
        throw "pip is still unavailable after running ensurepip."
    }
}

function Write-Utf8NoBomFile {
    param(
        [string]$Path,
        [string]$Content
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Invoke-KodaDownload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    $parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Path $parent -Force | Out-Null

    Write-Host "Downloading: $Uri"
    Write-Host "Destination: $Destination"

    # GitHub releases require modern TLS.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Invoke-WebRequest `
        -Uri $Uri `
        -OutFile $Destination `
        -UseBasicParsing

    if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) {
        throw "Download did not create the expected file: $Destination"
    }

    $size = (Get-Item -LiteralPath $Destination).Length
    if ($size -le 0) {
        throw "Downloaded file is empty: $Destination"
    }
}

function Install-ZippedSecurityTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolName,

        [Parameter(Mandatory = $true)]
        [string]$Version,

        [Parameter(Mandatory = $true)]
        [string]$DownloadUri,

        [Parameter(Mandatory = $true)]
        [string]$ExecutableName,

        [Parameter(Mandatory = $true)]
        [string]$DestinationExecutable
    )

    $toolDownloadDir = Join-Path $SecurityToolsDownloadDir $ToolName
    $archivePath = Join-Path $toolDownloadDir "$ToolName-$Version-windows-amd64.zip"
    $extractDir = Join-Path $toolDownloadDir "extracted"

    if (Test-Path -LiteralPath $toolDownloadDir) {
        Remove-Item -LiteralPath $toolDownloadDir -Recurse -Force
    }

    New-Item -ItemType Directory -Path $toolDownloadDir -Force | Out-Null

    Invoke-KodaDownload -Uri $DownloadUri -Destination $archivePath

    Write-Host "Extracting $ToolName $Version."
    Expand-Archive `
        -LiteralPath $archivePath `
        -DestinationPath $extractDir `
        -Force

    $executable = Get-ChildItem `
        -LiteralPath $extractDir `
        -Filter $ExecutableName `
        -File `
        -Recurse |
        Select-Object -First 1

    if (-not $executable) {
        throw "$ExecutableName was not found in downloaded $ToolName archive."
    }

    New-Item -ItemType Directory -Path $SecurityToolsCacheDir -Force | Out-Null
    Copy-Item `
        -LiteralPath $executable.FullName `
        -Destination $DestinationExecutable `
        -Force

    # Preserve upstream license text when the release archive includes it.
    $license = Get-ChildItem `
        -LiteralPath $extractDir `
        -File `
        -Recurse |
        Where-Object { $_.Name -match '^LICENSE(?:\..*)?$' } |
        Select-Object -First 1

    if ($license) {
        New-Item -ItemType Directory -Path $SecurityToolLicensesDir -Force | Out-Null
        Copy-Item `
            -LiteralPath $license.FullName `
            -Destination (Join-Path $SecurityToolLicensesDir "$ToolName-LICENSE.txt") `
            -Force
    }
}

function Test-SecurityTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolName,

        [Parameter(Mandatory = $true)]
        [string]$Executable
    )

    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        throw "$ToolName executable was not found: $Executable"
    }

    Write-Host "Checking $ToolName executable."
    & $Executable --version

    if ($LASTEXITCODE -ne 0) {
        throw "$ToolName version check failed: $Executable"
    }
}

function Update-GrypeDatabase {
    if (Test-Path -LiteralPath $GrypeDbDir) {
        Remove-Item -LiteralPath $GrypeDbDir -Recurse -Force
    }

    New-Item -ItemType Directory -Path $GrypeDbDir -Force | Out-Null

    $previousCacheDir = $env:GRYPE_DB_CACHE_DIR
    $previousAutoUpdate = $env:GRYPE_DB_AUTO_UPDATE
    $previousValidateAge = $env:GRYPE_DB_VALIDATE_AGE
    $previousCheckForAppUpdate = $env:GRYPE_CHECK_FOR_APP_UPDATE

    try {
        $env:GRYPE_DB_CACHE_DIR = $GrypeDbDir
        $env:GRYPE_DB_AUTO_UPDATE = "true"
        $env:GRYPE_DB_VALIDATE_AGE = "false"
        $env:GRYPE_CHECK_FOR_APP_UPDATE = "false"

        Write-Host "Downloading the Grype vulnerability database."
        & $GrypeExe db update

        if ($LASTEXITCODE -ne 0) {
            throw "Grype vulnerability database update failed."
        }

        Write-Host "Validating the downloaded Grype vulnerability database."
        $statusPath = Join-Path $SecurityToolsCacheDir "grype-db-status.json"
        & $GrypeExe db status -o json |
            Set-Content -LiteralPath $statusPath -Encoding UTF8

        if ($LASTEXITCODE -ne 0) {
            throw "Grype database status check failed."
        }

        $dbFiles = @(
            Get-ChildItem `
                -LiteralPath $GrypeDbDir `
                -File `
                -Recurse `
                -ErrorAction SilentlyContinue
        )

        if ($dbFiles.Count -eq 0) {
            throw "Grype database update completed without creating database files: $GrypeDbDir"
        }
    }
    finally {
        $env:GRYPE_DB_CACHE_DIR = $previousCacheDir
        $env:GRYPE_DB_AUTO_UPDATE = $previousAutoUpdate
        $env:GRYPE_DB_VALIDATE_AGE = $previousValidateAge
        $env:GRYPE_CHECK_FOR_APP_UPDATE = $previousCheckForAppUpdate
    }
}

function Confirm-GrypeDatabaseExists {
    if (-not (Test-Path -LiteralPath $GrypeDbDir -PathType Container)) {
        throw @"
The Grype database cache does not exist:

$GrypeDbDir

Run the build without -SkipGrypeDatabaseUpdate while connected to the internet.
"@
    }

    $dbFiles = @(
        Get-ChildItem `
            -LiteralPath $GrypeDbDir `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue
    )

    if ($dbFiles.Count -eq 0) {
        throw "The Grype database cache is empty: $GrypeDbDir"
    }
}

function Write-SecurityToolManifest {
    $syftHash = (Get-FileHash -LiteralPath $SyftExe -Algorithm SHA256).Hash
    $grypeHash = (Get-FileHash -LiteralPath $GrypeExe -Algorithm SHA256).Hash
    $generatedAt = [DateTimeOffset]::UtcNow.ToString("o")

    $manifest = @"
KODA bundled security tools
Generated at UTC: $generatedAt

Syft version requested: $SyftVersion
Syft executable: tools\syft.exe
Syft SHA256: $syftHash

Grype version requested: $GrypeVersion
Grype executable: tools\grype.exe
Grype SHA256: $grypeHash

Grype database: tools\grype-db
Grype database auto-update at runtime: disabled
"@

    Write-Utf8NoBomFile `
        -Path (Join-Path $SecurityToolsCacheDir "TOOL-VERSIONS.txt") `
        -Content $manifest
}

Write-Host "Preparing KODA Windows installer build."
Write-Host "Repository: $RepoRoot"
Write-Host "Syft version: $SyftVersion"
Write-Host "Grype version: $GrypeVersion"

if (-not (Test-Path -LiteralPath $GuiEntryPoint -PathType Leaf)) {
    throw "Missing GUI PyInstaller entry point: $GuiEntryPoint"
}

if (-not (Test-Path -LiteralPath (
    Join-Path $SharedPythonRoot "security_scanner"
) -PathType Container)) {
    throw "security_scanner package was not found. Run this script from the full repository."
}

if (-not (Test-Path -LiteralPath $InnoScript -PathType Leaf)) {
    throw "Missing Inno Setup script: $InnoScript"
}

New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null
New-Item -ItemType Directory -Path $InstallerOutDir -Force | Out-Null
New-Item -ItemType Directory -Path $SecurityToolsCacheDir -Force | Out-Null

$python = Find-Python310
$pythonCommand = $python.Command
$pythonArgs = @($python.Args)

if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
    Write-Host "Creating build virtual environment."

    & $pythonCommand @(
        $pythonArgs + @(
            "-m",
            "venv",
            $VenvDir
        )
    )

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create build virtual environment."
    }
}

Ensure-VenvPip -PythonPath $VenvPython

if (-not $SkipDependencyInstall) {
    Write-Host "Upgrading pip."

    & $VenvPython -m pip install --upgrade pip

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to upgrade pip."
    }

    Write-Host "Installing build dependencies."

    $buildPackages = @("pyinstaller")
    if (-not $SourceOnly) {
        $buildPackages += @("pywebview", "playwright==1.61.0")
    }

    & $VenvPython -m pip install --upgrade $buildPackages

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install the Windows build dependencies."
    }

    if (-not $SourceOnly) {
        Write-Host "Downloading Playwright Chromium for offline SPA rendering."

        $env:PLAYWRIGHT_BROWSERS_PATH = $BrowsersDir
        & $VenvPython -m playwright install chromium

        if ($LASTEXITCODE -ne 0) {
            throw "Failed to download Playwright Chromium."
        }
    }
    else {
        Write-Host "Source-only build: skipping pywebview, Playwright, and Chromium."
    }
}
else {
    Write-Host "Skipping Python dependency installation."

    & $VenvPython -m PyInstaller --version *> $null

    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller is not installed in the build virtual environment. Run again without -SkipDependencyInstall."
    }
}

# ---------------------------------------------------------------------------
# Download Syft and Grype for Windows x86_64 unless this is a source-only build.
# ---------------------------------------------------------------------------

if ($SourceOnly) {
    Write-Host "Source-only build: skipping Syft, Grype, NVD/CISA data, and Grype DB."
}
else {
    if (-not $SkipSecurityToolDownload) {
        $syftUri = "https://github.com/anchore/syft/releases/download/v$SyftVersion/syft_${SyftVersion}_windows_amd64.zip"
        $grypeUri = "https://github.com/anchore/grype/releases/download/v$GrypeVersion/grype_${GrypeVersion}_windows_amd64.zip"

        Install-ZippedSecurityTool `
            -ToolName "syft" `
            -Version $SyftVersion `
            -DownloadUri $syftUri `
            -ExecutableName "syft.exe" `
            -DestinationExecutable $SyftExe

        Install-ZippedSecurityTool `
            -ToolName "grype" `
            -Version $GrypeVersion `
            -DownloadUri $grypeUri `
            -ExecutableName "grype.exe" `
            -DestinationExecutable $GrypeExe
    }
    else {
        Write-Host "Skipping Syft and Grype downloads. Using cached executables."
    }

    Test-SecurityTool -ToolName "Syft" -Executable $SyftExe
    Test-SecurityTool -ToolName "Grype" -Executable $GrypeExe

    if (-not $SkipGrypeDatabaseUpdate) {
        Update-GrypeDatabase
    }
    else {
        Write-Host "Skipping Grype database update. Using cached database."
        Confirm-GrypeDatabaseExists
    }

    Write-SecurityToolManifest
}

# ---------------------------------------------------------------------------
# Generate runtime hook shared by GUI and CLI builds.
#
# The hook runs before application imports and points KODA at the bundled tools.
# ---------------------------------------------------------------------------

$runtimeHookSource = @'
from __future__ import annotations

import os
import sys
from pathlib import Path


def _install_root() -> Path:
    executable_dir = Path(sys.executable).resolve().parent

    # GUI:
    #   KODA\KODA.exe
    #
    # CLI:
    #   KODA\KODA-CLI\KODA-CLI.exe
    if executable_dir.name.casefold() == "koda-cli":
        return executable_dir.parent

    return executable_dir


root = _install_root()
tools = root / "tools"
syft = tools / "syft.exe"
grype = tools / "grype.exe"
grype_db = tools / "grype-db"

if syft.is_file():
    os.environ.setdefault("KODA_SYFT_BIN", str(syft))

if grype.is_file():
    os.environ.setdefault("KODA_GRYPE_BIN", str(grype))

if grype_db.is_dir():
    os.environ.setdefault("GRYPE_DB_CACHE_DIR", str(grype_db))

# NVD and CISA KEV ship as a separate data package because they change daily
# while the application does not. Unzip koda-vuln-data-<date>.zip into the
# install directory and jar-scan picks it up here; without it the scan still
# runs on Grype alone.
vuln_data = root / "vuln-data"
nvd_data = vuln_data / "nvd"
cisa_kev = vuln_data / "known_exploited_vulnerabilities.json"

if nvd_data.is_dir():
    os.environ.setdefault("KODA_NVD_DATA", str(nvd_data))

if cisa_kev.is_file():
    os.environ.setdefault("KODA_CISA_KEV", str(cisa_kev))

# The installed product is intended to work without internet access.
os.environ.setdefault("GRYPE_DB_AUTO_UPDATE", "false")
os.environ.setdefault("GRYPE_DB_VALIDATE_AGE", "false")
os.environ.setdefault("GRYPE_CHECK_FOR_APP_UPDATE", "false")

# Reuse Chromium bundled in the GUI application from the CLI build as well.
browser_candidates = (
    root / "_internal" / "ms-playwright",
    root / "ms-playwright",
)

for candidate in browser_candidates:
    if candidate.is_dir():
        os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(candidate))
        break
'@

if ($SourceOnly) {
    $runtimeHookSource += "`r`nos.environ.setdefault('KODA_SOURCE_ONLY', '1')`r`n"
}

Write-Utf8NoBomFile `
    -Path $RuntimeHook `
    -Content $runtimeHookSource

# Console entry point for KODA-CLI.exe.
$cliEntrySource = @'
from __future__ import annotations

from security_scanner.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
'@

Write-Utf8NoBomFile `
    -Path $CliEntryPoint `
    -Content $cliEntrySource

if (Test-Path -LiteralPath $AppDistDir) {
    Write-Host "Removing previous application build: $AppDistDir"
    Remove-Item -LiteralPath $AppDistDir -Recurse -Force
}

# ---------------------------------------------------------------------------
# Build GUI application: dist\KODA\KODA.exe
# ---------------------------------------------------------------------------

$guiWorkPath = Join-Path $BuildRoot "pyinstaller-gui-work"
$guiSpecPath = Join-Path $BuildRoot "pyinstaller-gui-spec"

$guiPyInstallerArgs = @(
    "--noconfirm",
    "--clean",
    "--onedir",
    "--windowed",

    "--name", $AppName,
    "--distpath", $DistDir,
    "--workpath", $guiWorkPath,
    "--specpath", $guiSpecPath,
    "--paths", $SharedPythonRoot,
    "--runtime-hook", $RuntimeHook,

    "--add-data",
    (
        (
            Join-Path $SharedPythonRoot `
                "security_scanner\assets\koda-hwpx-template.hwpx"
        ) + ";security_scanner\assets"
    ),

    "--add-data", $Sw49ResourcesData,

    "--hidden-import", "tkinter",
    "--hidden-import", "tkinter.filedialog",
    "--hidden-import", "tkinter.messagebox",
    "--hidden-import", "security_scanner.web_audit"
)

if ($SourceOnly) {
    foreach ($module in $SourceOnlyExcludedModules) {
        $guiPyInstallerArgs += @("--exclude-module", $module)
    }
}
else {
    $guiPyInstallerArgs += @(
        "--collect-submodules", "security_scanner",
        "--hidden-import", "security_scanner.web",
        "--collect-all", "webview",
        "--collect-all", "clr_loader",
        "--collect-all", "pythonnet",
        "--collect-all", "playwright"
    )
}

if (-not $SourceOnly -and (Test-Path -LiteralPath $BrowsersDir -PathType Container)) {
    $guiPyInstallerArgs += @(
        "--add-data",
        ($BrowsersDir + ";ms-playwright")
    )
}
elseif (-not $SourceOnly) {
    throw @"
Chromium was not found at:

$BrowsersDir

The Full distribution requires bundled Chromium for the web-audit browser capability.
Run the script again without -SkipDependencyInstall to stage Chromium.
"@
}

if (Test-Path -LiteralPath $IconPath -PathType Leaf) {
    $guiPyInstallerArgs += @(
        "--icon",
        $IconPath
    )
}

$guiPyInstallerArgs += $GuiEntryPoint

Write-Host "Building KODA.exe with PyInstaller."
& $VenvPython -m PyInstaller @guiPyInstallerArgs

if ($LASTEXITCODE -ne 0) {
    throw "KODA GUI PyInstaller build failed."
}

if (-not (Test-Path -LiteralPath $GuiExecutable -PathType Leaf)) {
    throw "KODA.exe was not created: $GuiExecutable"
}

$guiSw49Contracts = Join-Path $AppDistDir "_internal\security_scanner\resources\sw49\contracts.json"
if (-not (Test-Path -LiteralPath $guiSw49Contracts -PathType Leaf)) {
    throw "KODA.exe bundle is missing SW49 contracts: $guiSw49Contracts"
}

# Exercise the packaged GUI imports and an actual dashboard HTTP response.
# Wait on the returned process because this is a windowed executable.
$guiSmokeProcess = Start-Process `
    -FilePath $GuiExecutable `
    -ArgumentList "--smoke-test" `
    -PassThru
if (-not $guiSmokeProcess.WaitForExit(30000)) {
    Stop-Process -Id $guiSmokeProcess.Id -Force -ErrorAction SilentlyContinue
    throw "KODA.exe dashboard startup smoke test timed out."
}
if ($guiSmokeProcess.ExitCode -ne 0) {
    throw "KODA.exe dashboard startup smoke test failed with exit code $($guiSmokeProcess.ExitCode)."
}

# ---------------------------------------------------------------------------
# Build CLI application: dist\KODA\KODA-CLI\KODA-CLI.exe
# ---------------------------------------------------------------------------

$cliWorkPath = Join-Path $BuildRoot "pyinstaller-cli-work"
$cliSpecPath = Join-Path $BuildRoot "pyinstaller-cli-spec"

$cliPyInstallerArgs = @(
    "--noconfirm",
    "--clean",
    "--onedir",
    "--console",

    "--name", $CliAppName,
    "--distpath", $AppDistDir,
    "--workpath", $cliWorkPath,
    "--specpath", $cliSpecPath,
    "--paths", $SharedPythonRoot,
    "--runtime-hook", $RuntimeHook,

    "--add-data",
    (
        (
            Join-Path $SharedPythonRoot `
                "security_scanner\assets\koda-hwpx-template.hwpx"
        ) + ";security_scanner\assets"
    ),

    "--add-data", $Sw49ResourcesData,

    "--hidden-import", "tkinter",
    "--hidden-import", "tkinter.filedialog",
    "--hidden-import", "tkinter.messagebox",
    "--hidden-import", "security_scanner.web_audit"
)

if ($SourceOnly) {
    foreach ($module in $SourceOnlyExcludedModules) {
        $cliPyInstallerArgs += @("--exclude-module", $module)
    }
}
else {
    $cliPyInstallerArgs += @(
        "--collect-submodules", "security_scanner",
        "--hidden-import", "security_scanner.web",
        "--collect-all", "playwright"
    )
}

if (Test-Path -LiteralPath $IconPath -PathType Leaf) {
    $cliPyInstallerArgs += @(
        "--icon",
        $IconPath
    )
}

$cliPyInstallerArgs += $CliEntryPoint

Write-Host "Building KODA-CLI.exe with PyInstaller."
& $VenvPython -m PyInstaller @cliPyInstallerArgs

if ($LASTEXITCODE -ne 0) {
    throw "KODA CLI PyInstaller build failed."
}

if (-not (Test-Path -LiteralPath $CliExecutable -PathType Leaf)) {
    throw "KODA-CLI.exe was not created: $CliExecutable"
}

$cliSw49Contracts = Join-Path $CliDistDir "_internal\security_scanner\resources\sw49\contracts.json"
if (-not (Test-Path -LiteralPath $cliSw49Contracts -PathType Leaf)) {
    throw "KODA-CLI.exe bundle is missing SW49 contracts: $cliSw49Contracts"
}

& $CliExecutable --help *> $null
if ($LASTEXITCODE -ne 0) {
    throw "KODA-CLI.exe startup smoke test failed."
}

# Test the packaged executable itself against Windows false-positive regressions.
$sw49SmokeDir = Join-Path $BuildRoot "sw49-false-positive-smoke"
$sw49SmokeReport = Join-Path $BuildRoot "sw49-false-positive-smoke-report.json"
$sw49SmokeValidator = Join-Path $BuildRoot "validate-sw49-smoke.py"

if (Test-Path -LiteralPath $sw49SmokeDir) {
    Remove-Item -LiteralPath $sw49SmokeDir -Recurse -Force
}
if (Test-Path -LiteralPath $sw49SmokeReport) {
    Remove-Item -LiteralPath $sw49SmokeReport -Force
}

New-Item -ItemType Directory -Path (Join-Path $sw49SmokeDir "pdfjs\web") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $sw49SmokeDir "thirdparty") -Force | Out-Null

Write-Utf8NoBomFile -Path (Join-Path $sw49SmokeDir "DateCase.java") -Content @'
import devonframe.util.DateUtil;
class DateCase {
    String applDate = DateUtil.getDate("yyyyMMdd");
    void run() {
        String startDate = DateUtil.getNextMonthDate(applDate, 1);
        String value = String.format("%s01", String.format(startDate, "yyyyMM"));
    }
}
'@
Write-Utf8NoBomFile -Path (Join-Path $sw49SmokeDir "ThreadCase.java") -Content @'
class ThreadCase {
    void run() throws Exception {
        Thread thread11 = null;
        if (thread11 != null) thread11.join();
    }
}
'@
Write-Utf8NoBomFile -Path (Join-Path $sw49SmokeDir "viewer.html") -Content @'
<script>new RegExp("x").exec(window.location.href);</script>
'@
Write-Utf8NoBomFile -Path (Join-Path $sw49SmokeDir "thirdparty\jsrender.min.js") -Content @'
/*! JsRender v1.0.5 */
!function(){try{}catch(e){};target.innerHTML=location.hash}();
'@
Write-Utf8NoBomFile -Path (Join-Path $sw49SmokeDir "pdfjs\web\viewer.js") -Content @'
const layout = pdfDocument.getPageLayout().catch(function () {});
'@
Write-Utf8NoBomFile -Path (Join-Path $sw49SmokeDir "unsafe.c") -Content @'
void log_value(char *user_input) { printf(user_input); }
'@
Write-Utf8NoBomFile -Path $sw49SmokeValidator -Content @'
import json
import sys
from pathlib import Path

findings = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("findings", [])
unexpected = []

for finding in findings:
    leaf = Path(str(finding.get("path", ""))).name
    rule_id = str(finding.get("rule_id", ""))
    if (
        (leaf == "DateCase.java" and rule_id == "code.format-string-user-input")
        or (leaf == "ThreadCase.java" and rule_id == "code.null-pointer-dereference")
        or (leaf == "viewer.html" and rule_id == "code.eval-user-input")
        or leaf == "jsrender.min.js"
        or (leaf == "viewer.js" and rule_id == "code.empty-exception-handler")
    ):
        unexpected.append(rule_id)

if unexpected:
    raise SystemExit("known SW49 false positives: " + ", ".join(unexpected))

if not any(
    str(finding.get("rule_id", "")) == "code.format-string-user-input"
    and Path(str(finding.get("path", ""))).name == "unsafe.c"
    for finding in findings
):
    raise SystemExit("SW49 positive control was not detected")
'@

$previousErrorActionPreference = $ErrorActionPreference
try {
    # Windows PowerShell 5.1 promotes native stderr progress messages to
    # NativeCommandError when the script-wide preference is Stop.
    $ErrorActionPreference = "Continue"
    & $CliExecutable scan `
        --target $sw49SmokeDir `
        --standard sw-dev-security-49 `
        --format json `
        --output $sw49SmokeReport *> $null
    $sw49SmokeExitCode = $LASTEXITCODE

    if ($sw49SmokeExitCode -ne 0 -or -not (Test-Path -LiteralPath $sw49SmokeReport -PathType Leaf)) {
        throw "Packaged KODA CLI failed the SW49 false-positive smoke scan."
    }

    $sw49SmokeValidationOutput = @(& $VenvPython $sw49SmokeValidator $sw49SmokeReport 2>&1)
    $sw49SmokeValidationExitCode = $LASTEXITCODE

    if ($sw49SmokeValidationExitCode -ne 0) {
        throw "Packaged KODA CLI failed SW49 smoke validation: $($sw49SmokeValidationOutput -join ' ')"
    }
}
finally {
    $ErrorActionPreference = $previousErrorActionPreference
}

# ---------------------------------------------------------------------------
# Copy Syft, Grype and the Grype DB into the installation tree.
# ---------------------------------------------------------------------------

if (-not $SourceOnly) {
    if (Test-Path -LiteralPath $InstalledToolsDir) {
        Remove-Item -LiteralPath $InstalledToolsDir -Recurse -Force
    }

    Copy-Item `
        -LiteralPath $SecurityToolsCacheDir `
        -Destination $InstalledToolsDir `
        -Recurse `
        -Force

    if (-not (Test-Path -LiteralPath (
        Join-Path $InstalledToolsDir "syft.exe"
    ) -PathType Leaf)) {
        throw "Bundled syft.exe was not copied into the installer tree."
    }

    if (-not (Test-Path -LiteralPath (
        Join-Path $InstalledToolsDir "grype.exe"
    ) -PathType Leaf)) {
        throw "Bundled grype.exe was not copied into the installer tree."
    }

    Confirm-GrypeDatabaseExists
}
else {
    Write-Utf8NoBomFile `
        -Path (Join-Path $AppDistDir "SOURCE-ONLY.txt") `
        -Content "This KODASetup.exe contains SW49 source-code analysis only. Java/library and live-web scans are excluded."
}

# Root-level CLI launcher.
$cliLauncherPath = Join-Path $AppDistDir "KODA-CLI.cmd"

$cliLauncherSource = @'
@echo off
"%~dp0KODA-CLI\KODA-CLI.exe" %*
exit /b %ERRORLEVEL%
'@

Set-Content `
    -LiteralPath $cliLauncherPath `
    -Value $cliLauncherSource `
    -Encoding ASCII

# Keep the legacy launcher for compatibility and expose the short command
# users can type after the installer adds this directory to PATH.
$kodaLauncherPath = Join-Path $AppDistDir "koda.cmd"
Set-Content `
    -LiteralPath $kodaLauncherPath `
    -Value $cliLauncherSource `
    -Encoding ASCII

# Start Menu shell that remains open.
$cliShellPath = Join-Path $AppDistDir "KODA-CLI-Shell.cmd"

$cliShellSource = @'
@echo off
title KODA CLI
cd /d "%USERPROFILE%"
set "PATH=%~dp0;%PATH%"
echo.
echo KODA CLI
echo Run: koda --help
echo This shell temporarily adds the installed KODA directory to PATH.
echo.
%COMSPEC% /K
'@

Set-Content `
    -LiteralPath $cliShellPath `
    -Value $cliShellSource `
    -Encoding ASCII

# ---------------------------------------------------------------------------
# Copy documentation and example configuration files.
# ---------------------------------------------------------------------------

foreach ($fileName in @(
    "README.md",
    "scanner_config.example.json",
    "scanner_config.documents.example.json",
    "LICENSE",
    "NOTICE"
)) {
    $source = Join-Path $SharedPythonRoot $fileName

    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        $source = Join-Path $RepoRoot $fileName
    }

    if (Test-Path -LiteralPath $source -PathType Leaf) {
        Copy-Item `
            -LiteralPath $source `
            -Destination $AppDistDir `
            -Force
    }
}

$docsPath = Join-Path $RepoRoot "docs"

if (Test-Path -LiteralPath $docsPath -PathType Container) {
    Copy-Item `
        -LiteralPath $docsPath `
        -Destination $AppDistDir `
        -Recurse `
        -Force
}

# ---------------------------------------------------------------------------
# Build KODASetup.exe.
# ---------------------------------------------------------------------------

$iscc = Find-InnoCompiler -RequestedPath $InnoCompilerPath

Write-Host "Building KODASetup.exe with Inno Setup."
& $iscc "/DMyAppVersion=$Version" $InnoScript

if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup build failed."
}

$setupPath = Join-Path $InstallerOutDir "KODASetup.exe"

if (-not (Test-Path -LiteralPath $setupPath -PathType Leaf)) {
    throw "Installer was not created: $setupPath"
}

Write-Host ""
Write-Host "Build finished successfully."
Write-Host "GUI executable: $GuiExecutable"
Write-Host "CLI executable: $CliExecutable"
Write-Host "Bundled tools: $InstalledToolsDir"
Write-Host "Installer: $setupPath"
Write-Host ""
Write-Host "Installed CLI example:"
Write-Host '  koda jar-scan --target . --output-dir output --fail-on high'
Write-Host ""
Write-Host "Syft, Grype and the Grype DB will be detected automatically."
