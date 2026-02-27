#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the ObsidianQ release bundle and stages it to dist/ObsidianQBundle/.

.DESCRIPTION
    1. Locates cargo and dotnet (adds ~/.cargo/bin to PATH if needed).
    2. Builds obsidianq.exe (Rust release) from the workspace root.
    3. Publishes ObsidianQ.Launcher.exe (C# WinForms, self-contained, single-file).
    4. Stages all bundle files under dist/ObsidianQBundle/.
    5. Optionally zips to dist/ObsidianQBundle.zip.

.EXAMPLE
    # From repo root:
    powershell -ExecutionPolicy Bypass -File tools\release\build_bundle.ps1

    # Skip the zip step:
    powershell -ExecutionPolicy Bypass -File tools\release\build_bundle.ps1 -NoZip
#>

param(
    [switch]$NoZip
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step  { param($msg) Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK    { param($msg) Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Fail  { param($msg) Write-Host "`n[FAIL] $msg" -ForegroundColor Red; exit 1 }
function Write-Warn  { param($msg) Write-Host "    [WARN] $msg" -ForegroundColor Yellow }

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
$ScriptDir = $PSScriptRoot
$RepoRoot  = Split-Path (Split-Path $ScriptDir -Parent) -Parent

$RustCli      = Join-Path $RepoRoot 'target\release\obsidianq.exe'
$GuiProject   = Join-Path $RepoRoot 'tools\windows-gui\ObsidianQ.Launcher.csproj'
$GuiPublish   = Join-Path $RepoRoot 'tools\windows-gui\bin\Release\net8.0-windows\win-x64\publish\ObsidianQ.Launcher.exe'

$BundleDir    = Join-Path $RepoRoot 'dist\ObsidianQBundle'
$ZipPath      = Join-Path $RepoRoot 'dist\ObsidianQBundle.zip'

$SrcInstall   = Join-Path $RepoRoot 'tools\windows-gui\install_context_menu.cmd'
$SrcUninstall = Join-Path $RepoRoot 'tools\windows-gui\uninstall_context_menu.cmd'
$SrcReadme    = Join-Path $RepoRoot 'tools\windows-gui\README_TESTERS.md'

# ---------------------------------------------------------------------------
# Check required tools
# ---------------------------------------------------------------------------
Write-Step "Checking required tools"

# cargo - look in PATH, then fall back to the standard user install location
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) {
    $fallback = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (Test-Path $fallback) {
        $env:PATH = "$($env:USERPROFILE)\.cargo\bin;$($env:PATH)"
        $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    }
}
if (-not $cargo) { Write-Fail "cargo not found. Install Rust from https://rustup.rs" }
Write-OK "cargo: $(& cargo --version)"

# dotnet
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if (-not $dotnet) { Write-Fail "dotnet not found. Install .NET 8 SDK from https://dotnet.microsoft.com/download" }
Write-OK "dotnet: $(& dotnet --version)"

# Confirm source files exist
foreach ($f in @($GuiProject, $SrcInstall, $SrcUninstall, $SrcReadme)) {
    if (-not (Test-Path $f)) { Write-Fail "Expected source file not found: $f" }
}
Write-OK "Source files verified"

# WinFSP SDK detection - controls whether the mount feature is compiled in.
# The SDK (lib file) is only needed at build time; the runtime MSI is bundled
# separately for end-users.
$WinFspSdkLib = "C:\Program Files (x86)\WinFsp\lib\winfsp-x64.lib"
$WinFspFeatureArgs = @()
if (Test-Path $WinFspSdkLib) {
    $WinFspFeatureArgs = @("--features", "winfsp")
    Write-OK "WinFSP SDK found - building with virtual drive mount support"
} else {
    Write-Warn "WinFSP SDK not found at: $WinFspSdkLib"
    Write-Warn "Virtual drive mount feature will be DISABLED in this build."
    Write-Warn "To enable: install the WinFSP SDK from https://github.com/winfsp/winfsp/releases"
}

# ---------------------------------------------------------------------------
# Build Rust CLI
# ---------------------------------------------------------------------------
Write-Step "Building Rust CLI (release)"
Push-Location $RepoRoot
try {
    & cargo build -p obsidianq-cli --release @WinFspFeatureArgs
    if ($LASTEXITCODE -ne 0) { Write-Fail "cargo build failed (exit $LASTEXITCODE)" }
} finally { Pop-Location }

if (-not (Test-Path $RustCli)) { Write-Fail "Expected binary not found after build: $RustCli" }
$rustSize = [math]::Round((Get-Item $RustCli).Length / 1MB, 2)
Write-OK "obsidianq.exe built  ($rustSize MB)"

# ---------------------------------------------------------------------------
# Publish C# GUI (self-contained, single-file)
# ---------------------------------------------------------------------------
Write-Step "Publishing C# GUI (Release, win-x64, single-file)"
# PublishSingleFile, SelfContained, and RuntimeIdentifier are already in the .csproj.
# Just specify the configuration; dotnet publish reads the rest from the project file.
& dotnet publish $GuiProject -c Release --nologo

if ($LASTEXITCODE -ne 0) { Write-Fail "dotnet publish failed (exit $LASTEXITCODE)" }
if (-not (Test-Path $GuiPublish)) { Write-Fail "Expected launcher not found after publish: $GuiPublish" }

$guiSize = [math]::Round((Get-Item $GuiPublish).Length / 1MB, 2)
Write-OK "ObsidianQ.Launcher.exe published  ($guiSize MB)"

# ---------------------------------------------------------------------------
# Stage bundle
# ---------------------------------------------------------------------------
Write-Step "Staging bundle to $BundleDir"

# Clean and recreate bundle dir
if (Test-Path $BundleDir) { Remove-Item $BundleDir -Recurse -Force }
New-Item -ItemType Directory -Path $BundleDir | Out-Null
New-Item -ItemType Directory -Path (Join-Path $BundleDir 'keys') | Out-Null

# Core binaries
Copy-Item $RustCli   (Join-Path $BundleDir 'obsidianq.exe')
Copy-Item $GuiPublish (Join-Path $BundleDir 'ObsidianQ.Launcher.exe')
Write-OK "Copied binaries"

# WinFSP runtime installer - bundled so the GUI can install it on-demand.
# The MSI is expected in the repo root (not committed to git - add to .gitignore).
$WinFspMsi = Get-ChildItem -Path $RepoRoot -Filter "winfsp-*.msi" -ErrorAction SilentlyContinue |
             Sort-Object Name -Descending | Select-Object -First 1
if ($WinFspMsi) {
    Copy-Item $WinFspMsi.FullName (Join-Path $BundleDir $WinFspMsi.Name)
    Write-OK "Bundled $($WinFspMsi.Name) (WinFSP runtime - installed on-demand)"
} else {
    Write-Warn "winfsp-*.msi not found in repo root - virtual drive mounting will require manual WinFSP install"
    Write-Warn "Place the WinFSP MSI in: $RepoRoot"
}

# Install/uninstall scripts
Copy-Item $SrcInstall   (Join-Path $BundleDir 'install_context_menu.cmd')
Copy-Item $SrcUninstall (Join-Path $BundleDir 'uninstall_context_menu.cmd')
Write-OK "Copied context-menu scripts"

# README
Copy-Item $SrcReadme (Join-Path $BundleDir 'README_TESTERS.md')
Write-OK "Copied README_TESTERS.md"

# keys/README_KEYS.txt  (ASCII-only to avoid encoding issues on PS5.1)
$keysLines = @(
    'ObsidianQ - PQC Key Generation',
    '================================',
    '',
    'Use the CLI to generate a Kyber768 key pair:',
    '',
    '    obsidianq.exe keygen --pubkey recipient.pub.pem --privkey recipient.priv.pem',
    '',
    'Share  recipient.pub.pem  with anyone who needs to encrypt files for you.',
    'Keep   recipient.priv.pem  private (do not share, do not put in cloud storage).',
    '',
    'Key sizes:',
    '  Public  (encapsulation)  key : 1184 bytes (Base64 PEM ~1.6 KB)',
    '  Private (decapsulation)  key : 2400 bytes (Base64 PEM ~3.3 KB)',
    '',
    'Using keys in the GUI:',
    '  - Encrypt: toggle to PQC, browse to recipient.pub.pem',
    '  - Decrypt: toggle to PQC, browse to recipient.priv.pem'
)
$keysLines | Set-Content (Join-Path $BundleDir 'keys\README_KEYS.txt') -Encoding UTF8
Write-OK "Created keys/README_KEYS.txt"

# ---------------------------------------------------------------------------
# Zip
# ---------------------------------------------------------------------------
if (-not $NoZip) {
    Write-Step "Creating zip archive"
    if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
        if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
        Compress-Archive -Path $BundleDir -DestinationPath $ZipPath
        $zipSize = [math]::Round((Get-Item $ZipPath).Length / 1MB, 2)
        Write-OK "Created $ZipPath  ($zipSize MB)"
    } else {
        Write-Warn "Compress-Archive not available - skipping zip."
        Write-Warn "To zip manually: Compress-Archive -Path '$BundleDir' -DestinationPath '$ZipPath'"
    }
} else {
    Write-Warn "-NoZip specified - skipping zip."
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "====================================================" -ForegroundColor Green
Write-Host "  BUILD COMPLETE" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
Write-Host "  Bundle : $BundleDir" -ForegroundColor Green
if (-not $NoZip -and (Test-Path $ZipPath)) {
    Write-Host "  Zip    : $ZipPath" -ForegroundColor Green
}
Write-Host ""
Write-Host "  Hand testers:" -ForegroundColor White
Write-Host "    1. Extract ObsidianQBundle.zip (or copy the folder)" -ForegroundColor White
Write-Host "    2. Run install_context_menu.cmd  (once, no admin)" -ForegroundColor White
Write-Host "    3. Double-click ObsidianQ.Launcher.exe  OR  right-click any file" -ForegroundColor White
Write-Host ""
