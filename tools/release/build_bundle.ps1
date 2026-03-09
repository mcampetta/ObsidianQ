#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the ObsidianQ release bundle and stages it to dist/ObsidianQBundle/.

.DESCRIPTION
    1. Locates cargo and dotnet (adds ~/.cargo/bin to PATH if needed).
    2. Builds obsidianq.exe (Rust release) from the workspace root.
    3. Publishes ObsidianQ.Launcher.exe (C# WinForms, self-contained, single-file).
    4. Stages core bundle files under dist/ObsidianQBundle/.
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
foreach ($f in @($GuiProject)) {
    if (-not (Test-Path $f)) { Write-Fail "Expected source file not found: $f" }
}
Write-OK "Source files verified"

# ---------------------------------------------------------------------------
# Build Rust CLI
# ---------------------------------------------------------------------------
Write-Step "Building Rust CLI (release)"
Push-Location $RepoRoot
try {
    & cargo build -p obsidianq-cli --release
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
# If Remove-Item fails (e.g. Explorer or a file watcher holds the directory open)
# fall back to removing only the contents so we can still overwrite with fresh files.
if (Test-Path $BundleDir) {
    $removed = $false
    try { Remove-Item $BundleDir -Recurse -Force; $removed = $true } catch {}
    if (-not $removed) {
        Write-Warn "Could not delete bundle dir (locked). Clearing contents instead."
        Get-ChildItem $BundleDir -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
}
if (-not (Test-Path $BundleDir)) { New-Item -ItemType Directory -Path $BundleDir | Out-Null }

# Core binaries
Copy-Item $RustCli   (Join-Path $BundleDir 'obsidianq.exe')
Copy-Item $GuiPublish (Join-Path $BundleDir 'ObsidianQ.Launcher.exe')
Write-OK "Copied binaries"

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
Write-Host "  Release contents:" -ForegroundColor White
Write-Host "    - ObsidianQ.Launcher.exe" -ForegroundColor White
Write-Host "    - obsidianq.exe" -ForegroundColor White
Write-Host ""

