#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the ObsidianQ release bundle and stages it to dist/ObsidianQBundle/.

.DESCRIPTION
    1. Locates cargo and dotnet (adds ~/.cargo/bin to PATH if needed).
    2. Builds obsidianq.exe and obsidianq-bootstrapper.exe (Rust release) from the workspace root.
    3. Refreshes the launcher's embedded binaries from the current Rust build outputs.
    4. Publishes ObsidianQ.Launcher.exe (C# WinForms, self-contained, single-file).
    5. Stages core bundle files under dist/ObsidianQBundle/.

.EXAMPLE
    # From repo root:
    powershell -ExecutionPolicy Bypass -File tools\release\build_bundle.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step  { param($msg) Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK    { param($msg) Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Fail  { param($msg) Write-Host "`n[FAIL] $msg" -ForegroundColor Red; exit 1 }
function Write-Warn  { param($msg) Write-Host "    [WARN] $msg" -ForegroundColor Yellow }
function Get-Sha256  { param([string]$Path) (Get-FileHash -Path $Path -Algorithm SHA256).Hash }

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
$ScriptDir = $PSScriptRoot
$RepoRoot  = Split-Path (Split-Path $ScriptDir -Parent) -Parent

$RustCli              = Join-Path $RepoRoot 'target\release\obsidianq.exe'
$RustBootstrapper     = Join-Path $RepoRoot 'target\release\obsidianq-bootstrapper.exe'
$GuiProject           = Join-Path $RepoRoot 'tools\windows-gui\ObsidianQ.Launcher.csproj'
$GuiPublish           = Join-Path $RepoRoot 'tools\windows-gui\bin\Release\net8.0-windows\win-x64\publish\ObsidianQ.Launcher.exe'
$EmbeddedDir          = Join-Path $RepoRoot 'tools\windows-gui\embedded'
$EmbeddedCli          = Join-Path $EmbeddedDir 'obsidianq.exe'
$EmbeddedBootstrapper = Join-Path $EmbeddedDir 'ObsidianQ.Bootstrapper.exe'

$BundleDir            = Join-Path $RepoRoot 'dist\ObsidianQBundle'

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
# Build Rust binaries
# ---------------------------------------------------------------------------
Write-Step "Building Rust binaries (release)"
Push-Location $RepoRoot
try {
    & cargo build -p obsidianq-cli --release
    if ($LASTEXITCODE -ne 0) { Write-Fail "cargo build failed (exit $LASTEXITCODE)" }
} finally { Pop-Location }

if (-not (Test-Path $RustCli)) { Write-Fail "Expected binary not found after build: $RustCli" }
if (-not (Test-Path $RustBootstrapper)) { Write-Fail "Expected binary not found after build: $RustBootstrapper" }
$rustSize = [math]::Round((Get-Item $RustCli).Length / 1MB, 2)
$bootstrapperSize = [math]::Round((Get-Item $RustBootstrapper).Length / 1MB, 2)
Write-OK "obsidianq.exe built  ($rustSize MB)"
Write-OK "obsidianq-bootstrapper.exe built  ($bootstrapperSize MB)"

# ---------------------------------------------------------------------------
# Refresh embedded launcher binaries
# ---------------------------------------------------------------------------
Write-Step "Refreshing embedded launcher binaries"

if (-not (Test-Path $EmbeddedDir)) {
    New-Item -ItemType Directory -Path $EmbeddedDir | Out-Null
}

Copy-Item $RustCli $EmbeddedCli -Force
Copy-Item $RustBootstrapper $EmbeddedBootstrapper -Force
Write-OK "Updated embedded obsidianq.exe"
Write-OK "Updated embedded ObsidianQ.Bootstrapper.exe"

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
if (Test-Path $BundleDir) {
    try {
        Remove-Item $BundleDir -Recurse -Force
    }
    catch {
        Write-Fail "Could not clean bundle dir '$BundleDir'. Close any running copy of ObsidianQ launched from dist\\ObsidianQBundle, close Explorer windows pointing at that folder, and rebuild."
    }
}
try {
    New-Item -ItemType Directory -Path $BundleDir -Force | Out-Null
}
catch {
    Write-Fail "Could not create bundle dir '$BundleDir'. Check folder permissions and whether the directory is locked."
}

# Core binaries
Copy-Item $RustCli (Join-Path $BundleDir 'obsidianq.exe') -Force
Copy-Item $GuiPublish (Join-Path $BundleDir 'ObsidianQ.Launcher.exe') -Force
Write-OK "Copied bundle binaries"

$stagedCli = Join-Path $BundleDir 'obsidianq.exe'
$stagedLauncher = Join-Path $BundleDir 'ObsidianQ.Launcher.exe'
if ((Get-Sha256 $stagedCli) -ne (Get-Sha256 $RustCli)) {
    Write-Fail "Staged obsidianq.exe does not match the freshly built CLI."
}
if ((Get-Sha256 $stagedLauncher) -ne (Get-Sha256 $GuiPublish)) {
    Write-Fail "Staged ObsidianQ.Launcher.exe does not match the freshly published launcher. Close any running copy in dist\\ObsidianQBundle and rebuild."
}
Write-OK "Verified staged binaries"

# Bundle usage notes
$bundleReadme = @(
    'ObsidianQ Release Bundle',
    '========================',
    '',
    'Important:',
    '- Keep ObsidianQ.Launcher.exe and obsidianq.exe in the SAME folder.',
    '- The launcher calls obsidianq.exe at runtime.',
    '- If obsidianq.exe is missing or moved, launcher operations will fail.',
    '',
    'Recommended use:',
    '1. Extract this bundle to a folder you control.',
    '2. Run ObsidianQ.Launcher.exe from that folder.',
    '3. Use Settings inside the launcher if you want Explorer right-click actions.',
    '4. Do not rename or relocate obsidianq.exe independently.',
    '',
    'Versioning:',
    '- Replace launcher and CLI together when updating releases.'
)
$bundleReadme | Set-Content (Join-Path $BundleDir 'README_BUNDLE.txt') -Encoding UTF8
Write-OK "Created README_BUNDLE.txt"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "====================================================" -ForegroundColor Green
Write-Host "  BUILD COMPLETE" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
Write-Host "  Bundle : $BundleDir" -ForegroundColor Green
Write-Host ""
Write-Host "  Release contents:" -ForegroundColor White
Write-Host "    - ObsidianQ.Launcher.exe" -ForegroundColor White
Write-Host "    - obsidianq.exe" -ForegroundColor White
Write-Host "    - README_BUNDLE.txt" -ForegroundColor White
Write-Host ""

