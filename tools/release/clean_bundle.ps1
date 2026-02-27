#Requires -Version 5.1
<#
.SYNOPSIS
    Removes the dist/ObsidianQBundle/ folder and zip.
#>

$RepoRoot  = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$BundleDir = Join-Path $RepoRoot 'dist\ObsidianQBundle'
$ZipPath   = Join-Path $RepoRoot 'dist\ObsidianQBundle.zip'

$removed = 0
foreach ($path in @($BundleDir, $ZipPath)) {
    if (Test-Path $path) {
        Remove-Item $path -Recurse -Force
        Write-Host "Removed: $path" -ForegroundColor Yellow
        $removed++
    }
}

if ($removed -eq 0) { Write-Host "Nothing to clean." -ForegroundColor Gray }
else                { Write-Host "Clean complete." -ForegroundColor Green }
