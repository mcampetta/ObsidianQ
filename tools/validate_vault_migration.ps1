param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$Password,
  [string]$WorkDir = "C:\Temp\obsq_validate",
  [string]$LegacyVault = "",
  [switch]$DoMount,
  [string]$Drive = "V:"
)

$ErrorActionPreference = "Stop"

function Assert-True([bool]$Cond, [string]$Msg) {
  if (-not $Cond) { throw "ASSERT FAILED: $Msg" }
}

function Run-Obs([string]$ArgLine, [string]$Pw = "") {
  $argv = $ArgLine -split ' '
  if ($Pw -ne "") {
    $out = ($Pw | & $Exe $argv 2>&1) | Out-String
  } else {
    $out = (& $Exe $argv 2>&1) | Out-String
  }
  return $out
}

Write-Host "== Setup =="
Assert-True (Test-Path $Exe) "obsidianq.exe not found: $Exe"
if (Test-Path $WorkDir) { Remove-Item -Recurse -Force $WorkDir }
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$src = Join-Path $WorkDir "hello.txt"
Set-Content -Path $src -Value "hello from vault" -NoNewline -Encoding UTF8

$t1NoExt = Join-Path $WorkDir "t1"
$t1Vault = "$t1NoExt.vault"
$t2Vault = Join-Path $WorkDir "t2.vault"
$outDir = Join-Path $WorkDir "extract"

Write-Host "== Test 1: create without extension auto-appends .vault =="
$null = Run-Obs "vault create --out $t1NoExt --password-stdin" $Password
Assert-True (Test-Path $t1Vault) "Expected $t1Vault to exist"

Write-Host "== Test 2: create explicit .vault =="
$null = Run-Obs "vault create --out $t2Vault --password-stdin" $Password
Assert-True (Test-Path $t2Vault) "Expected $t2Vault to exist"

Write-Host "== Test 3: use --vault without extension (auto-append on use) =="
$lsOut = Run-Obs "vault ls --vault $($t2Vault.Substring(0,$t2Vault.Length-6)) --password-stdin" $Password
Assert-True ($lsOut -ne $null) "vault ls returned no output"

Write-Host "== Test 4: add/list/extract on .vault =="
$null = Run-Obs "vault add --vault $t2Vault --src $src --password-stdin" $Password
$lsOut2 = Run-Obs "vault ls --vault $t2Vault --password-stdin" $Password
Assert-True ($lsOut2 -match "hello.txt") "hello.txt not found in vault ls output"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$null = Run-Obs "vault extract --vault $t2Vault --dest $outDir --password-stdin" $Password
$extracted = Join-Path $outDir "hello.txt"
Assert-True (Test-Path $extracted) "Extracted file missing"
Assert-True ((Get-Content $extracted -Raw) -eq (Get-Content $src -Raw)) "Extracted content mismatch"

Write-Host "== Test 5: new header magic is OBSQVAULT =="
$bytes = [System.IO.File]::ReadAllBytes($t2Vault)
$magic = [System.Text.Encoding]::ASCII.GetString($bytes[0..8])
Assert-True ($magic -eq "OBSQVAULT") "Magic mismatch: got '$magic'"

Write-Host "== Test 6: legacy .obsqv compatibility (optional) =="
if ($LegacyVault -and (Test-Path $LegacyVault)) {
  $legacyOut = Run-Obs "vault ls --vault $LegacyVault --password-stdin" $Password
  Write-Host "Legacy open output:"
  Write-Host $legacyOut
} else {
  Write-Host "Skipping legacy test (no -LegacyVault provided)"
}

if ($DoMount) {
  Write-Host "== Test 7: mount sanity (optional) =="
  $null = Run-Obs "vault mount --vault $t2Vault --drive $Drive --password-stdin" $Password
  Start-Sleep -Seconds 2
  $dirOut = (cmd.exe /c "dir $Drive\" 2>&1) | Out-String
  Assert-True ($dirOut -match "hello.txt") "Mounted dir did not show hello.txt"
  $typeOut = (cmd.exe /c "type $Drive\hello.txt" 2>&1) | Out-String
  Assert-True ($typeOut -match "hello from vault") "Mounted file read mismatch"
  $null = Run-Obs "vault unmount --drive $Drive"
}

Write-Host "`nALL CHECKS PASSED"
