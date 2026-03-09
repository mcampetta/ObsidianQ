param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$Config = "debug"
)

$ErrorActionPreference = "Stop"

function New-Result([string]$Name, [bool]$Pass, [string]$Detail) {
    [pscustomobject]@{
        Name = $Name
        Pass = $Pass
        Detail = $Detail
    }
}

function Run-Exe([string]$Exe, [string]$CmdArgs) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = $CmdArgs
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    return [pscustomobject]@{
        ExitCode = $p.ExitCode
        Stdout = $stdout
        Stderr = $stderr
    }
}

Set-Location $RepoRoot

$results = New-Object System.Collections.Generic.List[object]
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$tmp = Join-Path $RepoRoot "temp\validate_phase2_$ts"
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

$exe = Join-Path $RepoRoot ("target\" + $Config + "\obsidianq.exe")
if (!(Test-Path $exe)) {
    Write-Host "obsidianq binary not found at: $exe" -ForegroundColor Red
    exit 1
}

# 1) Build check
$build = cmd /c "cargo build -p obsidianq-cli 2>&1"
if ($LASTEXITCODE -eq 0) {
    $results.Add((New-Result "Build obsidianq-cli" $true "ok"))
} else {
    $results.Add((New-Result "Build obsidianq-cli" $false (($build | Out-String).Trim())))
}

# 2) Key generation
$aPub = Join-Path $tmp "a_pub.bin"
$aPriv = Join-Path $tmp "a_priv.bin"
$bPub = Join-Path $tmp "b_pub.bin"
$bPriv = Join-Path $tmp "b_priv.bin"
$cPub = Join-Path $tmp "c_pub.bin"
$cPriv = Join-Path $tmp "c_priv.bin"

foreach ($pair in @(
    @($aPub, $aPriv, "A"),
    @($bPub, $bPriv, "B"),
    @($cPub, $cPriv, "C")
)) {
    $r = Run-Exe $exe ("keygen --pubkey `"" + $pair[0] + "`" --privkey `"" + $pair[1] + "`"")
    $results.Add((New-Result ("Keygen " + $pair[2]) ($r.ExitCode -eq 0) ($r.Stdout + $r.Stderr).Trim()))
}

# 3) File multi-recipient roundtrip
$plain = Join-Path $tmp "small.txt"
$cipher = Join-Path $tmp "small_multi.obsq"
$outA = Join-Path $tmp "out_a.txt"
$outB = Join-Path $tmp "out_b.txt"
Set-Content -Path $plain -Value "phase2-matrix-content" -NoNewline

$enc = Run-Exe $exe ("encrypt --in `"" + $plain + "`" --out `"" + $cipher + "`" --pubkey `"" + $aPub + "`" --pubkey `"" + $bPub + "`"")
$results.Add((New-Result "File encrypt multi-recipient" ($enc.ExitCode -eq 0) ($enc.Stdout + $enc.Stderr).Trim()))

$decA = Run-Exe $exe ("decrypt --in `"" + $cipher + "`" --out `"" + $outA + "`" --privkey `"" + $aPriv + "`"")
$decB = Run-Exe $exe ("decrypt --in `"" + $cipher + "`" --out `"" + $outB + "`" --privkey `"" + $bPriv + "`"")
$okA = (Test-Path $outA) -and ((Get-Content $outA -Raw) -eq (Get-Content $plain -Raw))
$okB = (Test-Path $outB) -and ((Get-Content $outB -Raw) -eq (Get-Content $plain -Raw))
$results.Add((New-Result "File decrypt with A" (($decA.ExitCode -eq 0) -and $okA) ($decA.Stdout + $decA.Stderr).Trim()))
$results.Add((New-Result "File decrypt with B" (($decB.ExitCode -eq 0) -and $okB) ($decB.Stdout + $decB.Stderr).Trim()))

# 4) Vault v2 multi-recipient create/add/list/extract/remove
$srcDir = Join-Path $tmp "srcdir"
New-Item -ItemType Directory -Path $srcDir -Force | Out-Null
Set-Content -Path (Join-Path $srcDir "nested.txt") -Value "nested-value" -NoNewline

$v2 = Join-Path $tmp "v2_multi.vault"
$v2Create = Run-Exe $exe ("vault create --out `"" + $v2 + "`" --pubkey `"" + $aPub + "`" --pubkey `"" + $bPub + "`"")
$results.Add((New-Result "Vault v2 create multi-recipient" ($v2Create.ExitCode -eq 0) ($v2Create.Stdout + $v2Create.Stderr).Trim()))

$v2Add1 = Run-Exe $exe ("vault add --vault `"" + $v2 + "`" --src `"" + $plain + "`" --dest /small.txt --privkey `"" + $aPriv + "`"")
$v2Add2 = Run-Exe $exe ("vault add --vault `"" + $v2 + "`" --src `"" + $srcDir + "`" --dest /docs --privkey `"" + $aPriv + "`"")
$results.Add((New-Result "Vault v2 add file" ($v2Add1.ExitCode -eq 0) ($v2Add1.Stdout + $v2Add1.Stderr).Trim()))
$results.Add((New-Result "Vault v2 add dir" ($v2Add2.ExitCode -eq 0) ($v2Add2.Stdout + $v2Add2.Stderr).Trim()))

$v2LsA = Run-Exe $exe ("vault ls --vault `"" + $v2 + "`" --path / --privkey `"" + $aPriv + "`"")
$v2LsB = Run-Exe $exe ("vault ls --vault `"" + $v2 + "`" --path / --privkey `"" + $bPriv + "`"")
$v2LsC = Run-Exe $exe ("vault ls --vault `"" + $v2 + "`" --path / --privkey `"" + $cPriv + "`"")
$results.Add((New-Result "Vault v2 list with A" ($v2LsA.ExitCode -eq 0) ($v2LsA.Stdout + $v2LsA.Stderr).Trim()))
$results.Add((New-Result "Vault v2 list with B" ($v2LsB.ExitCode -eq 0) ($v2LsB.Stdout + $v2LsB.Stderr).Trim()))
$results.Add((New-Result "Vault v2 unauthorized key rejected" ($v2LsC.ExitCode -ne 0) ($v2LsC.Stdout + $v2LsC.Stderr).Trim()))

$extractDir = Join-Path $tmp "extract_b"
New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
$v2Extract = Run-Exe $exe ("vault extract --vault `"" + $v2 + "`" --path /small.txt --dest `"" + $extractDir + "`" --privkey `"" + $bPriv + "`"")
$extractFile = Join-Path $extractDir "small.txt"
$extractOk = (Test-Path $extractFile) -and ((Get-Content $extractFile -Raw) -eq (Get-Content $plain -Raw))
$results.Add((New-Result "Vault v2 extract with B" (($v2Extract.ExitCode -eq 0) -and $extractOk) ($v2Extract.Stdout + $v2Extract.Stderr).Trim()))

$v2RmFile = Run-Exe $exe ("vault remove --vault `"" + $v2 + "`" --path /small.txt --privkey `"" + $bPriv + "`"")
$v2RmDir = Run-Exe $exe ("vault remove --vault `"" + $v2 + "`" --path /docs --recursive --privkey `"" + $bPriv + "`"")
$v2LsAfter = Run-Exe $exe ("vault ls --vault `"" + $v2 + "`" --path / --privkey `"" + $bPriv + "`"")
$emptyRoot = [string]::IsNullOrWhiteSpace($v2LsAfter.Stdout)
$results.Add((New-Result "Vault v2 remove file" ($v2RmFile.ExitCode -eq 0) ($v2RmFile.Stdout + $v2RmFile.Stderr).Trim()))
$results.Add((New-Result "Vault v2 remove dir recursive" ($v2RmDir.ExitCode -eq 0) ($v2RmDir.Stdout + $v2RmDir.Stderr).Trim()))
$results.Add((New-Result "Vault v2 empty after removals" (($v2LsAfter.ExitCode -eq 0) -and $emptyRoot) ($v2LsAfter.Stdout + $v2LsAfter.Stderr).Trim()))

# 5) Password vault create/open + wrong password fail
$pwVault = Join-Path $tmp "pw.vault"
$pwCreate = cmd /c "echo secret123| `"$exe`" vault create --out `"$pwVault`" --password-stdin"
$results.Add((New-Result "Vault password create" ($LASTEXITCODE -eq 0) (($pwCreate | Out-String).Trim())))
$pwAdd = cmd /c "echo secret123| `"$exe`" vault add --vault `"$pwVault`" --src `"$plain`" --dest /p.txt --password-stdin"
$results.Add((New-Result "Vault password add" ($LASTEXITCODE -eq 0) (($pwAdd | Out-String).Trim())))
$pwLsOk = cmd /c "echo secret123| `"$exe`" vault ls --vault `"$pwVault`" --path / --password-stdin"
$results.Add((New-Result "Vault password open (correct)" ($LASTEXITCODE -eq 0) (($pwLsOk | Out-String).Trim())))
$pwLsBad = cmd /c "echo wrongpass| `"$exe`" vault ls --vault `"$pwVault`" --path / --password-stdin 2>&1"
$results.Add((New-Result "Vault password open (wrong) rejected" ($LASTEXITCODE -ne 0) (($pwLsBad | Out-String).Trim())))

# 6) Rekey: multi(A,B) -> B only
$v2BOnly = Join-Path $tmp "v2_b_only.vault"
$rk = Run-Exe $exe ("vault rekey --vault `"" + $v2 + "`" --out `"" + $v2BOnly + "`" --privkey `"" + $aPriv + "`" --new-pubkey `"" + $bPub + "`"")
$rkB = Run-Exe $exe ("vault ls --vault `"" + $v2BOnly + "`" --path / --privkey `"" + $bPriv + "`"")
$rkA = Run-Exe $exe ("vault ls --vault `"" + $v2BOnly + "`" --path / --privkey `"" + $aPriv + "`"")
$results.Add((New-Result "Vault rekey command" ($rk.ExitCode -eq 0) ($rk.Stdout + $rk.Stderr).Trim()))
$results.Add((New-Result "Vault rekey open with new key" ($rkB.ExitCode -eq 0) ($rkB.Stdout + $rkB.Stderr).Trim()))
$results.Add((New-Result "Vault rekey old key rejected" ($rkA.ExitCode -ne 0) ($rkA.Stdout + $rkA.Stderr).Trim()))

# Optional: legacy v1 smoke if present.
$legacy = Join-Path $RepoRoot "temp\phase2_check\v1b.vault"
$legacyPriv = Join-Path $RepoRoot "temp\phase2_check\a_priv.bin"
if ((Test-Path $legacy) -and (Test-Path $legacyPriv)) {
    $v1 = Run-Exe $exe ("vault ls --vault `"" + $legacy + "`" --path / --privkey `"" + $legacyPriv + "`"")
    $results.Add((New-Result "Legacy v1 vault open compatibility" ($v1.ExitCode -eq 0) ($v1.Stdout + $v1.Stderr).Trim()))
}

$failed = @($results | Where-Object { -not $_.Pass })

Write-Host ""
Write-Host "Validation Matrix Results" -ForegroundColor Cyan
Write-Host "Workspace: $RepoRoot"
Write-Host "Artifacts: $tmp"
Write-Host ""
foreach ($r in $results) {
    $mark = if ($r.Pass) { "PASS" } else { "FAIL" }
    $color = if ($r.Pass) { "Green" } else { "Red" }
    Write-Host ("[{0}] {1}" -f $mark, $r.Name) -ForegroundColor $color
}

Write-Host ""
if ($failed.Count -eq 0) {
    Write-Host ("All checks passed ({0}/{0})." -f $results.Count) -ForegroundColor Green
    exit 0
}

Write-Host ("Failures: {0}/{1}" -f $failed.Count, $results.Count) -ForegroundColor Red
foreach ($f in $failed) {
    Write-Host ""
    Write-Host ("--- " + $f.Name) -ForegroundColor Red
    if (![string]::IsNullOrWhiteSpace($f.Detail)) {
        Write-Host $f.Detail
    }
}
exit 2
