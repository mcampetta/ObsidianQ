@echo off
:: ObsidianQ — Build release bundle
:: Double-click this file (or run from repo root) to produce dist\ObsidianQBundle\.

setlocal

:: Resolve script directory so this works wherever it is invoked from
set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%build_bundle.ps1"

echo.
echo  ObsidianQ Release Bundle Builder
echo  ==================================
echo.

:: Sanity check
if not exist "%PS1%" (
    echo ERROR: build_bundle.ps1 not found next to this file.
    echo        Expected: %PS1%
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*

if %ERRORLEVEL% neq 0 (
    echo.
    echo  BUILD FAILED  (exit code %ERRORLEVEL%)
    echo  Check output above for details.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo  Done. Press any key to close.
pause >nul
