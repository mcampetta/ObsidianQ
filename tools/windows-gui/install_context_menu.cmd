@echo off
:: ObsidianQ — Install HKCU context-menu entries (no admin required)
:: Registers:
::   Right-click any file   → "ObsidianQ Encrypt/Decrypt…"
::   Right-click .obsq file → "ObsidianQ Decrypt…"

setlocal EnableDelayedExpansion

:: ── Locate launcher ──────────────────────────────────────────────────────────
set "SELF_DIR=%~dp0"
set "LAUNCHER=%SELF_DIR%ObsidianQ.Launcher.exe"

if not exist "%LAUNCHER%" (
    echo ERROR: ObsidianQ.Launcher.exe not found in:
    echo        %SELF_DIR%
    echo.
    echo Build the project first:  dotnet publish -c Release
    pause
    exit /b 1
)

echo Installing ObsidianQ context-menu entries for current user…
echo Launcher: %LAUNCHER%
echo.

:: ── All-files handler (*\shell) ───────────────────────────────────────────────
set "KEY_ALL=HKCU\Software\Classes\*\shell\ObsidianQEncryptDecrypt"

reg add "%KEY_ALL%"                    /ve /d "ObsidianQ Encrypt/Decrypt\u2026" /f >nul
reg add "%KEY_ALL%"                    /v "Icon"       /d "\"%LAUNCHER%\",0"   /f >nul
reg add "%KEY_ALL%"                    /v "Position"   /d "Bottom"              /f >nul
reg add "%KEY_ALL%\command"            /ve /d "\"%LAUNCHER%\" \"%%1\""          /f >nul

:: ── .obsq file-type handler ───────────────────────────────────────────────────
set "KEY_OBSQ_FT=HKCU\Software\Classes\.obsq"
set "KEY_OBSQ_PROG=HKCU\Software\Classes\obsq_auto_file"

:: Associate .obsq with a ProgID
reg add "%KEY_OBSQ_FT%"                /ve /d "obsq_auto_file"                 /f >nul

:: ProgID shell verb: Decrypt
set "KEY_DECRYPT=%KEY_OBSQ_PROG%\shell\ObsidianQDecrypt"
reg add "%KEY_OBSQ_PROG%"              /ve /d "ObsidianQ Encrypted File"       /f >nul
reg add "%KEY_OBSQ_PROG%\DefaultIcon"  /ve /d "\"%LAUNCHER%\",0"              /f >nul
reg add "%KEY_DECRYPT%"                /ve /d "ObsidianQ Decrypt\u2026"        /f >nul
reg add "%KEY_DECRYPT%"                /v "Icon"       /d "\"%LAUNCHER%\",0"   /f >nul
reg add "%KEY_DECRYPT%\command"        /ve /d "\"%LAUNCHER%\" \"%%1\""          /f >nul

:: ── Refresh Explorer ─────────────────────────────────────────────────────────
:: Notify the shell that file associations changed (no Explorer restart needed)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.obsq\UserChoice" ^
    /v "ProgId" /d "obsq_auto_file" /f >nul 2>&1

:: Broadcast WM_SETTINGCHANGE
powershell -NoProfile -Command ^
    "[Microsoft.Win32.Registry]::CurrentUser.Flush(); " ^
    "$code = '[DllImport(\"shell32.dll\")]public static extern void SHChangeNotify(int e, int f, IntPtr a, IntPtr b);'; " ^
    "$t = Add-Type -MemberDefinition $code -Name SH -PassThru; " ^
    "$t::SHChangeNotify(0x08000000, 0x0000, [IntPtr]::Zero, [IntPtr]::Zero);" >nul 2>&1

echo.
echo Done.  Right-click any file to see the ObsidianQ menu.
echo (You may need to restart Explorer if the menu doesn't appear immediately.)
echo.
pause
