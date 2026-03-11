@echo off
:: ObsidianQ - Install HKCU context-menu and file associations (no admin required)
:: Registers:
::   Right-click any file    -> "ObsidianQ Encrypt File"
::   Right-click any file    -> "ObsidianQ Encrypt and make Package"
::   Right-click any folder  -> "ObsidianQ Encrypt Folder"
::   Right-click any folder  -> "ObsidianQ Encrypt Folder and make Package"
::   Right-click .obsq file  -> "ObsidianQ Decrypt..."
::   Open .vault files with ObsidianQ.Launcher.exe
::   Open .obsqpub identity files with ObsidianQ.Launcher.exe
::   Explorer New menu       -> "Obsidian Vault"

setlocal EnableDelayedExpansion

set "SELF_DIR=%~dp0"
set "LAUNCHER=%SELF_DIR%ObsidianQ.Launcher.exe"

if not exist "%LAUNCHER%" (
    echo ERROR: ObsidianQ.Launcher.exe not found in:
    echo        %SELF_DIR%
    echo.
    echo Build/publish the launcher first.
    pause
    exit /b 1
)

echo Installing ObsidianQ shell entries for current user...
echo Launcher: %LAUNCHER%
echo.

:: Any-file context menu
set "KEY_ALL=HKCU\Software\Classes\*\shell\ObsidianQEncryptDecrypt"
reg add "%KEY_ALL%"                 /ve /d "ObsidianQ Encrypt File" /f >nul
reg add "%KEY_ALL%"                 /v "Icon"     /d "\"%LAUNCHER%\",0" /f >nul
reg add "%KEY_ALL%"                 /v "Position" /d "Bottom" /f >nul
reg add "%KEY_ALL%\command"         /ve /d "\"%LAUNCHER%\" \"%%1\"" /f >nul

set "KEY_ALL_PKG=HKCU\Software\Classes\*\shell\ObsidianQEncryptPackage"
reg add "%KEY_ALL_PKG%"             /ve /d "ObsidianQ Encrypt and make Package" /f >nul
reg add "%KEY_ALL_PKG%"             /v "Icon"     /d "\"%LAUNCHER%\",0" /f >nul
reg add "%KEY_ALL_PKG%"             /v "Position" /d "Bottom" /f >nul
reg add "%KEY_ALL_PKG%\command"     /ve /d "\"%LAUNCHER%\" --create-package \"%%1\"" /f >nul

set "KEY_DIR_PKG=HKCU\Software\Classes\Directory\shell\ObsidianQEncryptPackage"
reg add "%KEY_DIR_PKG%"             /ve /d "ObsidianQ Encrypt Folder and make Package" /f >nul
reg add "%KEY_DIR_PKG%"             /v "Icon"     /d "\"%LAUNCHER%\",0" /f >nul
reg add "%KEY_DIR_PKG%"             /v "Position" /d "Bottom" /f >nul
reg add "%KEY_DIR_PKG%\command"     /ve /d "\"%LAUNCHER%\" --create-package \"%%1\"" /f >nul

set "KEY_DIR_ENC=HKCU\Software\Classes\Directory\shell\ObsidianQEncryptFolder"
reg add "%KEY_DIR_ENC%"             /ve /d "ObsidianQ Encrypt Folder" /f >nul
reg add "%KEY_DIR_ENC%"             /v "Icon"     /d "\"%LAUNCHER%\",0" /f >nul
reg add "%KEY_DIR_ENC%"             /v "Position" /d "Bottom" /f >nul
reg add "%KEY_DIR_ENC%\command"     /ve /d "\"%LAUNCHER%\" --encrypt-folder \"%%1\"" /f >nul

:: .obsq association + decrypt verb
set "KEY_OBSQ_FT=HKCU\Software\Classes\.obsq"
set "KEY_OBSQ_PROG=HKCU\Software\Classes\obsq_auto_file"
set "KEY_DECRYPT=%KEY_OBSQ_PROG%\shell\ObsidianQDecrypt"
reg add "%KEY_OBSQ_FT%"             /ve /d "obsq_auto_file" /f >nul
reg add "%KEY_OBSQ_PROG%"           /ve /d "ObsidianQ Encrypted File" /f >nul
reg add "%KEY_OBSQ_PROG%\DefaultIcon" /ve /d "\"%LAUNCHER%\",0" /f >nul
reg add "%KEY_DECRYPT%"             /ve /d "ObsidianQ Decrypt..." /f >nul
reg add "%KEY_DECRYPT%"             /v "Icon" /d "\"%LAUNCHER%\",0" /f >nul
reg add "%KEY_DECRYPT%\command"     /ve /d "\"%LAUNCHER%\" \"%%1\"" /f >nul

:: .vault/.obsqv association
set "KEY_VAULT_FT=HKCU\Software\Classes\.vault"
set "KEY_OBSQV_FT=HKCU\Software\Classes\.obsqv"
set "KEY_VAULT_PROG=HKCU\Software\Classes\obsidianq_vault_file"
set "KEY_VAULT_OPEN=%KEY_VAULT_PROG%\shell\open"
reg add "%KEY_VAULT_FT%"            /ve /d "obsidianq_vault_file" /f >nul
reg add "%KEY_OBSQV_FT%"            /ve /d "obsidianq_vault_file" /f >nul
reg add "%KEY_VAULT_PROG%"          /ve /d "Obsidian Vault" /f >nul
reg add "%KEY_VAULT_PROG%\DefaultIcon" /ve /d "\"%LAUNCHER%\",0" /f >nul
reg add "%KEY_VAULT_OPEN%"          /ve /d "Open with ObsidianQ" /f >nul
reg add "%KEY_VAULT_OPEN%\command"  /ve /d "\"%LAUNCHER%\" \"%%1\"" /f >nul

:: .obsqpub association
set "KEY_ID_FT=HKCU\Software\Classes\.obsqpub"
set "KEY_ID_PROG=HKCU\Software\Classes\obsidianq_identity_file"
set "KEY_ID_OPEN=%KEY_ID_PROG%\shell\open"
reg add "%KEY_ID_FT%"               /ve /d "obsidianq_identity_file" /f >nul
reg add "%KEY_ID_PROG%"             /ve /d "ObsidianQ Public Identity" /f >nul
reg add "%KEY_ID_PROG%\DefaultIcon" /ve /d "\"%LAUNCHER%\",0" /f >nul
reg add "%KEY_ID_OPEN%"             /ve /d "Open with ObsidianQ" /f >nul
reg add "%KEY_ID_OPEN%\command"     /ve /d "\"%LAUNCHER%\" \"%%1\"" /f >nul
reg delete "%KEY_VAULT_FT%\ShellNew" /v "NullFile" /f >nul 2>&1
reg add "%KEY_VAULT_FT%\ShellNew"   /v "Command" /d "\"%LAUNCHER%\" --create-vault \"%%1\"" /f >nul
reg delete "%KEY_VAULT_PROG%\ShellNew" /v "NullFile" /f >nul 2>&1
reg add "%KEY_VAULT_PROG%\ShellNew" /v "Command" /d "\"%LAUNCHER%\" --create-vault \"%%1\"" /f >nul

:: Hint Explorer to include our .vault ProgID in Open With
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.vault\OpenWithProgids" ^
    /v "obsidianq_vault_file" /t REG_NONE /d "" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.obsqv\OpenWithProgids" ^
    /v "obsidianq_vault_file" /t REG_NONE /d "" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.obsqpub\OpenWithProgids" ^
    /v "obsidianq_identity_file" /t REG_NONE /d "" /f >nul 2>&1

:: Refresh Explorer shell
powershell -NoProfile -Command ^
    "[Microsoft.Win32.Registry]::CurrentUser.Flush(); " ^
    "$code = '[DllImport(\"shell32.dll\")]public static extern void SHChangeNotify(int e, int f, IntPtr a, IntPtr b);'; " ^
    "$t = Add-Type -MemberDefinition $code -Name SH -PassThru; " ^
    "$t::SHChangeNotify(0x08000000, 0x0000, [IntPtr]::Zero, [IntPtr]::Zero);" >nul 2>&1

echo.
echo Done. You can now open .vault files and create New ^> Obsidian Vault.
pause
