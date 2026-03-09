@echo off
:: ObsidianQ - Remove HKCU shell entries and file associations (no admin required)

echo Removing ObsidianQ shell entries...

reg delete "HKCU\Software\Classes\*\shell\ObsidianQEncryptDecrypt" /f >nul 2>&1
reg delete "HKCU\Software\Classes\obsq_auto_file" /f >nul 2>&1
reg delete "HKCU\Software\Classes\.obsq" /f >nul 2>&1
reg delete "HKCU\Software\Classes\obsidianq_vault_file" /f >nul 2>&1
reg delete "HKCU\Software\Classes\obsidianq_identity_file" /f >nul 2>&1
reg delete "HKCU\Software\Classes\.vault" /f >nul 2>&1
reg delete "HKCU\Software\Classes\.obsqv" /f >nul 2>&1
reg delete "HKCU\Software\Classes\.obsqpub" /f >nul 2>&1

powershell -NoProfile -Command ^
    "[Microsoft.Win32.Registry]::CurrentUser.Flush(); " ^
    "$code = '[DllImport(\"shell32.dll\")]public static extern void SHChangeNotify(int e, int f, IntPtr a, IntPtr b);'; " ^
    "$t = Add-Type -MemberDefinition $code -Name SH -PassThru; " ^
    "$t::SHChangeNotify(0x08000000, 0x0000, [IntPtr]::Zero, [IntPtr]::Zero);" >nul 2>&1

echo Done. ObsidianQ shell entries removed.
pause
