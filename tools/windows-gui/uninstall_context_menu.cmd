@echo off
:: ObsidianQ — Remove HKCU context-menu entries (no admin required)

echo Removing ObsidianQ context-menu entries…

reg delete "HKCU\Software\Classes\*\shell\ObsidianQEncryptDecrypt" /f >nul 2>&1
reg delete "HKCU\Software\Classes\obsq_auto_file"                  /f >nul 2>&1
reg delete "HKCU\Software\Classes\.obsq"                           /f >nul 2>&1

:: Flush and notify
powershell -NoProfile -Command ^
    "[Microsoft.Win32.Registry]::CurrentUser.Flush(); " ^
    "$code = '[DllImport(\"shell32.dll\")]public static extern void SHChangeNotify(int e, int f, IntPtr a, IntPtr b);'; " ^
    "$t = Add-Type -MemberDefinition $code -Name SH -PassThru; " ^
    "$t::SHChangeNotify(0x08000000, 0x0000, [IntPtr]::Zero, [IntPtr]::Zero);" >nul 2>&1

echo Done.  ObsidianQ context-menu entries removed.
pause
