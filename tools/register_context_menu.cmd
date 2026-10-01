@echo off
setlocal
set "APP=%~dp0everbloom_gui.exe"
if not exist "%APP%" (
  echo everbloom_gui.exe was not found beside this script.
  exit /b 2
)
reg add "HKCU\Software\Classes\*\shell\EverbloomSecurityScan" /ve /d "Scan with EverbloomSecurity" /f >nul
if errorlevel 1 goto :failed
reg add "HKCU\Software\Classes\*\shell\EverbloomSecurityScan\command" /ve /d "\"%APP%\" --scan \"%%1\"" /f >nul
if errorlevel 1 goto :failed
reg add "HKCU\Software\Classes\Directory\shell\EverbloomSecurityScan" /ve /d "Scan with EverbloomSecurity" /f >nul
if errorlevel 1 goto :failed
reg add "HKCU\Software\Classes\Directory\shell\EverbloomSecurityScan\command" /ve /d "\"%APP%\" --scan \"%%1\"" /f >nul
if errorlevel 1 goto :failed
reg add "HKCU\Software\Classes\Directory\Background\shell\EverbloomSecurityScan" /ve /d "Scan with EverbloomSecurity" /f >nul
if errorlevel 1 goto :failed
reg add "HKCU\Software\Classes\Directory\Background\shell\EverbloomSecurityScan\command" /ve /d "\"%APP%\" --scan \"%%V\"" /f >nul
if errorlevel 1 goto :failed
echo EverbloomSecurity Explorer scan menu installed for the current user.
endlocal & exit /b 0
:failed
echo Could not install the EverbloomSecurity Explorer scan menu for the current user.
endlocal & exit /b 1
