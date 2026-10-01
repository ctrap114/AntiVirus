@echo off
reg delete "HKCU\Software\Classes\*\shell\EverbloomSecurityScan" /f >nul 2>&1
reg delete "HKCU\Software\Classes\Directory\shell\EverbloomSecurityScan" /f >nul 2>&1
reg delete "HKCU\Software\Classes\Directory\Background\shell\EverbloomSecurityScan" /f >nul 2>&1
echo EverbloomSecurity Explorer scan menu removed for the current user.
