@echo off
setlocal
set "ROOT=%~dp0.."
set "APP=%ROOT%\artifacts\package\install\bin\everbloom_gui.exe"
if exist "%ROOT%\bin\everbloom_gui.exe" set "APP=%ROOT%\bin\everbloom_gui.exe"
if not exist "%APP%" (
    echo EverbloomSecurity GUI was not found: "%APP%"
    echo Start this file from the source tree or an extracted package.
    pause
    exit /b 2
)
start "EverbloomSecurity" /wait /D "%~dp0" "%APP%"
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
    echo EverbloomSecurity GUI exited with code %RC%.
    if exist "%TEMP%\EverbloomSecurity-gui-startup.log" type "%TEMP%\EverbloomSecurity-gui-startup.log"
    pause
)
endlocal
