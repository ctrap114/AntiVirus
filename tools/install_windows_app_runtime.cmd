@echo off
setlocal
set "RUNTIME_DIR=%~dp0..\share\everbloom\windows-app-runtime\win10-x64"
set "EXPECTED_RUNTIME_VERSION=2.3.1.0"

if not exist "%RUNTIME_DIR%\MSIX.inventory" (
    echo EverbloomSecurity Windows App Runtime package set was not found:
    echo   "%RUNTIME_DIR%"
    exit /b 2
)

echo Checking Windows App Runtime %EXPECTED_RUNTIME_VERSION% registration...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference = 'Stop'; $dir = [IO.Path]::GetFullPath($env:RUNTIME_DIR); $expected = [Version]$env:EXPECTED_RUNTIME_VERSION; $packages = @(@{Name='Microsoft.WindowsAppRuntime.2'; File='Microsoft.WindowsAppRuntime.2.msix'}, @{Name='Microsoft.WindowsAppRuntime.Main.2'; File='Microsoft.WindowsAppRuntime.Main.2.msix'}, @{Name='Microsoft.WindowsAppRuntime.Singleton.2'; File='Microsoft.WindowsAppRuntime.Singleton.2.msix'}, @{Name='Microsoft.WindowsAppRuntime.DDLM.2'; File='Microsoft.WindowsAppRuntime.DDLM.2.msix'}); $installed = @(Get-AppxPackage -ErrorAction SilentlyContinue); $missing = @(); foreach ($item in $packages) { $matches = @($installed | Where-Object { $_.Name -eq $item.Name -and ([Version]$_.Version -ge $expected) }); if ($matches.Count -eq 0) { $missing += $item } }; if ($missing.Count -eq 0) { Write-Host ('Windows App Runtime ' + $expected + ' is already installed for this user.'); exit 0 }; Write-Host ('Installing ' + $missing.Count + ' missing/outdated Windows App Runtime package(s)...'); foreach ($item in $packages) { $path = Join-Path $dir $item.File; if (-not (Test-Path -LiteralPath $path)) { throw ('Missing package: ' + $path) }; Write-Host ('Installing ' + $item.File); Add-AppxPackage -Path $path -ErrorAction Stop }; $installed = @(Get-AppxPackage -ErrorAction SilentlyContinue); foreach ($item in $packages) { $matches = @($installed | Where-Object { $_.Name -eq $item.Name -and ([Version]$_.Version -ge $expected) }); if ($matches.Count -eq 0) { throw ('Package verification failed: ' + $item.Name + ' ' + $expected) } }; Write-Host ('Windows App Runtime ' + $expected + ' installation verified.')"
if errorlevel 1 (
    echo Windows App Runtime installation failed.
    echo Run this script from an Administrator PowerShell if UAC or package policy requires it.
    exit /b 1
)

echo Windows App Runtime installation completed. You can start EverbloomSecurity now.
endlocal
