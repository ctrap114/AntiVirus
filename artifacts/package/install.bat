@echo off
setlocal enabledelayedexpansion

:: HeliosAV 完整安装包
:: 包含引擎 + GUI + 驱动保护

echo ================================================
echo HeliosAV 完整安装包
echo ================================================
echo 当前时间: %date% %time%

:: 管理员权限检测
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] 请以管理员权限运行此安装包
    pause
    exit /b 1
)

:: 安装目录
set "INSTALL_DIR=%ProgramFiles%\HeliosAV"
set "SERVICE_NAME=HeliosAVDriver"

echo [1/4] 停止现有服务...
sc stop %SERVICE_NAME% >nul 2>&1
sc delete %SERVICE_NAME% >nul 2>&1

echo [2/4] 安装驱动保护...
copy /Y "%~dp0\engine\bin\heliosav_driver.sys" "%SystemRoot%\System32\drivers\" >nul 2>&1
sc create %SERVICE_NAME% binPath= System32\drivers\heliosav_driver.sys type= kernel >nul 2>&1
sc start %SERVICE_NAME% >nul 2>&1

echo [3/4] 安装引擎...
copy /Y "%~dp0\engine\bin\heliosav_engine.exe" "%INSTALL_DIR%\engine\" >nul 2>&1

echo [4/4] 安装GUI...
copy /Y "%~dp0\gui\HeliosAV.exe" "%ProgramFiles%\HeliosAV\" >nul 2>&1

echo ================================================
echo HeliosAV 安装完成！
echo 安装位置: %INSTALL_DIR%
echo ================================================
pause