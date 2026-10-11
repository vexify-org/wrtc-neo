@echo off
REM wrtc-neo TUN Driver Installer
REM Installs wintun driver for virtual NIC support
REM Requires Administrator privileges

echo wrtc-neo TUN Driver Installer
echo ==============================
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Administrator privileges required
    echo Right-click and "Run as Administrator"
    exit /b 1
)

set DRIVER_DIR=%~dp0
set WINTUN_SYS=%DRIVER_DIR%wintun.sys
set WINTUN_DLL=%DRIVER_DIR%wintun.dll
set WINTUN_INF=%DRIVER_DIR%wintun.inf

if not exist "%WINTUN_SYS%" (
    echo ERROR: wintun.sys not found in %DRIVER_DIR%
    echo Downloading from official source...
    powershell -Command "Invoke-WebRequest -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile '%TEMP%\wintun.zip'" >nul 2>&1
    if %errorlevel% neq 0 (
        echo Failed to download wintun. Please install manually.
        exit /b 1
    )
    powershell -Command "Expand-Archive -Path '%TEMP%\wintun.zip' -DestinationPath '%TEMP%\wintun' -Force" >nul 2>&1
    copy "%TEMP%\wintun\wintun.dll" "%DRIVER_DIR%" >nul 2>&1
    copy "%TEMP%\wintun\wintun.sys" "%DRIVER_DIR%" >nul 2>&1
    echo Downloaded wintun 0.14.1
)

echo Installing wintun driver...
pnputil /add-driver "%WINTUN_INF%" /install >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] wintun driver installed
) else (
    echo wintun driver may already be installed, or using fallback method
)

echo Copying wintun.dll to system directory...
copy "%WINTUN_DLL%" "%WINDIR%\System32\wintun.dll" /Y >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] wintun.dll copied to System32
) else (
    echo wintun.dll kept in local directory
)

echo.
echo Installation complete!
echo If TUN mode still doesn't work, restart your computer.
pause