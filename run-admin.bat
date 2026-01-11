@echo off
:: Run Sereno Service with Administrator privileges
:: Right-click this file and select "Run as administrator"

cd /d "%~dp0"

echo.
echo ==========================================
echo    SERENO NETWORK MONITOR - Admin Mode
echo ==========================================
echo.

target\x86_64-pc-windows-msvc\release\sereno-service.exe

pause
