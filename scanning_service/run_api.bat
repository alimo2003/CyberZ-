@echo off
title CyberZ Scanning API
color 0A
cls

echo ===================================================
echo    CyberZ User Scanning API 
echo ===================================================
echo.

echo Installing required packages...
pip install -r requirements.txt >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to install required packages
    pause
    exit /b 1
)


python simple_scan_service.py

pause
