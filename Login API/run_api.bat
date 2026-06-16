@echo off
title CyberZ User Management API (Port 8100)
color 0A
cls

echo ===================================================
echo    CyberZ User Management API (Port 8100)
echo ===================================================
echo.

echo Installing required packages...
pip install -r requirements.txt >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to install required packages
    pause
    exit /b 1
)

echo.
echo Starting CyberZ User Management API...
echo.
echo API Endpoints:
echo   1. GET    /api/health          - Health check
echo   2. POST   /api/login           - User login
echo   3. GET    /api/users           - Get all users (admin only)
echo   4. GET    /api/users/<id>      - Get user by ID (admin or self)
echo.
echo Test Commands:
echo   # Health check
echo   curl http://localhost:8100/api/health

echo.
echo   # Login (replace with actual credentials)
echo   curl -X POST http://localhost:8100/api/login ^
     -H "Content-Type: application/json" ^
     -d "{\"username\":\"admin\",\"password\":\"your_password_here\"}"

echo.
echo   # Get all users (requires admin token)
echo   curl http://localhost:8100/api/users ^
     -H "Authorization: Bearer YOUR_JWT_TOKEN"

echo.
echo   # Get specific user (requires admin or self token)
echo   curl http://localhost:8100/api/users/1 ^
     -H "Authorization: Bearer YOUR_JWT_TOKEN"
echo.
echo Note: Replace YOUR_JWT_TOKEN with the token received from login
echo.

python auth_api.py

pause
