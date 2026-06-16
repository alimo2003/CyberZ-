@echo off
echo Starting User Management API...

:: Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: Python is not installed or not in PATH
    pause
    exit /b 1
)

:: Check if required packages are installed
python -c "import flask" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Installing required Python packages...
    pip install flask flask-cors pyodbc
    if %ERRORLEVEL% neq 0 (
        echo Failed to install required packages
        pause
        exit /b 1
    )
)

:: Start the API server
echo Starting API server on http://localhost:5001
echo Press Ctrl+C to stop the server

python user_management_api.py

if %ERRORLEVEL% neq 0 (
    echo.
    echo Error: Failed to start the API server
    pause
)
