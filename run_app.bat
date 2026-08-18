@echo off
title CloudVPC Studio - Multi-Subnet Architecture Design Suite
echo ====================================================================
echo   Starting CloudVPC Studio (Virtual Private Cloud Design & Simulator)
echo   Python Web Application & Network Security Engine
echo ====================================================================
echo.

python run_app.py 8000

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo An error occurred starting CloudVPC Studio.
    pause
)
