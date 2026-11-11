@echo off
title FRI-DAY 5G SOC Launcher
cls
echo ================================================================
echo   🚀 LAUNCHING FRI-DAY 5G AGENTIC AUTONOMOUS DEFENSE SOC
echo ================================================================
echo.

echo [*] Starting FastAPI Backend & Neural Model (Terminal 1)...
start "FRI-DAY Backend (app.py)" cmd /k "cd /d C:\5g usecase && python app.py"

echo [*] Waiting 3 seconds for backend initialization...
timeout /t 3 /nobreak >nul

echo [*] Starting 5G UPF Sensor on UDP Port 2152 (Terminal 2)...
start "FRI-DAY UPF Sensor (sensor.py)" cmd /k "cd /d C:\5g usecase && python sensor.py"

echo [*] Launching Tactical Defense Dashboard in default browser...
timeout /t 2 /nobreak >nul
start http://127.0.0.1:8000/

echo.
echo ================================================================
echo   [✓] FRI-DAY SOC IS ONLINE AND SURVEILLANCE IS ACTIVE!
echo ================================================================
echo.
pause
