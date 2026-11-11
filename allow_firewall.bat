@echo off
title Unblock 5G Port 2152 & Ping in Windows Firewall
echo ================================================================
echo   🛡️  CONFIGURING WINDOWS FIREWALL FOR LAB NETWORK
echo ================================================================
echo.

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Requesting Administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c %~s0' -Verb RunAs"
    exit /b
)

echo [*] Adding Inbound Rule for 5G GTP-U (UDP Port 2152)...
netsh advfirewall firewall delete rule name="FRI_DAY_UPF_2152" >nul 2>&1
netsh advfirewall firewall add rule name="FRI_DAY_UPF_2152" dir=in action=allow protocol=UDP localport=2152 profile=any

echo [*] Adding Inbound Rule for ICMP Ping...
netsh advfirewall firewall delete rule name="FRI_DAY_ALLOW_PING" >nul 2>&1
netsh advfirewall firewall add rule name="FRI_DAY_ALLOW_PING" dir=in action=allow protocol=ICMPv4 profile=any

echo.
echo ================================================================
echo   [✓] SUCCESS: Port 2152 & Ping are now UNBLOCKED on all networks!
echo   👉 Second laptop can now reach 10.0.8.254 without firewall blocks.
echo ================================================================
echo.
pause
