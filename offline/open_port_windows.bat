@echo off
rem Opens inbound TCP 8000 in Windows Firewall so phones can reach the server.
rem Right click -> "Run as administrator".
net session >nul 2>&1
if errorlevel 1 goto noadmin

netsh advfirewall firewall delete rule name="Monitoring SIP 8000" >nul 2>&1
netsh advfirewall firewall add rule name="Monitoring SIP 8000" dir=in action=allow protocol=TCP localport=8000
if errorlevel 1 goto failed
echo OK: port 8000 is open (rule "Monitoring SIP 8000").
pause
exit /b 0

:noadmin
echo ERROR: run this file as administrator (right click - Run as administrator).
pause
exit /b 1

:failed
echo ERROR: netsh could not add the rule.
pause
exit /b 1
