@echo off
rem Monitoring SIP - start on Windows (offline kit).
rem Tries the bundled portable Python first, then a system one (3.10+).
setlocal
cd /d "%~dp0"
title Monitoring SIP

set "PY="
call :try "%~dp0runtime\windows\python.exe"
if not defined PY call :try py -3
if not defined PY call :try python
if not defined PY call :try python3
if not defined PY goto nopython

echo Starting Monitoring SIP on port 8000 ...
echo Stop: Ctrl+C or close this window.
echo.
%PY% "%~dp0run.py"
echo.
echo Server stopped (exit code %errorlevel%).
pause
exit /b

:try
%* -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1 && set "PY=%*"
exit /b

:nopython
echo ERROR: no working Python 3.10+ found.
echo The bundled one is in runtime\windows - check the archive was fully extracted.
echo See the "Problems" section of the instruction file.
pause
exit /b 1
