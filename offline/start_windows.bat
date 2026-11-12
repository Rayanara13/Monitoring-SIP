@echo off
rem Monitoring SIP - start on Windows (offline kit).
rem Tries the bundled portable Python first, then a system one (3.10+).
setlocal
if exist "%~dp0prepare_windows_kit.ps1" goto source_archive
cd /d "%~dp0"
title Monitoring SIP

set "PY="
call :try "%~dp0runtime\windows\python.exe"
if not defined PY call :try py -3
if not defined PY call :try python
if not defined PY call :try python3
if not defined PY goto nopython

echo Starting Monitoring SIP ...
echo Stop: Ctrl+C or close this window.
echo.
%PY% "%~dp0run.py" %*
set "RESULT=%errorlevel%"
echo.
echo Server stopped (exit code %RESULT%).
if "%~1"=="" pause
exit /b %RESULT%

:try
%* -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1 && set "PY=%*"
exit /b

:nopython
echo ERROR: no working Python 3.10+ found.
echo The bundled one is in runtime\windows - check the archive was fully extracted.
echo See the "Problems" section of the instruction file.
pause
exit /b 1

:source_archive
call "%~dp0..\start_windows.bat" %*
exit /b %errorlevel%
