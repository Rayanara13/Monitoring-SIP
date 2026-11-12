@echo off
setlocal DisableDelayedExpansion
set "KIT=%~dp0"
set "PY=%KIT%runtime\windows\python.exe"
if not exist "%KIT%diagnose.py" goto incomplete
if not exist "%KIT%app\server.py" goto incomplete
if not exist "%KIT%vendor\flask\__init__.py" goto incomplete
if not exist "%PY%" goto missing_python

"%PY%" -I -B -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if errorlevel 1 goto missing_python
"%PY%" -I -B -X utf8 "%KIT%diagnose.py" %*
set "RESULT=%errorlevel%"
if "%~1"=="" pause
exit /b %RESULT%

:missing_python
echo [FAIL] KIT_RUNTIME_MISSING - Bundled Python is missing or cannot start.
echo Extract the complete Windows x64 kit to a local folder.
if "%~1"=="" pause
exit /b 1

:incomplete
echo [FAIL] KIT_INCOMPLETE - Application or dependency files are missing.
echo Extract the complete offline Windows kit, then run this file again.
if "%~1"=="" pause
exit /b 1
