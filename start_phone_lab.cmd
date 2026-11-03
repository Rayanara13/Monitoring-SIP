@echo off
cd /d "%~dp0"
set PYTHONUTF8=1
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -m simulator --open %*
) else (
  py -3 -m simulator --open %*
)
if errorlevel 1 pause
