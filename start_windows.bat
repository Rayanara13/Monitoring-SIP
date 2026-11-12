@echo off
setlocal DisableDelayedExpansion
pushd "%~dp0" || goto no_directory

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ".\offline\prepare_windows_kit.ps1"
if errorlevel 1 goto failed
if /i "%~1"=="--prepare" goto prepared

call "%CD%\MonitoringSIP\start_windows.bat" %*
set "RESULT=%errorlevel%"
popd
exit /b %RESULT%

:prepared
echo Offline kit ready at "%CD%\MonitoringSIP".
popd
exit /b 0

:failed
echo ERROR: the offline kit could not be prepared.
popd
if "%~1"=="" pause
exit /b 1

:no_directory
echo ERROR: the source folder could not be opened.
if "%~1"=="" pause
exit /b 1
