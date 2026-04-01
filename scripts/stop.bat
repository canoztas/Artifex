@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0\.."

set "STATE_FILE=%CD%\data\artifex-services.env"
set "QUIET="
if /I "%~1"=="--quiet" set "QUIET=1"

if not exist "%STATE_FILE%" (
    if not defined QUIET echo No tracked Artifex services are currently running.
    exit /b 0
)

for /f "usebackq tokens=1,* delims==" %%A in ("%STATE_FILE%") do (
    set "%%A=%%B"
)

if not defined QUIET (
    echo ============================================
    echo  Artifex DFIR - Stopping Services
    echo ============================================
    echo.
)

call :stop_pid "%API_PID%" "API server"
call :stop_pid "%WORKER_PID%" "Python worker"
call :stop_pid "%COLLECTOR_PID%" "Collector service"

del /f /q "%STATE_FILE%" >nul 2>nul

if not defined QUIET (
    echo.
    echo All tracked Artifex services have been stopped.
)
exit /b 0

:stop_pid
set "TARGET_PID=%~1"
set "TARGET_NAME=%~2"

if "%TARGET_PID%"=="" (
    if not defined QUIET echo %TARGET_NAME%: no PID recorded.
    exit /b 0
)

tasklist /FI "PID eq %TARGET_PID%" 2>nul | findstr /C:" %TARGET_PID% " >nul
if %ERRORLEVEL% neq 0 (
    if not defined QUIET echo %TARGET_NAME%: already stopped ^(PID %TARGET_PID%^).
    exit /b 0
)

taskkill /PID %TARGET_PID% /T /F >nul 2>nul
if %ERRORLEVEL% equ 0 (
    if not defined QUIET echo %TARGET_NAME%: stopped ^(PID %TARGET_PID%^).
) else (
    if not defined QUIET echo %TARGET_NAME%: failed to stop ^(PID %TARGET_PID%^).
)
exit /b 0
