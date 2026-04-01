@echo off
setlocal EnableExtensions EnableDelayedExpansion

if /I "%~1"=="stop" (
    call "%~dp0stop.bat" %2 %3 %4 %5 %6 %7 %8 %9
    exit /b %ERRORLEVEL%
)

echo ============================================
echo  Artifex DFIR - Starting Services
echo ============================================
echo.

cd /d "%~dp0\.."

set "ROOT_DIR=%CD%"
set "DATA_DIR=%ROOT_DIR%\data"
set "EVIDENCE_DIR=%ROOT_DIR%\evidence"
set "STATE_FILE=%DATA_DIR%\artifex-services.env"

set "COLLECTOR_ERR_LOG=%DATA_DIR%\collector.log"
set "COLLECTOR_OUT_LOG=%DATA_DIR%\collector.stdout.log"
set "COLLECTOR_PID_FILE=%DATA_DIR%\collector.pid"
set "WORKER_ERR_LOG=%DATA_DIR%\worker.log"
set "WORKER_OUT_LOG=%DATA_DIR%\worker.stdout.log"
set "WORKER_PID_FILE=%DATA_DIR%\worker.pid"
set "API_ERR_LOG=%DATA_DIR%\api.log"
set "API_OUT_LOG=%DATA_DIR%\api.stdout.log"
set "API_PID_FILE=%DATA_DIR%\api.pid"

if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%EVIDENCE_DIR%" mkdir "%EVIDENCE_DIR%"

fltmc >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo WARNING: This shell is not running as Administrator.
    echo Advanced collection features such as memory capture may fail until Artifex is started from an elevated command prompt.
    echo.
)

echo Cleaning up any existing Artifex services from this workspace...
call "%~dp0stop.bat" --quiet
echo.

if not exist "bin\artifex-api.exe" (
    echo ERROR: bin\artifex-api.exe not found. Run scripts\build.bat first.
    exit /b 1
)
if not exist "bin\artifex-collector.exe" (
    echo ERROR: bin\artifex-collector.exe not found. Run scripts\build.bat first.
    exit /b 1
)
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python is not installed or not in PATH.
    echo The worker service requires Python 3.10+ and the packages in worker\requirements.txt.
    exit /b 1
)

echo Starting Collector service on :8081...
set "COLLECTOR_PID="
if exist "%COLLECTOR_PID_FILE%" del /f /q "%COLLECTOR_PID_FILE%" >nul 2>nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_background.ps1" -FilePath "%ROOT_DIR%\bin\artifex-collector.exe" -WorkingDirectory "%ROOT_DIR%" -StdOut "%COLLECTOR_OUT_LOG%" -StdErr "%COLLECTOR_ERR_LOG%" -PidFile "%COLLECTOR_PID_FILE%"
if exist "%COLLECTOR_PID_FILE%" set /p COLLECTOR_PID=<"%COLLECTOR_PID_FILE%"
echo(!COLLECTOR_PID!| findstr /R "^[0-9][0-9]*$" >nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to launch collector service.
    exit /b 1
)
echo   Collector service started with PID !COLLECTOR_PID!.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0wait_for_health.ps1" -Url "http://127.0.0.1:8081/health" -MaxAttempts 10 >nul 2>nul
if %ERRORLEVEL% neq 0 goto :startup_failed
echo   Collector service is healthy.

echo Starting Python Worker on :8083...
set "WORKER_PID="
if exist "%WORKER_PID_FILE%" del /f /q "%WORKER_PID_FILE%" >nul 2>nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_background.ps1" -FilePath "python" -ArgumentList "worker\main.py" -WorkingDirectory "%ROOT_DIR%" -StdOut "%WORKER_OUT_LOG%" -StdErr "%WORKER_ERR_LOG%" -PidFile "%WORKER_PID_FILE%" -EnvVar "ARTIFEX_DB=%ROOT_DIR%\data\artifex.db;ARTIFEX_EVIDENCE=%EVIDENCE_DIR%"
if exist "%WORKER_PID_FILE%" set /p WORKER_PID=<"%WORKER_PID_FILE%"
echo(!WORKER_PID!| findstr /R "^[0-9][0-9]*$" >nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to launch Python worker process.
    exit /b 1
)
echo   Python worker started with PID !WORKER_PID!.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0wait_for_health.ps1" -Url "http://127.0.0.1:8083/health" -MaxAttempts 20 >nul 2>nul
if %ERRORLEVEL% neq 0 goto :startup_failed
echo   Python worker is healthy.

echo Starting API server on :8080...
set "API_PID="
if exist "%API_PID_FILE%" del /f /q "%API_PID_FILE%" >nul 2>nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_background.ps1" -FilePath "%ROOT_DIR%\bin\artifex-api.exe" -WorkingDirectory "%ROOT_DIR%" -StdOut "%API_OUT_LOG%" -StdErr "%API_ERR_LOG%" -PidFile "%API_PID_FILE%"
if exist "%API_PID_FILE%" set /p API_PID=<"%API_PID_FILE%"
echo(!API_PID!| findstr /R "^[0-9][0-9]*$" >nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to launch API server.
    goto :startup_failed
)
echo   API server started with PID !API_PID!.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0wait_for_health.ps1" -Url "http://127.0.0.1:8080/health" -MaxAttempts 20 >nul 2>nul
if %ERRORLEVEL% neq 0 goto :startup_failed
echo   API server is healthy.

(
    echo ROOT_DIR=%ROOT_DIR%
    echo COLLECTOR_PID=%COLLECTOR_PID%
    echo WORKER_PID=%WORKER_PID%
    echo API_PID=%API_PID%
) > "%STATE_FILE%"

echo.
echo ============================================
echo  All services started!
echo  Web UI: http://127.0.0.1:8080
echo  API:    http://127.0.0.1:8080/api
echo  MCP:    Run bin\artifex-mcp.exe ^(stdio^)
echo ============================================
echo.
echo Press Ctrl+C in this window to stop the full stack cleanly.
echo You can also stop it later with scripts\stop.bat.
echo Logs:
echo   %COLLECTOR_ERR_LOG%
echo   %WORKER_ERR_LOG%
echo   %API_ERR_LOG%
echo.

powershell -NoProfile -Command ^
  "$script:stop = $false; " ^
  "$handler = [ConsoleCancelEventHandler]{ param($sender, $eventArgs) $script:stop = $true; $eventArgs.Cancel = $true }; " ^
  "[Console]::add_CancelKeyPress($handler); " ^
  "try { while (-not $script:stop) { Start-Sleep -Milliseconds 250 } } finally { [Console]::remove_CancelKeyPress($handler) }"

echo.
echo Stopping Artifex services...
call "%~dp0stop.bat" --quiet
echo All tracked Artifex services have been stopped.
exit /b 0

:startup_failed
echo.
echo ERROR: Startup failed. Cleaning up any services that were launched...
call "%~dp0stop.bat" --quiet
if exist "%STATE_FILE%" del /f /q "%STATE_FILE%" >nul 2>nul
exit /b 1
