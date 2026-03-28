@echo off
setlocal EnableExtensions

echo ============================================
echo  Pickaxe DFIR - Starting Services
echo ============================================
echo.

cd /d "%~dp0\.."

:: Create data directory
if not exist "data" mkdir data
if not exist "evidence" mkdir evidence

:: Check builds exist
if not exist "bin\pickaxe-api.exe" (
    echo ERROR: bin\pickaxe-api.exe not found. Run scripts\build.bat first.
    exit /b 1
)
if not exist "bin\pickaxe-collector.exe" (
    echo ERROR: bin\pickaxe-collector.exe not found. Run scripts\build.bat first.
    exit /b 1
)
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python is not installed or not in PATH.
    echo The worker service requires Python 3.10+ and the packages in worker\requirements.txt.
    exit /b 1
)

:: Start Collector service (background)
echo Starting Collector service on :8081...
start "Pickaxe Collector" /min bin\pickaxe-collector.exe
call :wait_for_health "http://127.0.0.1:8081/health" "Collector service" 10
if %ERRORLEVEL% neq 0 exit /b 1

:: Start Python Worker (background)
echo Starting Python Worker on :8083...
set "PICKAXE_DB=%CD%\data\pickaxe.db"
set "PICKAXE_EVIDENCE=%CD%\evidence"
set "WORKER_ERR_LOG=%CD%\data\worker.log"
set "WORKER_OUT_LOG=%CD%\data\worker.stdout.log"
powershell -NoProfile -Command "$env:PICKAXE_DB='%PICKAXE_DB%'; $env:PICKAXE_EVIDENCE='%PICKAXE_EVIDENCE%'; New-Item -ItemType File -Path '%WORKER_ERR_LOG%' -Force | Out-Null; Start-Process -FilePath 'python' -ArgumentList 'worker\main.py' -WorkingDirectory '%CD%' -RedirectStandardOutput '%WORKER_OUT_LOG%' -RedirectStandardError '%WORKER_ERR_LOG%' -WindowStyle Hidden"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to launch Python worker process.
    exit /b 1
)
call :wait_for_health "http://127.0.0.1:8083/health" "Python worker" 20
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python worker failed to start on :8083.
    echo Check data\worker.log and data\worker.stdout.log for startup errors.
    exit /b 1
)

:: Start API server (foreground)
echo Starting API server on :8080...
echo.
echo ============================================
echo  All services started!
echo  Web UI: http://127.0.0.1:8080
echo  API:    http://127.0.0.1:8080/api
echo  MCP:    Run bin\pickaxe-mcp.exe (stdio)
echo ============================================
echo.
echo Press Ctrl+C to stop the API server.
echo (Close other service windows manually)
echo.

bin\pickaxe-api.exe
goto :eof

:wait_for_health
set "HEALTH_URL=%~1"
set "SERVICE_NAME=%~2"
set "MAX_ATTEMPTS=%~3"
set /a ATTEMPT=0

:health_check_loop
set /a ATTEMPT+=1
powershell -NoProfile -Command "try { $r = Invoke-WebRequest -Uri '%HEALTH_URL%' -UseBasicParsing -TimeoutSec 2; if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 300) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo   %SERVICE_NAME% is healthy.
    exit /b 0
)

if %ATTEMPT% geq %MAX_ATTEMPTS% (
    echo   ERROR: %SERVICE_NAME% did not become healthy in time.
    exit /b 1
)

timeout /t 1 /nobreak >nul
goto :health_check_loop
