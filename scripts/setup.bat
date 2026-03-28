@echo off
setlocal EnableExtensions EnableDelayedExpansion

echo ============================================
echo  Pickaxe DFIR - Initial Setup
echo ============================================
echo.

cd /d "%~dp0\.."

:: Check Go
echo Checking prerequisites...
where go >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Go is not installed or not in PATH.
    echo Please install Go from https://go.dev/dl/
    exit /b 1
)
echo   Go: OK

:: Check Python
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo WARNING: Python is not installed or not in PATH.
    echo The worker service requires Python 3.10+.
    echo Please install Python from https://python.org
) else (
    echo   Python: OK
)

:: Check Node.js
where node >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo WARNING: Node.js is not installed or not in PATH.
    echo The UI requires Node.js 20+.
    echo Please install Node.js from https://nodejs.org
) else (
    set "NODE_VERSION="
    set "NODE_MAJOR="
    set "NPM_VERSION="
    for /f "delims=v tokens=2" %%A in ('node --version 2^>nul') do set "NODE_VERSION=%%A"
    for /f "tokens=1 delims=." %%A in ("!NODE_VERSION!") do set "NODE_MAJOR=%%A"

    where npm >nul 2>nul
    if !ERRORLEVEL! neq 0 (
        echo WARNING: npm is not installed or not in PATH.
        echo The UI build requires npm bundled with Node.js 20+.
        echo Please reinstall Node.js from https://nodejs.org
    ) else (
        if not defined NODE_MAJOR (
            echo WARNING: Unable to determine Node.js version.
            echo Please ensure Node.js 20+ is installed.
        ) else (
            if !NODE_MAJOR! lss 20 (
                echo WARNING: Node.js !NODE_VERSION! detected.
                echo The UI requires Node.js 20+.
                echo Please upgrade Node.js from https://nodejs.org
            ) else (
                echo   Node.js: OK ^(v!NODE_VERSION!^)
                for /f %%A in ('npm --version 2^>nul') do set "NPM_VERSION=%%A"
                if defined NPM_VERSION (
                    echo   npm: OK ^(v!NPM_VERSION!^)
                ) else (
                    echo   npm: OK
                )
            )
        )
    )
)

echo.

:: Create directories
echo Creating project directories...
if not exist "data" mkdir data
if not exist "evidence" mkdir evidence
if not exist "tools" mkdir tools
if not exist "bin" mkdir bin
echo   OK

:: Download Go dependencies
echo.
echo Downloading Go dependencies...
go mod download
if %ERRORLEVEL% neq 0 (
    echo   WARNING: go mod download failed. Trying go mod tidy...
    go mod tidy
    if %ERRORLEVEL% neq 0 (
        echo   WARNING: go mod tidy also failed.
    ) else (
        echo   OK
    )
 ) else (
    echo   OK
)

:: Install Python dependencies
echo.
echo Installing Python worker dependencies...
if exist "worker\requirements.txt" (
    where python >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo   SKIPPED: Python is not available, so worker dependencies could not be installed.
    ) else (
        python -m pip --version >nul 2>nul
        if %ERRORLEVEL% neq 0 (
            echo   SKIPPED: pip is not available for the active Python interpreter.
        ) else (
            call python -m pip install -r worker\requirements.txt
            if %ERRORLEVEL% neq 0 (
                echo   WARNING: Some Python dependencies failed to install.
            ) else (
                echo   OK
            )
        )
    )
)

:: Install UI dependencies
echo.
echo Installing UI dependencies...
if exist "ui\package.json" (
    where npm >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo   SKIPPED: npm is not available, so UI dependencies could not be installed.
    ) else (
        pushd ui
        call npm install
        if %ERRORLEVEL% neq 0 (
            echo   WARNING: UI dependency install failed.
        ) else (
            echo   OK
        )
        popd
    )
)

:: Create default config if missing
if not exist "config.json" (
    echo.
    echo Creating default config.json...
    echo Please edit config.json to add your API keys.
)

echo.
echo ============================================
echo  Setup complete!
echo.
echo  Next steps:
echo  1. Edit config.json with your LLM API key
echo  2. Run scripts\build.bat to compile
echo  3. Run scripts\run.bat to start services
echo  4. Open http://127.0.0.1:8080 in browser
echo ============================================
