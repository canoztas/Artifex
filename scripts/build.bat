@echo off
setlocal EnableExtensions

echo ============================================
echo  Pickaxe DFIR - Build Script (Windows)
echo ============================================
echo.

cd /d "%~dp0\.."

:: Create data directory
if not exist "data" mkdir data
if not exist "evidence" mkdir evidence
if not exist "tools" mkdir tools
if not exist "bin" mkdir bin

:: Check build prerequisites
where go >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Go is not installed or not in PATH.
    echo Please install Go from https://go.dev/dl/
    exit /b 1
)

:: Build Go services
echo [1/3] Building Go services...
echo   Building API server...
go build -o bin\pickaxe-api.exe .\cmd\api\
if %ERRORLEVEL% neq 0 (
    echo   FAILED: API server build failed
    exit /b 1
)
echo   OK

echo   Building Collector service...
go build -o bin\pickaxe-collector.exe .\cmd\collector\
if %ERRORLEVEL% neq 0 (
    echo   FAILED: Collector build failed
    exit /b 1
)
echo   OK

echo   Building MCP server...
go build -o bin\pickaxe-mcp.exe .\cmd\mcp\
if %ERRORLEVEL% neq 0 (
    echo   FAILED: MCP server build failed
    exit /b 1
)
echo   OK

:: Install Python dependencies
echo.
echo [2/3] Installing Python worker dependencies...
if exist "worker\requirements.txt" (
    where python >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo   WARNING: Python is not installed or not in PATH. Worker dependencies were skipped.
    ) else (
        python -m pip --version >nul 2>nul
        if %ERRORLEVEL% neq 0 (
            echo   WARNING: pip is not available for the active Python interpreter. Worker dependencies were skipped.
        ) else (
            call python -m pip install -r worker\requirements.txt --quiet --disable-pip-version-check
            if %ERRORLEVEL% neq 0 (
                echo   WARNING: Python dependency install failed. Worker may not function.
            ) else (
                echo   OK
            )
        )
    )
) else (
    echo   SKIPPED: No requirements.txt found
)

:: Build UI
echo.
echo [3/3] Building UI...
if exist "ui\package.json" (
    where node >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo   WARNING: Node.js is not installed or not in PATH. Skipping UI build.
    ) else (
        where npm >nul 2>nul
        if %ERRORLEVEL% neq 0 (
            echo   WARNING: npm is not installed or not in PATH. Skipping UI build.
        ) else (
            pushd ui
            if not exist "node_modules" (
                echo   Installing UI dependencies...
                if exist "package-lock.json" (
                    call npm ci
                ) else (
                    call npm install
                )
                if %ERRORLEVEL% neq 0 (
                    echo   WARNING: UI dependency install failed. Skipping UI build.
                    popd
                    goto :after_ui_build
                )
            )

            call npm run build
            if %ERRORLEVEL% neq 0 (
                echo   WARNING: UI build failed.
            ) else (
                echo   OK
            )
            popd
        )
    )
) else (
    echo   SKIPPED: No package.json found
)
:after_ui_build

echo.
echo ============================================
echo  Build complete!
echo  Binaries are in bin\
echo ============================================
