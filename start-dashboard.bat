@echo off
setlocal enableextensions

REM Always run from the folder where this .bat lives
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

REM Prefer local Node installation if available
set "NODE_EXE=C:\Program Files\nodejs\node.exe"
set "NPM_CMD=C:\Program Files\nodejs\npm.cmd"

if exist "%NODE_EXE%" (
  set "NODE=%NODE_EXE%"
) else (
  set "NODE=node"
)

if exist "%NPM_CMD%" (
  set "NPM=%NPM_CMD%"
) else (
  set "NPM=npm"
)

REM Bind to all interfaces so it works via LAN IP
set "HOST=0.0.0.0"

REM Install dependencies if node_modules missing
if not exist "%SCRIPT_DIR%node_modules" (
  echo Installing dependencies...
  call "%NPM%" install
  if errorlevel 1 (
    echo.
    echo Failed to install dependencies.
    pause
    exit /b 1
  )
)

echo.
echo Starting server...
echo - Local: http://localhost:5173
echo - LAN  : http://^<THIS-PC-IP^>:5173
echo.
echo If the page is not reachable from other devices, allow Node.js through Windows Firewall.
echo.

call "%NPM%" start

pause
