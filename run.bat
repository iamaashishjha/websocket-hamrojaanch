@echo off
REM ═══════════════════════════════════════════════════════
REM HamroJaanch WebSocket Signaling — Start Server (Windows)
REM Usage: run.bat [--skip]
REM   --skip  Skip npm install, start server directly
REM ═══════════════════════════════════════════════════════

setlocal
cd /d "%~dp0"

echo =======================================
echo   HamroJaanch WebSocket Signaling
echo =======================================
echo.

REM ── Create .env from example if missing ──
if not exist ".env" (
  if exist ".env.example" (
    echo [env] Creating .env from .env.example...
    copy ".env.example" ".env" >nul
  )
)

REM ── Install dependencies unless --skip ──
if "%~1" NEQ "--skip" (
  echo [npm] Installing dependencies...
  call npm install
  echo.
)

echo [ws] Starting signaling server on http://localhost:3001
echo      Press Ctrl+C to stop.
echo.
node index.cjs

endlocal
