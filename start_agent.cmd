@echo off
setlocal
cd /d "%~dp0"
set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not exist "%PY%" set "PY=python"

REM ============================================================
REM  AutoPentest Sentinel
REM  Primary  : Google Gemini   (from .env)
REM  Fallback : local Ollama    (automatic, when Gemini is down)
REM  URL      : http://127.0.0.1:8000
REM
REM  You do NOT need to set anything here: the LLM chain is
REM  configured in the .env file (APS_LLM_* / APS_LLM_FALLBACK_*).
REM  This script just launches the server on port 8000.
REM ============================================================

curl -s -o nul --max-time 3 http://127.0.0.1:11434/api/tags
if errorlevel 1 (
  echo [warn] Ollama is NOT running on 127.0.0.1:11434
  echo        For the automatic fallback to work, start it with:  ollama serve
  echo.
)

echo Starting AutoPentest Sentinel at http://127.0.0.1:8000
echo   Planner chain: Gemini  ->  Ollama (automatic fallback)
echo Press CTRL+C to stop.
"%PY%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
