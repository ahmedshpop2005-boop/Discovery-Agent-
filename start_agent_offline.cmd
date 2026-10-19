@echo off
setlocal
cd /d "%~dp0"
set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not exist "%PY%" set "PY=python"

REM ============================================================
REM  AutoPentest Sentinel - OFFLINE mode (no internet needed)
REM  Uses the local Ollama model for planning.
REM ============================================================
set "APS_LLM_BASE_URL=http://127.0.0.1:11434/v1"
set "APS_LLM_API_KEY=ollama"
set "APS_LLM_MODEL=qwen2.5:7b"
set "APS_LLM_TIMEOUT=120"

curl -s -o nul --max-time 3 http://127.0.0.1:11434/api/tags
if errorlevel 1 (
  echo [warn] Ollama is NOT running on 127.0.0.1:11434
  echo        Start it first in another window with:  ollama serve
  echo.
)

echo Starting AutoPentest Sentinel (Ollama) at http://127.0.0.1:8000
echo Press CTRL+C to stop.
"%PY%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
