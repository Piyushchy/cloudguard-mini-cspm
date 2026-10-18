@echo off
REM One-click offline demo for Windows. Needs Python 3.11+ on PATH. No AWS account needed.
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install -q -r scanner\requirements.txt
python -m pytest -q
if errorlevel 1 (
  echo Tests failed - see output above.
  pause
  exit /b 1
)
python -m scanner.demo_local --open
pause
