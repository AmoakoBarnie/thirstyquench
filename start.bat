@echo off
title Thirsty Quench - Balance Sheet
cd /d "%~dp0"

echo.
echo  Starting Thirsty Quench Balance Sheet...
echo.

where python >nul 2>&1
if errorlevel 1 (
  echo  Python was not found. Install Python and try again.
  pause
  exit /b 1
)

python -c "import flask" 2>nul
if errorlevel 1 (
  echo  Installing Flask...
  python -m pip install -r requirements.txt
)

echo  Opening login page...
start "" "http://127.0.0.1:5050/login"
python app.py

echo.
echo  Server stopped.
pause

