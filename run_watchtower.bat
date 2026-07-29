@echo off
REM WATCHTOWER launcher for Windows.
REM Run this from inside the watchtower project folder (D:\Projects\watchtower).

cd /d "%~dp0"

if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat

echo Installing/checking dependencies...
pip install -r requirements.txt

echo.
echo Starting WATCHTOWER...
echo Dashboard will be at http://localhost:5000/
echo Login: admin / watchtower123  (change this - see README_RUN.md)
echo Press CTRL+C to stop.
echo.
python core.py

pause
