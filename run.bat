@echo off
REM One-click launcher for Windows 11 (needs Python 3.11+ on PATH)
cd /d %~dp0
if not exist .venv ( python -m venv .venv )
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
pause
