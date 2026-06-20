@echo off
REM Cyber Exposure Governance Platform - Windows runner
REM Recommended location: C:\cyber-exposure-governance-platform-product

cd /d C:\cyber-exposure-governance-platform-product

IF NOT EXIST ".venv" (
    echo Creating Python virtual environment...
    python -m venv .venv
)

call .venv\Scripts\activate

echo Installing/updating required packages...
pip install -r requirements.txt

echo Starting Streamlit application...
streamlit run app.py
pause
