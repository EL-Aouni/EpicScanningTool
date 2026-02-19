@echo off
echo.
echo 🛡️ APEC Penetration Testing Tool - Setup
echo ==========================================
echo.

REM Check Python version
python --version

REM Create virtual environment
echo Creating virtual environment...
python -m venv venv

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

echo.
echo ✅ Setup complete!
echo.
echo To run the application:
echo   1. Activate virtual environment: venv\Scripts\activate.bat
echo   2. Run the tool: python main.py
echo.
pause
