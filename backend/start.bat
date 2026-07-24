@echo off
echo.
echo ============================================================
echo   ⚛ QuantumPay Backend Launcher
echo ============================================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found. Install from https://python.org
    pause
    exit /b 1
)

echo ✅ Python found
echo.
echo 📦 Installing dependencies...
cd /d "%~dp0"
pip install -r requirements.txt -q

echo.
echo ============================================================
echo   🚀 Starting QuantumPay Backend on http://localhost:8000
echo   📖 API Docs: http://localhost:8000/docs
echo   🔐 QRNG:     http://localhost:8000/api/qrng
echo ============================================================
echo.

python main.py
pause
