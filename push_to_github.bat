@echo off
echo ============================================================
echo   ⚛ QuantumPay — GitHub Push Utility
echo ============================================================
echo.

set /p REPO_URL="Enter your GitHub Repository URL (e.g. https://github.com/YOUR_USERNAME/quantumpay.git): "

if "%REPO_URL%"=="" (
    echo ❌ Repository URL cannot be empty.
    pause
    exit /b 1
)

echo.
echo 📦 Initializing Git repository...
git init
git branch -M main
git add .
git commit -m "Initial commit: QuantumPay Post-Quantum Payment Platform"
git remote add origin %REPO_URL%

echo.
echo 🚀 Pushing code to GitHub...
git push -u origin main

echo.
echo ============================================================
echo   ✅ QuantumPay successfully pushed to GitHub!
echo ============================================================
pause
