@echo off
REM Enhanced Features Setup Script for Windows
REM Creates a virtual environment and installs pefile for enhanced location tracking

echo 🔧 DER Private Key Analyzer - Enhanced Features Setup
echo =====================================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Error: Python not found. Please install Python 3.6 or higher.
    pause
    exit /b 1
)

echo ✅ Python found

REM Create virtual environment
echo 📦 Creating virtual environment...
python -m venv venv
if errorlevel 1 (
    echo ❌ Failed to create virtual environment
    pause
    exit /b 1
)
echo ✅ Virtual environment created: venv\

REM Activate virtual environment
echo 🔌 Activating virtual environment...
call venv\Scripts\activate.bat

REM Install pefile
echo 📦 Installing pefile in virtual environment...
pip install pefile
if errorlevel 1 (
    echo ❌ Failed to install pefile in virtual environment
    pause
    exit /b 1
)
echo ✅ Successfully installed pefile!

REM Test installation
echo 🧪 Testing installation...
python -c "import pefile; print('✅ pefile import successful!')"
if errorlevel 1 (
    echo ❌ Installation verification failed.
    pause
    exit /b 1
)
echo ✅ Installation verification passed!

REM Test enhanced features
echo 🔍 Testing enhanced features...
python -c "import sys; from pathlib import Path; sys.path.insert(0, str(Path('.').absolute())); from pe_analyzer import PEAnalyzer; analyzer = PEAnalyzer(); analyzer.cleanup(); print('✅ Enhanced features test passed!')"
if errorlevel 1 (
    echo ❌ Enhanced features test failed.
    pause
    exit /b 1
)
echo ✅ Enhanced features are working!

echo.
echo =====================================================
echo 🎉 Enhanced Features Setup Complete!
echo =====================================================
echo.
echo To use the enhanced features, activate the virtual environment first:
echo   venv\Scripts\activate.bat
echo.
echo Then run the analyzer:
echo   python der_private_key_analyzer.py C:\path\to\executable.exe
echo.
echo The tool will now show enhanced output like:
echo   ✓ Found DER private key at offset 0x123456 (Section: .rdata)
echo.
echo To deactivate the virtual environment when done:
echo   deactivate
echo.
pause
