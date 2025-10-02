#!/bin/bash
# Enhanced Features Setup Script
# Creates a virtual environment and installs pefile for enhanced location tracking

echo "🔧 DER Private Key Analyzer - Enhanced Features Setup"
echo "====================================================="
echo

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 not found. Please install Python 3.6 or higher."
    exit 1
fi

echo "✅ Python 3 found"

# Create virtual environment
echo "📦 Creating virtual environment..."
if python3 -m venv venv; then
    echo "✅ Virtual environment created: venv/"
else
    echo "❌ Failed to create virtual environment"
    exit 1
fi

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# Install pefile
echo "📦 Installing pefile in virtual environment..."
if pip install pefile; then
    echo "✅ Successfully installed pefile!"
else
    echo "❌ Failed to install pefile in virtual environment"
    exit 1
fi

# Test installation
echo "🧪 Testing installation..."
if python -c "import pefile; print('✅ pefile import successful!')"; then
    echo "✅ Installation verification passed!"
else
    echo "❌ Installation verification failed."
    exit 1
fi

# Test enhanced features
echo "🔍 Testing enhanced features..."
if python -c "
import sys
from pathlib import Path
sys.path.insert(0, str(Path('.').absolute()))
try:
    from pe_analyzer import PEAnalyzer
    analyzer = PEAnalyzer()
    analyzer.cleanup()
    print('✅ Enhanced features test passed!')
except Exception as e:
    print(f'❌ Enhanced features test failed: {e}')
    exit(1)
"; then
    echo "✅ Enhanced features are working!"
else
    echo "❌ Enhanced features test failed."
    exit 1
fi

echo
echo "====================================================="
echo "🎉 Enhanced Features Setup Complete!"
echo "====================================================="
echo
echo "To use the enhanced features, activate the virtual environment first:"
echo "  source venv/bin/activate"
echo
echo "Then run the analyzer:"
echo "  python der_private_key_analyzer.py /path/to/executable.exe"
echo
echo "The tool will now show enhanced output like:"
echo "  ✓ Found DER private key at offset 0x123456 (Section: .rdata)"
echo
echo "To deactivate the virtual environment when done:"
echo "  deactivate"
echo
