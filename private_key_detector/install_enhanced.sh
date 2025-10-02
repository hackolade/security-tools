#!/bin/bash
# Enhanced Features Installation Script
# Installs pefile dependency for enhanced location tracking

echo "🔧 DER Private Key Analyzer - Enhanced Features Installer"
echo "============================================================"
echo

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 not found. Please install Python 3.6 or higher."
    exit 1
fi

# Check Python version
python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
required_version="3.6"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Error: Python 3.6 or higher is required."
    echo "   Current version: $python_version"
    exit 1
fi

echo "✅ Python version check passed: $python_version"

# Check if pip is available
if ! python3 -m pip --version &> /dev/null; then
    echo "❌ Error: pip not found. Please install pip first."
    echo "   Visit: https://pip.pypa.io/en/stable/installation/"
    exit 1
fi

echo "✅ pip is available"

# Install pefile
echo "📦 Installing pefile dependency..."
if python3 -m pip install pefile; then
    echo "✅ Successfully installed pefile!"
else
    echo "❌ Failed to install pefile."
    echo
    echo "💡 Troubleshooting tips:"
    echo "   - Try running: python3 -m pip install --upgrade pip"
    echo "   - Check your internet connection"
    echo "   - Try running with sudo (Linux/Mac)"
    exit 1
fi

# Test installation
echo "🧪 Testing installation..."
if python3 -c "import pefile; print('✅ pefile import successful!')"; then
    echo "✅ Installation verification passed!"
else
    echo "❌ Installation verification failed."
    exit 1
fi

# Test enhanced features
echo "🔍 Testing enhanced features..."
if python3 -c "
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
echo "============================================================"
echo "🎉 Enhanced Features Installation Complete!"
echo "============================================================"
echo
echo "You can now use the DER Private Key Analyzer with enhanced location tracking:"
echo
echo "  📍 Location tracking will show which PE section contains keys"
echo "  📊 Enhanced reports will include detailed location information"
echo "  🔍 Resource table analysis for embedded secrets"
echo
echo "Example usage:"
echo "  python3 der_private_key_analyzer.py /path/to/executable.exe"
echo "  python3 der_private_key_analyzer.py file1.exe file2.exe --output analysis.md"
echo
echo "The tool will now show output like:"
echo "  ✓ Found DER private key at offset 0x123456 (Section: .rdata)"
echo
