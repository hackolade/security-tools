#!/usr/bin/env python3
"""
Enhanced Features Installation Script

This script installs the optional pefile dependency to enable enhanced location tracking
in the DER Private Key Analyzer. It handles different Python environments and provides
clear feedback about the installation process.
"""

import sys
import subprocess
import os
from pathlib import Path


def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 6):
        print("❌ Error: Python 3.6 or higher is required.")
        print(f"   Current version: {sys.version}")
        return False
    return True


def check_pip_available():
    """Check if pip is available."""
    try:
        import pip
        return True
    except ImportError:
        try:
            subprocess.run([sys.executable, "-m", "pip", "--version"],
                          capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False


def install_pefile():
    """Install pefile using pip."""
    print("📦 Installing pefile dependency...")

    # Try different installation methods
    installation_methods = [
        # Method 1: Standard installation
        ([sys.executable, "-m", "pip", "install", "pefile"], "Standard installation"),
        # Method 2: User installation
        ([sys.executable, "-m", "pip", "install", "--user", "pefile"], "User installation"),
        # Method 3: With break-system-packages flag
        ([sys.executable, "-m", "pip", "install", "--break-system-packages", "pefile"], "System packages override")
    ]

    for cmd, method_name in installation_methods:
        try:
            print(f"   Trying {method_name}...")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"✅ Successfully installed pefile using {method_name}!")
            return True

        except subprocess.CalledProcessError as e:
            if "externally-managed-environment" in e.stderr:
                print(f"   {method_name} failed: externally managed environment")
                continue
            else:
                print(f"   {method_name} failed: {e.stderr}")
                continue
        except FileNotFoundError:
            print("❌ pip not found. Please install pip first.")
            return False

    # If all methods failed, provide guidance
    print("❌ All installation methods failed.")
    print("\n💡 Alternative solutions:")
    print("   1. Create a virtual environment:")
    print("      python3 -m venv venv")
    print("      source venv/bin/activate  # On Windows: venv\\Scripts\\activate")
    print("      pip install pefile")
    print()
    print("   2. Use pipx (recommended for applications):")
    print("      brew install pipx  # On macOS")
    print("      pipx install pefile")
    print()
    print("   3. Use system package manager:")
    print("      # On Ubuntu/Debian: sudo apt install python3-pefile")
    print("      # On macOS: brew install python-pefile")
    return False


def test_installation():
    """Test if pefile can be imported after installation."""
    print("🧪 Testing installation...")

    try:
        import pefile
        print("✅ pefile import successful!")
        print(f"   Version: {pefile.__version__}")
        return True
    except ImportError as e:
        print(f"❌ pefile import failed: {e}")
        return False


def test_enhanced_features():
    """Test if enhanced features work with the installed pefile."""
    print("🔍 Testing enhanced features...")

    try:
        # Test importing the PE analyzer
        sys.path.insert(0, str(Path(__file__).parent))
        from pe_analyzer import PEAnalyzer

        # Test basic PE analyzer functionality
        analyzer = PEAnalyzer()
        print("✅ PE analyzer imported successfully!")

        # Clean up
        analyzer.cleanup()
        return True

    except ImportError as e:
        print(f"❌ Enhanced features test failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error during testing: {e}")
        return False


def show_usage_instructions():
    """Show instructions for using enhanced features."""
    print("\n" + "="*60)
    print("🎉 Enhanced Features Installation Complete!")
    print("="*60)
    print()
    print("You can now use the DER Private Key Analyzer with enhanced location tracking:")
    print()
    print("  📍 Location tracking will show which PE section contains keys")
    print("  📊 Enhanced reports will include detailed location information")
    print("  🔍 Resource table analysis for embedded secrets")
    print()
    print("Example usage:")
    print("  python der_private_key_analyzer.py /path/to/executable.exe")
    print("  python der_private_key_analyzer.py file1.exe file2.exe --output analysis.md")
    print()
    print("The tool will now show output like:")
    print("  ✓ Found DER private key at offset 0x123456 (Section: .rdata)")
    print()


def main():
    """Main installation process."""
    print("🔧 DER Private Key Analyzer - Enhanced Features Installer")
    print("="*60)
    print()

    # Check Python version
    if not check_python_version():
        sys.exit(1)

    # Check if pip is available
    if not check_pip_available():
        print("❌ pip is not available. Please install pip first.")
        print("   Visit: https://pip.pypa.io/en/stable/installation/")
        sys.exit(1)

    # Install pefile
    if not install_pefile():
        print("\n💡 Troubleshooting tips:")
        print("   - Try running: python -m pip install --upgrade pip")
        print("   - Check your internet connection")
        print("   - Try running as administrator (Windows) or with sudo (Linux/Mac)")
        sys.exit(1)

    # Test the installation
    if not test_installation():
        print("❌ Installation verification failed.")
        sys.exit(1)

    # Test enhanced features
    if not test_enhanced_features():
        print("❌ Enhanced features test failed.")
        print("   The pefile library is installed but the analyzer integration failed.")
        sys.exit(1)

    # Show usage instructions
    show_usage_instructions()


if __name__ == "__main__":
    main()
