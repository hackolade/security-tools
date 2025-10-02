# Private Key Detector

A security analysis tool for detecting embedded DER private keys in executable files.

## Overview

This tool analyzes Windows executable files to detect embedded DER-encoded private keys, which could represent a significant security risk when shared across multiple applications.

## Installation

### Basic Installation (Required)
The tool works out of the box with Python 3.6+ and no additional dependencies.

### Enhanced Location Tracking (Optional)
For enhanced location tracking that shows where keys are found in PE file sections (e.g., `.rdata`, resource tables), install the optional dependency:

#### Quick Installation
```bash
# Option 1: Direct installation (if your system allows it)
pip install pefile

# Option 2: User installation (recommended for most systems)
pip install --user pefile

# Option 3: Virtual environment (recommended for development)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install pefile
```

#### Automated Installation Scripts
We provide convenient installation scripts that handle different system configurations:

```bash
# Python script (handles multiple installation methods)
python3 install_enhanced_features.py

# Shell script (simple installation)
./install_enhanced.sh

# Virtual environment setup (isolated installation)
./setup_enhanced.sh

# Windows batch file (virtual environment setup)
setup_enhanced.bat
```

**Note**: The tool works perfectly without this dependency - you'll just get basic key detection without detailed location information.

## Quick Start

```bash
# Analyze single file (automatically extracts keys)
python der_private_key_analyzer.py /path/to/executable.exe

# Analyze multiple files (automatically detects shared keys and extracts)
python der_private_key_analyzer.py file1.exe file2.exe file3.exe

# List previously extracted keys
python der_private_key_analyzer.py --list-keys
```

## Command Line Options

- `files`: One or more executable files to analyze
- `--reference, -r`: Reference DER key file for comparison
- `--output, -o`: Output markdown report file (saved to `reports/` directory)
- `--list-keys, -l`: List previously extracted keys

## Key Detection

The tool automatically detects shared keys across multiple files by:

1. **Extracting DER keys** from each analyzed file
2. **Computing key hashes** for comparison
3. **Grouping identical keys** across files
4. **Identifying shared vulnerabilities** automatically

## Enhanced Location Tracking

When the `pefile` dependency is installed, the tool provides enhanced location tracking:

- **PE Section Detection**: Shows which section of the executable contains the key (e.g., `.rdata`, `.text`)
- **Resource Table Analysis**: Identifies if keys are embedded in resource tables
- **Detailed Location Reports**: Enhanced markdown reports with precise location information
- **Security Context**: Helps security analysts understand how keys are embedded

**Example output with location tracking:**
```
✓ Found DER private key at offset 0xad61fb0 (Section: .rdata)
```

**Example output without location tracking:**
```
✓ Found DER private key at offset 0xad61fb0
```

## Key Extraction

The tool extracts found private keys to markdown files:

- **Markdown format** (`.md`): Readable format with key information and PEM format
- **Automatic cleaning**: Previous extraction results are cleaned before new analysis
- **Fresh results**: Each analysis starts with a clean `extracted_keys/` directory

**Extraction directory**: `extracted_keys/` (automatically created and cleaned)
**Reports directory**: `reports/` (generated reports, not tracked by git)

**Reading extracted keys**:
```bash
# List all extracted keys
python der_private_key_analyzer.py --list-keys

# Read extracted keys (markdown format)
cat extracted_keys/*.md

# Read generated reports
cat reports/*.md
```

## Files

### Core Modules
- `der_private_key_analyzer.py` - Main entry point (backward compatible)
- `main.py` - Application entry point
- `models.py` - Data classes and types
- `key_detector.py` - Core key detection logic
- `key_extractor.py` - Key extraction and file operations
- `reporting.py` - Comprehensive reporting functionality
- `report_generator.py` - Report generation interface
- `cli.py` - Command-line interface

### Enhanced Features (Optional)
- `pe_analyzer.py` - PE file structure analysis for location tracking (requires `pefile`)

### Installation Scripts
- `install_enhanced_features.py` - Python script with multiple installation methods
- `install_enhanced.sh` - Shell script for simple installation
- `setup_enhanced.sh` - Virtual environment setup for Unix/Linux/macOS
- `setup_enhanced.bat` - Virtual environment setup for Windows
