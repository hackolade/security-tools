# Private Key Detector

A security analysis tool for detecting embedded DER private keys in executable files.

## Overview

This tool analyzes Windows executable files to detect embedded DER-encoded private keys, which could represent a significant security risk when shared across multiple applications.

## 🚀 Dependency-Free Toolbox

This toolbox is designed to be **completely dependency-free** and requires no external Python packages to run. All functionality is implemented using only Python's standard library, making it:

- **Easy to deploy**: No pip installs or virtual environments required
- **Portable**: Works on any system with Python 3.6+
- **Reliable**: No dependency conflicts or version issues
- **Fast setup**: Download and run immediately

The tool uses only built-in Python modules for:
- Binary file analysis and pattern matching
- Cryptographic hash computation (SHA-256)
- DER structure parsing and ASN.1 analysis
- Markdown report generation
- File operations and key extraction

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
- `--output, -o`: Output markdown report file
- `--list-keys, -l`: List previously extracted keys

## Key Detection

The tool automatically detects shared keys across multiple files by:

1. **Extracting DER keys** from each analyzed file
2. **Computing key hashes** for comparison
3. **Grouping identical keys** across files
4. **Identifying shared vulnerabilities** automatically

## Key Extraction

The tool extracts found private keys to markdown files:

- **Markdown format** (`.md`): Readable format with key information and PEM format
- **Automatic cleaning**: Previous extraction results are cleaned before new analysis
- **Fresh results**: Each analysis starts with a clean `extracted_keys/` directory

**Extraction directory**: `extracted_keys/` (automatically created and cleaned)

**Reading extracted keys**:
```bash
# List all extracted keys
python der_private_key_analyzer.py --list-keys

# Read extracted keys (markdown format)
cat extracted_keys/*.md
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
