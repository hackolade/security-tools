#!/usr/bin/env python3
"""
DER Private Key Analyzer - Modular Entry Point

This is the main entry point that imports and uses the modular components.
The original monolithic script has been split into focused modules:

- models.py: Data classes and types
- key_detector.py: Core key detection logic  
- key_extractor.py: Key extraction and file operations
- report_generator.py: Report generation
- cli.py: Command-line interface
- main.py: Main entry point

This file maintains backward compatibility while using the new modular structure.
"""

from main import main

if __name__ == "__main__":
    main()
