#!/usr/bin/env python3
"""
Main entry point for the DER Private Key Analyzer.

This module provides the main entry point for the application,
importing and coordinating all the modular components.
"""

import sys
import os
from cli import CLI


def main():
    """Main function for command-line usage."""
    try:
        cli = CLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
