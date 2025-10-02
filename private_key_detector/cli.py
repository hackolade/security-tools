#!/usr/bin/env python3
"""
Command-line interface for the DER Private Key Analyzer.

This module handles command-line argument parsing and user interface
for the analyzer application.
"""

import argparse
import sys
import os
from typing import List
from key_detector import KeyDetector
from key_extractor import KeyExtractor
from report_generator import ReportGenerator
from reporting import Reporting


class CLI:
    """Command-line interface for the DER Private Key Analyzer."""

    def __init__(self):
        """Initialize the CLI."""
        self.detector = KeyDetector()
        self.extractor = KeyExtractor()
        self.report_generator = ReportGenerator()
        self.reporting = Reporting()

    def parse_arguments(self) -> argparse.Namespace:
        """Parse command-line arguments."""
        parser = argparse.ArgumentParser(description='Analyze DER private keys in executable files')
        parser.add_argument('files', nargs='*', help='Executable files to analyze')
        parser.add_argument('--reference', '-r', help='Reference DER key file')
        parser.add_argument('--output', '-o', help='Output markdown report file')
        parser.add_argument('--list-keys', '-l', action='store_true', help='List previously extracted keys')

        return parser.parse_args()

    def handle_list_keys(self) -> None:
        """Handle the --list-keys option."""
        summary = self.extractor.generate_extraction_summary()
        print(summary)

    def analyze_files(self, file_paths: List[str]) -> None:
        """Analyze files and extract keys."""
        if not file_paths:
            print("Error: No files provided for analysis.")
            print("Use --help for usage information.")
            return

        # Load reference key if provided
        if hasattr(self, 'args') and self.args.reference:
            if not self.detector.load_reference_key(self.args.reference):
                print("Error: Could not load reference key")
                sys.exit(1)
            print("✓ Reference key loaded. Will compare against reference.")
        else:
            print("ℹ️  No reference key provided. Will detect shared keys by comparing files.")

        # Clean previous extraction results
        self.extractor.clean_extracted_keys()

        # Analyze files
        print("Starting analysis...")
        results = self.detector.analyze_multiple_files(file_paths)

        # Extract keys for files that have them
        files_with_keys = 0
        for result in results:
            if result.key_found:
                files_with_keys += 1
                print(f"  📁 Extracting key to local files...")
                key_data = self.extractor.extract_key_from_file(
                    result.file_path, result.key_offset, result.key_length
                )
                if key_data:
                    saved_files = self.extractor.save_extracted_key(
                        key_data, result.file_path, result.key_hash
                    )
                    if saved_files:
                        print(f"    ✓ Saved markdown format: {os.path.basename(saved_files.get('md', ''))}")

        # Generate markdown report
        report = self.report_generator.generate_markdown_report(results, getattr(self.args, 'output', None))

        # Print analysis summary using reporting module
        print(f"\n{self.reporting.generate_analysis_summary(results)}")

        # Show extraction summary if keys were found
        if files_with_keys > 0:
            print(f"\n📁 Extracted keys saved to: {self.extractor.extracted_keys_dir}")
            print("💡 TIP: Read .md files for key information")

            # Show list of extracted keys
            print("\n📋 EXTRACTED KEYS:")
            summary = self.extractor.generate_extraction_summary()
            print(summary)

    def run(self) -> None:
        """Run the CLI application."""
        self.args = self.parse_arguments()

        # Handle list keys option
        if self.args.list_keys:
            self.handle_list_keys()
            return

        # Check if files are provided
        if not self.args.files:
            print("Error: No files provided for analysis.")
            print("Use --help for usage information.")
            return

        # Analyze files
        self.analyze_files(self.args.files)
