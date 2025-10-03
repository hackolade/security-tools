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
        all_results = self.detector.analyze_all_files_all_keys(file_paths)

        # Flatten results for compatibility with existing code
        results = []
        for file_path, keys in all_results.items():
            if keys:
                # Use the first key for compatibility with existing extraction logic
                results.append(keys[0])
            else:
                # Create empty result if no keys found
                from models import DERKeyAnalysis
                results.append(DERKeyAnalysis(
                    file_path=file_path,
                    file_size=0,
                    key_found=False,
                    key_offset=None,
                    key_length=0,
                    key_hash="",
                    public_key=""
                ))

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
                        key_data, result.file_path, result.key_hash, result
                    )
                    if saved_files:
                        print(f"    ✓ Saved markdown format: {os.path.basename(saved_files.get('md', ''))}")

        # Generate markdown report
        report = self.report_generator.generate_markdown_report(results, getattr(self.args, 'output', None))

        # Generate key summary report
        print("📊 Generating key summary reports...")
        summary_dir = self.reporting.generate_key_summary_report(all_results)
        print(f"📁 Key summary reports saved to: {summary_dir}")

        # Print analysis summary using reporting module
        print(f"\n{self.reporting.generate_analysis_summary(results)}")

        # Add verification summary
        print("\n" + "="*60)
        print("🔍 VERIFICATION: Key Distribution Analysis")
        print("="*60)
        self._verify_key_distribution(all_results)

        # Show extraction summary if keys were found
        if files_with_keys > 0:
            print(f"\n📁 Extracted keys saved to: {self.extractor.extracted_keys_dir}")
            print("💡 TIP: Read .md files for key information")

    def _verify_key_distribution(self, all_results):
        """Verify key distribution across all files."""
        import os

        # Collect all unique key hashes
        all_key_hashes = set()
        for file_path, keys in all_results.items():
            for key in keys:
                if key.key_found:
                    all_key_hashes.add(key.key_hash)

        all_key_hashes = sorted(list(all_key_hashes))

        key_count = len(all_key_hashes)
        key_word = "key" if key_count == 1 else "keys"
        print(f"📊 Found {key_count} distinct {key_word} across all files")
        print()

        # For each file, show which keys it contains
        for file_path, keys in all_results.items():
            file_name = os.path.basename(file_path)
            parent_folder = os.path.basename(os.path.dirname(file_path))
            display_name = f"{parent_folder}/{file_name}" if parent_folder else file_name

            found_hashes = [key.key_hash for key in keys if key.key_found]
            key_count = len(found_hashes)
            key_word = "key" if key_count == 1 else "keys"
            print(f"📁 {display_name}: {key_count} {key_word}")

            for key_hash in all_key_hashes:
                if key_hash in found_hashes:
                    matching_key = next(key for key in keys if key.key_hash == key_hash)
                    print(f"   ✅ {key_hash[:16]}... at 0x{matching_key.key_offset:x}")
                else:
                    print(f"   ❌ {key_hash[:16]}... NOT FOUND")
            print()

        # Show key distribution summary
        print("📈 Key Distribution Summary:")
        for key_hash in all_key_hashes:
            files_with_key = []
            for file_path, keys in all_results.items():
                if any(key.key_hash == key_hash for key in keys if key.key_found):
                    file_name = os.path.basename(file_path)
                    parent_folder = os.path.basename(os.path.dirname(file_path))
                    display_name = f"{parent_folder}/{file_name}" if parent_folder else file_name
                    files_with_key.append(display_name)

            file_count = len(files_with_key)
            file_word = "file" if file_count == 1 else "files"
            print(f"   🔑 {key_hash[:16]}...: Found in {file_count} {file_word}")
            if len(files_with_key) > 1:
                print(f"      Files: {', '.join(files_with_key)}")

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
