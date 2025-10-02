#!/usr/bin/env python3
"""
Key extraction and file operations for the DER Private Key Analyzer.

This module handles the extraction of found private keys to local files.
"""

import os
from pathlib import Path
from typing import Dict
from reporting import Reporting


class KeyExtractor:
    """Handles extraction of found private keys to local files."""

    def __init__(self):
        """Initialize the key extractor."""
        self.extracted_keys_dir = Path("extracted_keys")
        self.extracted_keys_dir.mkdir(exist_ok=True)
        self.reporting = Reporting(self.extracted_keys_dir)

    def clean_extracted_keys(self) -> None:
        """Clean the extracted keys directory before new analysis."""
        if self.extracted_keys_dir.exists():
            import shutil
            shutil.rmtree(self.extracted_keys_dir)
            print("🧹 Cleaned previous extraction results")

        # Recreate the directory
        self.extracted_keys_dir.mkdir(exist_ok=True)

    def extract_key_from_file(self, file_path: str, offset: int, length: int) -> bytes:
        """Extract key data from a file at the specified offset."""
        try:
            with open(file_path, 'rb') as f:
                f.seek(offset)
                return f.read(length)
        except Exception as e:
            print(f"Error extracting key from {file_path}: {e}")
            return b""

    def save_extracted_key(self, key_data: bytes, file_path: str, key_hash: str, analysis_result=None) -> Dict[str, str]:
        """Save extracted key in markdown format."""
        if not key_data:
            return {}

        # Create safe filename with parent directory
        import os
        file_name = os.path.basename(file_path)
        parent_dir = os.path.basename(os.path.dirname(file_path))

        # Create unique identifier: parent_dir_filename_hash
        if parent_dir and parent_dir != '.':
            safe_filename = f"{parent_dir}_{file_name}"
        else:
            safe_filename = file_name

        safe_filename = "".join(c for c in safe_filename if c.isalnum() or c in ('-', '_', '.')).rstrip()
        key_hash_short = key_hash[:8]

        saved_files = {}

        try:
            # Save only markdown format
            md_file = self.extracted_keys_dir / f"{safe_filename}_{key_hash_short}.md"
            md_content = self.reporting.generate_key_markdown(key_data, file_path, key_hash, analysis_result)
            with open(md_file, 'w') as f:
                f.write(md_content)
            saved_files['md'] = str(md_file)

        except Exception as e:
            print(f"Error saving extracted key: {e}")

        return saved_files

    def list_extracted_keys(self):
        """List all extracted keys with their metadata."""
        return self.reporting.list_extracted_keys()

    def generate_extraction_summary(self) -> str:
        """Generate a summary of extracted keys."""
        return self.reporting.generate_extraction_summary()
