#!/usr/bin/env python3
"""
Core key detection logic for the DER Private Key Analyzer.

This module handles the detection of embedded DER private keys in executable files,
including pattern matching, ASN.1 structure analysis, and key comparison.
"""

import os
import hashlib
from typing import List, Dict, Optional
from models import DERKeyAnalysis

# Optional PE analysis - only import if available
try:
    from pe_analyzer import PEAnalyzer
    PE_ANALYSIS_AVAILABLE = True
except ImportError:
    PE_ANALYSIS_AVAILABLE = False
    PEAnalyzer = None


class KeyDetector:
    """Handles detection of embedded DER private keys in executable files."""

    def __init__(self):
        """Initialize the key detector."""
        self.reference_key: Optional[bytes] = None
        if PE_ANALYSIS_AVAILABLE:
            self.pe_analyzer = PEAnalyzer()
        else:
            self.pe_analyzer = None

    def load_reference_key(self, file_path: str) -> bool:
        """Load a reference DER key for comparison."""
        try:
            with open(file_path, 'rb') as f:
                self.reference_key = f.read()
            return True
        except Exception as e:
            print(f"Error loading reference key: {e}")
            return False

    def _extract_public_key(self, der_data: bytes) -> str:
        """Extract public key from DER private key data."""
        try:
            # Simple extraction of public key from DER structure
            # This is a simplified implementation
            if len(der_data) > 100:
                # Extract the public key portion (last 65 bytes for P-256)
                public_key_data = der_data[-65:]
                return public_key_data.hex()
            return ""
        except:
            return ""

    def _analyze_der_structure(self, der_data: bytes) -> Dict[str, any]:
        """Analyze DER structure to extract key information."""
        analysis = {
            'is_valid_der': False,
            'algorithm': 'Unknown',
            'curve': 'Unknown',
            'key_length': len(der_data)
        }

        try:
            if len(der_data) < 6:
                return analysis

            # Check for DER sequence tag
            if der_data[0] == 0x30:
                analysis['is_valid_der'] = True

            # Check for ECDSA algorithm OID
            if b'\x2a\x86\x48\xce\x3d' in der_data:
                analysis['algorithm'] = 'ECDSA'

            # Check for P-256 curve OID
            if b'\x2a\x86\x48\xce\x3d\x03\x01\x07' in der_data:
                analysis['curve'] = 'P-256'

        except Exception:
            pass

        return analysis

    def analyze_file(self, file_path: str) -> DERKeyAnalysis:
        """Analyze a single file for embedded DER private keys."""
        file_size = os.path.getsize(file_path)
        result = DERKeyAnalysis(
            file_path=file_path,
            file_size=file_size,
            key_found=False,
            key_offset=None,
            key_length=0,
            key_hash="",
            public_key=""
        )

        # Try to analyze as PE file for location information (if PE analysis is available)
        pe_analysis_success = False
        if self.pe_analyzer:
            pe_analysis_success = self.pe_analyzer.analyze_file(file_path)

        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            # Look for DER private key patterns
            der_patterns = [
                b'\x30\x82',  # DER sequence with length
                b'\x30\x81',  # DER sequence with short length
                b'\x30\x80',  # DER sequence with indefinite length
            ]

            for pattern in der_patterns:
                offset = 0
                while True:
                    offset = content.find(pattern, offset)
                    if offset == -1:
                        break

                    # Try to extract DER data starting from this offset
                    for length in [100, 120, 140, 160, 180, 200]:
                        if offset + length > len(content):
                            break

                        der_data = content[offset:offset + length]

                        # Analyze DER structure
                        analysis = self._analyze_der_structure(der_data)

                        if analysis['is_valid_der'] and analysis['algorithm'] == 'ECDSA':
                            # Calculate hash of the key data
                            key_hash = hashlib.sha256(der_data).hexdigest()

                            # Extract public key
                            public_key = self._extract_public_key(der_data)

                            result.key_found = True
                            result.key_offset = offset
                            result.key_length = length
                            result.key_hash = key_hash
                            result.public_key = public_key

                            # Get location information if PE analysis was successful
                            if pe_analysis_success:
                                location_info = self.pe_analyzer.get_location_info(offset)
                                result.section_name = location_info.section_name
                                result.resource_type = location_info.resource_type
                                result.resource_name = location_info.resource_name
                                result.location_description = location_info.location_description

                            # Check if it matches reference key
                            if self.reference_key and der_data == self.reference_key:
                                result.matches_reference = True

                            location_msg = f" at offset 0x{offset:x}"
                            if result.location_description:
                                location_msg += f" ({result.location_description})"
                            print(f"  ✓ Found DER private key{location_msg}")
                            break

                    if result.key_found:
                        break

                    offset += 1

            if not result.key_found:
                print(f"  ✗ No matching DER private key found")

        except Exception as e:
            print(f"  ✗ Error analyzing file: {e}")
        finally:
            # Clean up PE analyzer (if available)
            if self.pe_analyzer:
                self.pe_analyzer.cleanup()

        return result

    def analyze_multiple_files(self, file_paths: List[str]) -> List[DERKeyAnalysis]:
        """Analyze multiple files for embedded DER private keys."""
        results = []

        for file_path in file_paths:
            print(f"Analyzing: {file_path}")
            result = self.analyze_file(file_path)
            results.append(result)

        # Detect shared keys across files
        self._detect_shared_keys(results)

        return results

    def _detect_shared_keys(self, results: List[DERKeyAnalysis]) -> None:
        """Detect shared keys across multiple files."""
        key_groups = {}

        # Group results by key hash
        for result in results:
            if result.key_found:
                if result.key_hash not in key_groups:
                    key_groups[result.key_hash] = []
                key_groups[result.key_hash].append(result)

        # Mark shared keys
        for key_hash, group in key_groups.items():
            if len(group) > 1:
                print(f"✓ Found {len(group)} shared key(s) with hash {key_hash[:16]}...")
                for result in group:
                    result.matches_reference = True
