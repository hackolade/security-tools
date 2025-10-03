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


class KeyDetector:
    """Handles detection of embedded DER private keys in executable files."""

    def __init__(self):
        """Initialize the key detector."""
        self.reference_key: Optional[bytes] = None

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

    def _extract_detailed_key_info(self, der_data: bytes) -> Dict[str, str]:
        """Extract detailed human-readable information about the key."""
        info = {
            'key_type': 'Unknown',
            'algorithm_name': 'Unknown',
            'curve_name': 'Unknown',
            'key_size': 'Unknown',
            'security_level': 'Unknown',
            'usage': 'Unknown',
            'format': 'Unknown',
            'public_key_hex': '',
            'private_key_hex': '',
            'key_id': '',
            'creation_info': 'Unknown'
        }

        try:
            if len(der_data) < 10:
                return info

            # Basic DER structure analysis
            info['format'] = 'DER-encoded'

            # Check for ECDSA algorithm
            if b'\x2a\x86\x48\xce\x3d' in der_data:
                info['algorithm_name'] = 'Elliptic Curve Digital Signature Algorithm (ECDSA)'
                info['key_type'] = 'ECDSA Private Key'

            # Check for P-256 curve
            if b'\x2a\x86\x48\xce\x3d\x03\x01\x07' in der_data:
                info['curve_name'] = 'P-256 (secp256r1)'
                info['key_size'] = '256 bits'
                info['security_level'] = 'High (128-bit equivalent)'

            # Extract public key portion
            if len(der_data) > 100:
                public_key_data = der_data[-65:]
                info['public_key_hex'] = public_key_data.hex()

            # Extract private key portion (middle section typically)
            if len(der_data) > 50:
                # Private key is usually in the middle section
                private_start = len(der_data) // 3
                private_end = private_start + 32
                if private_end < len(der_data):
                    private_key_data = der_data[private_start:private_end]
                    info['private_key_hex'] = private_key_data.hex()

            # Generate a short key ID
            if info['public_key_hex']:
                key_id = hashlib.sha256(info['public_key_hex'].encode()).hexdigest()[:16]
                info['key_id'] = f"Key-{key_id}"

            # Determine usage based on context
            info['usage'] = 'Digital Signature and Authentication'
            info['creation_info'] = 'Embedded in executable file'

        except Exception as e:
            info['creation_info'] = f'Analysis error: {str(e)}'

        return info

    def _analyze_der_structure(self, der_data: bytes) -> Dict[str, any]:
        """Analyze DER structure to extract key information."""
        analysis = {
            'is_valid_der': False,
            'algorithm': 'Unknown',
            'curve': 'Unknown',
            'key_length': len(der_data),
            'is_certificate': False,
            'is_private_key': False
        }

        try:
            if len(der_data) < 6:
                return analysis

            # Check for DER sequence tag
            if der_data[0] == 0x30:
                analysis['is_valid_der'] = True

            # Check for certificate OIDs (these indicate X.509 certificates)
            certificate_oids = [
                b'\x06\x03\x55\x04\x03',  # Common Name (2.5.4.3)
                b'\x06\x03\x55\x04\x06',  # Country (2.5.4.6)
                b'\x06\x03\x55\x04\x08',  # State (2.5.4.8)
                b'\x06\x03\x55\x04\x07',  # Locality (2.5.4.7)
                b'\x06\x03\x55\x04\x0a',  # Organization (2.5.4.10)
                b'\x06\x03\x55\x04\x0b',  # Organizational Unit (2.5.4.11)
            ]

            # Check for certificate-specific patterns
            has_certificate_oids = any(oid in der_data for oid in certificate_oids)

            # Check for certificate text patterns
            certificate_text_patterns = [
                b'CERTIFICATE',
                b'TRUST',
                b'CA',
                b'ROOT',
                b'INTERMEDIATE',
                b'AUTHORITY'
            ]

            has_certificate_text = any(pattern in der_data for pattern in certificate_text_patterns)

            # If it has certificate OIDs or text, it's likely a certificate
            if has_certificate_oids or has_certificate_text:
                analysis['is_certificate'] = True
                return analysis  # Don't analyze further if it's a certificate

            # Check for ECDSA algorithm OID
            if b'\x2a\x86\x48\xce\x3d' in der_data:
                analysis['algorithm'] = 'ECDSA'

            # Check for P-256 curve OID
            if b'\x2a\x86\x48\xce\x3d\x03\x01\x07' in der_data:
                analysis['curve'] = 'P-256'

            # If it has ECDSA and P-256 OIDs but no certificate patterns, it's likely a private key
            if analysis['algorithm'] == 'ECDSA' and analysis['curve'] == 'P-256':
                analysis['is_private_key'] = True

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

        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            # Look for DER private key patterns
            der_patterns = [
                b'\x30\x81',  # DER sequence with short length
                b'\x30\x82',  # DER sequence with long length
                b'\x30\x80',  # DER sequence with indefinite length
            ]

            # Search for P-256 ECDSA private keys (certificates are filtered out)
            for pattern in der_patterns:
                offset = 0
                while True:
                    offset = content.find(pattern, offset)
                    if offset == -1:
                        break

                    # Try to extract DER data starting from this offset
                    # Try different lengths to find the complete key
                    for length in [200, 180, 160, 140, 120, 100]:
                        if offset + length > len(content):
                            break

                        der_data = content[offset:offset + length]

                        # Analyze DER structure
                        analysis = self._analyze_der_structure(der_data)

                        # Only accept if it's a valid DER private key (not a certificate)
                        if (analysis['is_valid_der'] and
                            analysis['is_private_key'] and
                            not analysis['is_certificate'] and
                            analysis['algorithm'] == 'ECDSA' and
                            analysis['curve'] == 'P-256'):
                            # Calculate hash of the key data
                            key_hash = hashlib.sha256(der_data).hexdigest()

                            # Extract public key
                            public_key = self._extract_public_key(der_data)

                            # Extract detailed key information
                            detailed_info = self._extract_detailed_key_info(der_data)

                            result.key_found = True
                            result.key_offset = offset
                            result.key_length = length
                            result.key_hash = key_hash
                            result.public_key = public_key
                            result.key_type = detailed_info['key_type']
                            result.algorithm_name = detailed_info['algorithm_name']
                            result.curve_name = detailed_info['curve_name']
                            result.key_size = detailed_info['key_size']
                            result.security_level = detailed_info['security_level']
                            result.usage = detailed_info['usage']
                            result.key_id = detailed_info['key_id']
                            result.private_key_hex = detailed_info['private_key_hex']

                            # Check if it matches reference key
                            if self.reference_key and der_data == self.reference_key:
                                result.matches_reference = True

                            print(f"  ⚠️ Found DER private key at offset 0x{offset:x}")
                            break

                    if result.key_found:
                        break

                    offset += 1

            if not result.key_found:
                print(f"  ✗ No matching DER private key found")

        except Exception as e:
            print(f"  ✗ Error analyzing file: {e}")

        return result

    def analyze_file_all_keys(self, file_path: str) -> List[DERKeyAnalysis]:
        """Analyze a file and return ALL private keys found, not just the first one."""
        all_keys = []

        if not os.path.exists(file_path):
            print(f"Error: File not found: {file_path}")
            return all_keys

        file_size = os.path.getsize(file_path)
        print(f"Analyzing: {file_path}")

        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            # Look for DER private key patterns
            der_patterns = [
                b'\x30\x81',  # DER sequence with short length
                b'\x30\x82',  # DER sequence with long length
                b'\x30\x80',  # DER sequence with indefinite length
            ]

            # Search for all keys
            for pattern in der_patterns:
                offset = 0
                while True:
                    offset = content.find(pattern, offset)
                    if offset == -1:
                        break

                    # Try to extract DER data starting from this offset
                    for length in [200, 180, 160, 140, 120, 100]:
                        if offset + length > len(content):
                            break

                        der_data = content[offset:offset + length]

                        # Analyze DER structure
                        analysis = self._analyze_der_structure(der_data)

                        # Only accept if it's a valid DER private key (not a certificate)
                        if (analysis['is_valid_der'] and
                            analysis['is_private_key'] and
                            not analysis['is_certificate'] and
                            analysis['algorithm'] == 'ECDSA' and
                            analysis['curve'] == 'P-256'):
                            # Calculate hash of the key data
                            key_hash = hashlib.sha256(der_data).hexdigest()

                            # Extract public key
                            public_key = self._extract_public_key(der_data)

                            # Extract detailed key information
                            detailed_info = self._extract_detailed_key_info(der_data)

                            # Create result for this key
                            key_result = DERKeyAnalysis(
                                file_path=file_path,
                                file_size=file_size,
                                key_found=True,
                                key_offset=offset,
                                key_length=length,
                                key_hash=key_hash,
                                public_key=public_key,
                                key_type=detailed_info['key_type'],
                                algorithm_name=detailed_info['algorithm_name'],
                                curve_name=detailed_info['curve_name'],
                                key_size=detailed_info['key_size'],
                                security_level=detailed_info['security_level'],
                                usage=detailed_info['usage'],
                                key_id=detailed_info['key_id'],
                                private_key_hex=detailed_info['private_key_hex']
                            )

                            # Add PE analysis if available
                            pe_analysis_success = False
                            if hasattr(self, 'pe_analyzer') and self.pe_analyzer:
                                pe_analysis_success = self.pe_analyzer.analyze_file(file_path)

                            if pe_analysis_success:
                                location_info = self.pe_analyzer.get_location_info(offset)
                                key_result.section_name = location_info.section_name
                                key_result.resource_type = location_info.resource_type
                                key_result.resource_name = location_info.resource_name
                                key_result.location_description = location_info.location_description

                            all_keys.append(key_result)
                            print(f"  ⚠️ Found DER private key at offset 0x{offset:x} (hash: {key_hash[:16]}...)")
                            break

                    offset += 1

        except Exception as e:
            print(f"Error analyzing file {file_path}: {e}")
        finally:
            if hasattr(self, 'pe_analyzer') and self.pe_analyzer:
                self.pe_analyzer.cleanup()

        return all_keys

    def analyze_all_files_all_keys(self, file_paths: List[str]) -> Dict[str, List[DERKeyAnalysis]]:
        """Analyze all files and return ALL keys found, grouped by file."""
        all_results = {}

        for file_path in file_paths:
            all_keys = self.analyze_file_all_keys(file_path)
            all_results[file_path] = all_keys

        # Find shared keys across all files
        self._detect_shared_keys_all(all_results)

        return all_results

    def _detect_shared_keys_all(self, all_results: Dict[str, List[DERKeyAnalysis]]):
        """Detect shared keys across all files and all keys."""
        # Collect all keys from all files
        all_keys = []
        for file_path, keys in all_results.items():
            for key in keys:
                all_keys.append(key)

        # Group keys by hash
        key_groups = {}
        for key in all_keys:
            if key.key_hash not in key_groups:
                key_groups[key.key_hash] = []
            key_groups[key.key_hash].append(key)

        # Report shared keys
        for key_hash, group in key_groups.items():
            if len(group) > 1:
                print()
                key_count = len(group)
                key_word = "key" if key_count == 1 else "keys"
                print(f"Found {key_count} shared {key_word} with hash {key_hash[:16]}...")
                print("Files sharing this key:")
                for key in group:
                    print(f"  - {key.file_path} (offset: 0x{key.key_offset:x})")
                    key.matches_reference = True

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
                print()
                key_count = len(group)
                key_word = "key" if key_count == 1 else "keys"
                print(f"Found {key_count} shared {key_word} with hash {key_hash[:16]}...")
                print("Files sharing this key:")
                for result in group:
                    print(f"  - {result.file_path}")
                    result.matches_reference = True
