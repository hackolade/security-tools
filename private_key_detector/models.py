#!/usr/bin/env python3
"""
Data models and types for the DER Private Key Analyzer.

This module contains all data classes and type definitions used throughout
the analyzer application.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class DERKeyAnalysis:
    """Data class for DER key analysis results."""
    file_path: str
    file_size: int
    key_found: bool
    key_offset: Optional[int]
    key_length: int
    key_hash: str
    public_key: str
    matches_reference: bool = False
    # Location tracking fields
    section_name: Optional[str] = None
    resource_type: Optional[str] = None
    resource_name: Optional[str] = None
    location_description: Optional[str] = None
    # Detailed key information fields
    key_type: Optional[str] = None
    algorithm_name: Optional[str] = None
    curve_name: Optional[str] = None
    key_size: Optional[str] = None
    security_level: Optional[str] = None
    usage: Optional[str] = None
    key_id: Optional[str] = None
    private_key_hex: Optional[str] = None
