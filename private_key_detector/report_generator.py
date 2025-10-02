#!/usr/bin/env python3
"""
Report generation for the DER Private Key Analyzer.

This module provides a simple interface to the comprehensive reporting module.
"""

from typing import List, Optional
from models import DERKeyAnalysis
from reporting import Reporting


class ReportGenerator:
    """Handles generation of security reports and analysis summaries."""

    def __init__(self):
        """Initialize the report generator."""
        self.reporting = Reporting()

    def generate_markdown_report(self, results: List[DERKeyAnalysis], output_file: Optional[str] = None, reference_key: Optional[bytes] = None) -> str:
        """Generate a markdown security report."""
        return self.reporting.generate_markdown_report(results, output_file, reference_key)
