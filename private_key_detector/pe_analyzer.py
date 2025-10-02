#!/usr/bin/env python3
"""
PE file analyzer for the DER Private Key Analyzer.

This module handles the analysis of Windows PE (Portable Executable) files
to identify sections, resource tables, and other structural elements where
private keys might be embedded.
"""

import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class PESection:
    """Represents a PE section."""
    name: str
    virtual_address: int
    virtual_size: int
    raw_address: int
    raw_size: int
    characteristics: int


@dataclass
class PEResource:
    """Represents a PE resource."""
    type_name: str
    name: str
    language: str
    data_rva: int
    size: int
    codepage: int


@dataclass
class PELocation:
    """Represents the location of data within a PE file."""
    section_name: Optional[str] = None
    resource_type: Optional[str] = None
    resource_name: Optional[str] = None
    location_description: Optional[str] = None


class PEAnalyzer:
    """Analyzes PE files to identify structural elements and locations."""

    def __init__(self):
        """Initialize the PE analyzer."""
        self.pe = None
        self.sections = []
        self.resources = []

    def analyze_file(self, file_path: str) -> bool:
        """Analyze a PE file and extract structural information."""
        try:
            import pefile
            self.pe = pefile.PE(file_path)
            self._extract_sections()
            self._extract_resources()
            return True
        except ImportError:
            print("Warning: pefile library not available. Location tracking disabled.")
            print("Install with: pip install pefile")
            return False
        except Exception as e:
            print(f"Error analyzing PE file {file_path}: {e}")
            return False

    def _extract_sections(self) -> None:
        """Extract section information from the PE file."""
        self.sections = []

        if not self.pe:
            return

        for section in self.pe.sections:
            section_info = PESection(
                name=section.Name.decode('utf-8').rstrip('\x00'),
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_address=section.PointerToRawData,
                raw_size=section.SizeOfRawData,
                characteristics=section.Characteristics
            )
            self.sections.append(section_info)

    def _extract_resources(self) -> None:
        """Extract resource information from the PE file."""
        self.resources = []

        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return

        try:
            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                type_name = self._get_resource_type_name(resource_type.id)

                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                resource_info = PEResource(
                                    type_name=type_name,
                                    name=str(resource_id.id) if resource_id.id else "unnamed",
                                    language=str(resource_lang.id),
                                    data_rva=resource_lang.data.struct.OffsetToData,
                                    size=resource_lang.data.struct.Size,
                                    codepage=resource_lang.data.struct.CodePage
                                )
                                self.resources.append(resource_info)
        except Exception as e:
            print(f"Error extracting resources: {e}")

    def _get_resource_type_name(self, resource_type_id: int) -> str:
        """Get the name of a resource type by its ID."""
        resource_types = {
            1: "CURSOR",
            2: "BITMAP",
            3: "ICON",
            4: "MENU",
            5: "DIALOG",
            6: "STRING",
            7: "FONTDIR",
            8: "FONT",
            9: "ACCELERATOR",
            10: "RCDATA",
            11: "MESSAGETABLE",
            12: "GROUP_CURSOR",
            14: "GROUP_ICON",
            16: "VERSION",
            17: "DLGINCLUDE",
            19: "PLUGPLAY",
            20: "VXD",
            21: "ANICURSOR",
            22: "ANIICON",
            23: "HTML",
            24: "MANIFEST"
        }
        return resource_types.get(resource_type_id, f"TYPE_{resource_type_id}")

    def get_location_info(self, offset: int) -> PELocation:
        """Determine the location of data at a given offset."""
        location = PELocation()

        if not self.pe:
            return location

        # Check which section contains this offset
        for section in self.sections:
            if section.raw_address <= offset < section.raw_address + section.raw_size:
                location.section_name = section.name
                location.location_description = f"Section: {section.name}"
                break

        # Check if the offset is in a resource
        for resource in self.resources:
            if resource.data_rva <= offset < resource.data_rva + resource.size:
                location.resource_type = resource.type_name
                location.resource_name = resource.name
                location.location_description = f"Resource: {resource.type_name}/{resource.name}"
                break

        # If we found a resource, that takes precedence
        if location.resource_type:
            location.location_description = f"Resource: {location.resource_type}/{location.resource_name}"
        elif location.section_name:
            location.location_description = f"Section: {location.section_name}"
        else:
            location.location_description = f"Offset: 0x{offset:x}"

        return location

    def get_section_info(self, section_name: str) -> Optional[PESection]:
        """Get information about a specific section."""
        for section in self.sections:
            if section.name == section_name:
                return section
        return None

    def get_resource_info(self, resource_type: str, resource_name: str = None) -> List[PEResource]:
        """Get information about resources of a specific type."""
        matching_resources = []
        for resource in self.resources:
            if resource.type_name == resource_type:
                if resource_name is None or resource.name == resource_name:
                    matching_resources.append(resource)
        return matching_resources

    def cleanup(self) -> None:
        """Clean up the PE analyzer."""
        if self.pe:
            self.pe.close()
            self.pe = None
        self.sections = []
        self.resources = []
