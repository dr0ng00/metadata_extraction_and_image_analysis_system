"""ExifTool-style metadata formatter.

Provides aligned text formatting for forensic metadata reports,
mimicking the output of the ExifTool utility.
"""
from typing import Any, Dict, List
import os

class ExifToolStyleFormatter:
    """Formats metadata dictionaries into aligned ExifTool-style text."""

    # Map internal keys to professional ExifTool-style names
    DISPLAY_MAPPING = {
        'width': 'Image Width',
        'height': 'Image Height',
        'format': 'File Type',
        'size': 'Image Size',
        'datetime_original': 'Date/Time Original',
        'camera_make': 'Camera Make',
        'camera_model': 'Camera Model',
        'software': 'Software',
        'size_bytes': 'File Size (Bytes)',
        'mime_type': 'MIME Type',
        'Profile Size': 'ICC Profile Size',
        # C2PA Mappings
        'JUMD Label': 'JUMD Label',
        'JUMD Type': 'JUMD Type',
        'Validation Results Active Manifest Success Code': 'Validation Results Active Manifest Success Code',
        'Actions Software Agent Name': 'Actions Software Agent Name',
        # GPS Location Mappings
        'location_name': 'GPS Location',
        'city': 'GPS City',
        'state': 'GPS State/Region',
        'country': 'GPS Country',
        'country_code': 'GPS Country Code',
        'latitude': 'GPS Latitude',
        'longitude': 'GPS Longitude',
        'coordinates': 'GPS Coordinates',
        'full_address': 'GPS Full Address'
    }

    @staticmethod
    def format(metadata: Dict[str, Any]) -> str:
        """
        Produce an aligned text report from metadata.
        
        Args:
            metadata: Nested or flat metadata dictionary.
            
        Returns:
            Formatted text string.
        """
        # 1. Flatten the metadata for easier display
        flat_metadata = ExifToolStyleFormatter._flatten_metadata(metadata)
        
        # Use the flattened metadata directly
        final_data = flat_metadata

        # 2. Calculate max key length for alignment
        if not final_data:
            return "No metadata available."
            
        max_key_len = max(len(str(k)) for k in final_data.keys())
        # Add some padding
        max_key_len = min(max(max_key_len + 2, 32), 40) 

        lines = []
        for key, value in final_data.items():
            # Skip internal keys 
            if key in ['absolute_path']:
                continue
                
            val_str = str(value)
            # Handle list/dict values by joining them
            if isinstance(value, (list, tuple)):
                val_str = ", ".join(map(str, value))
            elif isinstance(value, dict):
                val_str = str(value)
                
            line = f"{str(key):<{max_key_len}} : {val_str}"
            lines.append(line)

        return "\n".join(lines)

    @staticmethod
    def _flatten_metadata(metadata: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        """Recursively flatten a nested dictionary with professional naming."""
        items = {}
        for k, v in metadata.items():
            if v == "ABSENT":
                continue
                
            # Get professional name from mapping or stick with existing
            display_name = ExifToolStyleFormatter.DISPLAY_MAPPING.get(k)
            if not display_name:
                # Automate professional formatting for unmapped keys
                # e.g. "image_width" -> "Image Width"
                display_name = k.replace('_', ' ').title()
            
            # Special case: don't flatten some known list categories if they are strings
            if isinstance(v, dict):
                items.update(ExifToolStyleFormatter._flatten_metadata(v, ""))
            else:
                items[display_name] = v
        return items

__all__ = ['ExifToolStyleFormatter']
