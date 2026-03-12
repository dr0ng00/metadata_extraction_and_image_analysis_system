"""Forensic Domain Manager.

Categorizes metadata and provides specialized domain expertise for:
- 4.2.1. Image File Formats (JPEG, PNG, etc.)
- 4.2.2. Camera & Manufacturer-Specific (Canon, Nikon, Apple, etc.)
- 4.2.3. RAW Image Formats (DNG, CanonRaw, etc.)
- 4.2.4. Metadata Standards (Exif, XMP, IPTC)
- 4.2.5. GPS & Geotagging
"""
from typing import Any, Dict, List, Optional
from pathlib import Path

class ForensicDomainManager:
    """Manages specialized forensic domain knowledge and module routing."""

    def __init__(self):
        # 4.2.1 Image Format Expertise
        self.formats = {
            'JPEG': {'forensics': 'Quantization table analysis, ELA compatibility'},
            'PNG': {'forensics': 'Chunk ordering, ancillary data validation'},
            'TIFF': {'forensics': 'IFD structure audit, BigTIFF support'},
            'WebP': {'forensics': 'RIFF container validation'},
            'HEIF': {'forensics': 'ISO BMFF box structure audit'}
        }

        # 4.2.2 Manufacturer Expertise
        self.manufacturers = {
            'Canon': {'module': 'Canon.pm', 'notes': 'Proprietary MakerNotes decoding'},
            'Nikon': {'module': 'Nikon.pm', 'notes': 'Shutter count and proprietary tags'},
            'Sony': {'module': 'Sony.pm', 'notes': 'Deep firmware and lens auditing'},
            'Apple': {'module': 'Apple.pm', 'notes': 'iPhone-specific computationally fused data'},
            'GoPro': {'module': 'GoPro.pm', 'notes': 'Telemetry and GPMF data'},
            'DJI': {'module': 'DJI.pm', 'notes': 'Drone flight logs and specific metadata'}
        }

        # 4.2.3 RAW Expertise
        self.raw_formats = {
            'DNG': {'type': 'Digital Negative', 'forensics': 'Authenticity validation'},
            'CR2': {'type': 'Canon Raw', 'forensics': 'Sensor-direct data verification'},
            'NEF': {'type': 'Nikon Raw', 'forensics': 'Authentic capture validation'}
        }

        # 4.2.4 Standards Expertise
        self.standards = ['Exif', 'XMP', 'IPTC', 'ICC_Profile', 'GPS', 'MWG']

    def categorize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Categorize metadata into the 13-point spec domains."""
        summary = metadata.get('summary', {})
        if not isinstance(summary, dict): summary = {}
        
        exif = metadata.get('exif', {})
        if not isinstance(exif, dict): exif = {}
        
        image_info = metadata.get('image_info', {})
        if not isinstance(image_info, dict): image_info = {}
        
        categorized = {
            'image_format': self._identify_format(image_info),
            'manufacturer': self._identify_manufacturer(summary),
            'raw_domain': self._identify_raw(image_info),
            'standards_present': self._identify_standards(exif),
            'geospatial': self._identify_gps(exif)
        }
        
        return categorized

    def _identify_format(self, image_info: Dict) -> Dict:
        fmt = str(image_info.get('format', 'UNKNOWN')).upper()
        return {
            'label': fmt,
            'expertise': self.formats.get(fmt, {'forensics': 'Basic format analysis'})
        }

    def _identify_manufacturer(self, summary: Dict) -> Dict:
        make = str(summary.get('camera_make', 'Unknown')).lower()
        for ref_make, data in self.manufacturers.items():
            if ref_make.lower() in make:
                return {'label': ref_make, 'expertise': data}
        return {'label': 'Generic', 'expertise': {'notes': 'Generic hardware analysis'}}

    def _identify_raw(self, image_info: Dict) -> Dict:
        fmt = str(image_info.get('format', '')).upper()
        if fmt in ['DNG', 'CR2', 'NEF', 'RAW']:
            return {'is_raw': True, 'label': fmt, 'expertise': self.raw_formats.get(fmt, {})}
        return {'is_raw': False}

    def _identify_standards(self, exif: Dict) -> List[str]:
        found = []
        if any('XMP' in k for k in exif.keys()): found.append('XMP')
        if any('IPTC' in k for k in exif.keys()): found.append('IPTC')
        if any('GPS' in k for k in exif.keys()): found.append('GPS')
        if any('ICC' in k for k in exif.keys()): found.append('ICC_Profile')
        if exif: found.append('Exif')
        return found

    def _identify_gps(self, exif: Dict) -> Dict:
        has_gps = any('GPS' in k for k in exif.keys())
        return {
            'has_geotag': has_gps,
            'modules': ['GPS.pm', 'Geotag.pm'] if has_gps else []
        }

__all__ = ['ForensicDomainManager']
