"""
Core forensic analysis modules for MetaForensicAI.

This package contains the fundamental components for evidence handling,
metadata extraction, and forensic analysis.
"""

from .evidence_handler import ForensicEvidenceHandler
from .metadata_extractor import EnhancedMetadataExtractor
from .forensic_analyzer import MetadataAuthenticityAnalyzer
from .origin_detector import OriginDetector

__all__ = [
    'ForensicEvidenceHandler',
    'EnhancedMetadataExtractor',
    'MetadataAuthenticityAnalyzer',
    'OriginDetector'
]

# Core forensic constants
FORENSIC_CONSTANTS = {
    'HASH_ALGORITHMS': ['sha256', 'sha3_256', 'md5'],
    'SUPPORTED_FORMATS': [
        '.jpg', '.jpeg', '.png', '.tiff', '.tif',
        '.bmp', '.gif', '.webp', '.heic', '.cr2',
        '.nef', '.arw', '.dng'
    ],
    'METADATA_SECTIONS': [
        'exif', 'xmp', 'iptc', 'gps', 'makernotes',
        'file', 'composite', 'dublin_core', 'photoshop'
    ],
    'RISK_LEVELS': {
        'CRITICAL': 1.0,
        'HIGH': 0.75,
        'MEDIUM': 0.5,
        'LOW': 0.25
    }
}

def get_forensic_constants():
    """Return forensic constants used throughout the system."""
    return FORENSIC_CONSTANTS.copy()