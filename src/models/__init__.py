"""
Data models and fingerprints for forensic analysis.

This package contains platform fingerprints, compression patterns,
camera databases, and other forensic data models.
"""

from .platform_fingerprints import PlatformFingerprints
from .compression_patterns import CompressionPatterns

__all__ = [
    'PlatformFingerprints',
    'CompressionPatterns'
]

# Camera database placeholder
CAMERA_DATABASE = {
    'make_model_patterns': {
        'Canon': ['EOS', 'PowerShot', 'IXUS'],
        'Nikon': ['D', 'Z', 'Coolpix'],
        'Sony': ['ILCE', 'DSC', 'α'],
        'Apple': ['iPhone'],
        'Samsung': ['Galaxy']
    },
    'software_patterns': {
        'Adobe': ['Photoshop', 'Lightroom', 'Camera Raw'],
        'Apple': ['iOS', 'macOS', 'Photos'],
        'Google': ['Snapseed', 'Google Photos'],
        'Social Media': ['Instagram', 'WhatsApp', 'Facebook']
    }
}

def get_camera_database():
    """Return camera and software database."""
    return CAMERA_DATABASE.copy()