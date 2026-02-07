"""
MetaForensicAI: AI-Assisted Digital Image Forensics System

A comprehensive digital image forensics system that extends ExifTool-based
metadata extraction with intelligent forensic reasoning and interactive analysis.
"""

__version__ = "1.0.0"
__author__ = "MetaForensicAI Team"
__license__ = "MIT"
__copyright__ = "Copyright 2024 MetaForensicAI Project"

from .main import MetaForensicAI

# Core components
from .core import (
    ForensicEvidenceHandler,
    EnhancedMetadataExtractor,
    MetadataAuthenticityAnalyzer,
    OriginDetector
)

# Analysis modules
from .analysis import (
    ContextualAnalyzer,
    EvidenceRiskScorer,
    TimestampAnalyzer
)

# Interface modules
from .interface import (
    ForensicCLIAssistant,
    NaturalLanguageProcessor
)

# Reporting modules
from .reporting import ForensicReportGenerator

# Utility modules
from .utils import (
    ForensicHasher,
    ChainOfCustodyLogger
)

# Export main classes
__all__ = [
    'MetaForensicAI',
    'ForensicEvidenceHandler',
    'EnhancedMetadataExtractor',
    'MetadataAuthenticityAnalyzer',
    'OriginDetector',
    'ContextualAnalyzer',
    'EvidenceRiskScorer',
    'ForensicCLIAssistant',
    'ForensicReportGenerator',
    'ForensicHasher'
]

# Package metadata
PACKAGE_INFO = {
    'name': 'MetaForensicAI',
    'version': __version__,
    'description': 'AI-Assisted Digital Image Forensics System',
    'author': __author__,
    'license': __license__,
    'url': 'https://github.com/yourusername/MetaForensicAI',
    'forensic_methodology': 'Metadata-based analysis with AI reasoning',
    'compliance': [
        'DFIR best practices',
        'Read-only evidence handling',
        'Cryptographic integrity verification',
        'Chain of custody logging'
    ]
}

def get_system_info():
    """Return system information and capabilities."""
    import sys
    import platform
    
    return {
        'system': {
            'python_version': sys.version,
            'platform': platform.platform(),
            'package_version': __version__
        },
        'capabilities': {
            'metadata_extraction': True,
            'authenticity_analysis': True,
            'origin_detection': True,
            'risk_scoring': True,
            'explanatory_ai': True,
            'interactive_cli': True,
            'forensic_reporting': True
        },
        'forensic_standards': {
            'read_only': True,
            'hash_verification': True,
            'audit_logging': True,
            'non_destructive': True
        }
    }

def validate_environment():
    """Validate that all required dependencies are available."""
    import importlib
    import sys
    
    required_modules = [
        'PIL',
        'exifread',
        'numpy',
        'pandas',
        'yaml',
        'json',
        'hashlib',
        'datetime',
        'pathlib'
    ]
    
    missing = []
    for module in required_modules:
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(module)
    
    # Check for ExifTool
    import subprocess
    try:
        subprocess.run(['exiftool', '-ver'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        missing.append('exiftool')
    
    if missing:
        raise ImportError(
            f"Missing required dependencies: {', '.join(missing)}\n"
            f"Please install with: pip install -r requirements.txt\n"
            f"And ensure exiftool is installed system-wide."
        )
    
    return True