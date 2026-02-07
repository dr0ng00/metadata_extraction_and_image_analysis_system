"""
Analysis modules for forensic evaluation.

This package contains modules for analyzing image authenticity,
contextual information, and calculating evidence risk scores.
"""

from .authenticity_analyzer import MetadataAuthenticityAnalyzer
from .contextual_analyzer import ContextualAnalyzer
from .risk_scorer import EvidenceRiskScorer
from .timestamp_analyzer import TimestampAnalyzer

__all__ = [
    'MetadataAuthenticityAnalyzer',
    'ContextualAnalyzer',
    'EvidenceRiskScorer',
    'TimestampAnalyzer'
]

# Analysis configuration
ANALYSIS_CONFIG = {
    'timestamp_threshold_seconds': 3600,  # 1 hour
    'gps_anomaly_threshold': {
        'altitude_min': -1000,
        'altitude_max': 90000,
        'coordinate_precision': 0.0001
    },
    'compression_indicators': {
        'jpeg_quality_threshold': 85,
        'double_compression_confidence': 0.7,
        'quantization_anomaly_score': 0.5
    },
    'platform_detection': {
        'confidence_threshold': 0.6,
        'fingerprint_match_min': 3
    }
}

def get_analysis_config():
    """Return analysis configuration parameters."""
    return ANALYSIS_CONFIG.copy()