"""
Explainable AI modules for forensic reasoning.

This package contains the Confidence Explanation Engine and related
components for transparent, court-admissible forensic explanations.
"""

from .explanation_engine import ConfidenceExplanationEngine

__all__ = [
    'ConfidenceExplanationEngine'
]

# Explanation templates
EXPLANATION_TEMPLATES = {
    'TIMESTAMP_INCONSISTENCY': {
        'title': 'Timestamp Inconsistency',
        'template': 'Found {count} different timestamps across metadata fields. '
                   'Original camera images typically have consistent timestamps.',
        'forensic_significance': 'Multiple timestamps may indicate file copying, '
                                'editing, or manipulation.'
    },
    'SOFTWARE_MISMATCH': {
        'title': 'Software-Camera Mismatch',
        'template': 'Software signature "{software}" does not match reported '
                   'camera model "{model}".',
        'forensic_significance': 'Indicates post-capture processing or editing.'
    },
    'COMPRESSION_HISTORY': {
        'title': 'Multiple Compression Cycles',
        'template': 'Detected {cycle_count} compression cycles in image data.',
        'forensic_significance': 'Original camera images typically have '
                                'single-stage compression.'
    }
}

def get_explanation_template(flag_type):
    """Get explanation template for a specific flag type."""
    return EXPLANATION_TEMPLATES.get(flag_type, {
        'title': flag_type,
        'template': 'Forensic anomaly detected.',
        'forensic_significance': 'Requires further investigation.'
    })