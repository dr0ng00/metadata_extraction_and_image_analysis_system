"""
Reporting modules for forensic documentation.

This package contains report generators for PDF, JSON, and other formats
suitable for academic evaluation and legal analysis.
"""

from .report_generator import ForensicReportGenerator
from .json_schema import ForensicJSONSchema

__all__ = [
    'ForensicReportGenerator',
    'ForensicJSONSchema'
]

# Report templates and styles
REPORT_CONFIG = {
    'pdf': {
        'page_size': 'A4',
        'margins': (72, 72, 72, 72),  # 1 inch margins
        'font_family': 'Helvetica',
        'header_font_size': 14,
        'body_font_size': 10,
        'colors': {
            'header': (0.2, 0.2, 0.4),
            'risk_high': (0.8, 0.2, 0.2),
            'risk_medium': (0.9, 0.6, 0.2),
            'risk_low': (0.2, 0.6, 0.2)
        }
    },
    'json': {
        'indent': 2,
        'sort_keys': True,
        'ensure_ascii': False
    }
}

def get_report_config(format_type='pdf'):
    """Get configuration for specific report format."""
    return REPORT_CONFIG.get(format_type, {})