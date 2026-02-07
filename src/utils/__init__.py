"""
Utility modules for forensic operations.

This package contains helper functions for hashing, file validation,
logging, and chain of custody management.
"""

from .forensic_hasher import ForensicHasher
from .file_validator import FileValidator
from .logging_handler import ForensicLogger, ChainOfCustodyLogger
from .chain_of_custody import ChainOfCustody

__all__ = [
    'ForensicHasher',
    'FileValidator',
    'ForensicLogger',
    'ChainOfCustodyLogger',
    'ChainOfCustody'
]

# Utility functions
def format_file_size(bytes):
    """Format file size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes < 1024.0:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.2f} TB"

def calculate_hash(file_path, algorithm='sha256'):
    """Calculate hash of a file."""
    import hashlib
    hash_func = getattr(hashlib, algorithm)()
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

def validate_image_file(file_path):
    """Validate if file is a supported image format."""
    from pathlib import Path
    
    supported_extensions = ['.jpg', '.jpeg', '.png', '.tiff', '.tif', 
                           '.bmp', '.gif', '.webp']
    
    file_ext = Path(file_path).suffix.lower()
    return file_ext in supported_extensions

def get_timestamp():
    """Get current timestamp in ISO format."""
    from datetime import datetime
    return datetime.now().isoformat()