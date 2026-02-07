"""File validation helpers (stub).

Provides `FileValidator` with basic checks used across the project.
This minimal implementation resolves import errors and can be extended.
"""
from pathlib import Path
from typing import Dict, Any


class FileValidator:
    """Simple file validation utilities."""
    def __init__(self, allowed_extensions=None, max_size_bytes: int | None = None):
        self.allowed_extensions = set(allowed_extensions or [])
        self.max_size_bytes = max_size_bytes

    def validate_path(self, path: str) -> bool:
        p = Path(path)
        return p.exists()

    def validate_extension(self, path: str) -> bool:
        if not self.allowed_extensions:
            return True
        return Path(path).suffix.lower() in self.allowed_extensions

    def validate_size(self, path: str) -> bool:
        if self.max_size_bytes is None:
            return True
        try:
            size = Path(path).stat().st_size
            return size <= self.max_size_bytes
        except Exception:
            return False

    def validate(self, path: str) -> Dict[str, Any]:
        return {
            'exists': self.validate_path(path),
            'extension_ok': self.validate_extension(path),
            'size_ok': self.validate_size(path)
        }


__all__ = ['FileValidator']