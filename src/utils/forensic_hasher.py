"""Forensic hasher utilities (stub).

Provides `ForensicHasher` with simple hashing helpers used across the
project. This stub resolves import errors and offers a minimal API.
"""
import hashlib
from typing import Union


class ForensicHasher:
    """Simple wrapper around hashlib for consistent hashing."""
    def __init__(self, algorithm: str = 'sha256'):
        self.algorithm = algorithm

    def hash_bytes(self, data: bytes) -> str:
        h = hashlib.new(self.algorithm)
        h.update(data)
        return h.hexdigest()

    def hash_file(self, path: str) -> str:
        h = hashlib.new(self.algorithm)
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()


__all__ = ['ForensicHasher']
