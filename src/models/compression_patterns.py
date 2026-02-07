"""Compression pattern heuristics (stub).

Provides `CompressionPatterns` class used to identify compression artifacts
and history. Minimal implementation to satisfy imports.
"""
from typing import Dict, Any


class CompressionPatterns:
    def __init__(self):
        self.patterns: Dict[str, Any] = {
            'jpeg_double_compression': {'signature': 'QTABLES', 'confidence': 0.5}
        }

    def detect(self, image_bytes: bytes) -> Dict[str, Any]:
        return {'detected': False, 'pattern': None, 'confidence': 0.0}


__all__ = ['CompressionPatterns']
