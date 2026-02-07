"""Origin detection stub.

Provides `OriginDetector` for package exports.
"""
from typing import Any, Dict


class OriginDetector:
    def detect(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        return {'origin': 'unknown', 'confidence': 0.0}


__all__ = ['OriginDetector']
