"""Platform fingerprint definitions (stub).

Provides `PlatformFingerprints` data structure used for origin/platform
detection. This is a minimal placeholder to resolve imports and can be
expanded with real fingerprint data later.
"""
from typing import Dict, Any


class PlatformFingerprints:
    """Container for platform fingerprint patterns and lookup helpers."""
    def __init__(self):
        self.fingerprints: Dict[str, Any] = {
            'iOS': {'markers': ['iPhone', 'iOS'], 'confidence': 0.8},
            'Android': {'markers': ['Android', 'Google'], 'confidence': 0.7},
            'WhatsApp': {'markers': ['WhatsApp'], 'confidence': 0.6}
        }

    def lookup(self, name: str) -> Dict[str, Any]:
        return self.fingerprints.get(name, {})


__all__ = ['PlatformFingerprints']
