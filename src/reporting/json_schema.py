"""Forensic JSON schema utilities (stub).

Provides a minimal `ForensicJSONSchema` helper to validate or produce
simple JSON report structures. This resolves import errors and can be
replaced with a full JSON Schema implementation later.
"""
from typing import Any, Dict


class ForensicJSONSchema:
    """Minimal JSON schema helper for forensic reports."""
    def __init__(self, schema: Dict[str, Any] | None = None):
        self.schema = schema or {
            'type': 'object',
            'properties': {
                'manifest_id': {'type': 'string'},
                'generated': {'type': 'string'},
            },
            'required': ['manifest_id', 'generated']
        }

    def validate(self, data: Dict[str, Any]) -> bool:
        # Minimal validation: check required keys
        for key in self.schema.get('required', []):
            if key not in data:
                return False
        return True

    def get_schema(self) -> Dict[str, Any]:
        return self.schema.copy()


__all__ = ['ForensicJSONSchema']
