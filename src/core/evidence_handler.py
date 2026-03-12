#!/usr/bin/env python3
"""
Forensic evidence handler for MetaForensicAI.

This module provides the `ForensicEvidenceHandler` class, which is responsible
for the initial, forensically sound processing of digital evidence. Its key
responsibilities include:
- Verifying the existence and accessibility of the evidence file.
- Recording essential file system metadata (e.g., size, path).
- Calculating multiple cryptographic hashes (e.g., SHA-256, MD5) to ensure
  and verify the integrity of the evidence throughout the analysis pipeline.
"""

from pathlib import Path
from typing import Any, Dict
from datetime import datetime

from ..utils.forensic_hasher import ForensicHasher
from ..utils.file_validator import FileValidator


class ForensicEvidenceHandler:
    """Handles the initial verification and integrity checking of evidence."""

    def __init__(self, hash_algorithms: list[str] | None = None):
        """
        Initialize the evidence handler.

        Args:
            hash_algorithms: A list of hash algorithms to use (e.g., ['sha256', 'md5']).
        """
        self.hash_algorithms = hash_algorithms or ['sha256', 'md5']
        self.validator = FileValidator()

    def process_evidence(self, evidence_path: str) -> Dict[str, Any]:
        """
        Process an evidence file to verify its integrity and gather initial data.

        Args:
            evidence_path: The path to the evidence file.

        Returns:
            A dictionary containing integrity information.
        """
        path_obj = Path(evidence_path)
        is_valid = self.validator.validate_path(str(path_obj))

        if not is_valid:
            return {'verified': False, 'error': f"Evidence file not found at {evidence_path}"}

        hashes = {alg: ForensicHasher(alg).hash_file(str(path_obj)) for alg in self.hash_algorithms}

        return {
            'verified': True,
            'file_path': str(path_obj.absolute()),
            'file_size_bytes': path_obj.stat().st_size,
            'hashes': hashes,
            'processed': True,
            'processing_timestamp': datetime.now().isoformat()
        }
