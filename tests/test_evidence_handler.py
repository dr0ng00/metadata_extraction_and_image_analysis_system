"""Tests for the ForensicEvidenceHandler."""
from pathlib import Path
import unittest

from src.core import ForensicEvidenceHandler


class TestForensicEvidenceHandler(unittest.TestCase):
    def test_initialization(self):
        handler = ForensicEvidenceHandler()
        self.assertIsNotNone(handler)

    def test_process_evidence(self):
        handler = ForensicEvidenceHandler()
        evidence_path = Path('tests') / '.tmp_test_image.jpg'
        try:
            evidence_path.write_bytes(b'test image content')
            result = handler.process_evidence(str(evidence_path))
        finally:
            if evidence_path.exists():
                evidence_path.unlink()

        self.assertTrue(result['verified'])
        self.assertTrue(result['processed'])
        self.assertEqual(result['file_size_bytes'], len(b'test image content'))
        self.assertIn('sha256', result['hashes'])
        self.assertIn('md5', result['hashes'])


if __name__ == '__main__':
    unittest.main()
