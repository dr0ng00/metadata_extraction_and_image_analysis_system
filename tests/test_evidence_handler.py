"""Tests for the ForensicEvidenceHandler."""
import unittest
from src.core import ForensicEvidenceHandler


class TestForensicEvidenceHandler(unittest.TestCase):
    def test_initialization(self):
        handler = ForensicEvidenceHandler('test_image.jpg')
        self.assertIsNotNone(handler)
    
    def test_open(self):
        handler = ForensicEvidenceHandler('test_image.jpg')
        result = handler.open()
        self.assertIn('status', result)


if __name__ == '__main__':
    unittest.main()
