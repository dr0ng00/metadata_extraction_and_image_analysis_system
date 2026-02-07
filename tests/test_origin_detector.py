"""Tests for OriginDetector."""
import unittest
from src.core import OriginDetector


class TestOriginDetector(unittest.TestCase):
    def test_initialization(self):
        detector = OriginDetector()
        self.assertIsNotNone(detector)
    
    def test_detect(self):
        detector = OriginDetector()
        result = detector.detect({'test': 'metadata'})
        self.assertIn('origin', result)
        self.assertIn('confidence', result)


if __name__ == '__main__':
    unittest.main()
