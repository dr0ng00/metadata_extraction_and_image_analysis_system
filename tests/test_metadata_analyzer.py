"""Tests for MetadataAuthenticityAnalyzer."""
import unittest
from src.core import MetadataAuthenticityAnalyzer


class TestMetadataAuthenticityAnalyzer(unittest.TestCase):
    def test_initialization(self):
        analyzer = MetadataAuthenticityAnalyzer()
        self.assertIsNotNone(analyzer)
    
    def test_analyze(self):
        analyzer = MetadataAuthenticityAnalyzer()
        result = analyzer.analyze({'test': 'data'})
        self.assertIn('authentic', result)


if __name__ == '__main__':
    unittest.main()
