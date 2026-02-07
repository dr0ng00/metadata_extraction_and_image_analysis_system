"""Integration tests for MetaForensicAI."""
import unittest
from src import MetaForensicAI, ForensicEvidenceHandler, MetadataAuthenticityAnalyzer


class TestMetaForensicAIIntegration(unittest.TestCase):
    def test_main_import(self):
        system = MetaForensicAI()
        self.assertEqual(system.version, '1.0.0')
    
    def test_analyze_image(self):
        system = MetaForensicAI()
        result = system.analyze_image('test.jpg')
        self.assertIn('risk_score', result)
        self.assertIn('authentic', result)
    
    def test_core_modules_integration(self):
        handler = ForensicEvidenceHandler('test.jpg')
        analyzer = MetadataAuthenticityAnalyzer()
        self.assertIsNotNone(handler)
        self.assertIsNotNone(analyzer)


if __name__ == '__main__':
    unittest.main()
