"""Integration tests for MetaForensicAI."""
import unittest

from src import MetaForensicAI, ForensicEvidenceHandler, MetadataAuthenticityAnalyzer


class TestMetaForensicAIIntegration(unittest.TestCase):
    def test_main_import(self):
        system = MetaForensicAI()
        self.assertEqual(system.config['system']['version'], '1.0.0')
        self.assertIsNotNone(system.evidence_handler)
        self.assertIsNotNone(system.metadata_extractor)

    def test_analyze_image_missing_file(self):
        system = MetaForensicAI()
        with self.assertRaisesRegex(ValueError, 'Evidence integrity check failed'):
            system.analyze_image('test.jpg')
    
    def test_core_modules_integration(self):
        handler = ForensicEvidenceHandler()
        analyzer = MetadataAuthenticityAnalyzer()
        self.assertIsNotNone(handler)
        self.assertIsNotNone(analyzer)


if __name__ == '__main__':
    unittest.main()
