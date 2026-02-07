"""Tests for EvidenceRiskScorer."""
import unittest
from src.analysis import EvidenceRiskScorer


class TestEvidenceRiskScorer(unittest.TestCase):
    def test_initialization(self):
        scorer = EvidenceRiskScorer()
        self.assertIsNotNone(scorer)
    
    def test_score(self):
        scorer = EvidenceRiskScorer()
        result = scorer.score({'findings': []})
        self.assertIn('risk_score', result)
        self.assertIn('level', result)


if __name__ == '__main__':
    unittest.main()
