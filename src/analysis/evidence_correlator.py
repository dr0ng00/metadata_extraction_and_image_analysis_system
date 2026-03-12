"""Evidence Correlator.

Correlates findings from multiple forensic modules (ML, Rules, Statistics)
to produce a unified and consistent interpretive result.
"""
from typing import Any, Dict, List

class EvidenceCorrelator:
    """Consolidates findings from various modules into a unified interpretation (Point 9)."""

    def __init__(self):
        pass

    def correlate(self, ml_results: Dict[str, Any], rule_results: Dict[str, Any], stat_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Produce a unified forensic opinion by correlating multi-source outputs.
        
        Args:
            ml_results: Predictions from Origin Detection (Point 5).
            rule_results: Findings from Forensic Rules (Point 6).
            stat_results: Anomalies from Statistical Analysis (Point 7).
            
        Returns:
            Dictionary containing correlated interpretation.
        """
        ml_origin = ml_results.get('primary_origin', 'unknown')
        rule_flags = rule_results.get('flags', [])
        stat_issues = stat_results.get('issues', [])
        
        findings = []
        conflicts = []
        
        has_software_rule = any('software' in f.lower() for f in rule_flags)
        has_temporal_issue = len(stat_issues) > 0

        # 1. Verification of Origin Consistency
        if ml_origin == 'camera_original' and has_software_rule:
            conflicts.append("ML predicts original camera image, but hard rules detected editing software signatures.")
        
        # 2. Evidence Consolidation
        # Gather all flags and findings into a ranked list
        all_indicators = list(set(rule_flags + stat_issues))
        
        # 3. Formulate Unified Interpretation
        interpretation = "PENDING"
        confidence_modifier = 1.0

        if conflicts:
            interpretation = "INCONSISTENT_EVIDENCE"
            confidence_modifier = 0.5
        elif ml_origin in ['synthetic_ai_generated', 'ai_generated']:
            interpretation = "SYNTHETIC_CONTENT"
        elif ml_origin == 'camera_original' and not all_indicators:
            interpretation = "CONSISTENT_AUTHENTIC"
        elif ml_origin == 'camera_post_processed':
            interpretation = "AUTHENTIC_WITH_POST_PROCESSING"
        elif ml_origin in ['software_reencoded', 'software_generated']:
            interpretation = "REENCODED_IMAGE"
        elif has_software_rule and has_temporal_issue:
            interpretation = "MANIPULATED_CONTENT"
        elif has_software_rule:
            interpretation = "REENCODED_IMAGE"
        else:
            interpretation = "UNVERIFIED_ORIGIN"

        return {
            'unified_interpretation': interpretation,
            'indicators': all_indicators,
            'conflicts': conflicts,
            'origin_summary': f"ML predicted {ml_origin} with {len(all_indicators)} consistency flags found.",
            'confidence_modifier': confidence_modifier
        }

__all__ = ['EvidenceCorrelator']
