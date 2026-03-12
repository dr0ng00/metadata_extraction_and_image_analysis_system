"""Cross-Case Evidentiary Correlator.

Analyzes links between the current piece of evidence and historical findings
stored in the forensic intelligence database.
"""
from typing import Any, Dict, List
from ..utils.forensic_db import ForensicDatabase

class CrossCaseCorrelator:
    """Identifies links across multiple forensic cases (Point 13)."""

    def __init__(self, db_path: str = "forensic_intelligence.db"):
        self.db = ForensicDatabase(db_path)

    def correlate(self, current_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Search for evidentiary links across the case library.
        
        Args:
            current_results: Analysis results of the current evidence.
            
        Returns:
            Dictionary containing cross-case links and relationship strengths.
        """
        summary = current_results.get('metadata', {}).get('summary', {})
        make = summary.get('camera_make')
        model = summary.get('camera_model')
        software = summary.get('software')
        
        artifacts = current_results.get('artifact_analysis', {})
        results_qtable = artifacts.get('qtable_audit', {}).get('signature_match')
        
        # Find matches in the DB
        matches = self.db.find_similar_evidence(current_results)
        
        links = []
        for match in matches:
            link_type = "UNKNOWN"
            if match['hardware_make'] == make and make is not None:
                link_type = "HARDWARE_MATCH"
            elif match['software_tag'] == software and software is not None:
                link_type = "SOFTWARE_MATCH"
            elif match['qtable_sig'] == results_qtable and results_qtable is not None:
                link_type = "SIGNAL_MATCH" # Q-Table link
            
            if link_type != "UNKNOWN":
                links.append({
                    'linked_case': match['case_id'],
                    'linked_file': match['filename'],
                    'relationship': link_type,
                    'shared_signature': match['hardware_model'] if link_type == "HARDWARE_MATCH" else match['software_tag'] if link_type == "SOFTWARE_MATCH" else match['qtable_sig'],
                    'confidence': 0.9 if link_type == "HARDWARE_MATCH" else 0.8 if link_type == "SIGNAL_MATCH" else 0.6
                })

        # Ingest the current case into the DB for future correlation
        self.db.ingest_case(current_results)

        return {
            'has_cross_links': len(links) > 0,
            'link_count': len(links),
            'evidentiary_links': links,
            'summary': self._generate_link_summary(links)
        }

    def _generate_link_summary(self, links: List[Dict[str, Any]]) -> str:
        if not links:
            return "No previous cases share this forensic signature."
        
        unique_cases = len(set(l['linked_case'] for l in links))
        return f"Identified links to {len(links)} evidence items across {unique_cases} historical cases."

__all__ = ['CrossCaseCorrelator']
