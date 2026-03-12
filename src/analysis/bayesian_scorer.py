"""Bayesian Scorer for predictive forensic intelligence.

Implements a probabilistic risk model to weigh evidence from multiple
forensic modules (ELA, Metadata, Origin, etc.).
"""
from typing import Any, Dict, List

class BayesianScorer:
    """Predictive forensic risk scorer using Bayesian-inspired weighting."""

    def __init__(self):
        # Prior probabilities (Base rates for different artifact types)
        # e.g., P(Tampered | Evidence)
        self.priors = {
            'camera_original': 0.05,  # Low probability of original being "high risk"
            'camera_post_processed': 0.20,
            'software_generated': 0.30,
            'software_reencoded': 0.25,
            'origin_unverified': 0.20,
            'social_media': 0.30,
            'synthetic_ai_generated': 0.85,
            'ai_generated': 0.85
        }

        # Likelihood weights (Sensitivity of different detectors)
        self.likelihoods = {
            'HIGH_ELA_VARIANCE': 0.8,
            'FOREIGN_QTABLE': 0.7,
            'SOFTWARE_SIGNATURE': 0.6,
            'TEMPORAL_ANOMALY': 0.5,
            'GENERIC_CAM_MAKE': 0.2
        }

    def calculate_risk(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate a predictive risk score using weighted evidence.
        
        Args:
            analysis_results: Full multi-source analysis result.
            
        Returns:
            Dictionary with Bayesian risk score and interpretation.
        """
        origin = analysis_results.get('origin_detection', {}).get('primary_origin', 'unknown')
        prior = self.priors.get(origin, 0.5)

        # Collect evidence bits
        evidence = []
        
        # 1. Artifact cues
        artifacts = analysis_results.get('artifact_analysis', {})
        if artifacts.get('ela_results', {}).get('ela_intensity') == 'HIGH':
            evidence.append('HIGH_ELA_VARIANCE')
        if artifacts.get('qtable_audit', {}).get('signature_match') == 'Software_Modification':
            evidence.append('FOREIGN_QTABLE')

        # 2. Metadata cues
        flags = analysis_results.get('flags', [])
        if any('software' in f.lower() for f in flags):
            evidence.append('SOFTWARE_SIGNATURE')
        
        ts_analysis = analysis_results.get('timestamp_analysis', {})
        if ts_analysis.get('issues'):
            evidence.append('TEMPORAL_ANOMALY')

        # Cross-module deterministic interpretation for calibration
        deterministic = analysis_results.get('correlation', {}).get('unified_interpretation', 'UNKNOWN')
        has_software_signature = 'SOFTWARE_SIGNATURE' in evidence
        has_temporal_anomaly = 'TEMPORAL_ANOMALY' in evidence
        structural_only = set(evidence).issubset({'HIGH_ELA_VARIANCE', 'FOREIGN_QTABLE'}) and len(evidence) > 0

        # High risk should be emitted only when manipulation is corroborated
        manipulation_confirmed = (
            deterministic == 'MANIPULATED_CONTENT'
            or (has_software_signature and has_temporal_anomaly)
        )

        # Calculate posterior using a simplified Bayesian-weighted update
        # P(H|E) = P(H) * product(Weight_i) / Evidence_Normalization
        # For simulation, we use a sigmoid-like accumulation
        score_accumulator = prior
        for e_key in evidence:
            weight = self.likelihoods.get(e_key, 0.1)
            # Update: Increase probability based on evidence weight
            score_accumulator = score_accumulator + (1 - score_accumulator) * weight

        final_score = round(score_accumulator * 100, 1)

        # Calibration layer: prevent structural artifacts alone from producing critical risk
        calibration_note = "Score derived from Bayesian cue aggregation."
        if not evidence:
            final_score = 0.0
            calibration_note = "No manipulation cues detected; predictive risk set to 0."
        elif not manipulation_confirmed:
            if origin == 'camera_original' and structural_only and deterministic in ['CONSISTENT_AUTHENTIC', 'UNVERIFIED_ORIGIN']:
                final_score = min(final_score, 20.0)
                calibration_note = (
                    "Structural-only cues with camera-origin metadata and no deterministic manipulation confirmation; "
                    "score capped to LOW."
                )
            elif origin in ['origin_unverified', 'software_reencoded'] and structural_only:
                final_score = min(final_score, 30.0)
                calibration_note = (
                    "Metadata is missing or re-encoding likely; structural-only cues are treated as LOW/MODERATE risk."
                )
            else:
                final_score = min(final_score, 35.0)
                calibration_note = (
                    "Manipulation not corroborated across modules; Bayesian score constrained to LOW/MEDIUM."
                )
        else:
            final_score = max(final_score, 80.0)
            calibration_note = "Manipulation corroborated by cross-module evidence; high-risk floor applied."

        level = 'LOW'
        if final_score > 80: level = 'CRITICAL'
        elif final_score > 60: level = 'HIGH'
        elif final_score > 30: level = 'MEDIUM'

        return {
            'predictive_risk_score': final_score,
            'risk_level': level,
            'prior_probability': prior,
            'evidence_cues_used': evidence,
            'interpretation': f"Bayesian model predicts {level} risk from {len(evidence)} cue(s).",
            'calibration_note': calibration_note,
            'manipulation_confirmed': manipulation_confirmed
        }

__all__ = ['BayesianScorer']
