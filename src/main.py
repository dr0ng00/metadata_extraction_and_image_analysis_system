#!/usr/bin/env python3
"""
MetaForensicAI - Main Entry Point
AI-Assisted Digital Image Forensics System

Version: 1.0.0
Author: MetaForensicAI Research Team
License: MIT
"""

import argparse
import sys
import logging
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

# --- Local Application Imports ---

# Core Components
from .core.evidence_handler import ForensicEvidenceHandler
from .core.metadata_extractor import EnhancedMetadataExtractor
from .core.origin_detector import OriginDetector

# Analysis Modules
from .analysis.authenticity_analyzer import MetadataAuthenticityAnalyzer
from .analysis.contextual_analyzer import ContextualAnalyzer
from .analysis.timestamp_analyzer import TimestampAnalyzer
from .analysis.evidence_correlator import EvidenceCorrelator
from .analysis.artifact_analyzer import ArtifactAnalyzer
from .analysis.risk_scorer import EvidenceRiskScorer
from .analysis.bayesian_scorer import BayesianScorer
from .analysis.cross_case_correlator import CrossCaseCorrelator

# Utility Modules
from .utils.logging_handler import ForensicLogger, ChainOfCustodyLogger
from .utils.chain_of_custody import ChainOfCustody



class MetaForensicAI:
    """
    Main controller class for the AI-Assisted Digital Image Forensics System.
    Implements the complete forensic analysis pipeline.
    """
    
    def __init__(self, config_path=None):
        """
        Initialize the forensic analysis system.
        
        Args:
            config_path: Path to configuration file (optional)
        """
        self.config = self._load_config(config_path)
        self.logger = ForensicLogger('MetaForensicAI')
        self.chain_of_custody = ChainOfCustodyLogger()
        
        # Initialize core components
        self.evidence_handler = ForensicEvidenceHandler()
        self.metadata_extractor = EnhancedMetadataExtractor()
        self.origin_detector = OriginDetector()

        # Explanation and Reporting
        from .explanation.explanation_engine import ConfidenceExplanationEngine
        from .reporting.report_generator import ForensicReportGenerator
        
        # Initialize analysis components
        self.authenticity_analyzer = MetadataAuthenticityAnalyzer()
        self.contextual_analyzer = ContextualAnalyzer()
        self.timestamp_analyzer = TimestampAnalyzer()
        self.evidence_correlator = EvidenceCorrelator()
        self.artifact_analyzer = ArtifactAnalyzer()
        self.bayesian_scorer = BayesianScorer()
        self.cross_case_correlator = CrossCaseCorrelator()
        self.risk_scorer = EvidenceRiskScorer()
        
        # Initialize explanation and reporting
        self.explanation_engine = ConfidenceExplanationEngine()
        self.report_generator = ForensicReportGenerator()
        
        # Main analyzer is the authenticity analyzer with supporting components
        self.forensic_analyzer = MetadataAuthenticityAnalyzer()
        
        self.analysis_results = None
        self.cli_assistant = None
        
        self.logger.info("MetaForensicAI system initialized successfully")
        self.chain_of_custody.log_event("SYSTEM_INITIALIZED", {
            "config_path": config_path,
            "timestamp": datetime.now().isoformat()
        })
    
    def _load_config(self, config_path):
        """Load configuration from file or use defaults."""
        import yaml
        from pathlib import Path
        
        default_config = {
            'system': {
                'name': 'MetaForensicAI',
                'version': '1.0.0',
                'mode': 'forensic',
                'language': 'en'
            },
            'forensic': {
                'read_only': True,
                'hash_algorithms': ['sha256', 'sha3_256'],
                'audit_logging': True
            },
            'analysis': {
                'enable_timestamp_analysis': True,
                'enable_platform_detection': True,
                'confidence_threshold': 0.7
            },
            'reporting': {
                'generate_pdf': True,
                'generate_json': True,
                'output_dir': './results/reports'
            }
        }
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    # Recursive merge with default config
                    self._merge_configs(default_config, user_config)
            except Exception as e:
                self.logger.warning(f"Failed to load config from {config_path}: {e}")
        
        return default_config
    
    def _merge_configs(self, default, user):
        """Recursively merge user config into default config."""
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_configs(default[key], value)
            else:
                default[key] = value
    
    def _build_explainability_breakdown(self, combined_raw, risk_summary, bayesian_findings, explanations):
        """Build a detailed explainability payload for explain mode."""
        return {
            'pipeline_mode': 'explain',
            'module_outputs': {
                'authenticity': {
                    'flags': combined_raw.get('flags', []),
                    'confidence': combined_raw.get('confidence'),
                    'risk_score': combined_raw.get('risk_score')
                },
                'origin_detection': combined_raw.get('origin_detection', {}),
                'contextual_analysis': combined_raw.get('contextual_analysis', {}),
                'timestamp_analysis': combined_raw.get('timestamp_analysis', {}),
                'artifact_analysis': combined_raw.get('artifact_analysis', {}),
                'correlation': combined_raw.get('correlation', {}),
                'risk_assessment': risk_summary,
                'bayesian_risk': bayesian_findings
            },
            'explanation_count': len(explanations),
            'explanation_titles': [exp.get('title') for exp in explanations],
            'decision_trace': {
                'unified_interpretation': risk_summary.get('unified_interpretation'),
                'risk_level': risk_summary.get('level'),
                'risk_score': risk_summary.get('risk_score')
            }
        }

    def _score_to_band(self, score):
        """Map 0-100 score to LOW/MODERATE/HIGH."""
        if score >= 67:
            return 'HIGH'
        if score >= 34:
            return 'MODERATE'
        return 'LOW'

    def _refine_origin_with_artifacts(
        self,
        origin_results: Dict[str, Any],
        metadata: Dict[str, Any],
        artifact_findings: Dict[str, Any],
        auth_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Refine origin class with artifact evidence and metadata consistency."""
        refined = dict(origin_results or {})
        label = refined.get('primary_origin', 'origin_unverified')
        features = refined.get('features', {}) or {}

        if label in {'synthetic_ai_generated', 'ai_generated'}:
            return refined

        flags = auth_results.get('flags', []) if isinstance(auth_results, dict) else []
        has_software_flag = any('software' in str(f).lower() for f in flags)
        has_camera_signals = bool(features.get('camera_signature_strength', 0) >= 3)
        missing_camera = not has_camera_signals

        qtable_sig = artifact_findings.get('qtable_audit', {}).get('signature_match') if isinstance(artifact_findings, dict) else None
        qtable_profile = artifact_findings.get('qtable_audit', {}).get('software_profile') if isinstance(artifact_findings, dict) else None
        ela_intensity = artifact_findings.get('ela_results', {}).get('ela_intensity') if isinstance(artifact_findings, dict) else None
        has_structural_reencode = qtable_sig == 'Software_Modification' or ela_intensity == 'HIGH'

        if has_camera_signals and (has_software_flag or has_structural_reencode):
            refined['primary_origin'] = 'camera_post_processed'
            refined['confidence'] = max(refined.get('confidence', 0.0), 0.84)
            refined['details'] = "Camera metadata is preserved; artifacts/software suggest post-capture processing."
            return refined

        if missing_camera and has_structural_reencode:
            refined['primary_origin'] = 'software_reencoded'
            refined['confidence'] = max(refined.get('confidence', 0.0), 0.82)
            if qtable_profile:
                refined['details'] = f"Metadata is limited and quantization signature matches {qtable_profile}; likely software re-encoding."
            else:
                refined['details'] = "Metadata is limited and compression profile indicates software/platform re-encoding."
            return refined

        if missing_camera and not has_software_flag:
            refined['primary_origin'] = 'origin_unverified'
            refined['confidence'] = max(refined.get('confidence', 0.0), 0.70)
            refined['details'] = "Metadata appears removed during export. Editing application cannot be identified."
            return refined

        return refined

    def _build_explain_forensic_reasoning(self, combined_raw, risk_summary, bayesian_findings):
        """Build court-safe, evidence-weighted explain output."""
        flags = combined_raw.get('flags', [])
        origin = combined_raw.get('origin_detection', {})
        context = combined_raw.get('contextual_analysis', {})
        timestamp = combined_raw.get('timestamp_analysis', {})
        artifacts = combined_raw.get('artifact_analysis', {})
        correlation = combined_raw.get('correlation', {})

        origin_label = origin.get('primary_origin', 'unknown')
        features = origin.get('features', {})
        metadata_density = features.get('metadata_density', 0) or 0
        has_camera_make = bool(features.get('has_camera_make'))
        strong_camera_origin = bool(has_camera_make and metadata_density >= 15 and origin_label == 'camera_original')

        has_software_flag = any('software' in str(f).lower() for f in flags)
        has_aspect_flag = any('aspect ratio' in str(f).lower() for f in flags)
        has_compression_flag = any('compression' in str(f).lower() for f in flags)
        ts_issues = timestamp.get('issues', [])
        ctx_issues = context.get('issues', [])

        ela_intensity = artifacts.get('ela_results', {}).get('ela_intensity')
        qtable_sig = artifacts.get('qtable_audit', {}).get('signature_match')

        structural_score = 0
        if ela_intensity == 'HIGH':
            structural_score += 35
        if qtable_sig == 'Software_Modification':
            structural_score += 30
        if has_aspect_flag:
            structural_score += 15
        if has_compression_flag:
            structural_score += 20
        structural_score = min(100, structural_score)

        metadata_score = combined_raw.get('risk_score', 0) or 0
        if strong_camera_origin:
            metadata_score = max(0, metadata_score - 20)
        if has_software_flag:
            metadata_score = min(100, metadata_score + 20)

        temporal_score = 5 if not ts_issues else min(100, 25 + 20 * len(ts_issues))
        synthetic_probability = 95 if origin.get('is_synthetic') or origin_label in {'synthetic_ai_generated', 'ai_generated'} else 5

        reencode_probability = 0
        if has_compression_flag:
            reencode_probability += 30
        if qtable_sig == 'Software_Modification':
            reencode_probability += 35
        if origin_label in {'software_reencoded', 'social_media'}:
            reencode_probability += 25
        if origin_label == 'camera_post_processed':
            reencode_probability += 20
        if has_software_flag:
            reencode_probability += 10
        reencode_probability = min(100, reencode_probability)

        manipulation_likelihood = 0.35 * structural_score + 0.35 * metadata_score + 0.15 * temporal_score + 0.15 * synthetic_probability
        manipulation_likelihood = round(min(100, manipulation_likelihood), 1)

        severity_items = []
        for flag in flags:
            text = str(flag)
            if 'compression' in text.lower() or 'aspect ratio' in text.lower():
                sev = 'MODERATE'
                why = 'Structural/compression indicator; can occur in benign export or platform re-encoding.'
            elif 'software' in text.lower():
                sev = 'MODERATE'
                why = 'Indicates post-capture processing but does not alone prove malicious tampering.'
            else:
                sev = 'LOW'
                why = 'Single-module indicator without corroborating multi-domain contradictions.'
            severity_items.append({'indicator': text, 'severity': sev, 'reason': why})

        if ela_intensity == 'HIGH':
            severity_items.append({
                'indicator': 'HIGH_ELA_VARIANCE',
                'severity': 'MODERATE',
                'reason': 'Compression structure anomaly; non-specific without temporal/contextual or provenance conflicts.'
            })
        if qtable_sig == 'Software_Modification':
            severity_items.append({
                'indicator': 'FOREIGN_QTABLE',
                'severity': 'MODERATE',
                'reason': 'Supports re-save/re-encode hypothesis; not standalone proof of malicious pixel tampering.'
            })

        deterministic_level = risk_summary.get('level', 'LOW')
        bayes_level = bayesian_findings.get('risk_level', 'N/A')
        bayes_score = bayesian_findings.get('predictive_risk_score', 0) or 0
        deterministic_score = risk_summary.get('risk_score', 0) or 0

        conflict = False
        if bayes_level in ['HIGH', 'CRITICAL'] and deterministic_level in ['LOW', 'MEDIUM']:
            conflict = True
        if abs(bayes_score - deterministic_score) >= 35:
            conflict = True

        dominance_factors = []
        if strong_camera_origin:
            dominance_factors.append('Strong camera-origin metadata lowers manipulation probability')
        if not ts_issues:
            dominance_factors.append('No timestamp inconsistencies detected')
        if not ctx_issues:
            dominance_factors.append('No contextual contradictions detected')
        if bayesian_findings.get('evidence_cues_used'):
            dominance_factors.append(f"Bayesian model emphasized cues: {', '.join(bayesian_findings.get('evidence_cues_used', []))}")

        bayes_cues = set(bayesian_findings.get('evidence_cues_used', []))
        structural_only_cues = {'HIGH_ELA_VARIANCE', 'FOREIGN_QTABLE', 'SOFTWARE_SIGNATURE'}
        likely_overweighted = bool(
            bayes_score >= 80 and
            deterministic_score <= 35 and
            bayes_cues and
            bayes_cues.issubset(structural_only_cues) and
            not ts_issues and
            not ctx_issues
        )

        unified_label = 'INCONCLUSIVE'
        if origin_label in {'synthetic_ai_generated', 'ai_generated'} or origin.get('is_synthetic'):
            unified_label = 'SYNTHETIC'
        elif origin_label == 'camera_post_processed' or (strong_camera_origin and not ts_issues and not ctx_issues and reencode_probability >= 60 and manipulation_likelihood < 60):
            unified_label = 'AUTHENTIC_WITH_POST_PROCESSING'
        elif origin_label in {'software_reencoded', 'software_generated'} or (reencode_probability >= 70 and not ts_issues and not ctx_issues and not has_software_flag):
            unified_label = 'REENCODED'
        elif manipulation_likelihood >= 75 and (has_software_flag and (ts_issues or ctx_issues)):
            unified_label = 'LIKELY_MANIPULATED'
        elif manipulation_likelihood >= 55 and has_software_flag:
            unified_label = 'PARTIALLY_MODIFIED'
        elif manipulation_likelihood < 30 and strong_camera_origin and not flags:
            unified_label = 'AUTHENTIC'

        confidence_score = 70
        if conflict:
            confidence_score -= 25
        if strong_camera_origin:
            confidence_score += 10
        if not ts_issues and not ctx_issues:
            confidence_score += 10
        if has_software_flag and not (ts_issues or ctx_issues):
            confidence_score -= 5
        confidence_score = max(0, min(100, confidence_score))
        confidence_index = 'HIGH' if confidence_score >= 75 else 'MODERATE' if confidence_score >= 45 else 'LOW'

        narrative = (
            f"The evidence shows {origin_label.replace('_', ' ')} characteristics with "
            f"{'no' if not ts_issues else 'identified'} temporal inconsistencies and "
            f"{'no' if not ctx_issues else 'identified'} contextual contradictions. "
            f"Structural compression indicators are present, which support post-processing or re-encoding scenarios. "
            f"These structural indicators are not treated as standalone proof of malicious manipulation."
        )
        if origin_label == 'origin_unverified':
            narrative += " Metadata appears removed during export. Editing application cannot be identified."

        simple_verdict = unified_label.replace('_', ' ')
        if unified_label == 'AUTHENTIC_WITH_POST_PROCESSING':
            simple_verdict = "Likely real photo, but saved/processed after capture"
        elif unified_label == 'REENCODED':
            simple_verdict = "Likely re-saved/compressed copy"
        elif unified_label == 'LIKELY_MANIPULATED':
            simple_verdict = "Likely manipulated"
        elif unified_label == 'PARTIALLY_MODIFIED':
            simple_verdict = "Likely modified in parts"
        elif unified_label == 'AUTHENTIC':
            simple_verdict = "Likely original/authentic"
        elif unified_label == 'SYNTHETIC':
            simple_verdict = "Likely AI/synthetic image"
        elif unified_label == 'INCONCLUSIVE':
            simple_verdict = "Not enough evidence for a firm conclusion"

        supports = []
        if strong_camera_origin:
            supports.append("Camera-origin metadata is strong and internally consistent.")
        if not ts_issues:
            supports.append("No timestamp conflicts were detected.")
        if not ctx_issues:
            supports.append("No contextual contradictions were detected.")
        if has_compression_flag or qtable_sig == 'Software_Modification':
            supports.append("Compression/re-save signals indicate post-processing or re-encoding.")

        not_proof = [
            "Compression artifacts alone are not proof of malicious tampering.",
            "No single module is treated as conclusive evidence on its own."
        ]

        return {
            '0_plain_language_summary': {
                'simple_verdict': simple_verdict,
                'plain_confidence': confidence_index,
                'what_supports_this': supports,
                'what_this_does_not_prove': not_proof,
                'recommended_reading': "Use this plain summary first; technical sections below provide supporting detail."
            },
            '1_multi_domain_risk_assessment': {
                'structural_risk': self._score_to_band(structural_score),
                'metadata_integrity_risk': self._score_to_band(metadata_score),
                'temporal_consistency_risk': self._score_to_band(temporal_score),
                'synthetic_probability': self._score_to_band(synthetic_probability),
                'platform_reencoding_probability': self._score_to_band(reencode_probability),
                'unified_manipulation_likelihood': self._score_to_band(manipulation_likelihood)
            },
            '2_evidence_severity_classification': severity_items,
            '3_model_conflict_analysis': {
                'deterministic_aggregation': {
                    'risk_score': deterministic_score,
                    'risk_level': deterministic_level,
                    'interpretation': risk_summary.get('unified_interpretation')
                },
                'bayesian_predictive_model': {
                    'risk_score': bayes_score,
                    'risk_level': bayes_level,
                    'interpretation': bayesian_findings.get('interpretation')
                },
                'conflict_detected': conflict,
                'dominance_factors': dominance_factors
            },
            '4_bayesian_calibration_commentary': {
                'likelihood_overweighted': likely_overweighted,
                'commentary': 'Bayesian structural cues should be interpreted with cross-module agreement; structural artifacts alone are insufficient to assert malicious manipulation.'
            },
            '5_unified_interpretation_improved_classification': unified_label,
            '6_forensic_confidence_index': {
                'level': confidence_index,
                'basis': 'Confidence is derived from cross-module agreement, camera-origin strength, and deterministic-vs-probabilistic consistency.'
            },
            '7_narrative_forensic_summary': narrative
        }

    def _build_assist_suggestions(self, combined_raw, risk_summary):
        """Build analyst-augmentation suggestions for assist mode."""
        flags = combined_raw.get('flags', [])
        origin = combined_raw.get('origin_detection', {})
        features = origin.get('features', {})
        timestamp = combined_raw.get('timestamp_analysis', {})
        artifacts = combined_raw.get('artifact_analysis', {})

        strong_camera_metadata = bool(
            origin.get('primary_origin') == 'camera_original'
            and bool(features.get('has_camera_make'))
            and (features.get('metadata_density', 0) or 0) >= 15
        )
        no_temporal_issues = len(timestamp.get('issues', [])) == 0

        structural_finding = "No strong structural anomaly pattern detected."
        if artifacts.get('ela_results', {}).get('ela_intensity') == 'HIGH' or artifacts.get('qtable_audit', {}).get('signature_match') == 'Software_Modification':
            structural_finding = "Image exhibits compression artifacts consistent with software re-encoding."

        interpretation = "No independent evidence of metadata or temporal manipulation."
        if any('software' in str(f).lower() for f in flags):
            interpretation = "Possible post-processing detected. No independent evidence of metadata or temporal manipulation."
        if not no_temporal_issues:
            interpretation = "Temporal inconsistencies detected and require analyst verification before conclusion."

        suggested_risk = "Low to Moderate (Analyst confirmation required)"
        if not strong_camera_metadata and not no_temporal_issues:
            suggested_risk = "Moderate (Analyst confirmation required)"

        follow_up = [
            "Perform clone detection on suspicious regions.",
            "Inspect flagged regions visually at high zoom.",
            "Verify source acquisition chain and transfer history."
        ]

        return {
            'mode': 'assist',
            'suggested_structural_finding': structural_finding,
            'suggested_interpretation': interpretation,
            'suggested_risk_level': suggested_risk,
            'suggested_follow_up': follow_up,
            'final_decision': 'Pending Analyst Confirmation',
            'assist_governance': {
                'ai_role': 'Analyst augmentation only',
                'ai_does_not': [
                    'Issue final classification',
                    'Assign definitive risk labels',
                    'Override rule-based validation'
                ]
            }
        }

    def _build_modification_history(
        self,
        metadata: Dict[str, Any],
        origin_results: Dict[str, Any],
        auth_results: Dict[str, Any],
        timestamp_results: Dict[str, Any],
        artifact_findings: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build a concise, evidence-based modification history summary."""
        summary = metadata.get('summary', {})
        exif = metadata.get('exif', {})
        xmp = metadata.get('xmp', {})
        file_info = metadata.get('file_info', {})

        if not isinstance(summary, dict):
            summary = {}
        if not isinstance(exif, dict):
            exif = {}
        if not isinstance(xmp, dict):
            xmp = {}
        if not isinstance(file_info, dict):
            file_info = {}

        software_fields = origin_results.get('features', {}).get('software_fields', {}) or {}
        software_list: List[str] = []
        for value in list(software_fields.values()) + list(summary.get('software_candidates', []) or []):
            normalized = str(value).strip() if value else ""
            if normalized and normalized not in software_list:
                software_list.append(normalized)

        capture_time = summary.get('datetime_original')
        digitized_time = (
            exif.get('EXIF DateTimeDigitized')
            or exif.get('DateTimeDigitized')
            or xmp.get('DateTimeDigitized')
        )
        file_modified_time = file_info.get('File Modification Date/Time')

        xmp_history_entries: List[str] = []
        for key, value in xmp.items():
            key_l = str(key).lower()
            if "history" in key_l or "edit" in key_l:
                xmp_history_entries.append(f"{key}: {value}")

        origin_label = origin_results.get('primary_origin', 'origin_unverified')
        flags = auth_results.get('flags', []) or []
        ts_issues = timestamp_results.get('issues', []) or []
        qtable_audit = artifact_findings.get('qtable_audit', {}) if isinstance(artifact_findings, dict) else {}
        ela_results = artifact_findings.get('ela_results', {}) if isinstance(artifact_findings, dict) else {}

        events: List[Dict[str, Any]] = []
        if capture_time:
            events.append({
                'event': 'original_capture_time',
                'timestamp': capture_time,
                'source': 'metadata',
                'confidence': 'high',
                'details': 'Original capture timestamp present in metadata.'
            })
        if digitized_time:
            events.append({
                'event': 'digitized_or_saved_time',
                'timestamp': digitized_time,
                'source': 'metadata',
                'confidence': 'medium',
                'details': 'Digitized/save timestamp detected in metadata.'
            })
        if file_modified_time:
            events.append({
                'event': 'filesystem_modified_time',
                'timestamp': file_modified_time,
                'source': 'filesystem',
                'confidence': 'medium',
                'details': 'Filesystem modification timestamp recorded for current file.'
            })
        if software_list:
            events.append({
                'event': 'software_detected',
                'timestamp': None,
                'source': 'metadata',
                'confidence': 'medium',
                'details': f"Software markers detected: {', '.join(software_list[:5])}"
            })
        for entry in xmp_history_entries[:8]:
            events.append({
                'event': 'xmp_history_entry',
                'timestamp': None,
                'source': 'xmp',
                'confidence': 'medium',
                'details': entry
            })
        if qtable_audit.get('signature_match') == 'Software_Modification':
            events.append({
                'event': 'software_reencoding_indicated',
                'timestamp': None,
                'source': 'artifact_analysis',
                'confidence': 'medium',
                'details': 'Quantization table signature suggests software modification or re-save.'
            })
        if ela_results.get('ela_intensity') == 'HIGH':
            events.append({
                'event': 'high_structural_variance_detected',
                'timestamp': None,
                'source': 'artifact_analysis',
                'confidence': 'low',
                'details': 'ELA variance may indicate localized edits or aggressive recompression.'
            })

        likely_modified = bool(
            software_list
            or xmp_history_entries
            or origin_label in {'camera_post_processed', 'software_reencoded', 'software_generated'}
            or any('software' in str(flag).lower() for flag in flags)
            or qtable_audit.get('signature_match') == 'Software_Modification'
        )

        status = 'likely_modified' if likely_modified else 'no_clear_modification_history'
        if origin_label == 'camera_original' and not software_list and not xmp_history_entries:
            status = 'appears_original'
        confidence = 'high' if xmp_history_entries or software_list else 'medium' if likely_modified else 'low'

        summary_parts = []
        if capture_time:
            summary_parts.append(f"Original capture timestamp: {capture_time}.")
        if software_list:
            summary_parts.append(f"Software evidence: {', '.join(software_list[:3])}.")
        if xmp_history_entries:
            summary_parts.append("XMP history/edit markers were found.")
        if origin_label in {'camera_post_processed', 'software_reencoded', 'software_generated'}:
            summary_parts.append(f"Origin assessment indicates {origin_label.replace('_', ' ')}.")
        if ts_issues:
            summary_parts.append(f"Timestamp issues: {'; '.join(ts_issues[:3])}.")
        if not summary_parts:
            summary_parts.append("No explicit edit-history metadata was found; only limited forensic inference is available.")

        return {
            'status': status,
            'confidence': confidence,
            'likely_modified': likely_modified,
            'original_capture_time': capture_time,
            'digitized_time': digitized_time,
            'file_modified_time': file_modified_time,
            'software_detected': software_list,
            'xmp_history_entries': xmp_history_entries,
            'origin_assessment': origin_label,
            'timestamp_issues': ts_issues,
            'forensic_flags': flags,
            'events': events,
            'summary': " ".join(summary_parts)
        }

    def analyze_image(self, image_path, case_info=None, ai_mode='explain'):
        """
        Perform complete forensic analysis on an image.
        
        Args:
            image_path: Path to the image file
            case_info: Dictionary containing case information
            ai_mode: Explain mode
        
        Returns:
            Dictionary containing complete analysis results
        """
        try:
            self.logger.info(f"Starting forensic analysis of: {image_path}")
            self.chain_of_custody.log_event("ANALYSIS_STARTED", {
                "image_path": image_path,
                "case_info": case_info or {},
                "timestamp": datetime.now().isoformat()
            })
            
            # Step 1: Evidence integrity verification
            self.logger.info("Step 1: Verifying evidence integrity...")
            integrity_info = self.evidence_handler.process_evidence(image_path)
            
            if not integrity_info['verified']:
                self.logger.error("Evidence integrity verification failed")
                raise ValueError("Evidence integrity check failed")
            
            # Step 2: Metadata Extraction (Goal 1)
            self.logger.info("Step 2: Performing comprehensive metadata extraction...")
            extracted_metadata = self.metadata_extractor.extract(image_path)
            
            # Step 3: Origin Detection (Goals 3, 4, 6)
            origin_results = {'primary_origin': 'rule_only', 'confidence': 0.0, 'details': 'AI origin detector disabled in strict mode'}
            if ai_mode != 'strict':
                self.logger.info("Step 3: Detecting image origin (AI / Social Media / Screenshot)...")
                origin_results = self.origin_detector.detect(extracted_metadata, image_path=image_path)
            else:
                self.logger.info("Step 3: Skipped AI origin detection (strict mode)")
            
            # Step 4: Metadata Authenticity Analysis (Goal 1 & 2)
            self.logger.info("Step 4: Analyzing metadata authenticity and tampering...")
            auth_results = self.forensic_analyzer.analyze(
                metadata=extracted_metadata,
                image_path=image_path,
                case_info=case_info
            )
            
            # Step 5: Contextual Analysis (Goal 7)
            self.logger.info("Step 5: Validating GPS and scene consistency...")
            context_results = self.contextual_analyzer.analyze(extracted_metadata, image_path=image_path)
            
            # Step 5.5: Timestamp Consistency Analysis (Refinement)
            self.logger.info("Step 5.5: Performing deep chronological audit...")
            timestamp_results = self.timestamp_analyzer.analyze(extracted_metadata)
            
            # Step 5.8: Deep Artifact Analysis (Advanced Point 14)
            artifact_findings = {}
            if ai_mode != 'strict':
                self.logger.info("Step 5.8: Performing ELA and Quantization Table audit...")
                artifact_findings = self.artifact_analyzer.analyze(image_path)
            else:
                self.logger.info("Step 5.8: Skipped artifact AI-assisted analysis (strict mode)")

            # Refine origin class with artifact + metadata consistency evidence.
            origin_results = self._refine_origin_with_artifacts(
                origin_results=origin_results,
                metadata=extracted_metadata,
                artifact_findings=artifact_findings,
                auth_results=auth_results
            )
            
            # Step 5.9: Evidence Correlation (Point 9)
            self.logger.info("Step 5.9: Correlating multi-source findings...")
            correlation_results = self.evidence_correlator.correlate(
                ml_results=origin_results,
                rule_results=auth_results,
                stat_results=timestamp_results
            )
            
            # Step 6: Unified Risk Scoring (Point 10)
            self.logger.info("Step 6: Calculating unified evidence risk score...")
            
            # Combine intermediate results for scorer
            combined_raw = {
                **auth_results,
                'metadata': extracted_metadata,
                'domains': extracted_metadata.get('domains', {}),
                'origin_detection': origin_results,
                'contextual_analysis': context_results,
                'timestamp_analysis': timestamp_results,
                'artifact_analysis': artifact_findings,
                'correlation': correlation_results
            }
            
            risk_summary = self.risk_scorer.score(combined_raw)
            
            # Step 6.5: Bayesian Predictive Intelligence (Advanced Point 15)
            bayesian_findings = {
                'predictive_risk_score': 0,
                'risk_level': 'N/A',
                'prior_probability': 0,
                'evidence_cues_used': [],
                'interpretation': 'Bayesian scorer disabled in strict mode'
            }
            if ai_mode != 'strict':
                self.logger.info("Step 6.5: Calculating predictive Bayesian risk...")
                bayesian_findings = self.bayesian_scorer.calculate_risk(combined_raw)
            else:
                self.logger.info("Step 6.5: Skipped Bayesian predictive scoring (strict mode)")
            
            # Step 6.8: Cross-Case Evidentiary Correlation (Advanced Point 16)
            cross_case_links = {'has_cross_links': False, 'evidentiary_links': [], 'summary': 'Cross-case AI correlation disabled in strict mode'}
            if ai_mode != 'strict':
                self.logger.info("Step 6.8: Identifying links to historical cases...")
                cross_case_links = self.cross_case_correlator.correlate(combined_raw)
            else:
                self.logger.info("Step 6.8: Skipped cross-case correlation (strict mode)")
            
            # Combined analysis for explanations (including cross-case links)
            combined_analysis = {**combined_raw, 'cross_case_links': cross_case_links}
            
            # Step 7: Confidence Explanation Engine (Goal 9)
            self.logger.info("Step 7: Generating human-readable forensic explanations (XAI)...")
            explanations = self.explanation_engine.explain(combined_analysis)
            
            # Final Result Construction
            self.analysis_results = {
                **combined_raw,
                'metadata': extracted_metadata,
                'risk_assessment': risk_summary,
                'bayesian_risk': bayesian_findings,
                'cross_case_analysis': cross_case_links,
                'explanations': explanations,
                'ai_mode': ai_mode,
                'evidence_integrity': integrity_info,
                'modification_history': self._build_modification_history(
                    metadata=extracted_metadata,
                    origin_results=origin_results,
                    auth_results=auth_results,
                    timestamp_results=timestamp_results,
                    artifact_findings=artifact_findings,
                ),
                'analysis_timestamp': datetime.now().isoformat()
            }

            if ai_mode == 'assist':
                self.analysis_results['analyst_confirmation'] = {
                    'required': True,
                    'status': 'pending',
                    'message': 'AI findings are suggestions until analyst confirms.'
                }
                self.analysis_results['assist_suggestions'] = self._build_assist_suggestions(
                    combined_raw=combined_raw,
                    risk_summary=risk_summary
                )

            if ai_mode == 'explain':
                self.analysis_results['explainability_breakdown'] = self._build_explainability_breakdown(
                    combined_raw=combined_raw,
                    risk_summary=risk_summary,
                    bayesian_findings=bayesian_findings,
                    explanations=explanations
                )
                self.analysis_results['explain_forensic_reasoning'] = self._build_explain_forensic_reasoning(
                    combined_raw=combined_raw,
                    risk_summary=risk_summary,
                    bayesian_findings=bayesian_findings
                )
            
            self.logger.info("16-Point Forensic Workflow completed successfully")
            self.chain_of_custody.log_event("ANALYSIS_COMPLETED", {
                "image_path": image_path,
                "risk_score": risk_summary.get('risk_score'),
                "timestamp": datetime.now().isoformat()
            })
            
            return self.analysis_results
            
        except Exception as e:
            self.logger.error(f"13-Point Forensic Workflow failed: {e}")
            self.chain_of_custody.log_event("ANALYSIS_FAILED", {
                "image_path": image_path,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
            raise
    
    def interactive_analysis(self):
        """Launch interactive CLI assistant."""
        if not self.analysis_results:
            print("No analysis results available. Run analyze_image() first.")
            return
        
        # Lazy load CLI assistant to avoid circular dependencies if it grows
        from .interface.cli_assistant import ForensicCLIAssistant

        self.cli_assistant = ForensicCLIAssistant(
            analysis_results=self.analysis_results,
            forensic_system=self
        )
        self.cli_assistant.start_session()
    
    def generate_reports(self, output_dir=None, formats=None):
        """
        Generate forensic reports.
        
        Args:
            output_dir: Directory to save reports (optional)
            formats: List of formats ['pdf', 'json', 'html'] (optional)
        
        Returns:
            Dictionary of generated report paths
        """
        if not self.analysis_results:
            raise ValueError("No analysis results available. Run analyze_image() first.")
        
        formats = formats or self.config['reporting'].get('formats', ['pdf', 'json'])
        output_dir = output_dir or self.config['reporting'].get('output_dir', './results/reports')
        
        self.logger.info(f"Generating reports in formats: {formats}")
        
        reports = self.report_generator.generate(
            analysis_results=self.analysis_results,
            output_dir=output_dir,
            formats=formats
        )
        
        self.chain_of_custody.log_event("REPORTS_GENERATED", {
            "formats": formats,
            "output_dir": output_dir,
            "report_files": reports,
            "timestamp": datetime.now().isoformat()
        })
        
        return reports
    
    def batch_analyze(self, image_dir, output_dir=None, max_images=None, ai_mode='explain', report_formats=None, include_raw=False):
        """
        Analyze multiple images in batch mode.
        
        Args:
            image_dir: Directory containing images
            output_dir: Output directory for reports
            max_images: Maximum number of images to process
            ai_mode: Explain mode
            report_formats: List of report formats to generate per image
            include_raw: Include investigative raw metadata sections in reports
        
        Returns:
            List of analysis results
        """
        from pathlib import Path
        import concurrent.futures
        import tqdm
        
        image_dir = Path(image_dir)
        if not image_dir.is_dir():
            raise ValueError(f"Not a directory: {image_dir}")
        
        # Find image files
        image_patterns = ['*.jpg', '*.jpeg', '*.png', '*.tiff', '*.tif', 
                         '*.bmp', '*.gif', '*.webp', '*.cr2', '*.nef']
        
        image_files = []
        for pattern in image_patterns:
            image_files.extend(image_dir.rglob(pattern))
        
        if max_images:
            image_files = image_files[:max_images]
        
        self.logger.info(f"Found {len(image_files)} images for batch analysis")
        
        results = []
        successful = 0
        failed = 0
        
        # Process images with progress bar
        with tqdm.tqdm(total=len(image_files), desc="Batch Analysis", unit="image") as pbar:
            for img_file in image_files:
                try:
                    self.logger.debug(f"Analyzing: {img_file.name}")
                    
                    # Create case info based on filename
                    case_info = {
                        'image_filename': img_file.name,
                        'batch_id': f"BATCH_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        'analyst': 'batch_processor'
                    }
                    
                    # Analyze image
                    result = self.analyze_image(str(img_file), case_info, ai_mode=ai_mode)
                    result['include_raw'] = include_raw
                    self.analysis_results = result
                    results.append(result)
                    successful += 1
                    
                    # Generate report for this image in a unique per-file directory.
                    # Include relative parent path and extension to avoid collisions
                    # when different files share the same stem.
                    rel_path = img_file.relative_to(image_dir)
                    ext_label = img_file.suffix.lstrip('.').lower() or 'img'
                    img_output_dir = (
                        Path(output_dir or './results/batch_reports')
                        / rel_path.parent
                        / f"{img_file.stem}_{ext_label}"
                    )
                    if report_formats is None or report_formats:
                        self.generate_reports(output_dir=str(img_output_dir), formats=report_formats)
                    
                except Exception as e:
                    self.logger.error(f"Failed to analyze {img_file}: {e}")
                    failed += 1
                    results.append({
                        'image_path': str(img_file),
                        'error': str(e),
                        'status': 'FAILED'
                    })
                
                pbar.update(1)
                pbar.set_postfix({
                    'success': successful,
                    'failed': failed
                })
        
        # Generate batch summary report
        batch_summary = {
            'batch_id': f"BATCH_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'total_images': len(image_files),
            'successful_analyses': successful,
            'failed_analyses': failed,
            'analysis_timestamp': datetime.now().isoformat(),
            'image_directory': str(image_dir.absolute()),
            'individual_results': results
        }
        
        # Save batch summary
        summary_file = Path(output_dir or './results/batch_reports') / 'batch_summary.json'
        summary_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(summary_file, 'w') as f:
            json.dump(batch_summary, f, indent=2)
        
        self.logger.info(f"Batch analysis complete. Success: {successful}/{len(image_files)}")
        self.chain_of_custody.log_event("BATCH_ANALYSIS_COMPLETED", batch_summary)
        
        return batch_summary
    
    def compare_images(self, image_paths, comparison_type='metadata', ai_mode='explain', precomputed_results=None):
        """
        Compare multiple images for forensic analysis.
        
        Args:
            image_paths: List of image file paths
            comparison_type: Type of comparison ('metadata', 'timestamps', 'origin')
            ai_mode: Explain mode
            precomputed_results: Optional pre-analyzed results to avoid re-processing
        
        Returns:
            Comparison results
        """
        if len(image_paths) < 2:
            raise ValueError("At least 2 images required for comparison")
        
        self.logger.info(f"Comparing {len(image_paths)} images ({comparison_type})")
        
        analysis_results = precomputed_results or []
        if not analysis_results:
            for img_path in image_paths:
                try:
                    result = self.analyze_image(img_path, ai_mode=ai_mode)
                    analysis_results.append(result)
                except Exception as e:
                    self.logger.warning(f"Failed to analyze {img_path}: {e}")
                    analysis_results.append({
                        'image_path': img_path,
                        'error': str(e),
                        'status': 'FAILED'
                    })
        
        # Perform comparison based on type
        comparison_results = self._perform_comparison(
            analysis_results=analysis_results,
            comparison_type=comparison_type
        )
        
        return comparison_results
    
    def _perform_comparison(self, analysis_results, comparison_type):
        """Perform specific type of comparison on analysis results."""
        comparison = {
            'comparison_type': comparison_type,
            'compared_images': len([r for r in analysis_results if 'error' not in r]),
            'timestamp': datetime.now().isoformat(),
            'results': {}
        }
        
        if comparison_type == 'metadata':
            comparison['results'] = self._compare_metadata(analysis_results)
        elif comparison_type == 'timestamps':
            comparison['results'] = self._compare_timestamps(analysis_results)
        elif comparison_type == 'origin':
            comparison['results'] = self._compare_origins(analysis_results)
        else:
            comparison['results'] = {'error': f'Unknown comparison type: {comparison_type}'}
        
        return comparison
    
    def _compare_metadata(self, analysis_results):
        """Compare metadata across multiple images."""
        comparison = {}
        valid_results = [r for r in analysis_results if 'error' not in r]
        
        for i, result in enumerate(valid_results):
            metadata = result.get('metadata', {}).get('summary', {})
            comparison[f'image_{i}'] = {
                'filename': Path(result.get('evidence_integrity', {}).get('file_path', '')).name,
                'camera': metadata.get('camera_make', 'Unknown'),
                'timestamp': metadata.get('datetime_original', 'Unknown'),
                'dimensions': metadata.get('dimensions', 'Unknown')
            }
        
        return comparison
    
    def _compare_timestamps(self, analysis_results):
        """Compare timestamps across multiple images."""
        comparison = {
            'timestamps': [],
            'time_differences': {},
            'chronological_order': []
        }
        
        valid_results = [r for r in analysis_results if 'error' not in r]
        
        # Extract timestamps
        timestamps = []
        for result in valid_results:
            metadata = result.get('metadata', {}).get('summary', {})
            ts = metadata.get('datetime_original')
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    timestamps.append((dt, result))
                except:
                    pass
        
        # Sort chronologically
        timestamps.sort(key=lambda x: x[0])
        comparison['chronological_order'] = [
            {
                'timestamp': ts.isoformat(),
                'filename': Path(r.get('evidence_integrity', {}).get('file_path', '')).name
            }
            for ts, r in timestamps
        ]
        
        # Calculate time differences
        if len(timestamps) >= 2:
            for i in range(len(timestamps)-1):
                ts1, r1 = timestamps[i]
                ts2, r2 = timestamps[i+1]
                diff = (ts2 - ts1).total_seconds()
                
                comparison['time_differences'][f'image_{i}_to_{i+1}'] = {
                    'difference_seconds': diff,
                    'difference_human': f"{diff:.1f} seconds",
                    'from': Path(r1.get('evidence_integrity', {}).get('file_path', '')).name,
                    'to': Path(r2.get('evidence_integrity', {}).get('file_path', '')).name
                }
        
        return comparison
    
    def _compare_origins(self, analysis_results):
        """Compare origins across multiple images."""
        comparison = {
            'origins': {},
            'consistency': 'mixed'
        }
        
        origins = []
        for result in analysis_results:
            origin = result.get('origin_detection', {}).get('primary_origin', 'Unknown')
            origins.append(origin)
            comparison['origins'][Path(result.get('evidence_integrity', {}).get('file_path', '')).name] = origin
        
        # Check consistency
        if len(set(origins)) == 1:
            comparison['consistency'] = 'consistent'
        else:
            comparison['consistency'] = 'inconsistent'
        
        return comparison
    
    def get_system_info(self):
        """Get system information and status."""
        return {
            'system': {
                'name': 'MetaForensicAI',
                'version': '1.0.0',
                'status': 'operational',
                'timestamp': datetime.now().isoformat()
            },
            'components': {
                'evidence_handler': self.evidence_handler.__class__.__name__,
                'metadata_extractor': self.metadata_extractor.__class__.__name__,
                'forensic_analyzer': self.forensic_analyzer.__class__.__name__,
                'origin_detector': self.origin_detector.__class__.__name__
            },
            'config': {
                'forensic_mode': self.config['forensic']['read_only'],
                'analysis_modules': list(self.config['analysis'].keys()),
                'reporting_formats': self.config['reporting'].get('formats', ['pdf', 'json'])
            }
        }


def _extract_device_signature(result: Dict[str, Any]) -> Dict[str, Any]:
    """Extract device-identifying metadata fields for cross-image comparison."""
    metadata = result.get('metadata', {})
    summary = metadata.get('summary', {}) if isinstance(metadata.get('summary', {}), dict) else {}
    exif = metadata.get('exif', {}) if isinstance(metadata.get('exif', {}), dict) else {}

    make = summary.get('camera_make') or exif.get('EXIF Make') or exif.get('Make')
    model = summary.get('camera_model') or exif.get('EXIF Model') or exif.get('Model')
    serial = (
        exif.get('EXIF BodySerialNumber')
        or exif.get('EXIF SerialNumber')
        or exif.get('SerialNumber')
        or exif.get('MakerNotes SerialNumber')
    )

    return {
        'make': make,
        'model': model,
        'serial': serial,
        'signature': f"{make}|{model}|{serial}"
    }


def _qa_response(question: str, intent: str, answer: str, confidence_percent: int, domains: List[str], summary: str, evidence: List[str], per_image_metadata: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    """Standardize forensic Q&A response schema."""
    cp = max(0, min(100, int(confidence_percent)))
    if cp >= 75:
        level = 'High'
    elif cp >= 45:
        level = 'Moderate'
    else:
        level = 'Low'
    out = {
        'question': question,
        'intent': intent,
        'answer': answer,  # YES / NO / INCONCLUSIVE
        'confidence_percent': cp,
        'confidence_level': level,
        'reasoning': summary,
        'evidence_domains_used': domains,
        'evidence_used': domains,
        'evidence_domains': domains,
        'reasoning_summary': summary,
        'evidence': evidence
    }
    if per_image_metadata:
        out['per_image_metadata'] = per_image_metadata
    return out


def _detect_model_conflict(result: Dict[str, Any]) -> str | None:
    """Detect high-level conflict between deterministic and Bayesian outputs."""
    deterministic = result.get('risk_assessment', {})
    bayesian = result.get('bayesian_risk', {})
    d_level = str(deterministic.get('level', '')).upper()
    b_level = str(bayesian.get('risk_level', '')).upper()
    d_score = float(deterministic.get('risk_score', 0) or 0)
    b_score = float(bayesian.get('predictive_risk_score', 0) or 0)
    if (d_level in ['LOW', 'MEDIUM'] and b_level in ['HIGH', 'CRITICAL']) or abs(d_score - b_score) >= 35:
        return f"Model conflict: deterministic risk={d_level} ({d_score:.1f}) vs Bayesian risk={b_level} ({b_score:.1f})."
    return None


def _apply_conflict_note(response: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    """Append explicit conflict note for Ask mode decisions when present."""
    note = _detect_model_conflict(result)
    if not note:
        return response
    response['reasoning'] = f"{response.get('reasoning', '')} {note}".strip()
    response['reasoning_summary'] = response['reasoning']
    response.setdefault('evidence', [])
    response.setdefault('evidence_used', [])
    response['evidence'].append(note)
    response['evidence_used'] = response['evidence']
    if 'cross_module_correlation' not in response.get('evidence_domains_used', []):
        response['evidence_domains_used'].append('cross_module_correlation')
        response['evidence_domains'] = response['evidence_domains_used']
    return response


def _evaluate_edit_detection(result: Dict[str, Any], question: str, intent: str) -> Dict[str, Any]:
    flags = result.get('flags', [])
    correlation = result.get('correlation', {})
    interpretation = correlation.get('unified_interpretation', 'UNKNOWN')
    artifacts = result.get('artifact_analysis', {})
    qtable_sig = artifacts.get('qtable_audit', {}).get('signature_match')
    ela_level = artifacts.get('ela_results', {}).get('ela_intensity')
    ts_issues = result.get('timestamp_analysis', {}).get('issues', [])

    evidence = []
    if any('software' in str(f).lower() for f in flags):
        evidence.append("Software signature suggests post-capture processing.")
    if qtable_sig == 'Software_Modification':
        evidence.append("Quantization profile matches software re-save behavior.")
    if ela_level == 'HIGH':
        evidence.append("High ELA variance detected in structural compression artifacts.")
    if ts_issues:
        evidence.append("Timestamp anomalies detected.")
    if interpretation in ['MANIPULATED_CONTENT', 'INCONSISTENT_EVIDENCE']:
        evidence.append(f"Deterministic interpretation: {interpretation}.")

    if not evidence:
        return _qa_response(question, intent, 'NO', 70, ['metadata', 'structural', 'temporal'], "No corroborated manipulation indicators were found.", ["No strong edit/tamper indicators present."])

    # structural-only signals should not yield definitive malicious conclusion
    structural_only = len(evidence) > 0 and not any('Timestamp anomalies' in e or 'Deterministic interpretation' in e for e in evidence)
    if structural_only:
        return _qa_response(question, intent, 'INCONCLUSIVE', 65, ['structural', 'metadata'], "Artifacts indicate possible post-processing/re-encoding, but not definitive malicious tampering.", evidence)

    return _qa_response(question, intent, 'YES', 78, ['metadata', 'structural', 'temporal', 'correlation'], "Multiple domains support probable modification.", evidence)


def _evaluate_gps(result: Dict[str, Any], question: str, intent: str) -> Dict[str, Any]:
    metadata = result.get('metadata', {})
    exif = metadata.get('exif', {}) if isinstance(metadata.get('exif', {}), dict) else {}
    context = result.get('contextual_analysis', {})
    issues = context.get('issues', [])
    findings = context.get('findings', {})

    has_gps = bool(exif.get('GPS GPSLatitude') and exif.get('GPS GPSLongitude'))
    if not has_gps:
        return _qa_response(question, intent, 'INCONCLUSIVE', 40, ['gps', 'metadata'], "GPS coordinates are not present, so credibility cannot be validated.", ["No GPS latitude/longitude present in metadata."])

    gps_issues = [i for i in issues if 'GPS' in str(i) or 'Null Island' in str(i) or 'spoof' in str(i).lower()]
    gps_trustworthy = findings.get('gps_trustworthy', len(gps_issues) == 0)
    if gps_trustworthy:
        return _qa_response(question, intent, 'YES', 75, ['gps', 'contextual', 'metadata'], "GPS fields are present with no spoofing indicators detected.", ["GPS coordinates present.", "No GPS spoofing indicators detected."])

    return _qa_response(question, intent, 'NO', 82, ['gps', 'contextual', 'metadata'], "GPS integrity anomalies were detected.", gps_issues or ["GPS spoofing indicators detected."])


def _evaluate_same_device(results: List[Dict[str, Any]], question: str, intent: str) -> Dict[str, Any]:
    signatures = []
    per_image = []
    for result in results:
        sig = _extract_device_signature(result)
        filename = Path(result.get('evidence_integrity', {}).get('file_path', '')).name or 'unknown'
        signatures.append(sig['signature'])
        per_image.append({
            'file': filename,
            'make': sig['make'] or 'Unknown',
            'model': sig['model'] or 'Unknown',
            'serial': sig['serial'] or 'Unknown'
        })

    non_unknown = [s for s in signatures if 'None' not in s]
    if len(results) < 2:
        return _qa_response(question, intent, 'INCONCLUSIVE', 30, ['device_attribution', 'metadata'], "At least two files are required for cross-file device attribution.", ["Insufficient file count."], per_image)
    if non_unknown and len(set(non_unknown)) == 1:
        return _qa_response(question, intent, 'YES', 90, ['device_attribution', 'metadata', 'cross_file'], "Device signatures are consistent across files.", ["Camera make/model/serial signatures match across images."], per_image)
    if any('Unknown' in f"{p['make']}|{p['model']}|{p['serial']}" for p in per_image):
        return _qa_response(question, intent, 'INCONCLUSIVE', 45, ['device_attribution', 'metadata'], "One or more files lack reliable device signatures.", ["Incomplete make/model/serial fields in one or more files."], per_image)
    return _qa_response(question, intent, 'NO', 88, ['device_attribution', 'metadata', 'cross_file'], "Device signatures conflict across files.", ["Device signatures differ across compared images."], per_image)

def _evaluate_device_signature_single(result: Dict[str, Any], question: str, intent: str) -> Dict[str, Any]:
    """Evaluate camera/device signature from a single image without cross-file requirement."""
    sig = _extract_device_signature(result)
    filename = Path(result.get('evidence_integrity', {}).get('file_path', '')).name or 'unknown'
    per_image = [{
        'file': filename,
        'make': sig['make'] or 'Unknown',
        'model': sig['model'] or 'Unknown',
        'serial': sig['serial'] or 'Unknown'
    }]

    has_make_model = bool(sig.get('make') and sig.get('model'))
    has_serial = bool(sig.get('serial'))
    if has_make_model and has_serial:
        return _qa_response(
            question, intent, 'YES', 82, ['device_attribution', 'metadata'],
            "Camera make/model/serial signature is present in metadata.",
            [f"Detected signature: {sig.get('make')} | {sig.get('model')} | {sig.get('serial')}"],
            per_image
        )
    if has_make_model:
        return _qa_response(
            question, intent, 'INCONCLUSIVE', 62, ['device_attribution', 'metadata'],
            "Camera make/model are present, but serial is missing so attribution is partial.",
            [f"Detected make/model: {sig.get('make')} | {sig.get('model')}", "Serial number unavailable."],
            per_image
        )
    return _qa_response(
        question, intent, 'INCONCLUSIVE', 35, ['device_attribution', 'metadata'],
        "Device signature fields are missing or stripped in this image metadata.",
        ["Camera make/model/serial not found."],
        per_image
    )


def _evaluate_timestamp(result: Dict[str, Any], question: str, intent: str) -> Dict[str, Any]:
    ts = result.get('timestamp_analysis', {})
    issues = ts.get('issues', [])
    if not issues:
        return _qa_response(question, intent, 'YES', 85, ['temporal', 'metadata'], "Timestamp audit shows internal consistency.", ["DateTimeOriginal and related fields are consistent."])
    return _qa_response(question, intent, 'NO', 82, ['temporal', 'metadata'], "Timestamp anomalies suggest timeline inconsistency.", issues)


def _evaluate_synthetic(result: Dict[str, Any], question: str, intent: str) -> Dict[str, Any]:
    origin = result.get('origin_detection', {})
    label = origin.get('primary_origin', 'unknown')
    if origin.get('is_synthetic') or label in {'synthetic_ai_generated', 'ai_generated'}:
        return _qa_response(question, intent, 'YES', 90, ['origin', 'metadata'], "Origin classifier indicates synthetic generation.", [f"Origin classification: {label}.", origin.get('details', 'Synthetic indicators detected.')])
    if label in {'software_reencoded', 'software_generated', 'camera_post_processed', 'origin_unverified'}:
        return _qa_response(question, intent, 'NO', 72, ['origin', 'metadata'], "Evidence indicates processing/re-encoding or unverified origin, not conclusive AI synthesis.", [f"Origin classification: {label}.", origin.get('details', 'No explicit AI provenance indicators detected.')])
    if label == 'camera_original':
        return _qa_response(question, intent, 'NO', 80, ['origin', 'metadata'], "Origin classifier favors camera-captured content.", [origin.get('details', 'Camera-origin indicators present.')])
    return _qa_response(question, intent, 'INCONCLUSIVE', 55, ['origin', 'metadata'], "Synthetic status cannot be confirmed from current signals.", [f"Origin classification: {label}."])


def _evaluate_reencoding(result: Dict[str, Any], question: str, intent: str) -> Dict[str, Any]:
    flags = result.get('flags', [])
    artifacts = result.get('artifact_analysis', {})
    origin = result.get('origin_detection', {})
    label = origin.get('primary_origin', 'unknown')
    qtable_sig = artifacts.get('qtable_audit', {}).get('signature_match')
    has_compression_flag = any('compression' in str(f).lower() for f in flags)
    evidence = []
    if label in {'software_reencoded', 'camera_post_processed'}:
        evidence.append(f"Origin classification indicates post-capture processing: {label}.")
    if has_compression_flag:
        evidence.append("Compression-related rule flags are present.")
    if qtable_sig == 'Software_Modification':
        evidence.append("Quantization profile suggests software re-encoding.")
    if evidence:
        return _qa_response(question, intent, 'YES', 78, ['structural', 'compression', 'metadata'], "Signals are consistent with re-encoding/post-save processing.", evidence)
    return _qa_response(question, intent, 'INCONCLUSIVE', 50, ['structural', 'compression'], "No direct re-encoding signature was found.", ["No strong compression lineage indicators found."])


def _evaluate_camera_origin(result: Dict[str, Any], question: str, intent: str) -> Dict[str, Any]:
    origin = result.get('origin_detection', {})
    label = origin.get('primary_origin', 'unknown')
    if label in ['camera_original', 'camera_post_processed']:
        return _qa_response(question, intent, 'YES', 85, ['origin', 'metadata'], "Camera signatures are present; image may still be post-processed.", [origin.get('details', 'Camera-origin indicators detected.')])
    if label in ['synthetic_ai_generated', 'ai_generated', 'software_reencoded', 'software_generated', 'origin_unverified']:
        return _qa_response(question, intent, 'NO', 78, ['origin', 'metadata'], "Origin classification does not indicate direct camera-original evidence.", [f"Origin classification: {label}."])
    return _qa_response(question, intent, 'INCONCLUSIVE', 55, ['origin', 'metadata'], "Origin classification is uncertain.", [f"Origin classification: {label}."])


def _evaluate_metadata_integrity(result: Dict[str, Any], question: str, intent: str) -> Dict[str, Any]:
    flags = result.get('flags', [])
    ts_issues = result.get('timestamp_analysis', {}).get('issues', [])
    if not flags and not ts_issues:
        return _qa_response(question, intent, 'YES', 82, ['metadata', 'temporal'], "No metadata integrity anomalies were detected.", ["Metadata and timestamp checks are consistent."])
    meta_fabrication_signals = [f for f in flags if 'missing essential' in str(f).lower() or 'mismatch' in str(f).lower()]
    if meta_fabrication_signals:
        return _qa_response(question, intent, 'NO', 76, ['metadata', 'temporal'], "Metadata inconsistencies may indicate altered fields.", meta_fabrication_signals + ts_issues)
    return _qa_response(question, intent, 'INCONCLUSIVE', 60, ['metadata', 'temporal'], "Some anomalies exist but are not sufficient to assert metadata fabrication.", flags + ts_issues)


def _evaluate_altitude(result: Dict[str, Any], question: str, intent: str) -> Dict[str, Any]:
    exif = result.get('metadata', {}).get('exif', {})
    altitude = exif.get('GPS GPSAltitude')
    if altitude is None:
        return _qa_response(question, intent, 'INCONCLUSIVE', 40, ['gps', 'metadata'], "No GPS altitude tag is present.", ["GPS altitude missing."])
    try:
        alt_value = float(str(altitude).split('/')[0]) if '/' in str(altitude) else float(altitude)
        if -500 <= alt_value <= 9000:
            return _qa_response(question, intent, 'YES', 65, ['gps', 'metadata'], "Altitude value is within plausible physical range.", [f"Altitude: {altitude}"])
        return _qa_response(question, intent, 'NO', 75, ['gps', 'metadata'], "Altitude value appears implausible.", [f"Altitude: {altitude}"])
    except Exception:
        return _qa_response(question, intent, 'INCONCLUSIVE', 50, ['gps', 'metadata'], "Altitude value format is non-numeric/ambiguous.", [f"Altitude: {altitude}"])


INTENT_KEYWORDS = {
    'EDIT_DETECTION': ['edit', 'edited', 'modification', 'modified', 'tamper', 'altered', 'changed', 'fake', 'manipulated', 'any modifications happened'],
    'TIMESTAMP_AUDIT': ['time', 'date', 'timestamp', 'capture time', 'change in time', 'change in date', 'datetime', 'timeline'],
    'GPS_VALIDATION': ['gps', 'location', 'coordinates', 'geotag', 'place', 'latitude', 'longitude'],
    'DEVICE_SIGNATURE_CHECK': ['device', 'model', 'make', 'lens'],
    'CAMERA_ORIGIN_CHECK': ['camera origin', 'camera captured', 'real camera', 'camera photo', 'captured by camera'],
    'METADATA_INTEGRITY_CHECK': ['metadata', 'exif', 'fields', 'header', 'author', 'altered metadata'],
    'REENCODING_CHECK': ['compression', 'qtable', 'ela', 're-encoding', 'reencoding', 'artifacts'],
    'SYNTHETIC_CHECK': ['synthetic', 'ai generated', 'ai-generated', 'deepfake', 'fake image'],
    'RISK_ASSESSMENT': ['risk', 'suspicious', 'severity', 'confidence level', 'suspicion'],
    'SAME_DEVICE_CHECK': ['same device', 'from same device'],
    'SAME_SESSION_CHECK': ['same session'],
    'SAME_BATCH_CHECK': ['batch similarity', 'same batch']
}

FORENSIC_DOMAIN_LABELS = {
    'EDIT_DETECTION': 'editing/manipulation',
    'TIMESTAMP_AUDIT': 'timestamp consistency',
    'GPS_VALIDATION': 'GPS/location credibility',
    'DEVICE_SIGNATURE_CHECK': 'device attribution',
    'CAMERA_ORIGIN_CHECK': 'camera-origin assessment',
    'METADATA_INTEGRITY_CHECK': 'metadata integrity',
    'REENCODING_CHECK': 'structural/re-encoding',
    'SYNTHETIC_CHECK': 'synthetic/AI detection',
    'RISK_ASSESSMENT': 'risk/suspicion assessment',
    'SAME_DEVICE_CHECK': 'cross-file same-device correlation',
    'SAME_SESSION_CHECK': 'cross-file same-session correlation',
    'SAME_BATCH_CHECK': 'cross-file batch correlation'
}

ROUTER_ACTION_VERBS = {
    'analyze', 'check', 'inspect', 'audit', 'review', 'verify', 'evaluate',
    'assess', 'investigate', 'examine', 'determine', 'profile', 'explain', 'summarize'
}

# Normalized forensic intents -> human module names (as requested by investigation router spec)
NORMALIZED_INTENT_TO_MODULE = {
    'metadata_integrity_analysis': 'Metadata Integrity Analysis',
    'timestamp_consistency_analysis': 'Timestamp Consistency Analysis',
    'compression_artifact_analysis': 'Compression Artifact Analysis',
    'compression_lineage_analysis': 'Compression Lineage Analysis',
    'editing_after_capture_detection': 'Editing After Capture Detection',
    'camera_origin_authentication': 'Camera Origin Authentication',
    'ai_generation_detection': 'AI Generation Detection',
    'synthetic_graphic_detection': 'Synthetic Graphic Detection',
    'file_structure_consistency': 'File Structure Consistency Analysis',
    'quantization_table_analysis': 'Quantization Table Analysis',
    'platform_recompression_detection': 'Platform Recompression Detection',
    'gps_credibility_analysis': 'GPS Credibility Analysis',
    'exif_completeness_analysis': 'EXIF Completeness Analysis',
    'sensor_noise_realism_analysis': 'Sensor Noise Realism Analysis',
    'demosaicing_evidence_analysis': 'Demosaicing Evidence Analysis',
}

# Normalized intents -> existing internal evaluator intents.
NORMALIZED_TO_INTERNAL_INTENT = {
    'metadata_integrity_analysis': 'METADATA_INTEGRITY_CHECK',
    'timestamp_consistency_analysis': 'TIMESTAMP_AUDIT',
    'compression_artifact_analysis': 'REENCODING_CHECK',
    'compression_lineage_analysis': 'REENCODING_CHECK',
    'editing_after_capture_detection': 'EDIT_DETECTION',
    'camera_origin_authentication': 'CAMERA_ORIGIN_CHECK',
    'ai_generation_detection': 'SYNTHETIC_CHECK',
    'synthetic_graphic_detection': 'SYNTHETIC_CHECK',
    'file_structure_consistency': 'REENCODING_CHECK',
    'quantization_table_analysis': 'REENCODING_CHECK',
    'platform_recompression_detection': 'REENCODING_CHECK',
    'gps_credibility_analysis': 'GPS_VALIDATION',
    'exif_completeness_analysis': 'METADATA_INTEGRITY_CHECK',
    'sensor_noise_realism_analysis': 'CAMERA_ORIGIN_CHECK',
    'demosaicing_evidence_analysis': 'CAMERA_ORIGIN_CHECK',
}


def _internal_intent_to_module_label(internal_intent: str) -> str:
    """Map internal evaluator intent to human-readable module label."""
    for normalized_intent, mapped_internal in NORMALIZED_TO_INTERNAL_INTENT.items():
        if mapped_internal == internal_intent:
            return NORMALIZED_INTENT_TO_MODULE.get(normalized_intent, normalized_intent)
    return FORENSIC_DOMAIN_LABELS.get(internal_intent, internal_intent)

# Phrase signals for semantic normalization.
NORMALIZED_INTENT_SIGNALS = {
    'metadata_integrity_analysis': ['metadata integrity', 'metadata reliable', 'metadata reliability', 'metadata manipulated', 'altered metadata', 'metadata look manipulated'],
    'timestamp_consistency_analysis': ['timestamp consistency', 'timeline consistency', 'timeline plausible', 'chronology', 'datetimeoriginal vs', 'filemodifydate'],
    'compression_artifact_analysis': ['compression artifacts', 'ela', 'artifact analysis', 'jpeg artifacts'],
    'compression_lineage_analysis': ['compression lineage', 're-encoding', 'reencoding', 'double compression', 'recompressed'],
    'editing_after_capture_detection': ['was this image edited', 'editing traces', 'post-processing evidence', 'edited after capture', 'manipulation', 'tampering'],
    'camera_origin_authentication': ['camera origin', 'camera captured', 'camera authenticity', 'real camera photo'],
    'ai_generation_detection': ['ai generated', 'ai generation', 'generative model', 'diffusion artifact', 'deepfake'],
    'synthetic_graphic_detection': ['synthetic graphic', 'illustration', 'digital painting', 'non-photographic'],
    'file_structure_consistency': ['file structure', 'app0', 'app1', 'xmp record', 'icc profile', 'file-structure'],
    'quantization_table_analysis': ['quantization table', 'qtable', 'dqt'],
    'platform_recompression_detection': ['whatsapp recompression', 'instagram recompression', 'facebook recompression', 'platform recompression', 'telegram recompression'],
    'gps_credibility_analysis': ['gps credibility', 'gps spoof', 'location credible', 'latitude longitude', 'geotag'],
    'exif_completeness_analysis': ['exif completeness', 'missing exif', 'exif fields complete'],
    'sensor_noise_realism_analysis': ['sensor noise', 'prnu', 'noise realism'],
    'demosaicing_evidence_analysis': ['demosaicing', 'bayer pattern', 'cfa pattern'],
}


def _semantic_route_query(question: str) -> Dict[str, Any]:
    """Normalize forensic query intent and map to selected module/internal evaluator."""
    q = (question or '').strip().lower()
    if not q:
        return {
            'normalized_intent': 'UNSUPPORTED',
            'selected_module': 'Unsupported',
            'internal_intent': 'UNSUPPORTED',
            'candidates': []
        }

    compact = " ".join(q.replace("-", " ").replace("_", " ").split())
    tokens = [t for t in "".join(ch if ch.isalnum() else " " for ch in compact).split() if t and t not in ROUTER_ACTION_VERBS]

    scores: Dict[str, int] = {}
    for normalized_intent, cues in NORMALIZED_INTENT_SIGNALS.items():
        score = 0
        for cue in cues:
            cue_norm = cue.lower().strip()
            cue_tokens = [t for t in "".join(ch if ch.isalnum() else " " for ch in cue_norm).split() if t]
            if cue_norm in compact:
                score += 5 if len(cue_tokens) > 1 else 2
                continue
            matched = 0
            for ct in cue_tokens:
                if any(tok == ct or tok.startswith(ct) or ct.startswith(tok) for tok in tokens):
                    matched += 1
            if matched:
                score += 3 if matched == len(cue_tokens) else 1
        if score > 0:
            scores[normalized_intent] = score

    if not scores:
        return {
            'normalized_intent': 'UNSUPPORTED',
            'selected_module': 'Unsupported',
            'internal_intent': 'UNSUPPORTED',
            'candidates': []
        }

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    top_intent, _ = ranked[0]
    candidates = [intent for intent, score in ranked if score == ranked[0][1]]
    # treat near ties as ambiguous
    if len(ranked) > 1 and (ranked[0][1] - ranked[1][1]) <= 1 and ranked[1][0] not in candidates:
        candidates.append(ranked[1][0])

    return {
        'normalized_intent': top_intent,
        'selected_module': NORMALIZED_INTENT_TO_MODULE.get(top_intent, top_intent),
        'internal_intent': NORMALIZED_TO_INTERNAL_INTENT.get(top_intent, 'UNSUPPORTED'),
        'candidates': candidates,
    }


def _candidate_intents(question: str) -> Dict[str, int]:
    """Return semantic-router scores mapped to existing internal intents."""
    routed = _semantic_route_query(question)
    candidates = routed.get('candidates', [])
    scores: Dict[str, int] = {}
    for idx, normalized_intent in enumerate(candidates):
        internal = NORMALIZED_TO_INTERNAL_INTENT.get(normalized_intent, 'UNSUPPORTED')
        if internal == 'UNSUPPORTED':
            continue
        # Preserve ranking order: earlier candidates get higher score.
        scores[internal] = max(scores.get(internal, 0), 100 - idx)
    return scores


def _map_question_to_intent(question: str) -> str:
    """Map free-text question to best forensic domain intent."""
    routed = _semantic_route_query(question)
    intent = routed.get('internal_intent', 'UNSUPPORTED')
    if intent == 'UNSUPPORTED':
        return 'UNSUPPORTED'
    return intent


def _ambiguous_top_intents(question: str) -> List[str]:
    """Return tied top intents if ambiguity exists."""
    routed = _semantic_route_query(question)
    normalized_candidates = routed.get('candidates', [])
    internal_candidates = []
    for normalized_intent in normalized_candidates:
        internal = NORMALIZED_TO_INTERNAL_INTENT.get(normalized_intent)
        if internal and internal not in internal_candidates:
            internal_candidates.append(internal)
    return internal_candidates if len(internal_candidates) > 1 else []


def _is_out_of_scope(question: str) -> bool:
    """Detect clearly non-forensic asks."""
    q = (question or '').strip().lower()
    out_scope_markers = ['who is in', 'identify person', 'age of', 'what is this person', 'emotion', 'beauty rating']
    return any(m in q for m in out_scope_markers)


def _is_followup_query(question: str) -> bool:
    """Detect short follow-up prompts that should use previous answer context."""
    q = (question or '').strip().lower()
    followups = {
        'why', 'how', 'explain', 'explain more', 'details', 'more details',
        'what artifacts', 'what evidence', 'show evidence', 'reason', 'reasoning'
    }
    return q in followups or q.endswith('why?') or q.endswith('how?') or q.endswith('explain?')


def _evaluate_risk(result: Dict[str, Any], question: str, intent: str) -> Dict[str, Any]:
    risk = result.get('risk_assessment', {})
    level = str(risk.get('level', 'LOW')).upper()
    score = float(risk.get('risk_score', 0) or 0)
    answer = 'INCONCLUSIVE'
    confidence = 60
    if level in ['CRITICAL', 'HIGH']:
        answer = 'LIKELY'
        confidence = 80
    elif level == 'LOW':
        answer = 'UNLIKELY'
        confidence = 75
    elif level == 'MEDIUM':
        answer = 'INCONCLUSIVE'
        confidence = 65
    return _qa_response(
        question,
        intent,
        answer,
        confidence,
        ['risk_assessment', 'correlation', 'origin_detection'],
        f"Unified risk is {level} ({score:.1f}/100) based on combined module outputs.",
        [risk.get('findings_summary', 'Risk summary available.')]
    )


def answer_forensic_question(question: str, analysis_results: List[Dict[str, Any]], forced_intent: str | None = None) -> Dict[str, Any]:
    """Route free-text forensic questions to intent-based evaluators."""
    q = (question or '').strip()
    if not q:
        return _qa_response(question, 'UNSUPPORTED', 'INCONCLUSIVE', 0, [], "Question text is empty.", ["Provide a forensic question in natural language."])
    if not analysis_results:
        return _qa_response(question, 'UNSUPPORTED', 'INCONCLUSIVE', 0, [], "No analysis context is available.", ["Run analysis before asking forensic questions."])

    route = _semantic_route_query(q)
    intent = forced_intent or route.get('internal_intent') or _map_question_to_intent(q)
    first = analysis_results[0]

    def _with_route(resp: Dict[str, Any]) -> Dict[str, Any]:
        resp['normalized_intent'] = route.get('normalized_intent', 'UNSUPPORTED')
        resp['selected_module'] = route.get('selected_module', 'Unsupported')
        return resp

    if intent in ['EDIT_DETECTION', 'SPLICING_CHECK', 'LOCAL_TAMPERING_CHECK']:
        return _with_route(_apply_conflict_note(_evaluate_edit_detection(first, question, intent), first))
    if intent in ['GPS_VALIDATION', 'GPS_TIMEZONE_MATCH', 'LOCATION_SPOOF_CHECK']:
        return _with_route(_apply_conflict_note(_evaluate_gps(first, question, intent), first))
    if intent == 'ALTITUDE_PLAUSIBILITY':
        return _with_route(_apply_conflict_note(_evaluate_altitude(first, question, intent), first))
    if intent == 'SAME_DEVICE_CHECK':
        return _with_route(_apply_conflict_note(_evaluate_same_device(analysis_results, question, intent), first))
    if intent == 'DEVICE_SIGNATURE_CHECK':
        return _with_route(_apply_conflict_note(_evaluate_device_signature_single(first, question, intent), first))
    if intent == 'TIMESTAMP_AUDIT':
        return _with_route(_apply_conflict_note(_evaluate_timestamp(first, question, intent), first))
    if intent in ['SYNTHETIC_CHECK']:
        return _with_route(_apply_conflict_note(_evaluate_synthetic(first, question, intent), first))
    if intent in ['REENCODING_CHECK', 'SAME_BATCH_CHECK', 'SAME_SESSION_CHECK']:
        return _with_route(_apply_conflict_note(_evaluate_reencoding(first, question, intent), first))
    if intent == 'CAMERA_ORIGIN_CHECK':
        return _with_route(_apply_conflict_note(_evaluate_camera_origin(first, question, intent), first))
    if intent == 'METADATA_INTEGRITY_CHECK':
        return _with_route(_apply_conflict_note(_evaluate_metadata_integrity(first, question, intent), first))
    if intent == 'RISK_ASSESSMENT':
        return _with_route(_apply_conflict_note(_evaluate_risk(first, question, intent), first))

    return _with_route(_qa_response(
        question,
        'UNSUPPORTED',
        'INCONCLUSIVE',
        0,
        [],
        "No relevant forensic evidence found.",
        ["No relevant forensic evidence found."]
    ))


def _metadata_facts_from_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Extract factual fields for interactive metadata explorer mode."""
    metadata = result.get('metadata', {})
    summary = metadata.get('summary', {}) if isinstance(metadata.get('summary', {}), dict) else {}
    exif = metadata.get('exif', {}) if isinstance(metadata.get('exif', {}), dict) else {}
    image_info = metadata.get('image_info', {}) if isinstance(metadata.get('image_info', {}), dict) else {}
    file_info = metadata.get('file_info', {}) if isinstance(metadata.get('file_info', {}), dict) else {}

    device_make = summary.get('camera_make') or exif.get('EXIF Make') or exif.get('Make') or "Unknown"
    device_model = summary.get('camera_model') or exif.get('EXIF Model') or exif.get('Model') or "Unknown"
    capture_time = summary.get('datetime_original') or exif.get('EXIF DateTimeOriginal') or "Unknown"
    software = summary.get('software') or exif.get('Software') or "None"
    creation_date = (
        file_info.get('created_at')
        or file_info.get('created')
        or file_info.get('File Create Date/Time')
        or summary.get('file_modify_date')
        or file_info.get('modified_at')
        or "Unknown"
    )

    camera_settings = {
        'ISO': exif.get('EXIF ISOSpeedRatings') or exif.get('ISOSpeedRatings'),
        'Exposure': exif.get('EXIF ExposureTime') or exif.get('ExposureTime'),
        'FNumber': exif.get('EXIF FNumber') or exif.get('FNumber'),
        'FocalLength': exif.get('EXIF FocalLength') or exif.get('FocalLength'),
    }

    flat_metadata = {}
    try:
        from .utils.exiftool_formatter import ExifToolStyleFormatter
        flat_metadata = ExifToolStyleFormatter._flatten_metadata(metadata)
    except Exception:
        flat_metadata = {}

    gps_lat = exif.get('GPS GPSLatitude') or exif.get('Gps Gpslatitude') or exif.get('GPSLatitude')
    gps_lon = exif.get('GPS GPSLongitude') or exif.get('Gps Gpslongitude') or exif.get('GPSLongitude')
    gps_source = "EXIF GPS fields"
    if not (gps_lat and gps_lon):
        gps_lat = flat_metadata.get('GPS Latitude') or flat_metadata.get('Gps Gpslatitude')
        gps_lon = flat_metadata.get('GPS Longitude') or flat_metadata.get('Gps Gpslongitude')
        if gps_lat and gps_lon:
            gps_source = "Derived GPS fields"
    gps_value = f"{gps_lat}, {gps_lon}" if gps_lat and gps_lon else (flat_metadata.get('GPS Coordinates') or "Not present")
    if gps_value != "Not present" and gps_source == "EXIF GPS fields":
        gps_source = "EXIF/derived GPS fields"

    return {
        'device': {'value': f"{device_make} {device_model}".strip(), 'source': 'EXIF Make/Model'},
        'gps': {'value': gps_value, 'source': gps_source},
        'capture_time': {'value': capture_time, 'source': 'EXIF DateTimeOriginal'},
        'creation_date': {'value': creation_date, 'source': 'Filesystem/file metadata fields'},
        'software': {'value': software, 'source': 'EXIF/summary software tags'},
        'resolution': {'value': f"{image_info.get('width', 'Unknown')}x{image_info.get('height', 'Unknown')}", 'source': 'Image dimensions'},
        'camera_settings': {'value': camera_settings, 'source': 'EXIF camera setting fields'},
        'flat_metadata': {'value': flat_metadata, 'source': 'Flattened metadata map'}
    }


def _respond_metadata_query(query: str, facts: Dict[str, Any]) -> str:
    """Return facts only. No risk scoring or verdict language."""
    q = (query or "").strip().lower()
    if not q:
        return "Ask a factual metadata question. Type 'help' for examples."
    if q in ["help", "?"]:
        return (
            "Supported factual queries:\n"
            "- give me GPS location\n"
            "- what is the capture time\n"
            "- show <metadata field name>\n"
            "- which device was used\n"
            "- what software modified this\n"
            "- show camera settings\n"
            "- show resolution\n"
            "Type 'exit' to quit."
        )

    def fmt(name: str) -> str:
        item = facts[name]
        return f"{item['value']}\nSource: {item['source']}\nConfidence: Direct metadata extraction"

    def lookup_flat_field(term: str) -> str | None:
        flat = facts.get('flat_metadata', {}).get('value', {})
        if not isinstance(flat, dict) or not term:
            return None

        aliases = {
            'filename': 'File Name',
            'directory': 'Directory',
            'filesize': 'File Size',
            'filemodificationdatetime': 'File Modification Date/Time',
            'fileaccessdatetime': 'File Access Date/Time',
            'mimetype': 'Mime Type',
            'absolutepath': 'Absolute Path',
            'imagewidth': 'Image Width',
            'imageheight': 'Image Height',
            'imagesize': 'Image Size',
            'dpi': 'Dpi',
            'cameramake': 'Camera Make',
            'cameramodel': 'Camera Model',
            'datetimeoriginal': 'Date/Time Original',
            'exifdatetimeoriginal': 'Exif Datetimeoriginal',
            'exiffnumber': 'Exif Fnumber',
            'exifisospeedratings': 'Exif Isospeedratings',
            'exifexposuretime': 'Exif Exposuretime',
            'gpsgpslatitude': 'Gps Gpslatitude',
            'gpsgpslongitude': 'Gps Gpslongitude',
            'gpsgpsaltitude': 'Gps Gpsaltitude',
            'gpslocation': 'GPS Location',
            'gpsfulladdress': 'GPS Full Address',
            'software': 'Software',
            'megapixels': 'Megapixels',
            'dimensions': 'Dimensions',
            'standardspresent': 'Standards Present',
        }

        term_norm = "".join(ch for ch in term.lower() if ch.isalnum())
        alias_key = aliases.get(term_norm)
        if alias_key and alias_key in flat:
            return f"Answer:\n{flat.get(alias_key)}\n\nSource:\n{alias_key}\n\nConfidence:\nHigh (Direct metadata)"

        best_key = None
        for key in flat.keys():
            key_norm = "".join(ch for ch in str(key).lower() if ch.isalnum())
            if key_norm == term_norm:
                best_key = key
                break
        if not best_key:
            for key in flat.keys():
                key_norm = "".join(ch for ch in str(key).lower() if ch.isalnum())
                if term_norm in key_norm or key_norm in term_norm:
                    best_key = key
                    break
        if best_key:
            return f"Answer:\n{flat.get(best_key)}\n\nSource:\n{best_key}\n\nConfidence:\nHigh (Direct metadata)"

        # Token-level keyword matching: if any word from a field name is queried, return matching fields.
        tokens = [t for t in "".join(ch if ch.isalnum() else " " for ch in term.lower()).split() if t]
        if not tokens:
            return None

        matches = []
        for key, value in flat.items():
            key_tokens = [t for t in "".join(ch if ch.isalnum() else " " for ch in str(key).lower()).split() if t]
            if any(tok in key_tokens for tok in tokens):
                matches.append((str(key), value))

        # Fallback to partial token containment in normalized key string
        if not matches:
            for key, value in flat.items():
                key_norm = "".join(ch for ch in str(key).lower() if ch.isalnum())
                if any(tok in key_norm for tok in tokens):
                    matches.append((str(key), value))

        if not matches:
            return None

        # Keep output readable in interactive mode.
        max_items = 8
        shown = matches[:max_items]
        lines = [f"- {k}: {v}" for k, v in shown]
        more = ""
        if len(matches) > max_items:
            more = f"\n...and {len(matches) - max_items} more matching fields."
        return (
            "Answer:\n"
            + "\n".join(lines)
            + f"{more}\n\nSource:\nFlattened metadata field-name match\n\nConfidence:\nHigh (Direct metadata)"
        )

    if any(k in q for k in ["gps", "location", "geotag"]):
        if q.strip() == "gps":
            out = lookup_flat_field("gps")
            if out:
                return out
        # Prefer resolved location text when user asks for location/address
        if any(k in q for k in ["location", "address", "city", "state", "country"]):
            out = lookup_flat_field("gps location") or lookup_flat_field("gps full address")
            if out:
                return out
        return f"GPS: {fmt('gps')}"
    if any(k in q for k in ["capture time", "timestamp", "datetime", "time"]):
        return f"Capture Time: {fmt('capture_time')}"
    if any(k in q for k in ["creation date", "created date", "file create", "created time"]):
        return f"Creation Date: {fmt('creation_date')}"
    if any(k in q for k in ["device", "camera model", "which device", "phone"]):
        return f"Device: {fmt('device')}"
    if any(k in q for k in ["software", "modified"]):
        return f"Software: {fmt('software')}"
    if any(k in q for k in ["resolution", "dimensions", "size"]):
        return f"Resolution: {fmt('resolution')}"
    if any(k in q for k in ["camera settings", "iso", "exposure", "aperture", "focal"]):
        cs = facts['camera_settings']['value']
        return (
            "Camera Settings:\n"
            f"- ISO: {cs.get('ISO')}\n"
            f"- Exposure: {cs.get('Exposure')}\n"
            f"- FNumber: {cs.get('FNumber')}\n"
            f"- FocalLength: {cs.get('FocalLength')}\n"
            f"Source: {facts['camera_settings']['source']}\n"
            "Confidence: Direct metadata extraction"
        )

    # Generic field lookup for "show <field>" or "get <field>"
    if q.startswith("show ") or q.startswith("get ") or q.startswith("field "):
        requested = q.split(" ", 1)[1].strip() if " " in q else ""
        out = lookup_flat_field(requested)
        if out:
            return out
        return "No relevant metadata or forensic data found."

    # Direct field lookup (single word or phrase) without "show/get"
    out = lookup_flat_field(q)
    if out:
        return out
    return "No relevant metadata or forensic data found."


def run_interactive_metadata_mode(result: Dict[str, Any]) -> None:
    """INTERACTIVE mode: factual metadata explorer only."""
    print("\n[INTERACTIVE MODE: FORENSIC DATA EXPLORER]")
    print("Facts only. No deep inference. No verdict language.")
    print("Type 'help' for examples. Type 'exit' to quit.")
    facts = _metadata_facts_from_result(result)
    while True:
        q = input("interactive> ").strip()
        if q.lower() in ["exit", "quit", "q"]:
            print("Exiting interactive mode.")
            break
        print(_respond_metadata_query(q, facts))


def _print_ask_response(qa: Dict[str, Any]) -> None:
    """Render a structured Ask-mode response."""
    if qa.get('normalized_intent') and qa.get('selected_module'):
        print("\nRouting:")
        print(f"Normalized Intent: {qa.get('normalized_intent')}")
        print(f"Selected Module: {qa.get('selected_module')}")
    print("\nAnswer:")
    print(qa.get('answer'))
    print("\nReasoning:")
    print(qa.get('reasoning'))
    print("\nEvidence Used:")
    print(", ".join(qa.get('evidence_domains_used', [])))
    print("\nConfidence:")
    print(f"{qa.get('confidence_level')} ({qa.get('confidence_percent')}%)")
    for item in qa.get('evidence', []):
        print(f"   - {item}")
    if qa.get('per_image_metadata'):
        print("  Per-image metadata:")
        for row in qa.get('per_image_metadata', []):
            print(f"   - {row.get('file')}: make={row.get('make')}, model={row.get('model')}, serial={row.get('serial')}")


def _quick_forensic_examples() -> List[str]:
    """Concise starter examples for help output."""
    return [
        "Was this likely edited after capture?",
        "Is there evidence of WhatsApp/Instagram recompression?",
        "Do timestamps look internally consistent?",
        "Is this likely AI-generated or synthetic art?",
        "Show all camera-related fields.",
        "Compare DateTimeOriginal vs FileModifyDate.",
        "show DateTimeOriginal",
        "show Software",
        "show GPSLatitude",
    ]


def _normalize_forensic_intent(query: str) -> str:
    """Map a forensic query to a normalized intent id."""
    q = (query or "").lower()
    intent_rules = [
        ("metadata_integrity_analysis", ["metadata integrity", "metadata reliability", "exif integrity", "metadata consistency"]),
        ("timestamp_consistency_analysis", ["timestamp consistency", "timeline plausibility", "chronology", "datetimeoriginal", "filemodifydate"]),
        ("editing_after_capture_analysis", ["edited after capture", "post-processing", "manipulation", "tampering"]),
        ("compression_lineage_analysis", ["compression lineage", "re-encoding", "double compression", "quantization"]),
        ("software_trace_analysis", ["software editing traces", "creatortool", "processingsoftware", "software marker"]),
        ("platform_recompression_analysis", ["whatsapp recompression", "instagram recompression", "facebook recompression", "platform recompression"]),
        ("gps_credibility_analysis", ["gps credibility", "gps spoofing", "latitude", "longitude", "location credibility"]),
        ("camera_origin_authenticity_analysis", ["camera-origin authenticity", "camera captured", "camera make/model", "lensmodel"]),
        ("ai_generation_likelihood_analysis", ["ai-generation likelihood", "synthetic", "diffusion", "generative"]),
        ("unknown_origin_assessment", ["unknown-origin", "unknown origin", "insufficient evidence"]),
    ]
    for intent_id, cues in intent_rules:
        if any(cue in q for cue in cues):
            return intent_id
    return "general_forensic_analysis"


def _generate_forensic_query_examples() -> Dict[str, List[str]]:
    """Generate 200k+ meaningful investigator-style forensic query variations."""
    domains: Dict[str, List[str]] = {}

    # 1) Synonym expansion (investigator verbs)
    actions = [
        "analyze", "inspect", "audit", "review", "evaluate", "verify", "assess",
        "check", "investigate", "examine", "determine", "profile", "explain", "summarize"
    ]

    # 2) Evidence source expansion
    evidence_sources = [
        "using compression traces",
        "using metadata evidence",
        "using EXIF metadata",
        "using quantization tables",
        "using file-structure markers",
        "using timestamp fields",
        "using demosaicing artifacts",
        "using sensor noise patterns",
        "using XMP records",
        "using platform recompression signals",
    ]

    # 3) Forensic domain expansion
    forensic_domains = [
        "metadata integrity",
        "timestamp consistency",
        "editing after capture",
        "compression lineage",
        "double-compression artifacts",
        "quantization-table anomalies",
        "software editing traces",
        "platform recompression signatures",
        "GPS credibility",
        "EXIF completeness",
        "XMP provenance",
        "file-structure consistency",
        "sensor-noise realism",
        "demosaicing evidence",
        "AI-generation likelihood",
        "synthetic graphic characteristics",
        "camera-origin authenticity",
        "timeline plausibility",
        "unknown-origin conditions",
        "camera make/model reliability",
    ]

    # 4) Output style expansion
    output_styles = [
        "with confidence",
        "with supporting evidence",
        "without assumptions",
        "step by step",
        "and cite signals used",
        "and summarize uncertainty",
        "using only extracted fields",
        "in investigator-friendly format",
        "for a court-safe explanation",
        "with final risk context",
    ]

    # Additional phrasing layers used in practical AI query expansion
    request_prefixes = [
        "for current image",
        "for this evidence file",
        "for forensic triage",
        "for investigation record",
        "under strict forensic constraints",
        "for chain-of-custody reporting",
        "for analyst verification",
    ]
    result_targets = [
        "and provide concise conclusions",
        "and include explicit evidence mapping",
        "and include confidence rationale",
        "and highlight conflicts if any",
        "and avoid speculative language",
    ]

    # Intent normalization catalog
    normalized_domains = {
        "metadata_integrity_analysis": ["metadata integrity", "EXIF completeness", "XMP provenance"],
        "timestamp_consistency_analysis": ["timestamp consistency", "timeline plausibility"],
        "editing_after_capture_analysis": ["editing after capture", "software editing traces"],
        "compression_lineage_analysis": ["compression lineage", "double-compression artifacts", "quantization-table anomalies", "platform recompression signatures"],
        "gps_credibility_analysis": ["GPS credibility"],
        "camera_origin_authenticity_analysis": ["camera-origin authenticity", "camera make/model reliability", "demosaicing evidence", "sensor-noise realism"],
        "ai_synthetic_analysis": ["AI-generation likelihood", "synthetic graphic characteristics"],
        "unknown_origin_assessment": ["unknown-origin conditions", "file-structure consistency"],
    }

    def _add(bucket: List[str], seen: set, text: str, limit: int) -> bool:
        if len(bucket) >= limit:
            return False
        q = " ".join(text.split()).strip()
        if not q:
            return True
        key = q.lower()
        if key in seen:
            return True
        seen.add(key)
        bucket.append(q)
        return len(bucket) < limit

    def _intent_for_domain(domain: str) -> str:
        # normalization lookup for generated traceability
        for intent_id, variants in normalized_domains.items():
            if domain in variants:
                return intent_id
        return "general_forensic_analysis"

    # Template combination strategy
    templates = [
        "{evidence} {action} {domain} {style}?",
        "{action} {domain} {style} {evidence}.",
        "{prefix} {action} {domain} {evidence} {style}.",
        "{action} {domain} {evidence} {style} {target}.",
        "{prefix}: {action} {domain}; {evidence}; {style}; {target}.",
    ]

    # Build per-normalized-intent buckets.
    for intent_id, mapped_domains in normalized_domains.items():
        bucket: List[str] = []
        seen: set = set()
        # Keep each intent rich while bounded.
        limit = 26000
        for d in mapped_domains:
            for a in actions:
                for e in evidence_sources:
                    for s in output_styles:
                        for p in request_prefixes:
                            for t in result_targets:
                                for tpl in templates:
                                    query = tpl.format(
                                        evidence=e,
                                        action=a,
                                        domain=d,
                                        style=s,
                                        prefix=p,
                                        target=t,
                                    )
                                    if not _add(bucket, seen, query, limit):
                                        break
                                if len(bucket) >= limit:
                                    break
                            if len(bucket) >= limit:
                                break
                        if len(bucket) >= limit:
                            break
                    if len(bucket) >= limit:
                        break
                if len(bucket) >= limit:
                    break
            if len(bucket) >= limit:
                break
        # Add investigator-style direct versions tied to intent
        for d in mapped_domains:
            for a in actions:
                _add(bucket, seen, f"{a} {d}?", limit)
                _add(bucket, seen, f"{a} {d} using metadata evidence?", limit)
                _add(bucket, seen, f"{a} {d} using compression traces?", limit)
        domains[intent_id] = bucket

    # Legacy/domain display groups for help-all readability.
    domain_buckets: Dict[str, List[str]] = {k: [] for k in [
        "metadata", "timestamps", "editing", "compression", "gps", "camera", "ai", "origin", "advanced"
    ]}
    for intent_id, bucket in domains.items():
        if "metadata" in intent_id:
            domain_buckets["metadata"].extend(bucket[:1200])
        elif "timestamp" in intent_id:
            domain_buckets["timestamps"].extend(bucket[:1200])
        elif "editing" in intent_id:
            domain_buckets["editing"].extend(bucket[:1200])
        elif "compression" in intent_id:
            domain_buckets["compression"].extend(bucket[:1200])
        elif "gps" in intent_id:
            domain_buckets["gps"].extend(bucket[:1200])
        elif "camera" in intent_id:
            domain_buckets["camera"].extend(bucket[:1200])
        elif "ai" in intent_id:
            domain_buckets["ai"].extend(bucket[:1200])
        elif "unknown" in intent_id:
            domain_buckets["origin"].extend(bucket[:1200])
        else:
            domain_buckets["advanced"].extend(bucket[:1200])

    # Keep normalized intent sets and user-facing domain sets together.
    for k, v in domain_buckets.items():
        domains[k] = v

    # Attach a concise normalization map for transparency in help-all.
    normalization_preview = []
    for d in forensic_domains:
        normalization_preview.append(f"{d} -> {_intent_for_domain(d)}")
    domains["normalization_map"] = normalization_preview

    return domains


def run_ask_chat_mode(analysis_results: List[Dict[str, Any]], initial_question: str | None = None) -> None:
    """Conversational forensic decision chatbot loop."""
    all_examples: Optional[Dict[str, List[str]]] = None
    total_examples = 200000  # expected floor for generated library

    print("\nMetaForensic AI chatbox Activated")
    print("You may ask any forensic question.")
    print("Type 'help' for quick examples, 'help-all' for exhaustive examples, or 'exit' to quit.")
    print("--------------------")
    last_qa: Optional[Dict[str, Any]] = None
    pending_ambiguity: Optional[List[str]] = None
    pending_question: Optional[str] = None

    def handle_question(q: str, forced_intent: str | None = None) -> None:
        nonlocal last_qa
        qa = answer_forensic_question(q, analysis_results, forced_intent=forced_intent)
        _print_ask_response(qa)
        last_qa = qa

    if initial_question:
        handle_question(initial_question)

    while True:
        q = input("MetaForensic AI chatbox> ").strip()
        if q.lower() in ["exit", "quit", "q"]:
            print("Exiting MetaForensic AI chatbox.")
            break
        if q.lower() in ["help", "?"]:
            print("Quick Examples:")
            for ex in _quick_forensic_examples():
                print(f"  - {ex}")
            print(f"\nExhaustive example library available: 200,000+ generated queries.")
            print("Type 'help-all' to print all examples by domain.")
            continue
        if q.lower() in ["help-all", "examples-all", "help all"]:
            if all_examples is None:
                all_examples = _generate_forensic_query_examples()
                total_examples = sum(len(v) for v in all_examples.values())
            print(f"\nGenerated Forensic Query Library ({total_examples} queries)")
            for domain, examples in all_examples.items():
                print(f"\n[{domain.upper()}] ({len(examples)})")
                for ex in examples:
                    print(f"  - {ex}")
            continue
        if not q:
            continue

        # If waiting on clarifier selection, resolve it first.
        if pending_ambiguity:
            # support numeric selection or domain words.
            if q.isdigit():
                idx = int(q) - 1
                if 0 <= idx < len(pending_ambiguity):
                    chosen = pending_ambiguity[idx]
                    chosen_question = pending_question or q
                    pending_ambiguity = None
                    pending_question = None
                    handle_question(chosen_question, forced_intent=chosen)
                    continue
            chosen = _map_question_to_intent(q)
            if chosen in pending_ambiguity:
                chosen_question = pending_question or q
                pending_ambiguity = None
                pending_question = None
                handle_question(chosen_question, forced_intent=chosen)
                continue
            print("Please choose one of the listed clarification options.")
            continue

        # Follow-up memory handling.
        q_low = q.lower()
        if last_qa and _is_followup_query(q_low):
            follow_reason = last_qa.get('reasoning', 'No prior reasoning available.')
            follow_evidence = last_qa.get('evidence', [])
            print("\nAnswer:")
            print(last_qa.get('answer'))
            print("\nReasoning:")
            print(follow_reason)
            print("\nEvidence Used:")
            for ev in follow_evidence[:8]:
                print(f"- {ev}")
            print("\nConfidence:")
            print(last_qa.get('confidence_level', 'Moderate'))
            continue

        # Out-of-scope polite decline.
        if _is_out_of_scope(q):
            print("\nThis request is outside forensic scope. Ask about metadata, timestamps, GPS, device, structural artifacts, synthetic detection, or risk.")
            continue

        # Ambiguity handling.
        ambiguous = _ambiguous_top_intents(q)
        if ambiguous:
            pending_ambiguity = ambiguous
            pending_question = q
            print("\nYour question may refer to multiple forensic analyses.")
            print("Please clarify:")
            for i, intent in enumerate(ambiguous, 1):
                print(f"  {i}. {_internal_intent_to_module_label(intent)}")
            print("You can type the number or restate your question.")
            continue

        # If no clear forensic intent but possibly forensic wording, ask for clarification.
        mapped = _map_question_to_intent(q)
        if mapped == 'UNSUPPORTED':
            print("\nNo relevant forensic evidence found.")
            print("Ask about: editing, timestamps, GPS/location, device attribution, metadata integrity, structural/re-encoding, synthetic detection, risk, or cross-file correlation.")
            continue

        handle_question(q)


def _should_launch_wizard(args: argparse.Namespace) -> bool:
    """Auto-launch guided setup for minimal image or batch invocation."""
    return bool(
        (args.image or args.batch)
        and not args.compare
        and args.output == './results'
        and not args.interactive
        and args.ai_mode == 'explain'
        and not args.ask
        and args.report == 'all'
        and args.compare_type == 'metadata'
        and not args.config
        and not args.case_id
        and not args.analyst
        and args.max_images is None
        and not args.verbose
        and not args.debug
    )


def _prompt_choice(title: str, options: List[str], default_index: int = 0) -> str:
    """Prompt user to select one option by number."""
    print(f"\n{title}")
    for i, opt in enumerate(options, 1):
        default_tag = " (default)" if i - 1 == default_index else ""
        print(f"  {i}. {opt}{default_tag}")
    raw = input("Select option number (press Enter for default): ").strip()
    if raw.lower() in ["exit", "quit", "q"]:
        print("Exiting guided setup.")
        sys.exit(0)
    if not raw:
        return options[default_index]
    try:
        idx = int(raw) - 1
        if 0 <= idx < len(options):
            return options[idx]
    except ValueError:
        pass
    print("Invalid choice. Using default.")
    return options[default_index]


def _prompt_text(label: str, default: str = "") -> str:
    prompt = f"{label}"
    if default:
        prompt += f" [{default}]"
    prompt += ": "
    raw = input(prompt).strip()
    if raw.lower() in ["exit", "quit", "q"]:
        print("Exiting guided setup.")
        sys.exit(0)
    return raw if raw else default


def _prompt_ask_question(default: str = "Was this image edited?") -> str:
    """Prompt for forensic question with help support."""
    while True:
        raw = input("   Enter question (type 'help' for examples): ").strip()
        if raw.lower() in ["exit", "quit", "q"]:
            print("Exiting guided setup.")
            sys.exit(0)
        if raw.strip().lower() == "help":
            print("\nAsk examples:")
            print("  - Was this image edited?")
            print("  - Is GPS location credible?")
            print("  - Are timestamps consistent?")
            print("  - Is this likely synthetic?")
            print("  - Was metadata altered?")
            print("  - Are these from same device?")
            continue
        return raw if raw else default


def _prompt_yes_no(label: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    raw = input(f"{label} ({suffix}): ").strip().lower()
    if raw in ["exit", "quit", "q"]:
        print("Exiting guided setup.")
        sys.exit(0)
    if not raw:
        return default
    return raw in ["y", "yes"]


def _select_output_directory(current_default: str) -> str:
    """Offer common output directory options for non-technical users."""
    desktop_default = str(Path.home() / "Desktop" / "forensic_reports")
    choice = _prompt_choice(
        "1) Output directory",
        [
            f"Use default ({current_default})",
            f"Use desktop folder ({desktop_default})",
            "Use timestamped folder under ./results",
            "Enter custom path",
            "Do not save report files"
        ],
        default_index=0
    )

    if choice.startswith("Use default"):
        return current_default
    if choice.startswith("Use desktop folder"):
        return desktop_default
    if choice.startswith("Use timestamped folder"):
        return f"./results/session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    if choice.startswith("Do not save report files"):
        return "__NO_FILE_OUTPUT__"
    return _prompt_text("   Enter custom output directory", current_default)


def _run_guided_setup(args: argparse.Namespace) -> None:
    """Interactive, step-by-step option selection for image or batch mode."""
    print("\nGuided Setup: Step-by-step configuration")
    print("Press Enter to keep defaults.\n")
    print("Type 'exit' at any prompt to quit.\n")

    output_choice = _select_output_directory(args.output)
    skip_file_output = output_choice == "__NO_FILE_OUTPUT__"
    if skip_file_output:
        args.output = "./results"
        args.report = "none"
        print("   Note: Report files will not be saved. Analysis will continue for investigation modes only.")
    else:
        args.output = output_choice

        report_options = [
            "all (save all file reports)",
            "pdf (save PDF file)",
            "html (save HTML file)",
            "txt (save text file)",
            "none (no report files)",
            "json-cli (print narrative in terminal)",
            "exiftool-cli (print raw metadata in terminal)"
        ]
        report_choice = _prompt_choice("2) Report format", report_options, default_index=0)
        args.report = report_choice.split(" ")[0]
        if args.report in ["json-cli", "exiftool-cli"]:
            print("   Note: This choice prints output directly in terminal.")
        else:
            print("   Note: This choice saves output to files (no direct terminal report dump).")

    step_num = 2 if skip_file_output else 3
    if args.image:
        # For image mode, defer investigation-mode choice until after confirmation.
        args.interactive = False
        args.ask = None

    if args.batch:
        args.interactive = False
        args.ask = None
        max_images_raw = _prompt_text(f"{step_num}) Max images for batch (optional)", "")
        step_num += 1
        if max_images_raw:
            try:
                parsed = int(max_images_raw)
                if parsed <= 0:
                    print("   Invalid max-images. Keeping unlimited.")
                    args.max_images = None
                else:
                    args.max_images = parsed
            except ValueError:
                print("   Invalid max-images. Keeping unlimited.")
                args.max_images = None

    args.case_id = _prompt_text(f"{step_num}) Case ID (optional)", "")
    step_num += 1
    args.analyst = _prompt_text(f"{step_num}) Analyst name (optional)", "")
    step_num += 1
    args.verbose = _prompt_yes_no(f"{step_num}) Enable verbose logs", default=False)
    step_num += 1
    args.debug = _prompt_yes_no(f"{step_num}) Enable debug mode", default=False)

    print("\nSelected Options")
    if args.image:
        print(f"  image: {args.image}")
    if args.batch:
        print(f"  batch: {args.batch}")
        print(f"  max_images: {args.max_images if args.max_images is not None else 'unlimited'}")
    print(f"  output: {args.output}")
    print(f"  ai_mode: {args.ai_mode}")
    print(f"  report: {args.report}")
    print(f"  ask: {args.ask or 'None'}")
    print(f"  interactive: {args.interactive}")
    print(f"  case_id: {args.case_id or 'None'}")
    print(f"  analyst: {args.analyst or 'None'}")
    print(f"  verbose: {args.verbose}")
    print(f"  debug: {args.debug}")

    if not _prompt_yes_no("Proceed with analysis", default=True):
        print("Analysis canceled by user.")
        sys.exit(0)

    if args.batch:
        # For batch mode, defer investigation-mode choice until after analysis summary.
        args.interactive = False
        args.ask = None
        setattr(args, "_post_batch_investigation_prompt", True)

    if args.image:
        # For image mode, defer investigation-mode choice until after analysis summary.
        args.interactive = False
        args.ask = None
        setattr(args, "_post_image_investigation_prompt", True)


def _run_no_args_startup_prompt(args: argparse.Namespace) -> argparse.Namespace:
    """Handle bare `python forensicai.py` by collecting the analysis target first."""
    target_choice = _prompt_choice(
        "Choose analysis mode",
        [
            "Single image",
            "Folder"
        ],
        default_index=0
    )

    if target_choice == "Single image":
        args.image = _prompt_text("Enter image path").strip()
        while not args.image:
            print("Image path is required.")
            args.image = _prompt_text("Enter image path").strip()
        args.batch = None
    else:
        args.batch = _prompt_text("Enter folder path").strip()
        while not args.batch:
            print("Folder path is required.")
            args.batch = _prompt_text("Enter folder path").strip()
        args.image = None

    args.compare = None
    return args


def _sanitize_folder_label(value: str, fallback: str = "session", max_len: int = 40) -> str:
    """Create a filesystem-safe folder label."""
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", str(value or "")).strip("_")
    if not cleaned:
        cleaned = fallback
    return cleaned[:max_len]


def _prepare_output_session_dir(args: argparse.Namespace) -> str:
    """Create a per-run output subfolder to avoid mixing artifacts."""
    file_output_mode = args.report not in {"none", "json-cli", "exiftool-cli"}
    needs_output = bool(args.batch or file_output_mode)
    if not needs_output:
        return args.output

    base = Path(args.output)

    # If user already provided a timestamped/session-like folder, keep it.
    if re.search(r"(session|batch|compare|run|analysis)_\d{8}_\d{6}$", base.name):
        base.mkdir(parents=True, exist_ok=True)
        return str(base)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.image:
        prefix = _sanitize_folder_label(Path(args.image).stem, fallback="image")
    elif args.batch:
        prefix = "batch"
    elif args.compare:
        prefix = "compare"
    else:
        prefix = "analysis"

    session_dir = base / f"{prefix}_{timestamp}"
    session_dir.mkdir(parents=True, exist_ok=True)
    return str(session_dir)


def main():
    """Command-line entry point for MetaForensicAI."""
    parser = argparse.ArgumentParser(
        description="MetaForensicAI: AI-Assisted Digital Image Forensics System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --image evidence.jpg
  %(prog)s --image evidence.jpg --interactive
  %(prog)s --batch evidence_folder/ --output reports/
  %(prog)s --image evidence.jpg --report pdf --verbose
  %(prog)s --compare image1.jpg image2.jpg --type metadata
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument(
        '--image', '-i',
        help='Path to image file for analysis'
    )
    input_group.add_argument(
        '--batch', '-b',
        help='Path to directory for batch analysis'
    )
    input_group.add_argument(
        '--compare',
        nargs='+',
        help='Compare multiple images'
    )
    
    # Output options
    parser.add_argument(
        '--output', '-o',
        default='./results',
        help='Output directory for reports (default: ./results)'
    )
    
    # Analysis options
    parser.add_argument(
        '--interactive', '-I',
        action='store_true',
        help='Launch interactive CLI after analysis'
    )

    parser.add_argument(
        '--ai-mode',
        choices=['explain'],
        default='explain',
        help='AI decision mode (supported: explain)'
    )

    parser.add_argument(
        '--ask',
        nargs='?',
        const='Was this image edited?',
        help='Free-text forensic question mode with intent mapping (editing, GPS, device, timestamp, synthetic, metadata integrity, re-encoding).'
    )
    
    parser.add_argument(
        '--report', '-r',
        choices=['pdf', 'json', 'html', 'txt', 'json-cli', 'exiftool-cli', 'both', 'all', 'none'],
        default='all',
        help='Report format. Use "json-cli" for narrative or "exiftool-cli" for raw metadata to stdout. (default: all)'
    )

    parser.add_argument(
        '--compare-type',
        choices=['metadata', 'timestamps', 'origin'],
        default='metadata',
        help='Type of comparison for --compare (default: metadata)'
    )
    
    # Configuration options
    parser.add_argument(
        '--config', '-c',
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--case-id',
        help='Case identifier for reporting'
    )
    
    parser.add_argument(
        '--analyst',
        help='Analyst name for reporting'
    )
    
    parser.add_argument(
        '--max-images',
        type=int,
        help='Maximum number of images for batch analysis'
    )
    
    # Verbosity options
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug mode with detailed output'
    )
    
    args = parser.parse_args()
    if not any([args.image, args.batch, args.compare]):
        if len(sys.argv) == 1:
            args = _run_no_args_startup_prompt(args)
        else:
            parser.error("one of the arguments --image/-i --batch/-b --compare is required")
    if _should_launch_wizard(args):
        _run_guided_setup(args)
    args.output = _prepare_output_session_dir(args)
    effective_include_raw = args.ai_mode == 'explain' and args.report in ['html', 'pdf', 'all', 'both']
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('forensic_analysis.log'),
            logging.StreamHandler()
        ]
    )
    
    try:
        # Initialize system
        print("\n" + "="*70)
        print("METADATA EXTRACTION AND IMAGE ANALYSIS SYSTEM".center(70))
        print("="*70 + "\n")
        print(f"Output Folder: {args.output}")
        
        forensic_system = MetaForensicAI(config_path=args.config)
        
        # Prepare case info
        case_info = {}
        if args.case_id:
            case_info['case_id'] = args.case_id
        if args.analyst:
            case_info['analyst'] = args.analyst
        
        # Process based on input type
        if args.image:
            print(f"🔍 Analyzing image: {args.image}")
            
            # Perform analysis
            results = forensic_system.analyze_image(args.image, case_info, ai_mode=args.ai_mode)
            results['include_raw'] = effective_include_raw
            forensic_system.analysis_results = results
            
            # Display summary
            risk_assessment = results.get('risk_assessment', {})
            risk_score = risk_assessment.get('risk_score', 0)
            risk_level = risk_assessment.get('level', 'Unknown')
            origin = results.get('origin_detection', {}).get('primary_origin', 'Unknown')
            
            print(f"\n📊 Analysis Results:")
            print(f"   • Evidence Risk Score: {risk_score}/100")
            if args.ai_mode == 'assist':
                suggested = results.get('assist_suggestions', {}).get('suggested_risk_level', 'Analyst confirmation required')
                print(f"   • Suggested Risk Level: {suggested}")
            else:
                print(f"   • Risk Level: {risk_level}")
            print(f"   • Primary Origin: {origin}")
            print(f"   • Authenticity Flags: {len(results.get('flags', []))}")
            print(f"   • AI Decision Mode: {args.ai_mode}")
            history = results.get('modification_history', {})
            if history:
                print(f"   • Modification History: {history.get('status', 'unknown')} ({history.get('confidence', 'low')} confidence)")
            if args.ai_mode == 'assist':
                print(f"   • Analyst Confirmation: REQUIRED (AI suggestions pending)")
                assist = results.get('assist_suggestions', {})
                if assist:
                    print(f"   • Suggested Structural Finding: {assist.get('suggested_structural_finding')}")
                    print(f"   • Final Decision: {assist.get('final_decision')}")
            elif args.ai_mode == 'strict':
                print(f"   • Decision Policy: RULE-ONLY FORENSIC VALIDATION")
            elif args.ai_mode == 'explain':
                print(f"   • Explainability Entries: {len(results.get('explanations', []))}")

            if args.ask:
                run_ask_chat_mode([results], initial_question=args.ask)

            # Handle direct CLI output options
            if args.report == 'json-cli':
                print("\n--- BEGIN FORENSIC NARRATIVE REPORT ---")
                
                # Integrity
                integrity = results.get('evidence_integrity', {})
                print("\n[EVIDENCE INTEGRITY]")
                print(f"  File Path: {integrity.get('file_path')}")
                print(f"  File Size: {integrity.get('file_size_bytes')} bytes")
                for alg, h in integrity.get('hashes', {}).items():
                    print(f"  {alg.upper()}: {h}")

                # Risk Assessment
                print("\n[RISK ASSESSMENT]")
                print(f"  Unified Risk Score: {risk_score}/100 ({risk_level})")
                print(f"  Bayesian Predictive Risk: {results.get('bayesian_risk', {}).get('predictive_risk_score', 0)}/100 ({results.get('bayesian_risk', {}).get('risk_level', 'N/A')})")
                print(f"  Forensic Interpretation: {risk_assessment.get('unified_interpretation', 'N/A')}")

                # Origin
                print("\n[ORIGIN IDENTIFICATION]")
                print(f"  Primary Origin: {origin}")
                print(f"  Confidence: {results.get('origin_detection', {}).get('confidence', 0)*100:.1f}%")
                print(f"  Details: {results.get('origin_detection', {}).get('details')}")

                history = results.get('modification_history', {})
                if history:
                    print("\n[MODIFICATION HISTORY]")
                    print(f"  Status: {history.get('status')}")
                    print(f"  Confidence: {history.get('confidence')}")
                    print(f"  Likely Modified: {history.get('likely_modified')}")
                    print(f"  Summary: {history.get('summary')}")
                    for event in history.get('events', [])[:8]:
                        print(f"  - {event.get('event')}: {event.get('timestamp') or 'N/A'} | {event.get('details')}")

                # Explanations (XAI)
                print("\n[FORENSIC JUSTIFICATIONS (XAI)]")
                for exp in results.get('explanations', []):
                    print(f"  - [{exp.get('severity', 'INFO')}] {exp.get('title')}: {exp.get('observation')}")

                # Explain Mode Structured Output
                explain_reasoning = results.get('explain_forensic_reasoning', {})
                if explain_reasoning:
                    print("\n[EXPLAIN OUTPUT (STRUCTURED)]")
                    plain = explain_reasoning.get('0_plain_language_summary', {})
                    if plain:
                        print("0. Plain-Language Summary")
                        print(f"  verdict: {plain.get('simple_verdict')}")
                        print(f"  confidence: {plain.get('plain_confidence')}")
                        for item in plain.get('what_supports_this', []):
                            print(f"  - {item}")
                        for item in plain.get('what_this_does_not_prove', []):
                            print(f"  - {item}")
                        print(f"  note: {plain.get('recommended_reading')}")

                    print("1. Multi-Domain Risk Assessment")
                    for k, v in explain_reasoning.get('1_multi_domain_risk_assessment', {}).items():
                        print(f"  {k}: {v}")

                    print("\n2. Evidence Severity Classification")
                    for item in explain_reasoning.get('2_evidence_severity_classification', []):
                        print(f"  - {item.get('indicator')}: {item.get('severity')} ({item.get('reason')})")

                    print("\n3. Model Conflict Analysis")
                    model_conflict = explain_reasoning.get('3_model_conflict_analysis', {})
                    print(f"  conflict_detected: {model_conflict.get('conflict_detected')}")
                    deterministic = model_conflict.get('deterministic_aggregation', {})
                    bayesian = model_conflict.get('bayesian_predictive_model', {})
                    print(f"  deterministic_risk_score: {deterministic.get('risk_score')}")
                    print(f"  deterministic_risk_level: {deterministic.get('risk_level')}")
                    print(f"  deterministic_interpretation: {deterministic.get('interpretation')}")
                    print(f"  bayesian_risk_score: {bayesian.get('risk_score')}")
                    print(f"  bayesian_risk_level: {bayesian.get('risk_level')}")
                    print(f"  bayesian_interpretation: {bayesian.get('interpretation')}")
                    for factor in model_conflict.get('dominance_factors', []):
                        print(f"  - {factor}")

                    print("\n4. Bayesian Calibration Commentary")
                    calibration = explain_reasoning.get('4_bayesian_calibration_commentary', {})
                    print(f"  likelihood_overweighted: {calibration.get('likelihood_overweighted')}")
                    print(f"  commentary: {calibration.get('commentary')}")

                    print("\n5. Unified Interpretation (Improved Classification)")
                    print(f"  {explain_reasoning.get('5_unified_interpretation_improved_classification')}")

                    print("\n6. Forensic Confidence Index")
                    confidence = explain_reasoning.get('6_forensic_confidence_index', {})
                    print(f"  level: {confidence.get('level')}")
                    print(f"  basis: {confidence.get('basis')}")

                    print("\n7. Narrative Forensic Summary")
                    print(f"  {explain_reasoning.get('7_narrative_forensic_summary')}")
                print("--- END FORENSIC NARRATIVE REPORT ---")

                # For json-cli, always include ExifTool-style raw metadata after narrative.
                from .utils.exiftool_formatter import ExifToolStyleFormatter
                print("\n--- BEGIN EXIFTOOL-STYLE METADATA REPORT ---")
                formatted_text = ExifToolStyleFormatter.format(results.get('metadata', {}))
                print(formatted_text)
                print("--- END EXIFTOOL-STYLE METADATA REPORT ---")
            elif args.report == 'exiftool-cli':
                from .utils.exiftool_formatter import ExifToolStyleFormatter
                print("\n--- BEGIN EXIFTOOL-STYLE METADATA REPORT ---")
                formatted_text = ExifToolStyleFormatter.format(results.get('metadata', {}))
                print(formatted_text)
                print("--- END EXIFTOOL-STYLE METADATA REPORT ---")
            else:
                if args.report == 'json':
                    from .utils.exiftool_formatter import ExifToolStyleFormatter
                    print("\n--- BEGIN TERMINAL METADATA REPORT ---")
                    formatted_text = ExifToolStyleFormatter.format(results.get('metadata', {}))
                    print(formatted_text)
                    print("--- END TERMINAL METADATA REPORT ---")

            # Generate reports to files
            if args.report != 'none':
                report_formats = []
                if args.report in ['pdf', 'both', 'all']:
                    report_formats.append('pdf')
                if args.report in ['json', 'both', 'all']:
                    report_formats.append('json')
                if args.report in ['html', 'all']:
                    report_formats.append('html')
                if args.report in ['txt', 'all']:
                    report_formats.append('txt')
                
                if report_formats:
                    print(f"\n📄 Generating reports ({', '.join(report_formats)})...")
                    reports = forensic_system.generate_reports(
                        output_dir=args.output,
                        formats=report_formats
                    )
                    
                    for fmt, path in reports.items():
                        print(f"   ✅ {fmt.upper()} report: {path}")

            # Interactive mode
            if args.interactive:
                print(f"\nLaunching interactive metadata explorer...")
                run_interactive_metadata_mode(results)

            if getattr(args, "_post_image_investigation_prompt", False):
                investigation_mode = _prompt_choice(
                    "Investigation mode",
                    [
                        "Skip",
                        "Tag Investigation Mode (interactive tag inspection CLI)",
                        "MetaForensic AI chatbox (open investigation CLI after analysis)"
                    ],
                    default_index=0
                )
                if investigation_mode.startswith("Tag Investigation Mode"):
                    run_interactive_metadata_mode(results)
                elif investigation_mode.startswith("MetaForensic AI chatbox"):
                    run_ask_chat_mode([results])
        
        elif args.batch:
            print(f"🔍 Batch analyzing directory: {args.batch}")

            batch_report_formats = []
            if args.report in ['pdf', 'both', 'all']:
                batch_report_formats.append('pdf')
            if args.report in ['json', 'both', 'all']:
                batch_report_formats.append('json')
            if args.report in ['html', 'all']:
                batch_report_formats.append('html')
            if args.report in ['txt', 'all']:
                batch_report_formats.append('txt')

            # Keep default behavior only when --report is not a file-output control value.
            if args.report in ['json-cli', 'exiftool-cli']:
                batch_report_formats = []
            elif args.report == 'none':
                batch_report_formats = []
            elif not batch_report_formats:
                batch_report_formats = None
            
            # Perform batch analysis
            batch_results = forensic_system.batch_analyze(
                image_dir=args.batch,
                output_dir=args.output,
                max_images=args.max_images,
                ai_mode=args.ai_mode,
                report_formats=batch_report_formats,
                include_raw=effective_include_raw
            )
            
            print(f"\n📊 Batch Analysis Summary:")
            print(f"   • Total Images: {batch_results.get('total_images', 0)}")
            print(f"   • Successful: {batch_results.get('successful_analyses', 0)}")
            print(f"   • Failed: {batch_results.get('failed_analyses', 0)}")
            print(f"   • Summary Report: {args.output}/batch_summary.json")

            valid = [r for r in batch_results.get('individual_results', []) if 'error' not in r]

            if getattr(args, "_post_batch_investigation_prompt", False):
                setattr(args, "_post_batch_launch_ask_chat", False)
                investigation_mode = _prompt_choice(
                    "4) Investigation mode",
                    [
                        "Skip",
                        "MetaForensic AI chatbox (open investigation CLI after analysis)"
                    ],
                    default_index=0
                )
                if investigation_mode.startswith("MetaForensic AI chatbox"):
                    args.interactive = False
                    args.ask = None
                    setattr(args, "_post_batch_launch_ask_chat", True)
                else:
                    args.interactive = False
                    args.ask = None

            if args.ask:
                if valid:
                    run_ask_chat_mode(valid, initial_question=args.ask)
                else:
                    print("\nNo successful analyses available for MetaForensic AI chatbox.")
            elif getattr(args, "_post_batch_launch_ask_chat", False):
                if valid:
                    run_ask_chat_mode(valid)
                else:
                    print("\nNo successful analyses available for MetaForensic AI chatbox.")
        
        elif args.compare:
            print(f"🔍 Comparing {len(args.compare)} images...")
            analyzed_results = []
            for img_path in args.compare:
                try:
                    analyzed_results.append(forensic_system.analyze_image(img_path, ai_mode=args.ai_mode))
                except Exception as e:
                    analyzed_results.append({'image_path': img_path, 'error': str(e), 'status': 'FAILED'})

            # Perform comparison
            comparison_results = forensic_system.compare_images(
                image_paths=args.compare,
                comparison_type=args.compare_type,
                ai_mode=args.ai_mode,
                precomputed_results=analyzed_results
            )
            
            print(f"\n📊 Comparison Results ({args.compare_type}):")
            
            if args.compare_type == 'metadata':
                for img, info in comparison_results.get('results', {}).items():
                    print(f"   • {img}: {info.get('camera', 'Unknown')} - {info.get('timestamp', 'Unknown')}")
            
            elif args.compare_type == 'timestamps':
                order = comparison_results.get('results', {}).get('chronological_order', [])
                print(f"   • Chronological Order:")
                for i, item in enumerate(order):
                    print(f"     {i+1}. {item['filename']} - {item['timestamp']}")
            
            elif args.compare_type == 'origin':
                origins = comparison_results.get('results', {}).get('origins', {})
                consistency = comparison_results.get('results', {}).get('consistency', 'Unknown')
                print(f"   • Origin Consistency: {consistency}")
                for filename, origin in origins.items():
                    print(f"     - {filename}: {origin}")

            if args.ask:
                valid = [r for r in analyzed_results if 'error' not in r]
                run_ask_chat_mode(valid, initial_question=args.ask)
        
        print(f"\n✨ Analysis completed successfully!")
        print(f"Logs: forensic_analysis.log")
        print(f"Reports: {args.output}/")
        print("="*70 + "\n")
        
    except KeyboardInterrupt:
        print("\n\n[!] Analysis interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if args.debug or args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
