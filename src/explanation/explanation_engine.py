"""Confidence Explanation Engine (stub).

Provides a minimal `ConfidenceExplanationEngine` class to produce human-
readable explanations for forensic flags. Full implementation can be
expanded later; this stub resolves import errors for IDEs and runtime.
"""
from typing import Any, Dict, List


class ConfidenceExplanationEngine:
    """Generate explanations and confidence scores for forensic findings."""
    def __init__(self, templates: Dict[str, Any] | None = None):
        self.templates = templates or {}

    def explain(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Produce human-readable, legal-grade forensic narratives from analysis results.
        Returns a list of structured explanation objects.
        """
        explanations = []
        metadata = analysis_results.get('metadata', {})
        exif = metadata.get('exif', {})

        # 1. Authenticity: Software Signatures
        auth_flags = analysis_results.get('flags', [])
        for flag in auth_flags:
            if "software" in flag.lower():
                sw_tag = "EXIF Software" if "EXIF Software" in exif else "Image Software" if "Image Software" in exif else "Software"
                explanations.append({
                    'title': 'Post-Capture Software Modification',
                    'observation': f"Metadata indicates the image was processed using commercial or open-source editing software.",
                    'triggers': {sw_tag: exif.get(sw_tag, 'Unknown')},
                    'logic': "The presence of software tags unrelated to camera firmware (e.g., Photoshop, GIMP) is a primary indicator of non-original content.",
                    'significance': "In a forensic context, this proves the digital 'chain of custody' of the pixels has been broken by external software.",
                    'causes': {
                        'legitimate': "Standard color correction, cropping, or format conversion by the user.",
                        'malicious': "Targeted pixel manipulation, cloning, or deep-fake synthesis artifacts being masked."
                    },
                    'confidence': 'HIGH',
                    'severity': 'HIGH'
                })

        # 2. Chronological Audits
        ts_analysis = analysis_results.get('timestamp_analysis', {})
        for issue in ts_analysis.get('issues', []):
            trigger_fields = {}
            for field in ['EXIF DateTimeOriginal', 'DateTimeOriginal', 'ModifyDate', 'CreateDate']:
                if exif.get(field): trigger_fields[field] = exif[field]
            
            explanations.append({
                'title': 'Temporal Continuity Anomaly',
                'observation': f"Discrepancy detected between internal metadata timestamps and file system records.",
                'triggers': trigger_fields,
                'logic': "The 'DateTimeOriginal' must logically precede or equal the 'FileModifyDate'. A 'ModifyDate' prior to 'CreateDate' suggests manual retroactive editing.",
                'significance': "Temporal anomalies are often the first sign of 'anti-forensics' where a user attempts to back-date evidence.",
                'causes': {
                    'legitimate': "Incorrect camera clock settings or timezone shifts during file transfer.",
                    'malicious': "Intentional timestamp spoofing to create a false chronological alibi."
                },
                'confidence': 'MEDIUM',
                'severity': 'HIGH'
            })

        # 3. Origin: Synthetic/AI Detection
        origin = analysis_results.get('origin_detection', {})
        origin_label = origin.get('primary_origin')
        if origin_label in {'synthetic_ai_generated', 'ai_generated'}:
            explanations.append({
                'title': 'Synthetic Content (AI-Generated) Identification',
                'observation': "The image lacks the structural and metadata signatures typical of a physical optical sensor.",
                'triggers': {'Metadata Density': 'Low', 'Camera Profile': 'Missing'},
                'logic': "AI generators (DALL-E, Midjourney) typically produce 'sterile' metadata. The absence of expected sensor-specific tags (ISO, Aperture, Serial Number) is statistically significant.",
                'significance': "Identifies non-photographic evidence that may be used for disinformation or fraud.",
                'causes': {
                    'legitimate': "N/A (Synthetic images are by definition not camera-originals).",
                    'malicious': "Generation of non-existent events or personas."
                },
                'confidence': 'CRITICAL',
                'severity': 'CRITICAL'
            })
        elif origin_label == 'screenshot_capture':
            screenshot_signals = origin.get('features', {}).get('raw_signals', {}).get('screenshot_signals', {})
            explanations.append({
                'title': 'Screenshot / Screen-Capture Identification',
                'observation': "The image exhibits software-capture characteristics rather than optical camera-acquisition signatures.",
                'triggers': {
                    'Origin Classification': origin_label,
                    'Platform Hint': origin.get('platform_fingerprint', 'N/A'),
                    'Screenshot Signal Strength': origin.get('forensic_signals_detected', {}).get('screenshot_strength', 'N/A'),
                    'Screen Resolution Match': screenshot_signals.get('screen_resolution_score', 'N/A'),
                    'Timestamp Cluster': screenshot_signals.get('timestamp_cluster_score', 'N/A'),
                },
                'logic': "Screenshots usually lack camera EXIF, often match display resolutions, often preserve tightly clustered filesystem timestamps, and may include screenshot-oriented software identifiers or naming conventions.",
                'significance': "This distinguishes screen-captured content from camera photographs and explains the absence of lens/sensor metadata.",
                'causes': {
                    'legitimate': "User captured the screen using operating-system screenshot tooling.",
                    'malicious': "An evidentiary image may have been reproduced from a display rather than obtained as original camera output."
                },
                'confidence': 'HIGH',
                'severity': 'MEDIUM'
            })
        elif origin_label == 'social_media':
            social_signals = origin.get('features', {}).get('raw_signals', {}).get('social_media_signals', {})
            explanations.append({
                'title': 'Social Media / Messaging Redistribution Identification',
                'observation': "The image exhibits platform-style metadata stripping, recompression, and delivery-size characteristics.",
                'triggers': {
                    'Origin Classification': origin_label,
                    'Platform Hint': origin.get('platform_fingerprint', 'N/A'),
                    'Likely Platform': social_signals.get('likely_platform', 'N/A'),
                    'Likely Platform Confidence': social_signals.get('likely_platform_confidence', 'N/A'),
                    'Social Media Signal Strength': origin.get('forensic_signals_detected', {}).get('social_media_strength', 'N/A'),
                    'Platform Resolution Match': social_signals.get('platform_resolution_score', 'N/A'),
                    'Metadata Stripping Score': social_signals.get('metadata_strip_score', 'N/A'),
                },
                'logic': "Images downloaded from messaging and social-media platforms often lose EXIF, are resized to standardized delivery dimensions, and are re-encoded with platform-managed JPEG compression. Platform attribution is inferred from the convergence of filename, dimensions, token matches, and recompression cues.",
                'significance': "This indicates redistribution through a platform pipeline, which can explain missing camera metadata and recompression traces without implying original pixel tampering.",
                'causes': {
                    'legitimate': "The file was downloaded from WhatsApp, Instagram, Facebook, X, Snapchat, or another platform after upload.",
                    'malicious': "A manipulated image may have been laundered through a platform pipeline to obscure its original metadata lineage."
                },
                'confidence': 'HIGH',
                'severity': 'MEDIUM'
            })
        elif origin_label == 'origin_unverified':
            explanations.append({
                'title': 'Metadata Preservation Limitation',
                'observation': "Metadata appears removed during export. Editing application cannot be identified.",
                'triggers': {'Origin Classification': origin_label},
                'logic': "Missing camera and software attribution metadata prevents definitive lineage attribution.",
                'significance': "This is a forensic limitation notice, not direct proof of synthetic generation.",
                'causes': {
                    'legitimate': "Messaging app or social media export stripped metadata.",
                    'malicious': "Intentional metadata scrubbing before distribution."
                },
                'confidence': 'MEDIUM',
                'severity': 'MEDIUM'
            })
        
        # Get contextual analysis results
        context = analysis_results.get('contextual_analysis', {})

        # New: Contextual Location Inference
        inferred_loc = context.get('inferred_location', {})
        if inferred_loc:
            explanations.append({
                'title': 'Inferred Geospatial Origin (Non-GPS)',
                'observation': f"Probable origin region identified as '{inferred_loc.get('region', 'Unknown')}' based on indirect metadata.",
                'triggers': {'Source': inferred_loc.get('source', 'N/A')},
                'logic': "Even without GPS coordinates, metadata like TimeZoneOffset, when correlated with capture time, can strongly suggest a geographic region. This is a standard technique in digital forensics.",
                'significance': "Provides a probable geographic context for the evidence, which can be crucial for an investigation even if it's not coordinate-precise.",
                'causes': {
                    'legitimate': "The device correctly recorded its local timezone, which was used for inference.",
                    'malicious': "The timezone itself could be part of a sophisticated spoofing attempt, but this is less common than GPS spoofing."
                },
                'confidence': inferred_loc.get('confidence', 'LOW'),
                'severity': 'MEDIUM'
            })

        # 4. Contextual Paradoxes
        for issue in context.get('issues', []):
            title = 'Contextual Inconsistency'
            logic = "The analysis detected a mismatch between captured metadata and external environmental context."
            if 'Paradox' in issue:
                title = 'Luminosity-Time Paradox'
                logic = "The measured luminosity of the image pixels is inconsistent with the captured timestamp's solar position."
            elif 'GPS' in issue:
                title = 'Geospatial Trustworthiness Anomaly'
                logic = "The GPS coordinates indicate a location (e.g., 'Null Island') commonly associated with spoofing or default-initialized values."

            explanations.append({
                'title': title,
                'observation': issue,
                'triggers': {'GPSCoordinates': exif.get('GPS GPSLatitude', 'N/A'), 'CaptureTime': exif.get('EXIF DateTimeOriginal', 'N/A')},
                'logic': logic,
                'significance': "Proof of context prevents the presentation of 'misplaced' evidence recorded at one time/place as being from another.",
                'causes': {
                    'legitimate': "GPS sensor failure or use of powerful artificial lighting at night.",
                    'malicious': "Coordinate spoofing or manual 'cut-and-paste' of metadata from another file."
                },
                'confidence': 'HIGH',
                'severity': 'HIGH'
            })

        # 5. Signal Analysis (Advanced Point 14)
        artifacts = analysis_results.get('artifact_analysis', {})
        ela = artifacts.get('ela_results', {})
        if ela.get('ela_intensity') == 'HIGH':
            explanations.append({
                'title': 'Error Level Analysis (ELA) regional variance',
                'observation': f"Pixel compression error levels vary significantly across regions (Max Diff: {ela.get('max_difference')}).",
                'triggers': {'ELA Intensity': 'HIGH', 'Max Difference': ela.get('max_difference')},
                'logic': "In a uniform JPEG capture, compression artifacts should be homogeneous. Disproportionate error levels in specific regions suggest local pixel modification (e.g., cloning or airbrushing).",
                'significance': "Visual proof of regional tampering that may not be recorded in the metadata headers.",
                'causes': {
                    'legitimate': "Intense high-frequency detail vs. smooth gradients in the original scene.",
                    'malicious': "Post-capture regional editing to remove or add objects (cloning)."
                },
                'confidence': 'MEDIUM',
                'severity': 'HIGH'
            })

        qtable = artifacts.get('qtable_audit', {})
        if qtable.get('signature_match') == 'Software_Modification':
            explanations.append({
                'title': 'Non-Standard Quantization Profile',
                'observation': "The image uses compression matrices typically associated with editing software rather than camera firmware.",
                'triggers': {'Q-Table Match': 'Software_Modification'},
                'logic': "Every camera manufacturer uses specific quantization tables. A match with software-grade tables proves the image has been re-saved by a processing suite.",
                'significance': "Solidifies the 'Post-Capture Modification' flag with independent signal-layer evidence.",
                'causes': {
                    'legitimate': "Intentional re-save for web optimization or distribution.",
                    'malicious': "Final save after significant structural tampering."
                },
                'confidence': 'HIGH',
                'severity': 'HIGH'
            })

        # 7. Correlation & Conclusion
        correlation = analysis_results.get('correlation', {})
        interpretation = correlation.get('unified_interpretation', 'UNKNOWN')
        if interpretation != 'UNKNOWN':
            explanations.append({
                'title': 'Unified Forensic Conclusion',
                'observation': f"Multi-source correlation interprets this evidence as {interpretation.replace('_', ' ')}.",
                'triggers': {'Interpretation': interpretation},
                'logic': "Aggregated findings from ML classification, rule-based logic, and statistical anomalies converge on this result.",
                'significance': "Provides a single, weighted determination for the trier of fact.",
                'causes': {
                    'legitimate': "General consistency across all forensic modules.",
                    'malicious': "Converged evidence of intentional manipulation or fabrication."
                },
                'confidence': 'HIGH',
                'severity': 'CRITICAL'
            })

        return explanations


__all__ = ['ConfidenceExplanationEngine']
