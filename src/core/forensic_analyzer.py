"""Forensic analyzer implementation.

Provides `MetadataAuthenticityAnalyzer` for analyzing metadata consistency
and detecting potential manipulation traces.
"""
from typing import Any, Dict
from datetime import datetime


class MetadataAuthenticityAnalyzer:
    """Analyze metadata for authenticity indicators."""

    def __init__(self, model: Any | None = None):
        self.model = model

    def analyze(self, metadata: Dict[str, Any] | None = None, image_path: str | None = None, case_info: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """
        Analyze metadata for signs of manipulation (Goal 1).
        - EXIF/XMP/MakerNotes consistency
        - Identify anomalies and camera mismatches
        """
        if not metadata:
            return {'error': 'No metadata provided', 'authentic': False}

        flags = []
        score = 1.0  # Start with perfect score
        exif = metadata.get('exif', {})
        if not isinstance(exif, dict): exif = {}
        
        summary = metadata.get('summary', {})
        if not isinstance(summary, dict): summary = {}

        # 1. Software Signature Detection
        software_fields = summary.get('software_candidates', [])
        if not software_fields and summary.get('software'):
            software_fields = [summary.get('software')]
        if software_fields:
            editing_tools = ['photoshop', 'gimp', 'lightroom', 'paint', 'editor', 'canvas', 'adobe', 'picasa']
            joined = " | ".join(str(s) for s in software_fields)
            if any(tool in joined.lower() for tool in editing_tools):
                flags.append(f"Editing software detected: {joined}")
                score -= 0.3

        # 2. Date consistency checks
        file_info = metadata.get('file_info', {})
        mtime = file_info.get('modified_at')
        original_date = summary.get('datetime_original')
        digitized_date = exif.get('EXIF DateTimeDigitized') or exif.get('DateTimeDigitized')

        if original_date:
            try:
                dt_orig = datetime.strptime(str(original_date).split('+')[0].strip(), '%Y:%m:%d %H:%M:%S')
                
                # Check for mismatch between Original and Digitized
                if digitized_date:
                    dt_digi = datetime.strptime(str(digitized_date).split('+')[0].strip(), '%Y:%m:%d %H:%M:%S')
                    if dt_orig != dt_digi:
                        flags.append("Mismatch between DateTimeOriginal and DateTimeDigitized")
                        score -= 0.1
                
                # Check if file mtime is earlier than capture (Impossible)
                if mtime:
                    dt_file = datetime.fromisoformat(mtime)
                    if (dt_orig - dt_file).total_seconds() > 60: # 1 min buffer
                        flags.append("File modification time is earlier than metadata capture time")
                        score -= 0.4
            except (ValueError, TypeError):
                pass
        else:
            flags.append("Missing essential DateTimeOriginal metadata")
            score -= 0.05

        # 3. Camera/Hardware Mismatch (Simple)
        camera_make = summary.get('camera_make')
        # Many generated images or scrubbed images lack camera info
        if not camera_make:
            flags.append("No camera hardware signatures found in metadata")
            score -= 0.05

        # 4. Anomaly Detection: Missing typical EXIF for Camera
        camera_specific_tags = ['EXIF ExposureTime', 'EXIF FNumber', 'EXIF ISOSpeedRatings']
        missing_count = sum(1 for tag in camera_specific_tags if tag not in exif)
        if camera_make and missing_count > 1:
            flags.append("Camera metadata present but missing critical exposure tags")
            score -= 0.2

        # 5. Structural Heuristics: Resolution & Ratio (Goal 2/Recompression)
        image_info = metadata.get('image_info', {})
        if not isinstance(image_info, dict): image_info = {}
        
        w, h = image_info.get('width'), image_info.get('height')
        if w and h:
            ratio = round(w / h, 3)
            # Sensors usually 4:3 (1.333), 3:2 (1.5), 16:9 (1.778)
            std_ratios = [1.333, 1.5, 1.778, 0.75, 0.667, 0.562]
            if not any(abs(ratio - r) < 0.01 for r in std_ratios) and abs(ratio - 1.0) > 0.05:
                flags.append(f"Non-standard aspect ratio ({ratio}): Possible cropping or manipulation")
                score -= 0.1
            
            # Resolution vs Quality: Large image with very small file size
            # (Crude check for low-quality re-compression)
            file_size = metadata.get('evidence_integrity', {}).get('file_size_bytes', 0)
            if w * h > 2000000 and file_size < 100000: # >2MP but <100KB is suspicious
                flags.append("Abnormally high compression ratio: Potential mass distribution re-encoding")
                score -= 0.2

        # Final Assessment
        score = max(0.0, score)
        authentic = len(flags) == 0

        return {
            'authentic': authentic,
            'confidence': score,
            'flags': flags,
            'risk_score': round((1.0 - score) * 100, 1),
            'image_path': image_path,
            'case_info': case_info or {},
            'analysis_timestamp': datetime.now().isoformat()
        }


__all__ = ['MetadataAuthenticityAnalyzer']
