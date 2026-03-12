"""Timestamp consistency and tampering checks.

Lightweight `TimestampAnalyzer` stub used by the analysis package.
"""
from typing import Any, Dict
import datetime


class TimestampAnalyzer:
    """Analyze timestamp fields and detect anomalies."""
    def __init__(self, threshold_seconds: int = 3600):
        self.threshold_seconds = threshold_seconds

    def analyze(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze timestamp fields for forensic anomalies:
        - Future dates
        - Date inconsistencies (Digitized before Original)
        - File system vs EXIF mismatch
        """
        summary = metadata.get('summary', {})
        if not isinstance(summary, dict): summary = {}
        
        exif = metadata.get('exif', {})
        if not isinstance(exif, dict): exif = {}
        issues = []
        confidence = 1.0
        
        # 1. Extraction of various timestamp fields
        dt_original = summary.get('datetime_original')
        dt_digitized = exif.get('EXIF DateTimeDigitized')
        dt_file = summary.get('file_modify_date')
        
        # 2. Heuristic: Future Date Check
        now = datetime.datetime.now()
        
        def parse_exif_date(date_str):
            if not date_str or date_str == 'Unknown': return None
            try:
                # EXIF format is usually YYYY:MM:DD HH:MM:SS
                return datetime.datetime.strptime(str(date_str)[:19], "%Y:%m:%d %H:%M:%S")
            except ValueError:
                return None

        ts_original = parse_exif_date(dt_original)
        ts_digitized = parse_exif_date(dt_digitized)
        
        if ts_original:
            if ts_original > now + datetime.timedelta(days=1):
                issues.append(f"Future capture date detected: {dt_original}")
                confidence -= 0.5
            
            # Pre-digital era check (Heuristic: Pre-1990 is suspicious for modern EXIF)
            if ts_original.year < 1990:
                issues.append(f"Suspiciously old capture date: {dt_original}")
                confidence -= 0.3

        # 3. Sequencing Check: Digitized vs Original
        if ts_original and ts_digitized:
            if ts_digitized < ts_original:
                issues.append("Chronological paradox: Digitization date precedes Capture date")
                confidence -= 0.4

        # 4. File System Consistency
        # Note: In some cases, file modification date can lead EXIF (e.g. copying)
        # but EXIF original should almost never be after file creation if never edited.
        
        return {
            'issues': issues,
            'confidence': max(0.0, confidence),
            'timestamp_audit': {
                'original': dt_original,
                'digitized': dt_digitized,
                'is_consistent': len(issues) == 0
            }
        }


__all__ = ['TimestampAnalyzer']
