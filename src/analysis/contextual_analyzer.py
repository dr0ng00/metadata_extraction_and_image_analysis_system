"""Contextual analysis helpers for image evidence.

This module provides a lightweight `ContextualAnalyzer` class used by
the analysis package. Implementations can be fleshed out later.
"""
from typing import Any, Dict


class ContextualAnalyzer:
    """Analyze contextual metadata (e.g., GPS, captions, timestamps).

    This is a minimal stub that callers can import and extend.
    """
    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}

    def analyze(self, metadata: Dict[str, Any], image_path: str | None = None) -> Dict[str, Any]:
        """
        Perform contextual forensic checks (Goal 4 & Point 7):
        - GPS trustworthiness assessment
        - Day/Night consistency (Timestamp vs Luminosity)
        - Scene relevance (Object detection simulation)
        """
        from PIL import Image, ImageStat
        exif = metadata.get('exif', {})
        if not isinstance(exif, dict): exif = {}
        
        summary = metadata.get('summary', {})
        if not isinstance(summary, dict): summary = {}
        issues = []
        confidence = 1.0
        inferred_location = {}
        
        # 1. GPS Trustworthiness (Goal 4.1)
        lat = exif.get('GPS GPSLatitude')
        lon = exif.get('GPS GPSLongitude')
        altitude = exif.get('GPS GPSAltitude')
        
        if lat and lon:
            # Check for "Null Island" (0,0) or malformed data
            if '0, 0, 0' in str(lat) and '0, 0, 0' in str(lon):
                issues.append("GPS Spoofing Check: Detected 'Null Island' (0,0) coordinates.")
                confidence -= 0.3
            
            # Check for Altitude anomalies (e.g. negative or strictly zero)
            if altitude == '0' or altitude == '0/1':
                # many devices default to 0, so just a note
                pass
        
        # 2. Day/Night Consistency Verification (Goal 4.2)
        timestamp = summary.get('datetime_original')
        hour = None
        if timestamp:
            try:
                time_part = str(timestamp).split(' ')[1]
                hour = int(time_part.split(':')[0])
                is_night_time = hour >= 20 or hour <= 5 # 8 PM to 5 AM
                
                # Verify against Luminosity if image is available
                if image_path:
                    with Image.open(image_path) as img:
                        # Convert to grayscale and get average brightness
                        stat = ImageStat.Stat(img.convert('L'))
                        mean_brightness = stat.mean[0]
                        
                        # Thresholds (Simulated Forensic AI Logic)
                        if is_night_time and mean_brightness > 180:
                            issues.append(f"Day/Night Paradox: Timestamp indicates night ({hour}:00), but image luminosity is high ({mean_brightness:.1f}).")
                            confidence -= 0.4
                        elif not is_night_time and mean_brightness < 30:
                            issues.append(f"Day/Night Paradox: Timestamp indicates day ({hour}:00), but image luminosity is extremely low ({mean_brightness:.1f}).")
                            confidence -= 0.3
            except Exception as e:
                pass

        # 3. Metadata-Based Location Inference (Non-GPS)
        # Analyze TimeZoneOffset, etc.
        tz_offset = exif.get('EXIF TimeZoneOffset') or exif.get('TimeZoneOffset')
        if tz_offset and not (lat and lon):
            try:
                # Example: "+05:30" -> India, "-05:00" -> US East Coast
                if tz_offset == "+05:30":
                    inferred_location = {'region': 'Indian Subcontinent', 'source': 'TimeZoneOffset', 'confidence': 'MEDIUM'}
                    issues.append("Inferred Location: Probable origin in Indian Subcontinent based on TimeZoneOffset (+05:30).")
                elif tz_offset in ["-04:00", "-05:00"]:
                    inferred_location = {'region': 'North America (East)', 'source': 'TimeZoneOffset', 'confidence': 'MEDIUM'}
                    issues.append("Inferred Location: Probable origin in North America (East) based on TimeZoneOffset.")
            except Exception:
                pass # Ignore parsing errors

        # 4. Image Content-Based Geolocation (Simulated for Goal 4.3)
        # Use cases for scene relevance: vehicles, landmarks
        # In a full implementation, a CNN/Vision Transformer model would run here.
        caption = summary.get('user_comment', '').lower()
        if 'landmark' in caption or 'car' in caption:
            # simulated verification
            pass

        return {
            'issues': issues,
            'confidence': max(0.0, confidence),
            'risk_score': round((1.0 - confidence) * 100, 1),
            'findings': {
                'gps_trustworthy': len([i for i in issues if 'GPS' in i]) == 0,
                'day_night_consistent': len([i for i in issues if 'Paradox' in i]) == 0,
                'metadata_hour': hour,
                'inferred_location': inferred_location
            }
        }


__all__ = ['ContextualAnalyzer']
