"""Artifact Analyzer for deep signal and image analysis.

Provides `ArtifactAnalyzer` for detecting compression inconsistencies (ELA) 
and auditing quantization tables.
"""
import io
from typing import Any, Dict, List, Optional, Tuple, Union, cast
from PIL import Image, ImageChops

ExtremaPair = Tuple[int, int]
ExtremaValue = Union[ExtremaPair, Tuple[ExtremaPair, ...]]

class ArtifactAnalyzer:
    """Performs deep signal analysis on image artifacts."""

    def __init__(self):
        # Library of common Q-Table signatures (simplified for simulation)
        self.qtable_library = {
            'Adobe Photoshop': [1, 1, 1, 1, 1, 1, 1, 1], # Placeholder
            'Standard JPEG': [16, 11, 10, 16, 24, 40, 51, 61], # Common Luma Table
            'Canon Firmware': [2, 2, 2, 2, 2, 2, 2, 2] # Placeholder
        }
        # Bound ELA workload on high-resolution images.
        self.ela_max_side = 2048

    def analyze(self, image_path: str) -> Dict[str, Any]:
        """
        Perform deep artifact analysis.
        
        Args:
            image_path: Path to the image file.
            
        Returns:
            Dictionary with ELA results and Q-table audit findings.
        """
        results = {
            'ela_results': self._perform_ela(image_path),
            'qtable_audit': self._audit_qtables(image_path),
            'advanced_flags': []
        }

        # Correlate findings to generate flags
        if results['ela_results'].get('max_difference', 0) > 40:
             results['advanced_flags'].append("HIGH_ELA_VARIANCE: Potential regional manipulation detected.")
        
        if results['qtable_audit'].get('signature_match') == 'Software_Modification':
            results['advanced_flags'].append("FOREIGN_QTABLE: Compression profile matches non-camera software.")

        return results

    def _perform_ela(self, image_path: str, quality: int = 90) -> Dict[str, Any]:
        """
        Perform Error Level Analysis (ELA).
        Identifies areas with different levels of compression error.
        """
        try:
            # 1. Open original and save as temporary JPEG with specific quality
            with Image.open(image_path) as src:
                original = src.convert('RGB')

            resized = False
            if max(original.size) > self.ela_max_side:
                original.thumbnail((self.ela_max_side, self.ela_max_side), Image.Resampling.LANCZOS)
                resized = True

            # Use a buffer instead of a file for forensic soundness (minimal footprint)
            buf = io.BytesIO()
            original.save(buf, format='JPEG', quality=quality)
            buf.seek(0)
            with Image.open(buf) as resaved_img:
                resaved = resaved_img.convert('RGB')

            # 2. Calculate the difference
            diff = ImageChops.difference(original, resaved)
            
            # 3. Enhance the difference for human/algos
            extrema = cast(ExtremaValue, diff.getextrema())
            if isinstance(extrema[0], tuple):
                multi_extrema = cast(Tuple[ExtremaPair, ...], extrema)
                max_diff = float(max(pair[1] for pair in multi_extrema))
            else:
                single_extrema = cast(ExtremaPair, extrema)
                max_diff = float(single_extrema[1])
            if max_diff == 0:
                max_diff = 1
            scale = 255.0 / max_diff
            
            enhanced_diff = diff.point(lambda p: p * scale)
            
            # Summarize stats for our automated engine
            stats = enhanced_diff.getextrema()
            
            return {
                'max_difference': max_diff,
                'scale_factor': round(scale, 2),
                'ela_intensity': "HIGH" if max_diff > 35 else "NORMAL",
                'resized_for_speed': resized,
                'status': 'SUCCESS'
            }
        except KeyboardInterrupt:
            return {'status': 'INTERRUPTED', 'message': 'ELA interrupted by user'}
        except Exception as e:
            return {'status': 'ERROR', 'message': str(e)}

    def _audit_qtables(self, image_path: str) -> Dict[str, Any]:
        """
        Audit Quantization Tables from JPEG header.
        Different software/cameras use different Q-tables for the same quality level.
        """
        try:
            with Image.open(image_path) as img:
                if img.format != 'JPEG':
                    return {'status': 'SKIPPED', 'reason': 'Not a JPEG file'}
                
                # Pillow extracts quantization tables into img.quantization
                qtables = getattr(img, 'quantization', {})
                
                if not qtables:
                    return {'status': 'ABSENT', 'reason': 'No Q-tables found in header'}

                # Analyze the Luma Table (usually index 0)
                luma_table = qtables.get(0, [])
                
                # Simplified signature matching logic
                match = 'Generic_Capture'
                software_profile = None
                if any(x < 5 for x in luma_table[:3]): # Very high quality/editing software
                    match = 'Software_Modification'
                    software_profile = 'Adobe Photoshop (heuristic)'
                elif luma_table == self.qtable_library['Standard JPEG']:
                    match = 'Standard_JPEG_Profile'
                elif luma_table[:8] == self.qtable_library['Adobe Photoshop']:
                    match = 'Software_Modification'
                    software_profile = 'Adobe Photoshop'

                return {
                    'luma_table': list(luma_table),
                    'signature_match': match,
                    'software_profile': software_profile,
                    'status': 'SUCCESS'
                }
        except Exception as e:
            return {'status': 'ERROR', 'message': str(e)}

__all__ = ['ArtifactAnalyzer']
