"""
ExifTool Wrapper for MetaForensicAI

Provides a Python interface to the ExifTool binary for high-fidelity metadata extraction.
Falls back to Python-based extraction if ExifTool is not available.
"""
import subprocess
import json
import shutil
from pathlib import Path
from typing import Dict, Any, Optional


class ExifToolWrapper:
    """Wrapper for ExifTool binary with automatic detection and fallback."""
    
    def __init__(self):
        """Initialize the ExifTool wrapper and detect availability."""
        self.exiftool_path = self._find_exiftool()
        self.available = self.exiftool_path is not None
        
        if self.available:
            self.version = self._get_version()
        else:
            self.version = None
    
    def _find_exiftool(self) -> Optional[str]:
        """
        Locate ExifTool binary on the system.
        
        Returns:
            Path to exiftool binary, or None if not found.
        """
        # Check if exiftool is in PATH
        exiftool_path = shutil.which('exiftool')
        if exiftool_path:
            return exiftool_path
        
        # Check common Windows installation paths
        common_paths = [
            r'C:\Program Files\ExifTool\exiftool.exe',
            r'C:\Program Files (x86)\ExifTool\exiftool.exe',
            r'C:\exiftool\exiftool.exe',
            Path.home() / 'exiftool' / 'exiftool.exe',
        ]
        
        for path in common_paths:
            if Path(path).exists():
                return str(path)
        
        return None
    
    def _get_version(self) -> Optional[str]:
        """Get ExifTool version."""
        exiftool_path = self.exiftool_path
        if exiftool_path is None:
            return None
        try:
            result = subprocess.run(
                [exiftool_path, '-ver'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    def extract_metadata(self, image_path: str) -> Dict[str, Any]:
        """
        Extract metadata using ExifTool.
        
        Args:
            image_path: Absolute path to the image file.
            
        Returns:
            Dictionary containing extracted metadata.
            
        Raises:
            RuntimeError: If ExifTool is not available.
            FileNotFoundError: If the image file doesn't exist.
        """
        if not self.available:
            raise RuntimeError(
                "ExifTool is not available. Please install ExifTool from https://exiftool.org/ "
                "or ensure it's in your system PATH."
            )
        
        image_path_obj = Path(image_path)
        if not image_path_obj.exists():
            raise FileNotFoundError(f"Image not found: {image_path}")
        exiftool_path = self.exiftool_path
        if exiftool_path is None:
            raise RuntimeError("ExifTool path is unavailable despite available=True")
        
        try:
            # Run ExifTool with JSON output for structured parsing
            # -G: Group names, -a: Allow duplicate tags, -s: Short tag names
            # -j: JSON output, -n: Numerical values for GPS
            result = subprocess.run(
                [
                    exiftool_path,
                    '-G',           # Include group names
                    '-a',           # Extract duplicate tags
                    '-s',           # Use short tag names
                    '-j',           # JSON output
                    '-n',           # Print numerical GPS coordinates
                    '-b',           # Output binary data in base64
                    '-struct',      # Enable structured information extraction
                    str(image_path_obj.absolute())
                ],
                capture_output=True,
                text=True,
                timeout=30,
                encoding='utf-8',
                errors='replace'
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"ExifTool failed: {result.stderr}")
            
            # Parse JSON output
            metadata_list = json.loads(result.stdout)
            if not metadata_list:
                return {}
            
            # ExifTool returns a list with one element for single file
            raw_metadata = metadata_list[0]
            
            # Organize metadata into forensic groups
            organized = self._organize_metadata(raw_metadata)
            
            return organized
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("ExifTool execution timed out")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse ExifTool output: {e}")
        except Exception as e:
            raise RuntimeError(f"ExifTool extraction failed: {e}")
    
    def _organize_metadata(self, raw_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Organize ExifTool output into forensic metadata groups.
        
        Args:
            raw_metadata: Raw metadata dictionary from ExifTool JSON output.
            
        Returns:
            Organized metadata dictionary matching MetaForensicAI structure.
        """
        organized = {
            'file_info': {},
            'image_info': {},
            'exif': {},
            'xmp': {},
            'iptc': {},
            'gps': {},
            'icc_profile': {},
            'makernotes': {},
            'composite': {},
            'c2pa': {},
            'raw_exiftool': raw_metadata  # Keep original for reference
        }
        
        # Map ExifTool groups to our structure
        group_mapping = {
            'File': 'file_info',
            'EXIF': 'exif',
            'XMP': 'xmp',
            'IPTC': 'iptc',
            'GPS': 'gps',
            'ICC_Profile': 'icc_profile',
            'MakerNotes': 'makernotes',
            'Composite': 'composite',
            'MakerNote': 'makernotes',
        }
        
        # Process each tag
        for key, value in raw_metadata.items():
            # Skip SourceFile and other system fields
            if key in ['SourceFile', 'ExifToolVersion']:
                continue
            
            # Determine which group this tag belongs to
            placed = False
            for group_prefix, target_group in group_mapping.items():
                if key.startswith(group_prefix):
                    organized[target_group][key] = value
                    placed = True
                    break
            
            # If not placed in a specific group, check for special cases
            if not placed:
                # C2PA/CAI metadata
                if any(c2pa_key in key.lower() for c2pa_key in ['c2pa', 'cai', 'contentcredentials', 'jumbf']):
                    organized['c2pa'][key] = value
                # Image-related tags
                elif any(img_key in key for img_key in ['ImageWidth', 'ImageHeight', 'ImageSize', 'Format', 'ColorSpace']):
                    organized['image_info'][key] = value
                # Default to EXIF
                else:
                    organized['exif'][key] = value
        
        # Mark absent groups
        for group in ['exif', 'xmp', 'iptc', 'gps', 'icc_profile', 'makernotes', 'c2pa']:
            if not organized[group]:
                organized[group] = "ABSENT"
        
        # Generate summary
        organized['summary'] = self._generate_summary(organized)
        
        return organized
    
    def _generate_summary(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary of key metadata fields."""
        exif = metadata.get('exif', {})
        if not isinstance(exif, dict):
            exif = {}
        
        composite = metadata.get('composite', {})
        if not isinstance(composite, dict):
            composite = {}
        
        file_info = metadata.get('file_info', {})
        
        return {
            'dimensions': composite.get('ImageSize') or f"{exif.get('ImageWidth')}x{exif.get('ImageHeight')}",
            'format': file_info.get('FileType'),
            'datetime_original': exif.get('DateTimeOriginal') or exif.get('CreateDate'),
            'camera_make': exif.get('Make'),
            'camera_model': exif.get('Model'),
            'software': exif.get('Software'),
            'exiftool_version': metadata.get('raw_exiftool', {}).get('ExifToolVersion')
        }


__all__ = ['ExifToolWrapper']
