"""
Test script to verify ExifTool wrapper functionality
"""
from typing import Any

from src.core.metadata_extractor import EnhancedMetadataExtractor

def test_exiftool_wrapper():
    print("=" * 70)
    print("MetaForensicAI: ExifTool Wrapper Verification")
    print("=" * 70)
    
    # Initialize extractor
    extractor = EnhancedMetadataExtractor(prefer_exiftool=True)
    
    # Test with a sample image
    test_image = r'c:\metadata_extraction_and_image_analysis_system\venv\Lib\site-packages\sklearn\datasets\images\china.jpg'
    
    print(f"\n[*] Testing metadata extraction on: {test_image}")
    
    try:
        metadata = extractor.extract(test_image)
        
        print(f"\n[✓] Extraction successful!")
        print(f"\n--- Metadata Summary ---")
        print(f"Format: {metadata.get('summary', {}).get('format')}")
        print(f"Dimensions: {metadata.get('summary', {}).get('dimensions')}")
        print(f"Camera: {metadata.get('summary', {}).get('camera_make')} {metadata.get('summary', {}).get('camera_model')}")
        print(f"Software: {metadata.get('summary', {}).get('software')}")
        
        # Check which extraction method was used
        if 'raw_exiftool' in metadata:
            print(f"\n[✓] Extraction Method: ExifTool (Native)")
            print(f"[✓] ExifTool Version: {metadata.get('summary', {}).get('exiftool_version')}")
        else:
            print(f"\n[✓] Extraction Method: Python (Pillow + exifread)")
        
        print(f"\n--- Metadata Groups ---")
        for group in ['file_info', 'exif', 'xmp', 'iptc', 'gps', 'icc_profile', 'c2pa']:
            group_data: Any = metadata.get(group)
            status = "PRESENT" if group_data and group_data != "ABSENT" else "ABSENT"
            count = len(group_data) if isinstance(group_data, dict) else 0
            print(f"{group:15s}: {status:8s} ({count} tags)")
        
    except Exception as e:
        print(f"\n[✗] Extraction failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_exiftool_wrapper()
