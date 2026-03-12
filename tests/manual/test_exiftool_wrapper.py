"""
Manual verification script for ExifTool wrapper functionality.
"""

import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.metadata_extractor import EnhancedMetadataExtractor


def test_exiftool_wrapper() -> None:
    print("=" * 70)
    print("MetaForensicAI: ExifTool Wrapper Verification")
    print("=" * 70)

    extractor = EnhancedMetadataExtractor(prefer_exiftool=True)
    test_image = (
        PROJECT_ROOT
        / "venv"
        / "Lib"
        / "site-packages"
        / "sklearn"
        / "datasets"
        / "images"
        / "china.jpg"
    )

    print(f"\n[*] Testing metadata extraction on: {test_image}")

    try:
        metadata = extractor.extract(str(test_image))

        print("\n[OK] Extraction successful")
        print("\n--- Metadata Summary ---")
        print(f"Format: {metadata.get('summary', {}).get('format')}")
        print(f"Dimensions: {metadata.get('summary', {}).get('dimensions')}")
        print(
            "Camera: "
            f"{metadata.get('summary', {}).get('camera_make')} "
            f"{metadata.get('summary', {}).get('camera_model')}"
        )
        print(f"Software: {metadata.get('summary', {}).get('software')}")

        if "raw_exiftool" in metadata:
            print("\n[OK] Extraction Method: ExifTool (Native)")
            print(
                "[OK] ExifTool Version: "
                f"{metadata.get('summary', {}).get('exiftool_version')}"
            )
        else:
            print("\n[OK] Extraction Method: Python (Pillow + exifread)")

        print("\n--- Metadata Groups ---")
        for group in ["file_info", "exif", "xmp", "iptc", "gps", "icc_profile", "c2pa"]:
            group_data: Any = metadata.get(group)
            status = "PRESENT" if group_data and group_data != "ABSENT" else "ABSENT"
            count = len(group_data) if isinstance(group_data, dict) else 0
            print(f"{group:15s}: {status:8s} ({count} tags)")
    except Exception as exc:
        print(f"\n[X] Extraction failed: {exc}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    test_exiftool_wrapper()
