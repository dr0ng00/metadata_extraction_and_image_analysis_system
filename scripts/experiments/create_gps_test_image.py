"""
Create a sample image with GPS data for testing.
"""

import importlib
import sys
from pathlib import Path

from PIL import Image


def _load_piexif():
    """Load piexif lazily to avoid hard import errors in IDE/runtime."""
    try:
        return importlib.import_module("piexif")
    except ModuleNotFoundError:
        print("[!] Missing dependency: piexif")
        print("    Install it with: pip install piexif")
        sys.exit(1)


piexif = _load_piexif()
PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_PATH = PROJECT_ROOT / "test_gps_image.jpg"

img = Image.new("RGB", (100, 100), color="blue")

exif_dict = {
    "0th": {
        piexif.ImageIFD.Make: b"Test Camera",
        piexif.ImageIFD.Model: b"GPS Test Model",
        piexif.ImageIFD.Software: b"MetaForensicAI Test",
    },
    "GPS": {
        piexif.GPSIFD.GPSLatitudeRef: b"N",
        piexif.GPSIFD.GPSLatitude: ((27, 1), (10, 1), (3060, 100)),
        piexif.GPSIFD.GPSLongitudeRef: b"E",
        piexif.GPSIFD.GPSLongitude: ((78, 1), (2, 1), (3156, 100)),
    },
}

exif_bytes = piexif.dump(exif_dict)
img.save(OUTPUT_PATH, exif=exif_bytes)

print(f"[OK] Created {OUTPUT_PATH.name} with GPS coordinates")
print("    Location: Taj Mahal, Agra, India")
print("    Coordinates: 27.1751N, 78.0421E")
print("\nNow run: python forensicai.py --image test_gps_image.jpg")
