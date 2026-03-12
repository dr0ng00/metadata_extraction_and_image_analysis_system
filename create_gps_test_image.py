"""
Create a sample image with GPS data for testing
"""
import importlib
import sys
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

# Create a simple test image
img = Image.new('RGB', (100, 100), color='blue')

# Create EXIF data with GPS coordinates
# Example: Taj Mahal, Agra, India (27.1751° N, 78.0421° E)
exif_dict = {
    "0th": {
        piexif.ImageIFD.Make: b"Test Camera",
        piexif.ImageIFD.Model: b"GPS Test Model",
        piexif.ImageIFD.Software: b"MetaForensicAI Test"
    },
    "GPS": {
        piexif.GPSIFD.GPSLatitudeRef: b'N',
        piexif.GPSIFD.GPSLatitude: ((27, 1), (10, 1), (3060, 100)),  # 27°10'30.6"N
        piexif.GPSIFD.GPSLongitudeRef: b'E',
        piexif.GPSIFD.GPSLongitude: ((78, 1), (2, 1), (3156, 100)),  # 78°2'31.56"E
    }
}

exif_bytes = piexif.dump(exif_dict)
img.save('test_gps_image.jpg', exif=exif_bytes)

print("[✓] Created test_gps_image.jpg with GPS coordinates")
print("    Location: Taj Mahal, Agra, India")
print("    Coordinates: 27.1751°N, 78.0421°E")
print("\nNow run: python forensicai.py --image test_gps_image.jpg")
