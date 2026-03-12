"""
Verify GPS coordinates match location names.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.metadata_extractor import EnhancedMetadataExtractor

extractor = EnhancedMetadataExtractor()
metadata = extractor.extract(str(PROJECT_ROOT / "test_gps_image.jpg"))

print("=" * 70)
print("GPS COORDINATE VERIFICATION")
print("=" * 70)

gps = metadata.get("gps", {})
print("\n1. GPS COORDINATES FROM METADATA:")
print(f"   Latitude:  {gps.get('GPS GPSLatitude')} {gps.get('GPS GPSLatitudeRef')}")
print(f"   Longitude: {gps.get('GPS GPSLongitude')} {gps.get('GPS GPSLongitudeRef')}")

location = metadata.get("location", {})
if location:
    print("\n2. RESOLVED LOCATION:")
    print(f"   Decimal Coordinates: {location.get('latitude')}, {location.get('longitude')}")
    print(f"   Location Name: {location.get('location_name')}")
    print(f"   City: {location.get('city')}")
    print(f"   State: {location.get('state')}")
    print(f"   Country: {location.get('country')}")
    print("\n   Full Address:")
    print(f"   {location.get('full_address')}")

    lat = location.get("latitude")
    lon = location.get("longitude")
    print("\n3. VERIFY ON GOOGLE MAPS:")
    print(f"   https://www.google.com/maps?q={lat},{lon}")
else:
    print("\n2. NO LOCATION RESOLVED")

summary = metadata.get("summary", {})
print("\n4. SUMMARY:")
print(f"   Location Name: {summary.get('location_name')}")
print(f"   Country: {summary.get('country')}")
