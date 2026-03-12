"""
Debug GPS location resolution.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.metadata_extractor import EnhancedMetadataExtractor
from src.utils.gps_resolver import GPSLocationResolver

TEST_IMAGE = PROJECT_ROOT / "test_gps_image.jpg"

print("=" * 70)
print("GPS Location Resolution Debug")
print("=" * 70)

extractor = EnhancedMetadataExtractor()
metadata = extractor.extract(str(TEST_IMAGE))

gps_data = metadata.get("gps", {})
print("\n1. GPS Data from metadata:")
if isinstance(gps_data, dict):
    for key, value in gps_data.items():
        print(f"   {key}: {value}")
else:
    print(f"   {gps_data}")

print("\n2. Testing GPS Resolver:")
resolver = GPSLocationResolver()
coords = resolver._parse_gps_coordinates(gps_data)
print(f"   Parsed coordinates: {coords}")

if coords:
    lat, lon = coords
    print(f"   Latitude: {lat}")
    print(f"   Longitude: {lon}")

    print("\n3. Attempting reverse geocoding...")
    try:
        location = resolver._reverse_geocode_nominatim(lat, lon)
        if location:
            print("   [OK] Location resolved")
            print(f"   Location Name: {location.get('location_name')}")
            print(f"   City: {location.get('city')}")
            print(f"   Country: {location.get('country')}")
        else:
            print("   [X] Geocoding returned None")
    except Exception as exc:
        print(f"   [X] Geocoding failed: {exc}")
        import traceback

        traceback.print_exc()
else:
    print("   [X] Could not parse GPS coordinates")
    print("\n4. Debugging coordinate parsing:")
    print(f"   GPS data type: {type(gps_data)}")
    print(f"   GPS data is dict: {isinstance(gps_data, dict)}")
    if isinstance(gps_data, dict):
        print(f"   GPS data != 'ABSENT': {gps_data != 'ABSENT'}")
        print("   Looking for latitude keys...")
        for key in gps_data.keys():
            if "lat" in key.lower():
                print(f"     Found: {key} = {gps_data[key]}")

print("\n5. Location in metadata:")
print(f"   {metadata.get('location')}")

print("\n6. Summary location:")
print(f"   {metadata.get('summary', {}).get('location_name')}")
