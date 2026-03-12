"""
Debug GPS location resolution
"""
from src.core.metadata_extractor import EnhancedMetadataExtractor
from src.utils.gps_resolver import GPSLocationResolver
import json

print("=" * 70)
print("GPS Location Resolution Debug")
print("=" * 70)

# Extract metadata
extractor = EnhancedMetadataExtractor()
metadata = extractor.extract('test_gps_image.jpg')

# Check GPS data
gps_data = metadata.get('gps', {})
print("\n1. GPS Data from metadata:")
if isinstance(gps_data, dict):
    for key, value in gps_data.items():
        print(f"   {key}: {value}")
else:
    print(f"   {gps_data}")

# Test GPS resolver
print("\n2. Testing GPS Resolver:")
resolver = GPSLocationResolver()

# Try to parse coordinates
coords = resolver._parse_gps_coordinates(gps_data)
print(f"   Parsed coordinates: {coords}")

if coords:
    lat, lon = coords
    print(f"   Latitude: {lat}")
    print(f"   Longitude: {lon}")
    
    # Try reverse geocoding
    print("\n3. Attempting reverse geocoding...")
    try:
        location = resolver._reverse_geocode_nominatim(lat, lon)
        if location:
            print(f"   ✓ Location resolved!")
            print(f"   Location Name: {location.get('location_name')}")
            print(f"   City: {location.get('city')}")
            print(f"   Country: {location.get('country')}")
        else:
            print(f"   ✗ Geocoding returned None")
    except Exception as e:
        print(f"   ✗ Geocoding failed: {e}")
        import traceback
        traceback.print_exc()
else:
    print("   ✗ Could not parse GPS coordinates")
    print("\n4. Debugging coordinate parsing:")
    print(f"   GPS data type: {type(gps_data)}")
    print(f"   GPS data is dict: {isinstance(gps_data, dict)}")
    if isinstance(gps_data, dict):
        print(f"   GPS data != 'ABSENT': {gps_data != 'ABSENT'}")
        print(f"   Looking for latitude keys...")
        for key in gps_data.keys():
            if 'lat' in key.lower():
                print(f"     Found: {key} = {gps_data[key]}")

# Check if location was added to metadata
print("\n5. Location in metadata:")
location_in_metadata = metadata.get('location')
print(f"   {location_in_metadata}")

print("\n6. Summary location:")
summary_location = metadata.get('summary', {}).get('location_name')
print(f"   {summary_location}")
