"""
Test GPS location resolution functionality
"""
from src.core.metadata_extractor import EnhancedMetadataExtractor

def test_gps_resolution():
    print("=" * 70)
    print("MetaForensicAI: GPS Location Resolution Test")
    print("=" * 70)
    
    extractor = EnhancedMetadataExtractor()
    
    # Test with an image (you can replace with an image that has GPS data)
    test_image = r'c:\metadata_extraction_and_image_analysis_system\venv\Lib\site-packages\sklearn\datasets\images\china.jpg'
    
    print(f"\n[*] Extracting metadata from: {test_image}")
    
    try:
        metadata = extractor.extract(test_image)
        
        print(f"\n--- GPS Information ---")
        gps_data = metadata.get('gps')
        
        if gps_data and gps_data != "ABSENT":
            print(f"GPS Data Found: {len(gps_data)} tags")
            for key, value in gps_data.items():
                print(f"  {key}: {value}")
            
            # Check if location was resolved
            location = metadata.get('location')
            if location:
                print(f"\n[✓] Location Resolved!")
                print(f"Location Name: {location.get('location_name')}")
                print(f"City: {location.get('city')}")
                print(f"State: {location.get('state')}")
                print(f"Country: {location.get('country')} ({location.get('country_code')})")
                print(f"Coordinates: {location.get('coordinates')}")
                print(f"\nFull Address: {location.get('full_address')}")
            else:
                print(f"\n[!] GPS coordinates found but location resolution failed")
                print(f"    (This may happen if coordinates are invalid or geocoding service is unavailable)")
        else:
            print("No GPS data found in this image")
            print("\nNote: The test image (china.jpg) may not have GPS coordinates.")
            print("To test GPS resolution, use an image with embedded GPS data")
            print("(typically photos taken with smartphones or GPS-enabled cameras)")
        
    except Exception as e:
        print(f"\n[✗] Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_gps_resolution()
