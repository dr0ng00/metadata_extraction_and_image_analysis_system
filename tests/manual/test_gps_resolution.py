"""
Manual GPS location resolution verification.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.metadata_extractor import EnhancedMetadataExtractor


def test_gps_resolution() -> None:
    print("=" * 70)
    print("MetaForensicAI: GPS Location Resolution Test")
    print("=" * 70)

    extractor = EnhancedMetadataExtractor()
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

    print(f"\n[*] Extracting metadata from: {test_image}")

    try:
        metadata = extractor.extract(str(test_image))

        print("\n--- GPS Information ---")
        gps_data = metadata.get("gps")

        if gps_data and gps_data != "ABSENT":
            print(f"GPS Data Found: {len(gps_data)} tags")
            for key, value in gps_data.items():
                print(f"  {key}: {value}")

            location = metadata.get("location")
            if location:
                print("\n[OK] Location Resolved")
                print(f"Location Name: {location.get('location_name')}")
                print(f"City: {location.get('city')}")
                print(f"State: {location.get('state')}")
                print(
                    "Country: "
                    f"{location.get('country')} ({location.get('country_code')})"
                )
                print(f"Coordinates: {location.get('coordinates')}")
                print(f"\nFull Address: {location.get('full_address')}")
            else:
                print("\n[!] GPS coordinates found but location resolution failed")
                print(
                    "    (This may happen if coordinates are invalid or "
                    "geocoding service is unavailable)"
                )
        else:
            print("No GPS data found in this image")
            print("\nNote: The test image (china.jpg) may not have GPS coordinates.")
            print("To test GPS resolution, use an image with embedded GPS data")
            print("(typically photos taken with smartphones or GPS-enabled cameras)")
    except Exception as exc:
        print(f"\n[X] Test failed: {exc}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    test_gps_resolution()
