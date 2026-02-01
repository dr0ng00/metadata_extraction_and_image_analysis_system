from geopy.geocoders import Nominatim
from geopy.location import Location
from typing import Dict, Any, Optional


class LocationInference:
    """
    Resolve GPS coordinates into human-readable location
    using OpenStreetMap (Nominatim).
    """

    def __init__(self):
        # User agent is REQUIRED by Nominatim
        self.geolocator = Nominatim(user_agent="forensic-ai")

    def resolve(self, gps: Dict[str, Any]) -> Dict[str, Any]:
        if not gps:
            return {"location": "No GPS data"}

        lat = gps.get("Latitude")
        lon = gps.get("Longitude")

        if lat is None or lon is None:
            return {"location": "Incomplete GPS data"}

        try:
            # ⚠️ geopy typing bug: language expects bool in stubs
            # Runtime supports string, so we cast safely
            location: Optional[Location] = self.geolocator.reverse(
                (lat, lon),
                language="en"  # type: ignore[arg-type]
            )

        except Exception as e:
            return {
                "latitude": lat,
                "longitude": lon,
                "address": "Geolocation lookup failed",
                "error": str(e)
            }

        return {
            "latitude": lat,
            "longitude": lon,
            "address": location.address if location else "Unknown"
        }
