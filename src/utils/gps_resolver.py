"""
GPS Location Resolver for MetaForensicAI

Converts GPS coordinates to human-readable location names using reverse geocoding.
Supports multiple geocoding services with fallback.
"""
import requests
from typing import Dict, Any, Optional, Tuple
from functools import lru_cache
import time


class GPSLocationResolver:
    """Resolve GPS coordinates to location names using reverse geocoding."""
    
    def __init__(self, cache_size=100):
        """
        Initialize the GPS resolver.
        
        Args:
            cache_size: Number of locations to cache (default: 100)
        """
        self.cache_size = cache_size
        self.last_request_time = 0
        self.min_request_interval = 1.0  # Rate limiting: 1 second between requests
    
    def _parse_gps_coordinates(self, gps_data: Dict[str, Any]) -> Optional[Tuple[float, float]]:
        """
        Parse GPS coordinates from metadata.
        
        Args:
            gps_data: GPS metadata dictionary
            
        Returns:
            Tuple of (latitude, longitude) or None if parsing fails
        """
        if not isinstance(gps_data, dict) or gps_data == "ABSENT":
            return None
        
        try:
            # Try to find latitude and longitude in various formats
            lat = None
            lon = None
            
            # Check for common GPS tag formats
            for lat_key in ['GPS GPSLatitude', 'GPSLatitude', 'GPS:GPSLatitude']:
                if lat_key in gps_data:
                    lat = self._convert_to_decimal(gps_data[lat_key], gps_data.get('GPS GPSLatitudeRef', 'N'))
                    break
            
            for lon_key in ['GPS GPSLongitude', 'GPSLongitude', 'GPS:GPSLongitude']:
                if lon_key in gps_data:
                    lon = self._convert_to_decimal(gps_data[lon_key], gps_data.get('GPS GPSLongitudeRef', 'E'))
                    break
            
            if lat is not None and lon is not None:
                return (lat, lon)
            
            return None
            
        except Exception:
            return None
    
    def _convert_to_decimal(self, coordinate, ref):
        """Convert GPS coordinate to decimal degrees."""
        try:
            # If already a float, return it
            if isinstance(coordinate, (int, float)):
                result = float(coordinate)
                if ref in ['S', 'W']:
                    result = -result
                return result
            
            # Parse string format from exifread: "[27, 10, 153/5]"
            coord_str = str(coordinate)
            
            # Remove brackets and split
            coord_str = coord_str.strip('[]')
            
            # Handle comma-separated format
            if ',' in coord_str:
                parts = [p.strip() for p in coord_str.split(',')]
                
                degrees = 0
                minutes = 0
                seconds = 0
                
                # Parse degrees
                if len(parts) > 0:
                    deg_str = parts[0]
                    if '/' in deg_str:
                        num, den = deg_str.split('/')
                        degrees = float(num) / float(den)
                    else:
                        degrees = float(deg_str)
                
                # Parse minutes
                if len(parts) > 1:
                    min_str = parts[1]
                    if '/' in min_str:
                        num, den = min_str.split('/')
                        minutes = float(num) / float(den)
                    else:
                        minutes = float(min_str)
                
                # Parse seconds
                if len(parts) > 2:
                    sec_str = parts[2]
                    if '/' in sec_str:
                        num, den = sec_str.split('/')
                        seconds = float(num) / float(den)
                    else:
                        seconds = float(sec_str)
                
                # Convert to decimal degrees
                decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
                
                if ref in ['S', 'W']:
                    decimal = -decimal
                
                return decimal
            
            # Try direct float conversion as fallback
            return float(coord_str)
            
        except Exception as e:
            print(f"[!] GPS coordinate conversion failed: {e}")
            return None
    
    @lru_cache(maxsize=100)
    def _reverse_geocode_nominatim(self, lat: float, lon: float) -> Optional[Dict[str, Any]]:
        """
        Reverse geocode using OpenStreetMap Nominatim (free, no API key required).
        
        Args:
            lat: Latitude
            lon: Longitude
            
        Returns:
            Dictionary with location information or None
        """
        try:
            # Rate limiting
            elapsed = time.time() - self.last_request_time
            if elapsed < self.min_request_interval:
                time.sleep(self.min_request_interval - elapsed)
            
            url = "https://nominatim.openstreetmap.org/reverse"
            params = {
                'lat': lat,
                'lon': lon,
                'format': 'json',
                'addressdetails': 1,
                'zoom': 18  # Most detailed level
            }
            headers = {
                'User-Agent': 'MetaForensicAI/1.0 (Digital Forensics Tool)'
            }
            
            response = requests.get(url, params=params, headers=headers, timeout=10)
            self.last_request_time = time.time()
            
            if response.status_code == 200:
                data = response.json()
                address = data.get('address', {})
                
                # Build location string from most specific to least specific
                location_parts = []
                
                # Add specific location (building, house number, road)
                if address.get('house_number') and address.get('road'):
                    location_parts.append(f"{address['house_number']} {address['road']}")
                elif address.get('road'):
                    location_parts.append(address['road'])
                elif address.get('suburb'):
                    location_parts.append(address['suburb'])
                
                # Add city/town
                city = address.get('city') or address.get('town') or address.get('village')
                if city:
                    location_parts.append(city)
                
                # Add state/region
                state = address.get('state') or address.get('region')
                if state:
                    location_parts.append(state)
                
                # Add country
                if address.get('country'):
                    location_parts.append(address['country'])
                
                return {
                    'location_name': ', '.join(location_parts) if location_parts else data.get('display_name', 'Unknown'),
                    'city': city,
                    'state': state,
                    'country': address.get('country'),
                    'country_code': address.get('country_code', '').upper(),
                    'full_address': data.get('display_name'),
                    'coordinates': f"{lat}, {lon}"
                }
            
            return None
            
        except Exception as e:
            print(f"[!] Geocoding failed: {e}")
            return None
    
    def resolve_location(self, gps_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Resolve GPS coordinates to location name.
        
        Args:
            gps_data: GPS metadata dictionary
            
        Returns:
            Dictionary with location information or None
        """
        coords = self._parse_gps_coordinates(gps_data)
        if not coords:
            return None
        
        lat, lon = coords
        
        # Validate coordinates
        if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
            return None
        
        # Try reverse geocoding
        location = self._reverse_geocode_nominatim(lat, lon)
        
        if location:
            location['latitude'] = lat
            location['longitude'] = lon
        
        return location


__all__ = ['GPSLocationResolver']
