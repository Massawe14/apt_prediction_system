import requests
from geopy.geocoders import Nominatim

class GeoLocator:
    def __init__(self):
        self.geolocator = Nominatim(user_agent="apt_prediction_api")
        self.cache = {}  # Cache IP geolocation results

    def get_location(self, ip):
        """Get geolocation for an IP address."""
        if ip in self.cache:
            return self.cache[ip]
        
        try:
            # Use a free IP geolocation API (e.g., ip-api.com)
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = response.json()
            if data['status'] == 'success':
                location = {
                    'country': data['country'],
                    'city': data['city'],
                    'latitude': data['lat'],
                    'longitude': data['lon']
                }
                self.cache[ip] = location
                return location
        except Exception:
            pass
        return {'country': 'Unknown', 'city': 'Unknown', 'latitude': None, 'longitude': None}
    