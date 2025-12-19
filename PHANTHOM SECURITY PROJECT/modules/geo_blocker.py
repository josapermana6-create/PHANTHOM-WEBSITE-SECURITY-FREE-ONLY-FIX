"""
GeoIP Blocking Module
Geographic-based access control using MaxMind GeoLite2 database
"""
import os
from typing import Dict, List, Tuple, Optional
from utils.helpers import is_valid_ip

# Try to import geoip2, fall back gracefully
try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


class GeoBlocker:
    """Geographic IP blocking and filtering"""
    
    def __init__(self, config: Dict):
        self.config = config.get('geo_blocking', {})
        self.enabled = self.config.get('enabled', False) and GEOIP_AVAILABLE
        
        if not GEOIP_AVAILABLE and self.enabled:
            print("Warning: geoip2 not installed. GeoIP blocking disabled.")
            print("Install with: pip install geoip2")
            self.enabled = False
        
        if not self.enabled:
            self.reader = None
            return
        
        self.mode = self.config.get('mode', 'blacklist')  # whitelist or blacklist
        self.blacklist_countries = set(self.config.get('blacklist_countries', []))
        self. whitelist_countries = set(self.config.get('whitelist_countries', []))
        self.block_vpn = self.config.get('block_vpn', True)
        self.block_tor = self.config.get('block_tor', True)
        
        # MaxMind database path
        self.db_path = self.config.get('maxmind_db_path', 'data/GeoLite2-Country.mmdb')
        
        # Initialize database reader
        self._init_database()
    
    def _init_database(self):
        """Initialize GeoIP database"""
        if not os.path.exists(self.db_path):
            print(f"Warning: GeoIP database not found at {self.db_path}")
            print("Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
            self.enabled = False
            self.reader = None
            return
        
        try:
            self.reader = geoip2.database.Reader(self.db_path)
        except Exception as e:
            print(f"Error loading GeoIP database: {e}")
            self.enabled = False
            self.reader = None
    
    def detect(self, request_data: Dict) -> Tuple[bool, int, List[str]]:
        """
        Check if request should be blocked based on geography
        
        Args:
            request_data: Dictionary containing request data
        
        Returns:
            Tuple of (is_blocked, threat_score, matched_patterns)
        """
        if not self.enabled or not self.reader:
            return False, 0, []
        
        ip_address = request_data.get('ip', '')
        
        if not ip_address or not is_valid_ip(ip_address):
            return False, 0, []
        
        # Skip private/internal IPs
        if self._is_private_ip(ip_address):
            return False, 0, []
        
        try:
            response = self.reader.country(ip_address)
            country_code = response.country.iso_code
            country_name = response.country.name
            
            matched_patterns = []
            score = 0
            is_blocked = False
            
            # Check mode
            if self.mode == 'whitelist':
                # Whitelist mode: block if NOT in whitelist
                if country_code not in self.whitelist_countries:
                    is_blocked = True
                    score = 10
                    matched_patterns.append(f"Country not in whitelist: {country_name} ({country_code})")
            
            else:  # blacklist mode
                # Blacklist mode: block if IN blacklist
                if country_code in self.blacklist_countries:
                    is_blocked = True
                    score = 10
                    matched_patterns.append(f"Country blacklisted: {country_name} ({country_code})")
            
            # Check for VPN/Proxy (if database supports it)
            if self.block_vpn and hasattr(response, 'traits'):
                if response.traits.is_anonymous_proxy:
                    is_blocked = True
                    score = 9
                    matched_patterns.append("Anonymous proxy/VPN detected")
            
            # Check for Tor
            if self.block_tor and hasattr(response, 'traits'):
                if response.traits.is_tor_exit_node:
                    is_blocked = True
                    score = 10
                    matched_patterns.append("Tor exit node detected")
            
            return is_blocked, score, matched_patterns
        
        except geoip2.errors.AddressNotFoundError:
            # IP not in database
            return False, 0, []
        except Exception as e:
            # Other errors
            return False, 0, []
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback
        except:
            return False
    
    def get_country(self, ip: str) -> Optional[str]:
        """Get country name for an IP"""
        if not self.enabled or not self.reader:
            return None
        
        try:
            response = self.reader.country(ip)
            return response.country.name
        except:
            return None
    
    def add_to_blacklist(self, country_code: str):
        """Add country to blacklist"""
        country_code = country_code.upper()
        if len(country_code) == 2:
            self.blacklist_countries.add(country_code)
    
    def remove_from_blacklist(self, country_code: str):
        """Remove country from blacklist"""
        country_code = country_code.upper()
        self.blacklist_countries.discard(country_code)
    
    def add_to_whitelist(self, country_code: str):
        """Add country to whitelist"""
        country_code = country_code.upper()
        if len(country_code) == 2:
            self.whitelist_countries.add(country_code)
    
    def remove_from_whitelist(self, country_code: str):
        """Remove country from whitelist"""
        country_code = country_code.upper()
        self.whitelist_countries.discard(country_code)
    
    def get_stats(self) -> Dict:
        """Get GeoIP blocking statistics"""
        return {
            'enabled': self.enabled,
            'mode': self.mode,
            'blacklisted_countries': len(self.blacklist_countries),
            'whitelisted_countries': len(self.whitelist_countries),
            'block_vpn': self.block_vpn,
            'block_tor': self.block_tor,
            'database_loaded': self.reader is not None
        }
    
    def get_module_info(self) -> Dict:
        """Get module information"""
        return {
            'name': 'GeoIP Blocker',
            'version': '1.0.0',
            'enabled': self.enabled,
            'mode': self.mode,
            'blacklist_count': len(self.blacklist_countries),
            'whitelist_count': len(self.whitelist_countries),
            'database_available': GEOIP_AVAILABLE
        }
    
    def __del__(self):
        """Cleanup database connection"""
        if self.reader:
            try:
                self.reader.close()
            except:
                pass


# Example usage
if __name__ == '__main__':
    config = {
        'geo_blocking': {
            'enabled': True,
            'mode': 'blacklist',
            'blacklist_countries': ['CN', 'RU', 'KP'],
            'block_vpn': True,
            'block_tor': True,
            'maxmind_db_path': 'data/GeoLite2-Country.mmdb'
        }
    }
    
    blocker = GeoBlocker(config)
    
    # Test
    request = {
        'ip': '8.8.8.8',
        'method': 'GET',
        'path': '/'
    }
    
    is_blocked, score, patterns = blocker.detect(request)
    print(f"Blocked: {is_blocked}, Score: {score}, Patterns: {patterns}")
    
    # Get country
    country = blocker.get_country('8.8.8.8')
    print(f"Country: {country}")
