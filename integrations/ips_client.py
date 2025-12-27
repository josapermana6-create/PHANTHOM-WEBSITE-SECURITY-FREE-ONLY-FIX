"""
IPS Client for Python WAF Integration
Provides interface to communicate with the Go IPS service
"""
import requests
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class IPSResult:
    """Result from IPS analysis"""
    is_blocked: bool
    is_suspicious: bool
    threat_score: int
    reputation_score: int
    reasons: List[str]
    action: str
    threat_level: str
    processing_time: float


class IPSClient:
    """
    Client for communicating with Go IPS service
    """
    
    def __init__(self, base_url: str = "http://localhost:8081", timeout: int = 5):
        """
        Initialize IPS client
        
        Args:
            base_url: Base URL of the IPS service
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.enabled = self._check_service_health()
        
        if self.enabled:
            logger.info(f"IPS service connected at {base_url}")
        else:
            logger.warning(f"IPS service not available at {base_url}, running without IPS")
    
    def _check_service_health(self) -> bool:
        """Check if IPS service is healthy"""
        try:
            resp = requests.get(
                f"{self.base_url}/health",
                timeout=2
            )
            return resp.status_code == 200
        except Exception as e:
            logger.debug(f"Health check failed: {e}")
            return False
    
    def analyze_ip(self, ip_address: str, metadata: Optional[Dict] = None) -> Optional[IPSResult]:
        """
        Analyze an IP address for threats
        
        Args:
            ip_address: IP address to analyze
            metadata: Optional request metadata
                - method: HTTP method
                - path: Request path
                - user_agent: User agent string
                - headers: Request headers dict
                - timestamp: Request timestamp
                - request_size: Size of request in bytes
        
        Returns:
            IPSResult or None if service unavailable
        """
        if not self.enabled:
            return None
        
        if metadata is None:
            metadata = {}
        
        # Set timestamp if not provided
        if 'timestamp' not in metadata:
            metadata['timestamp'] = time.time()
        
        payload = {
            'ip_address': ip_address,
            'metadata': metadata
        }
        
        try:
            resp = requests.post(
                f"{self.base_url}/api/v1/analyze",
                json=payload,
                timeout=self.timeout
            )
            
            if resp.status_code == 200:
                data = resp.json()
                result = data.get('result', {})
                
                return IPSResult(
                    is_blocked=result.get('is_blocked', False),
                    is_suspicious=result.get('is_suspicious', False),
                    threat_score=result.get('threat_score', 0),
                    reputation_score=result.get('reputation_score', 0),
                    reasons=result.get('reasons', []),
                    action=result.get('action', 'allow'),
                    threat_level=result.get('threat_level', 'low'),
                    processing_time=result.get('processing_time_ms', 0)
                )
            else:
                logger.warning(f"IPS analysis failed: HTTP {resp.status_code}")
                return None
                
        except requests.Timeout:
            logger.warning(f"IPS analysis timeout for {ip_address}")
            return None
        except Exception as e:
            logger.error(f"IPS analysis error: {e}")
            return None
    
    def get_reputation(self, ip_address: str) -> Optional[Dict]:
        """
        Get IP reputation details
        
        Args:
            ip_address: IP address to lookup
        
        Returns:
            Reputation data dict or None
        """
        if not self.enabled:
            return None
        
        try:
            resp = requests.get(
                f"{self.base_url}/api/v1/reputation/{ip_address}",
                timeout=self.timeout
            )
            
            if resp.status_code == 200:
                return resp.json()
            return None
            
        except Exception as e:
            logger.error(f"Reputation lookup error: {e}")
            return None
    
    def record_violation(self, ip_address: str, violation_type: str, severity: int = 5) -> bool:
        """
        Record a security violation for an IP
        
        Args:
            ip_address: IP address that violated
            violation_type: Type of violation (e.g., 'sql_injection', 'xss')
            severity: Severity level 1-10
        
        Returns:
            True if recorded successfully
        """
        if not self.enabled:
            return False
        
        payload = {
            'ip_address': ip_address,
            'violation_type': violation_type,
            'severity': min(10, max(1, severity))
        }
        
        try:
            resp = requests.post(
                f"{self.base_url}/api/v1/violation",
                json=payload,
                timeout=self.timeout
            )
            return resp.status_code == 200
            
        except Exception as e:
            logger.error(f"Violation recording error: {e}")
            return False
    
    def block_ip(self, ip_address: str) -> bool:
        """
        Block an IP address
        
        Args:
            ip_address: IP to block
        
        Returns:
            True if blocked successfully
        """
        if not self.enabled:
            return False
        
        try:
            resp = requests.post(
                f"{self.base_url}/api/v1/block/{ip_address}",
                timeout=self.timeout
            )
            return resp.status_code == 200
            
        except Exception as e:
            logger.error(f"IP blocking error: {e}")
            return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock an IP address
        
        Args:
            ip_address: IP to unblock
        
        Returns:
            True if unblocked successfully
        """
        if not self.enabled:
            return False
        
        try:
            resp = requests.delete(
                f"{self.base_url}/api/v1/block/{ip_address}",
                timeout=self.timeout
            )
            return resp.status_code == 200
            
        except Exception as e:
            logger.error(f"IP unblocking error: {e}")
            return False
    
    def whitelist_ip(self, ip_address: str) -> bool:
        """
        Add IP to whitelist
        
        Args:
            ip_address: IP to whitelist
        
        Returns:
            True if whitelisted successfully
        """
        if not self.enabled:
            return False
        
        try:
            resp = requests.post(
                f"{self.base_url}/api/v1/whitelist/{ip_address}",
                timeout=self.timeout
            )
            return resp.status_code == 200
            
        except Exception as e:
            logger.error(f"IP whitelisting error: {e}")
            return False
    
    def get_stats(self) -> Optional[Dict]:
        """
        Get IPS service statistics
        
        Returns:
            Statistics dict or None
        """
        if not self.enabled:
            return None
        
        try:
            resp = requests.get(
                f"{self.base_url}/api/v1/stats",
                timeout=self.timeout
            )
            
            if resp.status_code == 200:
                return resp.json()
            return None
            
        except Exception as e:
            logger.error(f"Stats retrieval error: {e}")
            return None
    
    def get_top_threats(self) -> Optional[List[Dict]]:
        """
        Get top threatening IPs
        
        Returns:
            List of threat dicts or None
        """
        if not self.enabled:
            return None
        
        try:
            resp = requests.get(
                f"{self.base_url}/api/v1/threats/top",
                timeout=self.timeout
            )
            
            if resp.status_code == 200:
                data = resp.json()
                return data.get('threats', [])
            return None
            
        except Exception as e:
            logger.error(f"Top threats retrieval error: {e}")
            return None


# Example usage
if __name__ == '__main__':
    # Initialize client
    client = IPSClient()
    
    # Analyze an IP
    print("Analyzing IP address...")
    result = client.analyze_ip(
        '1.2.3.4',
        metadata={
            'method': 'GET',
            'path': '/api/login',
            'user_agent': 'Mozilla/5.0'
        }
    )
    
    if result:
        print(f"Threat Score: {result.threat_score}")
        print(f"Action: {result.action}")
        print(f"Reasons: {result.reasons}")
        print(f"Is Blocked: {result.is_blocked}")
    else:
        print("Analysis failed or service unavailable")
    
    # Get reputation
    print("\nGetting IP reputation...")
    rep = client.get_reputation('1.2.3.4')
    if rep:
        print(f"Reputation: {rep}")
    
    # Get statistics
    print("\nGetting IPS statistics...")
    stats = client.get_stats()
    if stats:
        print(f"Stats: {stats}")
