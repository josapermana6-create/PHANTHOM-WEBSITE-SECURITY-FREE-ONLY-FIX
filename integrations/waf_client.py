"""
WAF Client for Python Integration
High-Performance Go WAF + IPS Client
"""
import requests
import time
from typing import Dict, List, Optional
from dataclasses import dataclass
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class WAFResult:
    """Result from WAF analysis"""
    action: str         # allow, block, challenge
    threat_score: int   # 0-100
    is_suspicious: bool
    is_blocked: bool
    threats: List[str]
    module_results: Dict
    processing_time: float
    from_cache: bool


class PhantomWAFClient:
    """
    Client for communicating with Phantom WAF Service (Go)
    Provides full WAF + IPS protection
    """
    
    def __init__(self, base_url: str = "http://localhost:8080", timeout: int = 10):
        """
        Initialize WAF client    
        
        Args:
            base_url: Base URL of the WAF service
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.enabled = self._check_service_health()
        
        if self.enabled:
            logger.info(f"Phantom WAF service connected at {base_url}")
        else:
            logger.warning(f"WAF service not available at {base_url}, running without protection")
    
    def _check_service_health(self) -> bool:
        """Check if WAF service is healthy"""
        try:
            resp = requests.get(f"{self.base_url}/health", timeout=2)
            return resp.status_code == 200
        except Exception as e:
            logger.debug(f"Health check failed: {e}")
            return False
    
    def analyze_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        params: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        ip: Optional[str] = None,
        analysis_type: str = "full"  # full, waf, ips
    ) -> Optional[WAFResult]:
        """
        Analyze a complete HTTP request for threats
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            headers: Request headers dict
            params: Query parameters dict
            body: Request body string
            ip: Client IP address
            analysis_type: Type of analysis (full, waf, ips)
        
        Returns:
            WAFResult or None if service unavailable
        """
        if not self.enabled:
            return None
        
        if params is None:
            params = {}
        if body is None:
            body = ""
        if ip is None:
            ip = "127.0.0.1"
        
        payload = {
            'method': method,
            'path': path,
            'headers': headers,
            'params': params,
            'body': body,
            'ip': ip
        }
        
        # Choose endpoint based on analysis type
        endpoint_map = {
            'full': '/api/v1/analyze/full',
            'waf': '/api/v1/analyze/waf',
            'ips': '/api/v1/analyze/ips'
        }
        
        endpoint = endpoint_map.get(analysis_type, '/api/v1/analyze/full')
        
        try:
            resp = requests.post(
                f"{self.base_url}{endpoint}",
                json=payload,
                timeout=self.timeout
            )
            
            if resp.status_code == 200:
                data = resp.json()
                
                return WAFResult(
                    action=data.get('action', 'allow'),
                    threat_score=data.get('threat_score', 0),
                    is_suspicious=data.get('is_suspicious', False),
                    is_blocked=data.get('is_blocked', False),
                    threats=data.get('threats', []),
                    module_results=data.get('module_results', {}),
                    processing_time=data.get('processing_time_ms', 0),
                    from_cache=data.get('from_cache', False)
                )
            else:
                logger.warning(f"WAF analysis failed: HTTP {resp.status_code}")
                return None
                
        except requests.Timeout:
            logger.warning(f"WAF analysis timeout for {ip}")
            return None
        except Exception as e:
            logger.error(f"WAF analysis error: {e}")
            return None
    
    def generate_csrf_token(self, session_id: str) -> Optional[str]:
        """
        Generate CSRF token for a session
        
        Args:
            session_id: Session identifier
        
        Returns:
            CSRF token string or None
        """
        if not self.enabled:
            return None
        
        try:
            resp = requests.post(
                f"{self.base_url}/api/v1/csrf/token",
                json={'session_id': session_id},
                timeout=self.timeout
            )
            
            if resp.status_code == 200:
                data = resp.json()
                return data.get('token')
            return None
            
        except Exception as e:
            logger.error(f"CSRF token generation error: {e}")
            return None
    
    def verify_csrf_token(self, token: str, session_id: str) -> bool:
        """
        Verify CSRF token
        
        Args:
            token: CSRF token to verify
            session_id: Session identifier
        
        Returns:
            True if valid, False otherwise
        """
        if not self.enabled:
            return False
        
        try:
            resp = requests.post(
                f"{self.base_url}/api/v1/csrf/verify",
                json={'token': token, 'session_id': session_id},
                timeout=self.timeout
            )
            
            if resp.status_code == 200:
                data = resp.json()
                return data.get('valid', False)
            return False
            
        except Exception as e:
            logger.error(f"CSRF verification error: {e}")
            return False
    
    def block_ip(self, ip: str) -> bool:
        """Block an IP address (IPS function)"""
        if not self.enabled:
            return False
        
        try:
            resp = requests.post(
                f"{self.base_url}/api/v1/block/{ip}",
                timeout=self.timeout
            )
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"IP blocking error: {e}")
            return False
    
    def get_stats(self) -> Optional[Dict]:
        """Get WAF service statistics"""
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


# Flask Middleware
class PhantomWAFMiddleware:
    """Flask middleware for Phantom WAF"""
    
    def __init__(self, app, waf_url='http://localhost:8080'):
        self.app = app
        self.waf = PhantomWAFClient(waf_url)
        app.before_request(self.check_request)
    
    def check_request(self):
        from flask import request, abort
        
        if not self.waf.enabled:
            return None  # Continue without WAF if unavailable
        
        # Analyze request
        result = self.waf.analyze_request(
            method=request.method,
            path=request.path,
            headers=dict(request.headers),
            params=dict(request.args),
            body=request.get_data(as_text=True),
            ip=request.remote_addr
        )
        
        if result and result.is_blocked:
            logger.warning(f"Blocked request from {request.remote_addr}: {result.threats}")
            abort(403, description="Request blocked by WAF")
        
        return None  # Continue processing


# Example usage
if __name__ == '__main__':
    # Initialize client
    waf = PhantomWAFClient()
    
    print("=== Phantom WAF Client Demo ===\n")
    
    # Test 1: Normal request
    print("1. Normal Request:")
    result = waf.analyze_request(
        method='GET',
        path='/api/users',
        headers={'User-Agent': 'Mozilla/5.0'},
        params={},
        ip='192.168.1.100'
    )
    
    if result:
        print(f"   Action: {result.action}")
        print(f"   Threat Score: {result.threat_score}")
        print(f"   Processing: {result.processing_time:.2f}ms\n")
    
    # Test 2: SQL Injection attempt
    print("2. SQL Injection Attempt:")
    result = waf.analyze_request(
        method='POST',
        path='/api/login',
        headers={'User-Agent': 'sqlmap/1.0'},
        params={'user': "admin' OR '1'='1", 'pass': '123'},
        ip='203.0.113.45'
    )
    
    if result:
        print(f"   Action: {result.action}")
        print(f"   Blocked: {result.is_blocked}")
        print(f"   Threats: {result.threats}\n")
    
    # Test 3: CSRF token
    print("3. CSRF Token Generation:")
    token = waf.generate_csrf_token('session_123')
    if token:
        print(f"   Token: {token[:32]}...")
        valid = waf.verify_csrf_token(token, 'session_123')
        print(f"   Valid: {valid}\n")
    
    # Test 4: Statistics
    print("4. WAF Statistics:")
    stats = waf.get_stats()
    if stats:
        for key, value in stats.items():
            print(f"   {key}: {value}")
