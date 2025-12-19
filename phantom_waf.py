"""
Phantom WAF - Enterprise-Grade Web Application Firewall
Main WAF engine that orchestrates all security modules
"""
import yaml
import time
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

# Import all security modules
from modules.sql_injection_detector import SQLInjectionDetector
from modules.xss_detector import XSSDetector
from modules.command_injection_detector import CommandInjectionDetector
from modules.path_traversal_detector import PathTraversalDetector
from modules.csrf_detector import CSRFDetector
from modules.xxe_detector import XXEDetector
from modules.ssrf_detector import SSRFDetector
from modules.rate_limiter import RateLimiter
from modules.bot_detector import BotDetector
from modules.ml_anomaly_detector import MLAnomalyDetector
from modules.ip_reputation import IPReputationManager


class WAFAction(Enum):
    """Actions the WAF can take"""
    ALLOW = "allow"
    BLOCK = "block"
    CHALLENGE = "challenge"
    MONITOR = "monitor"


@dataclass
class WAFResult:
    """Result of WAF analysis"""
    action: WAFAction
    threat_score: int
    threats_detected: List[str]
    module_results: Dict[str, Dict]
    execution_time: float
    blocked_by: Optional[str] = None


class PhantomWAF:
    """
    Enterprise-Grade Web Application Firewall
    
    Features:
    - Multi-layer attack detection (SQLi, XSS, Command Injection, etc.)
    - Machine Learning anomaly detection
    - Intelligent rate limiting
    - Bot detection and mitigation
    - IP reputation management
    - Real-time threat scoring
    """
    
    def __init__(self, config_path: str = 'config.yaml'):
        """Initialize Phantom WAF with configuration"""
        
        # Load configuration
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Global settings
        global_config = self.config.get('global', {})
        self.enabled = global_config.get('enabled', True)
        self.mode = global_config.get('mode', 'block')  # monitor, block, challenge
        self.log_level = global_config.get('log_level', 'INFO')
        
        # Module configuration
        modules_config = self.config.get('modules', {})
        
        # Initialize detection modules
        self.modules = {}
        
        if modules_config.get('sql_injection', True):
            self.modules['sql_injection'] = SQLInjectionDetector(self.config)
        
        if modules_config.get('xss_protection', True):
            self.modules['xss'] = XSSDetector(self.config)
        
        if modules_config.get('command_injection', True):
            self.modules['command_injection'] = CommandInjectionDetector(self.config)
        
        if modules_config.get('path_traversal', True):
            self.modules['path_traversal'] = PathTraversalDetector(self.config)
        
        if modules_config.get('csrf_protection', True):
            self.modules['csrf'] = CSRFDetector(self.config)
        
        if modules_config.get('xxe_protection', True):
            self.modules['xxe'] = XXEDetector(self.config)
        
        if modules_config.get('ssrf_protection', True):
            self.modules['ssrf'] = SSRFDetector(self.config)
        
        if modules_config.get('rate_limiting', True):
            self.modules['rate_limiter'] = RateLimiter(self.config)
        
        if modules_config.get('bot_detection', True):
            self.modules['bot_detector'] = BotDetector(self.config)
        
        if modules_config.get('ml_anomaly', True):
            self.modules['ml_anomaly'] = MLAnomalyDetector(self.config)
        
        if modules_config.get('ip_reputation', True):
            self.modules['ip_reputation'] = IPReputationManager(self.config)
        
        # Statistics
        self.stats = {
            'requests_analyzed': 0,
            'requests_blocked': 0,
            'requests_challenged': 0,
            'threats_detected': 0,
            'start_time': time.time()
        }
    
    def analyze_request(self, request_data: Dict) -> WAFResult:
        """
        Analyze an incoming request for security threats
        
        Args:
            request_data: Dictionary containing:
                - method: HTTP method (GET, POST, etc.)
                - path: Request path
                - headers: Dictionary of headers
                - params: Query parameters
                - body: Request body
                - ip: Client IP address
        
        Returns:
            WAFResult object with analysis results
        """
        start_time = time.time()
        
        if not self.enabled:
            return WAFResult(
                action=WAFAction.ALLOW,
                threat_score=0,
                threats_detected=[],
                module_results={},
                execution_time=0.0
            )
        
        self.stats['requests_analyzed'] += 1
        
        total_threat_score = 0
        all_threats = []
        module_results = {}
        blocked_by = None
        
        # Run all detection modules
        for module_name, module in self.modules.items():
            try:
                is_threat, score, threats = module.detect(request_data)
                
                module_results[module_name] = {
                    'is_threat': is_threat,
                    'score': score,
                    'threats': threats
                }
                
                if is_threat:
                    total_threat_score += score
                    all_threats.extend(threats)
                    self.stats['threats_detected'] += 1
                    
                    # Record violation for IP reputation
                    if module_name == 'ip_reputation':
                        continue  # Already handled
                    elif hasattr(self.modules.get('ip_reputation'), 'record_violation'):
                        ip_address = request_data.get('ip', '')
                        self.modules['ip_reputation'].record_violation(
                            ip_address, 
                            violation_type=module_name
                        )
                    
                    # Set blocked_by if not already set
                    if not blocked_by:
                        blocked_by = module_name
                
            except Exception as e:
                # Log error but continue analysis
                module_results[module_name] = {
                    'error': str(e)
                }
        
        # Determine action based on threat score and mode
        action = self._determine_action(total_threat_score, module_results)
        
        # Update statistics
        if action == WAFAction.BLOCK:
            self.stats['requests_blocked'] += 1
        elif action == WAFAction.CHALLENGE:
            self.stats['requests_challenged'] += 1
        
        execution_time = time.time() - start_time
        
        return WAFResult(
            action=action,
            threat_score=total_threat_score,
            threats_detected=all_threats,
            module_results=module_results,
            execution_time=execution_time,
            blocked_by=blocked_by
        )
    
    def _determine_action(self, threat_score: int, module_results: Dict) -> WAFAction:
        """Determine what action to take based on threat score"""
        
        # Check if any critical module detected a threat
        critical_modules = ['sql_injection', 'command_injection', 'ip_reputation']
        for module in critical_modules:
            if module in module_results and module_results[module].get('is_threat'):
                if self.mode == 'block':
                    return WAFAction.BLOCK
                elif self.mode == 'challenge':
                    return WAFAction.CHALLENGE
        
        # Check threat score thresholds
        if threat_score >= 10:
            if self.mode == 'block':
                return WAFAction.BLOCK
            elif self.mode == 'challenge':
                return WAFAction.CHALLENGE
            else:  # monitor mode
                return WAFAction.MONITOR
        
        elif threat_score >= 7:
            if self.mode == 'block':
                return WAFAction.CHALLENGE
            else:
                return WAFAction.MONITOR
        
        return WAFAction.ALLOW
    
    def get_stats(self) -> Dict:
        """Get WAF statistics"""
        uptime = time.time() - self.stats['start_time']
        
        return {
            **self.stats,
            'uptime': uptime,
            'requests_per_second': self.stats['requests_analyzed'] / max(uptime, 1),
            'block_rate': (self.stats['requests_blocked'] / max(self.stats['requests_analyzed'], 1)) * 100
        }
    
    def get_module_info(self) -> Dict:
        """Get information about all loaded modules"""
        module_info = {}
        
        for module_name, module in self.modules.items():
            if hasattr(module, 'get_module_info'):
                module_info[module_name] = module.get_module_info()
        
        return module_info
    
    def cleanup(self):
        """Cleanup resources and expired data"""
        # Cleanup rate limiter
        if 'rate_limiter' in self.modules:
            self.modules['rate_limiter'].cleanup()
        
        # Cleanup IP reputation
        if 'ip_reputation' in self.modules:
            self.modules['ip_reputation'].cleanup()
        
        # Cleanup CSRF tokens
        if 'csrf' in self.modules:
            self.modules['csrf'].cleanup_expired_tokens()
    
    def whitelist_ip(self, ip_address: str):
        """Add IP to whitelist"""
        if 'ip_reputation' in self.modules:
            self.modules['ip_reputation'].whitelist_ip(ip_address)
    
    def blacklist_ip(self, ip_address: str):
        """Add IP to blacklist"""
        if 'ip_reputation' in self.modules:
            self.modules['ip_reputation'].blacklist_ip(ip_address)
    
    def get_ip_status(self, ip_address: str) -> Dict:
        """Get status of specific IP"""
        if 'ip_reputation' in self.modules:
            return self.modules['ip_reputation'].get_ip_status(ip_address)
        return {}
    
    def generate_csrf_token(self, session_id: str) -> str:
        """Generate CSRF token for a session"""
        if 'csrf' in self.modules:
            return self.modules['csrf'].generate_csrf_token(session_id)
        return ''


# Example usage
if __name__ == '__main__':
    # Initialize WAF
    waf = PhantomWAF('config.yaml')
    
    # Example request
    sample_request = {
        'method': 'POST',
        'path': '/api/login',
        'headers': {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Content-Type': 'application/json',
            'Host': 'example.com'
        },
        'params': {},
        'body': {
            'username': 'admin',
            'password': 'password123'
        },
        'ip': '192.168.1.100'
    }
    
    # Analyze request
    result = waf.analyze_request(sample_request)
    
    print(f"Action: {result.action.value}")
    print(f"Threat Score: {result.threat_score}")
    print(f"Threats: {result.threats_detected}")
    print(f"Execution Time: {result.execution_time:.4f}s")
    
    # Get stats
    stats = waf.get_stats()
    print(f"\nWAF Statistics: {stats}")
    
    # Get module info
    module_info = waf.get_module_info()
    for name, info in module_info.items():
        print(f"\n{name}: {info}")
