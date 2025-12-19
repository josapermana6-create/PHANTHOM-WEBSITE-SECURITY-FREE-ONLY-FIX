"""
Advanced Logging Module for Phantom WAF
Structured logging with JSON format, ELK compatibility, and audit trails
"""
import json
import logging
import os
from datetime import datetime
from typing import Dict, Any, Optional
from logging.handlers import RotatingFileHandler
import threading


class WAFLogger:
    """Advanced structured logger for WAF events"""
    
    def __init__(self, config: Dict):
        self.config = config.get('logging', {})
        self.enabled = self.config.get('enabled', True)
        self.format_type = self.config.get('format', 'json')
        self.destination = self.config.get('destination', 'file')
        self.file_path = self.config.get('file_path', 'logs/phantom_waf.log')
        self.max_size = self.config.get('max_size', 104857600)  # 100MB
        self.backup_count = self.config.get('backup_count', 5)
        
        # Logging preferences
        self.log_attacks = self.config.get('log_attacks', True)
        self.log_blocked = self.config.get('log_blocked', True)
        self.log_allowed = self.config.get('log_allowed', False)
        
        # Thread-safe
        self.lock = threading.Lock()
        
        # Setup logger
        self._setup_logger()
    
    def _setup_logger(self):
        """Setup logging configuration"""
        # Create logs directory if not exists
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
        
        # Create logger
        self.logger = logging.getLogger('PhantomWAF')
        self.logger.setLevel(logging.INFO)
        
        # Remove existing handlers
        self.logger.handlers = []
        
        # File handler with rotation
        if self.destination in ['file', 'both']:
            file_handler = RotatingFileHandler(
                self.file_path,
                maxBytes=self.max_size,
                backupCount=self.backup_count
            )
            file_handler.setLevel(logging.INFO)
            
            if self.format_type == 'json':
                file_handler.setFormatter(JSONFormatter())
            else:
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                file_handler.setFormatter(formatter)
            
            self.logger.addHandler(file_handler)
        
        # Console handler
        if self.destination in ['console', 'both']:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(formatter)
            
            self.logger.addHandler(console_handler)
    
    def log_request(self, request_data: Dict, result: Any, execution_time: float):
        """Log request analysis result"""
        if not self.enabled:
            return
        
        # Determine if should log
        if result.action.value == 'block' and not self.log_blocked:
            return
        if result.action.value == 'allow' and not self.log_allowed:
            return
        if result.threat_score > 0 and not self.log_attacks:
            return
        
        with self.lock:
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': 'request_analysis',
                'action': result.action.value,
                'threat_score': result.threat_score,
                'blocked_by': result.blocked_by,
                'execution_time_ms': round(execution_time * 1000, 2),
                'request': {
                    'method': request_data.get('method'),
                    'path': request_data.get('path'),
                    'ip': request_data.get('ip'),
                    'user_agent': request_data.get('headers', {}).get('User-Agent', '')[:100]
                },
                'threats': result.threats_detected[:5],  # Limit to 5
                'modules_triggered': [
                    name for name, res in result.module_results.items()
                    if res.get('is_threat', False)
                ]
            }
            
            if result.action.value == 'block':
                self.logger.warning(json.dumps(log_entry))
            elif result.threat_score > 0:
                self.logger.info(json.dumps(log_entry))
            else:
                self.logger.debug(json.dumps(log_entry))
    
    def log_attack(self, attack_type: str, details: Dict,  severity: str = 'high'):
        """Log security attack"""
        if not self.enabled or not self.log_attacks:
            return
        
        with self.lock:
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': 'security_attack',
                'attack_type': attack_type,
                'severity': severity,
                'details': details
            }
            
            if severity == 'critical':
                self.logger.critical(json.dumps(log_entry))
            elif severity == 'high':
                self.logger.error(json.dumps(log_entry))
            else:
                self.logger.warning(json.dumps(log_entry))
    
    def log_event(self, event_type: str, message: str, data: Optional[Dict] = None):
        """Log general WAF event"""
        if not self.enabled:
            return
        
        with self.lock:
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': event_type,
                'message': message,
                'data': data or {}
            }
            
            self.logger.info(json.dumps(log_entry))
    
    def log_ip_event(self, ip: str, action: str, reason: str):
        """Log IP whitelist/blacklist events"""
        if not self.enabled:
            return
        
        with self.lock:
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': 'ip_management',
                'ip': ip,
                'action': action,
                'reason': reason
            }
            
            self.logger.info(json.dumps(log_entry))
    
    def log_config_change(self, config_type: str, old_value: Any, new_value: Any, changed_by: str = 'system'):
        """Log configuration changes"""
        if not self.enabled:
            return
        
        with self.lock:
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': 'config_change',
                'config_type': config_type,
                'old_value': str(old_value),
                'new_value': str(new_value),
                'changed_by': changed_by
            }
            
            self.logger.warning(json.dumps(log_entry))
    
    def get_module_info(self) -> Dict:
        """Get module information"""
        return {
            'name': 'Advanced Logger',
            'version': '1.0.0',
            'enabled': self.enabled,
            'format': self.format_type,
            'destination': self.destination,
            'file_path': self.file_path
        }


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record):
        # If message is already JSON, return as is
        try:
            json.loads(record.getMessage())
            return record.getMessage()
        except (json.JSONDecodeError, ValueError):
            # Otherwise, format as JSON
            log_record = {
                'timestamp': datetime.utcnow().isoformat(),
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'module': record.module,
                'function': record.funcName,
                'line': record.lineno
            }
            
            if record.exc_info:
                log_record['exception'] = self.formatException(record.exc_info)
            
            return json.dumps(log_record)


# Audit trail helper
class AuditTrail:
    """Audit trail for compliance and security reviews"""
    
    def __init__(self, logger: WAFLogger):
        self.logger = logger
    
    def log_admin_action(self, admin_user: str, action: str, target: str, details: Dict):
        """Log administrative actions for audit"""
        self.logger.log_event(
            'admin_action',
            f"{admin_user} performed {action} on {target}",
            {
                'admin_user': admin_user,
                'action': action,
                'target': target,
                'details': details
            }
        )
    
    def log_policy_change(self, policy_name: str, changed_by: str, changes: Dict):
        """Log security policy changes"""
        self.logger.log_config_change(
            f'policy_{policy_name}',
            changes.get('old'),
            changes.get('new'),
            changed_by
        )
    
    def log_access_attempt(self, user: str, resource: str, result: str, ip: str):
        """Log access attempts for audit"""
        self.logger.log_event(
            'access_attempt',
            f"{user} attempted to access {resource}: {result}",
            {
                'user': user,
                'resource': resource,
                'result': result,
                'ip': ip
            }
        )
