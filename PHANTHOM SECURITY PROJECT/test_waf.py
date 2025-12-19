"""
Quick Test Script for Phantom WAF
Tests core functionality without running full server
"""
import sys
import yaml

# Test imports
print("Testing imports...")
try:
    from phantom_waf import PhantomWAF, WAFAction
    print("✅ Main WAF engine imported successfully")
except Exception as e:
    print(f"❌ Failed to import WAF: {e}")
    sys.exit(1)

# Test configuration loading
print("\nTesting configuration...")
try:
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    print("✅ Configuration loaded successfully")
except Exception as e:
    print(f"❌ Failed to load config: {e}")
    sys.exit(1)

# Initialize WAF
print("\nInitializing WAF...")
try:
    waf = PhantomWAF('config.yaml')
    print("✅ WAF initialized successfully")
    print(f"   Loaded {len(waf.modules)} modules")
except Exception as e:
    print(f"❌ Failed to initialize WAF: {e}")
    sys.exit(1)

# Test normal request
print("\n" + "="*80)
print("TEST 1: Normal Request (should be ALLOWED)")
print("="*80)
normal_request = {
    'method': 'GET',
    'path': '/api/user',
    'headers': {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Host': 'example.com',
        'Accept': 'text/html,application/json',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9'
    },
    'params': {'id': '123'},
    'body': {},
    'ip': '192.168.1.100'
}

result = waf.analyze_request(normal_request)
print(f"Action: {result.action.value}")
print(f"Threat Score: {result.threat_score}")
print(f"Execution Time: {result.execution_time*1000:.2f}ms")
if result.action == WAFAction.ALLOW:
    print("✅ PASS: Normal request was allowed")
else:
    print("⚠️  WARNING: Normal request was blocked!")

# Test SQL Injection
print("\n" + "="*80)
print("TEST 2: SQL Injection Attack (should be BLOCKED)")
print("="*80)
sqli_request = {
    'method': 'GET',
    'path': '/api/user',
    'headers': {
        'User-Agent': 'Mozilla/5.0',
        'Host': 'example.com'
    },
    'params': {'id': "1' OR '1'='1"},
    'body': {},
    'ip': '192.168.1.101'
}

result = waf.analyze_request(sqli_request)
print(f"Action: {result.action.value}")
print(f"Threat Score: {result.threat_score}")
print(f"Blocked By: {result.blocked_by}")
print(f"Threats: {result.threats_detected[:3]}")
if result.action == WAFAction.BLOCK:
    print("✅ PASS: SQL injection was blocked")
else:
    print("❌ FAIL: SQL injection was NOT blocked!")

# Test XSS
print("\n" + "="*80)
print("TEST 3: XSS Attack (should be BLOCKED)")
print("="*80)
xss_request = {
    'method': 'POST',
    'path': '/api/comment',
    'headers': {
        'User-Agent': 'Mozilla/5.0',
        'Host': 'example.com',
        'Content-Type': 'application/json'
    },
    'params': {},
    'body': {'comment': "<script>alert('XSS')</script>"},
    'ip': '192.168.1.102'
}

result = waf.analyze_request(xss_request)
print(f"Action: {result.action.value}")
print(f"Threat Score: {result.threat_score}")
print(f"Blocked By: {result.blocked_by}")
if result.action == WAFAction.BLOCK:
    print("✅ PASS: XSS attack was blocked")
else:
    print("❌ FAIL: XSS attack was NOT blocked!")

# Test Command Injection
print("\n" + "="*80)
print("TEST 4: Command Injection Attack (should be BLOCKED)")
print("="*80)
cmd_request = {
    'method': 'GET',
    'path': '/api/file',
    'headers': {
        'User-Agent': 'Mozilla/5.0',
        'Host': 'example.com'
    },
    'params': {'filename': 'test.txt; cat /etc/passwd'},
    'body': {},
    'ip': '192.168.1.103'
}

result = waf.analyze_request(cmd_request)
print(f"Action: {result.action.value}")
print(f"Threat Score: {result.threat_score}")
print(f"Blocked By: {result.blocked_by}")
if result.action == WAFAction.BLOCK:
    print("✅ PASS: Command injection was blocked")
else:
    print("❌ FAIL: Command injection was NOT blocked!")

# Test Path Traversal
print("\n" + "="*80)
print("TEST 5: Path Traversal Attack (should be BLOCKED)")
print("="*80)
path_request = {
    'method': 'GET',
    'path': '/api/file',
    'headers': {
        'User-Agent': 'Mozilla/5.0',
        'Host': 'example.com'
    },
    'params': {'path': '../../../etc/passwd'},
    'body': {},
    'ip': '192.168.1.104'
}

result = waf.analyze_request(path_request)
print(f"Action: {result.action.value}")
print(f"Threat Score: {result.threat_score}")
print(f"Blocked By: {result.blocked_by}")
if result.action == WAFAction.BLOCK:
    print("✅ PASS: Path traversal was blocked")
else:
    print("❌ FAIL: Path traversal was NOT blocked!")

# Test Rate Limiting
print("\n" + "="*80)
print("TEST 6: Rate Limiting (should trigger after threshold)")
print("="*80)
rate_limit_ip = '192.168.1.200'
blocked_count = 0

for i in range(120):  # Exceed per-IP limit of 100/60s
    test_request = {
        'method': 'GET',
        'path': '/api/test',
        'headers': {'User-Agent': 'Mozilla/5.0', 'Host': 'example.com'},
        'params': {},
        'body': {},
        'ip': rate_limit_ip
    }
    result = waf.analyze_request(test_request)
    if result.action == WAFAction.BLOCK or result.action == WAFAction.CHALLENGE:
        blocked_count += 1

print(f"Sent 120 requests, {blocked_count} were rate-limited")
if blocked_count > 15:
    print("✅ PASS: Rate limiting is working")
else:
    print("⚠️  WARNING: Rate limiting may not be working as expected")

# Get WAF Statistics
print("\n" + "="*80)
print("WAF STATISTICS")
print("="*80)
stats = waf.get_stats()
print(f"Total Requests Analyzed: {stats['requests_analyzed']}")
print(f"Requests Blocked: {stats['requests_blocked']}")
print(f"Threats Detected: {stats['threats_detected']}")
print(f"Block Rate: {stats['block_rate']:.1f}%")
print(f"Requests/Second: {stats['requests_per_second']:.2f}")

# Get Module Info
print("\n" + "="*80)
print("LOADED MODULES")
print("="*80)
modules = waf.get_module_info()
for name, info in modules.items():
    status = "✅" if info.get('enabled', True) else "❌"
    print(f"{status} {info.get('name', name)} v{info.get('version', '1.0.0')}")

print("\n" + "="*80)
print("✅ ALL TESTS COMPLETED!")
print("="*80)
print("\nPhantom WAF is ready to protect your applications!")
print("Run 'python demo/protected_app.py' to see the interactive demo.")
