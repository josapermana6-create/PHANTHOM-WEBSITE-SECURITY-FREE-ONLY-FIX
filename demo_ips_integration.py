"""
Demo: Integrating Phantom IPS with Phantom WAF
Shows how the Go IPS service enhances the Python WAF
"""
import time
from integrations.ips_client import IPSClient

print("=" * 60)
print("     PHANTOM IPS + WAF INTEGRATION DEMO")
print("=" * 60)
print()

# Initialize IPS client
print("🔌 Connecting to IPS service...")
ips = IPSClient('http://localhost:8081')

if not ips.enabled:
    print("❌ IPS service not available!")
    print("   Start the IPS service first:")
    print("   cd ips-service && go run cmd/ips-server/main.go")
    exit(1)

print("✅ IPS service connected!\n")

# Test 1: Normal IP
print("-" * 60)
print("TEST 1: Analyzing Normal IP")
print("-" * 60)

normal_ip = "192.168.1.100"
print(f"📊 Analyzing IP: {normal_ip}")

result = ips.analyze_ip(normal_ip, metadata={
    'method': 'GET',
    'path': '/api/data',
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
})

if result:
    print(f"   Threat Score: {result.threat_score}/100")
    print(f"   Action: {result.action.upper()}")
    print(f"   Threat Level: {result.threat_level}")
    print(f"   Reasons: {', '.join(result.reasons) if result.reasons else 'None'}")
    print(f"   Processing Time: {result.processing_time:.2f}ms")
    
    if result.is_blocked:
        print("   ❌ Request would be BLOCKED")
    elif result.is_suspicious:
        print("   ⚠️  Request is SUSPICIOUS")
    else:
        print("   ✅ Request is ALLOWED")
else:
    print("   ⚠️  Analysis failed")

print()
time.sleep(1)

# Test 2: Suspicious User Agent (Scanner)
print("-" * 60)
print("TEST 2: Suspicious Scanner User Agent")
print("-" * 60)

scanner_ip = "203.0.113.45"
print(f"📊 Analyzing IP: {scanner_ip}")

result = ips.analyze_ip(scanner_ip, metadata={
    'method': 'GET',
    'path': '/.env',  # Suspicious path
    'user_agent': 'sqlmap/1.0',  # Known attack tool
})

if result:
    print(f"   Threat Score: {result.threat_score}/100")
    print(f"   Action: {result.action.upper()}")
    print(f"   Threat Level: {result.threat_level}")
    print(f"   Reasons: {', '.join(result.reasons) if result.reasons else 'None'}")
    
    if result.is_blocked:
        print("   ❌ Request would be BLOCKED")
    elif result.is_suspicious:
        print("   ⚠️  Request is SUSPICIOUS, recording violation...")
        # Record the violation
        if ips.record_violation(scanner_ip, 'scanning_attempt', severity=8):
            print("   ✅ Violation recorded")
    else:
        print("   ✅ Request is ALLOWED")

print()
time.sleep(1)

# Test 3: Rate Limiting
print("-" * 60)
print("TEST 3: Rate Limiting Test")
print("-" * 60)

rapid_ip = "198.51.100.77"
print(f"📊 Simulating rapid requests from IP: {rapid_ip}")

for i in range(15):
    result = ips.analyze_ip(rapid_ip, metadata={
        'method': 'POST',
        'path': '/api/login',
        'user_agent': 'curl/7.68.0',
    })
    print(f"   Request {i+1:2d}: Score={result.threat_score:3d}, Action={result.action}")
    time.sleep(0.1)

print()

# Test 4: Manual Blocking
print("-" * 60)
print("TEST 4: Manual IP Blocking")
print("-" * 60)

malicious_ip = "192.0.2.123"
print(f"🚫 Manually blocking IP: {malicious_ip}")

if ips.block_ip(malicious_ip):
    print("   ✅ IP blocked successfully")
    
    # Verify it's blocked
    result = ips.analyze_ip(malicious_ip, metadata={})
    if result and result.is_blocked:
        print(f"   ✅ Confirmed: IP is now blocked (Score: {result.threat_score})")
        print(f"   Reasons: {', '.join(result.reasons)}")
    
    # Unblock it
    print(f"\n🔓 Unblocking IP: {malicious_ip}")
    if ips.unblock_ip(malicious_ip):
        print("   ✅ IP unblocked successfully")
else:
    print("   ❌ Failed to block IP")

print()
time.sleep(1)

# Test 5: Whitelist
print("-" * 60)
print("TEST 5: IP Whitelisting")
print("-" * 60)

trusted_ip = "10.0.0.50"
print(f"✅ Adding IP to whitelist: {trusted_ip}")

if ips.whitelist_ip(trusted_ip):
    print("   ✅ IP whitelisted successfully")
    
    # Verify it's whitelisted
    result = ips.analyze_ip(trusted_ip, metadata={
        'method': 'GET',
        'path': '/.env',  # Even with suspicious path
        'user_agent': 'sqlmap/1.0',  # Even with attack tool
    })
    
    if result:
        print(f"   Score: {result.threat_score}")
        print(f"   Action: {result.action}")
        print(f"   Reasons: {', '.join(result.reasons)}")
        print("   ✅ Even suspicious activity is allowed (whitelisted)")

print()
time.sleep(1)

# Test 6: Get Statistics
print("-" * 60)
print("TEST 6: IPS Statistics")
print("-" * 60)

stats = ips.get_stats()
if stats:
    print(f"📊 IPS Service Statistics:")
    print(f"   Total IPs tracked: {stats.get('total_ips', 0)}")
    print(f"   Blacklisted IPs: {stats.get('blacklisted_ips', 0)}")
    print(f"   Total violations: {stats.get('total_violations', 0)}")
    print(f"   Threat intel entries: {stats.get('threat_intel_count', 0)}")

print()
time.sleep(1)

# Test 7: Top Threats
print("-" * 60)
print("TEST 7: Top Threat IPs")
print("-" * 60)

threats = ips.get_top_threats()
if threats and len(threats) > 0:
    print(f"🔥 Top {len(threats)} Threatening IPs:")
    for idx, threat in enumerate(threats[:5], 1):
        print(f"   {idx}. {threat.get('ip_address', 'N/A')}")
        print(f"      Score: {threat.get('reputation_score', 0)}")
        print(f"      Level: {threat.get('threat_level', 'unknown')}")
        print(f"      Violations: {threat.get('violation_count', 0)}")
else:
    print("   No significant threats detected yet")

print()
print("=" * 60)
print("     DEMO COMPLETE")
print("=" * 60)
print()
print("💡 Next Steps:")
print("   1. Integrate IPS client into Phantom WAF")
print("   2. Configure thresholds in config/config.yaml")
print("   3. Monitor threats via /api/v1/stats endpoint")
print("   4. Review and tune detection rules")
print()
print("📚 Full documentation: ips-service/README.md")
