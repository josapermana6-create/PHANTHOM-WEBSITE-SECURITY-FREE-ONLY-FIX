# Phantom Security Project

**Enterprise-Grade Web Application Firewall (WAF)** dengan **High-Performance Go Backend** dan sistem deteksi ancaman lengkap.

## 🚀 Performance (Go WAF)

| Metric | Python WAF | **Go WAF** |
|--------|-----------|-----------|
| Throughput | ~500 req/s | **>10,000 req/s** (20x) |
| Latency (p50) | ~20ms | **<2ms** (10x faster) |
| Memory | ~200MB | **~80MB** (60% less) |

## ✨ Fitur Utama

### 🛡️ 9 Detection Modules (All in Go)

1. **SQL Injection** - 40+ patterns, bypass detection
2. **XSS Protection** - 35+ patterns, HTML/URL decoding
3. **Command Injection** - Shell metacharacter detection
4. **Path Traversal** - Encoding bypass, sensitive files
5. **CSRF Protection** - Cryptographic tokens
6. **Rate Limiting** - Token bucket (global/IP/route)
7. **Bot Detection** - Good/bad/suspicious bots
8. **Port Filter** - Scan detection, port policies
9. **IP Reputation** - Threat intel + behavioral analysis

### 🎯 Flexible Architecture

- **3 Deployment Modes**: Full (WAF+IPS), WAF-only, IPS-only
- **Enable/Disable** any module individually
- **Adjustable thresholds** per module
- **Concurrent execution** with goroutines
- **Multi-framework support** (Flask, Django, FastAPI)

## 📁 Struktur Project

```
PHANTHOM SECURITY PROJECT/
├── ips-service/                 # Go WAF Service (NEW!)
│   ├── cmd/phantom-waf/        # Main service
│   ├── internal/waf/           # 9 detection modules
│   ├── internal/detector/      # IP detection
│   ├── internal/intelligence/  # Threat feeds
│   ├── config/                 # Configuration
│   └── README.md               # Full documentation
│
├── integrations/               # Python clients
│   ├── waf_client.py          # Go WAF client
│   └── django_middleware.py   # Django integration
│
├── modules/                    # Python modules (legacy)
├── demo_port_filter.py        # Port filter demo
└── README.md                   # This file
```

## 🚀 Quick Start

### Option 1: High-Performance Go WAF (Recommended)

```bash
# 1. Build Go service
cd ips-service
go build -o phantom-waf cmd/phantom-waf/main.go

# 2. Run service
./phantom-waf

# 3. Test with Python
python demo_port_filter.py
```

### Option 2: Python WAF (Legacy)

```bash
# Install dependencies
pip install -r requirements.txt

# Run WAF
python phantom_waf.py
```

## 🔌 Integration

### Flask
```python
from integrations.waf_client import PhantomWAFMiddleware

app = Flask(__name__)
PhantomWAFMiddleware(app, waf_url='http://localhost:8080')
```

### Django
```python
MIDDLEWARE = [
    'integrations.waf_middleware.PhantomWAFMiddleware',
]
```

### FastAPI
```python
from integrations.waf_client import PhantomWAFClient

waf = PhantomWAFClient()

@app.middleware("http")
async def waf_middleware(request, call_next):
    result = waf.analyze_request(...)
    if result.is_blocked:
        return Response("Blocked", 403)
    return await call_next(request)
```

## ⚙️ Konfigurasi Fleksibel

```yaml
# Pilih deployment mode
deployment:
  mode: "full"  # full, waf-only, ips-only

# Enable/disable per module
waf_modules:
  sql_injection:
    enabled: true
    sensitivity: "high"
  port_filter:
    enabled: true
    allowed_ports: [80, 443, 8080]
    blocked_ports: [23, 445, 3389]
```

## 📊 Fitur Detection

### SQL Injection
- Union-based, Boolean-based, Time-based
- Stacked queries, Comment injection
- 40+ compiled patterns

### XSS Protection
- Script tags, Event handlers
- JavaScript protocol, DOM manipulation
- HTML/URL decoding

### Command Injection
- Shell metacharacters (;, &&, ||)
- Dangerous commands (bash, eval, exec)
- Command substitution detection

### Path Traversal
- ../  detection (all encodings)
- Null byte injection
- Sensitive file protection

### CSRF Protection
- Cryptographic token generation
- Origin/Referer validation
- Session-based verification

### Rate Limiting
- Token bucket algorithm
- Global/IP/Route limits
- Configurable windows

### Bot Detection
- Good bot whitelist (Googlebot, Bingbot)
- Malicious bot detection (sqlmap, nikto)
- Behavioral analysis

### Port Filter (NEW!)
- Allowed/blocked port enforcement
- Suspicious port flagging
- Port scan detection
- Attack pattern recognition

### IP Reputation
- Threat intelligence feeds
- Behavioral anomaly detection
- Auto-blocking

## 📡 API Endpoints

```bash
# Full WAF + IPS analysis
POST /api/v1/analyze/full

# WAF-only (no IP checking)
POST /api/v1/analyze/waf

# IPS-only (IP-based only)
POST /api/v1/analyze/ips

# CSRF token management
POST /api/v1/csrf/token
POST /api/v1/csrf/verify

# Statistics
GET /api/v1/stats
```

## 🎯 Use Cases

### High-Traffic E-Commerce
```yaml
deployment:
  mode: "full"
  concurrent_modules: true
performance:
  worker_pool_size: 200
```

### API-Only Service
```yaml
deployment:
  mode: "waf-only"
waf_modules:
  csrf_protection:
    enabled: false
```

### Maximum Security
```yaml
waf_modules:
  sql_injection:
    sensitivity: "high"
  port_filter:
    scan_detection:
      threshold: 5
```

## 📚 Documentation

- **[ips-service/README.md](ips-service/README.md)** - Full Go WAF docs
- **[ips-service/QUICKSTART.md](ips-service/QUICKSTART.md)** - Quick start guide
- **[ips-service/SETUP.md](ips-service/SETUP.md)** - Setup instructions
- **[PERBANDINGAN_ENTERPRISE.md](PERBANDINGAN_ENTERPRISE.md)** - Enterprise comparison

## 🧪 Testing

```bash
# Test WAF protection
python demo_ips_integration.py

# Test port filter
python demo_port_filter.py

# Test attack simulator
python attack_simulator.py
```

## 🛠️ Development

### Build Go WAF
```bash
cd ips-service
go mod download
go build -o phantom-waf cmd/phantom-waf/main.go
```

### Run Tests
```bash
go test ./... -v
```

## 🌟 Highlights

- ✅ **20x faster** than Python WAF
- ✅ **9 detection modules** all in Go
- ✅ **Flexible configuration** (enable/disable modules)
- ✅ **3 deployment modes** (full/WAF/IPS)
- ✅ **Multi-framework** support
- ✅ **Port scanning** detection
- ✅ **Single binary** deployment
- ✅ **Enterprise-grade** protection

## 🔒 Security Features

- [x] SQL Injection Protection
- [x] XSS Protection
- [x] Command Injection Protection
- [x] Path Traversal Protection
- [x] CSRF Protection
- [x] Rate Limiting
- [x] Bot Detection
- [x] Port Filter & Scan Detection
- [x] IP Reputation & Threat Intelligence
- [x] Behavioral Anomaly Detection
- [x] GeoIP Filtering (optional)

## 📄 License

MIT License

## 🙏 Credits

**Phantom Security Project** - Enterprise-Grade WAF dengan Go Performance

---

**Made with ❤️ for Maximum Security & Performance** 🛡️🚀
