# Phantom IPS - Quick Start

## 🎯 Apa yang Baru?

**Phantom WAF sekarang powered by Golang!**

- 🚀 **>10,000 req/s** (20x lebih cepat)
- ⚡ **<2ms latency** (10x lebih rendah)
- 🛡️ **9 Detection Modules** (termasuk Port Filter)
- 🎯 **3 Deployment Modes** (Full/WAF/IPS)

## 🚀 Quick Start (5 Menit)

### 1. Install Go (jika belum ada)

**Windows:**
Download dari https://go.dev/dl/

**Linux:**
```bash
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

Verifikasi:
```bash
go version
```

### 2. Build WAF Service

```bash
cd "d:\PHANTHOM SECURITY PROJECT\ips-service"
go mod download
go build -o phantom-waf.exe cmd/phantom-waf/main.go
```

### 3. Konfigurasi (Optional)

Edit `config/config.yaml`:

```yaml
# Mode deployment
deployment:
  mode: "full"  # full, waf-only, ips-only

# Enable/disable modules
waf_modules:
  sql_injection:
    enabled: true
  port_filter:
    enabled: true
    allowed_ports: [80, 443, 8080]
```

### 4. Jalankan Service

```bash
./phantom-waf.exe
```

Service akan running di `http://localhost:8080`

### 5. Test!

**Test dengan Python:**
```bash
cd ..
python demo_port_filter.py
```

**Test dengan curl:**
```bash
curl http://localhost:8080/health
```

## 🎯 Modules yang Tersedia (9 Total)

1. ✅ **SQL Injection** - 40+ patterns
2. ✅ **XSS Protection** - 35+ patterns
3. ✅ **Command Injection** - Shell detection
4. ✅ **Path Traversal** - File protection
5. ✅ **CSRF Protection** - Token-based
6. ✅ **Rate Limiting** - Token bucket
7. ✅ **Bot Detection** - Good/bad bots
8. ✅ **Port Filter** - Scan detection ← NEW!
9. ✅ **IP Reputation** - Threat intel

## 🔧 Konfigurasi Cepat

### Mode WAF-Only (Tanpa IPS)
```yaml
deployment:
  mode: "waf-only"
```

### Mode IPS-Only (Tanpa WAF)
```yaml
deployment:
  mode: "ips-only"
```

### Disable Module Tertentu
```yaml
waf_modules:
  csrf_protection:
    enabled: false  # Untuk API
  port_filter:
    enabled: false
```

### Custom Rate Limits
```yaml
waf_modules:
  rate_limiting:
    per_route:
      "/api/login":
        requests: 5
        window: 300
```

### Port Filter Setup
```yaml
waf_modules:
  port_filter:
    allowed_ports: [80, 443]      # Only these
    blocked_ports: [23, 3389]     # Always block
    suspicious_ports: [22, 3306]  # Flag as suspicious
    scan_detection:
      threshold: 10               # 10 ports = scan
      window: 60                  # in 60 seconds
```

## 🔌 Integrasi dengan Python

### Flask
```python
from integrations.waf_client import PhantomWAFMiddleware

app = Flask(__name__)
PhantomWAFMiddleware(app, waf_url='http://localhost:8080')
```

### Django
```python
# settings.py
MIDDLEWARE = [
    'integrations.waf_middleware.PhantomWAFMiddleware',
]
PHANTOM_WAF_URL = 'http://localhost:8080'
```

### Manual
```python
from integrations.waf_client import PhantomWAFClient

waf = PhantomWAFClient()
result = waf.analyze_request(
    method='POST',
    path='/api/login',
    headers={'User-Agent': '...'},
    ip='192.168.1.100'
)

if result.is_blocked:
    return "Blocked", 403
```

## 📊 Monitor & Stats

```bash
# Get statistics
curl http://localhost:8080/api/v1/stats

# Check IP reputation
curl http://localhost:8080/api/v1/reputation/1.2.3.4

# Top threats
curl http://localhost:8080/api/v1/threats/top
```

## 🐛 Troubleshooting

### Service tidak start

**Error: "go: command not found"**
- Install Go dari https://go.dev/dl/

**Error: "port 8080 already in use"**
```yaml
server:
  rest_port: 8081  # Ganti port
```

### False Positives

**Terlalu banyak request diblokir:**
```yaml
waf_modules:
  sql_injection:
    sensitivity: "low"
    threshold: 9
```

### Redis Error

**"Failed to connect to Redis"**
```yaml
redis:
  enabled: false  # Disable Redis
```

## 🚀 Production Deployment

### Systemd Service (Linux)

Create `/etc/systemd/system/phantom-waf.service`:
```ini
[Unit]
Description=Phantom WAF Service
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/phantom-waf
ExecStart=/opt/phantom-waf/phantom-waf
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable:
```bash
sudo systemctl enable phantom-waf
sudo systemctl start phantom-waf
```

### Windows Service

Use NSSM (Non-Sucking Service Manager):
```bash
nssm install PhantomWAF "C:\path\to\phantom-waf.exe"
nssm start PhantomWAF
```

## 💡 Tips

1. **Performance**: Enable `concurrent_modules: true`
2. **Security**: Set `sensitivity: "high"` for critical apps
3. **API Apps**: Disable `csrf_protection`
4. **High Traffic**: Increase `worker_pool_size`
5. **Port Security**: Enable `port_filter` scan detection

## 📚 Dokumentasi Lengkap

- [README.md](README.md) - Full documentation
- [config/config.yaml](config/config.yaml) - All config options
- [../demo_port_filter.py](../demo_port_filter.py) - Port filter demo

## 🆘 Need Help?

1. Check logs untuk error messages
2. Test dengan demo scripts
3. Review config syntax (YAML sensitive!)
4. Verify Go installation: `go version`

---

**Ready in 5 minutes! 🚀**
