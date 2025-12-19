# ⚙️ Panduan Konfigurasi Phantom WAF ke Website

Langkah demi langkah mengintegrasikan dan mengkonfigurasi Phantom WAF ke website Anda.

---

## 📋 Langkah 1: Persiapan File

### Copy File WAF ke Project Anda

```bash
# Struktur folder yang diperlukan:
your-website/
├── app.py                    # File utama aplikasi Anda
├── phantom_waf.py            # Copy dari Phantom WAF
├── config.yaml               # Copy dari Phantom WAF
├── modules/                  # Copy seluruh folder
│   ├── __init__.py
│   ├── sql_injection_detector.py
│   ├── xss_detector.py
│   ├── command_injection_detector.py
│   ├── path_traversal_detector.py
│   ├── csrf_detector.py
│   ├── xxe_detector.py
│   ├── ssrf_detector.py
│   ├── rate_limiter.py
│   ├── bot_detector.py
│   ├── ml_anomaly_detector.py
│   └── ip_reputation.py
├── utils/                    # Copy seluruh folder
│   ├── __init__.py
│   └── helpers.py
└── integrations/            # Copy seluruh folder
    ├── __init__.py
    └── flask_middleware.py
```

**Cara Copy:**
```bash
# Windows (dari project Phantom WAF)
xcopy /E /I "d:\PHANTHOM SECURITY PROJECT\modules" "path\to\your-website\modules"
xcopy /E /I "d:\PHANTHOM SECURITY PROJECT\utils" "path\to\your-website\utils"
xcopy /E /I "d:\PHANTHOM SECURITY PROJECT\integrations" "path\to\your-website\integrations"
copy "d:\PHANTHOM SECURITY PROJECT\phantom_waf.py" "path\to\your-website\"
copy "d:\PHANTHOM SECURITY PROJECT\config.yaml" "path\to\your-website\"
```

---

## 📋 Langkah 2: Install Dependencies

```bash
pip install flask pyyaml scikit-learn numpy
```

Atau buat `requirements.txt`:
```txt
Flask>=2.3.0
pyyaml>=6.0
scikit-learn>=1.3.0
numpy>=1.24.0
```

Install:
```bash
pip install -r requirements.txt
```

---

## 📋 Langkah 3: Integrasi ke Aplikasi Flask

### A. Aplikasi Baru (Paling Mudah)

Buat file `app.py`:

```python
from flask import Flask, request, jsonify
from integrations.flask_middleware import FlaskWAFMiddleware

# 1. Create Flask app
app = Flask(__name__)

# 2. AKTIFKAN WAF - HANYA 1 BARIS INI!
waf = FlaskWAFMiddleware(app, config_path='config.yaml')

# 3. Buat routes seperti biasa
@app.route('/')
def home():
    return 'Website dilindungi WAF!'

@app.route('/api/data')
def get_data():
    # Route ini otomatis dilindungi
    return jsonify({'data': 'sensitive info'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

**Selesai!** Jalankan:
```bash
python app.py
```

### B. Aplikasi Existing (Tambah 2 Baris)

Jika sudah ada aplikasi Flask:

```python
from flask import Flask
from integrations.flask_middleware import FlaskWAFMiddleware  # TAMBAH BARIS 1

app = Flask(__name__)

# ... konfigurasi existing Anda ...

# TAMBAH BARIS 2 - sebelum route definitions
waf = FlaskWAFMiddleware(app, config_path='config.yaml')

# Routes existing Anda tidak perlu diubah
@app.route('/existing-route')
def existing():
    return 'Now protected!'
```

---

## 📋 Langkah 4: Konfigurasi `config.yaml`

### A. Konfigurasi Basic (Development)

Untuk testing dan development:

```yaml
# Mode operasi
global:
  enabled: true
  mode: "monitor"      # Monitor dulu, tidak block (untuk testing)
  log_level: "INFO"

# Aktifkan module yang diperlukan
modules:
  sql_injection: true
  xss_protection: true
  command_injection: true
  path_traversal: true
  csrf_protection: false    # Disable jika bentrok dengan AJAX
  rate_limiting: true
  bot_detection: true
  ml_anomaly: false         # Disable untuk development

# Rate limiting - longgar untuk development
rate_limiting:
  per_ip:
    requests: 1000     # 1000 request
    window: 60         # per menit
```

### B. Konfigurasi Standard (Production)

Untuk website production standard:

```yaml
global:
  enabled: true
  mode: "block"        # Block serangan
  log_level: "WARNING"

modules:
  sql_injection: true
  xss_protection: true
  command_injection: true
  path_traversal: true
  csrf_protection: true
  xxe_protection: true
  ssrf_protection: true
  rate_limiting: true
  bot_detection: true
  ml_anomaly: true
  ip_reputation: true

# SQL Injection Protection
sql_injection:
  sensitivity: "medium"
  block_score_threshold: 7

# XSS Protection
xss_protection:
  sensitivity: "medium"
  block_score_threshold: 7

# Rate Limiting - Standard website
rate_limiting:
  enabled: true
  per_ip:
    requests: 100      # 100 request
    window: 60         # per menit
  per_route:
    "/api/login":
      requests: 5      # Max 5 login attempts
      window: 300      # per 5 menit
```

### C. Konfigurasi High Security (E-commerce/Banking)

Untuk website dengan keamanan tinggi:

```yaml
global:
  enabled: true
  mode: "block"
  log_level: "INFO"

modules:
  sql_injection: true
  xss_protection: true
  command_injection: true
  path_traversal: true
  csrf_protection: true
  xxe_protection: true
  ssrf_protection: true
  rate_limiting: true
  bot_detection: true
  ml_anomaly: true
  ip_reputation: true
  virtual_patching: true

# High sensitivity untuk semua
sql_injection:
  sensitivity: "high"       # Deteksi maksimal
  block_score_threshold: 5  # Threshold lebih rendah = lebih strict

xss_protection:
  sensitivity: "high"
  block_score_threshold: 5

command_injection:
  sensitivity: "high"
  block_score_threshold: 6

# Rate limiting ketat
rate_limiting:
  per_ip:
    requests: 50       # Hanya 50 request
    window: 60         # per menit
  per_route:
    "/checkout":
      requests: 5
      window: 300
    "/api/payment":
      requests: 3
      window: 600      # 10 menit
    "/api/login":
      requests: 3
      window: 600

# IP Reputation - Auto blacklist
ip_reputation:
  enabled: true
  auto_blacklist:
    enabled: true
    threshold: 5       # 5 violations = auto block
    duration: 7200     # Block selama 2 jam
```

---

## 📋 Langkah 5: Konfigurasi Route-Specific

### Whitelist Route Tertentu

Jika ada route yang tidak perlu proteksi ketat:

```python
from flask import Flask
from integrations.flask_middleware import FlaskWAFMiddleware

app = Flask(__name__)
waf = FlaskWAFMiddleware(app)

# Route yang tidak perlu WAF check
@app.route('/public/css/<path:filename>')
def static_css(filename):
    # Static files - tidak perlu check ketat
    return send_from_directory('public/css', filename)

# Whitelist IP untuk testing
@app.before_first_request
def setup_whitelist():
    # Whitelist IP development
    waf.waf.whitelist_ip('127.0.0.1')
    waf.waf.whitelist_ip('192.168.1.100')  # IP developer
```

### Custom Rate Limiting per Route

Edit `config.yaml`:

```yaml
rate_limiting:
  per_route:
    # Login page - ketat
    "/login":
      requests: 5
      window: 300
    
    # Search - moderate
    "/search":
      requests: 30
      window: 60
    
    # API endpoints
    "/api/products":
      requests: 100
      window: 60
    
    # Payment - sangat ketat
    "/api/checkout":
      requests: 3
      window: 300
```

---

## 📋 Langkah 6: Testing Konfigurasi

### Test 1: Verifikasi WAF Aktif

```bash
# Jalankan aplikasi
python app.py

# Di terminal lain, test dengan curl
curl http://localhost:5000/
```

Harusnya jalan normal.

### Test 2: Test Attack Protection

```bash
# Test SQL Injection
curl "http://localhost:5000/api/user?id=1' OR '1'='1"
```

Harusnya return **403 Forbidden** dengan response:
```json
{
  "error": "Request blocked by WAF",
  "threat_score": 17,
  "blocked_by": "sql_injection"
}
```

### Test 3: Test Rate Limiting

```bash
# Kirim banyak request cepat
for i in {1..150}; do curl http://localhost:5000/api/login; done
```

Setelah 100 request (atau sesuai config), harusnya diblock.

### Test 4: Check WAF Stats

```bash
curl http://localhost:5000/_waf/stats
```

Response:
```json
{
  "requests_analyzed": 150,
  "requests_blocked": 50,
  "threats_detected": 1,
  "block_rate": 33.3
}
```

---

## 📋 Langkah 7: Whitelist/Blacklist IP

### Via Code

```python
# Di app.py
@app.route('/admin/ip-management')
def manage_ips():
    # Whitelist IP
    waf.waf.whitelist_ip('203.123.45.67')
    
    # Blacklist IP
    waf.waf.blacklist_ip('123.45.67.89')
    
    return 'IP updated'
```

### Via API

```bash
# Whitelist
curl -X POST http://localhost:5000/_waf/whitelist/203.123.45.67

# Blacklist
curl -X POST http://localhost:5000/_waf/blacklist/123.45.67.89

# Check status IP
curl http://localhost:5000/_waf/ip/203.123.45.67
```

### Via Config File

Edit `config.yaml`:

```yaml
ip_reputation:
  enabled: true
  whitelist:
    - "127.0.0.1"
    - "192.168.1.0/24"     # Seluruh subnet
    - "203.123.45.67"      # IP specific
  blacklist:
    - "123.45.67.89"
    - "10.0.0.0/8"         # Block subnet
```

---

## 📋 Langkah 8: Monitoring & Logging

### Setup Logging

```python
import logging

# Di app.py
logging.basicConfig(
    filename='logs/waf.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

### View Logs

```bash
# Real-time monitoring
tail -f logs/waf.log

# Windows PowerShell
Get-Content logs/waf.log -Wait
```

### Dashboard Monitoring

Akses built-in endpoints:

```python
@app.route('/admin/dashboard')
def dashboard():
    stats = waf.waf.get_stats()
    modules = waf.waf.get_module_info()
    
    return render_template('dashboard.html', 
                          stats=stats, 
                          modules=modules)
```

---

## 📋 Langkah 9: Production Deployment

### A. Dengan Gunicorn

```bash
# Install
pip install gunicorn

# Run
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### B. Dengan Systemd (Linux)

Buat file `/etc/systemd/system/your-app.service`:

```ini
[Unit]
Description=Your Website with Phantom WAF
After=network.target

[Service]
User=www-data
WorkingDirectory=/var/www/your-website
ExecStart=/usr/bin/gunicorn -w 4 -b 0.0.0.0:5000 app:app
Restart=always
Environment="PATH=/var/www/your-website/venv/bin"

[Install]
WantedBy=multi-user.target
```

Enable dan start:
```bash
sudo systemctl enable your-app
sudo systemctl start your-app
sudo systemctl status your-app
```

### C. Dengan Nginx Reverse Proxy

File `/etc/nginx/sites-available/your-site`:

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable:
```bash
sudo ln -s /etc/nginx/sites-available/your-site /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## 🔧 Troubleshooting

### Problem 1: False Positive (Request Legitimate Diblock)

**Solusi:**
1. Turunkan sensitivity di `config.yaml`
2. Whitelist IP yang legitimate
3. Adjust threshold score

```yaml
sql_injection:
  sensitivity: "low"           # dari "medium"
  block_score_threshold: 10    # dari 7
```

### Problem 2: Terlalu Banyak Request Diblock

**Solusi:**
1. Set mode ke "monitor" untuk observe dulu
2. Adjust rate limiting

```yaml
global:
  mode: "monitor"  # Tidak block, hanya log

rate_limiting:
  per_ip:
    requests: 200    # Naikan dari 100
```

### Problem 3: Performance Lambat

**Solusi:**
1. Disable ML jika tidak perlu
2. Reduce modules yang aktif

```yaml
modules:
  ml_anomaly: false          # Disable ML
  bot_detection: false       # Disable jika tidak perlu
```

### Problem 4: Module Import Error

**Solusi:**
Pastikan struktur folder benar dan `__init__.py` ada:

```bash
# Cek struktur
ls -la modules/
ls -la utils/
ls -la integrations/

# Pastikan ada __init__.py
touch modules/__init__.py
touch utils/__init__.py
touch integrations/__init__.py
```

---

## ✅ Checklist Final

- [ ] File WAF sudah dicopy ke project
- [ ] Dependencies sudah diinstall
- [ ] `config.yaml` sudah dikonfigurasi
- [ ] Middleware sudah ditambahkan ke app
- [ ] Test attack berhasil diblock
- [ ] Rate limiting berfungsi
- [ ] Logging sudah disetup
- [ ] IP whitelist/blacklist sudah dikonfigurasi
- [ ] Production deployment sudah disetup

---

## 🎉 Selesai!

Website Anda sekarang dilindungi dengan **Enterprise-Grade WAF**!

**Next Steps:**
1. Monitor logs selama 1-2 minggu
2. Adjust konfigurasi berdasarkan traffic pattern
3. Setup alerts untuk attack (optional)
4. Regular update rules (optional)

**Documentation:**
- [README.md](file:///d:/PHANTHOM%20SECURITY%20PROJECT/README.md) - Fitur lengkap
- [QUICK_START.md](file:///d:/PHANTHOM%20SECURITY%20PROJECT/QUICK_START.md) - Quick reference
- [PERBANDINGAN_ENTERPRISE.md](file:///d:/PHANTHOM%20SECURITY%20PROJECT/PERBANDINGAN_ENTERPRISE.md) - Comparison dengan commercial WAF
