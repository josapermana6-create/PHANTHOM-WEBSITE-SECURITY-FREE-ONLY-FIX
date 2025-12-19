# 🚀 Quick Start Guide - Phantom WAF

## Instalasi Cepat (5 Menit)

### 1. Install Dependencies
```bash
pip install flask pyyaml scikit-learn numpy requests colorama
```

### 2. Uji WAF
```bash
cd "d:\PHANTHOM SECURITY PROJECT"
python test_waf.py
```

Output yang diharapkan:
```
✅ PASS: SQL injection was blocked
✅ PASS: XSS attack was blocked
✅ PASS: Command injection was blocked
✅ PASS: Path traversal was blocked
```

### 3. Jalankan Demo Aplikasi
```bash
python demo/protected_app.py
```

Buka browser: **http://localhost:5000**

### 4. Test dengan Attack Simulator
```bash
python attack_simulator.py --target http://localhost:5000
```

---

## 🎯 Cara Integrasikan ke Aplikasi Anda

### Flask Application

```python
from flask import Flask
from integrations.flask_middleware import FlaskWAFMiddleware

app = Flask(__name__)

# Aktifkan WAF Protection
waf = FlaskWAFMiddleware(app, config_path='config.yaml')

@app.route('/api/user/<id>')
def get_user(id):
    # Route ini OTOMATIS dilindungi WAF
    return {'user_id': id, 'name': 'John'}

if __name__ == '__main__':
    app.run()
```

**Selesai!** Aplikasi Anda sekarang dilindungi dari:
- ✅ SQL Injection
- ✅ XSS (Cross-Site Scripting)
- ✅ Command Injection
- ✅ Path Traversal
- ✅ CSRF
- ✅ XXE
- ✅ SSRF
- ✅ Bot Attacks
- ✅ Rate Limiting
- ✅ Anomali Mencurigakan (ML)

---

## 🔧 Konfigurasi Dasar

Edit `config.yaml` untuk mengatur:

### Mode Operasi
```yaml
global:
  enabled: true
  mode: "block"  # Options: monitor, block, challenge
```

### Sensitivity Level
```yaml
sql_injection:
  sensitivity: "medium"  # low, medium, high
  block_score_threshold: 7
```

### Rate Limiting
```yaml
rate_limiting:
  per_ip:
    requests: 100  # 100 requests
    window: 60     # per 60 detik
```

---

## 📊 Monitoring

### Check Stats
```bash
curl http://localhost:5000/_waf/stats
```

### Check Loaded Modules
```bash
curl http://localhost:5000/_waf/modules
```

### Whitelist IP
```bash
curl -X POST http://localhost:5000/_waf/whitelist/192.168.1.100
```

### Blacklist IP
```bash
curl -X POST http://localhost:5000/_waf/blacklist/192.168.1.100
```

---

## 🎓 Contoh Attack Tests

Coba di demo app (http://localhost:5000):

1. **SQL Injection**: Klik tombol "Test: OR 1=1"
   - Result: 🛡️ BLOCKED
   
2. **XSS Attack**: Klik tombol "Test: &lt;script&gt; tag"
   - Result: 🛡️ BLOCKED

3. **Command Injection**: Klik tombol "Test: ; ls -la"
   - Result: 🛡️ BLOCKED

4. **Normal Request**: Klik tombol "Test: Normal Request"
   - Result: ✅ ALLOWED

---

## 🐛 Troubleshooting

### WAF tidak memblokir serangan
1. Check mode di config.yaml (harus "block", bukan "monitor")
2. Check sensitivity level (naikan ke "high")
3. Check threshold score

### Too many false positives
1. Turunkan sensitivity ke "low"
2. Naikan block_score_threshold
3. Whitelist IP yang legitimate

### Performance issues
1. Disable ML anomaly detection jika tidak diperlukan
2. Adjust rate limiting windows
3. Enable caching di config

---

## 📚 File Penting

- `phantom_waf.py` - Engine utama
- `config.yaml` - Konfigurasi
- `demo/protected_app.py` - Demo interaktif
- `attack_simulator.py` - Testing tool
- `README.md` - Dokumentasi lengkap
- `walkthrough.md` - Penjelasan detail

---

## 🎉 Selamat!

WAF Anda sudah siap melindungi aplikasi dari serangan cyber!

**Next Steps**:
1. ✅ Test dengan attack simulator
2. ✅ Integrasikan ke aplikasi production
3. ✅ Monitor statistik secara berkala
4. ✅ Adjust configuration sesuai kebutuhan

**Support**: Baca `README.md` untuk dokumentasi lengkap
