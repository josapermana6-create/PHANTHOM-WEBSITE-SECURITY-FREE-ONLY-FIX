# Phantom WAF - Setup Instructions

## Prerequisites

- **Go 1.21+** (Required)
- **Redis** (Optional, recommended for performance)
- **SQLite** (Auto-included) or PostgreSQL

## Installation Steps

### 1. Install Go

#### Windows
1. Download installer: https://go.dev/dl/
2. Run installer (default: `C:\Go`)
3. Open new Command Prompt
4. Verify: `go version`

#### Linux (Ubuntu/Debian)
```bash
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version
```

### 2. Install Redis (Optional)

#### Windows
Download from: https://github.com/microsoftarchive/redis/releases

Or use Docker:
```bash
docker run -d -p 6379:6379 redis
```

#### Linux
```bash
sudo apt update
sudo apt install redis-server
sudo systemctl start redis-server
redis-cli ping  # Should return PONG
```

**Or skip Redis:**
```yaml
# config/config.yaml
redis:
  enabled: false
```

### 3. Build Phantom WAF

```bash
cd "d:\PHANTHOM SECURITY PROJECT\ips-service"

# Download dependencies
go mod download

# Build service
go build -o phantom-waf.exe cmd/phantom-waf/main.go
```

**For Linux:**
```bash
go build -o phantom-waf cmd/phantom-waf/main.go
```

### 4. Configure

Edit `config/config.yaml`:

```yaml
# Choose your deployment mode
deployment:
  mode: "full"  # full, waf-only, ips-only

# Database (SQLite default, no setup needed!)
database:
  type: "sqlite"
  sqlite_path: "data/phantom_waf.db"

# Modules (enable/disable as needed)
waf_modules:
  sql_injection:
    enabled: true
  xss_protection:
    enabled: true
  port_filter:
    enabled: true
```

### 5. Run Service

```bash
# Windows
.\phantom-waf.exe

# Linux
./phantom-waf
```

You should see:
```
INFO Starting Phantom WAF Service (IPS + WAF)...
INFO Configuration loaded successfully
INFO Database initialized
INFO WAF analyzer initialized with all detection modules
INFO REST API server started on port 8080
INFO Phantom WAF Service is running
```

### 6. Verify Installation

**Test health endpoint:**
```bash
curl http://localhost:8080/health
```

Expected response:
```json
{"status":"healthy","time":1234567890}
```

**Test full analysis:**
```bash
curl -X POST http://localhost:8080/api/v1/analyze/full \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "path": "/api/test",
    "headers": {"User-Agent": "Mozilla/5.0"},
    "params": {},
    "body": "",
    "ip": "192.168.1.100"
  }'
```

## Configuration Details

### Deployment Modes

#### Full Mode (Default)
```yaml
deployment:
  mode: "full"
```
- All 9 WAF modules
- IP reputation & threat intel
- Complete protection

#### WAF-Only Mode
```yaml
deployment:
  mode: "waf-only"
```
- Application-layer protection only
- No IP-based checking
- Faster for trusted networks

#### IPS-Only Mode
```yaml
deployment:
  mode: "ips-only"
```
- IP reputation only
- Threat intelligence
- Lightweight protection

### Module Configuration

Each module can be enabled/disabled:

```yaml
waf_modules:
  sql_injection:
    enabled: true
    sensitivity: "high"  # low, medium, high
    threshold: 7
    
  xss_protection:
    enabled: true
    sensitivity: "medium"
    
  command_injection:
    enabled: true
    
  path_traversal:
    enabled: true
    
  csrf_protection:
    enabled: true       # Disable for APIs
    
  rate_limiting:
    enabled: true
    per_ip_limit: 100
    
  bot_detection:
    enabled: true
    
  port_filter:          # NEW!
    enabled: true
    allowed_ports: [80, 443, 8080]
    blocked_ports: [23, 445, 3389]
    
  # IP reputation (from IPS)
  ip_detection:
    enabled: true
```

### Port Filter Setup

```yaml
waf_modules:
  port_filter:
    enabled: true
    
    # Whitelist (empty = allow all)
    allowed_ports:
      - 80    # HTTP
      - 443   # HTTPS
      - 8080  # Alt HTTP
      - 8443  # Alt HTTPS
    
    # Blacklist (always block)
    blocked_ports:
      - 23    # Telnet
      - 445   # SMB
      - 3389  # RDP
    
    # Suspicious (flag but allow)
    suspicious_ports:
      - 22    # SSH
      - 3306  # MySQL
      - 5432  # PostgreSQL
      - 6379  # Redis
      - 27017 # MongoDB
    
    # Scan detection
    scan_detection:
      enabled: true
      threshold: 10  # unique ports
      window: 60     # seconds
```

### Database Options

#### SQLite (Default - No Setup)
```yaml
database:
  type: "sqlite"
  sqlite_path: "data/phantom_waf.db"
```

#### PostgreSQL (Advanced)
```bash
# 1. Install PostgreSQL
# 2. Create database
createdb phantom_waf

# 3. Configure
```

```yaml
database:
  type: "postgres"
  host: "localhost"
  port: 5432
  name: "phantom_waf"
  user: "waf_user"
  password: "secure_password"
```

### Redis Configuration

```yaml
redis:
  enabled: true
  host: "localhost:6379"
  password: ""  # If password-protected
  db: 0
```

## Python Integration

### Install Client

The client is already included at `integrations/waf_client.py`

### Flask Example

```python
from flask import Flask
from integrations.waf_client import PhantomWAFMiddleware

app = Flask(__name__)

# Auto-protect all routes
PhantomWAFMiddleware(app, waf_url='http://localhost:8080')

@app.route('/')
def index():
    return "Protected by Phantom WAF!"

if __name__ == '__main__':
    app.run()
```

### Django Example

```python
# settings.py
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'integrations.waf_middleware.PhantomWAFMiddleware',  # Add this
    # ... other middleware
]

PHANTOM_WAF_URL = 'http://localhost:8080'
```

## Testing

### Run Demos

```bash
# Basic IPS test
python demo_ips_integration.py

# Port filter test
python demo_port_filter.py

# Attack simulation
python attack_simulator.py
```

### Manual Testing

**SQL Injection:**
```bash
curl -X POST http://localhost:8080/api/v1/analyze/full \
  -H "Content-Type: application/json" \
  -d '{
    "method": "POST",
    "path": "/login",
    "params": {"user": "admin'\'' OR 1=1--"},
    "ip": "192.168.1.100"
  }'
```

**Port Scan:**
```bash
# Multiple requests to different ports rapidly
for port in 22 23 80 443 3306 3389 8080; do
  curl -X POST http://localhost:8080/api/v1/analyze/full \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-Port: $port" \
    -d '{"method":"GET","path":"/","ip":"192.0.2.1"}' &
done
```

## Production Deployment

### Systemd (Linux)

```bash
sudo cp phantom-waf /opt/phantom-waf/
sudo cp config/config.yaml /opt/phantom-waf/

# Create service file
sudo nano /etc/systemd/system/phantom-waf.service
```

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
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable phantom-waf
sudo systemctl start phantom-waf
sudo systemctl status phantom-waf
```

### Windows Service (NSSM)

```bash
# Download NSSM: https://nssm.cc/download
nssm install PhantomWAF "C:\phantom-waf\phantom-waf.exe"
nssm set PhantomWAF AppDirectory "C:\phantom-waf"
nssm start PhantomWAF
```

## Troubleshooting

### Port Already in Use

```yaml
server:
  rest_port: 8081  # Change port
```

### Go Not Found

Add Go to PATH:
```bash
# Windows
setx PATH "%PATH%;C:\Go\bin"

# Linux
export PATH=$PATH:/usr/local/go/bin
```

### Redis Connection Failed

```yaml
redis:
  enabled: false  # Disable Redis
```

Or start Redis:
```bash
# Windows
redis-server

# Linux
sudo systemctl start redis-server
```

### Database Locked (SQLite)

Increase timeout:
```yaml
database:
  type: "sqlite"
  sqlite_path: "data/phantom_waf.db"
  # SQLite auto-handles this
```

## Next Steps

1. ✅ Verify service is running
2. ✅ Run test demos
3. ✅ Integrate with your app
4. ✅ Configure modules for your needs
5. ✅ Set up monitoring
6. ✅ Deploy to production

---

**Setup Complete! 🎉**
