# ShieldTier Deployment Guide

Deploy ShieldTier on a Linux server with HTTPS (port 443) behind Cloudflare.

## Prerequisites

- Ubuntu/Debian Linux server (20.04+ or Debian 11+)
- Domain name pointed to Cloudflare
- Root or sudo access

## Quick Install

```bash
# Download and run the install script
curl -sSL https://raw.githubusercontent.com/dillida-cmd/Threatintell/master/install.sh | sudo bash
```

Or manually follow the steps below.

---

## Step 1: System Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and essential packages
sudo apt install -y python3 python3-pip python3-venv git nginx

# Install Chromium for screenshots (optional but recommended)
sudo apt install -y chromium-browser chromium-chromedriver

# Install bubblewrap for sandbox (optional)
sudo apt install -y bubblewrap strace

# Install PDF tools
sudo apt install -y poppler-utils
```

## Step 2: Create Application User

```bash
# Create dedicated user
sudo useradd -r -s /bin/false -m -d /opt/shieldtier shieldtier

# Create directories
sudo mkdir -p /opt/shieldtier
sudo mkdir -p /var/log/shieldtier
sudo chown -R shieldtier:shieldtier /opt/shieldtier /var/log/shieldtier
```

## Step 3: Clone and Setup Application

```bash
# Clone repository
cd /opt/shieldtier
sudo -u shieldtier git clone https://github.com/dillida-cmd/Threatintell.git app

# Create Python virtual environment
cd /opt/shieldtier/app
sudo -u shieldtier python3 -m venv venv

# Install Python dependencies
sudo -u shieldtier ./venv/bin/pip install --upgrade pip
sudo -u shieldtier ./venv/bin/pip install \
    requests \
    reportlab \
    PyPDF2 \
    Pillow \
    selenium \
    pyzbar \
    python-magic \
    oletools \
    cryptography
```

## Step 4: Build Frontend

```bash
# Install Node.js (if not installed)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Build frontend
cd /opt/shieldtier/app/frontend
sudo -u shieldtier npm install
sudo -u shieldtier npm run build
```

## Step 5: Configure Environment

```bash
# Create environment file
sudo tee /opt/shieldtier/app/.env << 'EOF'
# ShieldTier Configuration
HOST=127.0.0.1
PORT=3000

# API Keys (optional - add your keys for full functionality)
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
ALIENVAULT_API_KEY=your_key_here
IPQUALITYSCORE_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here

# Storage
DATA_DIR=/opt/shieldtier/data
RETENTION_DAYS=15
EOF

sudo chown shieldtier:shieldtier /opt/shieldtier/app/.env
sudo chmod 600 /opt/shieldtier/app/.env

# Create data directory
sudo mkdir -p /opt/shieldtier/data
sudo chown shieldtier:shieldtier /opt/shieldtier/data
```

## Step 6: Create Systemd Service

```bash
sudo tee /etc/systemd/system/shieldtier.service << 'EOF'
[Unit]
Description=ShieldTier Threat Intelligence Platform
After=network.target

[Service]
Type=simple
User=shieldtier
Group=shieldtier
WorkingDirectory=/opt/shieldtier/app
Environment="PATH=/opt/shieldtier/app/venv/bin:/usr/bin"
ExecStart=/opt/shieldtier/app/venv/bin/python3 server.py
Restart=always
RestartSec=5
StandardOutput=append:/var/log/shieldtier/app.log
StandardError=append:/var/log/shieldtier/error.log

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/shieldtier/data /var/log/shieldtier

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable shieldtier
sudo systemctl start shieldtier

# Check status
sudo systemctl status shieldtier
```

## Step 7: Configure Nginx with HTTPS (Cloudflare Origin Certificate)

### Option A: Cloudflare Origin Certificate (Recommended)

1. Go to Cloudflare Dashboard → **SSL/TLS** → **Origin Server**
2. Click **Create Certificate**
3. Keep defaults (RSA 2048, 15 years)
4. Copy the certificate and private key

```bash
# Create certificate directory
sudo mkdir -p /etc/nginx/ssl

# Paste your Cloudflare Origin Certificate
sudo nano /etc/nginx/ssl/cloudflare-origin.pem
# Paste certificate content and save

# Paste your Private Key
sudo nano /etc/nginx/ssl/cloudflare-origin.key
# Paste private key content and save

# Secure the key file
sudo chmod 600 /etc/nginx/ssl/cloudflare-origin.key
```

### Nginx Configuration

```bash
sudo tee /etc/nginx/sites-available/shieldtier << 'EOF'
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name your-domain.com;  # Replace with your domain
    return 301 https://$server_name$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    server_name your-domain.com;  # Replace with your domain

    # Cloudflare Origin Certificate
    ssl_certificate /etc/nginx/ssl/cloudflare-origin.pem;
    ssl_certificate_key /etc/nginx/ssl/cloudflare-origin.key;

    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Cloudflare real IP
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 131.0.72.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 2400:cb00::/32;
    set_real_ip_from 2606:4700::/32;
    set_real_ip_from 2803:f800::/32;
    set_real_ip_from 2405:b500::/32;
    set_real_ip_from 2405:8100::/32;
    set_real_ip_from 2a06:98c0::/29;
    set_real_ip_from 2c0f:f248::/32;
    real_ip_header CF-Connecting-IP;

    # File upload size (for email/file analysis)
    client_max_body_size 50M;

    # Timeouts for long-running analysis
    proxy_connect_timeout 60s;
    proxy_send_timeout 120s;
    proxy_read_timeout 120s;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_cache_bypass $http_upgrade;
    }

    # Static files caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
        proxy_pass http://127.0.0.1:3000;
        expires 7d;
        add_header Cache-Control "public, immutable";
    }
}
EOF

# Enable site
sudo ln -sf /etc/nginx/sites-available/shieldtier /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test and reload nginx
sudo nginx -t && sudo systemctl reload nginx
```

## Step 8: Cloudflare Configuration

### DNS Setup
1. Log in to Cloudflare Dashboard
2. Select your domain
3. Go to **DNS** → **Records**
4. Add an **A record**:
   - Name: `@` (or subdomain like `threat`)
   - IPv4: Your server's public IP
   - Proxy status: **Proxied** (orange cloud) ✅

### SSL/TLS Setup (IMPORTANT)
1. Go to **SSL/TLS** → **Overview**
2. Set encryption mode to: **Full (strict)** ✅

### Edge Certificates
1. Go to **SSL/TLS** → **Edge Certificates**
2. Enable:
   - Always Use HTTPS: **ON** ✅
   - Minimum TLS Version: **1.2** ✅
   - Automatic HTTPS Rewrites: **ON** ✅

### Security Settings (Recommended)
1. **Security** → **Settings**:
   - Security Level: Medium or High
   - Challenge Passage: 30 minutes
   - Browser Integrity Check: ON

2. **Security** → **WAF** (if available):
   - Enable managed rules

---

## Step 9: Firewall Configuration (Allow only Cloudflare)

```bash
# Install UFW
sudo apt install -y ufw

# Reset UFW
sudo ufw --force reset

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (important!)
sudo ufw allow ssh

# Allow Cloudflare IPs on port 443 (HTTPS)
for ip in 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 104.16.0.0/13 \
          104.24.0.0/14 108.162.192.0/18 131.0.72.0/22 141.101.64.0/18 \
          162.158.0.0/15 172.64.0.0/13 173.245.48.0/20 188.114.96.0/20 \
          190.93.240.0/20 197.234.240.0/22 198.41.128.0/17; do
    sudo ufw allow from $ip to any port 443
done

# Also allow port 80 for redirect
for ip in 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 104.16.0.0/13 \
          104.24.0.0/14 108.162.192.0/18 131.0.72.0/22 141.101.64.0/18 \
          162.158.0.0/15 172.64.0.0/13 173.245.48.0/20 188.114.96.0/20 \
          190.93.240.0/20 197.234.240.0/22 198.41.128.0/17; do
    sudo ufw allow from $ip to any port 80
done

# Enable firewall
sudo ufw --force enable
sudo ufw status
```

---

## Verification

```bash
# Check service status
sudo systemctl status shieldtier

# Check nginx status
sudo systemctl status nginx

# Test locally
curl -s http://localhost:3000/api/status | head -c 100

# Test HTTPS (from another machine)
curl -s https://your-domain.com/api/status

# Check logs
sudo tail -f /var/log/shieldtier/app.log
sudo tail -f /var/log/nginx/error.log
```

---

## Management Commands

```bash
# Restart application
sudo systemctl restart shieldtier

# View logs
sudo journalctl -u shieldtier -f

# Update application
cd /opt/shieldtier/app
sudo -u shieldtier git pull
cd frontend && sudo -u shieldtier npm run build
sudo systemctl restart shieldtier
```

---

## Troubleshooting

### 502 Bad Gateway
```bash
# Check if backend is running
curl http://localhost:3000/api/status
sudo systemctl status shieldtier
```

### SSL Certificate Error
- Ensure Cloudflare SSL mode is set to **Full (strict)**
- Verify Origin Certificate is correctly installed

### Connection Refused
```bash
# Check firewall
sudo ufw status

# Check if Cloudflare proxy is enabled (orange cloud)
```
