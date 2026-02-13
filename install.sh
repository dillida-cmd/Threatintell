#!/bin/bash
#
# ShieldTier Installation Script
# Installs ShieldTier with Nginx reverse proxy for Cloudflare
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/dillida-cmd/Threatintell/master/install.sh | sudo bash -s -- your-domain.com
#   OR
#   sudo ./install.sh your-domain.com
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║          ShieldTier Installation Script                   ║"
echo "║      Threat Intelligence Platform by MTI                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo -e "${RED}Cannot detect OS${NC}"
    exit 1
fi

echo -e "${GREEN}Detected OS: $OS${NC}"

# Get domain name from argument or prompt
DOMAIN="$1"
if [ -z "$DOMAIN" ]; then
    # Try to read interactively
    if [ -t 0 ]; then
        read -p "Enter your domain name (e.g., threat.example.com): " DOMAIN
    fi
fi

if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Domain name is required${NC}"
    echo ""
    echo "Usage:"
    echo "  curl -sSL https://raw.githubusercontent.com/dillida-cmd/Threatintell/master/install.sh | sudo bash -s -- your-domain.com"
    echo "  OR"
    echo "  sudo ./install.sh your-domain.com"
    exit 1
fi

echo ""
echo -e "${YELLOW}Installing ShieldTier for domain: $DOMAIN${NC}"
echo ""

# Step 1: Install system dependencies
echo -e "${BLUE}[1/8] Installing system dependencies...${NC}"
apt update
apt install -y python3 python3-pip python3-venv git nginx ufw curl

# Optional dependencies - Screenshots
apt install -y chromium-browser chromium-chromedriver 2>/dev/null || \
apt install -y chromium chromium-driver 2>/dev/null || \
echo -e "${YELLOW}Chromium not available, screenshots will be limited${NC}"

# Sandbox dependencies - Core
apt install -y bubblewrap strace poppler-utils auditd 2>/dev/null || true

# Sandbox dependencies - Wine (for Windows .exe analysis)
echo -e "${BLUE}Installing Wine for Windows executable analysis...${NC}"
dpkg --add-architecture i386 2>/dev/null || true
apt update
apt install -y wine wine32 wine64 2>/dev/null || \
apt install -y wine 2>/dev/null || \
echo -e "${YELLOW}Wine not available, Windows executable analysis will be disabled${NC}"

# Sandbox dependencies - LibreOffice (for Office macro execution in sandbox)
echo -e "${BLUE}Installing LibreOffice for Office document analysis...${NC}"
apt install -y libreoffice --no-install-recommends 2>/dev/null || \
echo -e "${YELLOW}LibreOffice not available, Office macro execution will be disabled${NC}"

# Sandbox dependencies - Docker (optional, for stronger isolation)
echo -e "${BLUE}Installing Docker for enhanced sandbox isolation...${NC}"
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh 2>/dev/null || \
    echo -e "${YELLOW}Docker not available, using bubblewrap for sandboxing${NC}"
fi
if command -v docker &> /dev/null; then
    systemctl enable docker 2>/dev/null || true
    systemctl start docker 2>/dev/null || true
    usermod -aG docker shieldtier 2>/dev/null || true
fi

# Step 2: Install Node.js
echo -e "${BLUE}[2/8] Installing Node.js...${NC}"
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt install -y nodejs
fi
echo -e "${GREEN}Node.js version: $(node --version)${NC}"

# Step 3: Create application user
echo -e "${BLUE}[3/8] Creating application user...${NC}"
if ! id "shieldtier" &>/dev/null; then
    useradd -r -s /bin/false -m -d /opt/shieldtier shieldtier
fi
mkdir -p /opt/shieldtier /var/log/shieldtier
chown -R shieldtier:shieldtier /opt/shieldtier /var/log/shieldtier

# Step 4: Clone repository
echo -e "${BLUE}[4/8] Cloning ShieldTier repository...${NC}"
if [ -d /opt/shieldtier/app ]; then
    cd /opt/shieldtier/app
    sudo -u shieldtier git pull
else
    cd /opt/shieldtier
    sudo -u shieldtier git clone https://github.com/dillida-cmd/Threatintell.git app
fi

# Step 5: Setup Python environment
echo -e "${BLUE}[5/8] Setting up Python environment...${NC}"
cd /opt/shieldtier/app
if [ ! -d venv ]; then
    sudo -u shieldtier python3 -m venv venv
fi
sudo -u shieldtier ./venv/bin/pip install --upgrade pip
sudo -u shieldtier ./venv/bin/pip install \
    requests \
    reportlab \
    PyPDF2 \
    PyMuPDF \
    Pillow \
    selenium \
    pyzbar \
    python-magic \
    oletools \
    cryptography

# Step 6: Build frontend
echo -e "${BLUE}[6/8] Building frontend...${NC}"
cd /opt/shieldtier/app/frontend
sudo -u shieldtier npm install
sudo -u shieldtier npm run build

# Create data directory
mkdir -p /opt/shieldtier/data
chown shieldtier:shieldtier /opt/shieldtier/data

# Create API keys config template if not exists
if [ ! -f /opt/shieldtier/app/api_keys.json ]; then
    cat > /opt/shieldtier/app/api_keys.json << 'APIEOF'
{
  "_comment": "API Keys Configuration - Add your API keys below",

  "abuseipdb": {
    "api_key": "",
    "enabled": true,
    "description": "IP reputation - https://www.abuseipdb.com/account/api"
  },

  "virustotal": {
    "api_key": "",
    "enabled": true,
    "description": "URL/IP/Hash scanning - https://www.virustotal.com/gui/my-apikey"
  },

  "urlhaus": {
    "api_key": "",
    "enabled": true,
    "description": "Malicious URLs (abuse.ch) - https://auth.abuse.ch/"
  },

  "ipqualityscore": {
    "api_key": "",
    "enabled": true,
    "description": "IP fraud scoring - https://www.ipqualityscore.com/"
  },

  "alienvault_otx": {
    "api_key": "",
    "enabled": true,
    "description": "Open Threat Exchange - https://otx.alienvault.com/api"
  },

  "shodan": {
    "api_key": "",
    "enabled": true,
    "description": "Device search - https://account.shodan.io/"
  },

  "greynoise": {
    "api_key": "",
    "enabled": true,
    "description": "Scanner detection - https://viz.greynoise.io/account/api-key"
  },

  "threatfox": {
    "api_key": "",
    "enabled": true,
    "description": "IOC database (abuse.ch) - https://auth.abuse.ch/"
  }
}
APIEOF
    chown shieldtier:shieldtier /opt/shieldtier/app/api_keys.json
    chmod 600 /opt/shieldtier/app/api_keys.json
fi

# Step 7: Create systemd service
echo -e "${BLUE}[7/8] Creating systemd service...${NC}"
cat > /etc/systemd/system/shieldtier.service << 'EOF'
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

NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable shieldtier
systemctl start shieldtier

# Install sandbox audit rules
if [ -f /opt/shieldtier/app/audit-sandbox.rules ]; then
    echo -e "${BLUE}Installing sandbox audit rules...${NC}"
    cp /opt/shieldtier/app/audit-sandbox.rules /etc/audit/rules.d/sandbox.rules 2>/dev/null || true
    auditctl -R /etc/audit/rules.d/sandbox.rules 2>/dev/null || true
fi

# Step 8: Configure Nginx
echo -e "${BLUE}[8/8] Configuring Nginx...${NC}"

# Create SSL directory
mkdir -p /etc/nginx/ssl

cat > /etc/nginx/sites-available/shieldtier << EOF
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    # SSL Certificate (Cloudflare Origin Certificate)
    ssl_certificate /etc/nginx/ssl/cloudflare-origin.pem;
    ssl_certificate_key /etc/nginx/ssl/cloudflare-origin.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
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
    real_ip_header CF-Connecting-IP;

    client_max_body_size 50M;
    proxy_connect_timeout 60s;
    proxy_send_timeout 120s;
    proxy_read_timeout 120s;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

ln -sf /etc/nginx/sites-available/shieldtier /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Configure firewall
echo -e "${BLUE}Configuring firewall...${NC}"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh

# Allow Cloudflare IPs
for ip in 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 104.16.0.0/13 \
          104.24.0.0/14 108.162.192.0/18 131.0.72.0/22 141.101.64.0/18 \
          162.158.0.0/15 172.64.0.0/13 173.245.48.0/20 188.114.96.0/20 \
          190.93.240.0/20 197.234.240.0/22 198.41.128.0/17; do
    ufw allow from $ip to any port 443
    ufw allow from $ip to any port 80
done

ufw --force enable

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Installation Complete!                           ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}NEXT STEPS:${NC}"
echo ""
echo -e "1. ${BLUE}Create Cloudflare Origin Certificate:${NC}"
echo "   - Go to Cloudflare Dashboard → SSL/TLS → Origin Server"
echo "   - Click 'Create Certificate'"
echo "   - Copy certificate to: /etc/nginx/ssl/cloudflare-origin.pem"
echo "   - Copy private key to: /etc/nginx/ssl/cloudflare-origin.key"
echo ""
echo -e "2. ${BLUE}Set permissions:${NC}"
echo "   sudo chmod 600 /etc/nginx/ssl/cloudflare-origin.key"
echo ""
echo -e "3. ${BLUE}Test and start Nginx:${NC}"
echo "   sudo nginx -t && sudo systemctl restart nginx"
echo ""
echo -e "4. ${BLUE}Configure Cloudflare DNS:${NC}"
echo "   - Add A record pointing to your server IP"
echo "   - Enable Proxy (orange cloud)"
echo "   - Set SSL mode to 'Full (strict)'"
echo ""
echo -e "5. ${BLUE}Add API keys:${NC}"
echo "   sudo nano /opt/shieldtier/app/api_keys.json"
echo "   # Add keys for: VirusTotal, AbuseIPDB, GreyNoise, Shodan, etc."
echo ""
echo -e "6. ${BLUE}Restart and verify:${NC}"
echo "   sudo systemctl restart shieldtier"
echo "   curl -s http://localhost:3000/api/status"
echo ""
echo -e "7. ${BLUE}Verify sandbox status:${NC}"
echo "   curl -s http://localhost:3000/api/sandbox/status | python3 -m json.tool"
echo ""
echo -e "${GREEN}ShieldTier will be available at: https://$DOMAIN${NC}"
echo ""
echo -e "${BLUE}Sandbox Capabilities Installed:${NC}"
command -v bwrap &>/dev/null && echo "  ✓ Bubblewrap (sandbox isolation)" || echo "  ✗ Bubblewrap"
command -v docker &>/dev/null && echo "  ✓ Docker (enhanced isolation)" || echo "  ✗ Docker"
command -v wine &>/dev/null && echo "  ✓ Wine (Windows .exe analysis)" || echo "  ✗ Wine"
command -v libreoffice &>/dev/null && echo "  ✓ LibreOffice (Office macro execution)" || echo "  ✗ LibreOffice"
command -v strace &>/dev/null && echo "  ✓ Strace (syscall tracing)" || echo "  ✗ Strace"
command -v chromium &>/dev/null || command -v chromium-browser &>/dev/null && echo "  ✓ Chromium (URL screenshots)" || echo "  ✗ Chromium"
echo ""
