#!/bin/bash

# Manny Threat Intel - Interactive Installation Script
# =====================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${INSTALL_DIR}/api_keys.json"
ENV_FILE="${INSTALL_DIR}/.env"

# Default values
DEFAULT_PORT=3000
DEFAULT_DB_NAME="analysis_results.db"
DEFAULT_IOC_DB_NAME="ioc_cache.db"
DEFAULT_CACHE_HOURS=24

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║            ${BOLD}MANNY THREAT INTEL - INSTALLER${NC}${BLUE}                    ║"
echo "║                                                              ║"
echo "║        Threat Intelligence Platform & File Sandbox          ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ============================================================================
# STEP 1: System Requirements Check
# ============================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}STEP 1: Checking System Requirements${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check Python
if command -v python3 &>/dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}  ✓ Python ${PYTHON_VERSION} found${NC}"
else
    echo -e "${RED}  ✗ Python 3 not found. Please install Python 3.8+${NC}"
    exit 1
fi

# Check Node.js
if command -v node &>/dev/null; then
    NODE_VERSION=$(node --version 2>&1)
    echo -e "${GREEN}  ✓ Node.js ${NODE_VERSION} found${NC}"
else
    echo -e "${RED}  ✗ Node.js not found. Please install Node.js 18+${NC}"
    exit 1
fi

# Check npm
if command -v npm &>/dev/null; then
    NPM_VERSION=$(npm --version 2>&1)
    echo -e "${GREEN}  ✓ npm ${NPM_VERSION} found${NC}"
else
    echo -e "${RED}  ✗ npm not found${NC}"
    exit 1
fi

echo ""

# ============================================================================
# STEP 2: Server Configuration
# ============================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}STEP 2: Server Configuration${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Connection Mode
echo -e "${YELLOW}Select connection mode:${NC}"
echo "  1) Local only (127.0.0.1) - Access from this machine only"
echo "  2) Network (0.0.0.0) - Access from any device on the network"
echo ""
read -p "Enter choice [1-2] (default: 2): " CONNECTION_MODE
CONNECTION_MODE=${CONNECTION_MODE:-2}

if [ "$CONNECTION_MODE" == "1" ]; then
    BIND_HOST="127.0.0.1"
    echo -e "${GREEN}  ✓ Server will bind to localhost only${NC}"
else
    BIND_HOST="0.0.0.0"
    echo -e "${GREEN}  ✓ Server will be accessible on the network${NC}"
fi

# Port
echo ""
read -p "Enter server port (default: ${DEFAULT_PORT}): " SERVER_PORT
SERVER_PORT=${SERVER_PORT:-$DEFAULT_PORT}
echo -e "${GREEN}  ✓ Server port: ${SERVER_PORT}${NC}"

echo ""

# ============================================================================
# STEP 3: Database Configuration
# ============================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}STEP 3: Database Configuration${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Analysis Results Database
read -p "Analysis results database name (default: ${DEFAULT_DB_NAME}): " DB_NAME
DB_NAME=${DB_NAME:-$DEFAULT_DB_NAME}
echo -e "${GREEN}  ✓ Analysis database: ${DB_NAME}${NC}"

# IOC Cache Database
read -p "IOC cache database name (default: ${DEFAULT_IOC_DB_NAME}): " IOC_DB_NAME
IOC_DB_NAME=${IOC_DB_NAME:-$DEFAULT_IOC_DB_NAME}
echo -e "${GREEN}  ✓ IOC cache database: ${IOC_DB_NAME}${NC}"

# Cache Duration
echo ""
read -p "IOC cache duration in hours (default: ${DEFAULT_CACHE_HOURS}): " CACHE_HOURS
CACHE_HOURS=${CACHE_HOURS:-$DEFAULT_CACHE_HOURS}
echo -e "${GREEN}  ✓ Cache duration: ${CACHE_HOURS} hours${NC}"

echo ""

# ============================================================================
# STEP 4: Database Encryption
# ============================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}STEP 4: Database Encryption${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${YELLOW}⚠ IMPORTANT: The encryption key is used to encrypt sensitive data.${NC}"
echo -e "${YELLOW}  If you lose this key, encrypted data cannot be recovered!${NC}"
echo ""

read -p "Enable database encryption? [Y/n]: " ENABLE_ENCRYPTION
ENABLE_ENCRYPTION=${ENABLE_ENCRYPTION:-Y}

if [[ "$ENABLE_ENCRYPTION" =~ ^[Yy]$ ]]; then
    echo ""
    echo "Enter encryption secret (min 16 characters)"
    echo "Leave blank to auto-generate a secure key"
    read -s -p "Encryption secret: " ENCRYPTION_SECRET
    echo ""

    if [ -z "$ENCRYPTION_SECRET" ]; then
        ENCRYPTION_SECRET=$(openssl rand -base64 32 2>/dev/null || python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        echo -e "${GREEN}  ✓ Auto-generated encryption key${NC}"
    else
        if [ ${#ENCRYPTION_SECRET} -lt 16 ]; then
            echo -e "${RED}  ✗ Secret must be at least 16 characters${NC}"
            exit 1
        fi
        echo -e "${GREEN}  ✓ Custom encryption key set${NC}"
    fi

    # Save encryption key securely
    echo "$ENCRYPTION_SECRET" > "${INSTALL_DIR}/.encryption_key"
    chmod 600 "${INSTALL_DIR}/.encryption_key"
    echo -e "${YELLOW}  ! Key saved to .encryption_key (keep this file safe!)${NC}"
    DB_ENCRYPTION="true"
else
    DB_ENCRYPTION="false"
    echo -e "${YELLOW}  ! Database encryption disabled${NC}"
fi

echo ""

# ============================================================================
# STEP 5: API Keys Configuration
# ============================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}STEP 5: Threat Intelligence API Keys${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}Configure API keys for threat intelligence services.${NC}"
echo -e "${YELLOW}Press Enter to skip a service (can be configured later).${NC}"
echo ""

# Function to prompt for API key
prompt_api_key() {
    local service_name=$1
    local service_url=$2
    local var_name=$3

    echo -e "${BOLD}${service_name}${NC}"
    echo -e "  Get API key: ${BLUE}${service_url}${NC}"
    read -p "  API Key (Enter to skip): " api_key

    if [ -n "$api_key" ]; then
        eval "${var_name}=\"${api_key}\""
        eval "${var_name}_ENABLED=true"
        echo -e "${GREEN}  ✓ ${service_name} configured${NC}"
    else
        eval "${var_name}=\"\""
        eval "${var_name}_ENABLED=false"
        echo -e "${YELLOW}  - ${service_name} skipped${NC}"
    fi
    echo ""
}

# Prompt for each service
prompt_api_key "AbuseIPDB" "https://www.abuseipdb.com/account/api" "ABUSEIPDB_KEY"
prompt_api_key "VirusTotal" "https://www.virustotal.com/gui/my-apikey" "VIRUSTOTAL_KEY"
prompt_api_key "IPQualityScore" "https://www.ipqualityscore.com/create-account" "IPQS_KEY"
prompt_api_key "AlienVault OTX" "https://otx.alienvault.com/api" "OTX_KEY"
prompt_api_key "GreyNoise" "https://viz.greynoise.io/account/api-key" "GREYNOISE_KEY"
prompt_api_key "Shodan" "https://account.shodan.io/" "SHODAN_KEY"

# ============================================================================
# STEP 6: API Mode Configuration
# ============================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}STEP 6: API Mode Configuration${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${YELLOW}Select API mode:${NC}"
echo "  1) Full Mode - All features enabled (UI + API)"
echo "  2) API Only - REST API only (no web interface)"
echo "  3) UI Only - Web interface with basic lookups (no threat intel APIs)"
echo ""
read -p "Enter choice [1-3] (default: 1): " API_MODE
API_MODE=${API_MODE:-1}

case $API_MODE in
    1) API_MODE_NAME="full"; echo -e "${GREEN}  ✓ Full mode enabled${NC}" ;;
    2) API_MODE_NAME="api_only"; echo -e "${GREEN}  ✓ API-only mode enabled${NC}" ;;
    3) API_MODE_NAME="ui_only"; echo -e "${GREEN}  ✓ UI-only mode enabled${NC}" ;;
    *) API_MODE_NAME="full"; echo -e "${GREEN}  ✓ Full mode enabled (default)${NC}" ;;
esac

# Rate Limiting
echo ""
read -p "Enable API rate limiting? [Y/n]: " RATE_LIMIT
RATE_LIMIT=${RATE_LIMIT:-Y}
if [[ "$RATE_LIMIT" =~ ^[Yy]$ ]]; then
    read -p "Requests per minute (default: 60): " RATE_LIMIT_RPM
    RATE_LIMIT_RPM=${RATE_LIMIT_RPM:-60}
    RATE_LIMIT_ENABLED="true"
    echo -e "${GREEN}  ✓ Rate limiting: ${RATE_LIMIT_RPM} requests/minute${NC}"
else
    RATE_LIMIT_ENABLED="false"
    RATE_LIMIT_RPM=0
    echo -e "${YELLOW}  - Rate limiting disabled${NC}"
fi

echo ""

# ============================================================================
# STEP 7: Generate Configuration Files
# ============================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}STEP 7: Generating Configuration Files${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Generate api_keys.json
cat > "${CONFIG_FILE}" << APIKEYS
{
  "_comment": "Manny Threat Intel - API Configuration",
  "_generated": "$(date -Iseconds)",
  "abuseipdb": {
    "enabled": ${ABUSEIPDB_KEY_ENABLED},
    "api_key": "${ABUSEIPDB_KEY}"
  },
  "virustotal": {
    "enabled": ${VIRUSTOTAL_KEY_ENABLED},
    "api_key": "${VIRUSTOTAL_KEY}"
  },
  "ipqualityscore": {
    "enabled": ${IPQS_KEY_ENABLED},
    "api_key": "${IPQS_KEY}"
  },
  "alienvault_otx": {
    "enabled": ${OTX_KEY_ENABLED},
    "api_key": "${OTX_KEY}"
  },
  "greynoise": {
    "enabled": ${GREYNOISE_KEY_ENABLED},
    "api_key": "${GREYNOISE_KEY}"
  },
  "shodan": {
    "enabled": ${SHODAN_KEY_ENABLED},
    "api_key": "${SHODAN_KEY}"
  }
}
APIKEYS
chmod 600 "${CONFIG_FILE}"
echo -e "${GREEN}  ✓ Created api_keys.json${NC}"

# Generate .env file
cat > "${ENV_FILE}" << ENVFILE
# Manny Threat Intel - Environment Configuration
# Generated: $(date -Iseconds)

# Server Configuration
BIND_HOST=${BIND_HOST}
SERVER_PORT=${SERVER_PORT}
API_MODE=${API_MODE_NAME}

# Database Configuration
DATABASE_FILE=${DB_NAME}
IOC_CACHE_FILE=${IOC_DB_NAME}
CACHE_DURATION_HOURS=${CACHE_HOURS}

# Security
DB_ENCRYPTION_ENABLED=${DB_ENCRYPTION}
RATE_LIMIT_ENABLED=${RATE_LIMIT_ENABLED}
RATE_LIMIT_RPM=${RATE_LIMIT_RPM}

# Logging
LOG_LEVEL=INFO
ENVFILE
chmod 600 "${ENV_FILE}"
echo -e "${GREEN}  ✓ Created .env${NC}"

# Generate config.py for Python
cat > "${INSTALL_DIR}/config.py" << CONFIGPY
# Manny Threat Intel - Configuration
# Generated: $(date)

import os
from pathlib import Path

BASE_DIR = Path(__file__).parent

# Server Configuration
BIND_HOST = os.getenv('BIND_HOST', '${BIND_HOST}')
SERVER_PORT = int(os.getenv('SERVER_PORT', ${SERVER_PORT}))
API_MODE = os.getenv('API_MODE', '${API_MODE_NAME}')

# Database Configuration
DATABASE_FILE = os.getenv('DATABASE_FILE', '${DB_NAME}')
IOC_CACHE_FILE = os.getenv('IOC_CACHE_FILE', '${IOC_DB_NAME}')
CACHE_DURATION_HOURS = int(os.getenv('CACHE_DURATION_HOURS', ${CACHE_HOURS}))

# Security
DB_ENCRYPTION_ENABLED = os.getenv('DB_ENCRYPTION_ENABLED', '${DB_ENCRYPTION}').lower() == 'true'
RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', '${RATE_LIMIT_ENABLED}').lower() == 'true'
RATE_LIMIT_RPM = int(os.getenv('RATE_LIMIT_RPM', ${RATE_LIMIT_RPM}))

# Paths
DATABASE_PATH = BASE_DIR / DATABASE_FILE
IOC_CACHE_PATH = BASE_DIR / IOC_CACHE_FILE
API_KEYS_PATH = BASE_DIR / 'api_keys.json'
ENCRYPTION_KEY_PATH = BASE_DIR / '.encryption_key'
CONFIGPY
echo -e "${GREEN}  ✓ Created config.py${NC}"

echo ""

# ============================================================================
# STEP 8: Install Dependencies
# ============================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}STEP 8: Installing Dependencies${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Python dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
pip3 install -r "${INSTALL_DIR}/requirements.txt" --user --break-system-packages 2>/dev/null || \
pip3 install -r "${INSTALL_DIR}/requirements.txt" --user 2>/dev/null || \
pip3 install -r "${INSTALL_DIR}/requirements.txt"
echo -e "${GREEN}  ✓ Python dependencies installed${NC}"

# Node.js dependencies
echo -e "${YELLOW}Installing frontend dependencies...${NC}"
cd "${INSTALL_DIR}/frontend"
npm install --silent 2>/dev/null || npm install
echo -e "${GREEN}  ✓ Frontend dependencies installed${NC}"

# Build frontend
echo -e "${YELLOW}Building frontend...${NC}"
npm run build --silent 2>/dev/null || npm run build
echo -e "${GREEN}  ✓ Frontend built${NC}"
cd "${INSTALL_DIR}"

echo ""

# ============================================================================
# STEP 9: Create Helper Scripts
# ============================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}STEP 9: Creating Helper Scripts${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Start script
cat > "${INSTALL_DIR}/start.sh" << 'STARTSCRIPT'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Load environment
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

echo "Starting Manny Threat Intel..."
python3 server.py
STARTSCRIPT
chmod +x "${INSTALL_DIR}/start.sh"
echo -e "${GREEN}  ✓ Created start.sh${NC}"

# Stop script
cat > "${INSTALL_DIR}/stop.sh" << 'STOPSCRIPT'
#!/bin/bash
pkill -f "python.*server.py" 2>/dev/null && echo "Server stopped" || echo "Server not running"
STOPSCRIPT
chmod +x "${INSTALL_DIR}/stop.sh"
echo -e "${GREEN}  ✓ Created stop.sh${NC}"

# Status script
cat > "${INSTALL_DIR}/status.sh" << 'STATUSSCRIPT'
#!/bin/bash
if pgrep -f "python.*server.py" > /dev/null; then
    echo "Manny Threat Intel is running"
    echo "PID: $(pgrep -f 'python.*server.py')"
    echo "Port: $(ss -tlnp 2>/dev/null | grep python | awk '{print $4}' | cut -d: -f2)"
else
    echo "Manny Threat Intel is not running"
fi
STATUSSCRIPT
chmod +x "${INSTALL_DIR}/status.sh"
echo -e "${GREEN}  ✓ Created status.sh${NC}"

# Reconfigure script
cat > "${INSTALL_DIR}/reconfigure.sh" << 'RECONFIGSCRIPT'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Re-running installer to reconfigure..."
exec "${SCRIPT_DIR}/install.sh"
RECONFIGSCRIPT
chmod +x "${INSTALL_DIR}/reconfigure.sh"
echo -e "${GREEN}  ✓ Created reconfigure.sh${NC}"

echo ""

# ============================================================================
# STEP 10: Service Installation (Optional)
# ============================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}STEP 10: System Service Installation${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${YELLOW}Install as a system service for auto-start on boot?${NC}"
echo "This requires sudo/root access."
echo ""
read -p "Install service? [y/N]: " INSTALL_SERVICE

if [[ "$INSTALL_SERVICE" =~ ^[Yy]$ ]]; then
    SERVICE_FILE="/etc/systemd/system/manny-threatintel.service"
    CURRENT_USER="${SUDO_USER:-$USER}"

    echo ""
    echo -e "${YELLOW}Installing systemd service...${NC}"

    sudo bash -c "cat > ${SERVICE_FILE}" << SERVICEEOF
[Unit]
Description=Manny Threat Intel Server
After=network.target

[Service]
Type=simple
User=${CURRENT_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/server.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICEEOF

    sudo systemctl daemon-reload
    sudo systemctl enable manny-threatintel.service
    sudo systemctl start manny-threatintel.service

    echo -e "${GREEN}  ✓ Service installed and started${NC}"
    SERVICE_INSTALLED=true
else
    SERVICE_INSTALLED=false
    echo -e "${YELLOW}  - Service installation skipped${NC}"
fi

echo ""

# ============================================================================
# Installation Complete
# ============================================================================
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║            ${BOLD}INSTALLATION COMPLETE!${NC}${GREEN}                          ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BOLD}Configuration Summary:${NC}"
echo "  Server:      ${BIND_HOST}:${SERVER_PORT}"
echo "  API Mode:    ${API_MODE_NAME}"
echo "  Database:    ${DB_NAME}"
echo "  IOC Cache:   ${IOC_DB_NAME}"
echo "  Encryption:  ${DB_ENCRYPTION}"
echo ""

echo -e "${BOLD}API Keys Configured:${NC}"
[ "$ABUSEIPDB_KEY_ENABLED" = "true" ] && echo -e "  ${GREEN}✓${NC} AbuseIPDB" || echo -e "  ${YELLOW}-${NC} AbuseIPDB (not configured)"
[ "$VIRUSTOTAL_KEY_ENABLED" = "true" ] && echo -e "  ${GREEN}✓${NC} VirusTotal" || echo -e "  ${YELLOW}-${NC} VirusTotal (not configured)"
[ "$IPQS_KEY_ENABLED" = "true" ] && echo -e "  ${GREEN}✓${NC} IPQualityScore" || echo -e "  ${YELLOW}-${NC} IPQualityScore (not configured)"
[ "$OTX_KEY_ENABLED" = "true" ] && echo -e "  ${GREEN}✓${NC} AlienVault OTX" || echo -e "  ${YELLOW}-${NC} AlienVault OTX (not configured)"
[ "$GREYNOISE_KEY_ENABLED" = "true" ] && echo -e "  ${GREEN}✓${NC} GreyNoise" || echo -e "  ${YELLOW}-${NC} GreyNoise (not configured)"
[ "$SHODAN_KEY_ENABLED" = "true" ] && echo -e "  ${GREEN}✓${NC} Shodan" || echo -e "  ${YELLOW}-${NC} Shodan (not configured)"
echo ""

if [ "$SERVICE_INSTALLED" = true ]; then
    echo -e "${BOLD}Service Commands:${NC}"
    echo "  sudo systemctl status manny-threatintel   # Check status"
    echo "  sudo systemctl restart manny-threatintel  # Restart"
    echo "  sudo systemctl stop manny-threatintel     # Stop"
    echo "  sudo journalctl -u manny-threatintel -f   # View logs"
else
    echo -e "${BOLD}Start the server:${NC}"
    echo "  cd ${INSTALL_DIR}"
    echo "  ./start.sh"
fi

echo ""
echo -e "${BOLD}Access the application:${NC}"
if [ "$BIND_HOST" = "0.0.0.0" ]; then
    echo "  Local:   http://localhost:${SERVER_PORT}"
    echo "  Network: http://${LOCAL_IP}:${SERVER_PORT}"
else
    echo "  http://localhost:${SERVER_PORT}"
fi

echo ""
echo -e "${BOLD}Helper Scripts:${NC}"
echo "  ./start.sh        # Start server"
echo "  ./stop.sh         # Stop server"
echo "  ./status.sh       # Check server status"
echo "  ./reconfigure.sh  # Re-run configuration"

echo ""
echo -e "${YELLOW}Important Files (keep secure):${NC}"
echo "  api_keys.json     # API keys"
echo "  .env              # Environment config"
[ "$DB_ENCRYPTION" = "true" ] && echo "  .encryption_key   # Database encryption key"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
