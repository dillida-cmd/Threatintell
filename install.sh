#!/bin/bash

# Manny Threat Intel - Installation Script
# =========================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}"
echo "=================================================="
echo "       Manny Threat Intel - Installer"
echo "=================================================="
echo -e "${NC}"

# Check if running as root for system-wide install
if [ "$EUID" -eq 0 ]; then
    SUDO=""
    PIP_ARGS=""
else
    SUDO="sudo"
    PIP_ARGS="--user"
fi

# Function to check command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Python
echo -e "${YELLOW}[1/6] Checking Python...${NC}"
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}  ✓ Python ${PYTHON_VERSION} found${NC}"
else
    echo -e "${RED}  ✗ Python 3 not found. Please install Python 3.8+${NC}"
    exit 1
fi

# Check Node.js
echo -e "${YELLOW}[2/6] Checking Node.js...${NC}"
if command_exists node; then
    NODE_VERSION=$(node --version 2>&1)
    echo -e "${GREEN}  ✓ Node.js ${NODE_VERSION} found${NC}"
else
    echo -e "${RED}  ✗ Node.js not found. Please install Node.js 18+${NC}"
    echo -e "${YELLOW}  Install with: curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash - && sudo apt-get install -y nodejs${NC}"
    exit 1
fi

# Check npm
if command_exists npm; then
    NPM_VERSION=$(npm --version 2>&1)
    echo -e "${GREEN}  ✓ npm ${NPM_VERSION} found${NC}"
else
    echo -e "${RED}  ✗ npm not found${NC}"
    exit 1
fi

# Install Python dependencies
echo -e "${YELLOW}[3/6] Installing Python dependencies...${NC}"
if [ -f "${INSTALL_DIR}/requirements.txt" ]; then
    pip3 install -r "${INSTALL_DIR}/requirements.txt" ${PIP_ARGS} --break-system-packages 2>/dev/null || \
    pip3 install -r "${INSTALL_DIR}/requirements.txt" ${PIP_ARGS}
    echo -e "${GREEN}  ✓ Python dependencies installed${NC}"
else
    pip3 install flask requests oletools python-magic ${PIP_ARGS} --break-system-packages 2>/dev/null || \
    pip3 install flask requests oletools python-magic ${PIP_ARGS}
    echo -e "${GREEN}  ✓ Python dependencies installed${NC}"
fi

# Install Node.js dependencies
echo -e "${YELLOW}[4/6] Installing frontend dependencies...${NC}"
cd "${INSTALL_DIR}/frontend"
npm install --silent
echo -e "${GREEN}  ✓ Frontend dependencies installed${NC}"

# Build frontend
echo -e "${YELLOW}[5/6] Building frontend...${NC}"
npm run build --silent
echo -e "${GREEN}  ✓ Frontend built successfully${NC}"
cd "${INSTALL_DIR}"

# Create API keys config if not exists
echo -e "${YELLOW}[6/6] Setting up configuration...${NC}"
if [ ! -f "${INSTALL_DIR}/api_keys.json" ]; then
    cat > "${INSTALL_DIR}/api_keys.json" << 'APIKEYS'
{
  "_comment": "Add your API keys below. Set enabled to true for services you want to use.",
  "abuseipdb": {
    "enabled": false,
    "api_key": "YOUR_ABUSEIPDB_API_KEY"
  },
  "virustotal": {
    "enabled": false,
    "api_key": "YOUR_VIRUSTOTAL_API_KEY"
  },
  "ipqualityscore": {
    "enabled": false,
    "api_key": "YOUR_IPQUALITYSCORE_API_KEY"
  },
  "alienvault_otx": {
    "enabled": false,
    "api_key": "YOUR_ALIENVAULT_OTX_API_KEY"
  },
  "greynoise": {
    "enabled": false,
    "api_key": "YOUR_GREYNOISE_API_KEY"
  },
  "shodan": {
    "enabled": false,
    "api_key": "YOUR_SHODAN_API_KEY"
  }
}
APIKEYS
    echo -e "${GREEN}  ✓ Created api_keys.json template${NC}"
    echo -e "${YELLOW}  ! Please edit api_keys.json and add your API keys${NC}"
else
    echo -e "${GREEN}  ✓ api_keys.json already exists${NC}"
fi

# Create start script
cat > "${INSTALL_DIR}/start.sh" << 'STARTSCRIPT'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"
python3 server.py
STARTSCRIPT
chmod +x "${INSTALL_DIR}/start.sh"
echo -e "${GREEN}  ✓ Created start.sh${NC}"

# Create stop script
cat > "${INSTALL_DIR}/stop.sh" << 'STOPSCRIPT'
#!/bin/bash
pkill -f "python.*server.py" 2>/dev/null && echo "Server stopped" || echo "Server not running"
STOPSCRIPT
chmod +x "${INSTALL_DIR}/stop.sh"
echo -e "${GREEN}  ✓ Created stop.sh${NC}"

# Get local IP
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

echo ""
echo -e "${GREEN}=================================================="
echo "       Installation Complete!"
echo "==================================================${NC}"
echo ""
echo -e "  ${BLUE}To start the server:${NC}"
echo "    cd ${INSTALL_DIR}"
echo "    ./start.sh"
echo ""
echo -e "  ${BLUE}Access the application:${NC}"
echo "    Local:   http://localhost:3000"
echo "    Network: http://${LOCAL_IP}:3000"
echo ""
echo -e "  ${YELLOW}Important:${NC}"
echo "    Edit api_keys.json to add your threat intel API keys"
echo ""
echo -e "${GREEN}==================================================${NC}"
