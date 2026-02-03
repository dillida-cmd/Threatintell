#!/bin/bash

# Manny Threat Intel - Systemd Service Installer
# ===============================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Must run as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./install-service.sh)${NC}"
    exit 1
fi

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="/etc/systemd/system/manny-threatintel.service"
CURRENT_USER="${SUDO_USER:-$USER}"

echo -e "${BLUE}"
echo "=================================================="
echo "   Manny Threat Intel - Service Installer"
echo "=================================================="
echo -e "${NC}"

# Create service file from template
echo -e "${YELLOW}[1/3] Creating systemd service...${NC}"
sed -e "s|REPLACE_WITH_USERNAME|${CURRENT_USER}|g" \
    -e "s|REPLACE_WITH_INSTALL_PATH|${INSTALL_DIR}|g" \
    "${INSTALL_DIR}/manny-threatintel.service" > "${SERVICE_FILE}"
echo -e "${GREEN}  ✓ Service file created${NC}"

# Reload systemd
echo -e "${YELLOW}[2/3] Reloading systemd...${NC}"
systemctl daemon-reload
echo -e "${GREEN}  ✓ Systemd reloaded${NC}"

# Enable service
echo -e "${YELLOW}[3/3] Enabling service...${NC}"
systemctl enable manny-threatintel.service
echo -e "${GREEN}  ✓ Service enabled${NC}"

# Get local IP
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

echo ""
echo -e "${GREEN}=================================================="
echo "       Service Installation Complete!"
echo "==================================================${NC}"
echo ""
echo -e "  ${BLUE}Service commands:${NC}"
echo "    sudo systemctl start manny-threatintel    # Start server"
echo "    sudo systemctl stop manny-threatintel     # Stop server"
echo "    sudo systemctl restart manny-threatintel  # Restart server"
echo "    sudo systemctl status manny-threatintel   # Check status"
echo "    sudo journalctl -u manny-threatintel -f   # View logs"
echo ""
echo -e "  ${BLUE}Access the application:${NC}"
echo "    Local:   http://localhost:3000"
echo "    Network: http://${LOCAL_IP}:3000"
echo ""
echo -e "  ${YELLOW}To start the service now:${NC}"
echo "    sudo systemctl start manny-threatintel"
echo ""
echo -e "${GREEN}==================================================${NC}"
