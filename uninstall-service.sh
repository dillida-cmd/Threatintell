#!/bin/bash

# Manny Threat Intel - Service Uninstaller
# =========================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./uninstall-service.sh)${NC}"
    exit 1
fi

echo -e "${YELLOW}Stopping service...${NC}"
systemctl stop manny-threatintel.service 2>/dev/null || true

echo -e "${YELLOW}Disabling service...${NC}"
systemctl disable manny-threatintel.service 2>/dev/null || true

echo -e "${YELLOW}Removing service file...${NC}"
rm -f /etc/systemd/system/manny-threatintel.service

echo -e "${YELLOW}Reloading systemd...${NC}"
systemctl daemon-reload

echo -e "${GREEN}Service uninstalled successfully${NC}"
