#!/bin/bash
#
# ShieldTier Diagnostics Script
# Run as root on the server: sudo bash diagnostics.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

APP_DIR="/opt/shieldtier/app"
VENV_PYTHON="${APP_DIR}/venv/bin/python3"
VENV_PIP="${APP_DIR}/venv/bin/pip"

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}   ShieldTier Diagnostics Report${NC}"
echo -e "${BLUE}   $(date)${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Function to check status
check_ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

check_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

check_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

check_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# ============================================
# 1. SYSTEM SERVICE STATUS
# ============================================
echo -e "${YELLOW}=== 1. SERVICE STATUS ===${NC}"

if systemctl is-active --quiet shieldtier; then
    check_ok "shieldtier service is running"
    systemctl status shieldtier --no-pager -l | head -10
else
    check_fail "shieldtier service is NOT running"
    systemctl status shieldtier --no-pager -l | head -20
fi
echo ""

# ============================================
# 2. PYTHON ENVIRONMENT
# ============================================
echo -e "${YELLOW}=== 2. PYTHON ENVIRONMENT ===${NC}"

if [ -f "$VENV_PYTHON" ]; then
    check_ok "Virtual environment exists: $VENV_PYTHON"
    PYTHON_VERSION=$($VENV_PYTHON --version 2>&1)
    check_info "Python version: $PYTHON_VERSION"
else
    check_fail "Virtual environment not found at $VENV_PYTHON"
fi
echo ""

# ============================================
# 3. PYTHON DEPENDENCIES (VENV)
# ============================================
echo -e "${YELLOW}=== 3. PYTHON DEPENDENCIES (venv) ===${NC}"

PYTHON_DEPS=(
    "flask:Flask web framework"
    "requests:HTTP library"
    "pefile:PE/EXE analysis"
    "oletools:Office macro analysis"
    "reportlab:PDF generation"
    "PyPDF2:PDF parsing"
    "PIL:Image processing (Pillow)"
    "pyzbar:QR code detection"
    "pdf2image:PDF screenshots"
    "magic:File type detection"
)

for dep_info in "${PYTHON_DEPS[@]}"; do
    dep="${dep_info%%:*}"
    desc="${dep_info##*:}"
    if $VENV_PYTHON -c "import $dep" 2>/dev/null; then
        check_ok "$dep - $desc"
    else
        check_fail "$dep - $desc (NOT INSTALLED)"
    fi
done
echo ""

# ============================================
# 4. SANDBOX SERVICE FLAGS
# ============================================
echo -e "${YELLOW}=== 4. SANDBOX SERVICE FLAGS ===${NC}"

cd "$APP_DIR"
$VENV_PYTHON -c "
import sandbox_service as ss
print('PE_ANALYSIS_AVAILABLE:', ss.PE_ANALYSIS_AVAILABLE)
service = ss.get_service()
print('Sandbox backend:', service.backend if hasattr(service, 'backend') else 'N/A')
" 2>/dev/null || check_fail "Could not load sandbox_service"
echo ""

# ============================================
# 5. SCREENSHOT SERVICE
# ============================================
echo -e "${YELLOW}=== 5. SCREENSHOT SERVICE ===${NC}"

cd "$APP_DIR"
$VENV_PYTHON -c "
import screenshot_service as ss
import json
status = ss.get_service_status()
print(json.dumps(status, indent=2))
" 2>/dev/null || check_fail "Could not load screenshot_service"
echo ""

# ============================================
# 6. BROWSER AVAILABILITY
# ============================================
echo -e "${YELLOW}=== 6. BROWSER AVAILABILITY ===${NC}"

BROWSERS=(
    "google-chrome-stable"
    "google-chrome"
    "chromium"
    "chromium-browser"
    "/snap/bin/chromium"
    "firefox"
)

for browser in "${BROWSERS[@]}"; do
    path=$(which "$browser" 2>/dev/null || echo "")
    if [ -n "$path" ]; then
        version=$($browser --version 2>/dev/null | head -1 || echo "version unknown")
        check_ok "$browser: $path ($version)"
    else
        check_info "$browser: not found"
    fi
done
echo ""

# ============================================
# 7. SYSTEM DEPENDENCIES
# ============================================
echo -e "${YELLOW}=== 7. SYSTEM DEPENDENCIES ===${NC}"

SYS_DEPS=(
    "libzbar0:QR code scanning"
    "poppler-utils:PDF processing"
    "libreoffice:Office document conversion"
    "wine:Windows executable support"
    "bubblewrap:Sandbox isolation"
    "nodejs:Node.js runtime"
    "npm:Node package manager"
)

for dep_info in "${SYS_DEPS[@]}"; do
    dep="${dep_info%%:*}"
    desc="${dep_info##*:}"
    if dpkg -l | grep -q "^ii.*$dep"; then
        check_ok "$dep - $desc"
    elif which "$dep" >/dev/null 2>&1; then
        check_ok "$dep - $desc (binary found)"
    else
        check_warn "$dep - $desc (not installed)"
    fi
done
echo ""

# ============================================
# 8. DIRECTORY PERMISSIONS
# ============================================
echo -e "${YELLOW}=== 8. DIRECTORY PERMISSIONS ===${NC}"

DIRS=(
    "/opt/shieldtier/app:Application directory"
    "/opt/shieldtier/data:Data directory"
    "/opt/shieldtier/app/screenshots:Screenshot storage"
    "/opt/shieldtier/app/sandbox:Sandbox directory"
    "/var/log/shieldtier:Log directory"
)

for dir_info in "${DIRS[@]}"; do
    dir="${dir_info%%:*}"
    desc="${dir_info##*:}"
    if [ -d "$dir" ]; then
        owner=$(stat -c '%U:%G' "$dir")
        perms=$(stat -c '%a' "$dir")
        check_ok "$dir ($owner, $perms)"
    else
        check_warn "$dir - does not exist"
    fi
done
echo ""

# ============================================
# 9. DATABASE FILES
# ============================================
echo -e "${YELLOW}=== 9. DATABASE FILES ===${NC}"

DB_FILES=(
    "analysis_results.db:Analysis results"
    "ioc_cache.db:IOC cache"
)

for db_info in "${DB_FILES[@]}"; do
    db="${db_info%%:*}"
    desc="${db_info##*:}"
    db_path="$APP_DIR/$db"
    if [ -f "$db_path" ]; then
        size=$(du -h "$db_path" | cut -f1)
        check_ok "$db - $desc ($size)"
    else
        check_info "$db - $desc (not created yet)"
    fi
done
echo ""

# ============================================
# 10. API ENDPOINT TEST
# ============================================
echo -e "${YELLOW}=== 10. API ENDPOINT TEST ===${NC}"

API_URL="http://localhost:3000"

if curl -s --connect-timeout 5 "$API_URL/api/status" >/dev/null 2>&1; then
    check_ok "API is responding"
    echo "Status endpoint response:"
    curl -s "$API_URL/api/status" | python3 -m json.tool 2>/dev/null || echo "(could not parse JSON)"
else
    check_fail "API is not responding at $API_URL"
fi
echo ""

# ============================================
# 11. SCREENSHOT TEST
# ============================================
echo -e "${YELLOW}=== 11. SCREENSHOT TEST ===${NC}"

cd "$APP_DIR"
SCREENSHOT_RESULT=$($VENV_PYTHON -c "
import screenshot_service as ss
r = ss.capture_url_screenshot('https://example.com')
print('Success:', r['success'])
print('Browser:', r['browser'])
print('Error:', r.get('error', 'None'))
print('File size:', r.get('file_size', 0))
" 2>&1)

echo "$SCREENSHOT_RESULT"
if echo "$SCREENSHOT_RESULT" | grep -q "Success: True"; then
    check_ok "Screenshot capture working"
else
    check_fail "Screenshot capture failed"
fi
echo ""

# ============================================
# 12. GIT STATUS
# ============================================
echo -e "${YELLOW}=== 12. GIT STATUS ===${NC}"

cd "$APP_DIR"
if [ -d ".git" ]; then
    CURRENT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null)
    BRANCH=$(git branch --show-current 2>/dev/null)
    check_ok "Git repository: $BRANCH @ $CURRENT_COMMIT"

    # Check for uncommitted changes
    if git diff-index --quiet HEAD -- 2>/dev/null; then
        check_ok "No uncommitted changes"
    else
        check_warn "Uncommitted changes present"
    fi

    # Check if behind remote
    git fetch origin --quiet 2>/dev/null
    LOCAL=$(git rev-parse HEAD 2>/dev/null)
    REMOTE=$(git rev-parse origin/master 2>/dev/null)
    if [ "$LOCAL" = "$REMOTE" ]; then
        check_ok "Up to date with origin/master"
    else
        check_warn "Behind origin/master - run 'git pull'"
    fi
else
    check_warn "Not a git repository"
fi
echo ""

# ============================================
# 13. RECENT LOGS
# ============================================
echo -e "${YELLOW}=== 13. RECENT SERVICE LOGS ===${NC}"

echo "Last 20 log entries:"
journalctl -u shieldtier -n 20 --no-pager 2>/dev/null || echo "Could not read logs"
echo ""

# ============================================
# 14. NGINX STATUS (if applicable)
# ============================================
echo -e "${YELLOW}=== 14. NGINX STATUS ===${NC}"

if systemctl is-active --quiet nginx; then
    check_ok "nginx is running"
    nginx -t 2>&1 | head -5
else
    check_info "nginx not running (may be using different reverse proxy)"
fi
echo ""

# ============================================
# SUMMARY
# ============================================
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}   Diagnostics Complete${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo "If you see any [FAIL] items above, address them first."
echo "For [WARN] items, consider installing/fixing if needed."
echo ""
echo "Quick fixes:"
echo "  - Install Python deps: ${VENV_PIP} install pefile pillow pyzbar pdf2image"
echo "  - Install system deps: apt install libzbar0 poppler-utils"
echo "  - Restart service: systemctl restart shieldtier"
echo "  - View logs: journalctl -u shieldtier -f"
echo ""
