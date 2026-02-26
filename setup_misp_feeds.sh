#!/bin/bash
# ============================================================================
# MISP Feed Setup Script for ShieldTier
# Run this on the ShieldTier server after MISP Docker is running
# ============================================================================

set -e

echo "============================================"
echo "  ShieldTier MISP Feed Setup"
echo "============================================"
echo ""

# Ask for MISP API Key
read -p "Enter MISP API Key: " MISP_KEY
if [ -z "$MISP_KEY" ]; then
    echo "ERROR: API key cannot be empty"
    exit 1
fi

# Ask for MISP URL
read -p "Enter MISP URL [https://127.0.0.1:8443]: " MISP_URL
MISP_URL="${MISP_URL:-https://127.0.0.1:8443}"

echo ""
echo "  MISP URL: $MISP_URL"
echo "  API Key:  ${MISP_KEY:0:8}..."
echo "============================================"
echo ""

# Step 1: Check MISP is reachable
echo "[1/6] Checking MISP connectivity..."
VERSION=$(curl -sk "$MISP_URL/servers/getVersion.json" \
    -H "Authorization: $MISP_KEY" \
    -H "Accept: application/json" 2>&1)

if echo "$VERSION" | grep -q "version"; then
    VER=$(echo "$VERSION" | python3 -c "import json,sys; print(json.load(sys.stdin).get('version','unknown'))" 2>/dev/null)
    echo "  Connected - MISP v${VER}"
else
    echo "  ERROR: Cannot reach MISP at $MISP_URL"
    echo "  Response: $VERSION"
    exit 1
fi
echo ""

# Step 2: Load default feed metadata
echo "[2/6] Loading default feed metadata..."
RESULT=$(curl -sk "$MISP_URL/feeds/loadDefaultFeeds" \
    -H "Authorization: $MISP_KEY" \
    -H "Content-Type: application/json" \
    -X POST 2>&1)
echo "  $(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('message','Done'))" 2>/dev/null)"
echo ""

# Step 3: Enable all 41 feeds
echo "[3/6] Enabling 41 threat intelligence feeds..."

FEED_IDS=(1 2 3 8 9 12 13 14 17 18 19 33 34 37 41 42 43 44 53 54 59 60 61 62 63 64 65 66 67 69 70 76 77 78 79 80 81 83 85 86 87)

ENABLED=0
for fid in "${FEED_IDS[@]}"; do
    curl -sk "$MISP_URL/feeds/enable/$fid" \
        -H "Authorization: $MISP_KEY" \
        -H "Content-Type: application/json" \
        -X POST >/dev/null 2>&1
    ENABLED=$((ENABLED + 1))
    echo -n "."
done
echo ""
echo "  $ENABLED feeds enabled"
echo ""

# Step 4: Fetch all feeds
echo "[4/6] Fetching all feeds (background job)..."
RESULT=$(curl -sk "$MISP_URL/feeds/fetchFromAllFeeds" \
    -H "Authorization: $MISP_KEY" \
    -H "Content-Type: application/json" \
    -X POST 2>&1)
echo "  $(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('result','Queued'))" 2>/dev/null)"
echo ""

# Step 5: Update ShieldTier api_keys.json
echo "[5/6] Updating ShieldTier api_keys.json..."
API_KEYS_FILE="/opt/shieldtier/app/api_keys.json"
if [ -f "$API_KEYS_FILE" ]; then
    if grep -q '"misp"' "$API_KEYS_FILE"; then
        echo "  MISP already configured — updating key and URL..."
    fi
    python3 -c "
import json
with open('$API_KEYS_FILE') as f:
    config = json.load(f)
config['misp'] = {
    'api_key': '$MISP_KEY',
    'enabled': True,
    'base_url': '$MISP_URL',
    'verify_ssl': False,
    'description': 'MISP Threat Intelligence Platform - local instance',
    'rate_limit': 'No limit (self-hosted)'
}
with open('$API_KEYS_FILE', 'w') as f:
    json.dump(config, f, indent=2)
print('  MISP added to api_keys.json')
"
else
    echo "  api_keys.json not found at $API_KEYS_FILE — skipping"
fi
echo ""

# Step 6: Show status
echo "[6/6] Checking feed download progress..."
sleep 5
curl -sk "$MISP_URL/events/index.json" \
    -H "Authorization: $MISP_KEY" \
    -H "Accept: application/json" 2>&1 | python3 -c "
import json, sys
events = json.load(sys.stdin)
total_attrs = sum(int(e.get('Event',e).get('attribute_count',0)) for e in events)
print(f'  Events:  {len(events)}')
print(f'  IOCs:    {total_attrs:,}')
"

echo ""
echo "============================================"
echo "  Setup complete!"
echo "============================================"
echo "  Feeds downloading in background (~15-20 min)"
echo ""
echo "  Restart ShieldTier to apply:"
echo "    sudo systemctl restart shieldtier"
echo ""
