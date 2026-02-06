# ShieldTier - Threat Intelligence Platform

## Project Overview
- **Name:** ShieldTier (Powered by MTI)
- **Domain:** www.shieldtier.com
- **Repository:** https://github.com/dillida-cmd/Threatintell

## Tech Stack
- **Backend:** Python 3 (server.py)
- **Frontend:** React + TypeScript + Vite + Tailwind
- **Database:** SQLite (analysis_results.db, ioc_cache.db)
- **Reverse Proxy:** Nginx with Cloudflare Origin Certificate
- **Sandbox:** Bubblewrap + Docker (hardened)

## Key Features
- IP/URL/Hash threat intelligence lookups
- Email, PDF, Office file analysis (static)
- Sandbox analysis with script/executable execution (dynamic)
- Screenshot capture (Chromium)
- Encrypted PDF export with defanging
- **24-hour data retention** (auto-delete)
- SIEM/Sentinel IOC export
- VirusTotal-style attack flow diagram
- MITRE ATT&CK technique mapping

## File Limits
- **Upload:** 15MB max
- **Sandbox:** 50MB max

## Sandbox Capabilities

### Backends
- **Bubblewrap:** Linux namespace isolation
- **Docker:** Container-based isolation (optional)

### Supported File Types
| Type | Extension | Requires |
|------|-----------|----------|
| Bash scripts | .sh | bubblewrap |
| Python scripts | .py | bubblewrap + python3 |
| JavaScript | .js | bubblewrap + node |
| PHP scripts | .php | bubblewrap + php |
| PowerShell | .ps1 | bubblewrap + pwsh |
| Batch files | .bat | wine |
| VBScript | .vbs | wine |
| Windows EXE | .exe | docker + wine |
| Office macros | .docm/.xlsm | docker + libreoffice |

### Security Layers
1. **Seccomp:** Blocks 45+ dangerous syscalls (ptrace, mount, bpf, etc.)
2. **prlimit:** 512MB RAM, 100MB files, 50 processes, 256 file descriptors
3. **Namespaces:** PID, network, user, mount, IPC isolation
4. **Timeout:** Default 30s, max 5 minutes
5. **Auditd:** All sandbox activity logged

### Sandbox Files
- `sandbox_service.py` - Main sandbox service
- `sandbox_seccomp.json` - Syscall filter rules
- `audit-sandbox.rules` - Auditd monitoring rules
- `ai_flow_analyzer.py` - Attack flow diagram generator

## Attack Flow Diagram
VirusTotal-style radial relationship graph showing malware behavior:

### Layout
- **Center node:** Analyzed file (my_payload.exe)
- **Peripheral nodes:** Connected in a circle around center
- **Connections:** Dotted lines with labels (loads, connects, calls)

### Node Types
| Type | Icon | Shows |
|------|------|-------|
| File | 📁 | Filename, size, hash |
| C2 Server | 💀 | IP:port (e.g., 10.0.2.15:4444) |
| DLL | 📦 | Name + full path (C:\windows\system32\ws2_32.dll) |
| API | 🧠 | Function + source DLL (VirtualProtect from KERNEL32.dll) |

### Edge Colors
- **Red:** Network/C2 connections (animated)
- **Orange:** API calls
- **Blue:** Library loads
- **Purple:** DNS queries

### Files
- `ai_flow_analyzer.py` - Generates radial graph data
- `frontend/src/components/AttackFlowDiagram.tsx` - React Flow visualization

## API Keys Configuration
- **File:** `api_keys.json`
- **Services:**
  - VirusTotal
  - AbuseIPDB
  - GreyNoise
  - Shodan
  - AlienVault OTX
  - IPQualityScore
  - URLhaus (abuse.ch)
  - ThreatFox (abuse.ch)

## Deployment

### Quick Install on New Server
```bash
curl -sSL "https://raw.githubusercontent.com/dillida-cmd/Threatintell/master/install.sh?$(date +%s)" | sudo bash -s www.shieldtier.com
```

### Copy API Keys to New Server
```bash
scp /home/kali/Desktop/Claude/ip-lookup/api_keys.json user@SERVER_IP:/opt/shieldtier/app/
sudo chown shieldtier:shieldtier /opt/shieldtier/app/api_keys.json
sudo chmod 600 /opt/shieldtier/app/api_keys.json
```

### Cloudflare Setup
1. Create Origin Certificate: SSL/TLS → Origin Server → Create
2. Save to `/etc/nginx/ssl/cloudflare-origin.pem` and `.key`
3. DNS: A record → Server IP → Proxied (orange cloud)
4. SSL mode: Full (strict)

### Update Server
```bash
cd /opt/shieldtier/app && sudo -u shieldtier git pull && sudo systemctl daemon-reload && sudo systemctl restart shieldtier
```

### Rebuild Frontend
```bash
cd /opt/shieldtier/app/frontend
sudo -u shieldtier npm run build
sudo systemctl restart shieldtier
```

## Server Paths
- **App:** `/opt/shieldtier/app`
- **Data:** `/opt/shieldtier/data`
- **Logs:** `/var/log/shieldtier/`
- **SSL:** `/etc/nginx/ssl/`
- **Nginx:** `/etc/nginx/sites-available/shieldtier`
- **Sandbox:** `/opt/shieldtier/app/sandbox/`
- **Audit Rules:** `/etc/audit/rules.d/sandbox.rules`

## Service Commands
```bash
sudo systemctl status shieldtier
sudo systemctl restart shieldtier
sudo journalctl -u shieldtier -f
```

## Security
- UFW firewall allows only Cloudflare IPs on 80/443
- All URLs/IPs/emails defanged in PDF exports
- PDF reports encrypted with user's secret key
- Sandbox hardened with seccomp + namespaces + resource limits
- Auditd monitors all sandbox activity

## Database Queries
```bash
# List tables
sqlite3 /opt/shieldtier/app/analysis_results.db ".tables"

# Count analyses by type
sqlite3 /opt/shieldtier/app/analysis_results.db "SELECT file_type, COUNT(*) FROM analysis_results GROUP BY file_type;"

# Recent analyses
sqlite3 /opt/shieldtier/app/analysis_results.db "SELECT file_type, risk_level, created_at FROM analysis_results ORDER BY created_at DESC LIMIT 10;"

# Sandbox sessions
sqlite3 /opt/shieldtier/app/analysis_results.db "SELECT * FROM sandbox_sessions ORDER BY created_at DESC LIMIT 10;"
```

## Testing

### Quick Status Check
```bash
curl -s http://localhost:3000/api/status | python3 -m json.tool
```

### Sandbox Status
```bash
curl -s http://localhost:3000/api/sandbox/status | python3 -m json.tool
```

### Test Sandbox Analysis
```bash
curl -X POST http://localhost:3000/api/sandbox/analyze \
  -F "file=@/tmp/test_script.sh" \
  -F "secretKey=testkey123456" | python3 -m json.tool
```

### View Audit Logs
```bash
sudo ausearch -k shieldtier_sandbox | tail -20
```

## API Endpoints

### Threat Intelligence
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/lookup/<ip>` | GET | IP geolocation + basic info |
| `/api/threat-intel/investigate/ip` | POST | Full threat intel for IP |
| `/api/threat-intel/investigate/url` | POST | URL investigation |
| `/api/threat-intel/investigate/hash` | POST | Hash investigation |

### File Analysis (Static)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/analyze/email` | POST | Email analysis |
| `/api/analyze/pdf` | POST | PDF analysis |
| `/api/analyze/office` | POST | Office document analysis |
| `/api/analyze/qrcode` | POST | QR code detection |

### Sandbox Analysis (Dynamic)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/sandbox/status` | GET | Sandbox capabilities |
| `/api/sandbox/analyze` | POST | Execute file in sandbox |
| `/api/sandbox/url` | POST | Analyze URL in sandbox |

### IOC Export
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ioc/export` | GET | Export all IOCs |
| `/api/ioc/export/ips` | GET | Export IP IOCs |
| `/api/ioc/export/urls` | GET | Export URL IOCs |
| `/api/ioc/export/hashes` | GET | Export hash IOCs |

## Local Development
- **SSH Key:** `/home/kali/Desktop/couldbot`
- **Test Samples:** `/home/kali/Desktop/sandbox_test_samples/`

```bash
# Push changes
eval "$(ssh-agent -s)"
ssh-add /home/kali/Desktop/couldbot
git push
```
