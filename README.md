# Manny Threat Intel

A comprehensive threat intelligence platform for security analysts and researchers. Investigate IPs, URLs, and file hashes across multiple threat intelligence sources, and analyze suspicious files in a sandboxed environment.

## Features

### Threat Intelligence Lookups

- **IP Investigation** - Query IPs against multiple threat intel sources to get abuse reports, geolocation, hosting info, open ports, and malware associations
- **URL Investigation** - Analyze URLs for malicious content, phishing indicators, and known malware distribution
- **Hash Investigation** - Look up file hashes to identify known malware, get AV detection rates, and find associated threat campaigns

### File Analysis Sandbox

- **Email Analysis** - Parse .eml/.msg files to extract headers, attachments, embedded URLs, and detect phishing indicators
- **PDF Analysis** - Detect malicious JavaScript, embedded files, auto-open actions, and suspicious URLs in PDF documents
- **Office Document Analysis** - Detect VBA macros, external references, remote templates, and malicious payloads in Word/Excel/PowerPoint files
- **QR Code Detection** - Automatically detect and decode QR codes embedded in analyzed files
- **URL Screenshots** - Capture screenshots of suspicious URLs using headless browsers (Chromium, Firefox, or Puppeteer)
- **Encrypted PDF Export** - Export analysis results to password-protected PDF reports using the same secret key used during upload

### SIEM/Sentinel Integration

Export investigated IOCs for import into your SIEM or Azure Sentinel:

- **Separate IOC Tables** - IPs, URLs, and Hashes are stored in dedicated tables for easy querying
- **Multiple Export Formats** - JSON, CSV, or STIX 2.1 (Azure Sentinel compatible)
- **Filtered Exports** - Export only malicious IOCs or filter by risk score
- **Bulk Export** - Export up to 1000 IOCs at once

### Threat Intelligence Sources

| Source | Data Provided |
|--------|---------------|
| AbuseIPDB | IP abuse reports and confidence scores |
| VirusTotal | Multi-AV scanning and URL/hash analysis |
| IPQualityScore | Fraud scoring, VPN/proxy/Tor detection |
| AlienVault OTX | Threat pulses and IOC correlation |
| GreyNoise | Internet scanner and bot classification |
| Shodan | Open ports and service enumeration |
| ThreatFox | Malware IOC database |
| URLhaus | Malware URL tracking |

## Tech Stack

**Backend:**
- Python 3 with Flask
- SQLite for caching and IOC storage
- oletools for Office macro analysis

**Frontend:**
- React 18 with TypeScript
- Vite build tool
- Tailwind CSS (dark theme)
- Lucide React icons

## Installation

### Quick Start

```bash
git clone https://github.com/dillida-cmd/Threatintell.git
cd Threatintell
chmod +x install.sh
./install.sh
```

The interactive installer will guide you through all configuration options.

### Interactive Installer Options

The installer prompts for the following configurations:

#### Step 1: System Requirements
Automatically checks for:
- Python 3.8+
- Node.js 18+
- npm

#### Step 2: Server Configuration

```
Select connection mode:
  1) Local only (127.0.0.1) - Access from this machine only
  2) Network (0.0.0.0) - Access from any device on the network

Enter server port (default: 3000):
```

#### Step 3: Database Configuration

```
Analysis results database name (default: analysis_results.db):
IOC cache database name (default: ioc_cache.db):
IOC cache duration in hours (default: 24):
```

#### Step 4: Database Encryption

```
⚠ IMPORTANT: The encryption key is used to encrypt sensitive data.
  If you lose this key, encrypted data cannot be recovered!

Enable database encryption? [Y/n]:
Enter encryption secret (min 16 characters):
  (Leave blank to auto-generate a secure key)
```

#### Step 5: API Keys Configuration

The installer prompts for each threat intelligence service API key and shows where to obtain them:

```
AbuseIPDB
  Get API key: https://www.abuseipdb.com/account/api
  API Key (Enter to skip):

VirusTotal
  Get API key: https://www.virustotal.com/gui/my-apikey
  API Key (Enter to skip):

IPQualityScore
  Get API key: https://www.ipqualityscore.com/create-account
  API Key (Enter to skip):

AlienVault OTX
  Get API key: https://otx.alienvault.com/api
  API Key (Enter to skip):

GreyNoise
  Get API key: https://viz.greynoise.io/account/api-key
  API Key (Enter to skip):

Shodan
  Get API key: https://account.shodan.io/
  API Key (Enter to skip):
```

#### Step 6: API Mode Configuration

```
Select API mode:
  1) Full Mode - All features enabled (UI + API)
  2) API Only - REST API only (no web interface)
  3) UI Only - Web interface with basic lookups (no threat intel APIs)

Enable API rate limiting? [Y/n]:
Requests per minute (default: 60):
```

#### Step 7-9: Automatic Steps
- Generates configuration files (`api_keys.json`, `.env`, `config.py`)
- Installs Python and Node.js dependencies
- Builds the React frontend
- Creates helper scripts

#### Step 10: System Service

```
Install as a system service for auto-start on boot?
This requires sudo/root access.
Install service? [y/N]:
```

### Configuration Files Generated

| File | Purpose | Security |
|------|---------|----------|
| `api_keys.json` | API keys for threat intel services | chmod 600 |
| `.env` | Environment configuration | chmod 600 |
| `config.py` | Python configuration module | chmod 600 |
| `.encryption_key` | Database encryption key | chmod 600 |

**⚠ Important:** These files contain sensitive data and are excluded from git. Keep them secure and backed up!

### Installation Summary

After installation completes, you'll see:

```
╔══════════════════════════════════════════════════════════════╗
║            INSTALLATION COMPLETE!                            ║
╚══════════════════════════════════════════════════════════════╝

Configuration Summary:
  Server:      0.0.0.0:3000
  API Mode:    full
  Database:    analysis_results.db
  IOC Cache:   ioc_cache.db
  Encryption:  true

API Keys Configured:
  ✓ AbuseIPDB
  ✓ VirusTotal
  - IPQualityScore (not configured)
  ✓ AlienVault OTX
  - GreyNoise (not configured)
  - Shodan (not configured)
```

## Running the Server

### Manual Start

```bash
./start.sh
```

### Service Commands (if installed as service)

```bash
sudo systemctl start manny-threatintel    # Start server
sudo systemctl stop manny-threatintel     # Stop server
sudo systemctl restart manny-threatintel  # Restart server
sudo systemctl status manny-threatintel   # Check status
sudo journalctl -u manny-threatintel -f   # View logs
```

### Helper Scripts

| Script | Purpose |
|--------|---------|
| `./start.sh` | Start the server |
| `./stop.sh` | Stop the server |
| `./status.sh` | Check if server is running |
| `./reconfigure.sh` | Re-run the installer to change settings |

## Network Access

The server can be configured to listen on:
- **Local only** (`127.0.0.1`) - Access from this machine only
- **Network** (`0.0.0.0`) - Access from any device on the network

**Access URLs:**
- Local: `http://localhost:3000`
- Network: `http://<your-ip>:3000`

Find your IP address:
```bash
hostname -I | awk '{print $1}'
```

## API Endpoints

### Threat Intelligence

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/lookup` | GET | Look up visitor's IP |
| `/api/lookup/<ip>` | GET | Look up specific IP |
| `/api/threat-intel/investigate/ip` | POST | Full threat intel investigation for IP |
| `/api/threat-intel/investigate/url` | POST | Investigate URL across threat sources |
| `/api/threat-intel/investigate/hash` | POST | Investigate file hash |

### IOC Export (SIEM/Sentinel)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ioc/stats` | GET | Get IOC statistics |
| `/api/ioc/export` | GET | Export all IOCs |
| `/api/ioc/export/ips` | GET | Export IP IOCs only |
| `/api/ioc/export/urls` | GET | Export URL IOCs only |
| `/api/ioc/export/hashes` | GET | Export hash IOCs only |

**Export Query Parameters:**
- `format` - `json` (default), `csv`, or `sentinel` (STIX 2.1)
- `malicious` - `true` to export only malicious IOCs
- `min_risk` - Minimum risk score (0-100)
- `limit` - Maximum records (default: 1000)

**Examples:**

```bash
# Export malicious IPs for Azure Sentinel
curl "http://localhost:3000/api/ioc/export/ips?format=sentinel&malicious=true"

# Export all high-risk IOCs as CSV
curl "http://localhost:3000/api/ioc/export?format=csv&min_risk=50"

# Export all hashes
curl "http://localhost:3000/api/ioc/export/hashes"
```

### File Analysis

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/analyze/email` | POST | Analyze email file (.eml/.msg) |
| `/api/analyze/pdf` | POST | Analyze PDF document |
| `/api/analyze/office` | POST | Analyze Office document |
| `/api/results/<ref>` | POST | Retrieve analysis results |

### URL Screenshots

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/screenshot/status` | GET | Get screenshot service status and available tools |
| `/api/screenshot/url` | POST | Capture screenshot of a URL |

**Screenshot Request Body:**
```json
{
  "url": "https://example.com",
  "width": 1280,
  "height": 720,
  "timeout": 30,
  "userAgent": "chrome_windows"
}
```

**Supported Browsers:** Chromium, Firefox, Puppeteer, Playwright, wkhtmltoimage

### PDF Export

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/export/pdf/status` | GET | Get PDF export service status |
| `/api/export/pdf` | POST | Export analysis results to encrypted PDF |

**PDF Export Request Body:**
```json
{
  "entryRef": "MSB0050",
  "secretKey": "your-secret-key",
  "includeScreenshots": false
}
```

**Example:**
```bash
# Export analysis to encrypted PDF
curl -X POST http://localhost:3000/api/export/pdf \
  -H "Content-Type: application/json" \
  -d '{"entryRef":"MSB0050","secretKey":"your-secret-key"}'
```

## Database Schema

### IOC Tables

**ioc_ips** - Investigated IP addresses
- `ip`, `is_malicious`, `risk_score`, `abuse_score`
- `is_tor`, `is_proxy`, `is_vpn`, `is_hosting`
- `country`, `country_code`, `city`, `isp`, `org`, `asn`
- `tags`, `malware_families`, `threat_types`

**ioc_urls** - Investigated URLs
- `url`, `domain`, `is_malicious`, `risk_score`
- `vt_malicious`, `vt_suspicious`, `vt_harmless`
- `urlhaus_status`, `threat_type`, `malware_family`

**ioc_hashes** - Investigated file hashes
- `hash_value`, `hash_type`, `is_malicious`, `risk_score`
- `vt_malicious`, `vt_suspicious`, `vt_harmless`
- `file_name`, `file_type`, `malware_family`

## SIEM Integration

### Azure Sentinel

```bash
curl "http://localhost:3000/api/ioc/export?format=sentinel&malicious=true" > iocs.json
```

Import via Microsoft Graph Security API or Threat Intelligence connector.

### Splunk

```bash
curl "http://localhost:3000/api/ioc/export/ips?format=csv" > ip_iocs.csv
```

Upload as lookup table or use Threat Intelligence Framework.

## Project Structure

```
Threatintell/
├── server.py                 # Main Python backend
├── threat_intel.py           # Threat intelligence module
├── screenshot_service.py     # URL screenshot capture service
├── pdf_export.py             # Encrypted PDF export service
├── requirements.txt          # Python dependencies
├── install.sh                # Interactive installer
├── install-service.sh        # Standalone service installer
├── uninstall-service.sh      # Service uninstaller
├── start.sh                  # Start server
├── stop.sh                   # Stop server
├── status.sh                 # Check status
├── reconfigure.sh            # Re-run configuration
├── manny-threatintel.service # Systemd unit template
├── README.md                 # This file
│
├── api_keys.json             # API keys (generated, not in git)
├── .env                      # Environment config (generated, not in git)
├── config.py                 # Python config (generated, not in git)
├── .encryption_key           # Encryption key (generated, not in git)
│
├── screenshots/              # Captured URL screenshots
├── exports/                  # Exported PDF reports
├── test_samples/             # Test files for sandbox validation
│
└── frontend/                 # React frontend
    ├── src/
    │   ├── components/       # React components
    │   ├── hooks/            # Custom hooks
    │   ├── api/              # API client
    │   └── types/            # TypeScript types
    ├── dist/                 # Production build
    └── package.json          # Node dependencies
```

## Security Notes

- **Encryption Key**: If database encryption is enabled, the `.encryption_key` file is critical. If lost, encrypted data cannot be recovered. Back it up securely!
- **API Keys**: Stored in `api_keys.json` with restricted permissions (chmod 600)
- **Config Files**: `.env` and `config.py` contain sensitive settings
- **Git Exclusions**: All sensitive files are in `.gitignore`
- **File Analysis**: Performed locally, files are not uploaded to external services

## Screenshot Service Setup

The URL screenshot feature requires at least one of the following tools:

| Tool | Installation | Recommended |
|------|--------------|-------------|
| **Chromium** | `apt install chromium` | Yes |
| **Puppeteer** | `npm install -g puppeteer` | Yes |
| **Playwright** | `npm install -g playwright` | Yes |
| **wkhtmltoimage** | `apt install wkhtmltopdf` | Alternative |
| **Firefox** | Pre-installed | Has limitations with snap version |

Check available tools:
```bash
curl http://localhost:3000/api/screenshot/status
```

**Note:** Firefox installed via snap may have issues with headless mode when another Firefox instance is running. Chromium or Puppeteer are recommended for reliable screenshots.

## Troubleshooting

### Port already in use

```bash
lsof -i :3000
kill -9 <PID>
```

### Service not starting

```bash
sudo journalctl -u manny-threatintel -n 50
sudo systemctl status manny-threatintel
```

### Reconfigure settings

```bash
./reconfigure.sh
```

### Reset installation

```bash
./stop.sh
rm -f api_keys.json .env config.py .encryption_key
./install.sh
```

## Uninstall

### Remove service

```bash
sudo ./uninstall-service.sh
```

### Remove all data

```bash
./stop.sh
sudo ./uninstall-service.sh
rm -rf analysis_results.db ioc_cache.db api_keys.json .env config.py .encryption_key
```

## License

MIT License

## Author

Built for security analysts and threat intelligence teams.
