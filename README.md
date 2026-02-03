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

### SIEM/Sentinel Integration

Export investigated IOCs for import into your SIEM or Azure Sentinel:

- **Separate IOC Tables** - IPs, URLs, and Hashes are stored in dedicated tables for easy querying
- **Multiple Export Formats** - JSON, CSV, or STIX 2.1 (Azure Sentinel compatible)
- **Filtered Exports** - Export only malicious IOCs or filter by risk score
- **Bulk Export** - Export up to 1000 IOCs at once

### Threat Intelligence Sources

The platform aggregates data from multiple sources:

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

## Quick Installation

### One-Line Install

```bash
git clone https://github.com/dillida-cmd/Threatintell.git && cd Threatintell && chmod +x install.sh && ./install.sh
```

### What the Installer Does

1. Checks for Python 3.8+ and Node.js 18+
2. Installs Python dependencies
3. Installs frontend dependencies
4. Builds the React frontend
5. Creates `api_keys.json` template
6. Creates start/stop scripts
7. **Optionally installs as a system service (auto-start on boot)**

## Manual Installation

### Prerequisites

- Python 3.8+
- Node.js 18+
- API keys for threat intelligence services

### Step-by-Step

1. Clone the repository:
```bash
git clone https://github.com/dillida-cmd/Threatintell.git
cd Threatintell
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Install frontend dependencies and build:
```bash
cd frontend
npm install
npm run build
cd ..
```

4. Create `api_keys.json` in the root directory:
```json
{
  "abuseipdb": {
    "enabled": true,
    "api_key": "your-api-key"
  },
  "virustotal": {
    "enabled": true,
    "api_key": "your-api-key"
  },
  "ipqualityscore": {
    "enabled": true,
    "api_key": "your-api-key"
  },
  "alienvault_otx": {
    "enabled": true,
    "api_key": "your-api-key"
  },
  "greynoise": {
    "enabled": true,
    "api_key": "your-api-key"
  },
  "shodan": {
    "enabled": true,
    "api_key": "your-api-key"
  }
}
```

5. Start the server:
```bash
python server.py
```

## Running as a Service (Auto-Start on Boot)

### During Installation

When running `./install.sh`, answer **y** when prompted:
```
Would you like to install as a system service? (auto-start on boot)
Install service? [y/N]: y
```

### Manual Service Installation

```bash
sudo ./install-service.sh
```

### Service Commands

```bash
sudo systemctl start manny-threatintel    # Start server
sudo systemctl stop manny-threatintel     # Stop server
sudo systemctl restart manny-threatintel  # Restart server
sudo systemctl status manny-threatintel   # Check status
sudo journalctl -u manny-threatintel -f   # View logs
```

### Uninstall Service

```bash
sudo ./uninstall-service.sh
```

## Network Access

The server listens on all network interfaces (`0.0.0.0:3000`), allowing access from other devices on your network.

**Access URLs:**
- Local: `http://localhost:3000`
- Network: `http://<your-ip>:3000`

To find your IP address:
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
| `/api/ioc/stats` | GET | Get IOC statistics (total, malicious counts) |
| `/api/ioc/export` | GET | Export all IOCs |
| `/api/ioc/export/ips` | GET | Export only IP IOCs |
| `/api/ioc/export/urls` | GET | Export only URL IOCs |
| `/api/ioc/export/hashes` | GET | Export only hash IOCs |

**Export Query Parameters:**
- `format` - Output format: `json` (default), `csv`, or `sentinel` (STIX 2.1)
- `malicious` - Set to `true` to export only malicious IOCs
- `min_risk` - Minimum risk score (0-100)
- `limit` - Maximum records to export (default: 1000)

**Examples:**

```bash
# Export malicious IPs in Sentinel format
curl "http://localhost:3000/api/ioc/export/ips?format=sentinel&malicious=true"

# Export all IOCs with risk score >= 50 as CSV
curl "http://localhost:3000/api/ioc/export?format=csv&min_risk=50"

# Export all hashes as JSON
curl "http://localhost:3000/api/ioc/export/hashes"
```

### File Analysis

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/analyze/email` | POST | Analyze email file (.eml/.msg) |
| `/api/analyze/pdf` | POST | Analyze PDF document |
| `/api/analyze/office` | POST | Analyze Office document |
| `/api/results/<ref>` | POST | Retrieve analysis results |

## Database Schema

### IOC Tables

**ioc_ips** - Stores investigated IP addresses
- `ip` (unique), `is_malicious`, `risk_score`, `abuse_score`
- `is_tor`, `is_proxy`, `is_vpn`, `is_hosting`
- `country`, `country_code`, `city`, `isp`, `org`, `asn`
- `tags`, `malware_families`, `threat_types`
- `first_seen`, `last_seen`, `last_updated`

**ioc_urls** - Stores investigated URLs
- `url` (unique), `domain`, `is_malicious`, `risk_score`
- `vt_malicious`, `vt_suspicious`, `vt_harmless`
- `urlhaus_status`, `threat_type`, `malware_family`
- `tags`, `categories`
- `first_seen`, `last_seen`, `last_updated`

**ioc_hashes** - Stores investigated file hashes
- `hash_value` (unique), `hash_type`, `is_malicious`, `risk_score`
- `vt_malicious`, `vt_suspicious`, `vt_harmless`
- `file_name`, `file_type`, `file_size`
- `malware_family`, `threat_type`, `tags`
- `first_seen`, `last_seen`, `last_updated`

## SIEM Integration Examples

### Azure Sentinel

```bash
# Export IOCs in STIX 2.1 format
curl "http://localhost:3000/api/ioc/export?format=sentinel&malicious=true" > iocs.json
```

Import using Microsoft Graph Security API or Azure Sentinel Threat Intelligence connector.

### Splunk

```bash
# Export IOCs in CSV format
curl "http://localhost:3000/api/ioc/export/ips?format=csv" > ip_iocs.csv
```

Upload to Splunk as a lookup table or use the Threat Intelligence Framework.

### Generic SIEM

```bash
# Export all IOCs as JSON
curl "http://localhost:3000/api/ioc/export?format=json"
```

## Project Structure

```
Threatintell/
├── server.py              # Main Python backend
├── threat_intel.py        # Threat intelligence module
├── requirements.txt       # Python dependencies
├── api_keys.json          # API keys (not in repo)
├── install.sh             # Main installer
├── install-service.sh     # Service installer
├── uninstall-service.sh   # Service uninstaller
├── manny-threatintel.service  # Systemd unit file
├── start.sh               # Quick start script
├── stop.sh                # Quick stop script
├── README.md              # This file
└── frontend/              # React frontend
    ├── src/
    │   ├── components/    # React components
    │   ├── hooks/         # Custom hooks
    │   ├── api/           # API client
    │   └── types/         # TypeScript types
    ├── dist/              # Production build
    └── package.json       # Node dependencies
```

## Security Notes

- API keys are stored locally in `api_keys.json` (excluded from git)
- File analysis is performed locally without uploading to external services
- Analysis results are cached with configurable expiration
- Sensitive data is encrypted at rest
- Database files (`*.db`) are excluded from git

## Troubleshooting

### Port already in use
```bash
# Find and kill process using port 3000
lsof -i :3000
kill -9 <PID>
```

### Service not starting
```bash
# Check service logs
sudo journalctl -u manny-threatintel -n 50

# Check service status
sudo systemctl status manny-threatintel
```

### API keys not working
- Ensure `api_keys.json` exists in the root directory
- Set `"enabled": true` for each service you want to use
- Verify API keys are valid and have sufficient quota

## License

MIT License

## Author

Built with security analysts in mind.
