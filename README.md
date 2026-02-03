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

- AbuseIPDB - IP abuse reports and confidence scores
- VirusTotal - Multi-AV scanning and URL/hash analysis
- IPQualityScore - Fraud scoring, VPN/proxy/Tor detection
- AlienVault OTX - Threat pulses and IOC correlation
- GreyNoise - Internet scanner and bot classification
- Shodan - Open ports and service enumeration
- ThreatFox - Malware IOC database
- URLhaus - Malware URL tracking

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

### Prerequisites

- Python 3.8+
- Node.js 18+
- API keys for threat intelligence services

### Setup

1. Clone the repository:
```bash
git clone https://github.com/dillida-cmd/Threatintell.git
cd Threatintell
```

2. Install Python dependencies:
```bash
pip install flask requests oletools python-magic
```

3. Install frontend dependencies:
```bash
cd frontend
npm install
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

5. Build the frontend:
```bash
cd frontend
npm run build
```

6. Start the server:
```bash
python server.py
```

7. Open http://localhost:3000 in your browser

## Development

Run the frontend dev server with hot reload:
```bash
cd frontend
npm run dev
```

The dev server proxies API requests to the Python backend on port 3000.

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

**Example: Export malicious IPs in Sentinel format**
```bash
curl "http://localhost:3000/api/ioc/export/ips?format=sentinel&malicious=true"
```

**Example: Export all IOCs with risk score >= 50 as CSV**
```bash
curl "http://localhost:3000/api/ioc/export?format=csv&min_risk=50"
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
```sql
- ip (unique)
- is_malicious, risk_score, abuse_score
- is_tor, is_proxy, is_vpn, is_hosting
- country, country_code, city, isp, org, asn
- tags, malware_families, threat_types
- first_seen, last_seen, last_updated
```

**ioc_urls** - Stores investigated URLs
```sql
- url (unique), domain
- is_malicious, risk_score
- vt_malicious, vt_suspicious, vt_harmless
- urlhaus_status, threat_type, malware_family
- tags, categories
- first_seen, last_seen, last_updated
```

**ioc_hashes** - Stores investigated file hashes
```sql
- hash_value (unique), hash_type
- is_malicious, risk_score
- vt_malicious, vt_suspicious, vt_harmless
- file_name, file_type, file_size
- malware_family, threat_type, tags
- first_seen, last_seen, last_updated
```

## Sentinel/SIEM Integration

### Azure Sentinel

1. Export IOCs in STIX format:
```bash
curl "http://localhost:3000/api/ioc/export?format=sentinel&malicious=true" > iocs.json
```

2. Import using Microsoft Graph Security API or Azure Sentinel Threat Intelligence connector

### Splunk

1. Export IOCs in CSV format:
```bash
curl "http://localhost:3000/api/ioc/export/ips?format=csv" > ip_iocs.csv
```

2. Upload to Splunk as a lookup table or use the Threat Intelligence Framework

### Generic SIEM

Use the JSON export format for maximum flexibility:
```bash
curl "http://localhost:3000/api/ioc/export?format=json"
```

## Security Notes

- API keys are stored locally and never committed to the repository
- File analysis is performed locally without uploading to external services
- Analysis results are cached with configurable expiration
- Sensitive data is encrypted at rest

## License

MIT License
