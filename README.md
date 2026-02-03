# Threatintell

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
- SQLite for caching and result storage
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
  "abuseipdb": "your-api-key",
  "virustotal": "your-api-key",
  "ipqualityscore": "your-api-key",
  "alienvault_otx": "your-api-key",
  "greynoise": "your-api-key",
  "shodan": "your-api-key"
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

### File Analysis

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/analyze/email` | POST | Analyze email file (.eml/.msg) |
| `/api/analyze/pdf` | POST | Analyze PDF document |
| `/api/analyze/office` | POST | Analyze Office document |
| `/api/results/<ref>` | POST | Retrieve analysis results |

## Screenshots

The application features a dark-themed interface with:
- Real-time threat intelligence lookups
- Risk score visualization with color-coded indicators
- Detailed breakdown of findings from each source
- File upload with drag-and-drop support
- Comprehensive analysis reports

## Security Notes

- API keys are stored locally and never committed to the repository
- File analysis is performed locally without uploading to external services
- Analysis results are cached with configurable expiration
- Sensitive data is encrypted at rest

## License

MIT License
